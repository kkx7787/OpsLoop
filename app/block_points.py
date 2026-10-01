"""차단 적용 지점 (이슈 #77). 콘솔 · 보고서가 같은 기본값 · 합집합 · 종합 상태를 쓴다.

지점은 허니팟 관문(gateway, 허니팟 유입 앞 · 관측)과 내부 방화벽(fw, 보호 대상 앞 · 보호) 둘이다. 내부 방화벽은 늘 막고 관문은
고른 요청만 막는다(관문 전용은 없다). blocklist.points · absorbed_blocks.points 는 '{gateway,fw}' · '{fw}' 두 값만 받는다(정규
순서, DB CHECK). 열을 모르는 옛 요청은 기본값 두 지점이다.
  기본값    규칙만으로 정한다. 허니팟 남용 규칙(HONEYPOT_ABUSE_RULES)이면 관문 + 내부 방화벽, 아니면 내부 방화벽이다. 장비는 까닭
            (basis, 확인 창 ⓘ)에만 쓴다. detector/triage.py 의 사본과 같다(test_triage 가 맞춰 본다).
  넓히기    살아 있는 차단은 넓히기만 한다(UNION_SQL). 좁히기(관리자의 관문 빼기)는 콘솔이 한 트랜잭션에서 해제 뒤 다시 건다
            (main.add_action). DB 트리거(blocklist_points_change)가 좁히기를 거부한다.
  종합 상태 요청한 지점이 모두 확인이어야 적용이다(STATE_CASE). 대시보드 · 보고서가 같은 상수를 쓰고 화면(format.ts blockState)도
            같은 규칙이다.
  빠짐 확인 전 요청했다가 뺀 지점(관리자 관문 빼기 · 관문 없이 다시 건 행)은 그 지점이 뺐다고 확인될 때까지 요청 행도 미요청도
            아니다(removing_sql, 결정 14). 집행기가 그 지점 결과를 removing 으로 두고, 관문 세 열과 함께 확인 뒤 비운다.
  다시 걸기 해제 · 만료 행을 다시 걸어도(관문 포함 여부와 무관) 콘솔 · triage · 흡수는 관문 세 열을 비우지 않는다(결정 2). 관문이
            뺐다고 확인되면 집행기가 비우고(unenforced) 새로 확인하며, 아니면 다시 건 뒤의 새 보고로 확인해 관문 보고가 이어졌으면
            '기존 차단 유지', 아니면 '연속성 확인 불가' 로 적는다(enforcer/block_enforcer.py NOTE_KEPT · NOTE_UNCERTAIN, 결정 3).
"""

POINTS = ("gateway", "fw")                  # 정규 순서(관문 먼저)
DEFAULT = ["gateway", "fw"]                 # 지점을 주지 않은 요청 · 열이 없던 옛 행
# 관문도 기본으로 막는 허니팟 남용 규칙. 프록시 남용 시도(R004)만이다. 자원 소모 · 침해 의심은 사람이 확인 창에서 관문을 더한다
HONEYPOT_ABUSE_RULES = frozenset({"R004"})
# 기본값의 까닭(확인 창 ⓘ). 규칙이 허니팟 남용 → 장비 미확인 → 관측 센서뿐 → 보호 대상 포함 → 관제 시스템 포함 순으로 고른다
BASES = ("honeypot_abuse", "sensor_only", "protected", "monitor", "unconfirmed")

# 집행기(enforcer/block_enforcer.py)가 enforce_note 에 쓰는 말머리. main · targets 의 같은 이름 상수와 같다(test_block_points)
ENFORCE_EXCLUDED = "집행 제외"
ENFORCE_MISMATCH = "관문 불일치"


def default_points(rule_id) -> list[str]:
    """규칙의 기본 적용 지점(정규 순서)."""
    return list(DEFAULT) if rule_id in HONEYPOT_ABUSE_RULES else ["fw"]


def basis_of(rule_id, devices, device_state=None) -> str:
    """기본값의 까닭. devices 는 사건의 관련 장비(targets.devices_of 의 devices, 장비마다 group 이 targets.device_group)다."""
    if rule_id in HONEYPOT_ABUSE_RULES:
        return "honeypot_abuse"
    groups = {d.get("group") for d in devices or () if isinstance(d, dict)}
    if device_state == "unconfirmed" or not groups:
        return "unconfirmed"
    if groups == {"sensor"}:
        return "sensor_only"
    if "protected" in groups:
        return "protected"
    if "monitor" in groups:
        return "monitor"
    return "unconfirmed"


def normalize(points) -> list[str]:
    """요청 지점 → 정규 순서 목록. 모르는 값 · 중복 · 빈 목록 · 내부 방화벽 빠짐은 ValueError 다(내부 방화벽은 늘 막는다)."""
    if not isinstance(points, (list, tuple)) or not points:
        raise ValueError("적용 지점은 하나 이상이어야 합니다")
    unknown = [p for p in points if p not in POINTS]
    if unknown:
        raise ValueError(f"모르는 적용 지점입니다: {', '.join(map(str, unknown))}")
    if len(set(points)) != len(points):
        raise ValueError("적용 지점이 중복됐습니다")
    if "fw" not in points:
        raise ValueError("내부 방화벽은 늘 적용합니다(관문만 막을 수 없습니다)")
    return [p for p in POINTS if p in points]


def held_sql(point: str) -> str:
    """그 지점에 남은 기록(state 가 글자인 결과 기록, 관문은 확인 시각 enforced_at 도). 집행기(held_at) · 화면(format.ts heldPoint)과
    같은 정의다."""
    held = f"jsonb_typeof(enforcement -> '{point}' -> 'state') IS NOT DISTINCT FROM 'string'"      # NULL 이 아닌 참 · 거짓
    return f"({held} OR enforced_at IS NOT NULL)" if point == "gateway" else f"({held})"


def unrequested_sql(point: str) -> str:
    """그 지점을 요청하지 않았고 남은 기록도 없는 행(미요청)."""
    return f"NOT '{point}' = ANY(points) AND NOT {held_sql(point)}"


def removing_sql(point: str) -> str:
    """그 지점을 요청하지 않았는데 기록이 남은 행(빠짐 확인 전). 그 지점의 요청 행으로도 미요청으로도 세지 않는다."""
    return f"NOT '{point}' = ANY(points) AND {held_sql(point)}"


def union_of(old: str, new: str) -> str:
    """두 지점 배열 식의 합집합(정규 순서) SQL 식."""
    return (f"ARRAY(SELECT p FROM unnest(ARRAY['gateway', 'fw']) WITH ORDINALITY AS u(p, n) "
            f"WHERE p = ANY({old}) OR p = ANY({new}) ORDER BY n)")


# 살아 있는 차단에 다시 걸 때의 지점(ON CONFLICT DO UPDATE 안). 좁히지 않는다
UNION_SQL = union_of("blocklist.points", "EXCLUDED.points")

# 살아 있는 차단 요청 한 행의 종합 상태(blocklist 열 그대로). 요청한 지점이 모두 확인이어야 적용(enforced)이다.
#   우선순위: 제외(만료 없음 · 집행 제외 쪽지) > 실패(요청 지점 하나라도 failed) > 불일치(요청 지점 하나라도 stale · 관문 불일치 쪽지) >
#   대기(그 밖: pending · 기록 없음) > 적용. 관문의 확인 · 불일치는 지금처럼 관문 세 열(enforced_at · enforce_note)로, 실패 · 지연은
#   enforcement.gateway 로 본다. 요청한 관문의 결과가 대기(다시 걸거나 만료를 늘려 새 목록을 확인하기 전)이거나 남은 빠짐 확인 전
#   (다시 건 뒤 집행기 다음 회차 전)이면 남은 확인 시각이 있어도 대기다(지점 칸 '대기' 와 같다, 결정 2). 내부 방화벽은
#   enforcement.fw 로 본다. 요청하지 않은 지점은 보지 않는다
_GW = "'gateway' = ANY(points)"
_FW = "'fw' = ANY(points)"
STATE_CASE = f"""CASE WHEN expires_at IS NULL OR enforce_note LIKE '{ENFORCE_EXCLUDED}%' THEN 'excluded'
                      WHEN ({_GW} AND enforcement -> 'gateway' ->> 'state' = 'failed')
                           OR ({_FW} AND enforcement -> 'fw' ->> 'state' = 'failed') THEN 'failed'
                      WHEN ({_GW} AND (enforce_note LIKE '{ENFORCE_MISMATCH}%'
                                        OR enforcement -> 'gateway' ->> 'state' = 'stale'))
                           OR ({_FW} AND enforcement -> 'fw' ->> 'state' = 'stale') THEN 'mismatch'
                      WHEN ({_GW} AND (enforced_at IS NULL
                                        OR enforcement -> 'gateway' ->> 'state' IN ('pending', 'removing')))
                           OR ({_FW} AND enforcement -> 'fw' ->> 'state' IS DISTINCT FROM 'confirmed') THEN 'pending'
                      ELSE 'enforced' END"""
STATES = ("enforced", "pending", "excluded", "mismatch", "failed")

# 살아 있는 차단 요청을 종합 상태로 센다(대시보드 요약 blocks · 보고서 states). $1 기준 시각
BLOCK_STATES_SQL = f"""
    SELECT count(*) AS total,
           {""",
           """.join(f"count(*) FILTER (WHERE s = '{s}') AS {s}" for s in STATES)}
    FROM (SELECT {STATE_CASE} AS s
          FROM blocklist WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > $1)) b"""
