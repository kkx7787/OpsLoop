"""관제 대상별 상태판 (이슈 #52). GET /api/dashboard/targets

카드 네 장(AWS 센서 · web-01 · 관제 콘솔 · 데이터 노드)에 수집 · 보안 · 시스템 · 대응 · 취약점을 대상별로 모은다.
반복 읽기 · 읽기 전용 트랜잭션 하나에서 읽는다(대시보드 summary 와 같다). 표 · 권한이 없는 것은 오류가 아니라
선검사(to_regclass + has_table_privilege)로 갈라 '미확인' 으로 답한다. 한 질의라도 실패하면 트랜잭션 전체가 멈추므로
예외로 가르지 않는다.

정직한 표기
  - 수집: 생존 신호가 있는 대상만 신호 시각으로 정상 · 수신 없음을 가른다. 로그 시각만으로 정상 · 장애를 정하지 않는다
    (콘솔은 생존 신호가 없어 늘 '생존 상태 미확인' 이다). 신호는 정상인데 로그가 없으면 '요청 없음'(quiet)이다.
  - 대응: 그 지점(관문 · 내부 방화벽)이 적용을 확인한 것만 적용이다. 지점이 없는 대상은 수를 내지 않는다(null).
    0 이 '막지 못했다' 로 읽히지 않게 화면이 문구를 고른다.
  - 사건 → 대상 매핑은 순수 함수(resolve)다. 한 사건이 여러 대상에 붙을 수 있어 카드 합은 전체와 다르다.
    어느 대상에도 붙이지 못한 사건은 숨기지 않고 unmapped 로 센다.
"""
import json
from datetime import timedelta

from fastapi import APIRouter, Request

import cti
from absorbed import block_nets

router = APIRouter()

WINDOW_SECONDS = 3600          # 카드의 '최근 1시간'
LATEST_HOURS = 24              # 최근 중요 탐지 · 매핑 대상 사건의 창
HEARTBEAT_STALE = 900          # 업로더 생존 신호 · 탐지 실행이 이보다 오래되면 끊긴 것이다(15분).
                               #   업로더 신호는 적재기가 확인한 시각 기준으로 잰다(pull.py 의 HB_STALE 과 같은 기준)
CHECKER_STALE = 1800           # 적재기 확인 중단. checked_at 은 풀러 회차가 시작한 시각이고 기록은 받기 뒤라, 회차 간격 5분 +
                               #   받기 최장 10분(RUN_SECONDS) + 적재 · 탐지 여유를 넘겨야 멈춘 것이다(30분)
BLOCK_CHECKER_STALE = 600      # 집행기 확인 중단. 집행기는 1분마다 돈다. 10분 넘게 확인이 없으면 지점 적용 확인을 믿지 않는다
NODE_SILENT = 600              # 노드 수신 끊김(operations.py /api/nodes 의 10분과 같다)
METRICS_STALE = 600            # 자원 지표 최신 행이 이보다 오래되면 오래됨(10분)
HIGH_SEVERITIES = ("critical", "high")

# (id, 이름, 역할). 순서가 카드 순서다
TARGETS = [
    ("aws-sensor", "AWS 센서", "Cowrie 허니팟 · 웹 디코이 · AWS 관문 (DMZ)"),
    ("web-01", "web-01", "실서비스 웹 서버 (온프레미스)"),
    ("console", "관제 콘솔", "콘솔 A · B (HAProxy 뒤)"),
    ("data-node", "데이터 노드", "DB · 적재 · 탐지 · 집행 (온프레미스)"),
]
# 발생원(events.sensor · evidence.sensors · 규칙 params.sensors) → 대상
SENSOR_TARGET = {"cowrie": "aws-sensor", "decoy": "aws-sensor", "gateway": "aws-sensor", "web-01": "web-01",
                 "console": "console", "audit": "console", "collector": "data-node", "puller": "data-node"}
# 이벤트 이름 접두 → 발생원. 규칙의 eventids · eventid · eventid_like 로 발생원 후보를 고른다
EVENT_PREFIXES = {"cowrie.": "cowrie", "decoy.": "decoy", "gateway.": "gateway", "sshd.": "web-01",
                  "nginx.": "web-01", "console.": "console"}
# 발생원 조건 없이 세션 · 기준선을 보는 규칙은 허니팟(Cowrie) 규칙이다
COWRIE_TYPES = frozenset({"session_compound", "baseline_deviation", "key_plant"})
# 발생원 조건이 없는 세션 규칙(v3 R002)은 sessions 표 전체를 본다. 그 표에는 Cowrie 세션과 디코이 세션(parse_decoy)이 함께 있어
#   대상은 AWS 센서지만 나눔은 사건의 세션(evidence.sessions)으로 고른다
SESSION_TYPES = frozenset({"session_compound"})
SESSION_SOURCES = ("cowrie", "decoy")
# AWS 센서 카드의 발생원 나눔
AWS_PARTS = [("cowrie", "Cowrie"), ("decoy", "웹 디코이"), ("gateway", "AWS 관문")]
PART_KEYS = frozenset(key for key, _ in AWS_PARTS)
# 대상별 로그(events.sensor, 이름). 데이터 노드는 로그가 아니라 탐지 실행이 신호다
LOGS = {"aws-sensor": [("cowrie", "Cowrie"), ("decoy", "웹 디코이"), ("gateway", "AWS 관문 기록")],
        "web-01": [("web-01", "web-01 로그")], "console": [("console", "마지막 로그인 기록")], "data-node": []}
# 수집 상태 ok · quiet 를 가르는 로그(AWS 관문 기록은 요청이 아니라 관문 자체의 기록이라 넣지 않는다)
ACTIVE_LOGS = {"aws-sensor": ("cowrie", "decoy"), "web-01": ("web-01",)}
# 집행 지점(차단을 실제로 적용하는 곳)과 그 이름. 콘솔 · 데이터 노드 앞에는 차단 결과를 모으는 지점이 없다
POINTS = {"aws-sensor": ("gateway", "AWS 관문"), "web-01": ("fw", "내부 방화벽")}
# 대상별 자산(asset_inventory.asset_id)
TARGET_ASSETS = {"aws-sensor": ["honeypot-dmz", "gateway"], "web-01": ["web-01"],
                 "console": ["console-a", "console-b"], "data-node": ["data-01"]}
WEB_NODE = "web-01"

# 집행기가 enforce_note 에 쓰는 '집행 제외' 말머리. main.ENFORCE_EXCLUDED 와 같다(test_targets 가 맞춰 본다).
#   main 을 불러오면 순환이라 여기 둔다
ENFORCE_EXCLUDED = "집행 제외"

# 표가 있고 이 역할이 읽을 수 있는가. 표가 없으면 권한 함수가 오류를 내므로 먼저 본다(absorbed.EXEMPT_READABLE_SQL 과 같은 꼴)
HEARTBEATS_READABLE_SQL = ("SELECT CASE WHEN to_regclass('sensor_heartbeats') IS NULL THEN false"
                           " ELSE has_table_privilege('sensor_heartbeats', 'SELECT') END")
METRICS_READABLE_SQL = ("SELECT CASE WHEN to_regclass('node_metrics') IS NULL THEN false"
                        " ELSE has_table_privilege('node_metrics', 'SELECT') END")

HEARTBEATS_SQL = "SELECT source, kind, role, host, seen_at, checked_at, problem FROM sensor_heartbeats ORDER BY source"

# 매핑 대상 사건: 최근 1시간에 시작했거나, 24시간 안에 이어졌거나, 판정 기록이 없는 것. 근거는 발생원(sensors)만 꺼낸다.
#   시험 출발지를 빼지 않는다(대시보드 미판정 수와 같게). $1 기준 시각 · $2 창(초) · $3 최근 시간(시)
INCIDENTS_SQL = """
    SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity, host(i.actor_ip) AS actor_ip, i.target,
           i.first_ts, i.last_ts,
           CASE WHEN jsonb_typeof(i.evidence -> 'sensors') = 'array' THEN i.evidence -> 'sensors' END AS sensors,
           CASE WHEN jsonb_typeof(i.evidence -> 'sessions') = 'array' THEN i.evidence -> 'sessions' END AS sessions,
           EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key) AS judged
    FROM incidents i
    WHERE i.first_ts >= $1::timestamptz - make_interval(secs => $2)
       OR i.last_ts >= $1::timestamptz - make_interval(hours => $3)
       OR NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)
    ORDER BY i.incident_key"""

# 규칙 정의에서 발생원을 가르는 값만 꺼낸다(서명 목록 같은 큰 값은 가져오지 않는다). 규칙 버전 정의는 고칠 수 없으니
#   rules 가 배열이 아니거나 항목이 객체가 아니어도 질의가 실패하지 않게 거른다
RULES_SQL = """
    SELECT rv.rule_version, r ->> 'id' AS rule_id, r ->> 'type' AS type,
           r #> '{params,sensors}' AS sensors, r #> '{params,eventids}' AS eventids,
           r #> '{params,eventid}' AS eventid, r #> '{params,eventid_like}' AS eventid_like,
           r #> '{params,http_status}' AS http_status, r #> '{params,exclude_url_patterns}' AS exclude_url_patterns,
           r #> '{params,window_seconds}' AS window_seconds, r #> '{params,threshold}' AS threshold
    FROM rule_versions rv
    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(rv.definition -> 'rules') = 'array'
                                                 THEN rv.definition -> 'rules' ELSE '[]'::jsonb END) r
    WHERE rv.rule_version = ANY($1::text[]) AND jsonb_typeof(r) = 'object'"""

# 발생원이 섞인 규칙(R101 w2 · R102 · R104 …)의 사건만 실제 이벤트로 발생원을 고른다. 사건마다 묻지 않고 한 번에 묻는다.
#   탐지가 센 이벤트와 같은 범위를 본다(detect.signals_actor_rate):
#   - 출발지 빈도 규칙(w · th 가 있음)은 첫 시각 · 끝 시각이 든 고정 창 전체를 보고, 창 안 이벤트 수가 임계치 이상인 창만 센다
#     (끝 시각은 마지막 창의 첫 행이라 그 창의 나머지를 놓치면 안 된다. 임계치에 못 미친 사이 창은 사건에 들지 않았다)
#   - 응답 코드(st) · 제외 경로(ex, 탐지처럼 ^(?: … )$ 로 감싼 것)도 같게 건다
#   - 그 밖(event_match 등)은 첫 시각 ~ 끝 시각의 이벤트다
#   $1 [{k 사건 키, ip 출발지, f 첫 시각, l 끝 시각, ids 이벤트 이름들, lk 이벤트 이름 LIKE, ss 발생원 조건,
#        st 응답 코드들, ex 제외 경로 정규식들, w 창(초), th 임계치}]
#   이벤트 이름 조건이 둘 다 없으면 이름으로 거르지 않는다. 출발지 색인(idx_events_src_ip)으로 읽는다
JOIN_SQL = """
    SELECT q.k AS incident_key, e.sensor
    FROM jsonb_to_recordset($1::jsonb) AS q(k text, ip inet, f timestamptz, l timestamptz, ids text[], lk text, ss text[],
                                            st int[], ex text[], w int, th int)
    CROSS JOIN LATERAL (
        SELECT DISTINCT b.sensor FROM (
            SELECT ev.sensor, count(*) OVER (PARTITION BY floor(extract(epoch FROM ev.ts) / q.w)) AS n
            FROM events ev
            WHERE ev.src_ip = q.ip AND ev.provenance = 'real'
              AND ((q.w IS NULL AND ev.ts BETWEEN q.f AND q.l)
                   OR (q.w IS NOT NULL
                       AND ev.ts >= to_timestamp(floor(extract(epoch FROM q.f) / q.w) * q.w)
                       AND ev.ts < to_timestamp((floor(extract(epoch FROM q.l) / q.w) + 1) * q.w)))
              AND ((q.ids IS NULL AND q.lk IS NULL) OR ev.eventid = ANY(q.ids) OR ev.eventid LIKE q.lk)
              AND (q.ss IS NULL OR ev.sensor = ANY(q.ss))
              AND (q.st IS NULL OR ev.http_status = ANY(q.st))
              AND (q.ex IS NULL OR ev.url IS NULL OR NOT (ev.url ~ ANY(q.ex)))) b
        WHERE q.th IS NULL OR b.n >= q.th) e
    ORDER BY q.k, e.sensor"""

# 발생원 조건 없는 세션 규칙(v3 R002)의 사건: 근거의 세션으로 Cowrie · 디코이를 고른다. 세션 색인(idx_events_session)으로 읽는다.
#   $1 [{k 사건 키, s 세션들}]
SESSION_JOIN_SQL = """
    SELECT q.k AS incident_key, e.sensor
    FROM jsonb_to_recordset($1::jsonb) AS q(k text, s text[])
    CROSS JOIN LATERAL (
        SELECT DISTINCT ev.sensor FROM events ev
        WHERE ev.session = ANY(q.s) AND ev.sensor = ANY($2::text[]) AND ev.provenance = 'real') e
    ORDER BY q.k, e.sensor"""

# 발생원별 마지막 로그. (sensor, ts) 색인(idx_events_sensor_ts)으로 발생원마다 한 번 내려간다
LOGS_SQL = """
    SELECT s AS sensor, (SELECT max(e.ts) FROM events e WHERE e.sensor = s AND e.provenance = 'real') AS last_at
    FROM unnest($1::text[]) AS s"""

# 노드 수신 판정. operations.py /api/nodes 의 CASE 와 같은 규칙이다(now() 대신 기준 시각 $2). $1 노드 id
NODE_SQL = """
    SELECT n.status, n.last_seen_at, n.last_loaded_at,
           CASE WHEN n.status='revoked' THEN 'revoked' WHEN n.status='pending' THEN 'waiting'
                WHEN coalesce(n.last_seen_at,n.registered_at) < $2::timestamptz-interval '10 minutes' THEN 'silent'
                WHEN n.last_seen_at IS NULL THEN 'waiting' ELSE 'normal' END AS reception
    FROM nodes n WHERE n.node_id = $1"""

DETECTOR_SQL = "SELECT max(started_at) FROM detector_runs"

METRICS_SQL = """
    SELECT ts, cpu_pct, mem_used_pct, disk_root_pct, load1 FROM node_metrics
    WHERE node_id = $1 ORDER BY ts DESC LIMIT 1"""

# 살아 있는 차단(해제 · 만료 안 됨, 만료 없는 옛 차단 · 집행 제외 아님)을 지점별로 적용 확인 · 실패 · 미확인으로 나눈다.
#   실패는 그 지점이 거부했다고 보고한 것(failed)이다. 모르는 것이 아니라 알려진 미적용이라 미확인과 가른다.
#   미확인은 그 밖(pending · stale · 기록 없음)이다.
#   만료 없음 · 집행 제외는 main.BLOCK_STATES_SQL 의 excluded 와 같은 정의다. $1 기준 시각
BLOCKS_SQL = "SELECT " + ", ".join(
    f"count(*) FILTER (WHERE enforcement -> '{p}' ->> 'state' = 'confirmed') AS {p}_applied, "
    f"count(*) FILTER (WHERE enforcement -> '{p}' ->> 'state' = 'failed') AS {p}_failed, "
    f"count(*) FILTER (WHERE coalesce(enforcement -> '{p}' ->> 'state', '') NOT IN ('confirmed', 'failed')) AS {p}_unverified"
    for p, _ in POINTS.values()) + f"""
    FROM blocklist
    WHERE released_at IS NULL AND expires_at > $1
      AND (enforce_note IS NULL OR enforce_note NOT LIKE '{ENFORCE_EXCLUDED}%')"""

# 출발지 중 차단 금지 대역(absorbed.block_nets)에 드는 것. $1 주소들 · $2 대역들
EXEMPT_SQL = """
    SELECT DISTINCT host(ip) AS ip FROM unnest($1::text[]::inet[]) AS ip
    WHERE ip <<= ANY($2::text[]::inet[])"""


# ----------------------------------------------------------------------
#  순수 함수 (DB 없이 시험한다)
# ----------------------------------------------------------------------

def _strings(value) -> list[str]:
    """jsonb 값(글자로 온 것 포함) → 비지 않은 문자열 목록. 목록이 아니면 빈 목록."""
    value = cti.loads(value)
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _string(value) -> str | None:
    value = cti.loads(value)
    return value if isinstance(value, str) and value else None


def _ints(value) -> list[int]:
    value = cti.loads(value)
    return [v for v in value if isinstance(v, int) and not isinstance(v, bool)] if isinstance(value, list) else []


def _positive(value) -> int | None:
    value = cti.loads(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def rule_spec(row) -> dict:
    """규칙 정의 한 개(RULES_SQL 한 행) → {type, sensors, eventids, eventid_like, http_status, exclude, window, threshold}.
    eventid 는 eventids 에 합친다. sensors 가 없으면 None(발생원 조건 없음)이다.
    출발지 빈도 규칙(actor_rate)만 창 · 임계치 · 응답 코드 · 제외 경로를 쓴다(탐지와 같은 범위로 발생원을 고른다).
    제외 경로는 탐지처럼 ^(?: … )$ 로 감싼다. 규칙 정의(rule_versions)는 탐지가 형식을 본 뒤 들어간 것이다."""
    eventids = _strings(row["eventids"])
    one = _string(row["eventid"])
    if one and one not in eventids:
        eventids.append(one)
    rate = row["type"] == "actor_rate"
    window, threshold = _positive(row.get("window_seconds")), _positive(row.get("threshold"))
    return {"type": row["type"], "sensors": _strings(row["sensors"]) or None, "eventids": eventids,
            "eventid_like": _string(row["eventid_like"]),
            "http_status": (_ints(row.get("http_status")) or None) if rate else None,
            "exclude": ([f"^(?:{x})$" for x in _strings(row.get("exclude_url_patterns"))] or None) if rate else None,
            "window": window if rate and threshold else None, "threshold": threshold if rate and window else None}


def event_source(name: str) -> str | None:
    """이벤트 이름(또는 LIKE 식)의 접두로 고른 발생원."""
    for prefix, source in EVENT_PREFIXES.items():
        if name.startswith(prefix):
            return source
    return None


def candidate_sources(spec: dict) -> list[str]:
    """규칙의 발생원 후보: params.sensors ∪ 이벤트 이름 접두로 고른 발생원."""
    found = list(spec.get("sensors") or [])
    for name in [*spec.get("eventids", []), *([spec["eventid_like"]] if spec.get("eventid_like") else [])]:
        source = event_source(name)
        if source and source not in found:
            found.append(source)
    return found


def attach(sources) -> set[tuple[str, str | None]]:
    """발생원들 → {(대상, AWS 센서 발생원 나눔 또는 None)}. 모르는 발생원은 버린다."""
    out = set()
    for source in sources:
        target = SENSOR_TARGET.get(source)
        if target:
            out.add((target, source if source in PART_KEYS else None))
    return out


EVENTS, SESSIONS = "events", "sessions"   # resolve 의 둘째 값: 무엇으로 발생원을 더 고르는가(없으면 False)


def resolve(target, sensors, spec) -> tuple[set, str | bool]:
    """사건 하나를 대상에 붙인다. (붙인 곳 {(대상, 나눔)}, 더 고를 방법: False · EVENTS · SESSIONS).

    순서: (1) target 'node:<id>' (2) target 'user:…' → 콘솔 (3) 근거의 발생원(evidence.sensors) (4) 규칙의 발생원 후보.
    후보의 대상이 하나면 그 대상이고, 대상이 둘 이상이면(발생원이 섞인 규칙) 이벤트로 고른다(붙인 곳 없음 · EVENTS).
    대상은 하나인데 AWS 센서 발생원이 여럿이면 대상은 정하고 나눔만 이벤트로 고른다(대상만 붙인 곳 · EVENTS).
    (5) 후보가 없는 세션 규칙(v3 R002)은 AWS 센서이고 나눔은 사건의 세션으로 고른다(대상만 붙인 곳 · SESSIONS).
    고르지 못하면 Cowrie 다. (6) 후보가 없는 기준선 · 키 심기 규칙은 Cowrie (7) 그 밖은 붙이지 못한다.
    """
    if isinstance(target, str) and target.startswith("node:"):
        return attach([target[len("node:"):]]), False
    if isinstance(target, str) and target.startswith("user:"):
        return {("console", None)}, False
    evidence = _strings(sensors)
    if evidence:
        return attach(evidence), False
    if spec is None:
        return set(), False
    sources = candidate_sources(spec)
    if sources:
        pairs = attach(sources)
        targets = {t for t, _ in pairs}
        if len(targets) > 1:
            return set(), EVENTS
        if len({p for _, p in pairs if p}) > 1:
            return {(t, None) for t in targets}, EVENTS
        return pairs, False
    if spec.get("type") in SESSION_TYPES:
        return {("aws-sensor", None)}, SESSIONS
    if spec.get("type") in COWRIE_TYPES:
        return {("aws-sensor", "cowrie")}, False
    return set(), False


def join_item(incident: dict, spec: dict) -> dict:
    """JOIN_SQL 에 넘길 사건 한 개."""
    return {"k": incident["incident_key"], "ip": incident["actor_ip"], "f": cti.iso(incident["first_ts"]),
            "l": cti.iso(incident["last_ts"]), "ids": spec["eventids"] or None, "lk": spec["eventid_like"],
            "ss": spec["sensors"], "st": spec.get("http_status"), "ex": spec.get("exclude"),
            "w": spec.get("window"), "th": spec.get("threshold")}


def session_item(incident: dict) -> dict | None:
    """SESSION_JOIN_SQL 에 넘길 사건 한 개. 근거에 세션이 없으면 None."""
    sessions = _strings(incident.get("sessions"))
    return {"k": incident["incident_key"], "s": sessions} if sessions else None


def ago(as_of, at) -> str:
    """사람이 읽는 경과(방금 · n분 전 · n시간 전 · n일 전). 앞선 시각(시계 차)은 방금이다."""
    seconds = max(0.0, (as_of - at).total_seconds())
    if seconds < 60:
        return "방금"
    minutes = int(seconds // 60)
    if minutes < 120:
        return f"{minutes}분 전"
    hours = minutes // 60
    return f"{hours}시간 전" if hours < 48 else f"{hours // 24}일 전"


def older(as_of, at, seconds) -> bool:
    """at 이 as_of 보다 seconds 넘게 앞선다(없으면 참)."""
    return at is None or as_of - at > timedelta(seconds=seconds)


def logs_of(target_id: str, last: dict) -> list[dict]:
    return [{"key": key, "label": label, "last_at": cti.iso(last.get(key))} for key, label in LOGS[target_id]]


def active(target_id: str, last: dict, as_of) -> bool:
    """최근 1시간 안에 요청 로그가 있는가."""
    return any(not older(as_of, last.get(key), WINDOW_SECONDS) for key in ACTIVE_LOGS.get(target_id, ()))


def signal_of(label: str, stale_after: int, seen=None, checked=None, problem=None) -> dict:
    return {"label": label, "seen_at": cti.iso(seen), "checked_at": cti.iso(checked),
            "stale_after_seconds": stale_after, "problem": problem}


def collection(state, reason, signal, logs, extra=()) -> dict:
    return {"state": state, "reason": reason, "signal": signal, "logs": logs, "extra": list(extra)}


def sensor_collection(as_of, available: bool, heartbeats: list, last: dict) -> dict:
    """AWS 센서. 업로더 생존 신호(role=sensor)로 가른다.

    seen_at 은 풀러가 회차를 시작하며 읽은 hb 의 S3 시각, checked_at 은 그 회차가 시작한 시각이고, 기록은 받기가 끝난 뒤다.
    그래서 신호가 끊겼는지는 확인 시점 기준(checked_at - seen_at > 15분, pull.py 의 HB_STALE 과 같다)으로 재고, 적재기가 멈췄는지는
    지금 기준(as_of - checked_at > 30분)으로 따로 잰다. 받기가 길어 기록이 늦었을 뿐인 센서를 '수신 없음' 으로 그리지 않는다.
    적재기가 더는 확인하지 않는 행(떼어 둔 호스트의 남은 행)은 고르지 않는다. 모든 행이 그렇다면 적재기 확인이 멈춘 것이다(미확인).
    여럿이면 확인 시점에 가장 늦었던 신호로 가른다. 신호가 새로우면 Cowrie · 웹 디코이 로그로 정상 · 요청 없음을 가른다."""
    logs = logs_of("aws-sensor", last)
    label = "업로더 생존 신호"
    rows = [r for r in heartbeats if r["kind"] == "uploader" and r["role"] == "sensor"]
    if not available or not rows:
        return collection("unknown", "생존 신호 미기록" + ("" if available else " · 생존 신호 표를 읽을 수 없음"),
                          signal_of(label, HEARTBEAT_STALE), logs)
    live = [r for r in rows if not older(as_of, r["checked_at"], CHECKER_STALE)]
    if not live:
        row = max(rows, key=lambda r: r["checked_at"])
        return collection("unknown", f"적재기 확인 중단 · 마지막 확인 {ago(as_of, row['checked_at'])}",
                          signal_of(label, HEARTBEAT_STALE, row["seen_at"], row["checked_at"], row["problem"]), logs)

    def lag(r):
        return (r["checked_at"] - r["seen_at"]).total_seconds() if r["seen_at"] is not None else float("inf")
    row = max(live, key=lambda r: (lag(r), r["host"]))
    signal = signal_of(label, HEARTBEAT_STALE, row["seen_at"], row["checked_at"], row["problem"])
    many = f"(센서 {len(live)}대 중 가장 늦은 것)" if len(live) > 1 else ""
    if row["seen_at"] is None:
        return collection("no_signal", f"업로더 생존 신호 없음{many}" + (f" · {row['problem']}" if row["problem"] else ""),
                          signal, logs)
    head = f"업로더 생존 신호 {ago(as_of, row['seen_at'])}{many} · 적재기 확인 {ago(as_of, row['checked_at'])}"
    if lag(row) > HEARTBEAT_STALE:
        return collection("no_signal", f"{head} · 확인 때 이미 15분 넘게 새 신호 없음", signal, logs)
    if active("aws-sensor", last, as_of):
        return collection("ok", f"{head} · 최근 1시간 로그 있음", signal, logs)
    return collection("quiet", f"{head} · 최근 1시간 요청 없음", signal, logs)


def node_collection(as_of, node, last: dict) -> dict:
    """web-01. 노드 수신 판정(operations.py 와 같은 규칙)으로 가른다. 정상이면 web-01 로그로 정상 · 요청 없음을 가른다."""
    logs = logs_of("web-01", last)
    seen = node["last_seen_at"] if node else None
    signal = signal_of("노드 수신", NODE_SILENT, seen)
    extra = [{"label": "마지막 적재", "at": cti.iso(node["last_loaded_at"]) if node else None, "note": None}]
    if node is None:
        return collection("unknown", "노드 등록 기록 없음", signal, logs, extra)
    reception = node["reception"]
    if reception == "revoked":
        return collection("unknown", "노드 폐기됨", signal, logs, extra)
    if reception == "waiting":
        return collection("unknown", "노드 등록 대기 · 수신 전", signal, logs, extra)
    if reception == "silent":
        reason = (f"노드 수신 {ago(as_of, seen)} · 10분 넘게 끊김" if seen
                  else "노드 수신 기록 없음 · 등록 뒤 10분 넘게 수신 없음")
        return collection("no_signal", reason, signal, logs, extra)
    head = f"노드 수신 {ago(as_of, seen)}"
    if active("web-01", last, as_of):
        return collection("ok", f"{head} · 최근 1시간 로그 있음", signal, logs, extra)
    return collection("quiet", f"{head} · 최근 1시간 요청 없음", signal, logs, extra)


def console_collection(last: dict) -> dict:
    """관제 콘솔. 생존 신호가 없어 늘 미확인이다. 지금 붙은 콘솔은 화면이 실시간 연결(hello)로 보인다."""
    return collection("unknown", "생존 신호 없음 · 현재 콘솔은 실시간 연결로 표시", None, logs_of("console", last))


def data_collection(as_of, started, available: bool, heartbeats: list) -> dict:
    """데이터 노드. 마지막 탐지 실행이 신호다. 적재기 · 집행기가 마지막으로 확인한 시각을 곁들인다."""
    signal = signal_of("마지막 탐지 실행", HEARTBEAT_STALE, started)
    extra = []
    stopped = []
    for label, kind, limit in (("적재기 확인", "uploader", CHECKER_STALE), ("집행기 확인", "block_report", BLOCK_CHECKER_STALE)):
        times = [r["checked_at"] for r in heartbeats if r["kind"] == kind]
        note = None if times else ("기록 없음" if available else "생존 신호 표를 읽을 수 없음")
        if times and older(as_of, max(times), limit):
            note = "멈춤"
            stopped.append(f"{label} 중단 · 마지막 {ago(as_of, max(times))}")
        extra.append({"label": label, "at": cti.iso(max(times)) if times else None, "note": note})
    tail = "".join(f" · {x}" for x in stopped)
    if started is None:
        return collection("unknown", "탐지 실행 기록 없음" + tail, signal, [], extra)
    head = f"마지막 탐지 실행 {ago(as_of, started)}"
    if older(as_of, started, HEARTBEAT_STALE):
        return collection("no_signal", f"{head} · 15분 넘게 실행 없음" + tail, signal, [], extra)
    return collection("ok", head + tail, signal, [], extra)


def system_block(target_id: str, readable: bool, row, as_of) -> dict:
    """자원 지표. web-01 만 모은다. 읽을 수 없음 · 행 없음 · 오래됨을 가른다."""
    if target_id != WEB_NODE:
        return {"state": "not_collected", "metrics": None}
    if not readable:
        return {"state": "no_privilege", "metrics": None}
    if row is None:
        return {"state": "no_data", "metrics": None}

    def num(value, digits=1):
        return round(float(value), digits) if value is not None else None
    metrics = {"ts": cti.iso(row["ts"]), "cpu_pct": num(row["cpu_pct"]), "mem_used_pct": num(row["mem_used_pct"]),
               "disk_root_pct": num(row["disk_root_pct"]), "load1": num(row["load1"], 2)}
    return {"state": "stale" if older(as_of, row["ts"], METRICS_STALE) else "ok", "metrics": metrics}


def response_block(target_id: str, blocks, exempt: int, reports: dict, as_of=None, heartbeats_available=False) -> dict:
    """대응. 지점이 있는 대상만 적용 확인 · 실패 · 미확인 수를 낸다. 지점이 없으면 수 대신 null 이다(0 이 아니다).
    reports 는 {지점: 차단 보고 신호 행}(없으면 빈 사전).

    지점 결과(enforcement)를 내리는 쪽은 집행기뿐이다. 집행기가 멈추면 옛 '적용 확인' 이 그대로 남으므로, 생존 신호 표를 읽을 수
    있는데 그 지점의 집행기 확인(block:<지점>.checked_at)이 없거나 10분 넘게 멈췄으면 적용 · 실패를 믿지 않고 모두 미확인으로 합친다.
    까닭은 stalled 에 적는다. 표를 읽을 수 없으면(마이그레이션 전) 멈춤을 판정할 수 없어 수를 그대로 둔다."""
    point, label = POINTS.get(target_id, (None, None))
    if point is None:
        return {"point": None, "point_label": None, "applied": None, "failed": None, "unverified": None,
                "exempt": exempt, "report": None, "stalled": None}
    report = reports.get(point)
    applied = int(blocks[f"{point}_applied"]) if blocks else 0
    failed = int(blocks[f"{point}_failed"]) if blocks else 0
    unverified = int(blocks[f"{point}_unverified"]) if blocks else 0
    stalled = None
    if heartbeats_available and as_of is not None:
        if report is None:
            stalled = "집행기 확인 기록 없음"
        elif older(as_of, report["checked_at"], BLOCK_CHECKER_STALE):
            stalled = f"집행기 확인 중단 · 마지막 확인 {ago(as_of, report['checked_at'])}"
    if stalled:
        applied, failed, unverified = 0, 0, applied + failed + unverified
    return {"point": point, "point_label": label, "applied": applied, "failed": failed, "unverified": unverified,
            "exempt": exempt,
            "report": {"seen_at": cti.iso(report["seen_at"]), "checked_at": cti.iso(report["checked_at"]),
                       "problem": report["problem"]} if report else None,
            "stalled": stalled}


def vulns_block(target_id: str, available: bool, assets: dict, as_of) -> dict:
    """취약점. 자산 표에 없는 자산은 수 0 · 오래됨 · missing 이다(없다고 '취약점 0' 으로 읽히지 않게)."""
    if not available:
        return {"available": False, "assets": []}
    out = []
    for asset_id in TARGET_ASSETS[target_id]:
        row = assets.get(asset_id)
        if row is None:
            out.append({"asset_id": asset_id, "vuln_total": 0, "vuln_kev": 0, "collected_at": None,
                        "checked_at": None, "stale": True, "missing": True})
            continue
        out.append({"asset_id": asset_id, "vuln_total": int(row["vuln_total"]), "vuln_kev": int(row["vuln_kev"]),
                    "collected_at": cti.iso(row["collected_at"]), "checked_at": cti.iso(row["checked_at"]),
                    "stale": cti.is_stale(row["collected_at"], as_of), "missing": False})
    return {"available": True, "assets": out}


def latest_of(incidents: list, as_of) -> dict | None:
    """최근 중요 탐지 한 줄: 24시간 안 critical · high 중 last_ts 최신, 없으면 24시간 안 아무 사건 최신."""
    recent = [i for i in incidents if not older(as_of, i["last_ts"], LATEST_HOURS * 3600)]
    if not recent:
        return None
    pool = [i for i in recent if i["severity"] in HIGH_SEVERITIES] or recent
    best = min(pool, key=lambda i: (-i["last_ts"].timestamp(), i["incident_key"]))
    return {"incident_key": best["incident_key"], "rule_id": best["rule_id"], "rule_name": best["rule_name"],
            "severity": best["severity"], "actor_ip": best["actor_ip"], "target": best["target"],
            "last_ts": cti.iso(best["last_ts"]), "judged": bool(best["judged"])}


def tally(incidents: list, attached: dict, as_of) -> tuple[dict, dict]:
    """대상별 보안 집계와 붙이지 못한 사건 수. attached 는 {사건 키: {(대상, 나눔)}}. 대상별 rows 는 붙은 사건이다."""
    since = as_of - timedelta(seconds=WINDOW_SECONDS)
    per = {tid: {"incidents_1h": 0, "high_1h": 0, "pending": 0, "rows": [],
                 "parts": {key: {"incidents_1h": 0, "pending": 0} for key, _ in AWS_PARTS}} for tid, _, _ in TARGETS}
    unmapped = {"incidents_1h": 0, "pending": 0}
    for inc in incidents:
        pairs = attached.get(inc["incident_key"]) or set()
        fresh, pending = inc["first_ts"] >= since, not inc["judged"]
        if not pairs:
            unmapped["incidents_1h"] += fresh
            unmapped["pending"] += pending
            continue
        for tid in sorted({t for t, _ in pairs}):
            slot = per[tid]
            slot["incidents_1h"] += fresh
            slot["high_1h"] += fresh and inc["severity"] in HIGH_SEVERITIES
            slot["pending"] += pending
            slot["rows"].append(inc)
        for part in sorted({p for _, p in pairs if p}):
            per["aws-sensor"]["parts"][part]["incidents_1h"] += fresh
            per["aws-sensor"]["parts"][part]["pending"] += pending
    return per, unmapped


def security_block(target_id: str, slot: dict, as_of) -> dict:
    parts = [{"key": key, "label": label, **slot["parts"][key]} for key, label in AWS_PARTS] \
        if target_id == "aws-sensor" else []
    return {"incidents_1h": slot["incidents_1h"], "high_1h": slot["high_1h"], "pending": slot["pending"],
            "parts": parts, "latest": latest_of(slot["rows"], as_of)}


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------

async def attach_incidents(c, incidents: list) -> dict:
    """{사건 키: {(대상, 나눔)}}. 규칙 정의는 쓰인 버전만 한 번에 읽고, 발생원이 섞인 규칙의 사건만 이벤트로 고른다."""
    versions = sorted({i["rule_version"] for i in incidents})
    specs = {}
    for row in (await c.fetch(RULES_SQL, versions) if versions else []):
        specs.setdefault((row["rule_version"], row["rule_id"]), rule_spec(row))
    attached, joins, by_session, fallback = {}, [], [], {}
    for inc in incidents:
        spec = specs.get((inc["rule_version"], inc["rule_id"]))
        pairs, need = resolve(inc["target"], inc["sensors"], spec)
        attached[inc["incident_key"]] = pairs
        if need == EVENTS and inc["actor_ip"]:
            joins.append(join_item(inc, spec))
            fallback[inc["incident_key"]] = pairs
        elif need == SESSIONS:
            # 세션으로 고르지 못하면(근거에 세션 없음 · 이벤트 없음) 전처럼 Cowrie 로 둔다
            attached[inc["incident_key"]] = fallback[inc["incident_key"]] = {("aws-sensor", "cowrie")}
            item = session_item(inc)
            if item:
                by_session.append(item)
    found: dict[str, list] = {}
    if joins:
        for row in await c.fetch(JOIN_SQL, json.dumps(joins)):
            found.setdefault(row["incident_key"], []).append(row["sensor"])
    if by_session:
        for row in await c.fetch(SESSION_JOIN_SQL, json.dumps(by_session), list(SESSION_SOURCES)):
            found.setdefault(row["incident_key"], []).append(row["sensor"])
    for key, sensors in found.items():
        # 이벤트가 모르는 발생원뿐이면 앞서 정한 것(대상만 · Cowrie · 없음)을 둔다
        attached[key] = attach(sensors) or fallback[key]
    return attached


async def targets_view(c, as_of) -> dict:
    """상태판 본문. 부른 쪽이 반복 읽기 트랜잭션을 연다(시험은 기준 시각을 넘겨 경계를 본다)."""
    heartbeats_available = bool(await c.fetchval(HEARTBEATS_READABLE_SQL))
    metrics_available = bool(await c.fetchval(METRICS_READABLE_SQL))
    heartbeats = [dict(r) for r in await c.fetch(HEARTBEATS_SQL)] if heartbeats_available else []

    incidents = [dict(r) for r in await c.fetch(INCIDENTS_SQL, as_of, WINDOW_SECONDS, LATEST_HOURS)]
    attached = await attach_incidents(c, incidents)
    per, unmapped = tally(incidents, attached, as_of)

    sensors = sorted({key for rows in LOGS.values() for key, _ in rows})
    last = {r["sensor"]: r["last_at"] for r in await c.fetch(LOGS_SQL, sensors)}
    node = await c.fetchrow(NODE_SQL, WEB_NODE, as_of)
    started = await c.fetchval(DETECTOR_SQL)
    metrics = await c.fetchrow(METRICS_SQL, WEB_NODE) if metrics_available else None
    blocks = await c.fetchrow(BLOCKS_SQL, as_of)
    reports = {r["source"][len("block:"):]: r for r in heartbeats
               if r["kind"] == "block_report" and r["source"].startswith("block:")}

    # 차단 금지 대역에 드는 출발지(대상별로 서로 다른 주소 수)
    ips = sorted({i["actor_ip"] for slot in per.values() for i in slot["rows"] if i["actor_ip"]})
    exempt_ips = {r["ip"] for r in await c.fetch(EXEMPT_SQL, ips, await block_nets(c))} if ips else set()

    # 표가 있고 콘솔 역할이 모두 읽을 수 있어야 한다(cti.TABLES_SQL 이 권한까지 본다). 역할 블록만 다시 적용해 CTI 권한이 빠져도
    #   취약점 구역만 '정보 없음' 이 되고 나머지 구역은 그대로 나온다
    cti_available = bool(await c.fetchval(cti.TABLES_SQL, cti.CTI_TABLES))
    assets = {r["asset_id"]: r for r in await c.fetch(cti.ASSETS_SQL, None)} if cti_available else {}

    collections = {
        "aws-sensor": sensor_collection(as_of, heartbeats_available, heartbeats, last),
        "web-01": node_collection(as_of, node, last),
        "console": console_collection(last),
        "data-node": data_collection(as_of, started, heartbeats_available, heartbeats),
    }
    targets = []
    for tid, label, role in TARGETS:
        exempt = len({i["actor_ip"] for i in per[tid]["rows"] if i["actor_ip"] in exempt_ips})
        targets.append({
            "id": tid, "label": label, "role": role,
            "collection": collections[tid],
            "security": security_block(tid, per[tid], as_of),
            "system": system_block(tid, metrics_available, metrics, as_of),
            "response": response_block(tid, blocks, exempt, reports, as_of, heartbeats_available),
            "vulns": vulns_block(tid, cti_available, assets, as_of),
        })
    return {"as_of": cti.iso(as_of), "window_seconds": WINDOW_SECONDS,
            "heartbeats_available": heartbeats_available, "metrics_available": metrics_available,
            "targets": targets, "unmapped": unmapped}


@router.get("/api/dashboard/targets")
async def dashboard_targets(request: Request):
    """관제 대상별 상태판. 읽기 조회라 역할 검사 없이 세션 미들웨어만 둔다."""
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        return await targets_view(c, as_of)
