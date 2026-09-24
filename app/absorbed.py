"""같은 페이로드 흡수(규칙 v3 · incident_absorbed)의 차단 · 해제 · 후속 차단.

흡수된 인시던트는 지워져 상세가 없으므로 차단은 첫 사건에서 건다. 흡수 차단 행은 incident_key = 첫 사건 키 ·
reason = '흡수: <첫 사건 키>' 로 남고, 둘은 함께 풀거나 한 곳만 풀 때 고르는 표시다.

  함께 차단   첫 사건 차단(block_ip)에 include_absorbed 를 주면 지금 흡수된 출발지를 올리고, 후속 차단 약속
              (absorbed_blocks)을 같은 만료로 남긴다.
  후속 차단   흡수는 첫 사건이 판정 · 차단된 뒤에도 24시간 창 끝까지 붙는다(실험 DB 흡수 186건 중 175건이 첫 사건
              첫 시각보다 1시간 넘게 뒤). 탐지 역할에는 차단 목록 권한이 없으므로, 콘솔이 주기적으로 약속이 살아 있는
              첫 사건의 새 흡수 출발지를 약속과 같은 만료로 올린다(AbsorbedFollower).
  함께 해제   첫 사건 해제(unblock_ip)에 include_absorbed 를 주면 이 사건의 흡수 차단을 모두 풀고 약속도 거둔다.
  한 곳 해제  해제에 actor_ip 를 주면 그 행만 푼다. 이 사건의 살아 있는 흡수 차단 행일 때만 된다.

넣지 않는 곳
  - 다른 사건으로 살아 있는 차단: 그 사건 것으로 두고 만료도 건드리지 않는다(kept). 가져오거나 늘리면 그 사건의
    해제가 '근거 사건 변경'으로 막히거나, 그 사건이 정한 만료가 이 판단으로 바뀐다.
  - 사람이 푼 차단(released_by 있음): 누군가 그 출발지를 일부러 풀었다. 다시 걸지 않고 목록으로 보인다(skipped).
  - 차단 금지 대역(NO_BLOCK_NETS): 사설 · 예약 주소. 해시만으로 묶이므로 우리 쪽 주소가 섞여도 막지 않게 한다.
detector/triage.py 의 같은 이름 문장과 규칙이 같다(자리표시자만 다르다). 고칠 때 함께 고친다.
"""
import asyncio
import logging

log = logging.getLogger("opsloop.absorbed")

# 흡수 차단에 넣지 않는 대역. 사람이 한 곳씩 보지 않고 거는 차단이라 인프라 · 사설 · 예약 주소를 뺀다.
# 문서용 주소(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)는 시험이 쓰므로 넣지 않는다.
NO_BLOCK_NETS = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
                 "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
                 "::/127", "fc00::/7", "fe80::/10", "ff00::/8"]

FOLLOW_INTERVAL = 60        # 후속 차단 주기(초). 탐지 한 회차(5분)보다 짧다
FOLLOW_ACTOR = "system:absorbed-follow"


def absorbed_reason_tag(first_key: str) -> str:
    """흡수 차단 행의 reason. 함께 풀 때 이 값과 incident_key 로 고른다."""
    return f"흡수: {first_key}"


# 이 사건의 살아 있는 흡수 차단(충돌한 행 기준)
_OWN_LIVE = ("(blocklist.incident_key = EXCLUDED.incident_key AND blocklist.reason = EXCLUDED.reason "
             "AND blocklist.released_at IS NULL AND (blocklist.expires_at IS NULL OR blocklist.expires_at > now()))")

# $1 첫 사건 키 · $2 reason · $3 첫 사건 출발지 · $4 요청자 · $5 만료 시각 · $6 차단 금지 대역
#   빈 자리 · 만료된 행 · 누가 풀었는지 없는 풀린 행은 이 사건의 흡수 차단으로 새로 건다(집행 정보는 비운다).
#   이 사건의 살아 있는 흡수 차단은 만료만 늦춘다(앞당기지 않는다). 다른 사건의 살아 있는 차단과 사람이 푼 행은
#   건드리지 않는다. 앞의 걸러내기는 문장 시작 때의 스냅샷이고, 그 사이 바뀐 행은 충돌 절의 WHERE 가 최신 행으로
#   다시 본다. 같은 출발지가 한 첫 사건에 두 번 흡수될 수 있어(DISTINCT) 한 문장이 같은 행을 두 번 고치지 않게 하고,
#   동시에 도는 다른 흡수 차단과 행 잠금 순서가 엇갈리지 않게 주소 순으로 넣는다.
BLOCK_ABSORBED_SQL = f"""
    INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at)
    SELECT DISTINCT a.actor_ip, $2::text, $1::text, $4::text, $5::timestamptz
    FROM incident_absorbed a
    WHERE a.first_key = $1 AND a.kind = 'absorbed' AND a.actor_ip IS NOT NULL
      AND a.actor_ip IS DISTINCT FROM $3::inet
      AND NOT (a.actor_ip <<= ANY($6::text[]::inet[]))
      AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.actor_ip = a.actor_ip
                      AND b.released_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now())
                      AND (b.incident_key IS DISTINCT FROM $1 OR b.reason IS DISTINCT FROM $2))
      AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.actor_ip = a.actor_ip
                      AND b.released_at IS NOT NULL AND b.released_by IS NOT NULL)
    ORDER BY a.actor_ip
    ON CONFLICT (actor_ip) DO UPDATE SET
        reason       = EXCLUDED.reason,
        incident_key = EXCLUDED.incident_key,
        requested_by = CASE WHEN {_OWN_LIVE} THEN blocklist.requested_by ELSE EXCLUDED.requested_by END,
        expires_at   = EXCLUDED.expires_at,
        method       = CASE WHEN {_OWN_LIVE} THEN blocklist.method END,
        enforced_at  = CASE WHEN {_OWN_LIVE} THEN blocklist.enforced_at END,
        enforce_note = CASE WHEN {_OWN_LIVE} THEN blocklist.enforce_note END,
        created_at   = CASE WHEN {_OWN_LIVE} THEN blocklist.created_at ELSE now() END,
        released_at  = NULL,
        released_by  = NULL
    WHERE (blocklist.released_at IS NULL AND blocklist.expires_at IS NOT NULL AND blocklist.expires_at <= now())
       OR (blocklist.released_at IS NOT NULL AND blocklist.released_by IS NULL)
       OR ({_OWN_LIVE} AND blocklist.expires_at IS NOT NULL AND blocklist.expires_at < EXCLUDED.expires_at)"""

# 흡수 출발지의 지금 상태. 한 출발지는 한 칸에만 든다(앞의 것이 먼저).
#   blocked 이 사건 흡수 차단으로 살아 있다 · kept 다른 사건 차단으로 살아 있다 · skipped 사람이 풀었다(목록) ·
#   unblockable 차단 금지 대역 · open 그 밖(아직 넣지 않았다)
# $1 첫 사건 키 · $2 reason · $3 첫 사건 출발지 · $4 차단 금지 대역 · $5 skipped 목록 최대 수
ABSORBED_STATE_SQL = """
    WITH s AS (
        SELECT DISTINCT ON (a.actor_ip) a.actor_ip,
               CASE WHEN b.actor_ip IS NOT NULL AND b.released_at IS NULL
                         AND (b.expires_at IS NULL OR b.expires_at > now())
                    THEN CASE WHEN b.incident_key = $1 AND b.reason = $2 THEN 'blocked' ELSE 'kept' END
                    WHEN b.released_at IS NOT NULL AND b.released_by IS NOT NULL THEN 'skipped'
                    WHEN a.actor_ip <<= ANY($4::text[]::inet[]) THEN 'unblockable'
                    ELSE 'open' END AS state
        FROM incident_absorbed a LEFT JOIN blocklist b ON b.actor_ip = a.actor_ip
        WHERE a.first_key = $1 AND a.kind = 'absorbed' AND a.actor_ip IS NOT NULL
          AND a.actor_ip IS DISTINCT FROM $3::inet
        ORDER BY a.actor_ip)
    SELECT count(*) FILTER (WHERE state = 'blocked') AS blocked,
           count(*) FILTER (WHERE state = 'kept') AS kept,
           count(*) FILTER (WHERE state = 'skipped') AS skipped_total,
           coalesce((array_agg(host(actor_ip) ORDER BY actor_ip) FILTER (WHERE state = 'skipped'))[1:$5],
                    '{}') AS skipped,
           count(*) FILTER (WHERE state = 'unblockable') AS unblockable,
           count(*) FILTER (WHERE state = 'open') AS open
    FROM s"""

# $1 첫 사건 키 · $2 해제자 · $3 reason. 이 사건의 흡수 차단으로 살아 있는 행만 푼다. 뒤에 다른 사건이 다시 걸어
# 근거 사건 · 사유가 바뀐 행은 그 사건의 차단이라 건드리지 않는다.
RELEASE_ABSORBED_SQL = """
    UPDATE blocklist SET released_at = now(), released_by = $2
    WHERE incident_key = $1 AND reason = $3 AND released_at IS NULL
      AND (expires_at IS NULL OR expires_at > clock_timestamp())"""

# 후속 차단 약속. 함께 차단할 때 남기고(살아 있으면 만료는 늦추기만 한다) 함께 풀 때 거둔다.
# 돌려주는 만료가 흡수 차단의 만료다. $1 첫 사건 키 · $2 만료 시간(시) · $3 요청자
_FOLLOW_LIVE = "(absorbed_blocks.released_at IS NULL AND absorbed_blocks.expires_at > now())"
FOLLOW_UPSERT_SQL = f"""
    INSERT INTO absorbed_blocks (first_key, expires_at, requested_by)
    VALUES ($1, now() + make_interval(hours => $2::int), $3)
    ON CONFLICT (first_key) DO UPDATE SET
        expires_at   = CASE WHEN {_FOLLOW_LIVE} AND absorbed_blocks.expires_at > EXCLUDED.expires_at
                            THEN absorbed_blocks.expires_at ELSE EXCLUDED.expires_at END,
        requested_by = CASE WHEN {_FOLLOW_LIVE} THEN absorbed_blocks.requested_by ELSE EXCLUDED.requested_by END,
        created_at   = CASE WHEN {_FOLLOW_LIVE} THEN absorbed_blocks.created_at ELSE now() END,
        released_at  = NULL,
        released_by  = NULL
    RETURNING expires_at"""

FOLLOW_RELEASE_SQL = """
    UPDATE absorbed_blocks SET released_at = now(), released_by = $2
    WHERE first_key = $1 AND released_at IS NULL AND expires_at > now()"""

FOLLOW_STATE_SQL = """
    SELECT expires_at, requested_by FROM absorbed_blocks
    WHERE first_key = $1 AND released_at IS NULL AND expires_at > now()"""

# 후속 차단할 것이 있는 약속. 새로 흡수된 출발지 가운데 아직 살아 있는 차단도, 사람이 푼 기록도 없고 차단 금지 대역이
# 아닌 것이 하나라도 있는 첫 사건만 고른다. 없으면 아무것도 쓰지 않는다(감사 · 조치 기록이 매분 쌓이지 않는다).
FOLLOW_DUE_SQL = """
    SELECT f.first_key, f.expires_at, f.requested_by, host(i.actor_ip) AS own
    FROM absorbed_blocks f JOIN incidents i ON i.incident_key = f.first_key
    WHERE f.released_at IS NULL AND f.expires_at > now()
      AND EXISTS (
          SELECT 1 FROM incident_absorbed a
          WHERE a.first_key = f.first_key AND a.kind = 'absorbed' AND a.actor_ip IS NOT NULL
            AND a.actor_ip IS DISTINCT FROM i.actor_ip
            AND NOT (a.actor_ip <<= ANY($1::text[]::inet[]))
            AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.actor_ip = a.actor_ip
                            AND ((b.released_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now()))
                                 OR (b.released_at IS NOT NULL AND b.released_by IS NOT NULL))))
    ORDER BY f.first_key"""

# 판정 뒤에 흡수됐는데 차단이 없는 출발지(대시보드). 첫 사건의 마지막 판정이 위협이고, 첫 판정보다 뒤에 흡수됐고,
# 살아 있는 차단이 없고, 차단 금지 대역이 아닌 것. 함께 차단을 고르지 않았으면(후속 차단 약속이 없으면) 여기 남는다
UNBLOCKED_AFTER_VERDICT_SQL = """
    WITH judged AS (
        SELECT DISTINCT ON (v.incident_key) v.incident_key, v.verdict,
               min(v.created_at) OVER (PARTITION BY v.incident_key) AS first_verdict_at
        FROM verdicts v
        WHERE v.incident_key IN (SELECT first_key FROM incident_absorbed WHERE kind = 'absorbed')
        ORDER BY v.incident_key, v.created_at DESC, v.id DESC)
    SELECT count(DISTINCT a.actor_ip) AS sources, count(DISTINCT a.first_key) AS incidents,
           min(a.first_key) AS first_key
    FROM incident_absorbed a
    JOIN judged j ON j.incident_key = a.first_key AND j.verdict = 'threat'
    JOIN incidents i ON i.incident_key = a.first_key
    WHERE a.kind = 'absorbed' AND a.actor_ip IS NOT NULL AND a.actor_ip IS DISTINCT FROM i.actor_ip
      AND a.recorded_at > j.first_verdict_at
      AND NOT (a.actor_ip <<= ANY($1::text[]::inet[]))
      AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.actor_ip = a.actor_ip AND b.released_at IS NULL
                      AND (b.expires_at IS NULL OR b.expires_at > now()))"""


async def block_absorbed(c, first_key: str, own_ip, who: str, expires_at) -> dict:
    """흡수 출발지를 올리고 상태를 센다. 같은 트랜잭션 안에서 부른다(opsloop.actor 는 부른 쪽이 넘긴다)."""
    tag = absorbed_reason_tag(first_key)
    await c.execute(BLOCK_ABSORBED_SQL, first_key, tag, own_ip, who, expires_at, NO_BLOCK_NETS)
    return dict(await c.fetchrow(ABSORBED_STATE_SQL, first_key, tag, own_ip, NO_BLOCK_NETS, 20))


def absorbed_note(state: dict) -> str:
    """조치 이력에 붙이는 한 줄. 흡수 출발지를 함께 다룬 차단을 이력에서 알아보게 한다."""
    parts = [f"흡수 출발지 {state['blocked']}곳 함께 차단"]
    if state.get("kept"):
        parts.append(f"{state['kept']}곳은 다른 사건으로 차단 중")
    if state.get("skipped_total"):
        parts.append(f"사람이 푼 {state['skipped_total']}곳 제외")
    if state.get("unblockable"):
        parts.append(f"차단 금지 대역 {state['unblockable']}곳 제외")
    return "[" + " · ".join(parts) + "]"


class AbsorbedFollower:
    """후속 차단 루프. 약속이 살아 있는 첫 사건의 새 흡수 출발지를 약속과 같은 만료로 차단 목록에 올린다.

    콘솔 역할로 돈다(탐지 역할에는 차단 목록 권한이 없다). 여러 콘솔이 떠 있어도 한 번에 하나만 돈다(권고 잠금).
    올린 곳이 있으면 첫 사건에 메모 조치(note)를 남긴다. 사건 상태는 바꾸지 않는다(판정된 사건이 다시 열리지 않는다).
    """

    def __init__(self, pool, interval: int = FOLLOW_INTERVAL):
        self.pool = pool
        self.interval = interval
        self.task: asyncio.Task | None = None

    async def start(self):
        self.task = asyncio.create_task(self.loop(), name="absorbed-follow")

    async def stop(self):
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
            self.task = None

    async def loop(self):
        while True:
            try:
                async with self.pool.acquire() as c:
                    await self.step(c)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # 표가 아직 없거나(마이그레이션 전) 권한이 빠져도 콘솔의 다른 기능은 떠야 한다
                log.warning("흡수 후속 차단 실패: %s", type(error).__name__)
            await asyncio.sleep(self.interval)

    async def step(self, c) -> list[tuple[str, int]]:
        """한 회차. [(첫 사건 키, 새로 올린 곳 수)] 를 돌려준다."""
        done = []
        async with c.transaction():
            if not await c.fetchval("SELECT pg_try_advisory_xact_lock(hashtext('opsloop.absorbed_follow'))"):
                return done
            await c.execute("SELECT set_config('opsloop.actor', $1, true)", FOLLOW_ACTOR)
            for f in await c.fetch(FOLLOW_DUE_SQL, NO_BLOCK_NETS):
                tag = absorbed_reason_tag(f["first_key"])
                before = await c.fetchval(
                    "SELECT count(*) FROM blocklist WHERE incident_key = $1 AND reason = $2 "
                    "AND released_at IS NULL AND (expires_at IS NULL OR expires_at > now())", f["first_key"], tag)
                state = await block_absorbed(c, f["first_key"], f["own"], f["requested_by"] or FOLLOW_ACTOR,
                                             f["expires_at"])
                added = state["blocked"] - before
                if added > 0:
                    await c.execute(
                        "INSERT INTO actions (incident_key, action, operator, note) VALUES ($1, 'note', $2, $3)",
                        f["first_key"], FOLLOW_ACTOR,
                        f"[흡수 후속 차단 {added}곳 · 만료 {f['expires_at'].isoformat(timespec='minutes')}]")
                    done.append((f["first_key"], added))
        for key, added in done:
            log.info("흡수 후속 차단 %s %d곳", key, added)
        return done
