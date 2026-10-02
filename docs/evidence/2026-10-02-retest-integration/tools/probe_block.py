# 차단 행 변화 관측 (읽기 전용). 1초마다 ACTOR 의 blocklist 행을 읽어 바뀔 때마다 DB 시각과 함께 찍는다.
#   실행(콘솔 A 컨테이너 안):
#   ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -e ACTOR=203.0.113.10 -w /app opsloop-api python3 -" < probe_block.py
#   차단 요청(released_at 비움) → 지점별 결과(enforcement) 대기 → 확인 → 해제 → 빠짐 확인 전(removing) → 비움 까지 본다.
#   해제된 뒤 enforcement 가 비면 30초 더 보고 끝낸다. TIMEOUT(초, 기본 2400).
import asyncio, json, os, time
from datetime import timezone
import asyncpg

ACTOR = os.environ.get("ACTOR", "203.0.113.10")
TIMEOUT = int(os.environ.get("TIMEOUT", "2400"))
COLS = ("points", "expires_at", "released_at", "enforced_at", "method", "enforce_note", "enforcement")


def t(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def view(row):
    if row is None:
        return None
    out = {}
    for k in COLS:
        v = row[k]
        if k == "enforcement" and v is not None:
            v = json.loads(v) if isinstance(v, str) else v
        out[k] = t(v) if hasattr(v, "astimezone") else (list(v) if k == "points" and v is not None else v)
    return out


async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"],
                              server_settings={"default_transaction_read_only": "on",
                                               "application_name": "opsloop-retest-ro"})
    async with c.transaction(readonly=True):
        t0 = await c.fetchval("SELECT now()")
    print("T0", t(t0), "· 출발지", ACTOR, flush=True)
    prev, live_seen, done_at, start = "∅", False, None, time.time()
    while time.time() - start < TIMEOUT:
        async with c.transaction(isolation="repeatable_read", readonly=True):
            now = await c.fetchval("SELECT now()")
            row = await c.fetchrow(f"SELECT {', '.join(COLS)} FROM blocklist WHERE actor_ip = $1::inet", ACTOR)
        v = view(row)
        key = json.dumps(v, ensure_ascii=False, sort_keys=True)
        if key != prev:
            prev = key
            print(t(now), key, flush=True)
        if v and v["released_at"] is None:
            live_seen = True
        if live_seen and v and v["released_at"] is not None and v["enforcement"] is None and done_at is None:
            done_at = time.time()
        if done_at and time.time() - done_at > 30:
            break
        await asyncio.sleep(1)
    async with c.transaction(isolation="repeatable_read", readonly=True):
        audit = await c.fetch("""SELECT ts, eventid, actor, detail FROM audit_log
                                 WHERE eventid LIKE 'console.block.%' AND detail LIKE $1 AND ts >= $2 ORDER BY ts""",
                              f"%ip={ACTOR} %", t0)
        acts = await c.fetch("""SELECT a.created_at, a.action, a.operator, a.incident_key FROM actions a
                                JOIN incidents i USING (incident_key)
                                WHERE i.actor_ip = $1::inet AND a.created_at >= $2 ORDER BY a.created_at""", ACTOR, t0)
        verdicts = await c.fetch("""SELECT v.created_at, v.incident_key, v.verdict, v.operator, v.proposed FROM verdicts v
                                    JOIN incidents i USING (incident_key)
                                    WHERE i.actor_ip = $1::inet AND v.created_at >= $2 ORDER BY v.created_at""", ACTOR, t0)
    print("== 감사(console.block.*)")
    for r in audit:
        print("  ", t(r["ts"]), r["eventid"], r["actor"], r["detail"])
    print("== 조치")
    for r in acts:
        print("  ", t(r["created_at"]), r["action"], r["operator"], r["incident_key"])
    print("== 판정")
    for r in verdicts:
        print("  ", t(r["created_at"]), r["verdict"], r["operator"], "제안", r["proposed"], r["incident_key"])
    await c.close()

asyncio.run(run())
