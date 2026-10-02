# 요청 → 적재 → 사건 실측 (읽기 전용, #73 probe73.py 와 같은 방식으로 1초마다 본다)
#   실행(콘솔 A 컨테이너 안):
#   ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -e UA=<UA> -e ACTOR=203.0.113.10 -w /app opsloop-api python3 -" < probe_detect.py
#   UA 의 요청이 web-01 이벤트로 들어온 시각과 ACTOR 의 새 사건(R102 · R105)이 DB 에 보인 시각을 남긴다.
#   기준 시각 T0 = 이 스크립트 시작 시각. TIMEOUT(초, 기본 900) 안에 R102 · R105 가 모두 보이면 10초 더 보고 끝낸다.
import asyncio, os, time
from datetime import datetime, timezone
import asyncpg

UA = os.environ["UA"]
ACTOR = os.environ.get("ACTOR", "203.0.113.10")
TIMEOUT = int(os.environ.get("TIMEOUT", "900"))
WANT = {"R102", "R105"}


def t(dt):
    return dt.astimezone(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z" if dt else "-"


async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"],
                              server_settings={"default_transaction_read_only": "on",
                                               "application_name": "opsloop-retest-ro"})
    async with c.transaction(readonly=True):
        t0 = await c.fetchval("SELECT now()")
    print("T0", t(t0), "· UA", UA, "· 출발지", ACTOR, flush=True)
    seen_ev, seen_inc, done_at, last_n = {}, {}, None, -1
    start = time.time()
    while time.time() - start < TIMEOUT:
        async with c.transaction(isolation="repeatable_read", readonly=True):
            now = await c.fetchval("SELECT now()")
            ev = await c.fetchrow("""SELECT count(*) AS n, min(ts) AS first, max(ts) AS last FROM events
                                     WHERE sensor = 'web-01' AND user_agent = $1 AND ts >= $2::timestamptz - interval '5 minutes'""", UA, t0)
            incs = await c.fetch("""SELECT incident_key, rule_id, rule_version, severity, signal_count, first_ts, created_at
                                    FROM incidents WHERE actor_ip = $1::inet AND created_at >= $2 ORDER BY created_at""", ACTOR, t0)
        if ev["n"] != last_n:
            last_n = ev["n"]
            seen_ev[ev["n"]] = now
            print(f"{t(now)} 이벤트 {ev['n']}건 (nginx 첫 {t(ev['first'])} · 끝 {t(ev['last'])})", flush=True)
        for r in incs:
            if r["incident_key"] not in seen_inc:
                seen_inc[r["incident_key"]] = (now, r)
                print(f"{t(now)} 사건 보임 {r['incident_key']} · {r['severity']} · 신호 {r['signal_count']} · "
                      f"first_ts {t(r['first_ts'])} · created_at {t(r['created_at'])}", flush=True)
        if done_at is None and WANT <= {r["rule_id"] for _, r in seen_inc.values()}:
            done_at = time.time()
        if done_at and time.time() - done_at > 10:
            break
        await asyncio.sleep(1)
    async with c.transaction(isolation="repeatable_read", readonly=True):
        runs = await c.fetch("""SELECT rule_version, started_at, finished_at, incidents FROM detector_runs
                                WHERE started_at >= $1::timestamptz - interval '2 minutes' AND rule_version IN ('w2', 'c1')
                                ORDER BY started_at LIMIT 12""", t0)
        node = await c.fetchrow("SELECT last_loaded_at FROM nodes WHERE node_id = 'web-01'")
    print("== 탐지 실행(w2 · c1, T0 2분 전부터)")
    for r in runs:
        print(f"   {r['rule_version']} 시작 {t(r['started_at'])} · 끝 {t(r['finished_at'])} · 사건 {r['incidents']}")
    print("== web-01 마지막 적재", t(node["last_loaded_at"]) if node else "-")
    print("== 요약 (요청 → 사건 = created_at − first_ts, 9/29 과 같은 기준)")
    for key, (seen, r) in seen_inc.items():
        print(f"   {r['rule_id']} {r['rule_version']} {r['severity']} 신호 {r['signal_count']} | "
              f"요청 → 사건 {(r['created_at'] - r['first_ts']).total_seconds():.1f}s | "
              f"요청 → DB 에 보임 {(seen - r['first_ts']).total_seconds():.1f}s | {key}")
    if not WANT <= {r["rule_id"] for _, r in seen_inc.values()}:
        print(f"!! {TIMEOUT}초 안에 R102 · R105 가 모두 보이지 않았다: {[k for k in seen_inc]}")
    await c.close()

asyncio.run(run())
