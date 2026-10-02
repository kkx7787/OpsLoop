# 요청 → 로그 API 표시 실측 + 운영 경로 가림 확인(읽기 전용). 가짜 값 원문은 출력하지 않는다.
import asyncio, os, json, time, datetime as dt
import asyncpg
import node_logs

UA = "opsloop-latency-probe/0930"
FAKE = ("probefake0930keyvalue", "probefake0930pw")
T_SEND = float(os.environ["T_SEND"])

async def run():
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=1, max_size=2,
                                     server_settings={"default_transaction_read_only": "on"})
    async with pool.acquire() as c:
        seen = None
        polls = 0
        while time.time() - T_SEND < 240:
            polls += 1
            async with c.transaction(isolation="repeatable_read", readonly=True):
                r = await node_logs.logs_view(c, "web-01", kind="web", src_ip="203.0.113.10", limit=20)
            hit = [it for it in r["items"] if it.get("user_agent") == UA]
            if hit:
                seen = time.time(); it = hit[0]; break
            await asyncio.sleep(1)
        if not seen:
            print("240초 안에 보이지 않음", polls); return
        ts = dt.datetime.fromisoformat(it["ts"]).timestamp()
        dumped = json.dumps(r, ensure_ascii=False)
        async with c.transaction(readonly=True):
            raw = await c.fetchval("SELECT url FROM events WHERE sensor='web-01' AND user_agent=$1 ORDER BY ts DESC LIMIT 1", UA)
        print(f"보낸 시각(공격자)   {dt.datetime.fromtimestamp(T_SEND):%H:%M:%S.%f}"[:-3])
        print(f"nginx 요청 시각     {dt.datetime.fromtimestamp(ts):%H:%M:%S.%f}"[:-3], f"(보낸 뒤 {ts - T_SEND:+.2f}s)")
        print(f"마지막 적재 시각    {r['times']['loaded_at']}")
        print(f"API 에 보인 시각    {dt.datetime.fromtimestamp(seen):%H:%M:%S.%f}"[:-3], f"→ 요청 → API 표시 {seen - T_SEND:.1f}s (조회 {polls}회)")
        print(f"응답 url           {it['url']} · 응답 코드 {it['http_status']}")
        print(f"DB 원문에 가짜 값 있음 {all(f in (raw or '') for f in FAKE)} · 응답 전체에 가짜 값 있음 {any(f in dumped for f in FAKE)}")
        # 사건이 생기지 않는지: 보인 뒤 90초(탐지 회차 한 번 이상) 기다려 확인
        while time.time() - seen < 90:
            await asyncio.sleep(5)
        async with c.transaction(readonly=True):
            n = await c.fetchval("SELECT count(*) FROM incidents WHERE actor_ip = '203.0.113.10' AND created_at > to_timestamp($1)", T_SEND)
            last = await c.fetchval("SELECT max(created_at) FROM incidents")
        print(f"보낸 뒤 203.0.113.10 새 사건 {n}건 (확인 {dt.datetime.now():%H:%M:%S}, 전체 최근 사건 생성 {last:%m-%d %H:%M:%S})")
    await pool.close()

asyncio.run(run())
