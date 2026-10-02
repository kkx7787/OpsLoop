# 재시험(콘솔 이중화 정지 3회) 읽기 전용: 콘솔 역할 연결의 출발지(client_addr) · 이름표 · 상태별 수.
#   살아 있는 콘솔 컨테이너에서 'docker exec -i -w /app opsloop-api python3 -' 로 돈다(콘솔 역할은 자기 역할 세션의 client_addr 를 본다).
#   이 조회 연결은 이름표 retest-readonly 이고 결과에서 뺀다(pid). 읽기 전용 세션 · 읽기 전용 트랜잭션. 비밀값은 찍지 않는다
import asyncio
import os

import asyncpg

SQL = """SELECT coalesce(host(client_addr), '-') AS addr, coalesce(nullif(application_name, ''), '(none)') AS app,
                coalesce(state, '-') AS state, count(*) AS n
         FROM pg_stat_activity
         WHERE datname = current_database() AND usename = current_user AND pid <> pg_backend_pid()
         GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"""


async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"], timeout=10,
                              server_settings={"default_transaction_read_only": "on", "application_name": "retest-readonly"})
    try:
        async with c.transaction(readonly=True):
            at = await c.fetchval("SELECT now()")
            rows = await c.fetch(SQL)
    finally:
        await c.close()
    print("기준", at.isoformat(), "· 조회한 콘솔", os.environ.get("OPSLOOP_WORKER") or "-")
    for r in rows:
        print(r["addr"], r["app"], r["state"], r["n"], sep="\t")


asyncio.run(run())
