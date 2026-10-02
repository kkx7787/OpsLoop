# #84 운영 확인(읽기 전용): 보고서 대상 표의 콘솔 행 · 지점 이름
import asyncio, os, json, datetime
import asyncpg
import reports

async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"], server_settings={"default_transaction_read_only": "on"})
    async with c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        sec = await reports.targets_section(c, as_of - datetime.timedelta(days=1), as_of, as_of)
    for r in sec["targets"]:
        print(r["id"], r["label"], json.dumps(r["collection"], ensure_ascii=False)[:160], "| 지점:", r["response"].get("point_label"))
    await c.close()
asyncio.run(run())
