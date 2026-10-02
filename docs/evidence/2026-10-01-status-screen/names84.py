# #84 운영 확인(읽기 전용): 대상 카드 이름 칸 · 집행 지점 이름 · 보고서 콘솔 행
import asyncio, os, json
import asyncpg
import targets, reports

async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"], server_settings={"default_transaction_read_only": "on"})
    async with c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        tv = await targets.targets_view(c, as_of, True)
    t0 = tv["targets"][0]
    print("카드 키:", sorted(t0.keys()))
    for t in tv["targets"]:
        print(t["id"], {k: t.get(k) for k in ("label", "title", "head", "state") if k in t})
    print("지점 이름:", {k: v for k, v in vars(targets).items() if k.endswith("_NAME") and isinstance(v, str)})
    print("보고서 함수:", [n for n in dir(reports) if "console" in n.lower() or "target" in n.lower()][:20])
    await c.close()
asyncio.run(run())
