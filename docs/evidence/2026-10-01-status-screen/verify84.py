# #84 운영 확인(읽기 전용): 대상 카드 이름 · 머리 · 수집 · 대응 배지 값 · 콘솔 DB 연결 · 띠 · 연결 이름표
import asyncio, os, json
import asyncpg
import targets

def short(v, n=160):
    s = json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + "…"

async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"], server_settings={"default_transaction_read_only": "on"})
    async with c.transaction(readonly=True):
        as_of = await c.fetchval("SELECT now()")
    print("기준", as_of)
    print("연결 이름표:", [dict(r) for r in await c.fetch(
        "SELECT usename, application_name, count(*) n FROM pg_stat_activity WHERE datname = current_database() GROUP BY 1,2 ORDER BY 1,2")])
    async with c.transaction(isolation="repeatable_read", readonly=True):
        tv = await targets.targets_view(c, as_of, True)
        mv = await targets.monitor_view(c, as_of)
    print("대상 카드 키:", sorted(tv.keys()))
    for t in tv["targets"]:
        col = t.get("collection") or {}
        print(f"- {t.get('id')} | {t.get('name')} | group={t.get('group')} | role={short(t.get('role'), 120)}")
        print(f"    수집 state={col.get('state')} reason={short(col.get('reason'), 140)}")
        if col.get("db_links") is not None or t.get("id") == "console":
            print(f"    db_links={short(col.get('db_links'), 300)}")
        r = t.get("response")
        if r: print(f"    response={short({k: r.get(k) for k in ('point','state','checking','delayed','failed','removing','stalled','report_issue','requested') if k in r}, 300)}")
        s = t.get("system")
        if s: print(f"    system state={s.get('state')}")
        logs = col.get("logs") or []
        if logs: print(f"    logs={[l.get('label') or l.get('key') for l in logs]}")
    print("띠:", short(mv, 1200))
    await c.close()
asyncio.run(run())
