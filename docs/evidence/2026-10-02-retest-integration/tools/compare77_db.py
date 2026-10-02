# #77 통합 대조의 DB 쪽 (읽기 전용). 대시보드 요약 · 상태판 카드 · 차단 목록 화면이 쓰는 것과 같은 SQL · 함수로 센다.
#   실행(콘솔 A 컨테이너 안). 표준 출력은 JSON 한 덩이다:
#   ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -w /app opsloop-api python3 -" < compare77_db.py > c-db.json
#   blocks          대시보드 요약 blocks (block_points.BLOCK_STATES_SQL, 종합 상태)
#   blocks_by_point 대시보드 요약 blocks_by_point · 대상 카드 대응 (targets.BLOCKS_SQL + targets.point_counts)
#   live            살아 있는 집행 대상 행(해제 전 · 만료 전 · 만료 있음 · 집행 제외 아님 · IPv4)과 지점별 결과
#   want            그 행에서 만든 지점별 주소 집합(관문 = points 에 gateway, 내부 방화벽 = 모두)
#   monitor         관제 이상 띠 항목(targets.monitor_view)
import asyncio, json, os
import asyncpg
import block_points, targets


def plain(v):
    if hasattr(v, "isoformat"):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if isinstance(v, dict):
        return {k: plain(x) for k, x in v.items()}
    return v


async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"],
                              server_settings={"default_transaction_read_only": "on",
                                               "application_name": "opsloop-retest-ro"})
    async with c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        states = await c.fetchrow(block_points.BLOCK_STATES_SQL, as_of)
        by_point = await c.fetchrow(targets.BLOCKS_SQL, as_of)
        hb_ok = bool(await c.fetchval(targets.HEARTBEATS_READABLE_SQL))
        hbs = [dict(r) for r in await c.fetch(targets.HEARTBEATS_SQL)] if hb_ok else []
        reports = targets.reports_of(hbs)
        rows = await c.fetch("""
            SELECT host(actor_ip) AS ip, points, expires_at, enforced_at, method, enforce_note, enforcement, incident_key
              FROM blocklist
             WHERE released_at IS NULL AND expires_at IS NOT NULL AND expires_at > $1 AND family(actor_ip) = 4
               AND (enforce_note IS NULL OR enforce_note NOT LIKE $2)
             ORDER BY actor_ip""", as_of, block_points.ENFORCE_EXCLUDED + "%")
        mon = await targets.monitor_view(c, as_of)
    live = []
    for r in rows:
        e = r["enforcement"]
        e = json.loads(e) if isinstance(e, str) else (e or {})
        live.append({"ip": r["ip"], "points": list(r["points"]), "expires_at": r["expires_at"],
                     "gateway": (e.get("gateway") or {}).get("state"), "fw": (e.get("fw") or {}).get("state"),
                     "fw_since": (e.get("fw") or {}).get("since"), "enforced_at": r["enforced_at"],
                     "method": r["method"], "enforce_note": r["enforce_note"], "incident_key": r["incident_key"]})
    out = {
        "as_of": as_of,
        "blocks": {"total": states["total"], **{k: states[k] for k in block_points.STATES}},
        "blocks_by_point": [targets.point_counts(p, by_point, reports.get(p), as_of, hb_ok) for p in targets.POINT_LABELS],
        "block_reports": [{k: h.get(k) for k in ("source", "seen_at", "checked_at", "problem")}
                          for h in hbs if str(h.get("source", "")).startswith("block:")],
        "live": live,
        "want": {"gateway": sorted(x["ip"] for x in live if "gateway" in x["points"]),
                 "fw": sorted(x["ip"] for x in live)},
        "monitor": [{k: i.get(k) for k in ("key", "level", "label", "reason", "count")} for i in mon["items"]],
    }
    print(json.dumps(plain(out), ensure_ascii=False, indent=1, default=str))
    await c.close()

asyncio.run(run())
