# #73 운영 확인(읽기 전용). 비밀 원문은 출력하지 않는다 — 개수와 가린 모양만.
import asyncio, os, json, re, time, statistics
import asyncpg
from fastapi import HTTPException
import main, node_logs, targets

RO = {"default_transaction_read_only": "on"}
KEYV = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|token|access_token|api_?key|secret|session(?:id)?|sid)\s*[=:]\s*(?!…)([^\s&;,\"']+)")
BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+(?!…)([A-Za-z0-9._~+/\-]{6,}=*)")
FIELDS = ("url", "user_agent", "message", "http_method", "input")

def secrets_in(s):
    """원문 줄에서 비밀로 볼 값들(쿼리 값 4자 이상 · key=값 · JWT · 32자 이상 16진 · Bearer)."""
    out = set()
    if not s: return out
    if "?" in s:
        for part in s.split("?", 1)[1].split("&"):
            if "=" in part and len(part.split("=", 1)[1]) >= 4: out.add(part.split("=", 1)[1])
    out |= {m.group(2) for m in KEYV.finditer(s) if len(m.group(2)) >= 4}
    out |= set(node_logs.JWT.findall(s)) | set(node_logs.HEX.findall(s)) | {m.group(1) for m in BEARER.finditer(s)}
    return out

def residue(s):
    """가린 뒤 남은 비밀 모양 수."""
    if not s: return {}
    h = {}
    for name, rx in (("key=값", KEYV), ("jwt", node_logs.JWT), ("hex32", node_logs.HEX), ("bearer", BEARER)):
        n = len(rx.findall(s))
        if n: h[name] = n
    if "?" in s:
        n = sum(1 for p in s.split("?", 1)[1].split("&") if "=" in p and p.split("=", 1)[1] not in ("", node_logs.QMASK))
        if n: h["쿼리값"] = n
    return h

def shape(s, n=3):
    return re.sub(r"=([^&…]{%d})[^&]*" % n, r"=\1***", s or "")[:120]

async def timed(c, fn, *a, **k):
    ts = []
    res = None
    for _ in range(5):
        t = time.perf_counter()
        try:
            async with c.transaction(isolation="repeatable_read", readonly=True):
                res = await fn(c, *a, **k)
        except HTTPException as e:
            res = e
        ts.append((time.perf_counter() - t) * 1000)
    return res, statistics.median(ts), max(ts)

async def run():
    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=1, max_size=3, server_settings=RO)
    main.app.state.pool = pool
    key = node_logs.line_id_key()
    async with pool.acquire() as c:
        print("== A. 장비별 로그 API (중앙값 · 최대 ms, 5회)")
        for dev in ("web-01", "aws-sensor", "console", "data-node", "web-99"):
            r, med, mx = await timed(c, node_logs.logs_view, dev)
            if isinstance(r, HTTPException):
                print(f"  {dev:11s} {r.status_code} {r.detail} | {med:.1f} · {mx:.1f}")
            else:
                kinds = {}
                for it in r["items"]: kinds[it["kind"]] = kinds.get(it["kind"], 0) + 1
                print(f"  {dev:11s} 200 줄 {len(r['items'])} {kinds} future {r['future']} | {med:.1f} · {mx:.1f}")
                print(f"     시각: {json.dumps(r['times'], ensure_ascii=False)[:400]}")
                web01 = r
        srcs = {}
        for it in web01["items"]: srcs[it["src_ip"]] = srcs.get(it["src_ip"], 0) + 1
        top = max(srcs, key=srcs.get) if srcs else None
        for label, kw in (("kind=web", {"kind": "web"}), ("kind=ssh", {"kind": "ssh"}), ("status=404", {"status": 404}),
                          (f"src_ip=최다출발지({srcs.get(top)}줄)", {"src_ip": top}), ("limit=200", {"limit": 200})):
            r, med, mx = await timed(c, node_logs.logs_view, "web-01", **kw)
            print(f"  web-01 {label:28s} 줄 {len(r['items'])} | {med:.1f} · {mx:.1f}")

        print("== B. web-01 응답 가림 대조 (limit=200 응답 ↔ 같은 줄의 DB 원문)")
        async with c.transaction(isolation="repeatable_read", readonly=True):
            resp = await node_logs.logs_view(c, "web-01", limit=200)
            raw = await c.fetch("""SELECT line_hash, url, user_agent, message FROM events
                WHERE sensor = 'web-01' AND provenance = 'real' AND ts >= now() - interval '7 days'
                  AND (eventid LIKE 'nginx.%' OR eventid LIKE 'sshd.%')""")
        byid = {node_logs.line_id(r["line_hash"], key): r for r in raw}
        matched = with_q = with_secret = leaks = masked_rows = 0
        for it in resp["items"]:
            r = byid.get(it["id"])
            if r is None: continue
            matched += 1
            toks = set()
            for f in ("url", "user_agent", "message"): toks |= secrets_in(r[f])
            if r["url"] and "?" in r["url"]: with_q += 1
            if toks: with_secret += 1
            dumped = json.dumps({k: v for k, v in it.items() if k != "id"}, ensure_ascii=False)
            if node_logs.MASK in dumped or "=" + node_logs.QMASK in dumped: masked_rows += 1
            for t in toks:
                if t in dumped:
                    leaks += 1
                    print("   누출?", it["eventid"], shape(it.get("url")))
        print(f"  응답 줄 {len(resp['items'])} · 원문 대응 {matched} · 쿼리 있는 원문 {with_q} · 비밀 모양 원문 {with_secret} · 가린 줄 {masked_rows} · 누출 {leaks}")
        res = {}
        for it in resp["items"]:
            for f in FIELDS:
                for k, v in residue(it.get(f)).items(): res[f"{f}:{k}"] = res.get(f"{f}:{k}", 0) + v
        print(f"  응답에 남은 비밀 모양: {res or '없음'}")

        print("== B2. web-01 전체 이력에 가림 적용 (모든 provenance)")
        async with c.transaction(isolation="repeatable_read", readonly=True):
            allrows = await c.fetch("SELECT url, user_agent, message, username, http_method FROM events WHERE sensor = 'web-01'")
        worst = 0.0; res = {}; t0 = time.perf_counter()
        for r in allrows:
            t = time.perf_counter(); m = node_logs.mask_row(r); worst = max(worst, (time.perf_counter() - t) * 1000)
            for f in ("url", "user_agent", "message", "http_method"):
                for k, v in residue(m.get(f)).items(): res[f"{f}:{k}"] = res.get(f"{f}:{k}", 0) + v
        print(f"  줄 {len(allrows)} · 전체 {(time.perf_counter() - t0) * 1000:.0f}ms · 한 줄 최대 {worst:.2f}ms · 남은 비밀 모양 {res or '없음'}")

        print("== C. 사건 상세 가림")
        keys = []
        async with c.transaction(isolation="repeatable_read", readonly=True):
            for dev, lim in (("web-01", 50), ("aws-sensor", 4), ("data-node", 2)):
                page = await main.incident_page(c, device=dev, limit=lim)
                keys += [(dev, it["incident_key"]) for it in page["items"]]
            ev_web = await c.fetch("""SELECT incident_key FROM incidents
                WHERE jsonb_path_exists(evidence::jsonb, '$.sample[*] ? (@.sensor == "web-01")') ORDER BY created_at DESC LIMIT 10""")
        keys += [("표본web-01", r["incident_key"]) for r in ev_web if r["incident_key"] not in {k for _, k in keys}]
        print(f"  확인 사건 {len(keys)}")
        for dev, k in keys:
            t = time.perf_counter(); d = await main.get_incident(k); ms = (time.perf_counter() - t) * 1000
            rows = [("raw", r) for r in d["raw"]] + [("behavior", r) for r in d["behavior"]]
            prot = [(w, r) for w, r in rows if r.get("sensor") == "web-01"]
            other = [(w, r) for w, r in rows if r.get("sensor") != "web-01"]
            p_res = {}
            p_masked = 0
            for _, r in prot:
                s = json.dumps({f: r.get(f) for f in FIELDS}, ensure_ascii=False)
                if node_logs.MASK in s or "=" + node_logs.QMASK in s: p_masked += 1
                for f in FIELDS:
                    for kk, v in residue(r.get(f)).items(): p_res[kk] = p_res.get(kk, 0) + v
            o_marked = sum(1 for _, r in other if node_logs.MASK in json.dumps({f: r.get(f) for f in FIELDS}, ensure_ascii=False))
            # ① 표본: DB 원문과 비교
            async with c.transaction(readonly=True):
                ev = await c.fetchval("SELECT evidence FROM incidents WHERE incident_key = $1", k)
            ev = json.loads(ev) if isinstance(ev, str) else ev
            samp = (ev or {}).get("sample") if isinstance(ev, dict) else None
            s_web = s_web_changed = s_other = s_other_same = 0
            if isinstance(samp, list) and isinstance(d["evidence"], dict):
                for a, b in zip(samp, d["evidence"].get("sample") or []):
                    if isinstance(a, dict) and a.get("sensor") == "web-01":
                        s_web += 1; s_web_changed += a != b
                        for f in FIELDS:
                            for kk, v in residue(b.get(f) if isinstance(b.get(f), str) else None).items(): p_res["표본" + kk] = p_res.get("표본" + kk, 0) + v
                    elif isinstance(a, dict):
                        s_other += 1; s_other_same += a == b
            sensors = sorted({r.get("sensor") for _, r in rows if r.get("sensor")})
            print(f"  [{dev}] {k[:60]} | {ms:.0f}ms | 줄 {len(rows)} {sensors} | web-01 줄 {len(prot)} 가림 {p_masked} 남은 {p_res or '없음'}"
                  f" | 그 밖 줄 가림표식 {o_marked} | 표본 web-01 {s_web}(바뀜 {s_web_changed}) 그 밖 {s_other}(같음 {s_other_same})")

        print("== E. web-01 사건: 요청(첫 신호) → 사건 생성")
        async with c.transaction(readonly=True):
            rows = await c.fetch("""SELECT i.incident_key, i.rule_id, i.rule_version, i.first_ts, i.last_ts, i.created_at, i.signal_count
                FROM incidents i WHERE i.incident_key = ANY($1::text[]) ORDER BY i.created_at""", [k for dev, k in keys if dev in ("web-01", "표본web-01")])
        for r in rows:
            print(f"  {r['rule_id']}|{r['rule_version']} 신호 {r['signal_count']} | 첫 {r['first_ts']:%m-%d %H:%M:%S} 끝 {r['last_ts']:%H:%M:%S}"
                  f" 생성 {r['created_at']:%H:%M:%S} | 첫→생성 {(r['created_at'] - r['first_ts']).total_seconds():.0f}s · 끝→생성 {(r['created_at'] - r['last_ts']).total_seconds():.0f}s")
    await pool.close()

asyncio.run(run())
