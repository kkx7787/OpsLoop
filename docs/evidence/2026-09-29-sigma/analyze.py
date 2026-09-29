"""이슈 #54 갈래 C — 요청 단위 비교 (읽기 전용). 실험 DB(opsloop-lab54)에만 붙는다.

요청 행: events 에서 provenance='real' · eventid IN (nginx.request, decoy.request). 규칙의 eventids 와 같다.
매치: detect.url_signature_fullmatch(파이썬) 로 서명마다 센다. 같은 답을 detect.signals_url_signature(SQL, 탐지기와 같은 질의)
로 다시 받아 (시각 · 출발지 · eventid · 발생원 · 메서드 · url · 응답 코드 · 맞은 서명 목록) 다중집합이 같은지 대조한다.
정상 시나리오 표식 행(normal49)은 real 과 따로 센다.
"""
import collections, copy, json, sys
sys.path.insert(0, "/repo/detector")
import detect
import psycopg2

OUT = sys.argv[1]
pw = open("/pw").read().strip()
conn = psycopg2.connect(host="127.0.0.1", port=5432, user="opsloop", password=pw, dbname="opsloop",
                        options="-c default_transaction_read_only=on")
conn.set_session(readonly=True)
cur = conn.cursor()
cur.execute("SHOW transaction_read_only"); ro = cur.fetchone()[0]
assert ro == "on", ro


def load(p):
    return json.load(open(p, encoding="utf-8"))


sg1 = load("/repo/detector/rules_sigma.json")
c1 = load("/repo/detector/rules_cve.json")
sgx = load("/out/rules_sigma_lab.json")
sel = load("/repo/detector/sigma/selection.json")
classify = {r["path"]: r for r in load("/out/classify.json")}
R107 = sg1["rules"][0]
RX = sgx["rules"][0]
C1R = {r["id"]: r for r in c1["rules"]}
EIDS = R107["params"]["eventids"]
for r in [RX] + list(C1R.values()):
    assert r["params"]["eventids"] == EIDS and "sensors" not in r["params"]

MARK = r"^\[정상 시나리오 [A-Z][0-9]{2}\] "
cur.execute("SELECT line_hash, ts, src_ip, session, eventid, sensor, http_method, url, http_status, "
            "(coalesce(message, '') ~ %s AND coalesce(user_agent, '') LIKE 'OpsLoop-Normal49/%%') AS marked, "
            "substring(message from '^\\[정상 시나리오 ([A-Z][0-9]{2})\\] ') "
            "FROM events WHERE provenance = 'real' AND eventid = ANY(%s) ORDER BY ts, line_hash", (MARK, EIDS))
rows = cur.fetchall()
REQ = {r[0]: r for r in rows}
real = [r for r in rows if not r[9]]
marked = [r for r in rows if r[9]]


def match_sets(rule):
    """서명 id → 맞은 line_hash 집합 (파이썬 판)"""
    out = {}
    for s in rule["params"]["signatures"]:
        out[s["id"]] = {r[0] for r in rows if detect.url_signature_fullmatch(s, r[6], r[7], r[8])}
    return out


def sql_crosscheck(rule, py):
    """탐지기 신호 질의(SQL)와 파이썬 판의 다중집합 대조. (같은가, SQL 신호 수, 파이썬 신호 수)"""
    sig = detect.signals_url_signature(cur, rule, None, None)
    a = collections.Counter((ts.isoformat(), str(ip), d["eventid"], d["sensor"], d["http_method"], d["url"],
                             d["http_status"], tuple(d["signatures"])) for ts, ip, sess, d in sig)
    per = collections.defaultdict(list)
    for sid, hs in py.items():
        for h in hs:
            per[h].append(sid)
    b = collections.Counter()
    for h, sids in per.items():
        r = REQ[h]
        b[(r[1].isoformat(), str(r[2]), r[4], r[5], r[6], r[7], r[8], tuple(sorted(sids)))] += 1
    return a == b, sum(a.values()), sum(b.values())


def strip_status(rule):
    r = copy.deepcopy(rule)
    for s in r["params"]["signatures"]:
        s.pop("statuses", None)
    return r


def summarize(hs):
    rs = [REQ[h] for h in hs]
    by_sensor = collections.Counter(r[5] for r in rs)
    return {"requests": len(rs), "by_sensor": dict(sorted(by_sensor.items())),
            "sources": len({str(r[2]) for r in rs}),
            "first_ts": min((r[1] for r in rs), default=None), "last_ts": max((r[1] for r in rs), default=None)}


def url_sample(hs, n=8):
    c = collections.Counter((REQ[h][6], REQ[h][7], REQ[h][8]) for h in hs)
    return [{"method": m, "url": u, "status": s, "count": k} for (m, u, s), k in c.most_common(n)]


real_h = {r[0] for r in real}
mark_h = {r[0] for r in marked}

res = {"read_only": ro, "request_rows": {"total": len(rows), "real_unmarked": len(real), "normal_marked": len(marked),
       "by_sensor_real": dict(collections.Counter(r[5] for r in real)),
       "sources_real": len({str(r[2]) for r in real}),
       "status_real": {str(k): v for k, v in collections.Counter(r[8] for r in real).most_common()},
       "method_real": dict(collections.Counter(r[6] for r in real).most_common()),
       "urls_with_query_real": sum(1 for r in real if r[7] and "?" in r[7]),
       "urls_with_percent_real": sum(1 for r in real if r[7] and "%" in r[7])}}

# 서명별 매치
m_sg1 = match_sets(R107)
m_sg1_ns = match_sets(strip_status(R107))
m_c1 = {}
for rid, r in C1R.items():
    for sid, hs in match_sets(r).items():
        m_c1[(rid, sid)] = hs
m_sgx = match_sets(RX)
m_sgx_ns = match_sets(strip_status(RX))

# SQL 대조
checks = {}
for name, rule, py in [("sg1 R107", R107, m_sg1), ("sg1 R107 (statuses 뺌)", strip_status(R107), m_sg1_ns),
                       ("c1 R105", C1R["R105"], {s: h for (rid, s), h in m_c1.items() if rid == "R105"}),
                       ("c1 R106", C1R["R106"], {s: h for (rid, s), h in m_c1.items() if rid == "R106"}),
                       ("sgx R107", RX, m_sgx), ("sgx R107 (statuses 뺌)", strip_status(RX), m_sgx_ns)]:
    same, n_sql, n_py = sql_crosscheck(rule, py)
    checks[name] = {"same": same, "sql_signals": n_sql, "python_signals": n_py}
res["sql_vs_python"] = checks

c1_any = set().union(*m_c1.values())
c1_by_rule = {rid: set().union(*[h for (r, s), h in m_c1.items() if r == rid]) for rid in C1R}

# 선정 10개
sig_by_path = collections.defaultdict(list)
for s in R107["params"]["signatures"]:
    sig_by_path[s["sigma"]["path"]].append(s)
table = []
for ent in sel["rules"]:
    path = ent["path"]
    sigs = sig_by_path[path]
    ids = [s["id"] for s in sigs]
    pair = ent.get("c1_pair")
    ref = pair or {"rule": "R106", "signature": "apache-path-traversal", "reference_only": True}
    pair_h = m_c1[(ref["rule"], ref["signature"])]
    allh = set().union(*[m_sg1[i] for i in ids]) if ids else set()
    nsh = set().union(*[m_sg1_ns[i] for i in ids]) if ids else set()
    hit, hit_ns = allh & real_h, nsh & real_h
    excl = hit_ns - hit
    notes = [n for s in sigs for n in s["sigma"]["notes"]]
    table.append({
        "path": path, "title": sigs[0]["sigma"]["title"] if sigs else None, "sigma_id": sigs[0]["sigma"]["id"] if sigs else None,
        "signatures": ids, "converted": bool(sigs), "branches": len(sigs),
        "statuses": sorted({c for s in sigs for c in s.get("statuses", [])}),
        "methods": sorted({m for s in sigs for m in s.get("methods", [])}),
        "notes": notes,
        "c1_pair": pair, "c1_compare_to": ref,
        "real": summarize(hit),
        "also_c1_pair": len(hit & pair_h), "also_c1_any": len(hit & c1_any),
        "also_c1_by_rule": {rid: len(hit & h) for rid, h in c1_by_rule.items()},
        "sigma_only": len(hit - c1_any), "c1_pair_only": len((pair_h & real_h) - hit),
        "c1_pair_total_real": len(pair_h & real_h),
        "status_excluded": len(excl), "status_excluded_status": {str(k): v for k, v in collections.Counter(REQ[h][8] for h in excl).most_common()},
        "status_excluded_urls": url_sample(excl),
        "urls": url_sample(hit), "c1_pair_only_urls": url_sample((pair_h & real_h) - hit, 5),
        "normal_marked": len(allh & mark_h),
        "normal_marked_scenarios": sorted({REQ[h][10] for h in allh & mark_h}),
        "normal_marked_no_status": len(nsh & mark_h),
    })
res["selected"] = table

u_sg1 = set().union(*m_sg1.values()) & real_h
u_sg1_ns = set().union(*m_sg1_ns.values()) & real_h
res["sg1_union"] = {**summarize(u_sg1), "also_c1_any": len(u_sg1 & c1_any), "sigma_only": len(u_sg1 - c1_any),
                    "c1_any_total_real": len(c1_any & real_h), "c1_only_vs_sg1": len((c1_any & real_h) - u_sg1),
                    "status_excluded": len(u_sg1_ns - u_sg1),
                    "normal_marked": len(set().union(*m_sg1.values()) & mark_h)}
res["c1_signatures"] = [{"rule": rid, "signature": sid, **summarize(h & real_h), "normal_marked": len(h & mark_h)}
                        for (rid, sid), h in sorted(m_c1.items())]

# sgx 전체
xs = []
for s in RX["params"]["signatures"]:
    h = m_sgx[s["id"]]
    hns = m_sgx_ns[s["id"]]
    p = s["sigma"]["path"]
    xs.append({"signature": s["id"], "path": p, "title": s["sigma"]["title"], "pure": classify[p]["pure"],
               "statuses": s.get("statuses"), "real": summarize(h & real_h), "also_c1_any": len(h & real_h & c1_any),
               "status_excluded": len((hns - h) & real_h), "normal_marked": len(h & mark_h),
               "normal_marked_scenarios": sorted({REQ[x][10] for x in h & mark_h}),
               "urls": url_sample(h & real_h, 5)})
res["sgx_signatures"] = xs
byp = collections.defaultdict(list)
for x in xs:
    byp[x["path"]].append(x)
rules_hit = []
for p, lst in byp.items():
    hs = set().union(*[m_sgx[x["signature"]] for x in lst]) & real_h
    mk = set().union(*[m_sgx[x["signature"]] for x in lst]) & mark_h
    rules_hit.append({"path": p, "title": lst[0]["title"], "pure": lst[0]["pure"], "signatures": [x["signature"] for x in lst],
                      "selected": p in sig_by_path, **summarize(hs), "also_c1_any": len(hs & c1_any),
                      "normal_marked": len(mk)})
res["sgx_rules"] = rules_hit
res["sgx_totals"] = {"rules_converted": len(byp), "rules_pure_converted": sum(1 for r in rules_hit if r["pure"]),
                     "signatures": len(xs),
                     "rules_hit_real": sum(1 for r in rules_hit if r["requests"]),
                     "rules_pure_hit_real": sum(1 for r in rules_hit if r["requests"] and r["pure"]),
                     "requests_hit_real": len(set().union(*m_sgx.values()) & real_h),
                     "rules_hit_normal": sum(1 for r in rules_hit if r["normal_marked"]),
                     "requests_hit_normal": len(set().union(*m_sgx.values()) & mark_h)}
json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
print(json.dumps({"checks": checks, "rows": res["request_rows"]["total"], "real": len(real), "marked": len(marked),
                  "sg1_union": res["sg1_union"], "sgx": res["sgx_totals"]}, ensure_ascii=False, default=str))


# 조건 단계별 탈락(진단). 서명의 조건을 하나씩 더해 가며 real · 표식 행에서 몇 건이 남는지 본다
def stages(sig):
    def hit(p, u):
        return u is not None and __import__("re").fullmatch(p, u, __import__("re").I | __import__("re").S) is not None
    st = collections.OrderedDict()
    cur_set = [r for r in rows if hit(sig["pattern"], r[7])]
    st["pattern"] = cur_set
    if "all_patterns" in sig:
        cur_set = [r for r in cur_set if all(hit(p, r[7]) for p in sig["all_patterns"])]
        st["+all_patterns"] = cur_set
    if "not_patterns" in sig:
        cur_set = [r for r in cur_set if not any(hit(p, r[7]) for p in sig["not_patterns"])]
        st["+not_patterns"] = cur_set
    if "methods" in sig:
        cur_set = [r for r in cur_set if (r[6] or "").upper() in sig["methods"]]
        st["+methods"] = cur_set
    if "statuses" in sig:
        cur_set = [r for r in cur_set if r[8] in sig["statuses"]]
        st["+statuses"] = cur_set
    final = {r[0] for r in cur_set}
    assert final == m_all[sig["id"]], sig["id"]
    return [{"stage": k, "real": sum(1 for r in v if not r[9]), "normal_marked": sum(1 for r in v if r[9]),
             "urls": url_sample([r[0] for r in v if not r[9]], 5)} for k, v in st.items()]


m_all = {**m_sg1}
res["sg1_stages"] = {s["id"]: stages(s) for s in R107["params"]["signatures"]}
m_all = {**m_sgx}
xst = {s["id"]: stages(s) for s in RX["params"]["signatures"]}
res["sgx_pattern_only_hits"] = [{"signature": k, "path": next(x["path"] for x in xs if x["signature"] == k),
                                 "stages": v} for k, v in xst.items() if v[0]["real"] or v[0]["normal_marked"]]

# rule_versions 에 들어간 sg1 정의가 규칙 파일과 같은가
cur.execute("SELECT definition FROM rule_versions WHERE rule_version = 'sg1'")
got = cur.fetchone()
res["rule_versions_sg1_equals_file"] = None if got is None else (got[0] == sg1)
json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
print("stages:", {k: [(x["stage"], x["real"], x["normal_marked"]) for x in v] for k, v in res["sg1_stages"].items()})
print("sgx pattern-only:", [(x["signature"], [(y["stage"], y["real"], y["normal_marked"]) for y in x["stages"]]) for x in res["sgx_pattern_only_hits"]])
print("rule_versions sg1 == file:", res["rule_versions_sg1_equals_file"])
