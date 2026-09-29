"""이슈 #54 갈래 C — 합성 대조군(양성 대조). 실데이터에서 Sigma 매치가 0 이라, 배선이 비어서 0 인 것이 아님을 같은 실험 DB
연결에서 보인다. 갈래 A 시험의 표본 45건(test_sigma_convert.SAMPLES)을 연결 전용 임시 표(search_path=pg_temp 의 events)에
web-01 꼴(nginx.request)과 디코이 꼴(decoy.request)로 한 번씩 넣고 sg1 · sg1(statuses 뺌) · c1 · sgx 신호를 탐지기 질의로 받은 뒤
롤백한다. 실제 표(public.events)는 읽지도 쓰지도 않는다. 합성이라 관측이 아니다.
"""
import collections, copy, json, sys
from datetime import timedelta
sys.path.insert(0, "/repo/detector")
import detect
import test_sigma_convert as t
import psycopg2

pw = open("/pw").read().strip()
conn = psycopg2.connect(host="127.0.0.1", port=5432, user="opsloop", password=pw, dbname="opsloop")
cur = conn.cursor()
cur.execute("SET search_path TO pg_temp")
cur.execute(t.TEMP_EVENTS)
rows = []
for i, (method, url, status, _) in enumerate(t.SAMPLES):
    rows += [(f"n{i}", t.T0 + timedelta(minutes=i), "nginx.request", None, "192.0.2.10", url, "real", method, status, "web-01"),
             (f"d{i}", t.T0 + timedelta(minutes=i, seconds=30), "decoy.request", f"s{i}", "192.0.2.20", url, "real", method,
              status, "decoy")]
cur.executemany("INSERT INTO events VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", rows)
cur.execute("SELECT count(*) FROM events"); n_tmp = cur.fetchone()[0]
cur.execute("SELECT count(*) FROM pg_temp.events"); assert cur.fetchone()[0] == n_tmp


def load(p):
    return json.load(open(p, encoding="utf-8"))


def strip(rule):
    r = copy.deepcopy(rule)
    for s in r["params"]["signatures"]:
        s.pop("statuses", None)
    return r


sg1 = load("/repo/detector/rules_sigma.json")["rules"][0]
c1 = {r["id"]: r for r in load("/repo/detector/rules_cve.json")["rules"]}
sgx = load("/out/rules_sigma_lab.json")["rules"][0]


def hits(rule):
    out = {}
    for ts, ip, sess, d in detect.signals_url_signature(cur, rule, None, None):
        out[(d["url"], d["http_method"], d["http_status"], d["sensor"])] = d["signatures"]
    return out


H = {"sg1": hits(sg1), "sg1_nostatus": hits(strip(sg1)), "c1": {**hits(c1["R105"]), **{k: v for k, v in hits(c1["R106"]).items()}},
     "sgx": hits(sgx)}
# c1 R105 · R106 이 같은 요청에 모두 맞으면 합친다
r105, r106 = hits(c1["R105"]), hits(c1["R106"])
H["c1"] = {k: sorted(set(r105.get(k, [])) | set(r106.get(k, []))) for k in set(r105) | set(r106)}
conn.rollback()
conn.close()

# 표본의 기대 서명(파이썬 판)과 같은가
want_ok = all(sorted(H["sg1"].get((u, m, s, "web-01"), [])) == sorted(w) for m, u, s, w in t.SAMPLES)
per = []
for m, u, s, w in t.SAMPLES:
    for sensor in ("web-01", "decoy"):
        k = (u, m, s, sensor)
        per.append({"sensor": sensor, "method": m, "url": u, "status": s, "sg1": H["sg1"].get(k, []),
                    "sg1_nostatus": H["sg1_nostatus"].get(k, []), "c1": H["c1"].get(k, []), "sgx": H["sgx"].get(k, [])})
agg = collections.Counter()
for p in per:
    agg["rows"] += 1
    agg["sg1"] += bool(p["sg1"]); agg["c1"] += bool(p["c1"]); agg["sgx"] += bool(p["sgx"])
    agg["sg1_and_c1"] += bool(p["sg1"]) and bool(p["c1"])
    agg["sg1_only"] += bool(p["sg1"]) and not p["c1"]
    agg["c1_only"] += bool(p["c1"]) and not p["sg1"]
    agg["status_excluded"] += bool(p["sg1_nostatus"]) and not p["sg1"]
res = {"temp_rows": n_tmp, "samples": len(t.SAMPLES), "sg1_equals_expected_web01": want_ok, "totals": dict(agg), "rows": per,
       "rolled_back": True}
json.dump(res, open("/out/control.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps({k: v for k, v in res.items() if k != "rows"}, ensure_ascii=False))
for p in per:
    if p["sg1"] or p["c1"] or p["sg1_nostatus"]:
        print(p["sensor"], p["method"], p["status"], p["url"][:70], "| sg1", p["sg1"], "| nostat", p["sg1_nostatus"] != p["sg1"], "| c1", p["c1"])
