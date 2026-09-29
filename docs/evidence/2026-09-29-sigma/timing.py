# 신호 질의 소요 시간(읽기 전용, 각 5회 중앙값)
import json, statistics, sys, time
sys.path.insert(0, "/repo/detector")
import detect, psycopg2
conn = psycopg2.connect(host="127.0.0.1", port=5432, user="opsloop", password=open("/pw").read().strip(), dbname="opsloop",
                        options="-c default_transaction_read_only=on")
cur = conn.cursor()
out = {}
for name, path, idx in [("c1 R105", "/repo/detector/rules_cve.json", 0), ("c1 R106", "/repo/detector/rules_cve.json", 1),
                        ("sg1 R107", "/repo/detector/rules_sigma.json", 0), ("sgx R107", "/out/rules_sigma_lab.json", 0)]:
    rule = json.load(open(path))["rules"][idx]
    ts = []
    for _ in range(5):
        t0 = time.perf_counter(); n = len(detect.signals_url_signature(cur, rule, None, None)); ts.append(time.perf_counter() - t0)
    out[name] = {"signatures": len(rule["params"]["signatures"]), "signals": n, "median_ms": round(1000 * statistics.median(ts), 1)}
print(json.dumps(out, ensure_ascii=False))
json.dump(out, open("/out/timing.json", "w"), ensure_ascii=False, indent=1)
