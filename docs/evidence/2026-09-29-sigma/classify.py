# webserver 규칙마다 detection 이 쓰는 필드를 모아, 경로 · 메서드 · 응답 코드(+ keywords)만 쓰는 규칙을 가른다
import os, sys, json, yaml
sys.path.insert(0, "/repo/detector")
import sigma_convert as sc
src = "/sigma-src"
OK = set(sc.URL_FIELDS) | set(sc.METHOD_FIELDS) | set(sc.STATUS_FIELDS)
rows = []
for dp, dn, fn in os.walk(src):
    dn.sort()
    for n in sorted(fn):
        if not n.endswith(".yml"):
            continue
        p = os.path.join(dp, n)
        d = yaml.safe_load(open(p, encoding="utf-8"))
        if not (isinstance(d, dict) and isinstance(d.get("logsource"), dict) and d["logsource"].get("category") == "webserver"):
            continue
        fields, kw, nulls = set(), False, False
        for k, v in d["detection"].items():
            if k in ("condition", "timeframe"):
                continue
            items = v if isinstance(v, list) else [v]
            for it in items:
                if isinstance(it, dict):
                    for fk, fv in it.items():
                        fields.add(fk.split("|")[0])
                        if fv is None or (isinstance(fv, list) and None in fv):
                            nulls = True
                else:
                    kw = True
        other = sorted(f for f in fields if f not in OK)
        rows.append({"path": os.path.relpath(p, src), "id": d.get("id"), "title": " ".join(str(d.get("title")).split()),
                     "fields": sorted(fields), "keywords": kw, "other_fields": other, "null_values": nulls,
                     "pure": not other})
json.dump(rows, open("/out/classify.json", "w"), ensure_ascii=False, indent=1)
print(len(rows), "webserver;", sum(r["pure"] for r in rows), "pure (경로·메서드·응답코드·keywords 만)")
print("pure 이지만 null 값:", [r["path"] for r in rows if r["pure"] and r["null_values"]])
