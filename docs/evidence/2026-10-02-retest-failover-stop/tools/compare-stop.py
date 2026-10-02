#!/usr/bin/env python3
"""재시험(콘솔 이중화 정지 · 강제 종료) 비교: results.json 여러 개의 정지(stop) · 강제 종료(kill) 회차 값을 한 줄씩 늘어놓는다. 읽기만 한다.
  python3 compare-stop.py <이번 results.json> docs/evidence/2026-09-26-failover/baseline/results.json docs/evidence/2026-09-26-failover/tuned/results.json
"""
import json
import sys

for p in sys.argv[1:]:
    d = json.load(open(p, encoding="utf-8"))
    print("==", p, "· git", (d["provenance"].get("git_head") or "-")[:7], "· 날짜", d.get("date"))
    for r in d["runs"]:
        for e in r["episodes"]:
            if e["scenario"] not in ("stop", "kill"):
                continue
            f, l, w = e["fail"], e["latency"], e["ws"]
            print(f"  {r['run']} {e['scenario']} {e['target']} 판정 {e['pass']} · 감지 {e['detect_s']} · 전환완료 {e['failover_s']} · 도구전환 {e['switchover_s']}"
                  f" · 실패 {f['count']} {f['by_error']} · 최대 {l['max_ms']}ms · 성공최대 {l['ok_max_ms']}ms · p99 {l['p99_ms']}ms"
                  f" · WS미감지 {w['undetected']} · 재연결최대 {w['reconnect_max_s']} · 401+1008 {e['unauthorized']['total']}"
                  f" · 복귀표시 {e['recover_at_s']} · 복귀UP {e['recover']['up_s']}")
    for sc in ("stop", "kill"):
        s = d.get("summary", {}).get(sc)
        if not s:
            continue
        print(f"  묶음 {sc}: {s['pass']}/{s['n']} 합격 · 감지 {s['detect_s']['median']}({s['detect_s']['max']}) · 전환완료 {s['failover_s']['median']}({s['failover_s']['max']})"
                  f" · 실패 최대 {s['fail_count']['max']} · 401+1008 최대 {s['unauthorized']['max']}")
