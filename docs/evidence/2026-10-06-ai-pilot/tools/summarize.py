#!/usr/bin/env python3
"""추천 결과 집계. 쓰는 법: python3 summarize.py 결과.jsonl"""
import json
import statistics
import sys
from collections import Counter, defaultdict

SSH = {"R001", "R002", "R003", "R004", "R005", "R006"}
R = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
n = len(R)
sc = Counter(r["score"] for r in R)
print(f"전체 {n}건: " + ", ".join(f"{k} {v}" for k, v in sc.most_common()))

def rate(rows):
    c = Counter(r["score"] for r in rows)
    return f"{c['맞음']}/{len(rows)} (보류 {c['보류']}, 틀림 {c['틀림']}, 깨짐 {c['깨짐']})"

groups = {
    "위협 사건": [r for r in R if r["label"] == "threat"],
    "무시 가능 사건": [r for r in R if r["label"] == "non_actionable"],
    "오탐, 양성 정탐 사건": [r for r in R if r["label"] in ("false_positive", "benign_positive")],
    "SSH 규칙 전체": [r for r in R if r["rule_id"] in SSH],
    "SSH 규칙 중 R002 제외": [r for r in R if r["rule_id"] in SSH - {"R002"}],
    "규칙 기반 제안 있음": [r for r in R if r["proposed"]],
    "규칙 기반 제안 없음": [r for r in R if not r["proposed"]],
    "규칙 기반 제안 없는 SSH 사건": [r for r in R if not r["proposed"] and r["rule_id"] in SSH],
}
for k, rows in groups.items():
    if rows:
        print(f"  {k}: {rate(rows)}")

by_rule = defaultdict(list)
for r in R:
    by_rule[(r["rule_id"], r["label"])].append(r)
print("규칙별")
for (rule, label), rows in sorted(by_rule.items()):
    print(f"  {rule} {label}: {rate(rows)}")

over = [r for r in R if r["rec"] and r["rec"]["recommendation"] == "threat" and r["label"] != "threat"]
miss = [r for r in R if r["rec"] and r["label"] == "threat" and r["rec"]["recommendation"] != "threat"]
print(f"과잉 차단 추천(위협 아닌데 위협 추천) {len(over)}건, 위협 놓침 {len(miss)}건")
human = [r for r in R if r["rec"] and r["rec"]["needs_human"]]
print(f"사람 확인 표시 {len(human)}건 (안전장치로 붙은 것 {sum(1 for r in human if r['rec'].get('guard'))}건)")
secs = [r["seconds"] for r in R]
print(f"건당 시간 중앙 {statistics.median(secs):.1f}초, 평균 {statistics.mean(secs):.1f}초, 최대 {max(secs):.1f}초, 합계 {sum(secs) / 60:.1f}분")
print(f"재시도 {sum(1 for r in R if r.get('tries', 1) > 1)}건")
conf = Counter((r["rec"] or {}).get("confidence") for r in R if r["score"] == "틀림")
print(f"틀린 것의 확신도 {dict(conf)}")
for r in over + miss + [r for r in R if r["score"] in ("틀림", "깨짐") and r not in over and r not in miss]:
    rec = r["rec"] or {}
    print(f"  - {r['rule_id']} 사람 {r['label']} / AI {rec.get('recommendation')} 확신 {rec.get('confidence')} 사람확인 {rec.get('needs_human')} {r.get('error') or ''}")
    for line in rec.get("reason_ko") or []:
        print(f"      {line}")
