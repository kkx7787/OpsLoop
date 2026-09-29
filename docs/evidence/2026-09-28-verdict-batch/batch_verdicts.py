#!/usr/bin/env python3
"""판정안 일괄 기록 (2026-09-28). triage.py 의 gather · propose · observed_of · record 를 그대로 써서 검토한 판정안대로
기록한다. 판정자 han · 사유 앞 '[판정안 일괄 검토]' · decision_seconds NULL · 차단은 계획에 표시된 것만 24시간.
사용: python3 batch_verdicts.py plan.json            (기본 dry-run: 읽기만 하고 끝에 rollback)
      python3 batch_verdicts.py plan.json --apply    (기록)
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psycopg2
import triage

OPERATOR = "han"
PREFIX = "[판정안 일괄 검토]"


def read_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
    return env


def main():
    plan = json.load(open(sys.argv[1]))
    apply = "--apply" in sys.argv
    url = os.environ.get("DATABASE_URL") or read_env("/etc/opsloop/triage.env")["DATABASE_URL"]
    conn = psycopg2.connect(url)
    cur = conn.cursor()
    n_rec = n_blk = 0
    refused, skipped = [], []
    for i, p in enumerate(plan, 1):
        key = p["key"]
        cur.execute("""
            SELECT rule_id, rule_version, host(actor_ip), first_ts, last_ts, signal_count, evidence
            FROM incidents WHERE incident_key = %s
              AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = incidents.incident_key)""", (key,))
        row = cur.fetchone()
        if not row:
            skipped.append((key, "이미 판정됐거나 없음"))
            continue
        rid, ver, ip, first_ts, last_ts, n_sig, evidence = row
        sessions = (evidence or {}).get("sessions") or []
        ev = triage.gather(cur, key, ip, first_ts, last_ts, sessions, ver)
        suggestion, basis = triage.propose(rid, ev)
        if suggestion != p["verdict"]:
            skipped.append((key, f"제안이 표와 다름: {suggestion} ≠ {p['verdict']}"))
            continue
        observed, unit = triage.observed_of(evidence, n_sig)
        reason = f"{PREFIX} {basis[1]}"
        why = triage.cannot_block(ip, ev) if ip else "출발지 없음"
        block = bool(p.get("block")) and suggestion == "threat" and not ev["blocked"] and not why
        if apply:
            done = triage.record(conn, key, ip, suggestion, reason, observed, OPERATOR, suggestion, block,
                                 seconds=None, block_hours=24)
            if done and done.get("refused"):
                refused.append((key, done["refused"]))
            elif block:
                n_blk += 1
            n_rec += 1
            if i % 20 == 0:
                print(f"  {i}/{len(plan)} 기록 · 차단 {n_blk}", flush=True)
        else:
            n_rec += 1
            n_blk += int(block)
            print(f"  {rid} {ip or '-':<16} {suggestion:<14} 차단={'예' if block else '아니오'}"
                  + (f" ({why})" if p.get('block') and why else "") + f"  관측값 {observed:g} {unit}")
    if not apply:
        conn.rollback()
    print(f"\n{'기록' if apply else '예정'}: 판정 {n_rec}건 · 차단 {n_blk}건 · 차단 거부 {len(refused)} · 건너뜀 {len(skipped)}")
    for k, w in refused:
        print("  차단 거부:", k, "·", w)
    for k, w in skipped:
        print("  건너뜀:", k, "·", w)
    conn.close()


if __name__ == "__main__":
    main()
