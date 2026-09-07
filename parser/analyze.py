#!/usr/bin/env python3
"""
OpsLoop - 탐지 규칙 임계치 도출용 분포 분석 (WBS 2.3)

탐지 규칙의 임계치를 감으로 정하지 않기 위해, 실제 관측 분포를 먼저 본다.
여기서 나온 백분위 값이 rules.json 의 근거가 된다.

사용
  python3 analyze.py
  python3 analyze.py --since 2026-09-05 --until 2026-09-07
"""

import argparse
import os
import sqlite3
import statistics
from collections import defaultdict
from datetime import datetime

DEFAULT_DB = os.path.expanduser("~/opsloop/data/opsloop.db")


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def describe(name, values, unit=""):
    if not values:
        print(f"\n[{name}] 표본 없음")
        return
    v = sorted(values)
    print(f"\n[{name}]  표본 {len(v):,}개")
    print(f"  최소 {v[0]:>10.1f}{unit}   중앙 {pct(v,50):>10.1f}{unit}   최대 {v[-1]:>10.1f}{unit}")
    print(f"  p75  {pct(v,75):>10.1f}{unit}   p90  {pct(v,90):>10.1f}{unit}   "
          f"p95  {pct(v,95):>10.1f}{unit}   p99 {pct(v,99):>10.1f}{unit}")
    if len(v) > 1:
        m, s = statistics.mean(v), statistics.pstdev(v)
        print(f"  평균 {m:>10.1f}{unit}   표준편차 {s:>8.1f}{unit}   평균+3σ {m+3*s:>10.1f}{unit}")


def hist(name, values, bins):
    """구간별 도수. 임계치 후보 주변에서 몇 건이 걸리는지 보기 위함."""
    if not values:
        return
    print(f"\n[{name}] 구간 분포")
    counts = [0] * (len(bins) + 1)
    for x in values:
        placed = False
        for i, b in enumerate(bins):
            if x <= b:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    total = len(values)
    prev = 0
    for i, b in enumerate(bins):
        label = f"{prev+1}~{b}" if b != prev + 1 else f"{b}"
        bar = "#" * int(40 * counts[i] / total)
        print(f"  {label:>10} : {counts[i]:>6,} ({100*counts[i]/total:5.1f}%) {bar}")
        prev = b
    bar = "#" * int(40 * counts[-1] / total)
    print(f"  {bins[-1]+1:>7}+   : {counts[-1]:>6,} ({100*counts[-1]/total:5.1f}%) {bar}")


def where(since, until, col):
    c, p = ["provenance='real'"], []
    if since:
        c.append(f"{col} >= ?"); p.append(since)
    if until:
        c.append(f"{col} < ?"); p.append(until)
    return " AND ".join(c), p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--since")
    ap.add_argument("--until")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()
    we, pe = where(args.since, args.until, "ts")
    ws, ps = where(args.since, args.until, "first_ts")

    print("=" * 66)
    print(" OpsLoop  탐지 임계치 도출용 분포 분석")
    print("=" * 66)

    # ---- 1. 세션당 로그인 시도 --------------------------------------
    rows = cur.execute(
        f"SELECT login_attempts FROM sessions WHERE {ws} AND login_attempts > 0", ps
    ).fetchall()
    vals = [r[0] for r in rows]
    describe("세션당 로그인 시도 횟수", vals, "회")
    hist("세션당 로그인 시도 횟수", vals, [1, 2, 3, 5, 10, 20, 50])

    # ---- 2. IP당 세션 수 --------------------------------------------
    rows = cur.execute(
        f"SELECT src_ip, COUNT(*) FROM sessions WHERE {ws} AND src_ip IS NOT NULL GROUP BY 1", ps
    ).fetchall()
    vals = [r[1] for r in rows]
    describe("IP당 세션 수", vals, "건")
    hist("IP당 세션 수", vals, [1, 2, 3, 5, 10, 30, 100])
    print("\n  상위 5개 IP:")
    for ip, c in sorted(rows, key=lambda x: -x[1])[:5]:
        print(f"    {c:>6,}  {ip}")

    # ---- 3. 동일 IP 연속 세션 간격 (인시던트 통합 창 결정) ----------
    rows = cur.execute(
        f"SELECT src_ip, first_ts FROM sessions WHERE {ws} AND src_ip IS NOT NULL "
        f"ORDER BY src_ip, first_ts", ps
    ).fetchall()
    gaps = []
    prev_ip = prev_t = None
    for ip, ts in rows:
        try:
            t = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if ip == prev_ip and prev_t:
            gaps.append((t - prev_t).total_seconds())
        prev_ip, prev_t = ip, t
    describe("동일 IP 연속 세션 간격", gaps, "초")
    hist("동일 IP 연속 세션 간격", gaps, [10, 60, 300, 900, 1800, 3600, 21600])

    # ---- 4. 세션당 명령 수 ------------------------------------------
    rows = cur.execute(
        f"SELECT command_count FROM sessions WHERE {ws} AND command_count > 0", ps
    ).fetchall()
    vals = [r[0] for r in rows]
    describe("세션당 실행 명령 수", vals, "개")
    hist("세션당 실행 명령 수", vals, [1, 2, 3, 5, 10, 20])

    # ---- 5. 시간당 전체 이벤트 (기준선 이탈 탐지용) -----------------
    rows = cur.execute(
        f"SELECT substr(ts,1,13), COUNT(*) FROM events WHERE {we} GROUP BY 1 ORDER BY 1", pe
    ).fetchall()
    vals = [r[1] for r in rows]
    describe("시간당 전체 이벤트 수", vals, "건")
    if len(vals) > 3:
        m, s = statistics.mean(vals), statistics.pstdev(vals)
        over = [(h, c) for h, c in rows if c > m + 3 * s]
        print(f"\n  기준선(평균+3σ = {m+3*s:.0f}건) 초과 구간 {len(over)}개")
        for h, c in over[:10]:
            print(f"    {h}시  {c:,}건")

    # ---- 6. 세션 지속시간 -------------------------------------------
    rows = cur.execute(
        f"SELECT duration_ms FROM sessions WHERE {ws} AND duration_ms IS NOT NULL", ps
    ).fetchall()
    describe("세션 지속시간", [r[0] / 1000 for r in rows], "초")

    # ---- 7. 로그인 성공 후 명령 실행 여부 ---------------------------
    row = cur.execute(
        f"""SELECT
              SUM(login_success = 1),
              SUM(login_success = 1 AND command_count > 0),
              SUM(login_success = 1 AND command_count = 0)
            FROM sessions WHERE {ws}""", ps
    ).fetchone()
    print(f"\n[로그인 성공 세션의 행동]")
    print(f"  성공 {row[0] or 0:,}건 중  명령 실행 {row[1] or 0:,}건 / 무행동 {row[2] or 0:,}건")
    print("  * 무행동 세션은 접속만 확인하고 끊은 스캐너로 볼 수 있다")

    # ---- 8. 규칙 후보별 예상 발생량 ---------------------------------
    print("\n" + "=" * 66)
    print(" 규칙 후보별 예상 발생 건수 (통합 전 원시 기준)")
    print("=" * 66)
    checks = [
        ("R001 무차별 대입 (세션 로그인 시도 3회 이상)",
         f"SELECT COUNT(*) FROM sessions WHERE {ws} AND login_attempts >= 3", ps),
        ("R002 침해 후 행위 (로그인 성공 + 명령 실행)",
         f"SELECT COUNT(*) FROM sessions WHERE {ws} AND login_success=1 AND command_count>0", ps),
        ("R003 악성코드 투하 (파일 업로드/다운로드)",
         f"SELECT COUNT(*) FROM events WHERE {we} AND eventid LIKE 'cowrie.session.file_%'", pe),
        ("R004 프록시 남용 (direct-tcpip 요청)",
         f"SELECT COUNT(*) FROM events WHERE {we} AND eventid='cowrie.direct-tcpip.request'", pe),
    ]
    for label, sql, prm in checks:
        n = cur.execute(sql, prm).fetchone()[0]
        print(f"  {n:>6,}  {label}")

    print("\n  * 이 숫자가 그대로 알림이 되면 알림 피로가 발생한다.")
    print("    인시던트 통합(동일 IP·동일 규칙을 시간 창으로 묶기)이 필요한 이유.\n")

    conn.close()


if __name__ == "__main__":
    main()