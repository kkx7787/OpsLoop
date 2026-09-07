#!/usr/bin/env python3
"""
OpsLoop - 탐지 엔진 (WBS 2.3 / PostgreSQL)

정규화된 이벤트에 규칙을 적용해 인시던트를 만든다.

핵심 설계
  1. 시간 범위와 규칙 버전을 인자로 받는다. 기간을 코드에 박지 않아야
     같은 구간에 다른 규칙 버전을 재적용(리플레이)할 수 있다.
  2. 신호(signal)와 인시던트(incident)를 분리한다.
     신호는 규칙에 걸린 개별 사건, 인시던트는 사람이 볼 단위로 묶은 것.
     알림 피로는 이 통합 단계에서 줄인다.
  3. 멱등하다. 같은 (규칙, 버전, 대상, 시작시각)이면 다시 만들지 않는다.
  4. 규칙 정의를 rule_versions 에 남긴다. 임계치를 왜 바꿨는지가 남아야
     "조치가 탐지를 개선했다"를 나중에 증명할 수 있다.

사용
  export DATABASE_URL='postgresql://opsloop:PASSWORD@호스트:5432/opsloop'
  python3 detect.py --run
  python3 detect.py --run --since 2026-09-05 --until 2026-09-06
  python3 detect.py --run --rules rules_v2.json
  python3 detect.py --list
  python3 detect.py --compare v1 v2
  python3 detect.py --quality
"""

import argparse
import json
import os
import statistics
import sys
from datetime import datetime, timezone

try:
    import psycopg2
    from psycopg2.extras import execute_batch
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

# session_threshold 규칙이 참조할 수 있는 컬럼. SQL 조립 전에 검사한다.
ALLOWED_SESSION_FIELDS = {
    "login_attempts", "command_count", "downloads", "duration_ms",
}
ALLOWED_OPS = {">=", ">", "=", "<=", "<"}


def db_url(arg):
    url = arg or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다. 환경변수나 --db-url 로 주세요.")
    return url


def range_clause(since, until, col):
    c, p = ["provenance = 'real'"], []
    if since:
        c.append(f"{col} >= %s"); p.append(since)
    if until:
        c.append(f"{col} < %s"); p.append(until)
    return " AND ".join(c), p


# ----------------------------------------------------------------------
#  규칙별 신호 수집
#  각 함수는 (ts, actor_ip, session, detail) 튜플 목록을 돌려준다
# ----------------------------------------------------------------------

def signals_session_threshold(cur, rule, since, until):
    p = rule["params"]
    if p["field"] not in ALLOWED_SESSION_FIELDS:
        raise ValueError(f"{rule['id']}: 허용되지 않은 필드 {p['field']}")
    if p["op"] not in ALLOWED_OPS:
        raise ValueError(f"{rule['id']}: 허용되지 않은 연산자 {p['op']}")
    w, prm = range_clause(since, until, "first_ts")
    cur.execute(
        f"SELECT first_ts, src_ip, session, {p['field']} "
        f"FROM sessions WHERE {w} AND {p['field']} {p['op']} %s",
        prm + [p["value"]])
    return [(ts, ip, s, {p["field"]: v}) for ts, ip, s, v in cur.fetchall()]


def signals_session_compound(cur, rule, since, until):
    w, prm = range_clause(since, until, "first_ts")
    cur.execute(
        f"SELECT first_ts, src_ip, session, login_attempts, command_count "
        f"FROM sessions WHERE {w} AND ({rule['params']['expr']})", prm)
    return [(ts, ip, s, {"login_attempts": la, "command_count": cc})
            for ts, ip, s, la, cc in cur.fetchall()]


def signals_event_match(cur, rule, since, until):
    p = rule["params"]
    w, prm = range_clause(since, until, "ts")
    if "eventid" in p:
        cond, extra = "eventid = %s", [p["eventid"]]
    else:
        cond, extra = "eventid LIKE %s", [p["eventid_like"]]
    cur.execute(
        f"SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) "
        f"FROM events WHERE {w} AND {cond}", prm + extra)
    return [(ts, ip, s, {"eventid": ev, "detail": d}) for ts, ip, s, ev, d in cur.fetchall()]


def signals_baseline_deviation(cur, rule, since, until):
    """시간당 이벤트 수가 평균 + kσ 를 넘는 구간을 신호로 만든다.

    학습 모델이 아니라 기술 통계다. 관측 구간의 평균과 표준편차로 임계선을
    정한다. 규칙에 없는 새 패턴을 잡기 위한 보완 장치.
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "ts")
    cur.execute(
        f"SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE {w} GROUP BY 1 ORDER BY 1",
        prm)
    rows = cur.fetchall()
    if len(rows) < p.get("min_buckets", 24):
        return []
    counts = [c for _, c in rows]
    mean, sd = statistics.mean(counts), statistics.pstdev(counts)
    if sd == 0:
        return []
    limit = mean + p["sigma"] * sd
    return [(h, None, None,
             {"bucket": h.isoformat(), "count": c, "mean": round(mean, 1),
              "sigma": round(sd, 1), "limit": round(limit, 1)})
            for h, c in rows if c > limit]


def signals_actor_rate(cur, rule, since, until):
    """동일 출발지의 이벤트 누적 빈도를 본다.

    관측 결과 봇은 한 세션에 로그인 1회만 시도하고 끊는다. 무차별 대입이
    세션 안이 아니라 세션들 사이에 퍼져 있어, 세션 단위 임계치로는 잡히지 않는다.
    그래서 IP 단위로 고정 시간창을 잘라 누적 횟수를 센다.
    """
    p = rule["params"]
    window = p["window_seconds"]
    w, prm = range_clause(since, until, "ts")
    cur.execute(
        f"SELECT ts, src_ip, session FROM events "
        f"WHERE {w} AND eventid = ANY(%s) AND src_ip IS NOT NULL ORDER BY src_ip, ts",
        prm + [p["eventids"]])

    buckets = {}
    for ts, ip, sess in cur.fetchall():
        buckets.setdefault((ip, int(ts.timestamp()) // window), []).append((ts, sess))

    out = []
    for (ip, _slot), items in buckets.items():
        if len(items) >= p["threshold"]:
            items.sort(key=lambda x: x[0])
            out.append((items[0][0], ip, items[0][1],
                        {"count": len(items), "window_seconds": window,
                         "threshold": p["threshold"]}))
    return out


COLLECTORS = {
    "session_threshold": signals_session_threshold,
    "actor_rate": signals_actor_rate,
    "session_compound": signals_session_compound,
    "event_match": signals_event_match,
    "baseline_deviation": signals_baseline_deviation,
}


# ----------------------------------------------------------------------
#  인시던트 통합
# ----------------------------------------------------------------------

def aggregate(signals, gap_seconds):
    """동일 대상(IP)의 신호를 시간 간격으로 묶는다.

    간격이 gap_seconds 이내로 이어지면 같은 인시던트로 본다.
    한 IP 가 사흘 내내 두드려도 끊김 없이 이어지면 인시던트 하나다.
    """
    by_ip = {}
    for ts, ip, sess, detail in signals:
        by_ip.setdefault(ip, []).append((ts, sess, detail))

    groups = []
    for ip, items in by_ip.items():
        items.sort(key=lambda x: x[0])
        cur_group = [items[0]]
        for prev, nxt in zip(items, items[1:]):
            if (nxt[0] - prev[0]).total_seconds() <= gap_seconds:
                cur_group.append(nxt)
            else:
                groups.append((ip, cur_group))
                cur_group = [nxt]
        groups.append((ip, cur_group))
    return groups


def run(conn, rules_doc, since, until, verbose=True):
    version = rules_doc["rule_version"]
    gap = rules_doc["aggregation"]["window_gap_seconds"]
    cur = conn.cursor()

    # 규칙 정의를 남긴다. 나중에 "그때 임계치가 뭐였지"를 코드가 아니라 DB 가 답한다.
    cur.execute(
        """INSERT INTO rule_versions (rule_version, definition, reason)
           VALUES (%s, %s::jsonb, %s)
           ON CONFLICT (rule_version) DO NOTHING""",
        (version, json.dumps(rules_doc, ensure_ascii=False), rules_doc.get("note")))

    created = skipped = 0
    summary = []

    for rule in rules_doc["rules"]:
        if not rule.get("enabled", True):
            continue
        collector = COLLECTORS.get(rule["type"])
        if collector is None:
            raise ValueError(f"{rule['id']}: 알 수 없는 규칙 유형 {rule['type']}")

        # 고정 시간창으로 신호를 만드는 규칙은 슬롯 경계 때문에 전역 창과
        # 같은 값을 쓰면 연속 활동이 쪼개진다. 규칙별 지정을 우선한다.
        rule_gap = rule.get("aggregation_gap_seconds", gap)
        signals = collector(cur, rule, since, until)
        groups = aggregate(signals, rule_gap)

        rows = []
        for ip, items in groups:
            first_ts, last_ts = items[0][0], items[-1][0]
            sessions = sorted({i[1] for i in items if i[1]})
            key = f"{rule['id']}|{version}|{ip or '-'}|{first_ts.isoformat()}"
            evidence = json.dumps(
                {"sample": [i[2] for i in items[:5]], "sessions": sessions[:10]},
                ensure_ascii=False, default=str)
            rows.append((key, rule["id"], version, rule["name"], rule["severity"], ip,
                         first_ts, last_ts, len(items), len(sessions), evidence))

        cur.execute("SELECT count(*) FROM incidents WHERE rule_id = %s AND rule_version = %s",
                    (rule["id"], version))
        before = cur.fetchone()[0]
        execute_batch(cur, """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (incident_key) DO NOTHING""", rows, page_size=200)
        cur.execute("SELECT count(*) FROM incidents WHERE rule_id = %s AND rule_version = %s",
                    (rule["id"], version))
        n_new = cur.fetchone()[0] - before

        created += n_new
        skipped += len(rows) - n_new
        summary.append((rule["id"], rule["name"], len(signals), len(groups), n_new, rule_gap))

    conn.commit()
    cur.close()

    if verbose:
        print("=" * 82)
        print(f" 탐지 실행  규칙버전 {version}   범위 {since or '전체'} ~ {until or '전체'}")
        print("=" * 82)
        print(f"{'규칙':<6} {'이름':<18} {'신호':>8} {'인시던트':>10} {'신규':>8}  압축률   통합창")
        print("-" * 82)
        tot_s = tot_i = 0
        for rid, name, ns, ni, nn, g in summary:
            comp = f"{100 * (1 - ni / ns):5.1f}%" if ns else "    -"
            print(f"{rid:<6} {name:<18} {ns:>8,} {ni:>10,} {nn:>8,}  {comp}  {g // 60:>4}분")
            tot_s += ns; tot_i += ni
        print("-" * 82)
        comp = f"{100 * (1 - tot_i / tot_s):5.1f}%" if tot_s else "-"
        print(f"{'합계':<25} {tot_s:>8,} {tot_i:>10,} {created:>8,}  {comp}")
        print(f"\n  기존과 동일해 건너뛴 항목 {skipped:,}건 (멱등)")
        print(f"  기본 통합 창 {gap}초 ({gap // 60}분), 규칙별 지정이 있으면 그 값을 쓴다\n")
    return summary


def list_incidents(conn, limit, severity=None, status=None):
    cur = conn.cursor()
    c, p = [], []
    if severity:
        c.append("severity = %s"); p.append(severity)
    if status:
        c.append("status = %s"); p.append(status)
    w = ("WHERE " + " AND ".join(c)) if c else ""
    cur.execute(f"""
        SELECT rule_id, rule_version, severity, host(actor_ip), first_ts,
               signal_count, session_count, status
        FROM incidents {w}
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                               WHEN 'medium' THEN 2 ELSE 3 END, first_ts DESC
        LIMIT %s""", p + [limit])
    print(f"{'규칙':<6} {'버전':<5} {'심각도':<9} {'출발지':<17} {'시작':<20} {'신호':>6} {'세션':>5} {'상태'}")
    print("-" * 96)
    for r in cur.fetchall():
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:<9} {(r[3] or '-'):<17} "
              f"{r[4].strftime('%Y-%m-%d %H:%M:%S'):<20} {r[5]:>6,} {(r[6] or 0):>5} {r[7]}")
    print()
    cur.close()


def compare(conn, v1, v2):
    """두 규칙 버전의 결과를 비교한다. 리플레이 평가의 출력부."""
    cur = conn.cursor()
    cur.execute("""
        SELECT rule_id, severity,
               count(*) FILTER (WHERE rule_version = %s) a,
               count(*) FILTER (WHERE rule_version = %s) b
        FROM incidents WHERE rule_version IN (%s, %s)
        GROUP BY rule_id, severity ORDER BY rule_id""", (v1, v2, v1, v2))
    print(f"\n{'규칙':<6} {'심각도':<9} {v1:>10} {v2:>10} {'증감':>10}")
    print("-" * 50)
    ta = tb = 0
    for rid, sev, a, b in cur.fetchall():
        print(f"{rid:<6} {sev:<9} {a:>10,} {b:>10,} {b - a:>+10,}")
        ta += a; tb += b
    print("-" * 50)
    print(f"{'합계':<16} {ta:>10,} {tb:>10,} {tb - ta:>+10,}\n")
    cur.close()


def quality(conn):
    """규칙 버전별 오탐률·비조치율. 판정이 쌓인 뒤에 의미가 생긴다."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM rule_quality ORDER BY rule_id, rule_version")
    rows = cur.fetchall()
    print(f"\n{'규칙':<6} {'버전':<5} {'인시던트':>8} {'판정':>6} {'위협':>6} "
          f"{'무시가능':>8} {'오탐':>6} {'오탐률':>8} {'비조치율':>9}")
    print("-" * 76)
    for r in rows:
        fp = f"{r[7]}%" if r[7] is not None else "-"
        na = f"{r[8]}%" if r[8] is not None else "-"
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:>8,} {r[3]:>6,} {r[4]:>6,} "
              f"{r[5]:>8,} {r[6]:>6,} {fp:>8} {na:>9}")
    if not any(r[3] for r in rows):
        print("\n  판정 기록이 없습니다. 콘솔에서 인시던트를 판정하면 여기에 반영됩니다.")
    print()
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 탐지 엔진 (PostgreSQL)")
    ap.add_argument("--db-url", dest="url", help="미지정 시 환경변수 DATABASE_URL 사용")
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--severity"); ap.add_argument("--status")
    ap.add_argument("--compare", nargs=2, metavar=("V1", "V2"))
    ap.add_argument("--quality", action="store_true", help="오탐률·비조치율 집계")
    args = ap.parse_args()

    conn = psycopg2.connect(db_url(args.url))

    if args.run:
        with open(args.rules, encoding="utf-8") as f:
            run(conn, json.load(f), args.since, args.until)
    if args.list:
        list_incidents(conn, args.limit, args.severity, args.status)
    if args.compare:
        compare(conn, *args.compare)
    if args.quality:
        quality(conn)
    if not (args.run or args.list or args.compare or args.quality):
        ap.print_help()

    conn.close()


if __name__ == "__main__":
    main()