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
    """세션 지표의 논리식으로 거른다.

    v2 에서 조건 하나가 붙었다. 명령을 실행했다는 것과 무언가를 했다는 것은
    다르다. 관측된 봇 상당수가 로그인 후 `echo` 한 줄만 찍고 끊는다.
    자격증명이 먹히는지 확인하는 행위이지 침해 후 행위가 아니다.
    noop_command_patterns 에 걸리지 않는 명령이 하나라도 있어야 신호가 된다.
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "first_ts")
    cond, extra = f"({p['expr']})", []
    noop = p.get("noop_command_patterns")
    if noop:
        cond += (" AND EXISTS (SELECT 1 FROM events e WHERE e.session = sessions.session"
                 " AND e.eventid = 'cowrie.command.input' AND e.input IS NOT NULL"
                 " AND e.input !~* ALL(%s))")
        extra.append(noop)
    cur.execute(
        f"SELECT first_ts, src_ip, session, login_attempts, command_count "
        f"FROM sessions WHERE {w} AND {cond}", prm + extra)
    return [(ts, ip, s, {"login_attempts": la, "command_count": cc})
            for ts, ip, s, la, cc in cur.fetchall()]


def signals_event_match(cur, rule, since, until):
    """이벤트 하나로 성립하는 규칙.

    v2 에서 제외 목록이 붙었다. 파일 이동 이벤트가 있다는 것과 악성코드가
    들어왔다는 것은 다르다. 빈 파일(0바이트)의 해시가 반복 관측되었고,
    이것을 critical 로 올리는 것은 규칙이 겨냥한 현상이 아니다.
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "ts")
    if "eventid" in p:
        cond, extra = "eventid = %s", [p["eventid"]]
    else:
        cond, extra = "eventid LIKE %s", [p["eventid_like"]]
    for pref in p.get("exclude_shasum_prefixes", []):
        cond += " AND (shasum IS NULL OR shasum NOT LIKE %s)"
        extra.append(pref + "%")
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

    # v2: 이미 다른 규칙이 잡은 행위자를 기준선에서 뺀다.
    #
    # 이 규칙은 "규칙에 없는 새 패턴"을 잡으라고 넣었는데, v1 에서 잡은 두 건이
    # 모두 기존 규칙이 이미 잡은 IP 하나의 폭주였다. 전체 이벤트로 기준선을
    # 계산하면 한 행위자의 활동이 기준선을 흔들고, 그 흔들림을 자기가 다시
    # 잡는다. 새 패턴이 아니라 기존 규칙의 그림자를 잡는 것이다.
    #
    # 같은 실행 안에서 앞선 규칙들이 만든 인시던트를 본다. 그래서 이 규칙은
    # 규칙 목록의 마지막에 있어야 한다.
    excl = []
    if p.get("exclude_alerted_actors"):
        cur.execute(
            "SELECT DISTINCT host(actor_ip) FROM incidents "
            "WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL",
            (p["_version"], rule["id"]))
        excl = [r[0] for r in cur.fetchall()]

    cond = w
    if excl:
        cond += " AND (src_ip IS NULL OR host(src_ip) <> ALL(%s))"
        prm = prm + [excl]

    cur.execute(
        f"SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE {cond} GROUP BY 1 ORDER BY 1",
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
              "sigma": round(sd, 1), "limit": round(limit, 1),
              "excluded_actors": len(excl)})
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


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def suppress(cur, rules_doc, staged):
    """더 높은 심각도 알림에 흡수되는 인시던트를 지운다.

    판정 결과 R001 의 비조치율이 100% 였다. 관측값은 임계치의 5배까지
    올라갔는데도 전부 "무시 가능"이었고, 이유는 모두 같았다. 같은 행위자에
    대해 같은 시간대에 더 심각한 알림이 이미 떠 있었다.

    임계치를 올려서 해결되는 문제가 아니다. 관측값 전 구간이 비위협이므로
    임계치를 올리면 규칙이 아무것도 잡지 않게 될 뿐이다. 문제는 값이 아니라
    같은 사건을 여러 규칙이 각자 보고한다는 데 있다.

    그래서 값이 아니라 구조를 바꾼다. 규칙은 그대로 두고, 인시던트를 만드는
    단계에서 상위 심각도 알림에 흡수시킨다. 규칙을 지우지 않는 이유는 분명하다.
    상위 알림이 없을 때는 이 규칙이 유일한 탐지이기 때문이다.
    허니팟은 대부분의 비밀번호를 통과시켜 무차별 대입이 거의 항상 로그인
    성공으로 이어지지만, 실제 서버에서는 실패만 반복하는 쪽이 다수다.
    """
    conf = rules_doc["suppression"]
    if not conf.get("absorb_by_higher_severity"):
        return {}
    gap = conf.get("window_seconds", 900)

    flat = [(rule["id"], r) for rule, rows, _, _ in staged for r in rows]
    victims, counts = [], {}

    for rid, r in flat:
        rank, ip, first_ts, last_ts = SEVERITY_RANK[r[4]], r[5], r[6], r[7]
        if ip is None:
            continue
        for orid, o in flat:
            if o[0] == r[0] or o[5] != ip:
                continue
            if SEVERITY_RANK[o[4]] < rank and \
               (o[6] - last_ts).total_seconds() <= gap and \
               (first_ts - o[7]).total_seconds() <= gap:
                victims.append(r[0])
                counts[rid] = counts.get(rid, 0) + 1
                break

    if victims:
        # 판정이 붙은 인시던트는 지우지 않는다. 사람이 내린 판단이 사라지면
        # 폐루프의 근거가 함께 사라진다. 새 버전에서만 억제가 적용된다.
        cur.execute("""DELETE FROM incidents i WHERE i.incident_key = ANY(%s)
                       AND NOT EXISTS (SELECT 1 FROM verdicts v
                                       WHERE v.incident_key = i.incident_key)""",
                    (victims,))
    return counts


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
    staged = []   # (rule, rows, signal_count)

    for rule in rules_doc["rules"]:
        if not rule.get("enabled", True):
            continue
        collector = COLLECTORS.get(rule["type"])
        if collector is None:
            raise ValueError(f"{rule['id']}: 알 수 없는 규칙 유형 {rule['type']}")

        # 고정 시간창으로 신호를 만드는 규칙은 슬롯 경계 때문에 전역 창과
        # 같은 값을 쓰면 연속 활동이 쪼개진다. 규칙별 지정을 우선한다.
        rule_gap = rule.get("aggregation_gap_seconds", gap)
        rule.setdefault("params", {})["_version"] = version
        signals = collector(cur, rule, since, until)
        groups = aggregate(signals, rule_gap)

        rows = []
        for ip, items in groups:
            first_ts, last_ts = items[0][0], items[-1][0]
            sessions = sorted({i[1] for i in items if i[1]})
            key = f"{rule['id']}|{version}|{ip or '-'}|{first_ts.isoformat()}"
            # 임계치와 비교되는 값을 신호 전체에서 뽑아 남긴다. 표본 몇 개만
            # 보고 나중에 다시 계산하면 큰 인시던트에서 최댓값을 놓친다.
            metrics = [i[2] for i in items if isinstance(i[2], dict)]
            counts = [m["count"] for m in metrics if "count" in m]
            devs = [(m["count"] - m["mean"]) / m["sigma"]
                    for m in metrics if m.get("sigma")]
            observed = {}
            if counts:
                observed["observed_count_max"] = max(counts)
            if devs:
                observed["observed_sigma_max"] = round(max(devs), 2)

            evidence = json.dumps(
                {"sample": [i[2] for i in items[:5]], "sessions": sessions[:10],
                 **observed},
                ensure_ascii=False, default=str)
            rows.append((key, rule["id"], version, rule["name"], rule["severity"], ip,
                         first_ts, last_ts, len(items), len(sessions), evidence))

        staged.append((rule, rows, len(signals), rule_gap))

        # 이 규칙의 인시던트를 바로 넣는다. 뒤 규칙(기준선 이탈)이 앞 규칙의
        # 결과를 보아야 하므로 억제 판단보다 적재가 먼저다. 억제된 것은
        # 아래에서 지운다.
        execute_batch(cur, """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (incident_key) DO NOTHING""", rows, page_size=200)

    suppressed = suppress(cur, rules_doc, staged) if rules_doc.get("suppression") else {}

    for rule, rows, n_signals, rule_gap in staged:
        cur.execute("SELECT count(*) FROM incidents WHERE rule_id = %s AND rule_version = %s",
                    (rule["id"], version))
        n_now = cur.fetchone()[0]
        n_sup = suppressed.get(rule["id"], 0)
        created += n_now
        summary.append((rule["id"], rule["name"], n_signals, len(rows), n_now, rule_gap, n_sup))

    conn.commit()
    cur.close()

    if verbose:
        print("=" * 82)
        print(f" 탐지 실행  규칙버전 {version}   범위 {since or '전체'} ~ {until or '전체'}")
        print("=" * 82)
        print(f"{'규칙':<6} {'이름':<18} {'신호':>8} {'통합':>8} {'억제':>6} {'인시던트':>9}  압축률   통합창")
        print("-" * 82)
        tot_s = tot_i = tot_x = 0
        for rid, name, ns, ni, nn, g, nx in summary:
            comp = f"{100 * (1 - (ni - nx) / ns):5.1f}%" if ns else "    -"
            print(f"{rid:<6} {name:<18} {ns:>8,} {ni:>8,} {nx:>6,} {nn:>9,}  {comp}  {g // 60:>4}분")
            tot_s += ns; tot_i += ni; tot_x += nx
        print("-" * 82)
        comp = f"{100 * (1 - (tot_i - tot_x) / tot_s):5.1f}%" if tot_s else "-"
        print(f"{'합계':<25} {tot_s:>8,} {tot_i:>8,} {tot_x:>6,} {created:>9,}  {comp}")
        if tot_x:
            print(f"\n  억제 {tot_x}건 — 같은 행위자·같은 구간에 더 높은 심각도 알림이 있어")
            print(f"  관제자에게 새 정보를 주지 않는 인시던트를 만들지 않았다")
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
