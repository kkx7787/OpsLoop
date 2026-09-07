#!/usr/bin/env python3
"""
OpsLoop - 탐지 엔진 (WBS 2.3)

정규화된 이벤트에 규칙을 적용해 인시던트를 만든다.

핵심 설계
  1. detect(rule_version, start, end) 형태로 시간 범위와 규칙 버전을 인자로 받는다.
     기간을 코드에 박지 않아야 같은 구간에 다른 규칙 버전을 재적용(리플레이)할 수 있다.
  2. 신호(signal)와 인시던트(incident)를 분리한다.
     신호는 규칙에 걸린 개별 사건, 인시던트는 그것을 사람이 볼 단위로 묶은 것.
     알림 피로는 이 통합 단계에서 줄인다.
  3. 멱등하다. 같은 (규칙, 버전, 대상, 시작시각)이면 다시 만들지 않는다.

사용
  python3 detect.py --run
  python3 detect.py --run --since 2026-09-05 --until 2026-09-06
  python3 detect.py --run --rules rules_v2.json      # 리플레이 비교
  python3 detect.py --list
  python3 detect.py --compare v1 v2
"""

import argparse
import json
import os
import sqlite3
import statistics
from datetime import datetime, timedelta

DEFAULT_DB = os.path.expanduser("~/opsloop/data/opsloop.db")
DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_key  TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    rule_version  TEXT NOT NULL,
    rule_name     TEXT,
    severity      TEXT NOT NULL,
    actor_ip      TEXT,
    first_ts      TEXT NOT NULL,
    last_ts       TEXT NOT NULL,
    signal_count  INTEGER NOT NULL,
    session_count INTEGER,
    evidence      TEXT,
    status        TEXT NOT NULL DEFAULT 'open',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inc_rule    ON incidents(rule_id, rule_version);
CREATE INDEX IF NOT EXISTS idx_inc_ts      ON incidents(first_ts);
CREATE INDEX IF NOT EXISTS idx_inc_actor   ON incidents(actor_ip);
CREATE INDEX IF NOT EXISTS idx_inc_status  ON incidents(status);

-- 조치 기록. 폐루프의 입력이 된다 (WBS 4.x)
CREATE TABLE IF NOT EXISTS actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT NOT NULL,
    action       TEXT NOT NULL,
    operator     TEXT,
    note         TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_act_incident ON actions(incident_key);

-- 판정 기록. 오탐률·비조치율 산출의 근거 (WBS 4.x)
CREATE TABLE IF NOT EXISTS verdicts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_key TEXT NOT NULL,
    verdict      TEXT NOT NULL,   -- threat | non_actionable | false_positive
    reason       TEXT,
    observed_value REAL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ver_incident ON verdicts(incident_key);
"""


def now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def parse_ts(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def range_clause(since, until, col):
    c, p = ["provenance='real'"], []
    if since:
        c.append(f"{col} >= ?"); p.append(since)
    if until:
        c.append(f"{col} < ?"); p.append(until)
    return " AND ".join(c), p


# ----------------------------------------------------------------------
#  규칙별 신호 수집
#  각 함수는 (ts, actor_ip, session, detail) 튜플 목록을 돌려준다
# ----------------------------------------------------------------------

def signals_session_threshold(cur, rule, since, until):
    p = rule["params"]
    if p["op"] not in (">=", ">", "=", "<=", "<"):
        raise ValueError(f"{rule['id']}: 허용되지 않은 연산자 {p['op']}")
    w, prm = range_clause(since, until, "first_ts")
    sql = (f"SELECT first_ts, src_ip, session, {p['field']} "
           f"FROM sessions WHERE {w} AND {p['field']} {p['op']} ?")
    rows = cur.execute(sql, prm + [p["value"]]).fetchall()
    return [(ts, ip, sess, {p["field"]: val}) for ts, ip, sess, val in rows]


def signals_session_compound(cur, rule, since, until):
    w, prm = range_clause(since, until, "first_ts")
    expr = rule["params"]["expr"]
    sql = (f"SELECT first_ts, src_ip, session, login_attempts, command_count "
           f"FROM sessions WHERE {w} AND ({expr})")
    rows = cur.execute(sql, prm).fetchall()
    return [(ts, ip, sess, {"login_attempts": la, "command_count": cc})
            for ts, ip, sess, la, cc in rows]


def signals_event_match(cur, rule, since, until):
    p = rule["params"]
    w, prm = range_clause(since, until, "ts")
    if "eventid" in p:
        cond, extra = "eventid = ?", [p["eventid"]]
    else:
        cond, extra = "eventid LIKE ?", [p["eventid_like"]]
    sql = (f"SELECT ts, src_ip, session, eventid, COALESCE(shasum, url, input, message) "
           f"FROM events WHERE {w} AND {cond}")
    rows = cur.execute(sql, prm + extra).fetchall()
    return [(ts, ip, sess, {"eventid": ev, "detail": d}) for ts, ip, sess, ev, d in rows]


def signals_baseline_deviation(cur, rule, since, until):
    """시간당 이벤트 수가 평균 + kσ 를 넘는 구간을 신호로 만든다.

    통계적 이상탐지지만 학습 모델이 아니다. 관측 구간의 평균과 표준편차를
    계산해 임계선을 정하는 기술 통계다. 규칙에 없는 새 패턴을 잡기 위한 보완 장치.
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "ts")
    rows = cur.execute(
        f"SELECT substr(ts,1,13), COUNT(*) FROM events WHERE {w} GROUP BY 1 ORDER BY 1", prm
    ).fetchall()
    if len(rows) < p.get("min_buckets", 24):
        return []
    counts = [c for _, c in rows]
    mean = statistics.mean(counts)
    sd = statistics.pstdev(counts)
    if sd == 0:
        return []
    limit = mean + p["sigma"] * sd
    out = []
    for bucket, c in rows:
        if c > limit:
            out.append((bucket + ":00:00+00:00", None, None,
                        {"bucket": bucket, "count": c,
                         "mean": round(mean, 1), "sigma": round(sd, 1),
                         "limit": round(limit, 1)}))
    return out


COLLECTORS = {
    "session_threshold": signals_session_threshold,
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
    한 IP가 사흘 내내 두드려도, 끊김 없이 이어지면 인시던트 하나다.
    이것이 알림 피로를 줄이는 지점이다.
    """
    buckets = {}
    for ts, ip, sess, detail in signals:
        t = parse_ts(ts)
        if t is None:
            continue
        buckets.setdefault(ip, []).append((t, ts, sess, detail))

    groups = []
    for ip, items in buckets.items():
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
    cur = conn.cursor()
    version = rules_doc["rule_version"]
    gap = rules_doc["aggregation"]["window_gap_seconds"]
    created = skipped = 0
    summary = []

    for rule in rules_doc["rules"]:
        if not rule.get("enabled", True):
            continue
        collector = COLLECTORS.get(rule["type"])
        if collector is None:
            raise ValueError(f"{rule['id']}: 알 수 없는 규칙 유형 {rule['type']}")

        signals = collector(cur, rule, since, until)
        groups = aggregate(signals, gap)
        n_new = 0

        for ip, items in groups:
            first_ts = items[0][1]
            last_ts = items[-1][1]
            sessions = {i[2] for i in items if i[2]}
            key = f"{rule['id']}|{version}|{ip or '-'}|{first_ts}"
            evidence = {
                "sample": [i[3] for i in items[:5]],
                "sessions": sorted(sessions)[:10],
            }
            cur.execute(
                """INSERT OR IGNORE INTO incidents
                   (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
                    first_ts, last_ts, signal_count, session_count, evidence, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,'open',?)""",
                (key, rule["id"], version, rule["name"], rule["severity"], ip,
                 first_ts, last_ts, len(items), len(sessions),
                 json.dumps(evidence, ensure_ascii=False), now()),
            )
            if cur.rowcount:
                n_new += 1
            else:
                skipped += 1
        created += n_new
        summary.append((rule["id"], rule["name"], len(signals), len(groups), n_new))

    conn.commit()

    if verbose:
        print("=" * 72)
        print(f" 탐지 실행  규칙버전 {version}   범위 {since or '전체'} ~ {until or '전체'}")
        print("=" * 72)
        print(f"{'규칙':<6} {'이름':<18} {'신호':>8} {'인시던트':>10} {'신규':>8}  압축률")
        print("-" * 72)
        tot_s = tot_i = 0
        for rid, name, ns, ni, nn in summary:
            comp = f"{100*(1-ni/ns):5.1f}%" if ns else "    -"
            print(f"{rid:<6} {name:<18} {ns:>8,} {ni:>10,} {nn:>8,}  {comp}")
            tot_s += ns; tot_i += ni
        print("-" * 72)
        comp = f"{100*(1-tot_i/tot_s):5.1f}%" if tot_s else "-"
        print(f"{'합계':<25} {tot_s:>8,} {tot_i:>10,} {created:>8,}  {comp}")
        print(f"\n  기존 인시던트와 동일해 건너뛴 항목 {skipped:,}건 (멱등)")
        print(f"  통합 창: {gap}초 ({gap//60}분)\n")
    return summary


def list_incidents(conn, limit, severity=None, status=None):
    cur = conn.cursor()
    c, p = [], []
    if severity:
        c.append("severity = ?"); p.append(severity)
    if status:
        c.append("status = ?"); p.append(status)
    w = ("WHERE " + " AND ".join(c)) if c else ""
    rows = cur.execute(
        f"""SELECT rule_id, rule_version, severity, actor_ip, first_ts, last_ts,
                   signal_count, session_count, status
            FROM incidents {w}
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END, first_ts DESC
            LIMIT ?""", p + [limit]).fetchall()
    print(f"{'규칙':<6} {'버전':<5} {'심각도':<9} {'출발지':<17} {'시작':<20} {'신호':>6} {'세션':>5} {'상태'}")
    print("-" * 96)
    for r in rows:
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:<9} {(r[3] or '-'):<17} {r[4][:19]:<20} "
              f"{r[6]:>6,} {(r[7] or 0):>5} {r[8]}")
    print()


def compare(conn, v1, v2):
    """두 규칙 버전의 결과를 비교한다. 리플레이 평가의 출력부."""
    cur = conn.cursor()
    print(f"\n{'규칙':<6} {'심각도':<9} {v1:>10} {v2:>10} {'증감':>10}")
    print("-" * 50)
    rows = cur.execute(
        """SELECT rule_id, severity,
                  SUM(rule_version = ?) AS a,
                  SUM(rule_version = ?) AS b
           FROM incidents WHERE rule_version IN (?, ?)
           GROUP BY rule_id, severity ORDER BY rule_id""", (v1, v2, v1, v2)).fetchall()
    ta = tb = 0
    for rid, sev, a, b in rows:
        d = (b or 0) - (a or 0)
        print(f"{rid:<6} {sev:<9} {a or 0:>10,} {b or 0:>10,} {d:>+10,}")
        ta += a or 0; tb += b or 0
    print("-" * 50)
    print(f"{'합계':<16} {ta:>10,} {tb:>10,} {tb-ta:>+10,}\n")


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 탐지 엔진")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--run", action="store_true", help="탐지 실행")
    ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--list", action="store_true", help="인시던트 목록")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--severity"); ap.add_argument("--status")
    ap.add_argument("--compare", nargs=2, metavar=("V1", "V2"), help="두 규칙 버전 비교")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.executescript(SCHEMA)

    if args.run:
        with open(args.rules, encoding="utf-8") as f:
            rules_doc = json.load(f)
        run(conn, rules_doc, args.since, args.until)
    if args.list:
        list_incidents(conn, args.limit, args.severity, args.status)
    if args.compare:
        compare(conn, *args.compare)
    if not (args.run or args.list or args.compare):
        ap.print_help()

    conn.close()


if __name__ == "__main__":
    main()