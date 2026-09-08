#!/usr/bin/env python3
"""
OpsLoop - 인시던트 검토 도구 (WBS 2.5 / 폐루프 입력부)

인시던트를 하나씩 보여주고 판정을 받는다. 폐루프는 여기서 시작한다.
자동화할 수 없는 유일한 단계이므로, 사람이 최대한 빨리 판단할 수 있게
증거를 압축해 보여주는 것이 이 도구의 전부다.

판정을 받을 때 그 인시던트의 관측값을 함께 남긴다. 이것이 중요하다.
판정 없이 관측 분포만 보면 "많이 일어나는 값"밖에 알 수 없지만,
판정이 붙으면 "위협인 값"과 "무시해도 되는 값"이 분리된다.
임계치는 그 경계에서 나와야 하며, 그 경계는 사람의 판단에서만 나온다.

  threat          탐지도 옳고 조치도 필요하다
  non_actionable  탐지는 옳으나 조치할 것이 없다
  false_positive  탐지가 틀렸다. 규칙이 의도한 현상이 아니다

세 번째를 두 번째와 섞으면 규칙을 고쳐야 할 때와 임계치만 올리면 될 때를
구분할 수 없게 된다. 오탐률과 비조치율을 따로 두는 이유가 이것이다.

사용
  set -a; . /etc/opsloop/collector.env; set +a
  python3 detector/triage.py                 미판정 인시던트 순회
  python3 detector/triage.py --rule R001     특정 규칙만
  python3 detector/triage.py --summary       진척도와 규칙 품질
  python3 detector/triage.py --thresholds    판정 분포에서 임계치 후보 도출
"""

import argparse
import json
import os
import sys
from datetime import timezone

try:
    import psycopg2
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

VERDICTS = {
    "t": ("threat", "실제 위협"),
    "n": ("non_actionable", "무시 가능"),
    "f": ("false_positive", "오탐"),
}

BAR = "=" * 78
DIV = "-" * 78


def db_url(arg):
    url = arg or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다. 환경변수나 --db-url 로 주세요.")
    return url


def kst(ts):
    """저장은 UTC 로 하고 보여줄 때만 현지 시각으로 옮긴다."""
    return ts.astimezone().strftime("%m-%d %H:%M:%S")


# ────────────────────────────────────────────────────────────────
#  증거 수집
# ────────────────────────────────────────────────────────────────

def gather_evidence(cur, ip, first_ts, last_ts):
    """인시던트 구간에서 그 출발지가 실제로 무엇을 했는지 모은다.

    규칙이 남긴 evidence 는 규칙이 본 것만 담고 있다. 판정하려면 규칙이
    보지 않은 것까지 봐야 한다. 예를 들어 무차별 대입으로 걸린 IP 가
    같은 구간에 명령을 실행했는지는 R001 의 증거에 없다.
    """
    ev = {}

    if ip:
        cur.execute("""
            SELECT username, password, count(*) FROM events
            WHERE src_ip = %s AND ts BETWEEN %s AND %s
              AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
            GROUP BY username, password ORDER BY count(*) DESC LIMIT 6""",
            (ip, first_ts, last_ts))
        ev["creds"] = cur.fetchall()

        cur.execute("""
            SELECT input, count(*) FROM events
            WHERE src_ip = %s AND ts BETWEEN %s AND %s
              AND eventid = 'cowrie.command.input' AND input IS NOT NULL
            GROUP BY input ORDER BY count(*) DESC LIMIT 8""",
            (ip, first_ts, last_ts))
        ev["commands"] = cur.fetchall()

        cur.execute("""
            SELECT eventid, shasum, url FROM events
            WHERE src_ip = %s AND ts BETWEEN %s AND %s
              AND eventid LIKE 'cowrie.session.file_%%' LIMIT 5""",
            (ip, first_ts, last_ts))
        ev["files"] = cur.fetchall()

        # 같은 출발지가 다른 규칙에도 걸렸는지. 단독으로는 애매한 신호도
        # 다른 규칙과 겹치면 판단이 쉬워진다.
        cur.execute("""
            SELECT rule_id, rule_name, severity, count(*) FROM incidents
            WHERE actor_ip = %s GROUP BY rule_id, rule_name, severity
            ORDER BY rule_id""", (ip,))
        ev["also"] = cur.fetchall()

        cur.execute("SELECT 1 FROM blocklist WHERE actor_ip = %s AND released_at IS NULL", (ip,))
        ev["blocked"] = cur.fetchone() is not None

    return ev


def show(cur, row, idx, total):
    (key, rid, ver, rname, sev, ip, first_ts, last_ts,
     n_sig, n_sess, evidence, status) = row

    print("\n" + BAR)
    print(f" [{idx}/{total}]  {sev.upper():<9} {rid} {rname}   (규칙 {ver})")
    print(BAR)
    print(f"  출발지   {ip or '-'}")
    print(f"  기간     {kst(first_ts)} ~ {kst(last_ts)}"
          f"   ({int((last_ts - first_ts).total_seconds())}초)")
    print(f"  규모     신호 {n_sig}건 · 세션 {n_sess}개")

    ev = gather_evidence(cur, ip, first_ts, last_ts)

    if ev.get("blocked"):
        print("  상태     이 출발지는 이미 차단되어 있다")

    if ev.get("creds"):
        print(f"\n  로그인 시도")
        for u, p, c in ev["creds"]:
            print(f"    {(u or '-'):<16} / {(p or '-'):<20} {c:>4}회")

    if ev.get("commands"):
        print(f"\n  실행한 명령")
        for cmd, c in ev["commands"]:
            line = cmd.replace("\n", " ")[:62]
            print(f"    {line}" + (f"   ({c}회)" if c > 1 else ""))

    if ev.get("files"):
        print(f"\n  파일 이동")
        for eid, sha, url in ev["files"]:
            what = (url or sha or "-")[:52]
            print(f"    {eid.split('.')[-1]:<12} {what}")

    if ev.get("also") and len(ev["also"]) > 1:
        print(f"\n  같은 출발지가 걸린 다른 규칙")
        for r_id, r_name, r_sev, c in ev["also"]:
            mark = " ←" if r_id == rid else ""
            print(f"    {r_id} {r_name:<18} {r_sev:<9} {c}건{mark}")

    if evidence:
        sample = (evidence or {}).get("sample") or []
        if sample:
            print(f"\n  규칙이 본 것")
            for s in sample[:3]:
                print(f"    {str(s)[:66]}")

    print(DIV)


# ────────────────────────────────────────────────────────────────
#  판정 기록
# ────────────────────────────────────────────────────────────────

def record(conn, key, ip, verdict, reason, observed, operator, block):
    cur = conn.cursor()

    # 판정과 조치는 한 트랜잭션에 넣는다. 판정만 남고 조치가 유실되면
    # 나중에 "왜 차단했는지"는 알아도 "차단했는지"를 모르게 된다.
    cur.execute("""
        INSERT INTO verdicts (incident_key, verdict, reason, observed_value, operator)
        VALUES (%s, %s, %s, %s, %s)""",
        (key, verdict, reason, observed, operator))

    if block and ip:
        cur.execute("""
            INSERT INTO actions (incident_key, action, operator, note)
            VALUES (%s, 'block_ip', %s, %s)""", (key, operator, reason))
        cur.execute("""
            INSERT INTO blocklist (actor_ip, reason, incident_key)
            VALUES (%s, %s, %s)
            ON CONFLICT (actor_ip) DO UPDATE
              SET released_at = NULL, reason = EXCLUDED.reason,
                  incident_key = EXCLUDED.incident_key""",
            (ip, reason, key))
        cur.execute("UPDATE incidents SET status = 'resolved' WHERE incident_key = %s", (key,))
    else:
        cur.execute("""
            INSERT INTO actions (incident_key, action, operator, note)
            VALUES (%s, 'acknowledge', %s, %s)""", (key, operator, reason))
        cur.execute("UPDATE incidents SET status = 'acknowledged' WHERE incident_key = %s", (key,))

    conn.commit()
    cur.close()


def triage(conn, rule_id, limit, operator):
    cur = conn.cursor()
    c, p = ["v.id IS NULL"], []
    if rule_id:
        c.append("i.rule_id = %s"); p.append(rule_id)
    cur.execute(f"""
        SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity,
               host(i.actor_ip), i.first_ts, i.last_ts, i.signal_count,
               i.session_count, i.evidence, i.status
        FROM incidents i
        LEFT JOIN verdicts v ON v.incident_key = i.incident_key
        WHERE {' AND '.join(c)}
        ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                 WHEN 'medium' THEN 2 ELSE 3 END,
                 i.first_ts
        LIMIT %s""", p + [limit])
    rows = cur.fetchall()

    if not rows:
        print("\n  미판정 인시던트가 없습니다.\n")
        return

    print(f"\n  미판정 {len(rows)}건. 판정은 오탐률·비조치율의 근거가 되고,")
    print(f"  기록되는 관측값은 다음 임계치의 근거가 됩니다.\n")

    done = 0
    for i, row in enumerate(rows, 1):
        show(cur, row, i, len(rows))
        key, ip, n_sig = row[0], row[5], row[8]

        while True:
            ans = input("  [t] 실제 위협  [n] 무시 가능  [f] 오탐  "
                        "[s] 건너뜀  [q] 종료 > ").strip().lower()
            if ans == "q":
                print(f"\n  {done}건 판정하고 종료합니다.\n")
                cur.close()
                return
            if ans == "s":
                break
            if ans in VERDICTS:
                verdict, label = VERDICTS[ans]
                reason = input(f"  근거 (엔터 = '{label}') > ").strip() or label
                block = False
                if verdict == "threat" and ip:
                    block = input("  이 출발지를 차단할까요? [y/N] > ").strip().lower() == "y"
                record(conn, key, ip, verdict, reason, float(n_sig), operator, block)
                done += 1
                print(f"  기록됨: {label}" + ("  · 차단" if block else ""))
                break
            print("  t / n / f / s / q 중 하나를 입력하세요.")

    print(f"\n  {done}건 판정 완료. 다음은 --summary 로 확인하세요.\n")
    cur.close()


# ────────────────────────────────────────────────────────────────
#  집계
# ────────────────────────────────────────────────────────────────

def summary(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT count(*), count(v.id)
        FROM incidents i LEFT JOIN verdicts v ON v.incident_key = i.incident_key""")
    total, judged = cur.fetchone()

    if not total:
        print("\n  인시던트가 없습니다.\n")
        cur.close()
        return
    print(f"\n  판정 진척  {judged} / {total}  ({100 * judged / total:.0f}%)")

    cur.execute("SELECT * FROM rule_quality ORDER BY rule_id, rule_version")
    print(f"\n{'규칙':<6} {'버전':<5} {'인시던트':>8} {'판정':>5} {'위협':>5} "
          f"{'무시':>5} {'오탐':>5} {'오탐률':>8} {'비조치율':>9}")
    print(DIV)
    for r in cur.fetchall():
        fp = f"{r[7]}%" if r[7] is not None else "-"
        na = f"{r[8]}%" if r[8] is not None else "-"
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:>8,} {r[3]:>5,} {r[4]:>5,} "
              f"{r[5]:>5,} {r[6]:>5,} {fp:>8} {na:>9}")
    print()
    cur.close()


def thresholds(conn):
    """판정된 관측값의 분포에서 임계치 후보를 뽑는다.

    조치가 필요했던 것들의 최솟값과, 조치가 불필요했던 것들의 최댓값
    사이가 후보 구간이다. 두 분포가 겹치면 그 규칙은 임계치를 올리는
    것으로 해결되지 않고 조건 자체를 바꿔야 한다는 뜻이다.
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT i.rule_id, i.rule_version,
               min(v.observed_value) FILTER (WHERE v.verdict = 'threat'),
               max(v.observed_value) FILTER (WHERE v.verdict = 'threat'),
               count(*)              FILTER (WHERE v.verdict = 'threat'),
               min(v.observed_value) FILTER (WHERE v.verdict <> 'threat'),
               max(v.observed_value) FILTER (WHERE v.verdict <> 'threat'),
               count(*)              FILTER (WHERE v.verdict <> 'threat')
        FROM incidents i JOIN verdicts v ON v.incident_key = i.incident_key
        WHERE v.observed_value IS NOT NULL
        GROUP BY i.rule_id, i.rule_version ORDER BY i.rule_id""")
    rows = cur.fetchall()

    if not rows:
        print("\n  판정 기록이 없습니다. 먼저 triage 를 돌리세요.\n")
        return

    print(f"\n{'규칙':<6} {'버전':<5} {'위협 관측값':>14} {'n':>4} "
          f"{'비위협 관측값':>16} {'n':>4}  판단")
    print("=" * 78)
    for rid, ver, t_min, t_max, t_n, o_min, o_max, o_n in rows:
        t = f"{t_min:.0f}~{t_max:.0f}" if t_n else "-"
        o = f"{o_min:.0f}~{o_max:.0f}" if o_n else "-"

        if not t_n:
            note = "위협 판정 없음. 규칙 재검토"
        elif not o_n:
            note = "전부 위협. 임계치 낮출 여지"
        elif o_max < t_min:
            note = f"분리됨. 임계치 후보 {int(o_max) + 1}"
        else:
            note = "분포 겹침. 조건 변경 필요"

        print(f"{rid:<6} {ver:<5} {t:>14} {t_n:>4} {o:>16} {o_n:>4}  {note}")
    print()
    print("  분리됨   : 관측값만으로 위협과 비위협이 갈린다. 임계치를 올리면 된다")
    print("  겹침     : 같은 값에 두 판정이 모두 있다. 임계치로는 못 나눈다")
    print()
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 인시던트 검토")
    ap.add_argument("--db-url", dest="url")
    ap.add_argument("--rule", help="특정 규칙만 검토")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--operator", default=os.environ.get("USER", "operator"))
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--thresholds", action="store_true")
    a = ap.parse_args()

    conn = psycopg2.connect(db_url(a.url))
    try:
        if a.summary:
            summary(conn)
        elif a.thresholds:
            thresholds(conn)
        else:
            triage(conn, a.rule, a.limit, a.operator)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
