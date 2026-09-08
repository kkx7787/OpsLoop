#!/usr/bin/env python3
"""
OpsLoop - 인시던트 검토 도구 (WBS 2.5 / 폐루프 입력부)

판정은 폐루프의 유일한 비자동 단계다. 그러나 판정 기준(docs/2026-09-08-판정-기준.md)
중 상당 부분은 조회로 답이 나오는 조건이며, 그것까지 사람에게 시키면 판단이
아니라 받아쓰기가 된다. 그래서 이 도구는 판정을 **제안**하고 근거를 함께 보여준다.
사람은 수락하거나 뒤집는다.

  제안의 원칙
    1. 제안 근거는 되도록 규칙이 보지 않은 증거에서 가져온다.
       빈도로 걸린 인시던트를 "그 뒤에 무엇을 했는가"로 판정하면 순환이 아니다.
    2. 조건과 판정 근거가 겹치는 규칙은 그 사실을 화면에 밝힌다.
       그런 규칙에서 위협 판정이 100% 나오는 것은 규칙이 정확하다는 증거가
       아니라 같은 것을 두 번 센 것이다. 그 규칙에서 의미 있는 것은
       "이 알림이 따로 뜰 값어치가 있었는가", 즉 중복 여부다.
    3. 오탐(false_positive)은 절대 제안하지 않는다. 규칙이 틀렸다는 판단은
       규칙을 만든 쪽이 스스로 내릴 수 없다.

  수락과 뒤집기를 나눠 기록한다. 뒤집힌 비율이 낮으면 기준이 잘 잡힌 것이고,
  높으면 기준 문서를 고쳐야 한다는 뜻이다. 이 비율 자체가 지표다.

사용
  set -a; . /etc/opsloop/collector.env; set +a
  python3 detector/triage.py                 미판정 인시던트 순회
  python3 detector/triage.py --rule R001     특정 규칙만
  python3 detector/triage.py --summary       진척도·규칙 품질·제안 정확도
  python3 detector/triage.py --thresholds    판정 분포에서 임계치 후보 도출
"""

import argparse
import os
import sys

try:
    import psycopg2
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

VERDICTS = {
    "t": ("threat", "실제 위협"),
    "n": ("non_actionable", "무시 가능"),
    "f": ("false_positive", "오탐"),
}
LABEL = {v: l for v, l in VERDICTS.values()}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# 조건과 판정 근거가 겹치는 규칙. 여기서 나오는 위협 판정은 규칙의 정확성을
# 증명하지 않는다. 화면에 그 사실을 밝히고, 중복 여부만 제안한다.
CIRCULAR = {
    "R002": "규칙 조건이 '로그인 성공 + 명령 실행'이고 판정 기준의 위협 조건도 같다",
    "R003": "규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다",
    "R004": "규칙 조건이 경유 시도이고 판정 기준의 위협 조건도 같다",
}

BAR = "=" * 78
DIV = "-" * 78


def db_url(arg):
    url = arg or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다. 환경변수나 --db-url 로 주세요.")
    return url


def ensure_column(conn):
    """제안 기록용 열. 없으면 만든다.

    스키마 변경을 도구가 하는 것은 원칙적으로 피할 일이지만, 이 열 하나를
    위해 별도 절차를 두는 비용이 더 크다. 멱등이라 반복 실행해도 안전하다.
    """
    cur = conn.cursor()
    cur.execute("ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS proposed text")
    conn.commit()
    cur.close()


def local(ts):
    return ts.astimezone().strftime("%m-%d %H:%M:%S")


# ────────────────────────────────────────────────────────────────
#  증거 수집
# ────────────────────────────────────────────────────────────────

def gather(cur, ip, first_ts, last_ts, rule_id, severity):
    """인시던트 구간에서 그 출발지가 실제로 한 일을 모은다.

    규칙이 남긴 evidence 는 규칙이 본 것만 담고 있다. 판정하려면 규칙이
    보지 않은 것까지 봐야 한다.
    """
    ev = {"counts": {}, "creds": [], "commands": [], "files": [],
          "also": [], "blocked": False, "covered_by": None}
    if not ip:
        return ev

    cur.execute("""
        SELECT eventid, count(*) FROM events
        WHERE src_ip = %s AND ts BETWEEN %s AND %s
        GROUP BY eventid""", (ip, first_ts, last_ts))
    ev["counts"] = dict(cur.fetchall())

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
        GROUP BY input ORDER BY count(*) DESC LIMIT 6""",
        (ip, first_ts, last_ts))
    ev["commands"] = cur.fetchall()

    cur.execute("""
        SELECT eventid, shasum, url FROM events
        WHERE src_ip = %s AND ts BETWEEN %s AND %s
          AND eventid LIKE 'cowrie.session.file_%%' LIMIT 5""",
        (ip, first_ts, last_ts))
    ev["files"] = cur.fetchall()

    cur.execute("""
        SELECT rule_id, rule_name, severity, count(*) FROM incidents
        WHERE actor_ip = %s GROUP BY rule_id, rule_name, severity
        ORDER BY rule_id""", (ip,))
    ev["also"] = cur.fetchall()

    cur.execute("SELECT 1 FROM blocklist WHERE actor_ip = %s AND released_at IS NULL", (ip,))
    ev["blocked"] = cur.fetchone() is not None

    # 이미 위협으로 판정된, 같은 출발지의 겹치는 인시던트. 있으면 이 알림은
    # 새 정보를 주지 않았을 가능성이 있다. 알림 중복은 규칙 조건과 무관한
    # 증거이므로, 조건이 겹치는 규칙에서도 순환 없이 물을 수 있다.
    cur.execute("""
        SELECT i.rule_id, i.severity FROM incidents i
        JOIN verdicts v ON v.incident_key = i.incident_key
        WHERE i.actor_ip = %s AND v.verdict = 'threat'
          AND i.first_ts <= %s AND i.last_ts >= %s
        ORDER BY i.first_ts LIMIT 1""",
        (ip, last_ts, first_ts))
    row = cur.fetchone()
    if row and SEV_ORDER.get(row[1], 9) <= SEV_ORDER.get(severity, 9):
        ev["covered_by"] = row[0]

    return ev


# ────────────────────────────────────────────────────────────────
#  판정 제안
# ────────────────────────────────────────────────────────────────

def propose(rule_id, ev):
    """(판정, 근거줄들) 또는 (None, 근거줄들) 을 돌려준다."""
    c = ev["counts"]
    fails = c.get("cowrie.login.failed", 0)
    oks = c.get("cowrie.login.success", 0)
    cmds = c.get("cowrie.command.input", 0)
    files = sum(v for k, v in c.items() if k.startswith("cowrie.session.file_"))
    proxy = c.get("cowrie.direct-tcpip.request", 0)

    facts = (f"로그인 실패 {fails} · 성공 {oks} · 명령 {cmds} · "
             f"파일 {files} · 경유시도 {proxy}")

    if ev["covered_by"]:
        return "non_actionable", [
            facts,
            f"같은 출발지의 {ev['covered_by']} 인시던트가 이미 위협으로 판정됐고 구간이 겹친다",
            "따로 뜰 값어치가 없었던 알림이다. 조치는 이미 그쪽에서 이뤄진다"]

    if rule_id in CIRCULAR:
        return None, [
            facts,
            f"제안 없음 — {CIRCULAR[rule_id]}",
            "여기서 위협 판정은 규칙의 정확성을 증명하지 않는다.",
            "이 알림이 따로 뜰 값어치가 있었는지를 직접 보고 정하세요."]

    # 빈도·통계로 걸린 규칙은 그 뒤에 무엇을 했는지로 판정한다. 서로 다른 증거다.
    if cmds or files or proxy:
        why = []
        if cmds: why.append(f"명령 {cmds}회")
        if files: why.append(f"파일 {files}건")
        if proxy: why.append(f"경유 시도 {proxy}회")
        return "threat", [
            facts,
            f"빈도로 걸렸고 뒤이어 실제 행위가 있었다 ({', '.join(why)})",
            "규칙이 본 것과 다른 증거로 확인된 침해다"]

    if oks:
        return "non_actionable", [
            facts,
            "로그인에는 성공했으나 아무 명령도 실행하지 않았다",
            "탐지는 맞았으나 조치할 것이 없다"]

    if fails:
        return "non_actionable", [
            facts,
            "로그인 시도만 있고 성공도 후속 행위도 없다",
            "빈도 조건은 맞았으나 조치할 것이 없다"]

    return None, [facts, "제안 없음 — 근거가 될 행위 기록이 없다"]


# ────────────────────────────────────────────────────────────────
#  화면
# ────────────────────────────────────────────────────────────────

def show(row, idx, total, ev, suggestion, basis):
    (key, rid, ver, rname, sev, ip, first_ts, last_ts, n_sig, n_sess, _, _) = row

    print("\n" + BAR)
    print(f" [{idx}/{total}]  {sev.upper():<9} {rid} {rname}   (규칙 {ver})")
    print(BAR)
    print(f"  출발지   {ip or '-'}"
          + ("   [이미 차단됨]" if ev["blocked"] else ""))
    print(f"  기간     {local(first_ts)} ~ {local(last_ts)}"
          f"   ({int((last_ts - first_ts).total_seconds())}초)")
    print(f"  규모     신호 {n_sig}건 · 세션 {n_sess}개")

    if ev["creds"]:
        print("\n  로그인 시도")
        for u, p, n in ev["creds"]:
            print(f"    {(u or '-'):<14} / {(p or '-'):<18} {n:>4}회")

    if ev["commands"]:
        print("\n  실행한 명령")
        for cmd, n in ev["commands"]:
            print(f"    {cmd.replace(chr(10), ' ')[:62]}" + (f"  ({n}회)" if n > 1 else ""))

    if ev["files"]:
        print("\n  파일 이동")
        for eid, sha, url in ev["files"]:
            print(f"    {eid.split('.')[-1]:<12} {(url or sha or '-')[:50]}")

    if len(ev["also"]) > 1:
        print("\n  같은 출발지가 걸린 다른 규칙")
        for r_id, r_name, r_sev, n in ev["also"]:
            print(f"    {r_id} {r_name:<18} {r_sev:<9} {n}건" + ("  ←" if r_id == rid else ""))

    print()
    if suggestion:
        print(f"  제안     {LABEL[suggestion]}")
        print(f"  근거     {basis[0]}")
        for line in basis[1:]:
            print(f"           {line}")
    else:
        print(f"  제안     없음 — 직접 판단이 필요합니다")
        print(f"  참고     {basis[0]}")
        for line in basis[1:]:
            print(f"           {line}")
    print(DIV)


# ────────────────────────────────────────────────────────────────
#  기록
# ────────────────────────────────────────────────────────────────

def record(conn, key, ip, verdict, reason, observed, operator, proposed, block):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO verdicts (incident_key, verdict, reason, observed_value, operator, proposed)
        VALUES (%s,%s,%s,%s,%s,%s)""",
        (key, verdict, reason, observed, operator, proposed))

    if block and ip:
        cur.execute("INSERT INTO actions (incident_key, action, operator, note) "
                    "VALUES (%s,'block_ip',%s,%s)", (key, operator, reason))
        cur.execute("""
            INSERT INTO blocklist (actor_ip, reason, incident_key) VALUES (%s,%s,%s)
            ON CONFLICT (actor_ip) DO UPDATE
              SET released_at = NULL, reason = EXCLUDED.reason,
                  incident_key = EXCLUDED.incident_key""", (ip, reason, key))
        cur.execute("UPDATE incidents SET status='resolved' WHERE incident_key=%s", (key,))
    else:
        cur.execute("INSERT INTO actions (incident_key, action, operator, note) "
                    "VALUES (%s,'acknowledge',%s,%s)", (key, operator, reason))
        cur.execute("UPDATE incidents SET status='acknowledged' WHERE incident_key=%s", (key,))

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
        FROM incidents i LEFT JOIN verdicts v ON v.incident_key = i.incident_key
        WHERE {' AND '.join(c)}
        ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                 WHEN 'medium' THEN 2 ELSE 3 END, i.first_ts
        LIMIT %s""", p + [limit])
    rows = cur.fetchall()

    if not rows:
        print("\n  미판정 인시던트가 없습니다.\n")
        return

    print(f"\n  미판정 {len(rows)}건.")
    print("  제안이 붙은 것은 엔터로 수락, 다르게 보이면 t/n/f 로 뒤집습니다.")
    print("  제안이 없는 것은 조건과 판정 근거가 겹치는 규칙이라 직접 보셔야 합니다.\n")

    taken = flipped = skipped = judged = 0
    for i, row in enumerate(rows, 1):
        key, rid, ip, n_sig, sev = row[0], row[1], row[5], row[8], row[4]
        # 앞선 판정이 이 인시던트의 중복 여부를 바꾸므로 매번 다시 본다.
        ev = gather(cur, ip, row[6], row[7], rid, sev)
        suggestion, basis = propose(rid, ev)
        show(row, i, len(rows), ev, suggestion, basis)

        prompt = ("  [Enter] 제안 수락  [t] 위협  [n] 무시 가능  [f] 오탐  "
                  "[s] 건너뜀  [q] 종료 > ") if suggestion else \
                 ("  [t] 위협  [n] 무시 가능  [f] 오탐  [s] 건너뜀  [q] 종료 > ")

        while True:
            ans = input(prompt).strip().lower()
            if ans == "q":
                break
            if ans == "s":
                skipped += 1
                break
            if ans == "" and suggestion:
                verdict, note = suggestion, basis[1]
                taken += 1
            elif ans in VERDICTS:
                verdict = VERDICTS[ans][0]
                if suggestion:
                    if verdict != suggestion:
                        flipped += 1
                    else:
                        taken += 1
                note = input(f"  근거 (엔터 = '{LABEL[verdict]}') > ").strip() or LABEL[verdict]
            else:
                print("  입력을 다시 확인하세요.")
                continue

            block = False
            if verdict == "threat" and ip:
                block = input("  이 출발지를 차단 목록에 올릴까요? [y/N] > ").strip().lower() == "y"
            record(conn, key, ip, verdict, note, float(n_sig), operator, suggestion, block)
            judged += 1
            print(f"  기록됨: {LABEL[verdict]}" + ("  · 차단" if block else ""))
            break

        if ans == "q":
            break

    print(f"\n  판정 {judged}건 · 건너뜀 {skipped}건")
    if taken + flipped:
        print(f"  제안이 붙은 {taken + flipped}건 중 수락 {taken} · 뒤집음 {flipped}"
              f"  (뒤집힌 비율 {100 * flipped / (taken + flipped):.0f}%)")
    print()
    cur.close()


# ────────────────────────────────────────────────────────────────
#  집계
# ────────────────────────────────────────────────────────────────

def summary(conn):
    cur = conn.cursor()
    cur.execute("""SELECT count(*), count(v.id) FROM incidents i
                   LEFT JOIN verdicts v ON v.incident_key = i.incident_key""")
    total, judged = cur.fetchone()
    if not total:
        print("\n  인시던트가 없습니다.\n"); cur.close(); return
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

    cur.execute("""
        SELECT count(*) FILTER (WHERE proposed IS NOT NULL),
               count(*) FILTER (WHERE proposed IS NOT NULL AND proposed = verdict)
        FROM verdicts""")
    n, ok = cur.fetchone()
    if n:
        print(f"\n  제안이 붙은 판정 {n}건 중 {ok}건 수락, {n - ok}건 뒤집힘"
              f"  (뒤집힌 비율 {100 * (n - ok) / n:.0f}%)")
        print("  뒤집힌 비율이 높으면 판정 기준 문서를 고쳐야 한다는 뜻입니다.")
    print()
    cur.close()


def thresholds(conn):
    """판정된 관측값의 분포에서 임계치 후보를 뽑는다.

    조치가 필요했던 것들의 최솟값과 불필요했던 것들의 최댓값 사이가 후보다.
    두 분포가 겹치면 임계치로는 나눌 수 없고 조건 자체를 바꿔야 한다.
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
        print("\n  판정 기록이 없습니다. 먼저 triage 를 돌리세요.\n"); cur.close(); return

    print(f"\n{'규칙':<6} {'버전':<5} {'위협 관측값':>13} {'n':>4} "
          f"{'비위협 관측값':>15} {'n':>4}  판단")
    print(BAR)
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
        print(f"{rid:<6} {ver:<5} {t:>13} {t_n:>4} {o:>15} {o_n:>4}  {note}")
    print("\n  분리됨 : 관측값만으로 위협과 비위협이 갈린다. 임계치를 올리면 된다")
    print("  겹침   : 같은 값에 두 판정이 모두 있다. 임계치로는 못 나눈다\n")
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 인시던트 검토")
    ap.add_argument("--db-url", dest="url")
    ap.add_argument("--rule")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--operator", default=os.environ.get("USER", "operator"))
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--thresholds", action="store_true")
    a = ap.parse_args()

    conn = psycopg2.connect(db_url(a.url))
    try:
        ensure_column(conn)
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
