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

# 두벌식 자판에서 한/영 전환을 잊고 누른 키를 알아듣는다.
# 판정 중 매번 전환하는 것은 도구가 감당할 몫이지 사람이 감당할 몫이 아니다.
HANGUL = {"ㅅ": "t", "ㅜ": "n", "ㄹ": "f", "ㄴ": "s", "ㅂ": "q", "ㅁ": "a", "ㅛ": "y"}

BAR = "=" * 78
DIV = "-" * 78


def keypress(raw):
    """입력을 한 글자 명령으로 정규화한다. 한글 자모도 받는다."""
    v = raw.strip().lower()
    if len(v) == 1 and v in HANGUL:
        return HANGUL[v]
    # 'ㅅt' 처럼 전환 직후 두 글자가 들어온 경우 뒤의 영문을 쓴다
    if len(v) == 2 and v[0] in HANGUL and v[1].isascii():
        return v[1]
    return v


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


def observed_of(evidence, signal_count):
    """그 규칙이 임계치와 비교하는 값을 증거에서 꺼낸다.

    신호 수를 관측값으로 쓰면 안 된다. R001 에서 신호 수는 "임계치를 넘은
    시간창이 몇 개인가"이지 "그 창에서 몇 번 시도했는가"가 아니다. 임계치와
    비교되지 않는 값으로 임계치를 도출하면 결과가 무의미하다.

    돌려주는 값: (관측값, 단위 설명)
    """
    e = evidence or {}
    # 탐지기가 신호 전체에서 계산해 남긴 값이 있으면 그것을 쓴다.
    if e.get("observed_sigma_max") is not None:
        return float(e["observed_sigma_max"]), "표준편차 배수"
    if e.get("observed_count_max") is not None:
        return float(e["observed_count_max"]), "시간창 최대 누적 횟수"

    # 없으면 표본에서 추정한다. v1 시점 인시던트가 여기 해당한다.
    samples = [x for x in (e.get("sample") or []) if isinstance(x, dict)]
    if samples:
        head = samples[0]
        # 기준선 이탈: 평균에서 몇 표준편차 떨어졌는가. sigma 파라미터와 비교된다.
        if "limit" in head and head.get("sigma"):
            vals = [(x["count"] - x["mean"]) / x["sigma"]
                    for x in samples if x.get("sigma")]
            if vals:
                return max(vals), "표준편차 배수"
        # 빈도 규칙: 시간창 안의 누적 횟수. threshold 와 비교된다.
        if "count" in head and "threshold" in head:
            return float(max(x["count"] for x in samples)), "시간창 최대 누적 횟수"
    # 임계치가 없는 규칙. 남겨두되 임계치 도출에는 쓰지 않는다.
    return float(signal_count), "알림 신호 수"


def local(ts):
    return ts.astimezone().strftime("%m-%d %H:%M:%S")


# ────────────────────────────────────────────────────────────────
#  증거 수집
# ────────────────────────────────────────────────────────────────

def gather(cur, inc_key, ip, first_ts, last_ts, sessions):
    """인시던트 구간에서 그 출발지가 실제로 한 일을 모은다.

    규칙이 남긴 evidence 는 규칙이 본 것만 담고 있다. 판정하려면 규칙이
    보지 않은 것까지 봐야 한다.
    """
    ev = {"counts": {}, "creds": [], "commands": [], "files": [],
          "also": [], "blocked": False, "covered_by": None}
    if not ip:
        return ev

    # 인시던트 기간만으로 조회하면 안 된다. 세션 하나에서 나온 인시던트는
    # first_ts 와 last_ts 가 같아 폭이 0 초이고, 그 세션의 로그인·명령은
    # 몇 초 뒤에 일어나 범위 밖으로 빠진다. 증거가 통째로 비어 보인다.
    # 규칙이 근거로 삼은 세션을 함께 조건에 넣어 그 세션 전체를 본다.
    scope = "(session = ANY(%s) OR ts BETWEEN %s AND %s)"
    args = (ip, sessions or [], first_ts, last_ts)

    cur.execute(f"""
        SELECT eventid, count(*) FROM events
        WHERE src_ip = %s AND {scope}
        GROUP BY eventid""", args)
    ev["counts"] = dict(cur.fetchall())

    cur.execute(f"""
        SELECT username, password, count(*) FROM events
        WHERE src_ip = %s AND {scope}
          AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
        GROUP BY username, password ORDER BY count(*) DESC LIMIT 6""", args)
    ev["creds"] = cur.fetchall()

    cur.execute(f"""
        SELECT input, count(*) FROM events
        WHERE src_ip = %s AND {scope}
          AND eventid = 'cowrie.command.input' AND input IS NOT NULL
        GROUP BY input ORDER BY count(*) DESC LIMIT 6""", args)
    ev["commands"] = cur.fetchall()

    cur.execute(f"""
        SELECT eventid, shasum, url FROM events
        WHERE src_ip = %s AND {scope}
          AND eventid LIKE 'cowrie.session.file_%%' LIMIT 5""", args)
    ev["files"] = cur.fetchall()

    cur.execute("""
        SELECT rule_id, rule_name, severity, count(*) FROM incidents
        WHERE actor_ip = %s GROUP BY rule_id, rule_name, severity
        ORDER BY rule_id""", (ip,))
    ev["also"] = cur.fetchall()

    cur.execute("SELECT 1 FROM blocklist WHERE actor_ip = %s AND released_at IS NULL", (ip,))
    ev["blocked"] = cur.fetchone() is not None

    # 같은 출발지의 겹치는 인시던트들을 하나의 에피소드로 보고, 그중 심각도가
    # 가장 높은 것(동률이면 가장 이른 것)을 대표로 삼는다. 대표가 아닌 것은
    # 관제자에게 새 정보를 주지 않은 알림이다.
    #
    # 이 계산은 사람의 판정이 아니라 인시던트 자체에서 나오므로 첫 건부터
    # 답이 있고, 규칙 조건과도 무관하다. 조건이 겹치는 규칙에서도 순환 없이
    # 물을 수 있는 유일한 질문이 이것이다.
    cur.execute("""
        SELECT incident_key, rule_id FROM incidents
        WHERE actor_ip = %s
          AND first_ts <= %s + interval '15 minutes'
          AND last_ts  >= %s - interval '15 minutes'
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                               WHEN 'medium' THEN 2 ELSE 3 END, first_ts
        LIMIT 1""", (ip, last_ts, first_ts))
    row = cur.fetchone()
    if row and row[0] != inc_key:
        ev["covered_by"] = row[1]

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

    # 1순위: 중복인가. 규칙 조건과 무관한 증거라 어느 규칙에나 쓸 수 있다.
    if ev["covered_by"]:
        return "non_actionable", [
            facts,
            f"같은 출발지·같은 구간에서 {ev['covered_by']} 가 더 높은 심각도로 이미 떴다",
            "이 알림은 새 정보를 주지 않았다. 조치는 대표 인시던트 쪽에서 이뤄진다"]

    # 2순위: 대표 알림이다. 뒤이은 행위로 판정한다.
    if cmds or files or proxy:
        why = []
        if cmds: why.append(f"명령 {cmds}회")
        if files: why.append(f"파일 {files}건")
        if proxy: why.append(f"경유 시도 {proxy}회")
        lines = [facts, f"이 에피소드의 대표 알림이고 실제 행위가 있었다 ({', '.join(why)})"]
        if rule_id in CIRCULAR:
            lines.append(f"※ {CIRCULAR[rule_id]}.")
            lines.append("   이 위협 판정은 규칙의 정확성이 아니라 중복이 아님을 뜻한다")
        else:
            lines.append("규칙이 본 것과 다른 증거로 확인된 침해다")
        return "threat", lines

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

def show(row, idx, total, ev, suggestion, basis, observed, unit):
    (key, rid, ver, rname, sev, ip, first_ts, last_ts, n_sig, n_sess, _, _) = row

    print("\n" + BAR)
    print(f" [{idx}/{total}]  {sev.upper():<9} {rid} {rname}   (규칙 {ver})")
    print(BAR)
    print(f"  출발지   {ip or '-'}"
          + ("   [이미 차단됨]" if ev["blocked"] else ""))
    print(f"  기간     {local(first_ts)} ~ {local(last_ts)}"
          f"   ({int((last_ts - first_ts).total_seconds())}초)")
    print(f"  규모     신호 {n_sig}건 · 세션 {n_sess}개")
    if unit != "알림 신호 수":
        print(f"  관측값   {observed:g}  ({unit} · 이 값이 임계치와 비교된다)")

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

    taken = flipped = skipped = judged = auto_done = 0
    auto = False
    for i, row in enumerate(rows, 1):
        key, rid, ip, n_sig, sev = row[0], row[1], row[5], row[8], row[4]
        evidence = row[10] or {}
        sessions = list(evidence.get("sessions") or [])
        observed, unit = observed_of(evidence, n_sig)
        ev = gather(cur, key, ip, row[6], row[7], sessions)
        suggestion, basis = propose(rid, ev)

        # 일괄 수락 중이면 제안이 있는 것만 조용히 기록하고 넘어간다.
        # 제안이 없는 것은 남겨둔다. 판단이 필요한 것을 자동으로 넘기지 않는다.
        if auto:
            if suggestion:
                record(conn, key, ip, suggestion, basis[1] + " [일괄 수락]",
                       observed, operator, suggestion, False)
                taken += 1; judged += 1; auto_done += 1
            else:
                skipped += 1
            continue

        show(row, i, len(rows), ev, suggestion, basis, observed, unit)

        prompt = ("  [Enter] 제안 수락  [t] 위협  [n] 무시 가능  [f] 오탐  "
                  "[a] 남은 것 전부 제안대로  [s] 건너뜀  [q] 종료 > ") if suggestion else \
                 ("  [t] 위협  [n] 무시 가능  [f] 오탐  [s] 건너뜀  [q] 종료 > ")

        while True:
            ans = keypress(input(prompt))
            if ans == "q":
                break
            if ans == "s":
                skipped += 1
                break
            if ans == "a" and suggestion:
                left = len(rows) - i + 1
                yn = keypress(input(f"  남은 {left}건을 제안대로 기록합니다. "
                                f"제안이 없는 건은 남겨둡니다. [y/N] > "))
                if yn != "y":
                    continue
                auto = True
                record(conn, key, ip, suggestion, basis[1] + " [일괄 수락]",
                       observed, operator, suggestion, False)
                taken += 1; judged += 1; auto_done += 1
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
                block = keypress(input("  이 출발지를 차단 목록에 올릴까요? [y/N] > ")) == "y"
            record(conn, key, ip, verdict, note, observed, operator, suggestion, block)
            judged += 1
            print(f"  기록됨: {LABEL[verdict]}" + ("  · 차단" if block else ""))
            break

        if ans == "q":
            break

    print(f"\n  판정 {judged}건 · 건너뜀 {skipped}건"
          + (f"  (그중 일괄 수락 {auto_done}건)" if auto_done else ""))
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

    임계치가 없는 조건형 규칙(event_match, session_compound)은 이 표에서
    제외한다. 낮출 임계치가 없는 규칙에 "임계치를 낮출 여지"라고 쓰면
    읽는 사람을 잘못된 조치로 이끈다.
    """
    cur = conn.cursor()

    # 규칙 정의를 DB 에서 읽어 어떤 규칙에 임계치가 있는지 판별한다.
    # 코드에 규칙 목록을 박으면 규칙이 바뀔 때마다 여기도 고쳐야 한다.
    kinds = {}
    cur.execute("SELECT rule_version, definition FROM rule_versions")
    for ver, doc in cur.fetchall():
        for r in (doc or {}).get("rules", []):
            kinds[(ver, r["id"])] = (r.get("type"), r.get("params", {}))

    TUNABLE = {
        "actor_rate":         ("threshold", "시간창 최대 누적 횟수"),
        "baseline_deviation": ("sigma",     "표준편차 배수"),
        "session_threshold":  ("threshold", "세션 지표"),
    }

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

    tunable, fixed = [], []
    for r in rows:
        kind, params = kinds.get((r[1], r[0]), (None, {}))
        (tunable if kind in TUNABLE else fixed).append((r, kind, params))

    if tunable:
        print(f"\n  임계치가 있는 규칙 — 판정 분포에서 다음 값을 도출한다")
        print(BAR)
        print(f"{'규칙':<6} {'현재':>7} {'위협':>12} {'n':>3} {'비위협':>12} {'n':>3}  판단")
        print(DIV)
        for r, kind, params in tunable:
            rid, ver, t_min, t_max, t_n, o_min, o_max, o_n = r
            field, unit = TUNABLE[kind]
            now = params.get(field, "-")
            t = f"{t_min:g}~{t_max:g}" if t_n else "-"
            o = f"{o_min:g}~{o_max:g}" if o_n else "-"
            if not t_n:
                note = "위협 판정이 없다. 규칙을 유지할 근거가 없다"
            elif not o_n:
                note = "전부 위협. 임계치를 낮춰 더 잡을 여지"
            elif o_max < t_min:
                cand = o_max + (1 if float(o_max).is_integer() else 0.1)
                note = f"분리됨. 임계치 후보 {cand:g} (현재 {now})"
            else:
                note = "분포 겹침. 임계치로는 못 나눈다. 조건 변경"
            print(f"{rid:<6} {str(now):>7} {t:>12} {t_n:>3} {o:>12} {o_n:>3}  {note}")
            print(f"{'':6} {'':>7} 관측 단위: {unit}")

    if fixed:
        print(f"\n  임계치가 없는 조건형 규칙 — 임계치 조정 대상이 아니다")
        print(BAR)
        print(f"{'규칙':<6} {'유형':<18} {'위협':>5} {'비위협':>7}  판단")
        print(DIV)
        for r, kind, _ in fixed:
            rid, ver, _, _, t_n, _, _, o_n = r
            if o_n and not t_n:
                note = "전부 비조치. 규칙을 없애거나 조건을 좁힌다"
            elif o_n:
                note = "일부가 비조치. 조건을 좁힐 여지"
            else:
                note = "전부 위협. 다만 조건과 판정 근거가 같은지 확인할 것"
            print(f"{rid:<6} {str(kind or '-'):<18} {t_n:>5} {o_n:>7}  {note}")

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