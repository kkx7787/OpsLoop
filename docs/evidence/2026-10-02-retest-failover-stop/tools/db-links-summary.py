#!/usr/bin/env python3
"""재시험(콘솔 이중화 정지 3회) DB 연결 표본 요약. Mac 에서 돈다. 표준 라이브러리만. 읽기만 한다(화면 출력).

  python3 db-links-summary.py <raw 폴더> <db-links.tsv>
      raw 폴더 아래 회차 폴더(marks.jsonl 있는 곳)마다, 표본 파일에서 T0 앞 45초 ~ T0 뒤 290초 표본만 쓴다.
      끝에 표본 전체에서 'DB 연결 확인' 판정이 바뀐 시각(KST)을 늘어놓는다(합류 · 떼기 포함).

회차마다: T0(marks.jsonl inject 의 t_local_ns, summarize.py 와 같은 기준) · 복귀(recover) 시각,
대상 콘솔 이름표(opsloop-console-a · b) 수와 연결 상대 주소(192.168.50.11 · .12) 수의 변화,
상태판 'DB 연결 확인' 과 같은 판정(이름표 연결이 1 이상이면 있음)이 바뀐 표본.
표본 줄: <Mac epoch 초>\tapp <이름표=수 …> | peer <주소=수 …>  (db-sample.sh 출력)
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
NAMES = {"console-a": ("opsloop-console-a", "192.168.50.11", "콘솔 A"),
         "console-b": ("opsloop-console-b", "192.168.50.12", "콘솔 B")}


def pairs(text):
    out = {}
    for tok in text.split():
        k, sep, v = tok.rpartition("=")
        if sep and v.isdigit():
            out[k] = int(v)
    return out


def parse_line(line):
    t, _, rest = line.rstrip("\n").partition("\t")
    try:
        t = float(t)
    except ValueError:
        return None
    if not rest.startswith("app ") or "| peer" not in rest:
        return t, None, None, rest.strip()[:120]            # ssh · psql 오류 줄
    app, _, peer = rest[4:].partition("| peer")
    return t, pairs(app), pairs(peer), None


def links(app):
    return " · ".join(f"{label} {'있음' if app.get(name, 0) > 0 else '없음'}" for name, _, label in NAMES.values())


def fmt(s):
    return "-" if s is None else f"{s:.1f}"


PRE, POST = 45, 290


def one(run_dir, samples):
    marks = [json.loads(x) for x in open(os.path.join(run_dir, "marks.jsonl"), encoding="utf-8") if x.strip()]
    inj = next((m for m in marks if m.get("kind") == "inject"), None)
    if inj is None:
        print(f"== {os.path.basename(run_dir)}: inject 표시 없음")
        return
    rec = next((m for m in marks if m.get("kind") == "recover" and m["t_local_ns"] > inj["t_local_ns"]), None)
    t0 = inj["t_local_ns"] / 1e9
    tr = rec["t_local_ns"] / 1e9 - t0 if rec else None
    name, addr, label = NAMES[inj["target"]]
    rows = [r for r in samples if -PRE <= r[0] - t0 <= POST]
    print(f"== {os.path.basename(run_dir)} · {inj.get('scenario')} · 대상 {label}({name} · {addr})")
    print(f"   T0 {datetime.fromtimestamp(t0, KST).isoformat(timespec='milliseconds')} · 복귀 T0+{fmt(tr)}초 · 표본 {len(rows)}개")
    before = [r for r in rows if r[1] is not None and r[0] - t0 < 0]
    if before:
        _, app, peer, _ = before[-1]
        print(f"   주입 직전 표본: 이름표 {app.get(name, 0)}개 · 상대 주소 {peer.get(addr, 0)}개 · {links(app)}")
    after = [r for r in rows if r[1] is not None and r[0] - t0 >= 0 and (tr is None or r[0] - t0 < tr)]
    for key, pick, what in (("이름표", 1, name), ("상대 주소", 2, addr)):
        last_pos = None
        first_zero = None
        for r in after:
            s, n = r[0] - t0, r[pick].get(what, 0)
            if n > 0 and first_zero is None:
                last_pos = s
            if n == 0 and first_zero is None:
                first_zero = s
        if first_zero is None:
            print(f"   {key}: 복귀 전까지 0 이 되지 않았다 (마지막 {fmt(last_pos)}초에 남음)")
        else:
            span = f"{fmt(last_pos)} ~ {fmt(first_zero)}초 사이에 0" if last_pos is not None else f"주입 뒤 첫 표본({fmt(first_zero)}초)에 이미 0"
            print(f"   {key}: T0 뒤 {span} (3분 기준 {'안' if first_zero <= 180 else '밖'})")
    if tr is not None:
        back = next((r[0] - t0 for r in rows if r[1] is not None and r[0] - t0 >= tr and r[1].get(name, 0) > 0), None)
        print(f"   복귀 뒤 이름표 다시 보임: T0+{fmt(back)}초 (복귀 뒤 {fmt(back - tr) if back is not None else '-'}초)")
    prev = None
    for r in rows:
        if r[1] is None:
            continue
        cur = links(r[1])
        if cur != prev:
            print(f"   판정 바뀜 T0{r[0] - t0:+.1f}초: DB 연결 확인: {cur}")
            prev = cur
    errors = [r for r in rows if r[1] is None]
    if errors:
        print(f"   표본 오류 {len(errors)}줄 · 첫 줄: {errors[0][3]}")
    print("   표본(초 이름표/상대): " + " ".join(
        f"{r[0] - t0:.0f} {r[1].get(name, 0)}/{r[2].get(addr, 0)}" for r in rows if r[1] is not None))


def main(argv):
    if len(argv) != 3 or not os.path.isdir(argv[1]) or not os.path.isfile(argv[2]):
        print(__doc__, file=sys.stderr)
        return 2
    root = argv[1]
    samples = [r for r in (parse_line(x) for x in open(argv[2], encoding="utf-8")) if r]
    dirs = sorted(d for d in (os.path.join(root, x) for x in os.listdir(root)) if os.path.isfile(os.path.join(d, "marks.jsonl")))
    if not dirs:
        print("회차 폴더(marks.jsonl)가 없다", file=sys.stderr)
        return 2
    for d in dirs:
        one(d, samples)
    print(f"== 표본 전체 {len(samples)}줄 (오류 {sum(1 for r in samples if r[1] is None)}줄) · 'DB 연결 확인' 판정이 바뀐 시각")
    prev = None
    for r in samples:
        if r[1] is None:
            continue
        cur = links(r[1])
        if cur != prev:
            print(f"   {datetime.fromtimestamp(r[0], KST).strftime('%H:%M:%S')} {cur}  (이름표 {' '.join(f'{k}={v}' for k, v in sorted(r[1].items()))})")
            prev = cur
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
