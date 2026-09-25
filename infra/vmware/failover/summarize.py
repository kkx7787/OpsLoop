#!/usr/bin/env python3
"""장애 주입 시험 결과 요약 (이슈 #43). Mac 에서 돈다. 표준 라이브러리만 쓴다.

회차 폴더(http.jsonl · ws.jsonl · fw.csv · marks.jsonl, 있으면 fw-haproxy.log · fw-meta.json)를 읽어
results.json 과 sha256.json 을 만든다. 형식은 docs/evidence/2026-09-22-isolation/ 과 맞춘다
(results.json 에 날짜 · 시간대 · 범위 · 출처(git HEAD · 도구 sha256) · 회차별 원천 파일 sha256, sha256.json 에 results.json 의 sha256).

사용 (저장소 루트)
  python3 infra/vmware/failover/summarize.py ~/opsloop-failover/r01-stop-a ~/opsloop-failover/r02-kill-a \\
          --out docs/evidence/2026-09-26-failover
  python3 infra/vmware/failover/summarize.py ~/opsloop-failover     하위 폴더 가운데 회차 폴더를 모두 (결과는 그 폴더에)
  --limit 30 · --streak 20 · --zombie-window 120
  종료 코드: 0 합격선 대상 구간이 모두 합격 · 1 불합격 또는 판정 불가가 있다 · 2 입력 오류

구간과 시각
  주입 표시(marks.jsonl 의 inject) 하나가 구간 하나다. T0 = 그 표시의 t_local_ns(Mac 시각, 주입 명령 바로 앞).
  구간은 다음 inject 까지(없으면 기록 끝). 구간 안의 첫 recover 표시가 복귀 시각이다.
  대상은 표시의 target(없으면 T0 뒤 먼저 빠진 서버). 콘솔 이름 opsloop-console-a 는 HAProxy 서버 console-a 와 같다.
  시각은 모두 Mac 시계로 맞춘다. fw.csv 의 방화벽 시각은 min(t_local − t_fw) 만큼 옮긴다(clock_offset_ms).

지표 (초는 T0 기준)
  detect_s      fw.csv 에서 대상 서버가 DOWN(drain 시나리오는 MAINT · DRAIN 도)이 된 첫 시각 − T0
  fail          T0 ~ 복귀 사이에 발사한 요청의 실패. 첫 실패 발사(first_s) ~ 마지막 실패 발사(last_s), 건수 · 종류별 · 줄기별.
                복귀 뒤 실패는 recover.fail_count 로 따로 센다
  latency       T0 뒤 발사한 요청의 지연 p99 · 최댓값(모든 요청 · 성공만)과 기준선(T0 앞 60초) p99 (밀리초)
  failover_s    T0 뒤 다른 콘솔이 응답한 요청이 20번(간격 100ms 면 2초) 연속 성공한 첫 요청의 발사 시각.
                me 줄기는 응답의 console, health 줄기는 fw-haproxy.log 의 서버로 콘솔을 안다.
                콘솔을 모르는 줄기는 T0 뒤 첫 실패 다음의 20번 연속 성공으로 세고 basis 에 적는다(실패가 없으면 뺀다).
                줄기 가운데 늦은 쪽이다(한 줄기가 처음부터 다른 콘솔에만 갔어도 다른 줄기의 실패를 넘긴다)
  ws            연결마다. T0 에 대상 콘솔에 붙어 있던 연결의 좀비 = T0 → close
                (zombie-window 120초 안에 close 가 없으면 '미감지'), 재연결 = 그 close → 다음 hello, 새 콘솔.
                프로브를 멈춘(end) 뒤의 기록은 다른 실행이라 그 연결의 관찰은 end 에서 끝난다
  unauthorized  T0 뒤 http_401 건수 + 웹소켓 1008 닫힘 수 (세션 유지)
  recover_up_s  recover 표시 뒤 대상이 UP 이 된 첫 시각 − recover 시각
  switchover_s  감지(detect_s)와 실패 구간 끝(fail.last_s) 가운데 늦은 것. 감지가 없으면 비운다
합격선: switchover_s ≤ 30 · unauthorized = 0. 마지막 실패 뒤 성공이 20번 넘게 이어지지 않았으면(fail.settled 거짓,
  실패 속에서 기록이 끝났거나 복귀 표시까지 실패가 이어짐) 전환을 확인하지 못한 것으로 불합격이다.
  감지가 없으면(주입이 먹지 않음 · T0 에 대상이 이미 빠져 있음 · fw.csv 없음) 전환을 셀 수 없어 판정 불가다.
  HAProxy 로그에서 같은 p 가 다른 서버로 두 번 나오면 그 요청의 콘솔은 모르는 것으로 둔다.
  합격선 대상 시나리오는 stop · kill · vm-off 이고(mark.py),
  나머지(net-cut · db-cut · drain)는 같은 값을 참고로 적는다. 여러 회차는 시나리오별 중앙값 · 최댓값 표로 묶는다.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import common  # noqa: E402
from mark import SCENARIOS  # noqa: E402

KST = timezone(timedelta(hours=9))
SOURCES = ("http.jsonl", "ws.jsonl", "fw.csv", "marks.jsonl", "fw-haproxy.log", "fw-meta.json")
TOOLS = ("common.py", "probe_http.py", "probe_ws.py", "collect_fw.sh", "mark.py", "summarize.py")
BASELINE_S = 60.0
# httplog 한 줄: ... console consoles/console-a 0/0/1/2/3 200 ... "GET /health?p=r01-42 HTTP/1.1"
LOG_LINE = re.compile(r'\sconsoles/(?P<srv>\S+)\s+\S+\s+(?P<status>-?\d+)\s.*?"GET /health\?p=(?P<p>[A-Za-z0-9_.-]+)[ "]')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(name):
    """콘솔 이름 → HAProxy 서버 이름 꼴. opsloop-console-a → console-a."""
    if not isinstance(name, str) or not name.strip():
        return None
    n = name.strip().lower()
    return n[len("opsloop-"):] if n.startswith("opsloop-") else n


def pct(values, p):
    """가장 가까운 순위 백분위. 비었으면 None."""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(p / 100.0 * len(s)) - 1)]


def r3(x):
    return None if x is None else round(x, 3)


def ns_s(v):
    return v / 1e9 if isinstance(v, int) else None


def out_of_rotation(status, drain=False):
    s = (status or "").upper()
    if s.startswith("DOWN"):
        return True
    return drain and (s.startswith("MAINT") or s.startswith("DRAIN"))


# ──────────────────────────────────────────────────────────────
#  읽기
# ──────────────────────────────────────────────────────────────
def read_fw(path):
    """fw.csv → ([{t, svname, status}], clock_offset_s). t 는 Mac 시계(초)."""
    rows = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            for r in csv.DictReader(f):
                try:
                    tl = float(r.get("t_local") or "nan")
                except ValueError:
                    continue
                try:
                    tf = float(r.get("t_fw") or "nan")
                except ValueError:
                    tf = float("nan")
                rows.append((tl, tf, (r.get("svname") or "").strip(), (r.get("status") or "").strip()))
    except FileNotFoundError:
        return [], None
    diffs = [tl - tf for tl, tf, _, _ in rows if not math.isnan(tl) and not math.isnan(tf)]
    offset = min(diffs) if diffs else None
    out = []
    for tl, tf, sv, st in rows:
        t = tf + offset if offset is not None and not math.isnan(tf) else tl
        if not math.isnan(t):
            out.append({"t": t, "svname": sv, "status": st})
    out.sort(key=lambda x: x["t"])
    return out, offset


def read_log_servers(path):
    """fw-haproxy.log → {'<회차>-<번호>': 서버}. health 요청을 어느 콘솔이 받았는지.
    같은 p 가 다른 서버로 두 번 나오면(번호가 겹친 옛 기록 · 프로브 둘) 어느 요청인지 가릴 수 없어 None 으로 둔다."""
    found = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = LOG_LINE.search(line)
                if m:
                    p, srv = m.group("p"), m.group("srv")
                    found[p] = srv if found.get(p, srv) == srv else None
    except FileNotFoundError:
        pass
    return found


def load_run(path):
    run = {"dir": path, "name": os.path.basename(os.path.normpath(path))}
    run["files"] = {n: sha256_file(os.path.join(path, n)) for n in SOURCES if os.path.isfile(os.path.join(path, n))}
    http = [r for r in common.read_jsonl(os.path.join(path, "http.jsonl"))
            if isinstance(r.get("t_send_ns"), int) and r.get("stream") in ("health", "me")]
    servers = read_log_servers(os.path.join(path, "fw-haproxy.log"))
    for r in http:
        r["_t"] = r["t_send_ns"] / 1e9
        r["_tr"] = ns_s(r.get("t_recv_ns")) or r["_t"]
        r["_ok"] = r.get("error") is None and isinstance(r.get("status"), int) and 200 <= r["status"] < 300
        if r["stream"] == "health":
            r["_console"] = norm(servers.get("%s-%s" % (r.get("run"), r.get("seq"))))
        else:
            r["_console"] = norm(r.get("console"))
    http.sort(key=lambda r: r["_t"])
    run["http"] = http
    run["log_servers"] = len(servers)
    ws = [e for e in common.read_jsonl(os.path.join(path, "ws.jsonl")) if isinstance(e.get("t_ns"), int)]
    for e in ws:
        e["_t"] = e["t_ns"] / 1e9
    ws.sort(key=lambda e: e["_t"])
    run["ws"] = ws
    marks = [m for m in common.read_jsonl(os.path.join(path, "marks.jsonl")) if isinstance(m.get("t_local_ns"), int)]
    for m in marks:
        m["_t"] = m["t_local_ns"] / 1e9
    marks.sort(key=lambda m: m["_t"])
    run["marks"] = marks
    run["fw"], run["fw_offset"] = read_fw(os.path.join(path, "fw.csv"))
    return run


# ──────────────────────────────────────────────────────────────
#  지표
# ──────────────────────────────────────────────────────────────
def infer_target(fw, t0, end):
    for r in fw:
        if t0 <= r["t"] < end and r["svname"] not in ("BACKEND", "FRONTEND", "-", "") and out_of_rotation(r["status"], True):
            return r["svname"]
    return None


def detect(fw, target, t0, end, drain):
    """→ (detect_s, 그때 상태, 메모)."""
    rows = [r for r in fw if r["svname"] == target]
    if not rows:
        return None, None, "fw.csv 에 대상 서버 행이 없다"
    before = [r for r in rows if r["t"] < t0]
    if before and out_of_rotation(before[-1]["status"], drain):
        return None, before[-1]["status"], "T0 에 이미 빠져 있었다 (%s)" % before[-1]["status"]
    for r in rows:
        if t0 <= r["t"] < end and out_of_rotation(r["status"], drain):
            return r["t"] - t0, r["status"], None
    return None, None, "구간 안에 대상이 빠지지 않았다"


def recover_up(fw, target, t_rec, end):
    rows = [r for r in fw if r["svname"] == target]
    before = [r for r in rows if r["t"] < t_rec]
    if before and before[-1]["status"].upper().startswith("UP"):
        return 0.0, "복귀 표시 때 이미 UP"
    for r in rows:
        if t_rec <= r["t"] < end and r["status"].upper().startswith("UP"):
            return r["t"] - t_rec, None
    return None, "구간 안에 UP 이 되지 않았다"


def fail_summary(reqs, t0):
    fails = [r for r in reqs if r.get("error")]
    if not fails:
        return {"count": 0, "first_s": None, "last_s": None, "window_s": None, "by_error": {}, "by_stream": {}}
    first, last = fails[0]["_t"] - t0, fails[-1]["_t"] - t0
    return {"count": len(fails), "first_s": r3(first), "last_s": r3(last), "window_s": r3(last - first),
            "by_error": dict(sorted(Counter(r["error"] for r in fails).items())),
            "by_stream": dict(sorted(Counter(r["stream"] for r in fails).items()))}


def latency(reqs, base):
    allv = [r["latency_ms"] for r in reqs if isinstance(r.get("latency_ms"), (int, float))]
    okv = [r["latency_ms"] for r in reqs if r["_ok"] and isinstance(r.get("latency_ms"), (int, float))]
    basev = [r["latency_ms"] for r in base if r["_ok"] and isinstance(r.get("latency_ms"), (int, float))]
    return {"p99_ms": r3(pct(allv, 99)), "max_ms": r3(max(allv) if allv else None),
            "ok_p99_ms": r3(pct(okv, 99)), "ok_max_ms": r3(max(okv) if okv else None),
            "baseline_p99_ms": r3(pct(basev, 99)), "n": len(allv)}


def streak(reqs, t0, target, need, by_console):
    """need 번 연속 성공(by_console 이면 다른 콘솔이 응답한 것만)의 첫 요청 → (failover_s, confirmed_s)."""
    run, start = 0, None
    for r in reqs:
        good = r["_ok"] and (not by_console or (r["_console"] is not None and r["_console"] != target))
        if not good:
            run, start = 0, None
            continue
        if run == 0:
            start = r
        run += 1
        if run >= need:
            return start["_t"] - t0, r["_tr"] - t0
    return None, None


def failover(reqs, t0, target, need):
    out = {}
    for stream in ("me", "health"):
        rs = [r for r in reqs if r["stream"] == stream]
        if not rs:
            continue
        if target and any(r["_console"] for r in rs):
            s, c = streak(rs, t0, target, need, True)
            out[stream] = {"basis": "다른 콘솔", "failover_s": r3(s), "confirmed_s": r3(c)}
            continue
        first_fail = next((i for i, r in enumerate(rs) if r.get("error")), None)
        if first_fail is None:
            out[stream] = {"basis": "콘솔 이름 없음 · 실패 없음", "failover_s": None, "confirmed_s": None}
            continue
        s, c = streak(rs[first_fail:], t0, target, need, False)
        out[stream] = {"basis": "콘솔 이름 없음 · 첫 실패 뒤 연속 성공", "failover_s": r3(s), "confirmed_s": r3(c)}
    # 줄기마다 값을 모아 가장 늦은 것. 콘솔을 모르는 줄기도 실패가 있었으면 넣는다(실패 없는 줄기는 넘어갈 일이 없었다).
    # roundrobin 은 같은 순간 쏜 두 줄기를 번갈아 받으므로 한 줄기가 처음부터 다른 콘솔에만 갈 수 있다.
    # 그 줄기만 보면 전환 완료가 0초가 되어 다른 줄기의 실패보다 앞선다
    pool = [v["failover_s"] for v in out.values() if v["basis"] != "콘솔 이름 없음 · 실패 없음"]
    if not pool or any(v is None for v in pool):
        best = None
    else:
        best = max(pool)
    return best, out


def ws_metrics(events, t0, end, target, window):
    groups = defaultdict(list)
    for e in events:
        groups[(e.get("stream"), e.get("conn"))].append(e)
    conns, unauthorized = [], 0
    for (stream, conn), evs in sorted(groups.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        unauthorized += sum(1 for e in evs if e.get("event") == "close" and e.get("code") == 1008 and t0 <= e["_t"] < end)
        connected, console = False, None
        for e in evs:
            if e["_t"] >= t0:
                break
            ev = e.get("event")
            if ev == "hello":
                connected, console = True, norm(e.get("console"))
            elif ev in ("close", "end", "stopped"):
                connected, console = False, None
        item = {"stream": stream, "conn": conn, "console_at_t0": console}
        if not connected:
            item["state"] = "T0 에 연결 없음"
            conns.append(item)
            continue
        after = [e for e in evs if t0 <= e["_t"] < end]
        # 프로브를 멈춘(end) 뒤 같은 줄기 · 번호로 다시 띄운 실행은 다른 연결이다. 이 연결의 관찰은 end 에서 끝난다
        ended = next((i for i, e in enumerate(after) if e.get("event") == "end"), None)
        if ended is not None:
            after = after[:ended + 1]
        close = next((e for e in after if e.get("event") == "close"), None)
        on_target = console is None or target is None or console == target
        item["on_target"] = on_target
        if not on_target:
            item["state"] = "다른 콘솔"
            if close is not None:
                item["unexpected_close_s"] = r3(close["_t"] - t0)
            conns.append(item)
            continue
        last_seen = after[-1]["_t"] if after else t0
        if close is None or close["_t"] - t0 > window:
            item["state"] = "미감지"
            item["zombie_s"] = None
            item["observed_s"] = r3(min(last_seen, t0 + window) - t0) if after else 0.0
            if close is not None:
                item["late_close_s"] = r3(close["_t"] - t0)
            conns.append(item)
            continue
        item["state"] = "감지"
        item["zombie_s"] = r3(close["_t"] - t0)
        item["close_code"] = close.get("code")
        item["close_by"] = close.get("by")
        hello = next((e for e in after if e.get("event") == "hello" and e["_t"] > close["_t"]), None)
        item["reconnect_s"] = r3(hello["_t"] - close["_t"]) if hello else None
        item["new_console"] = norm(hello.get("console")) if hello else None
        conns.append(item)
    zombies = [c for c in conns if c.get("state") in ("감지", "미감지")]
    detected = [c["zombie_s"] for c in zombies if c.get("zombie_s") is not None]
    reconnects = [c["reconnect_s"] for c in zombies if c.get("reconnect_s") is not None]
    return {"conns": conns, "target_conns": len(zombies),
            "zombie_max_s": r3(max(detected)) if detected else None,
            "undetected": sum(1 for c in zombies if c["state"] == "미감지"),
            "reconnect_max_s": r3(max(reconnects)) if reconnects else None}, unauthorized


def episode(run, i, mark, end, args):
    t0 = mark["_t"]
    scenario = mark.get("scenario") or "unknown"
    drain = scenario == "drain"
    notes = []
    target = mark.get("target")
    if not target:
        target = infer_target(run["fw"], t0, end)
        notes.append("표시에 대상이 없어 fw.csv 로 정했다: %s" % target)
    rec = next((m for m in run["marks"] if m.get("kind") == "recover" and t0 < m["_t"] < end
                and (not m.get("target") or m.get("target") == target)), None)
    t_rec = rec["_t"] if rec else None
    stop_at = t_rec if t_rec is not None else end
    reqs = [r for r in run["http"] if t0 <= r["_t"] < end]
    during = [r for r in reqs if r["_t"] < stop_at]
    after = [r for r in reqs if t_rec is not None and r["_t"] >= t_rec]
    base = [r for r in run["http"] if t0 - BASELINE_S <= r["_t"] < t0]

    det, det_status, det_note = detect(run["fw"], target, t0, end, drain) if run["fw"] else (None, None, "fw.csv 없음")
    if det_note:
        notes.append("감지: " + det_note)
    fail = fail_summary(during, t0)
    # 마지막 실패 뒤에 성공이 streak 번 넘게 이어져야 전환이 끝난 것이다(기록이 실패 속에서 끝나면 전환을 확인하지 못한 것)
    last_fail = max((r["_t"] for r in during if r.get("error")), default=None)
    fail["ok_after_last"] = sum(1 for r in during if last_fail is not None and r["_t"] > last_fail and r["_ok"])
    fail["settled"] = last_fail is None or fail["ok_after_last"] >= args.streak
    lat = latency(reqs, base)
    fo, fo_detail = failover(reqs, t0, target, args.streak)
    ws, ws_401 = ws_metrics(run["ws"], t0, end, target, args.zombie_window)
    if any(c.get("on_target") and c.get("console_at_t0") is None for c in ws["conns"]):
        notes.append("웹소켓 hello 에 콘솔 이름이 없어 T0 에 열려 있던 연결을 모두 대상으로 보았다")
    http_401 = sum(1 for r in reqs if r.get("error") == "http_401")
    rec_up, rec_note = recover_up(run["fw"], target, t_rec, end) if t_rec is not None and run["fw"] else (None, None)
    if rec_note:
        notes.append("복귀: " + rec_note)

    # 전환 = 감지와 실패 구간 끝 가운데 늦은 것. 감지가 없으면 셀 수 없다(실패 끝만으로 재면 감지가 늦은 회차를 놓친다)
    switchover = max(det, fail["last_s"] or 0.0) if det is not None else None
    unauthorized = http_401 + ws_401
    gate = SCENARIOS.get(scenario, (None, None, None, None, False))[4]
    reasons, undecided = [], []
    if not reqs:
        undecided.append("T0 뒤 HTTP 요청 기록이 없다")
    else:
        if det is None:
            # 주입이 먹지 않았거나 · 대상이 이미 빠져 있었거나 · fw.csv 가 없다. 실패가 없어도 합격으로 치지 않는다
            undecided.append("감지 시각이 없어 전환을 셀 수 없다 (%s)" % det_note)
        elif switchover > args.limit:
            reasons.append("전환 %.1f초 > %g초" % (switchover, args.limit))
        if not fail["settled"]:
            reasons.append("실패가 %s까지 이어졌다 (T0 뒤 %.1f초 · 뒤이은 성공 %d번 < %d, 전환 확인 못 함)" % (
                "복귀 표시" if t_rec is not None else "기록 끝", fail["last_s"], fail["ok_after_last"], args.streak))
        if unauthorized:
            reasons.append("401 · 1008 %d건 (세션 유지 실패)" % unauthorized)
    verdict = False if reasons else (None if undecided else True)
    reasons += ["%s (판정 불가)" % u for u in undecided]
    return {
        "index": i, "scenario": scenario, "target": target, "gate": gate,
        "t0": common.iso(mark["t_local_ns"]), "t0_remote": common.iso(mark.get("t_remote_ns")),
        "t0_host": mark.get("host"),
        "recover_at_s": r3(t_rec - t0) if t_rec is not None else None,
        "window_s": r3((min(end, max([r["_t"] for r in reqs] + [t0])) - t0)),
        "detect_s": r3(det), "detect_status": det_status,
        "fail": fail, "latency": lat,
        "failover_s": r3(fo), "failover": fo_detail,
        "ws": ws,
        "unauthorized": {"total": unauthorized, "http_401": http_401, "ws_1008": ws_401},
        "recover": {"up_s": r3(rec_up), "fail_count": sum(1 for r in after if r.get("error")),
                    "fail_by_error": dict(sorted(Counter(r["error"] for r in after if r.get("error")).items()))},
        "baseline_fail_count": sum(1 for r in base if r.get("error")),
        "switchover_s": r3(switchover),
        "pass": verdict, "reasons": reasons, "notes": notes,
    }


def summarize_run(run, args):
    injects = [m for m in run["marks"] if m.get("kind") == "inject"]
    eps = []
    for i, m in enumerate(injects):
        end = injects[i + 1]["_t"] if i + 1 < len(injects) else float("inf")
        eps.append(episode(run, i, m, end, args))
    return {"run": run["name"], "files": run["files"],
            "counts": {"http": len(run["http"]), "ws": len(run["ws"]), "fw": len(run["fw"]),
                       "marks": len(run["marks"]), "log_servers": run["log_servers"]},
            "fw_clock_offset_ms": r3(run["fw_offset"] * 1000) if run["fw_offset"] is not None else None,
            "episodes": eps}


METRICS = (
    ("detect_s", lambda e: e["detect_s"]),
    ("fail_window_s", lambda e: e["fail"]["window_s"]),
    ("fail_last_s", lambda e: e["fail"]["last_s"]),
    ("fail_count", lambda e: e["fail"]["count"]),
    ("switchover_s", lambda e: e["switchover_s"]),
    ("failover_s", lambda e: e["failover_s"]),
    ("p99_ms", lambda e: e["latency"]["p99_ms"]),
    ("max_ms", lambda e: e["latency"]["max_ms"]),
    ("ws_zombie_max_s", lambda e: e["ws"]["zombie_max_s"]),
    ("ws_undetected", lambda e: e["ws"]["undetected"]),
    ("ws_reconnect_max_s", lambda e: e["ws"]["reconnect_max_s"]),
    ("unauthorized", lambda e: e["unauthorized"]["total"]),
    ("recover_up_s", lambda e: e["recover"]["up_s"]),
)


def aggregate(runs):
    groups = defaultdict(list)
    for run in runs:
        for e in run["episodes"]:
            groups[e["scenario"]].append(e)
    out = {}
    for scenario, eps in sorted(groups.items()):
        row = {"n": len(eps), "gate": eps[0]["gate"], "targets": sorted({str(e["target"]) for e in eps}),
               "pass": sum(1 for e in eps if e["pass"] is True),
               "fail": sum(1 for e in eps if e["pass"] is False),
               "undecided": sum(1 for e in eps if e["pass"] is None)}
        for name, get in METRICS:
            vals = [get(e) for e in eps if get(e) is not None]
            row[name] = {"median": r3(statistics.median(vals)) if vals else None,
                         "max": r3(max(vals)) if vals else None, "n": len(vals)}
        out[scenario] = row
    return out


def provenance():
    repo = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
    tools = {"infra/vmware/failover/%s" % n: sha256_file(os.path.join(HERE, n))
             for n in TOOLS if os.path.isfile(os.path.join(HERE, n))}
    head, note = None, "git 정보를 읽지 못했다"
    try:
        head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=10).stdout.decode().strip() or None
        dirty = subprocess.run(["git", "-C", repo, "status", "--porcelain", "--", "infra/vmware/failover"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10).stdout.decode().strip()
        note = "도구 파일에 커밋하지 않은 변경이 있다 (sha256 로 판을 가린다)" if dirty else "도구 파일은 git HEAD 와 같다"
    except (OSError, subprocess.SubprocessError):
        pass
    return {"git_head": head, "worktree_note": note, "source_sha256": tools}


def find_runs(paths):
    """회차 폴더 목록. 부모 · 자식을 함께 주거나 같은 폴더를 두 번 줘도 한 번만 센다(중앙값 · n 이 틀어지지 않게)."""
    runs, seen = [], set()
    for p in paths:
        if not os.path.isdir(p):
            raise common.ToolError("폴더가 아니다: %s" % p)
        if os.path.isfile(os.path.join(p, "marks.jsonl")):
            subs = [p]
        else:
            subs = sorted(os.path.join(p, d) for d in os.listdir(p)
                          if os.path.isfile(os.path.join(p, d, "marks.jsonl")))
            if not subs:
                raise common.ToolError("회차 폴더(marks.jsonl 있는 폴더)가 없다: %s" % p)
        for d in subs:
            real = os.path.realpath(d)
            if real not in seen:
                seen.add(real)
                runs.append(d)
    return runs


def fmt(v):
    if v is None:
        return "-"
    return ("%.3f" % v).rstrip("0").rstrip(".") if isinstance(v, float) else str(v)


def table(summary):
    lines = ["시나리오      n  합격  감지(중앙/최대)  실패구간끝      전환            전환완료        p99ms           "
             "좀비 최대/미감지  재연결      401"]
    for sc, row in summary.items():
        def mm(k):
            return "%s/%s" % (fmt(row[k]["median"]), fmt(row[k]["max"]))
        lines.append("%-12s %2d  %s  %-15s %-15s %-15s %-15s %-15s %-17s %-11s %s" % (
            sc + ("" if row["gate"] else "*"), row["n"], "%d/%d" % (row["pass"], row["n"]),
            mm("detect_s"), mm("fail_last_s"), mm("switchover_s"), mm("failover_s"), mm("p99_ms"),
            "%s/%s" % (fmt(row["ws_zombie_max_s"]["max"]), fmt(row["ws_undetected"]["max"])),
            fmt(row["ws_reconnect_max_s"]["max"]), fmt(row["unauthorized"]["max"])))
    lines.append("(* 합격선 밖 · 참고. 초 단위, 지연은 밀리초)")
    return "\n".join(lines)


def parse_args(argv):
    p = argparse.ArgumentParser(description="장애 주입 시험 결과 요약 (이슈 #43). 사용법은 파일 머리 주석")
    p.add_argument("paths", nargs="+", help="회차 폴더, 또는 회차 폴더들을 담은 폴더")
    p.add_argument("--out", help="results.json · sha256.json 을 둘 폴더 (기본: 폴더 하나만 주면 그 폴더)")
    p.add_argument("--limit", type=float, default=30.0, help="전환 합격선 초 (기본 30)")
    p.add_argument("--streak", type=int, default=20, help="전환 완료로 볼 연속 성공 수 (기본 20)")
    p.add_argument("--zombie-window", type=float, default=120.0, help="좀비 감지 창 초 (기본 120)")
    return p.parse_args(argv)


def build(args):
    dirs = find_runs(args.paths)
    runs = [summarize_run(load_run(d), args) for d in dirs]
    t0s = [e["t0"] for r in runs for e in r["episodes"]]
    first = datetime.fromisoformat(min(t0s)).astimezone(KST) if t0s else datetime.now(KST)
    return {
        "date": first.strftime("%Y-%m-%d"),
        "timezone": "Asia/Seoul",
        "scope": "콘솔 이중화 장애 주입 시험 (이슈 #43). 시각 문자열은 UTC ISO, 지표는 T0(주입 직전 표시, Mac 시계) 기준 초 · 밀리초다.",
        "provenance": provenance(),
        "criteria": {"switchover_max_s": args.limit, "unauthorized_max": 0, "streak": args.streak,
                     "zombie_window_s": args.zombie_window,
                     "gate_scenarios": sorted(k for k, v in SCENARIOS.items() if v[4])},
        "runs": runs,
        "summary": aggregate(runs),
    }


def write_results(result, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    with open(os.path.join(out_dir, "sha256.json"), "w", encoding="utf-8") as f:
        json.dump({"results.json": sha256_file(path)}, f, indent=2)
        f.write("\n")
    return path


def main(argv=None):
    args = parse_args(argv)
    if args.limit <= 0 or args.streak < 1 or args.zombie_window <= 0:
        raise common.ToolError("--limit · --zombie-window 는 0 보다, --streak 는 1 이상")
    out = args.out or (args.paths[0] if len(args.paths) == 1 else None)
    if not out:
        raise common.ToolError("폴더를 여럿 주면 --out 이 필요하다")
    result = build(args)
    path = write_results(result, out)
    print(table(result["summary"]))
    eps = [e for r in result["runs"] for e in r["episodes"]]
    for r in result["runs"]:
        for e in r["episodes"]:
            mark = {True: "합격", False: "불합격", None: "판정 불가"}[e["pass"]]
            print("  %s #%d %s %s: %s%s" % (r["run"], e["index"], e["scenario"], e["target"], mark,
                                          " (" + " · ".join(e["reasons"]) + ")" if e["reasons"] else ""))
    print("→ %s" % path)
    gated = [e for e in eps if e["gate"]]
    if not eps:
        print("주입 표시(inject)가 없다", file=sys.stderr)
        return 1
    return 0 if all(e["pass"] is True for e in gated) else 1


if __name__ == "__main__":
    sys.exit(common.main_guard(main))
