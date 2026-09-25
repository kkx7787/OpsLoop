#!/usr/bin/env python3
"""장애 주입 시험 도구 시험 (이슈 #43).  python3 infra/vmware/failover/test_failover_tools.py

운영에 닿지 않는다. HOME 은 임시 폴더이고 ssh · date · curl · stat · sudo 는 가짜로 바꾼다(PATH 앞 가짜 실행기).
서버는 127.0.0.1 의 가짜 HTTP · 최소 웹소켓 서버다.
  - 요약        합성 회차로 지표를 고정한다: 즉시 거부형(컨테이너 정지) · 무응답형(VM 끔, 좀비 · 망 감지) ·
                401 · 1008(세션 유지 실패) · 늦은 전환 · 실패 속에서 끝남(전환 확인 못 함) · 콘솔 이름 없음 · 판정 불가 ·
                관찰 시나리오 · 대상 추정 · 여러 회차 중앙값 · 최댓값 · 방화벽 시계 맞춤 · HAProxy 로그로 health 콘솔 찾기 ·
                results.json 원천 sha256(절대 경로 없음) · sha256.json · 종료 코드 ·
                감지 없음은 판정 불가(주입이 먹지 않음 · 이미 빠져 있음 · fw.csv 없음) · 로그 p 겹침은 모름 ·
                end 뒤 다시 띄운 웹소켓 기록은 앞 연결로 치지 않음 · 같은 회차 폴더를 두 번 줘도 한 번 ·
                줄기가 서로 다른 콘솔에 고정돼도 전환 완료가 다른 줄기의 실패를 넘김
  - 웹소켓 프레임 RFC 6455 예시 바이트 · 길이 경계(125 · 126 · 65535 · 65536) · 조각 · 모자란 버퍼 · 규칙 위반 · 클로즈 본문 ·
                live.ts 와 같은 백오프
  - HTTP 프로브  가짜 서버로 JSONL 필드 · 줄기 · 쿼리 p · 쿠키 · Origin · console 기록 · 오류 분류
                (http_5xx · http_401 · connect_refused · timeout · reset) · 쿠키 파일 권한 · 꼴 · 만료 거부 ·
                SIGINT 가 무시된 채 떠도(백그라운드) Ctrl-C · kill 에 정리 종료 · 같은 폴더에 다시 띄우면 번호를 이어 감 ·
                기술자 soft 한도 256 에서도 걸린 요청이 쌓여 EMFILE 이 나지 않음 · hard 한도가 낮으면 동시 한도를 낮춤
  - 웹소켓 프로브 browser(서버 핑에 퐁 · 1012 뒤 백오프 재연결 · 1008 뒤 멈춤 · 403 은 1006 · 열리지 않으면 백오프 계속) ·
                net(퐁 없으면 끊김) · 클라이언트 프레임 가림 · 연결 여럿 · kill 에 연결마다 end
  - 쿠키        --mint-cookie(ssh 인자 · 원격 명령 · 0600 파일 · 0700 폴더) · 실패 문구 가림 · 이상한 별칭 거부 · --drop-cookie
  - 쿠키 미출력 프로브 · 발급의 표준 출력 · 표준 오류 · 기록 파일에 쿠키와 서명이 없다
  - 표시        mark.py 원격 시각 ns · local(VM 시나리오) · ssh 실패 · 인자 검사 · 시나리오 목록
  - 방화벽 수집 collect_fw.sh 를 가짜 ssh 로 로컬에서 돌린다(원격 루프도 실제로 돈다): CSV 열 · 상태 변화 · 통계 실패 ·
                Ctrl-C(프로세스 묶음 SIGINT) 뒤 로그 발췌 · 로그 돌려짐 · 로그 읽기 불가 · ssh 실패 · 인자 검사
  - 문법        bash -n (/bin/bash 3.2, 원격 루프 포함) · 파이썬 3.9 문법 · 표준 라이브러리만
"""
import base64
import csv as csv_mod
import hashlib
import http.server
import json
import os
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import common  # noqa: E402
import probe_ws  # noqa: E402
import summarize  # noqa: E402

PY = sys.executable
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
PROBE_HTTP = os.path.join(HERE, "probe_http.py")
PROBE_WS = os.path.join(HERE, "probe_ws.py")
MARK = os.path.join(HERE, "mark.py")
SUMMARIZE = os.path.join(HERE, "summarize.py")
COLLECT = os.path.join(HERE, "collect_fw.sh")


def make_token(exp_offset=12 * 3600, user="failover-probe", salt=b"t43"):
    body = json.dumps({"u": user, "r": "viewer", "e": int(time.time()) + exp_offset}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(body).decode().rstrip("=")
    sig = hashlib.sha256(payload.encode() + salt).hexdigest()[:32]
    return "%s.%s" % (payload, sig)


FAKE_SSH = r'''#!{py}
import json, os, sys
args = sys.argv[1:]
opts, i = [], 0
while i < len(args) and args[i].startswith("-"):
    opts += args[i:i + 2]
    i += 2
alias, cmd = args[i], " ".join(args[i + 1:])
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps({{"opts": opts, "alias": alias, "cmd": cmd}}) + "\n")
mode = os.environ.get("FAKE_SSH_MODE", "exec")
if mode == "fail":
    sys.stderr.write("ssh: connect to host %s port 22: Connection refused\n" % alias)
    sys.exit(255)
if mode == "date":
    print(os.environ.get("FAKE_REMOTE_DATE", "1790000000.123456789"))
    sys.exit(0)
if mode == "mint":
    print(os.environ["FAKE_TOKEN"])
    sys.exit(0)
if mode == "mint-fail":
    sys.stderr.write("Traceback: 쿠키 %s 를 만들다 실패\n" % os.environ["FAKE_TOKEN"])
    sys.exit(1)
os.execvp("bash", ["bash", "-c", cmd])
'''

FAKE_DATE = r'''#!{py}
import os, sys, time
a = sys.argv[1:]
if a == ["+%s.%N"]:
    print("%.9f" % time.time())
elif a == ["+%s"]:
    print(int(time.time()))
else:
    os.execv("/bin/date", ["/bin/date"] + a)
'''

FAKE_STAT = r'''#!{py}
import os, sys
a = sys.argv[1:]
if len(a) == 3 and a[0] == "-c" and a[1] in ("%s", "%i"):
    try:
        st = os.stat(a[2])
    except OSError:
        sys.exit(1)
    print(st.st_size if a[1] == "%s" else st.st_ino)
else:
    os.execv("/usr/bin/stat", ["/usr/bin/stat"] + a)
'''

FAKE_CURL = r'''#!{py}
import os, sys
try:
    data = open(os.environ["FAKE_CSV"]).read()
except OSError:
    sys.exit(7)
if not data:
    sys.exit(7)
sys.stdout.write(data)
'''

FAKE_SUDO = "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n"


class Sandbox:
    """임시 HOME · 가짜 실행기 PATH."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="t43-failover-")
        self.home = os.path.join(self.root, "home")
        self.bin = os.path.join(self.root, "bin")
        os.makedirs(self.home)
        os.makedirs(self.bin)
        for name, body in (("ssh", FAKE_SSH), ("date", FAKE_DATE), ("stat", FAKE_STAT), ("curl", FAKE_CURL)):
            self.script(name, body.format(py=PY))
        self.script("sudo", FAKE_SUDO)
        os.symlink(PY, os.path.join(self.bin, "python3"))
        self.ssh_log = os.path.join(self.root, "ssh.log")

    def script(self, name, body):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def env(self, **extra):
        e = dict(os.environ)
        e.update({"HOME": self.home, "PATH": self.bin + os.pathsep + os.environ.get("PATH", ""),
                  "FAKE_SSH_LOG": self.ssh_log, "PYTHONDONTWRITEBYTECODE": "1"})
        e.update(extra)
        return e

    def cookie(self, token, mode=0o600):
        d = os.path.join(self.home, ".config", "opsloop")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "probe-cookie")
        with open(p, "w") as f:
            f.write(token + "\n")
        os.chmod(p, mode)
        return p

    def ssh_calls(self):
        try:
            with open(self.ssh_log) as f:
                return [json.loads(x) for x in f if x.strip()]
        except FileNotFoundError:
            return []

    def run(self, argv, timeout=60, **env):
        return subprocess.run(argv, env=self.env(**env), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=self.root)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def assert_no_secret(tc, token, *texts):
    sig = token.rpartition(".")[2]
    for t in texts:
        if isinstance(t, bytes):
            t = t.decode("utf-8", "replace")
        tc.assertNotIn(token, t)
        tc.assertNotIn(sig, t)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ──────────────────────────────────────────────────────────────
#  합성 회차
# ──────────────────────────────────────────────────────────────
T0 = 1_790_000_100.0


class Synth:
    """콘솔 A · B 가 roundrobin 으로 번갈아 받는 회차를 만든다. 시각은 T0 기준 초."""

    def __init__(self, root, name):
        self.name = name
        self.dir = os.path.join(root, name)
        os.makedirs(self.dir)
        self.http, self.ws, self.marks, self.fw, self.log = [], [], [], [], []

    @staticmethod
    def ns(rel):
        return int(round((T0 + rel) * 1e9))

    def traffic(self, start=-30.0, end=60.0, detect_at=5.5, broken=(0.0, 30.0), up_at=36.5, fail=None,
                with_console=True, overrides=None):
        """간격 100ms · health · me. 짝수 번호는 A 로 간다(A 가 빠진 동안은 B).
        A 가 고장(broken 구간)인데 아직 빠지지 않았으면 fail(rel, k) 가 (status, error, latency) 를 준다."""
        fail = fail or (lambda rel, k: (503, "http_5xx", 3000.0))
        overrides = overrides or {}
        k = 0
        while True:
            rel = round(start + k * 0.1, 6)
            if rel >= end:
                break
            a_out = detect_at <= rel < up_at
            to_a = (k % 2 == 0) and not a_out
            a_broken = broken[0] <= rel < broken[1]
            for stream in ("health", "me"):
                status, error, lat = 200, None, 5.0
                console = "opsloop-console-a" if to_a else "opsloop-console-b"
                if to_a and a_broken:
                    status, error, lat = fail(rel, k)
                    console = None
                if (stream, k) in overrides:
                    status, error, lat = overrides[(stream, k)]
                    console = None
                t = self.ns(rel)
                self.http.append({"run": self.name, "stream": stream, "seq": k, "t_send_ns": t,
                                  "t_recv_ns": t + int(lat * 1e6), "status": status, "latency_ms": lat,
                                  "error": error,
                                  "console": console if (stream == "me" and with_console and status == 200) else None})
                if stream == "health" and with_console:
                    srv = "console-a" if to_a else "console-b"
                    self.log.append('Sep 25 10:00:00 opsloop-fw haproxy[9]: 192.168.70.1:50000 [25/Sep/2026:10:00:00.000] '
                                    'console consoles/%s 0/0/0/1/1 %s 170 - - ---- 1/1/0/0/0 0/0 '
                                    '"GET /health?p=%s-%d HTTP/1.1"' % (srv, status if status else -1, self.name, k))
            k += 1

    def fw_samples(self, start=-30.0, end=60.0, detect_at=5.5, up_at=36.5, skew=-0.25):
        i = 0
        while True:
            rel = round(start + i * 0.5, 6)
            if rel >= end:
                break
            if rel < detect_at - 4:
                a = "UP"
            elif rel < detect_at - 2:
                a = "UP 1/3"
            elif rel < detect_at:
                a = "UP 2/3"
            elif rel < up_at:
                a = "DOWN"
            else:
                a = "UP"
            t_local = T0 + rel + 0.01 + (i % 3) * 0.01
            t_fw = T0 + rel + skew
            for sv, st in (("console-a", a), ("console-b", "UP"), ("BACKEND", "UP")):
                self.fw.append("%.6f,%.6f,%s,%s,0,0,0,1,L7OK,1,0" % (t_local, t_fw, sv, st))
            i += 1

    def mark(self, kind, rel, scenario, target="console-a"):
        self.marks.append({"run": self.name, "kind": kind, "scenario": scenario, "target": target,
                           "host": target, "t_local_ns": self.ns(rel), "t_local_before_ns": self.ns(rel) - 50_000_000,
                           "t_remote_ns": self.ns(rel), "rtt_ms": 50.0, "offset_ms": 0.0, "note": None})

    def ws_ev(self, stream, conn, rel, event, **kw):
        rec = {"run": self.name, "stream": stream, "conn": conn, "event": event, "t_ns": self.ns(rel)}
        rec.update(kw)
        self.ws.append(rec)

    def write(self, log=True, fw=True):
        def jl(name, rows):
            with open(os.path.join(self.dir, name), "w") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        jl("http.jsonl", self.http)
        jl("ws.jsonl", self.ws)
        jl("marks.jsonl", self.marks)
        if fw:
            with open(os.path.join(self.dir, "fw.csv"), "w") as f:
                f.write("t_local,t_fw,svname,status,bck,chkfail,chkdown,lastchg,check_status,check_duration,scur\n")
                f.write("\n".join(self.fw) + "\n")
        if log and self.log:
            with open(os.path.join(self.dir, "fw-haproxy.log"), "w") as f:
                f.write("\n".join(self.log) + "\n")
        return self.dir


class Args:
    limit, streak, zombie_window = 30.0, 20, 120.0


def stop_run(root, name="r01-stop-a", detect_at=5.5, **kw):
    s = Synth(root, name)
    s.traffic(detect_at=detect_at, **kw)
    s.fw_samples(detect_at=detect_at)
    s.mark("inject", 0.0, "stop")
    s.mark("recover", 30.0, "stop")
    # browser 연결 둘: 0 은 A 에 붙어 있다가 정지 때 서버가 1012 로 닫는다 · 1 은 B
    s.ws_ev("ws-browser", 0, -20.0, "open")
    s.ws_ev("ws-browser", 0, -19.95, "hello", console="opsloop-console-a")
    s.ws_ev("ws-browser", 0, 0.3, "close", code=1012, by="server", reason="", was_open=True)
    s.ws_ev("ws-browser", 0, 1.3, "reconnect", attempt=1, delay_ms=1000)
    s.ws_ev("ws-browser", 0, 1.32, "open")
    s.ws_ev("ws-browser", 0, 1.35, "hello", console="opsloop-console-b")
    s.ws_ev("ws-browser", 1, -20.0, "open")
    s.ws_ev("ws-browser", 1, -19.9, "hello", console="opsloop-console-b")
    s.ws_ev("ws-browser", 0, 59.0, "end", was_open=True)
    s.ws_ev("ws-browser", 1, 59.0, "end", was_open=True)
    return s


class SummarizeTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="t43-sum-")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def one(self, synth, **write):
        synth.write(**write)
        run = summarize.summarize_run(summarize.load_run(synth.dir), Args())
        self.assertEqual(len(run["episodes"]), 1)
        return run, run["episodes"][0]

    def test_immediate_refusal_stop(self):
        """즉시 거부형: A 로 간 요청이 503 으로 빨리 실패하다 DOWN 뒤 B 만 받는다."""
        run, e = self.one(stop_run(self.root))
        self.assertAlmostEqual(run["fw_clock_offset_ms"], 260.0, places=1)
        self.assertEqual(e["scenario"], "stop")
        self.assertTrue(e["gate"])
        self.assertAlmostEqual(e["detect_s"], 5.51, places=2)
        self.assertEqual(e["detect_status"], "DOWN")
        f = e["fail"]
        self.assertEqual(f["count"], 56)                    # 0.0 ~ 5.4 짝수 번호 28개 × 두 줄기
        self.assertEqual(f["by_error"], {"http_5xx": 56})
        self.assertEqual(f["by_stream"], {"health": 28, "me": 28})
        self.assertAlmostEqual(f["first_s"], 0.0, places=3)
        self.assertAlmostEqual(f["last_s"], 5.4, places=3)
        self.assertAlmostEqual(f["window_s"], 5.4, places=3)
        self.assertTrue(f["settled"])
        self.assertAlmostEqual(e["switchover_s"], 5.51, places=2)
        self.assertAlmostEqual(e["failover_s"], 5.5, places=3)
        self.assertEqual(e["failover"]["me"]["basis"], "다른 콘솔")
        self.assertEqual(e["failover"]["health"]["basis"], "다른 콘솔")   # fw-haproxy.log 로 서버를 안다
        self.assertAlmostEqual(e["failover"]["me"]["confirmed_s"], 7.405, places=3)
        self.assertEqual(e["latency"]["max_ms"], 3000.0)
        self.assertEqual(e["latency"]["ok_max_ms"], 5.0)
        self.assertEqual(e["latency"]["baseline_p99_ms"], 5.0)
        self.assertEqual(e["unauthorized"], {"total": 0, "http_401": 0, "ws_1008": 0})
        self.assertAlmostEqual(e["recover"]["up_s"], 6.51, places=2)
        self.assertEqual(e["recover"]["fail_count"], 0)
        self.assertEqual(e["baseline_fail_count"], 0)
        ws = e["ws"]
        self.assertEqual(ws["target_conns"], 1)
        c0 = [c for c in ws["conns"] if c["conn"] == 0][0]
        c1 = [c for c in ws["conns"] if c["conn"] == 1][0]
        self.assertEqual(c0["state"], "감지")
        self.assertAlmostEqual(c0["zombie_s"], 0.3, places=3)
        self.assertEqual(c0["close_code"], 1012)
        self.assertAlmostEqual(c0["reconnect_s"], 1.05, places=3)
        self.assertEqual(c0["new_console"], "console-b")
        self.assertEqual(c1["state"], "다른 콘솔")
        self.assertIs(e["pass"], True)
        self.assertEqual(e["reasons"], [])

    def test_no_response_vm_off(self):
        """무응답형: A 로 간 요청이 504(60초) · 타임아웃(70초)으로 끝난다. 브라우저 연결은 좀비, net 연결은 퐁 없음으로 끊는다."""
        def hang(rel, k):
            return (None, "timeout", 70000.0) if k in (300, 302) else (504, "http_5xx", 60000.0)
        s = Synth(self.root, "r02-vm-off-a")
        s.traffic(detect_at=6.0, fail=hang)
        s.fw_samples(detect_at=6.0)
        s.mark("inject", 0.0, "vm-off")
        s.mark("recover", 30.0, "vm-off")
        s.ws_ev("ws-browser", 0, -20.0, "open")
        s.ws_ev("ws-browser", 0, -19.9, "hello", console="opsloop-console-a")
        s.ws_ev("ws-browser", 0, 150.0, "end", was_open=True)
        s.ws_ev("ws-net", 0, -20.0, "open")
        s.ws_ev("ws-net", 0, -19.9, "hello", console="opsloop-console-a")
        s.ws_ev("ws-net", 0, 2.6, "close", code=1006, by="local", reason="퐁 없음", was_open=True)
        s.ws_ev("ws-net", 0, 3.6, "reconnect", attempt=1, delay_ms=1000)
        s.ws_ev("ws-net", 0, 3.65, "hello", console="opsloop-console-b")
        _, e = self.one(s)
        self.assertAlmostEqual(e["detect_s"], 6.01, places=2)
        self.assertAlmostEqual(e["fail"]["last_s"], 5.8, places=3)
        self.assertEqual(e["fail"]["by_error"], {"http_5xx": 56, "timeout": 4})
        self.assertAlmostEqual(e["switchover_s"], 6.01, places=2)
        self.assertEqual(e["latency"]["max_ms"], 70000.0)
        self.assertEqual(e["latency"]["p99_ms"], 60000.0)
        ws = e["ws"]
        net = [c for c in ws["conns"] if c["stream"] == "ws-net"][0]
        br = [c for c in ws["conns"] if c["stream"] == "ws-browser"][0]
        self.assertEqual(br["state"], "미감지")
        self.assertIsNone(br["zombie_s"])
        self.assertEqual(br["observed_s"], 120.0)
        self.assertEqual(net["state"], "감지")
        self.assertAlmostEqual(net["zombie_s"], 2.6, places=3)
        self.assertEqual(net["close_by"], "local")
        self.assertAlmostEqual(net["reconnect_s"], 1.05, places=3)
        self.assertEqual(ws["undetected"], 1)
        self.assertAlmostEqual(ws["zombie_max_s"], 2.6, places=3)
        self.assertIs(e["pass"], True)

    def test_late_zombie_close_is_undetected(self):
        """120초 넘어 닫히면 미감지로 두고 늦은 닫힘 시각을 따로 적는다."""
        s = stop_run(self.root)
        s.ws = [w for w in s.ws if w["conn"] != 0]
        s.ws_ev("ws-browser", 0, -20.0, "open")
        s.ws_ev("ws-browser", 0, -19.9, "hello", console="opsloop-console-a")
        s.ws_ev("ws-browser", 0, 130.0, "close", code=1006, by="net", reason="eof", was_open=True)
        _, e = self.one(s)
        c0 = [c for c in e["ws"]["conns"] if c["conn"] == 0][0]
        self.assertEqual(c0["state"], "미감지")
        self.assertAlmostEqual(c0["late_close_s"], 130.0, places=3)

    def test_unauthorized_fails(self):
        """전환 뒤 B 가 401 을 주면(세션 비밀이 다르다) 불합격이다. 웹소켓 1008 도 센다."""
        over = {("me", 400): (401, "http_401", 4.0), ("me", 401): (401, "http_401", 4.0)}
        s = stop_run(self.root, overrides=over)
        s.ws_ev("ws-browser", 1, 12.0, "close", code=1008, by="server", reason="", was_open=True)
        s.ws_ev("ws-browser", 1, 12.0, "stopped")
        _, e = self.one(s)
        self.assertEqual(e["unauthorized"], {"total": 3, "http_401": 2, "ws_1008": 1})
        self.assertIs(e["pass"], False)
        self.assertTrue(any("401" in r for r in e["reasons"]))

    def test_late_switchover_fails(self):
        s = Synth(self.root, "r03-slow")
        s.traffic(detect_at=35.0, broken=(0.0, 50.0), up_at=56.5, end=80.0)
        s.fw_samples(detect_at=35.0, up_at=56.5, end=80.0)
        s.mark("inject", 0.0, "kill")
        s.mark("recover", 50.0, "kill")
        _, e = self.one(s)
        self.assertAlmostEqual(e["detect_s"], 35.01, places=2)
        self.assertAlmostEqual(e["fail"]["last_s"], 34.8, places=3)
        self.assertIs(e["pass"], False)
        self.assertTrue(any("30" in r for r in e["reasons"]))

    def test_failures_until_end_not_settled(self):
        """실패 속에서 기록이 끝나면(대상이 빠지지 않음) 실패 구간이 짧아도 전환을 확인하지 못한 것으로 불합격이다."""
        s = Synth(self.root, "r05-unsettled")
        s.traffic(end=10.0, detect_at=1000.0, broken=(0.0, 1000.0), up_at=2000.0)
        s.fw_samples(end=10.0, detect_at=1000.0, up_at=2000.0)
        s.mark("inject", 0.0, "stop")
        _, e = self.one(s)
        self.assertIsNone(e["detect_s"])
        self.assertIsNone(e["switchover_s"])               # 감지가 없으면 전환을 셀 수 없다
        self.assertLess(e["fail"]["last_s"], 30)
        self.assertFalse(e["fail"]["settled"])
        self.assertIs(e["pass"], False)
        self.assertTrue(any("전환 확인 못 함" in r for r in e["reasons"]))

    def test_without_console_names(self):
        """콘솔 이름(/api/me console · 로그)이 없으면 첫 실패 뒤 연속 성공으로 세고 그렇게 적는다."""
        s = stop_run(self.root, with_console=False)
        for w in s.ws:
            w.pop("console", None)
        _, e = self.one(s, log=False)
        self.assertEqual(e["ws"]["target_conns"], 2)
        self.assertTrue(any("콘솔 이름이 없어" in n for n in e["notes"]))
        for stream in ("me", "health"):
            self.assertEqual(e["failover"][stream]["basis"], "콘솔 이름 없음 · 첫 실패 뒤 연속 성공")
        self.assertAlmostEqual(e["failover_s"], 5.5, places=3)

    def test_streams_pinned_to_different_consoles(self):
        """roundrobin 이 같은 순간 쏜 두 줄기를 번갈아 받아 health 는 늘 A, me 는 늘 B 로 간다(로그 발췌 없음).
        me 만 보면 전환 완료가 0초지만 health 의 실패(5.4초까지)를 넘겨야 한다."""
        s = Synth(self.root, "r09-pinned")
        k = 0
        while True:
            rel = round(-30.0 + k * 0.1, 6)
            if rel >= 60.0:
                break
            for stream in ("health", "me"):
                to_a = stream == "health" and not 5.5 <= rel < 36.5
                status, error, lat = 200, None, 5.0
                console = "opsloop-console-a" if to_a else "opsloop-console-b"
                if to_a and 0.0 <= rel < 30.0:
                    status, error, lat, console = 503, "http_5xx", 3000.0, None
                t = s.ns(rel)
                s.http.append({"run": s.name, "stream": stream, "seq": k, "t_send_ns": t,
                               "t_recv_ns": t + int(lat * 1e6), "status": status, "latency_ms": lat, "error": error,
                               "console": console if stream == "me" else None})
            k += 1
        s.fw_samples(detect_at=5.5)
        s.mark("inject", 0.0, "stop")
        s.mark("recover", 30.0, "stop")
        _, e = self.one(s, log=False)
        self.assertEqual(e["fail"]["by_stream"], {"health": 55})
        self.assertEqual(e["failover"]["me"]["failover_s"], 0.0)
        self.assertEqual(e["failover"]["health"]["basis"], "콘솔 이름 없음 · 첫 실패 뒤 연속 성공")
        self.assertAlmostEqual(e["failover_s"], 5.5, places=3)
        self.assertIs(e["pass"], True)

    def test_undecided_without_requests(self):
        s = Synth(self.root, "r04-empty")
        s.fw_samples()
        s.mark("inject", 0.0, "stop")
        _, e = self.one(s)
        self.assertIsNone(e["pass"])
        self.assertTrue(e["reasons"])

    def test_observation_scenario_not_gated(self):
        s = stop_run(self.root)
        for m in s.marks:
            m["scenario"] = "db-cut"
        _, e = self.one(s)
        self.assertFalse(e["gate"])

    def test_target_inferred_from_fw(self):
        s = stop_run(self.root)
        for m in s.marks:
            m["target"] = None
        _, e = self.one(s)
        self.assertEqual(e["target"], "console-a")
        self.assertTrue(any("fw.csv" in n for n in e["notes"]))

    def test_log_server_parse(self):
        line = ('Sep 25 10:00:00 fw haproxy[1]: 192.168.70.1:5000 [25/Sep/2026:10:00:00.001] console '
                'consoles/console-b 0/0/0/2/2 200 170 - - ---- 1/1/0/0/0 0/0 "GET /health?p=r-01-42 HTTP/1.1"')
        p = os.path.join(self.root, "x.log")
        with open(p, "w") as f:
            f.write(line + "\nother line\n")
        self.assertEqual(summarize.read_log_servers(p), {"r-01-42": "console-b"})
        # 같은 p 가 다른 서버로 두 번(번호가 겹친 기록) → 어느 요청인지 모르니 콘솔을 모르는 것으로 둔다
        with open(p, "w") as f:
            f.write("\n".join([line, line.replace("r-01-42", "r-01-43"), line,     # 같은 서버로 두 번은 그대로
                               line.replace("consoles/console-b", "consoles/console-a"),
                               line, line.replace("r-01-42", "r-01-43")]) + "\n")
        self.assertEqual(summarize.read_log_servers(p), {"r-01-42": None, "r-01-43": "console-b"})

    def test_no_detection_is_undecided(self):
        """감지가 없으면 실패가 없어도 합격이 아니다: 주입이 먹지 않음 · T0 에 대상이 이미 빠져 있음 · fw.csv 없음."""
        s = Synth(self.root, "r06-noop")
        s.traffic(detect_at=1000.0, broken=(1000.0, 1000.0), up_at=2000.0)
        s.fw_samples(detect_at=1000.0, up_at=2000.0)
        s.mark("inject", 0.0, "stop")
        s.mark("recover", 30.0, "stop")
        _, e = self.one(s)
        self.assertEqual(e["fail"]["count"], 0)
        self.assertIsNone(e["switchover_s"])
        self.assertIsNone(e["pass"])
        self.assertTrue(any("감지 시각이 없어" in r and "빠지지 않았다" in r and "판정 불가" in r for r in e["reasons"]))
        s = Synth(self.root, "r07-already")
        s.traffic(detect_at=-20.0, broken=(-25.0, 30.0), up_at=36.5)
        s.fw_samples(detect_at=-20.0, up_at=36.5)
        s.mark("inject", 0.0, "stop")
        s.mark("recover", 30.0, "stop")
        _, e = self.one(s)
        self.assertIsNone(e["pass"])
        self.assertTrue(any("이미 빠져" in r for r in e["reasons"]))
        _, e = self.one(stop_run(self.root, "r08-nofw"), fw=False)
        self.assertEqual(e["fail"]["count"], 56)
        self.assertIsNone(e["switchover_s"])                # 실패 끝(5.4초)만으로 재지 않는다
        self.assertIsNone(e["pass"])
        self.assertTrue(any("fw.csv 없음" in r for r in e["reasons"]))
        # 판정 불가 회차가 있으면 종료 1
        p = subprocess.run([PY, SUMMARIZE, os.path.join(self.root, "r06-noop")], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(p.returncode, 1, p.stderr.decode())
        self.assertIn("판정 불가", p.stdout.decode())

    def test_ws_observation_ends_at_probe_end(self):
        """프로브를 멈춘(end) 뒤 같은 줄기 · 번호로 다시 띄운 실행의 close 를 앞 연결의 좀비 닫힘으로 세지 않는다."""
        s = stop_run(self.root)
        s.ws = [w for w in s.ws if w["conn"] != 0]
        s.ws_ev("ws-browser", 0, -20.0, "open")
        s.ws_ev("ws-browser", 0, -19.9, "hello", console="opsloop-console-a")
        s.ws_ev("ws-browser", 0, 50.0, "end", was_open=True)
        s.ws_ev("ws-browser", 0, 60.0, "open")
        s.ws_ev("ws-browser", 0, 60.1, "hello", console="opsloop-console-b")
        s.ws_ev("ws-browser", 0, 70.0, "close", code=1012, by="server", reason="", was_open=True)
        _, e = self.one(s)
        c0 = [c for c in e["ws"]["conns"] if c["conn"] == 0][0]
        self.assertEqual(c0["state"], "미감지")
        self.assertIsNone(c0["zombie_s"])
        self.assertAlmostEqual(c0["observed_s"], 50.0, places=3)
        self.assertNotIn("late_close_s", c0)

    def test_cli_aggregate_and_evidence(self):
        """여러 회차: 시나리오별 중앙값 · 최댓값, 원천 sha256, sha256.json, 종료 코드."""
        base = os.path.join(self.root, "runs")
        os.makedirs(base)
        stop_run(base, "r01-stop-a", detect_at=5.5).write()
        stop_run(base, "r02-stop-a", detect_at=4.0).write()
        out = os.path.join(self.root, "evidence")
        p = subprocess.run([PY, SUMMARIZE, base, "--out", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        text = p.stdout.decode()
        self.assertIn("stop", text)
        self.assertIn("합격", text)
        with open(os.path.join(out, "results.json")) as f:
            res = json.load(f)
        self.assertEqual(res["timezone"], "Asia/Seoul")
        self.assertEqual(res["date"], "2026-09-21")      # T0 = 2026-09-21T14:15:00Z → 한국 시각 23:15
        self.assertIn("infra/vmware/failover/summarize.py", res["provenance"]["source_sha256"])
        self.assertEqual(res["criteria"]["gate_scenarios"], ["kill", "stop", "vm-off"])
        self.assertEqual([r["run"] for r in res["runs"]], ["r01-stop-a", "r02-stop-a"])
        for r in res["runs"]:
            for name, digest in r["files"].items():
                self.assertEqual(digest, summarize.sha256_file(os.path.join(base, r["run"], name)))
            self.assertIn("fw-haproxy.log", r["files"])
            self.assertNotIn(self.root, json.dumps(r))    # 절대 경로(사용자 이름)를 싣지 않는다
        row = res["summary"]["stop"]
        self.assertEqual(row["n"], 2)
        self.assertEqual(row["pass"], 2)
        self.assertAlmostEqual(row["detect_s"]["median"], 4.76, places=2)
        self.assertAlmostEqual(row["detect_s"]["max"], 5.51, places=2)
        self.assertEqual(row["unauthorized"]["max"], 0)
        with open(os.path.join(out, "sha256.json")) as f:
            self.assertEqual(json.load(f), {"results.json": summarize.sha256_file(os.path.join(out, "results.json"))})
        # 불합격 회차가 섞이면 종료 1
        over = {("me", 400): (401, "http_401", 4.0)}
        stop_run(base, "r03-stop-a", overrides=over).write()
        p = subprocess.run([PY, SUMMARIZE, base, "--out", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=60)
        self.assertEqual(p.returncode, 1)
        self.assertIn("불합격", p.stdout.decode())

    def test_cli_same_run_given_twice(self):
        """부모 폴더와 그 안의 회차 폴더를 함께 줘도 회차를 한 번만 센다."""
        base = os.path.join(self.root, "runs")
        os.makedirs(base)
        stop_run(base, "r01-stop-a").write()
        out = os.path.join(self.root, "evidence")
        p = subprocess.run([PY, SUMMARIZE, base, os.path.join(base, "r01-stop-a"), base + "/", "--out", out],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        with open(os.path.join(out, "results.json")) as f:
            res = json.load(f)
        self.assertEqual([r["run"] for r in res["runs"]], ["r01-stop-a"])
        self.assertEqual(res["summary"]["stop"]["n"], 1)

    def test_cli_errors(self):
        p = subprocess.run([PY, SUMMARIZE, self.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertIn("회차 폴더", p.stderr.decode())


# ──────────────────────────────────────────────────────────────
#  웹소켓 프레임
# ──────────────────────────────────────────────────────────────
class FrameTest(unittest.TestCase):
    def test_accept_key_rfc(self):
        self.assertEqual(probe_ws.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_rfc_examples(self):
        # RFC 6455 5.7
        self.assertEqual(probe_ws.encode_frame(probe_ws.OP_TEXT, b"Hello", mask=False),
                         bytes([0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]))
        self.assertEqual(probe_ws.encode_frame(probe_ws.OP_TEXT, b"Hello", mask_key=b"\x37\xfa\x21\x3d"),
                         bytes([0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]))
        self.assertEqual(probe_ws.encode_frame(probe_ws.OP_PING, b"Hello", mask=False)[:2], bytes([0x89, 0x05]))
        self.assertEqual(probe_ws.encode_frame(probe_ws.OP_BINARY, b"\0" * 256, mask=False)[:4],
                         bytes([0x82, 0x7E, 0x01, 0x00]))
        self.assertEqual(probe_ws.encode_frame(probe_ws.OP_BINARY, b"\0" * 65536, mask=False)[:10],
                         bytes([0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0]))
        frame, used = probe_ws.decode_frame(bytes([0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]))
        self.assertEqual((frame.fin, frame.opcode, frame.payload, frame.masked, used), (True, 1, b"Hello", True, 11))

    def test_roundtrip_lengths(self):
        for n in (0, 1, 125, 126, 127, 65535, 65536, 70000):
            payload = os.urandom(n)
            for mask in (True, False):
                data = probe_ws.encode_frame(probe_ws.OP_BINARY, payload, mask=mask)
                frame, used = probe_ws.decode_frame(data + b"extra")
                self.assertEqual(used, len(data), n)
                self.assertEqual(frame.payload, payload)
                self.assertEqual(frame.masked, mask)
                # 모자란 버퍼는 기다린다
                for cut in (0, 1, 2, len(data) - 1):
                    if cut < len(data):
                        self.assertEqual(probe_ws.decode_frame(data[:cut]), (None, 0))

    def test_fragments(self):
        a = probe_ws.Assembler()
        f1, _ = probe_ws.decode_frame(bytes([0x01, 0x03]) + b"Hel")
        f2, _ = probe_ws.decode_frame(bytes([0x80, 0x02]) + b"lo")
        self.assertIsNone(a.feed(f1))
        self.assertEqual(a.feed(f2), (probe_ws.OP_TEXT, b"Hello"))
        with self.assertRaises(probe_ws.ProtocolError):
            probe_ws.Assembler().feed(f2)                       # 시작 없는 이어짐

    def test_protocol_errors(self):
        bad = [bytes([0xC1, 0x00]),                              # RSV1
               bytes([0x83, 0x00]),                              # 모르는 opcode
               bytes([0x89, 0x7E, 0x00, 0x7E]) + b"x" * 126,     # 제어 프레임 126 바이트
               bytes([0x09, 0x00])]                              # 조각난 제어 프레임
        for data in bad:
            with self.assertRaises(probe_ws.ProtocolError, msg=data[:2]):
                probe_ws.decode_frame(data)
        with self.assertRaises(probe_ws.ProtocolError):
            probe_ws.decode_frame(probe_ws.encode_frame(probe_ws.OP_TEXT, b"x" * 200, mask=False), max_payload=100)
        with self.assertRaises(probe_ws.ProtocolError):
            probe_ws.encode_frame(probe_ws.OP_PING, b"x" * 126)

    def test_close_payload(self):
        self.assertEqual(probe_ws.parse_close(probe_ws.close_payload(1008, "정책")), (1008, "정책"))
        self.assertEqual(probe_ws.parse_close(b""), (1005, ""))
        self.assertEqual(probe_ws.close_payload(None), b"")

    def test_backoff_matches_live_ts(self):
        self.assertEqual([probe_ws.backoff(n) for n in range(7)], [1, 2, 4, 8, 16, 30, 30])


# ──────────────────────────────────────────────────────────────
#  가짜 서버
# ──────────────────────────────────────────────────────────────
class FakeConsole(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, token, console="opsloop-console-a"):
        self.token, self.console, self.health_status = token, console, 200
        self.seen = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server_address[1]

    def stop(self):
        self.shutdown()
        self.server_close()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv = self.server
        with srv.lock:
            srv.seen.append({"path": self.path, "cookie": self.headers.get("Cookie"),
                             "origin": self.headers.get("Origin"), "ua": self.headers.get("User-Agent")})
        if self.path.startswith("/health"):
            self._send(srv.health_status, {"status": "ok"} if srv.health_status == 200 else {"detail": "x"})
        elif self.path == "/api/me":
            if self.headers.get("Cookie") == "%s=%s" % (common.COOKIE_NAME, srv.token):
                self._send(200, {"username": "failover-probe", "role": "viewer", "console": srv.console})
            else:
                self._send(401, {"detail": "인증이 필요합니다"})
        else:
            self._send(404, {})


class RawServer:
    """accept 하지 않는 서버(timeout) · 받자마자 RST 로 끊는 서버(reset) ·
    받아 두고 답하지 않는 서버(accept-hold. 대기열 128 을 넘는 연결도 걸어 둔다)."""

    def __init__(self, mode):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.held = []
        self.stopped = False
        if mode == "reset":
            threading.Thread(target=self._reset, daemon=True).start()
        elif mode == "accept-hold":
            threading.Thread(target=self._hold, daemon=True).start()

    def _hold(self):
        while not self.stopped:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.held.append(c)

    def _reset(self):
        while not self.stopped:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.close()

    def stop(self):
        self.stopped = True
        self.sock.close()
        for c in self.held:
            c.close()


class FakeWs:
    """최소 웹소켓 서버. 연결 순서대로 scripts 의 동작을 한다(마지막 것을 되풀이)."""

    def __init__(self, token, scripts):
        self.token, self.scripts = token, scripts
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.origin = "http://127.0.0.1:%d" % self.port
        self.events = []
        self.lock = threading.Lock()
        self.n = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def note(self, *e):
        with self.lock:
            self.events.append(e)

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            mode = self.scripts[min(self.n, len(self.scripts) - 1)]
            self.n += 1
            threading.Thread(target=self._serve, args=(c, mode), daemon=True).start()

    def _frames(self, c, buf):
        """→ (frame 또는 None(EOF), buf)."""
        while True:
            frame, used = probe_ws.decode_frame(buf)
            if frame is not None:
                return frame, buf[used:]
            data = c.recv(65536)
            if not data:
                return None, buf
            buf += data

    def _send(self, c, op, payload=b""):
        c.sendall(probe_ws.encode_frame(op, payload, mask=False))

    def _text(self, c, obj):
        self._send(c, probe_ws.OP_TEXT, json.dumps(obj).encode())

    def _serve(self, c, mode):
        c.settimeout(10)
        try:
            status, headers, rest = self._head(c)
            self.note("handshake", headers.get("origin"), headers.get("cookie"))
            if mode == "403" or headers.get("origin") != self.origin:
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            key = headers["sec-websocket-key"]
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n" % probe_ws.accept_key(key)).encode())
            buf = bytearray(rest)
            if headers.get("cookie") != "%s=%s" % (common.COOKIE_NAME, self.token):
                self._send(c, probe_ws.OP_CLOSE, probe_ws.close_payload(1008))
                frame, buf = self._frames(c, buf)
                self.note("unauth-echo", frame.opcode if frame else None)
                return
            if mode == "close1012":
                self._text(c, {"type": "hello", "data": {"channel": "opsloop_incident", "console": "opsloop-console-a"}})
                self._text(c, {"type": "verdict.created", "data": {"incident_key": "k", "id": 1}})
                self._send(c, probe_ws.OP_PING, b"srv")
                frame, buf = self._frames(c, buf)
                self.note("reply", frame.opcode, frame.payload, frame.masked)
                time.sleep(0.2)
                self._send(c, probe_ws.OP_CLOSE, probe_ws.close_payload(1012, "restart"))
                frame, buf = self._frames(c, buf)
                self.note("close-echo", frame.opcode if frame else None)
                return
            hello = {"type": "hello", "data": {"channel": "opsloop_incident",
                                                "console": "opsloop-console-a" if mode == "zombie" else "opsloop-console-b"}}
            self._text(c, hello)
            while True:
                frame, buf = self._frames(c, buf)
                if frame is None:
                    return
                self.note("frame", mode, frame.opcode, frame.masked)
                if frame.opcode == probe_ws.OP_PING and mode == "stay":
                    self._send(c, probe_ws.OP_PONG, frame.payload)
                elif frame.opcode == probe_ws.OP_CLOSE:
                    self._send(c, probe_ws.OP_CLOSE, frame.payload[:2])
                    return
        except (OSError, probe_ws.ProtocolError):
            return
        finally:
            c.close()

    @staticmethod
    def _head(c):
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = c.recv(4096)
            if not data:
                raise OSError("eof")
            buf += data
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        return lines[0], headers, rest

    def stop(self):
        self.sock.close()


# ──────────────────────────────────────────────────────────────
#  HTTP 프로브
# ──────────────────────────────────────────────────────────────
class ProbeHttpTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.token = make_token()
        self.sb.cookie(self.token)
        self.run_dir = os.path.join(self.sb.root, "runs", "r01-test")

    def tearDown(self):
        self.sb.cleanup()

    def probe(self, url, *extra, timeout=60):
        return self.sb.run([PY, PROBE_HTTP, "--run-dir", self.run_dir, "--url", url, *extra], timeout=timeout)

    def records(self):
        return common.read_jsonl(os.path.join(self.run_dir, "http.jsonl"))

    def test_fields_streams_cookie_origin_console(self):
        srv = FakeConsole(self.token)
        try:
            p = self.probe(srv.url, "--duration", "1", "--interval", "0.05")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        recs = self.records()
        self.assertGreater(len(recs), 20)
        fields = {"run", "stream", "seq", "t_send_ns", "t_recv_ns", "status", "latency_ms", "error", "console"}
        for r in recs:
            self.assertTrue(fields <= set(r), r)
            self.assertEqual(r["run"], "r01-test")
            self.assertEqual(r["status"], 200)
            self.assertIsNone(r["error"])
            self.assertGreaterEqual(r["t_recv_ns"], r["t_send_ns"])
            self.assertGreater(r["latency_ms"], 0)
        me = [r for r in recs if r["stream"] == "me"]
        health = [r for r in recs if r["stream"] == "health"]
        self.assertEqual(len(me), len(health))
        self.assertTrue(all(r["console"] == "opsloop-console-a" for r in me))
        self.assertTrue(all(r["console"] is None for r in health))
        # 발사 간격은 앞 요청을 기다리지 않는다(번호가 이어지고 시각이 간격만큼 벌어진다)
        seqs = sorted(r["seq"] for r in health)
        self.assertEqual(seqs, list(range(len(seqs))))
        paths = [s["path"] for s in srv.seen if s["path"].startswith("/health")]
        self.assertIn("/health?p=r01-test-0", paths)
        for s in srv.seen:
            if s["path"] == "/api/me":
                self.assertEqual(s["origin"], srv.url)
                self.assertEqual(s["cookie"], "%s=%s" % (common.COOKIE_NAME, self.token))
            else:
                self.assertIsNone(s["cookie"])       # health 는 인증 없음
        assert_no_secret(self, self.token, p.stdout, p.stderr, read_text(os.path.join(self.run_dir, "http.jsonl")))

    def test_5xx_and_401(self):
        srv = FakeConsole(make_token(salt=b"other"))       # 서버가 다른 비밀을 쓴다 → 401
        srv.health_status = 503
        try:
            p = self.probe(srv.url, "--duration", "0.5", "--interval", "0.1")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        recs = self.records()
        self.assertTrue(all(r["error"] == "http_5xx" and r["status"] == 503 for r in recs if r["stream"] == "health"))
        self.assertTrue(all(r["error"] == "http_401" and r["console"] is None for r in recs if r["stream"] == "me"))

    def test_connect_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        p = self.probe("http://127.0.0.1:%d" % port, "--duration", "0.3", "--interval", "0.1")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        recs = self.records()
        self.assertTrue(recs)
        self.assertTrue(all(r["error"] == "connect_refused" and r["status"] is None for r in recs), recs[:2])

    def test_timeout(self):
        raw = RawServer("hold")
        try:
            p = self.probe("http://127.0.0.1:%d" % raw.port, "--duration", "0.25", "--interval", "0.1",
                           "--timeout", "0.4", "--streams", "health")
        finally:
            raw.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        recs = self.records()
        self.assertTrue(recs)
        for r in recs:
            self.assertEqual(r["error"], "timeout")
            self.assertGreaterEqual(r["latency_ms"], 350)

    def test_reset(self):
        raw = RawServer("reset")
        try:
            p = self.probe("http://127.0.0.1:%d" % raw.port, "--duration", "0.3", "--interval", "0.1",
                           "--timeout", "3", "--streams", "health")
        finally:
            raw.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        recs = self.records()
        self.assertTrue(recs)
        self.assertTrue(all(r["error"] == "reset" for r in recs), [r["error"] for r in recs])

    def test_rerun_continues_seq(self):
        """같은 회차 폴더에 다시 띄우면 번호를 이어 간다. health 의 p 가 HAProxy 로그에서 겹치지 않는다."""
        srv = FakeConsole(self.token)
        try:
            for _ in range(2):
                p = self.probe(srv.url, "--duration", "0.35", "--interval", "0.1", "--streams", "health")
                self.assertEqual(p.returncode, 0, p.stderr.decode())
        finally:
            srv.stop()
        self.assertIn("이어 감", p.stderr.decode())
        seqs = [r["seq"] for r in self.records()]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(sorted(seqs), list(range(len(seqs))))
        paths = [s["path"] for s in srv.seen]
        self.assertEqual(len(paths), len(set(paths)))

    def _hold(self, ulimit, *extra):
        """받아 두고 답하지 않는 서버에 200 개/초로 2초 쏜다(한도 3초라 400 개쯤이 한꺼번에 걸린다).
        가짜 서버도 연결마다 기술자를 쥐므로 시험 프로세스의 soft 한도를 먼저 올린다."""
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
        if soft != resource.RLIM_INFINITY and soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
        raw = RawServer("accept-hold")
        try:
            p = self.sb.run([BASH, "-c", '%s && exec "$0" "$@"' % ulimit, PY, PROBE_HTTP, "--run-dir", self.run_dir,
                             "--url", "http://127.0.0.1:%d" % raw.port, "--streams", "health",
                             "--interval", "0.005", "--duration", "2", "--timeout", "3", *extra], timeout=60)
        finally:
            raw.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return p, self.records()

    def test_fd_soft_limit_raised(self):
        """macOS 터미널 기본 soft 한도(256)여도 걸린 요청이 300 개를 넘게 쌓일 때 새 요청이 EMFILE 로 실패하지 않는다."""
        import resource
        hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if hard != resource.RLIM_INFINITY and hard < 1024:
            self.skipTest("hard 한도가 낮다 (%d)" % hard)
        p, recs = self._hold("ulimit -S -n 256")
        self.assertGreater(len(recs), 300)
        self.assertEqual({r["error"] for r in recs}, {"timeout"}, {r.get("detail") for r in recs})
        self.assertNotIn("낮춘다", p.stderr.decode())

    def test_fd_hard_limit_lowers_inflight(self):
        """hard 한도가 모자라면 동시 요청 한도를 낮추고 알린다. 넘친 회차는 EMFILE 이 아니라 'in-flight 한도' 로 남는다."""
        p, recs = self._hold("ulimit -n 160")
        err = p.stderr.decode()
        self.assertIn("낮춘다", err)
        self.assertIn("2000 → 96", err)
        details = {r.get("detail") for r in recs}
        self.assertFalse([d for d in details if d and "EMFILE" in d], details)
        self.assertIn("in-flight 한도", details)
        self.assertLessEqual(sum(1 for r in recs if r["error"] == "timeout"), 96)

    def test_cookie_file_checks(self):
        path = self.sb.cookie(self.token, 0o644)
        p = self.probe("http://127.0.0.1:9", "--duration", "0.1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("0600", p.stderr.decode())
        assert_no_secret(self, self.token, p.stdout, p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, "http.jsonl")))
        os.chmod(path, 0o600)
        with open(path, "w") as f:
            f.write("이건 쿠키가 아니다\n")
        p = self.probe("http://127.0.0.1:9", "--duration", "0.1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("꼴", p.stderr.decode())
        old = make_token(exp_offset=-60)
        self.sb.cookie(old)
        p = self.probe("http://127.0.0.1:9", "--duration", "0.1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("만료", p.stderr.decode())
        assert_no_secret(self, old, p.stdout, p.stderr)
        os.remove(path)
        p = self.probe("http://127.0.0.1:9", "--duration", "0.1")
        self.assertEqual(p.returncode, 2)
        self.assertIn("--mint-cookie", p.stderr.decode())

    def test_health_only_needs_no_cookie(self):
        os.remove(os.path.join(self.sb.home, ".config", "opsloop", "probe-cookie"))
        srv = FakeConsole(self.token)
        try:
            p = self.probe(srv.url, "--duration", "0.3", "--interval", "0.1", "--streams", "health")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertTrue(all(r["stream"] == "health" for r in self.records()))

    def test_stops_on_signal_even_if_sigint_ignored(self):
        """백그라운드(&)처럼 SIGINT 가 무시된 채 떠도 Ctrl-C · kill 에 걸린 요청을 기다렸다 끝낸다."""
        srv = FakeConsole(self.token)
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                before = len(self.records())
                proc = subprocess.Popen([PY, PROBE_HTTP, "--run-dir", self.run_dir, "--url", srv.url, "--duration", "0"],
                                        env=self.sb.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
                deadline = time.monotonic() + 10
                while len(self.records()) < before + 4 and time.monotonic() < deadline:
                    time.sleep(0.1)
                proc.send_signal(sig)
                out, err = proc.communicate(timeout=20)
                self.assertEqual(proc.returncode, 130, err.decode())
                self.assertIn("발사를 멈췄다", err.decode())
        finally:
            srv.stop()

    def test_bad_args(self):
        for extra in (["--streams", "health,x"], ["--interval", "0"], ["--max-inflight", "0"]):
            p = self.probe("http://127.0.0.1:9", *extra)
            self.assertEqual(p.returncode, 2, extra)
        p = self.sb.run([PY, PROBE_HTTP])
        self.assertEqual(p.returncode, 2)


# ──────────────────────────────────────────────────────────────
#  웹소켓 프로브
# ──────────────────────────────────────────────────────────────
class ProbeWsTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.token = make_token()
        self.sb.cookie(self.token)
        self.run_dir = os.path.join(self.sb.root, "runs", "r01-ws")

    def tearDown(self):
        self.sb.cleanup()

    def probe(self, srv, *extra, timeout=30):
        return self.sb.run([PY, PROBE_WS, "--run-dir", self.run_dir, "--url", srv.origin, *extra], timeout=timeout)

    def events(self):
        return common.read_jsonl(os.path.join(self.run_dir, "ws.jsonl"))

    def test_browser_reconnect_after_server_close(self):
        srv = FakeWs(self.token, ["close1012", "stay"])
        try:
            p = self.probe(srv, "--mode", "browser", "--duration", "2", "--base-delay", "0.2")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        ev = self.events()
        self.assertEqual([e["event"] for e in ev],
                         ["open", "hello", "message", "close", "reconnect", "open", "hello", "end"])
        self.assertTrue(all(e["stream"] == "ws-browser" and e["conn"] == 0 and e["run"] == "r01-ws" for e in ev))
        self.assertEqual(ev[1]["console"], "opsloop-console-a")
        self.assertEqual(ev[2]["msg_type"], "verdict.created")
        self.assertEqual((ev[3]["code"], ev[3]["by"], ev[3]["was_open"]), (1012, "server", True))
        self.assertEqual((ev[4]["attempt"], ev[4]["delay_ms"]), (1, 200))
        self.assertGreaterEqual(ev[4]["t_ns"] - ev[3]["t_ns"], 190_000_000)
        self.assertEqual(ev[6]["console"], "opsloop-console-b")
        # 서버 핑에 같은 본문의 퐁 · 클라이언트 프레임은 가린다 · 클로즈에 답한다 · browser 는 핑을 보내지 않는다
        self.assertIn(("reply", probe_ws.OP_PONG, b"srv", True), srv.events)
        self.assertIn(("close-echo", probe_ws.OP_CLOSE), srv.events)
        frames = [e for e in srv.events if e[0] == "frame"]
        self.assertTrue(frames)
        self.assertTrue(all(e[3] for e in frames))
        self.assertNotIn(probe_ws.OP_PING, [e[2] for e in frames])
        hs = [e for e in srv.events if e[0] == "handshake"]
        self.assertTrue(all(e[1] == srv.origin and e[2] == "%s=%s" % (common.COOKIE_NAME, self.token) for e in hs))
        assert_no_secret(self, self.token, p.stdout, p.stderr, read_text(os.path.join(self.run_dir, "ws.jsonl")))

    def test_browser_stops_on_1008(self):
        self.sb.cookie(make_token(salt=b"other"))
        srv = FakeWs(self.token, ["stay"])
        t = time.monotonic()
        try:
            p = self.probe(srv, "--mode", "browser", "--duration", "8", "--base-delay", "0.2")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertLess(time.monotonic() - t, 6)
        ev = self.events()
        self.assertEqual([e["event"] for e in ev], ["open", "close", "stopped"])
        self.assertEqual((ev[1]["code"], ev[1]["by"]), (1008, "server"))
        self.assertIn(("unauth-echo", probe_ws.OP_CLOSE), srv.events)

    def test_handshake_rejected_is_1006(self):
        srv = FakeWs(self.token, ["403"])
        try:
            p = self.probe(srv, "--mode", "browser", "--duration", "0.8", "--base-delay", "0.2")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        ev = self.events()
        closes = [e for e in ev if e["event"] == "close"]
        self.assertGreaterEqual(len(closes), 2)
        self.assertTrue(all(e["code"] == 1006 and e["was_open"] is False and e["status"] == 403 for e in closes))
        rec = [e for e in ev if e["event"] == "reconnect"]
        self.assertEqual([e["attempt"] for e in rec][:2], [1, 2])
        self.assertEqual([e["delay_ms"] for e in rec][:2], [200, 400])   # 열리지 않았으니 되돌리지 않는다
        self.assertNotIn("open", [e["event"] for e in ev])

    def test_net_mode_detects_missing_pong(self):
        srv = FakeWs(self.token, ["zombie", "stay"])
        try:
            p = self.probe(srv, "--mode", "net", "--duration", "2.5", "--base-delay", "0.2",
                           "--ping-interval", "0.2", "--pong-timeout", "0.5")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        ev = self.events()
        self.assertEqual([e["event"] for e in ev], ["open", "hello", "close", "reconnect", "open", "hello", "end"])
        self.assertTrue(all(e["stream"] == "ws-net" for e in ev))
        close = ev[2]
        self.assertEqual((close["code"], close["by"], close["reason"]), (1006, "local", "퐁 없음"))
        gap = (close["t_ns"] - ev[1]["t_ns"]) / 1e9
        self.assertGreater(gap, 0.5)
        self.assertLess(gap, 1.6)
        pings = [e for e in srv.events if e[0] == "frame" and e[2] == probe_ws.OP_PING]
        self.assertTrue(pings)

    def test_sigterm_ends_cleanly(self):
        srv = FakeWs(self.token, ["stay"])
        try:
            proc = subprocess.Popen([PY, PROBE_WS, "--run-dir", self.run_dir, "--url", srv.origin, "--duration", "0",
                                     "--conns", "2"], env=self.sb.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 10
            while sum(e["event"] == "hello" for e in self.events()) < 2 and time.monotonic() < deadline:
                time.sleep(0.1)
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=20)
        finally:
            srv.stop()
        self.assertEqual(proc.returncode, 130, err.decode())
        ends = [e for e in self.events() if e["event"] == "end"]
        self.assertEqual(sorted(e["conn"] for e in ends), [0, 1])

    def test_conns_and_cookie_required(self):
        os.remove(os.path.join(self.sb.home, ".config", "opsloop", "probe-cookie"))
        srv = FakeWs(self.token, ["stay"])
        try:
            p = self.probe(srv, "--duration", "0.5")
            self.assertEqual(p.returncode, 2)
            self.sb.cookie(self.token)
            p = self.probe(srv, "--duration", "0.8", "--conns", "3")
        finally:
            srv.stop()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        hellos = [e for e in self.events() if e["event"] == "hello"]
        self.assertEqual(sorted(e["conn"] for e in hellos), [0, 1, 2])


# ──────────────────────────────────────────────────────────────
#  쿠키 발급 · 삭제
# ──────────────────────────────────────────────────────────────
class MintCookieTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.token = make_token()
        self.path = os.path.join(self.sb.home, ".config", "opsloop", "probe-cookie")

    def tearDown(self):
        self.sb.cleanup()

    def test_mint_writes_0600_and_never_prints(self):
        for tool in (PROBE_HTTP, PROBE_WS):
            p = self.sb.run([PY, tool, "--mint-cookie", "console-a"], FAKE_SSH_MODE="mint", FAKE_TOKEN=self.token)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            assert_no_secret(self, self.token, p.stdout, p.stderr)
            self.assertIn("0600", p.stderr.decode())
            self.assertEqual(read_text(self.path).strip(), self.token)
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)
        call = self.sb.ssh_calls()[-1]
        self.assertEqual(call["alias"], "console-a")
        self.assertIn(os.path.join(self.sb.home, ".ssh", "config.opsloop"), call["opts"])
        self.assertIn("BatchMode=yes", call["opts"])
        self.assertIn("docker exec opsloop-api python3 -c", call["cmd"])
        self.assertIn('auth.issue("failover-probe", "viewer")', call["cmd"])
        self.assertEqual(common.load_cookie(self.path), self.token)
        p = self.sb.run([PY, PROBE_HTTP, "--drop-cookie"])
        self.assertEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.path))

    def test_mint_failure_masks(self):
        p = self.sb.run([PY, PROBE_HTTP, "--mint-cookie", "console-b"], FAKE_SSH_MODE="mint-fail", FAKE_TOKEN=self.token)
        self.assertEqual(p.returncode, 2)
        self.assertIn("***", p.stderr.decode())
        assert_no_secret(self, self.token, p.stdout, p.stderr)
        self.assertFalse(os.path.exists(self.path))
        p = self.sb.run([PY, PROBE_HTTP, "--mint-cookie", "console-a"], FAKE_SSH_MODE="mint", FAKE_TOKEN="not-a-cookie")
        self.assertEqual(p.returncode, 2)
        self.assertFalse(os.path.exists(self.path))
        p = self.sb.run([PY, PROBE_HTTP, "--mint-cookie", "a;rm -rf /"])
        self.assertEqual(p.returncode, 2)
        self.assertEqual(len(self.sb.ssh_calls()), 2)


# ──────────────────────────────────────────────────────────────
#  주입 시각 표시
# ──────────────────────────────────────────────────────────────
class MarkTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.run_dir = os.path.join(self.sb.root, "runs", "r01-mark")

    def tearDown(self):
        self.sb.cleanup()

    def marks(self):
        return common.read_jsonl(os.path.join(self.run_dir, "marks.jsonl"))

    def test_remote_and_local(self):
        p = self.sb.run([PY, MARK, self.run_dir, "inject", "--scenario", "stop", "--target", "console-a"],
                        FAKE_SSH_MODE="date", FAKE_REMOTE_DATE="1790000000.123456789")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn("docker stop opsloop-api", p.stderr.decode())
        self.assertIn("console-a", p.stderr.decode())
        m = self.marks()[-1]
        self.assertEqual((m["kind"], m["scenario"], m["target"], m["host"], m["run"]),
                         ("inject", "stop", "console-a", "console-a", "r01-mark"))
        self.assertEqual(m["t_remote_ns"], 1790000000123456789)
        self.assertGreaterEqual(m["t_local_ns"], m["t_local_before_ns"])
        self.assertIsNotNone(m["offset_ms"])
        self.assertEqual(self.sb.ssh_calls()[-1]["cmd"], "date +%s.%N")
        # VM 끔은 Mac 에서 돌리므로 원격을 부르지 않는다
        n = len(self.sb.ssh_calls())
        p = self.sb.run([PY, MARK, self.run_dir, "recover", "--scenario", "vm-off", "--target", "console-b"])
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn("opsloop-console-b.vmx", p.stderr.decode())
        m = self.marks()[-1]
        self.assertEqual((m["host"], m["t_remote_ns"]), ("local", m["t_local_before_ns"]))
        self.assertEqual(len(self.sb.ssh_calls()), n)
        # 메모는 시나리오 · 대상 없이 남는다
        p = self.sb.run([PY, MARK, self.run_dir, "note", "--text", "메모"], FAKE_SSH_MODE="date")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual((self.marks()[-1]["kind"], self.marks()[-1]["note"]), ("note", "메모"))

    def test_ssh_failure_keeps_local(self):
        p = self.sb.run([PY, MARK, self.run_dir, "inject", "--scenario", "kill", "--target", "console-a"],
                        FAKE_SSH_MODE="fail")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        m = self.marks()[-1]
        self.assertIsNone(m["t_remote_ns"])
        self.assertIn("255", m["error"])
        self.assertIn("경고", p.stderr.decode())

    def test_args(self):
        bad = [["inject", "--scenario", "nope", "--target", "console-a"],
               ["inject", "--scenario", "stop"],
               ["inject", "--scenario", "stop", "--target", "fw"],
               ["note"],
               ["inject", "--scenario", "stop", "--target", "console-a", "--host", "a;b"]]
        for extra in bad:
            p = self.sb.run([PY, MARK, self.run_dir] + extra)
            self.assertEqual(p.returncode, 2, extra)
        p = self.sb.run([PY, MARK, "--list"])
        self.assertEqual(p.returncode, 0)
        out = p.stdout.decode()
        for name in ("stop", "kill", "vm-off", "net-cut", "db-cut", "drain", "docker kill opsloop-api", "hard"):
            self.assertIn(name, out)

    def test_parse_remote_date(self):
        import mark
        self.assertEqual(mark.parse_remote_date("1790000000.5\n"), 1790000000500000000)
        self.assertIsNone(mark.parse_remote_date("1790000000.N"))       # macOS date 는 %N 을 모른다
        self.assertIsNone(mark.parse_remote_date(""))


# ──────────────────────────────────────────────────────────────
#  방화벽 수집
# ──────────────────────────────────────────────────────────────
HEADER = ("pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,"
          "act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,"
          "rate_max,check_status,check_code,check_duration,hrsp_1xx").split(",")


def stats_csv(a_status, a_check="L7OK", a_fail=0):
    def row(**kv):
        vals = {k: "" for k in HEADER}
        vals.update({k: str(v) for k, v in kv.items()})
        return ",".join(vals[k] for k in HEADER)
    lines = ["# " + ",".join(HEADER),
             row(pxname="console", svname="FRONTEND", status="OPEN", scur=3),
             row(pxname="consoles", svname="console-a", status=a_status, bck=0, chkfail=a_fail, chkdown=a_fail,
                 lastchg=12, check_status=a_check, check_duration=1, scur=2),
             row(pxname="consoles", svname="console-b", status="UP", bck=0, chkfail=0, chkdown=0, lastchg=99,
                 check_status="L7OK", check_duration=2, scur=1),
             row(pxname="consoles", svname="BACKEND", status="UP", bck=0, chkdown=0, lastchg=99, scur=3),
             row(pxname="stats", svname="FRONTEND", status="OPEN")]
    return "\n".join(lines) + "\n"


class CollectFwTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.run_dir = os.path.join(self.sb.root, "runs", "r01-fw")
        self.csv = os.path.join(self.sb.root, "stats.csv")
        self.log = os.path.join(self.sb.root, "haproxy.log")

    def tearDown(self):
        self.sb.cleanup()

    def put(self, text):
        tmp = self.csv + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, self.csv)

    def test_syntax(self):
        p = subprocess.run([BASH, "-n", COLLECT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        with open(COLLECT) as f:
            body = f.read()
        remote = body.split("<<'EOF_REMOTE' || true\n", 1)[1].split("\nEOF_REMOTE\n", 1)[0]
        p = subprocess.run([BASH, "-n"], input=remote.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 0, p.stderr.decode())

    def rows(self):
        try:
            with open(os.path.join(self.run_dir, "fw.csv")) as f:
                return list(csv_mod.DictReader(f))
        except FileNotFoundError:
            return []

    def wait_for(self, pred, what, limit=20):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            if pred(self.rows()):
                return
            time.sleep(0.1)
        self.fail("기다렸지만 없다: %s" % what)

    def test_collect_and_excerpt(self):
        """Ctrl-C(프로세스 묶음에 SIGINT)로 멈춰도 fw.csv · 메타 · 로그 발췌가 남는다."""
        self.put(stats_csv("UP"))
        with open(self.log, "w") as f:
            f.write("old line before test\n")
        proc = subprocess.Popen([BASH, COLLECT, self.run_dir, "--duration", "0", "--period", "0.2", "--log", self.log],
                                env=self.sb.env(FAKE_CSV=self.csv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            self.wait_for(lambda rs: sum(r["svname"] == "console-a" for r in rs) >= 2, "UP 두 번")
            self.put(stats_csv("DOWN", "L4CON", 3))
            with open(self.log, "a") as f:
                f.write("Server consoles/console-a is DOWN\n")
            self.wait_for(lambda rs: any(r["status"] == "DOWN" for r in rs), "DOWN")
            os.remove(self.csv)                            # 통계를 못 읽는 회차
            self.wait_for(lambda rs: any(r["status"] == "stats_error" for r in rs), "stats_error")
            self.put(stats_csv("DOWN", "L4CON", 3))
            n = len(self.rows())
            self.wait_for(lambda rs: len(rs) > n, "다시 읽힘")
        finally:
            os.killpg(proc.pid, signal.SIGINT)
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err.decode())
        rows = self.rows()
        self.assertEqual(list(rows[0].keys()), ["t_local", "t_fw", "svname", "status", "bck", "chkfail", "chkdown",
                                                "lastchg", "check_status", "check_duration", "scur"])
        self.assertEqual({r["svname"] for r in rows}, {"console-a", "console-b", "BACKEND", "-"})
        a = [r for r in rows if r["svname"] == "console-a"]
        self.assertEqual(a[0]["status"], "UP")
        self.assertEqual(a[-1]["status"], "DOWN")
        self.assertEqual((a[-1]["check_status"], a[-1]["chkfail"], a[-1]["lastchg"], a[-1]["scur"]),
                         ("L4CON", "3", "12", "2"))
        for r in rows:
            self.assertLess(abs(float(r["t_local"]) - float(r["t_fw"])), 2.0)
        with open(os.path.join(self.run_dir, "fw-meta.json")) as f:
            meta = json.load(f)
        self.assertEqual(meta["log_offset"], len("old line before test\n"))
        self.assertIsNotNone(meta["clock_offset_ms"])
        self.assertIsNotNone(meta["t_local_end"])
        self.assertEqual(read_text(os.path.join(self.run_dir, "fw-haproxy.log")), "Server consoles/console-a is DOWN\n")
        self.assertIn("console-a → DOWN", err.decode())
        calls = self.sb.ssh_calls()
        self.assertEqual([c["alias"] for c in calls], ["fw", "fw"])
        self.assertTrue(calls[0]["cmd"].startswith("bash -s -- "))
        self.assertIn("ServerAliveInterval=5", calls[0]["opts"])
        # summarize 가 이 파일을 읽는다
        fw, offset = summarize.read_fw(os.path.join(self.run_dir, "fw.csv"))
        self.assertTrue(fw)
        self.assertIsNotNone(offset)

    def test_rotated_log(self):
        self.put(stats_csv("UP"))
        with open(self.log, "w") as f:
            f.write("x" * 1000 + "\n")
        proc = subprocess.Popen([BASH, COLLECT, self.run_dir, "--duration", "1", "--period", "0.3", "--log", self.log],
                                env=self.sb.env(FAKE_CSV=self.csv), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        with open(self.log, "w") as f:
            f.write("new file\n")
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err.decode())
        text = read_text(os.path.join(self.run_dir, "fw-haproxy.log"))
        self.assertIn("돌려졌다", text)
        self.assertIn("new file", text)

    def test_rotated_log_keeps_tail_of_old_file(self):
        # 자정 logrotate: 옛 파일은 .1 로 옮겨지고(같은 내용 · 시험 중 붙은 줄 포함) 새 파일이 생긴다
        self.put(stats_csv("UP"))
        with open(self.log, "w") as f:
            f.write("old line before test\n")
        proc = subprocess.Popen([BASH, COLLECT, self.run_dir, "--duration", "1", "--period", "0.3", "--log", self.log],
                                env=self.sb.env(FAKE_CSV=self.csv), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        with open(self.log, "a") as f:
            f.write("before midnight GET /health?p=r1-1\n")
        os.rename(self.log, self.log + ".1")
        with open(self.log, "w") as f:
            f.write("after midnight GET /health?p=r1-2\n")
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err.decode())
        text = read_text(os.path.join(self.run_dir, "fw-haproxy.log"))
        self.assertIn("옛 파일(.1)의 뒷부분", text)
        self.assertIn("before midnight GET /health?p=r1-1", text)
        self.assertIn("after midnight GET /health?p=r1-2", text)
        self.assertNotIn("old line before test", text)

    def test_unreadable_log(self):
        """로그를 읽을 수 없으면(권한 없음 · sudo 거절) 경고와 종료 1. fw.csv 는 남는다."""
        self.put(stats_csv("UP"))
        with open(self.log, "w") as f:
            f.write("x\n")
        os.chmod(self.log, 0)
        try:
            p = self.sb.run([BASH, COLLECT, self.run_dir, "--duration", "0.8", "--period", "0.2", "--log", self.log],
                            FAKE_CSV=self.csv)
        finally:
            os.chmod(self.log, 0o600)
        self.assertEqual(p.returncode, 1, p.stderr.decode())
        self.assertIn("읽지 못했다", p.stderr.decode())
        self.assertTrue(os.path.getsize(os.path.join(self.run_dir, "fw.csv")) > 0)
        self.assertFalse(os.path.exists(os.path.join(self.run_dir, "fw-haproxy.log")))

    def test_ssh_failure_and_args(self):
        p = self.sb.run([BASH, COLLECT, self.run_dir, "--duration", "1"], FAKE_SSH_MODE="fail")
        self.assertEqual(p.returncode, 2)
        self.assertIn("수집 실패", p.stderr.decode())
        for extra in (["--period", "0"], ["--log", "relative.log"], ["--host", "fw;id"], ["--nope"]):
            p = self.sb.run([BASH, COLLECT, self.run_dir] + extra)
            self.assertEqual(p.returncode, 2, extra)
        p = self.sb.run([BASH, COLLECT, "--help"])
        self.assertEqual(p.returncode, 0)
        self.assertIn("fw.csv", p.stdout.decode())


class SyntaxTest(unittest.TestCase):
    def test_python_39_grammar(self):
        import ast
        for name in ("common.py", "probe_http.py", "probe_ws.py", "mark.py", "summarize.py", "test_failover_tools.py"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                ast.parse(f.read(), name, feature_version=(3, 9))

    def test_stdlib_only(self):
        import ast
        allowed = set(sys.stdlib_module_names) | {"common", "mark", "probe_ws", "summarize"} \
            if hasattr(sys, "stdlib_module_names") else None
        if allowed is None:
            self.skipTest("파이썬 3.10 부터")
        for name in ("common.py", "probe_http.py", "probe_ws.py", "mark.py", "summarize.py"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods = [node.module.split(".")[0]]
                for m in mods:
                    self.assertIn(m, allowed, "%s: %s" % (name, m))


if __name__ == "__main__":
    unittest.main(verbosity=2)
