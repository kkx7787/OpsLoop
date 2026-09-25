#!/usr/bin/env python3
"""콘솔 진입점 감시(console-watch.sh) · launchd 설치기 시험 (이슈 #43).  python3 infra/vmware/scripts/test_console_watch.py

원격 없이 Mac 에서 돈다. HOME 은 임시 폴더이고 curl · osascript · launchctl · sleep 은 가짜로 바꾼다
(PATH 앞 가짜 실행기. curl · osascript · launchctl 은 bash 내보낸 함수로도 덮어 진짜가 불리지 않게 한다).
  - 상태 전이   UP 은 알리지 않음 · UP→DOWN 알림 한 번 · 계속 DOWN 은 30분 전 재알림 없음 · 30분 지나면 재알림 ·
                복구 알림 한 번 · 처음부터 DOWN 이면 알림 · 한 번이라도 200 이면 UP · 실패 사유(503 · 시간 초과 · 연결 실패)
  - 검사 모양   기본 주소 http://192.168.70.254:8443/health · curl -m 3 · 프록시 · .curlrc 안 탐 · 5초 간격 3번
  - 점검 창     창 안에서는 알리지 않고 상태만 · 창이 끝나면 이어진 DOWN 을 알림 · 창 안 복구는 창 뒤에 알림 ·
                읽지 못하는 파일은 무시하고 알림 · 창 안에서는 웹훅도 없음 · --pause · --resume ·
                DOWN 을 알린 뒤 창 안에서 복구 · 다시 DOWN 이면 이어진 DOWN (미룬 복구 알림을 잃지 않음)
  - 웹훅        0600 파일의 주소로 {"text": ...} POST (curl -m 10 · https 만 · 주소는 표준 입력 설정) ·
                0600 이 아니면 거부 · https 가 아니거나 이상한 주소는 거부 · 따옴표 · export 꼴 ·
                주소가 기록 · 화면 · 명령줄 · 상태 파일 · 알림 문구 어디에도 남지 않음 · 실패도 주소 없이 기록
  - 잠금        동시에 돈 두 회차는 한 번만 알림 · 살아 있는 잠금이면 건너뜀 · 죽은 pid · 5분 넘은 잠금은 치움
  - 기타        알림 문구는 osascript 인자로 · osascript 실패 · --status · --test-alert · 잘못된 환경변수 · 모르는 옵션 ·
                기록 돌리기 · 깨진 상태 파일
  - 진짜 curl   127.0.0.1 에 띄운 서버로 200 · 503 · 연결 거부를 가르고, 웹훅은 자체 서명 https 서버가
                주소(경로 · 쿼리)와 JSON 본문을 그대로 받는지 본다 (openssl 이 없으면 웹훅은 건너뛴다)
  - 셸 문법     bash -n (/bin/bash 3.2 포함) · shellcheck(있으면)
  - launchd     plist(60초 · 올릴 때 한 번 · 기록 파일 · 사본 경로) · 사본 · 다시 설치해도 같음 · 웹훅 권한 안내 ·
                --uninstall · --remove · 모르는 옵션 · 사본이 저장소 없이 돈다
"""
import http.server
import json
import os
import plistlib
import shutil
import stat
import subprocess
import ssl
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WATCH = os.path.join(HERE, "console-watch.sh")
INSTALL = os.path.join(HERE, "install-console-watch.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
LABEL = "local.opsloop.console-watch"
DEFAULT_URL = "http://192.168.70.254:8443/health"
HOOK = "https://hooks.example.test/workflows/abc123/triggers/manual?sig=SeCrEtSiG0123456789"
SECRET = "SeCrEtSiG0123456789"
OSA_HEAD = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run"]

# 헬스 검사는 FAKE_CURL_SEQ 파일에서 한 줄씩 꺼내고, 비면 FAKE_CURL_MODE. 숫자는 그 HTTP 코드로 답한다.
# 웹훅(-K -)은 표준 입력(curl 설정)까지 적는다
FAKE_CURL = r'''#!{python}
import json, os, sys
args = sys.argv[1:]
stdin = sys.stdin.read() if "-K" in args else ""
with open(os.environ["FAKE_CURL_LOG"], "a") as f:
    f.write(json.dumps({{"args": args, "stdin": stdin}}) + "\n")
if "-K" in args:
    rc = int(os.environ.get("FAKE_HOOK_RC", "0"))
    sys.stdout.write(os.environ.get("FAKE_HOOK_CODE", "202") if rc == 0 else "000")
    sys.exit(rc)
mode = os.environ.get("FAKE_CURL_MODE", "200")
seq = os.environ.get("FAKE_CURL_SEQ", "")
if seq and os.path.exists(seq):
    with open(seq) as f:
        items = f.read().split()
    if items:
        mode = items[0]
        with open(seq, "w") as f:
            f.write("\n".join(items[1:]))
if mode.isdigit():
    sys.stdout.write(mode)
    sys.exit(0)
sys.stdout.write("000")
sys.exit({{"refused": 7, "timeout": 28, "reset": 56, "empty": 52, "dns": 6}}[mode])
'''

FAKE_OSA = r'''#!{python}
import json, os, sys
with open(os.environ["FAKE_OSA_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
sys.exit(int(os.environ.get("FAKE_OSA_RC", "0")))
'''


def write_exec(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def jsonl(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.home = os.path.join(self.t, "home")
        self.fake = os.path.join(self.t, "fakebin")
        os.makedirs(self.home)
        os.makedirs(self.fake)
        self.curl_log = os.path.join(self.t, "curl.jsonl")
        self.osa_log = os.path.join(self.t, "osascript.jsonl")
        self.lc_log = os.path.join(self.t, "launchctl.log")
        self.sleep_log = os.path.join(self.t, "sleep.log")
        self.seq = os.path.join(self.t, "curl.seq")
        for p in (self.curl_log, self.osa_log, self.lc_log, self.sleep_log):
            open(p, "w").close()
        write_exec(os.path.join(self.fake, "curl"), FAKE_CURL.format(python=sys.executable))
        write_exec(os.path.join(self.fake, "osascript"), FAKE_OSA.format(python=sys.executable))
        write_exec(os.path.join(self.fake, "launchctl"), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_LC_LOG"\n')
        write_exec(os.path.join(self.fake, "sleep"), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_SLEEP_LOG"\n')
        # 진짜 curl · osascript · launchctl 이 불리지 않게 PATH 에 더해 bash 내보낸 함수로도 덮는다
        self.env = {"HOME": self.home, "PATH": self.fake + ":/usr/bin:/bin", "TMPDIR": self.t, "LANG": "en_US.UTF-8",
                    "FAKE_BIN": self.fake, "FAKE_CURL_LOG": self.curl_log, "FAKE_OSA_LOG": self.osa_log,
                    "FAKE_LC_LOG": self.lc_log, "FAKE_SLEEP_LOG": self.sleep_log, "FAKE_CURL_SEQ": self.seq,
                    "BASH_FUNC_curl%%": '() {  "$FAKE_BIN/curl" "$@"; }',
                    "BASH_FUNC_osascript%%": '() {  "$FAKE_BIN/osascript" "$@"; }',
                    "BASH_FUNC_launchctl%%": '() {  "$FAKE_BIN/launchctl" "$@"; }'}
        self.conf = os.path.join(self.home, ".config", "opsloop")
        self.env_file = os.path.join(self.conf, "console-watch.env")
        self.pause_file = os.path.join(self.conf, "console-watch.pause")
        self.log = os.path.join(self.home, "Library", "Logs", "opsloop", "console-watch.log")
        self.state = os.path.join(self.home, "Library", "Application Support", "OpsLoop", "console-watch.state")

    def run_watch(self, *args, script=WATCH, mode=None, seq=None, **extra):
        env = dict(self.env, **extra)
        if mode is not None:
            env["FAKE_CURL_MODE"] = mode
        if seq is not None:
            with open(self.seq, "w") as f:
                f.write("\n".join(seq))
        return subprocess.run([BASH, script, *args], env=env, capture_output=True, text=True, encoding="utf-8",
                              stdin=subprocess.DEVNULL, timeout=60)

    def ok(self, *args, **kw):
        r = self.run_watch(*args, **kw)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stderr, "", "launchd 에서는 표준 오류도 기록 파일로 간다")
        return r

    def osa(self):
        return jsonl(self.osa_log)

    def titles(self):
        return [a[len(OSA_HEAD)] for a in self.osa()]

    def curls(self):
        return jsonl(self.curl_log)

    def health_calls(self):
        return [c for c in self.curls() if "-K" not in c["args"]]

    def hook_calls(self):
        return [c for c in self.curls() if "-K" in c["args"]]

    def read_state(self):
        return dict(line.split("=", 1) for line in read(self.state).splitlines())

    def set_state(self, **kv):
        s = self.read_state()
        s.update({k: str(v) for k, v in kv.items()})
        with open(self.state, "w") as f:
            f.write("".join("%s=%s\n" % kv for kv in s.items()))

    def write_env(self, body, mode=0o600):
        os.makedirs(self.conf, exist_ok=True)
        if os.path.exists(self.env_file):
            os.remove(self.env_file)
        with open(self.env_file, "w") as f:
            f.write(body)
        os.chmod(self.env_file, mode)

    def write_pause(self, value):
        os.makedirs(self.conf, exist_ok=True)
        with open(self.pause_file, "w") as f:
            f.write(str(value) + "\n")


class TransitionTest(Base):
    def test_UP_은_알리지_않고_상태만_적는다(self):
        self.ok(mode="200")
        self.assertEqual(self.osa(), [])
        self.assertEqual(self.read_state()["state"], "UP")
        self.assertEqual(self.read_state()["alerted"], "0")
        self.assertIn("UP · HTTP 200", read(self.log))
        self.assertEqual(len(self.health_calls()), 1)
        self.ok(mode="200")
        self.assertEqual(self.osa(), [])

    def test_검사_모양_기본_주소_시간_한도_프록시_안_탐_5초_간격_3번(self):
        self.ok(mode="refused")
        calls = self.health_calls()
        self.assertEqual(len(calls), 3)
        for c in calls:
            a = c["args"]
            self.assertEqual(a[0], "-q", ".curlrc 를 읽지 않는다")
            self.assertEqual(a[-1], DEFAULT_URL)
            self.assertEqual(a[a.index("-m") + 1], "3")
            self.assertEqual(a[a.index("--noproxy") + 1], "*")
            self.assertNotIn("-L", a)
        self.assertEqual(read(self.sleep_log).split(), ["5", "5"], "시도 사이에만 5초 쉰다")

    def test_UP_에서_DOWN_은_한_번_알리고_30분_전에는_다시_알리지_않는다(self):
        self.ok(mode="200")
        self.ok(mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
        body = self.osa()[0][-1]
        self.assertIn("진입점 /health 3번 모두 실패 (연결 실패)", body)
        self.assertIn("부터", body)
        self.assertNotIn("192.168", body, "알림 문구에 내부 주소를 넣지 않는다")
        st = self.read_state()
        self.assertEqual((st["state"], st["alerted"]), ("DOWN", "1"))
        self.assertIn("DOWN · 3번 모두 실패 (연결 실패 · 연결 실패 · 연결 실패)", read(self.log))

        self.ok(mode="refused")
        self.assertEqual(len(self.osa()), 1, "DOWN 이 이어져도 바로 다시 알리지 않는다")
        self.assertIn("DOWN 이어짐", read(self.log))

        now = int(time.time())
        self.set_state(last_alert=now - 1790)
        self.ok(mode="refused")
        self.assertEqual(len(self.osa()), 1, "30분이 안 지났다")

        self.set_state(last_alert=now - 1810, since=now - 2400)
        self.ok(mode="503")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 계속 DOWN"])
        self.assertIn("40분째 (HTTP 503)", self.osa()[1][-1])
        self.ok(mode="503")
        self.assertEqual(len(self.osa()), 2, "다시 알린 시각부터 30분을 센다")

    def test_복구는_한_번_알린다(self):
        self.ok(mode="200")
        self.ok(mode="refused")
        now = int(time.time())
        self.set_state(since=now - 300, down_since=now - 300)
        self.ok(mode="200")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 복구"])
        self.assertIn("DOWN 5분 뒤 복구", self.osa()[1][-1])
        self.assertIn("UP · 복구 (DOWN 5분)", read(self.log))
        st = self.read_state()
        self.assertEqual((st["state"], st["alerted"]), ("UP", "0"))
        self.ok(mode="200")
        self.assertEqual(len(self.osa()), 2)

    def test_처음부터_DOWN_이면_알린다(self):
        self.ok(mode="503")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
        self.assertIn("(HTTP 503)", self.osa()[0][-1])

    def test_한_번이라도_200_이면_UP(self):
        self.ok(seq=["refused", "200"])
        self.assertEqual(len(self.health_calls()), 2, "성공하면 더 보지 않는다")
        self.assertEqual(self.osa(), [])
        self.assertEqual(self.read_state()["state"], "UP")
        self.assertIn("HTTP 200 · 2번째 (앞선 실패: 연결 실패)", read(self.log))

    def test_실패_사유는_시도마다_적고_알림에는_마지막_사유(self):
        self.ok(seq=["timeout", "503", "reset"])
        self.assertIn("3번 모두 실패 (시간 초과 · HTTP 503 · 수신 끊김)", read(self.log))
        self.assertIn("(수신 끊김)", self.osa()[0][-1])

    def test_200_이_아닌_2xx_도_DOWN(self):
        self.ok(mode="204")
        self.assertEqual(self.read_state()["state"], "DOWN")

    def test_시도_횟수는_환경변수로_바꿀_수_있다(self):
        self.ok(mode="refused", CONSOLE_WATCH_TRIES="1")
        self.assertEqual(len(self.health_calls()), 1)
        self.assertEqual(read(self.sleep_log), "")
        self.assertIn("1번 모두 실패", self.osa()[0][-1])

    def test_알림_문구는_osascript_인자로_넘긴다(self):
        self.ok(mode="refused")
        a = self.osa()[0]
        self.assertEqual(a[:len(OSA_HEAD)], OSA_HEAD)
        self.assertEqual(len(a), len(OSA_HEAD) + 2)

    def test_osascript_가_실패해도_상태는_남는다(self):
        self.ok(mode="refused", FAKE_OSA_RC="1")
        self.assertIn("macOS 알림 실패", read(self.log))
        self.assertEqual(self.read_state()["alerted"], "1")

    def test_깨진_상태_파일은_처음처럼_본다(self):
        os.makedirs(os.path.dirname(self.state))
        with open(self.state, "w") as f:
            f.write("state=MAYBE\nsince=$(touch %s/pwned)\nalerted=7\nlast_alert=abc\n쓰레기\n" % self.t)
        self.ok(mode="200")
        self.assertFalse(os.path.exists(os.path.join(self.t, "pwned")))
        st = self.read_state()
        self.assertEqual((st["state"], st["alerted"]), ("UP", "0"))
        self.assertTrue(st["since"].isdigit())
        self.assertEqual(self.osa(), [])

    def test_상태_파일과_기록은_본인만_읽는다(self):
        self.ok(mode="200")
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.log).st_mode & 0o777, 0o600)

    def test_기록은_1MiB_를_넘으면_한_벌_돌린다(self):
        os.makedirs(os.path.dirname(self.log))
        with open(self.log, "w") as f:
            f.write("x" * (1024 * 1024 + 10))
        self.ok(mode="200")
        self.assertEqual(os.path.getsize(self.log + ".1"), 1024 * 1024 + 10)
        self.assertIn("UP", read(self.log))
        self.assertLess(os.path.getsize(self.log), 1000)


class PauseTest(Base):
    def test_점검_창에서는_상태만_적고_끝나면_알린다(self):
        self.ok(mode="200")
        now = int(time.time())
        self.write_pause(now + 600)
        self.ok(mode="refused")
        self.assertEqual(self.osa(), [])
        self.assertEqual((self.read_state()["state"], self.read_state()["alerted"]), ("DOWN", "0"))
        self.assertIn("점검 창", read(self.log))
        self.assertIn("알리지 않는다", read(self.log))

        self.write_pause(now - 1)
        self.ok(mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"], "창이 끝났는데 DOWN 이 이어지면 알린다")

        self.write_pause(now + 600)
        self.ok(mode="200")
        self.assertEqual(len(self.osa()), 1)
        self.assertIn("복구 알림은 창이 끝난 뒤에", read(self.log))
        self.assertEqual((self.read_state()["state"], self.read_state()["alerted"]), ("UP", "1"))

        os.remove(self.pause_file)
        self.ok(mode="200")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 복구"])
        self.ok(mode="200")
        self.assertEqual(len(self.osa()), 2)

    def test_창_안에서_시작하고_끝난_DOWN_은_알리지_않는다(self):
        self.write_pause(int(time.time()) + 600)
        self.ok(mode="refused")
        self.ok(mode="200")
        os.remove(self.pause_file)
        self.ok(mode="200")
        self.assertEqual(self.osa(), [])

    def test_복구를_알리기_전에_다시_DOWN_이면_이어진_DOWN_으로_본다(self):
        # DOWN 을 알린 뒤 창 안에서 복구 · 다시 DOWN · 다시 복구. 미뤄 둔 복구 알림이 사라지면 DOWN 알림만 남는다
        self.ok(mode="200")
        self.ok(mode="refused")
        first = self.read_state()
        self.write_pause(int(time.time()) + 600)
        self.ok(mode="200")
        self.ok(mode="refused")
        st = self.read_state()
        self.assertEqual((st["state"], st["alerted"]), ("DOWN", "1"))
        self.assertEqual((st["since"], st["down_since"]), (first["down_since"], first["down_since"]),
                         "처음 DOWN 부터 이어서 센다")
        self.assertIn("복구를 알리기 전에 다시 DOWN", read(self.log))
        self.ok(mode="200")
        os.remove(self.pause_file)
        self.ok(mode="200")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 복구"])
        self.assertEqual(self.read_state()["alerted"], "0")
        self.ok(mode="200")
        self.assertEqual(len(self.osa()), 2)

    def test_복구를_알리기_전에_다시_DOWN_이_창_뒤에도_이어지면_30분마다_다시_알린다(self):
        self.ok(mode="200")
        self.ok(mode="refused")
        now = int(time.time())
        self.write_pause(now + 600)
        self.ok(mode="200")
        self.ok(mode="refused")
        os.remove(self.pause_file)
        self.ok(mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"], "새 DOWN 으로 다시 알리지 않는다 (30분 전)")
        self.set_state(last_alert=now - 1810, since=now - 2400, down_since=now - 2400)
        self.ok(mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 계속 DOWN"])
        self.assertIn("40분째", self.osa()[1][-1])

    def test_읽지_못하는_점검_창_파일은_무시하고_알린다(self):
        for bad in ("내일", "", "1" * 20):
            with self.subTest(bad=bad):
                for p in (self.state, self.osa_log):
                    if os.path.exists(p):
                        os.remove(p)
                self.write_pause(bad)
                self.ok(mode="refused")
                self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
                if bad:
                    self.assertIn("점검 창 파일을 읽지 못했다", read(self.log))

    def test_점검_창에서는_웹훅도_보내지_않는다(self):
        self.write_env("WEBHOOK_URL=%s\n" % HOOK)
        self.write_pause(int(time.time()) + 600)
        self.ok(mode="refused")
        self.assertEqual(self.hook_calls(), [])
        self.assertEqual(self.osa(), [])

    def test_pause_resume_옵션(self):
        before = int(time.time())
        r = self.ok("--pause", "30")
        until = int(read(self.pause_file).strip())
        self.assertTrue(before + 1800 <= until <= int(time.time()) + 1800, until)
        self.assertEqual(os.stat(self.pause_file).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.conf).st_mode & 0o777, 0o700)
        self.assertIn("점검 창:", r.stdout)
        self.assertIn("점검 창 둠", read(self.log))
        self.ok(mode="refused")
        self.assertEqual(self.osa(), [])
        self.ok("--resume")
        self.assertFalse(os.path.exists(self.pause_file))
        self.ok(mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
        for bad in (["--pause"], ["--pause", "0"], ["--pause", "abc"], ["--pause", "10081"], ["--pause", "-5"]):
            with self.subTest(args=bad):
                r = self.run_watch(*bad)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("1 ~ 10080", r.stderr)


class LockTest(Base):
    """한 번에 한 회차만. launchd 회차와 손으로 돌린 회차가 겹쳐도 한 번만 알린다."""

    def lock(self):
        return os.path.join(os.path.dirname(self.state), "console-watch.lock")

    def put_lock(self, pid, age=0):
        os.makedirs(os.path.dirname(self.state), exist_ok=True)
        os.symlink(str(pid), self.lock())
        if age:
            t = time.time() - age
            os.utime(self.lock(), (t, t), follow_symlinks=False)

    def dead_pid(self):
        p = subprocess.Popen(["/usr/bin/true"])
        p.wait()
        return p.pid

    def test_동시에_돈_두_회차는_한_번만_알린다(self):
        self.ok(mode="200")
        write_exec(os.path.join(self.fake, "curl"), "#!/bin/sh\n/bin/sleep 1\nprintf 000\nexit 7\n")
        env = dict(self.env, CONSOLE_WATCH_TRIES="2")
        ps = [subprocess.Popen([BASH, WATCH], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for p in ps:
            out, err = p.communicate(timeout=60)
            self.assertEqual((p.returncode, err), (0, ""))
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
        self.assertIn("이번 회차는 건너뛴다", read(self.log))
        self.assertFalse(os.path.lexists(self.lock()), "끝나면 잠금을 푼다")

    def test_살아_있는_잠금이면_건너뛴다(self):
        self.put_lock(os.getpid())
        self.ok(mode="refused")
        self.assertEqual(self.health_calls(), [])
        self.assertEqual(self.osa(), [])
        self.assertFalse(os.path.exists(self.state))
        self.assertIn("다른 회차(pid %d)가 돌고 있다" % os.getpid(), read(self.log))
        self.assertEqual(os.readlink(self.lock()), str(os.getpid()), "남의 잠금은 풀지 않는다")

    def test_남은_잠금은_치우고_돈다(self):
        for pid, age in ((self.dead_pid(), 0), (os.getpid(), 600), ("쓰레기", 0)):
            with self.subTest(pid=pid, age=age):
                for p in (self.state, self.osa_log, self.lock()):
                    if os.path.lexists(p):
                        os.remove(p)
                self.put_lock(pid, age)
                self.ok(mode="refused")
                self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
                self.assertIn("남은 잠금을 치운다", read(self.log))
                self.assertFalse(os.path.lexists(self.lock()))

    def test_상태_조회_점검_창_시험_알림은_잠금을_보지_않는다(self):
        self.put_lock(os.getpid())
        self.ok("--status")
        self.ok("--test-alert")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 감시 시험"])
        self.ok("--pause", "5")
        self.ok("--resume")
        self.assertEqual(os.readlink(self.lock()), str(os.getpid()))


class WebhookTest(Base):
    def assert_no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(SECRET, t)
            self.assertNotIn("hooks.example.test", t)
        for root, _, files in os.walk(self.home):
            for name in files:
                p = os.path.join(root, name)
                if p == self.env_file:
                    continue
                with open(p, "rb") as f:
                    data = f.read()
                self.assertNotIn(SECRET.encode(), data, p)
                self.assertNotIn(b"hooks.example.test", data, p)
        self.assertNotIn(SECRET, read(self.osa_log))
        for c in self.curls():
            self.assertNotIn(SECRET, " ".join(c["args"]), "주소는 명령줄에 두지 않는다")

    def test_0600_파일의_주소로_보내고_주소는_어디에도_남지_않는다(self):
        self.write_env("# 콘솔 감시 웹훅\nWEBHOOK_URL=%s\n" % HOOK)
        r = self.ok(mode="refused")
        hooks = self.hook_calls()
        self.assertEqual(len(hooks), 1)
        a = hooks[0]["args"]
        self.assertEqual(a[0], "-q")
        self.assertEqual(a[a.index("-K") + 1], "-")
        self.assertEqual(a[a.index("-m") + 1], "10")
        self.assertEqual(a[a.index("--proto") + 1], "=https")
        self.assertIn("Content-Type: application/json", a)
        self.assertNotIn("-L", a)
        self.assertEqual(hooks[0]["stdin"], 'url = "%s"\n' % HOOK)
        body = json.loads(a[a.index("--data-binary") + 1])
        self.assertEqual(list(body), ["text"])
        self.assertIn("OpsLoop 콘솔 DOWN", body["text"])
        self.assertIn("3번 모두 실패 (연결 실패)", body["text"])
        self.assertNotIn("192.168", body["text"], "본문에 내부 주소를 넣지 않는다")
        self.assertIn("웹훅 보냄 (HTTP 202)", read(self.log))
        self.assert_no_secret(r.stdout, r.stderr)

        self.ok(mode="200")
        self.assertEqual(len(self.hook_calls()), 2)
        self.assertIn("OpsLoop 콘솔 복구", json.loads(self.hook_calls()[1]["args"][
            self.hook_calls()[1]["args"].index("--data-binary") + 1])["text"])
        self.assert_no_secret()

    def test_따옴표_export_CRLF_꼴도_읽는다(self):
        for body in ('export WEBHOOK_URL="%s"\n' % HOOK, "WEBHOOK_URL='%s'\n" % HOOK,
                     "OTHER=1\r\nWEBHOOK_URL=%s\r\n" % HOOK, "WEBHOOK_URL=%s" % HOOK):
            with self.subTest(body=body):
                open(self.curl_log, "w").close()
                self.write_env(body)
                self.ok("--test-alert")
                hooks = self.hook_calls()
                self.assertEqual(len(hooks), 1)
                self.assertEqual(hooks[0]["stdin"], 'url = "%s"\n' % HOOK)

    def test_0600_이_아니면_거부한다(self):
        for mode in (0o644, 0o640, 0o400, 0o700, 0o606):
            with self.subTest(mode=oct(mode)):
                for p in (self.state, self.osa_log, self.log):
                    if os.path.exists(p):
                        os.remove(p)
                self.write_env("WEBHOOK_URL=%s\n" % HOOK, mode)
                r = self.ok(mode="refused")
                self.assertEqual(self.hook_calls(), [])
                self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"], "macOS 알림은 그대로 뜬다")
                log = read(self.log)
                self.assertIn("웹훅 거부 (권한 0%o · 0600 이어야 한다" % mode, log)
                self.assertIn("보내지 않는다", log)
                self.assert_no_secret(r.stdout, r.stderr)

    def test_https_가_아니거나_이상한_주소는_거부한다(self):
        cases = (("WEBHOOK_URL=http://hooks.example.test/x?sig=%s\n" % SECRET, "https:// 주소가 아니다"),
                 ("WEBHOOK_URL=https://hooks.example.test/a b?sig=%s\n" % SECRET, "쓸 수 없는 문자"),
                 ('WEBHOOK_URL=https://hooks.example.test/a"b?sig=%s\n' % SECRET, "쓸 수 없는 문자"),
                 ("WEBHOOK_URL=https://\n", "https:// 주소가 아니다"),
                 ("WEBHOOK_URL=file:///etc/passwd\n", "https:// 주소가 아니다"))
        for body, why in cases:
            with self.subTest(body=body):
                if os.path.exists(self.log):
                    os.remove(self.log)
                self.write_env(body)
                r = self.ok("--test-alert")
                self.assertEqual(self.hook_calls(), [])
                self.assertIn(why, read(self.log))
                self.assert_no_secret(r.stdout, r.stderr)

    def test_주소가_없으면_조용히_넘어간다(self):
        for body in ("", "# 비었다\n", "WEBHOOK_URL=\n"):
            with self.subTest(body=body):
                self.write_env(body)
                self.ok("--test-alert")
                self.assertEqual(self.hook_calls(), [])
                self.assertNotIn("웹훅 거부", read(self.log))
        self.assertEqual(len(self.osa()), 3)

    def test_보내기_실패도_주소_없이_적는다(self):
        self.write_env("WEBHOOK_URL=%s\n" % HOOK)
        r1 = self.ok("--test-alert", FAKE_HOOK_RC="6")
        r2 = self.ok("--test-alert", FAKE_HOOK_CODE="500")
        log = read(self.log)
        self.assertIn("웹훅 실패 (curl 종료 6 · HTTP 000)", log)
        self.assertIn("웹훅 실패 (curl 종료 0 · HTTP 500)", log)
        self.assert_no_secret(r1.stdout, r1.stderr, r2.stdout, r2.stderr)


class CommandTest(Base):
    def test_status(self):
        r = self.ok("--status")
        self.assertIn("상태: 아직 없음", r.stdout)
        self.assertIn("점검 창: 없음", r.stdout)
        self.assertIn("웹훅: 없음", r.stdout)
        self.write_env("WEBHOOK_URL=%s\n" % HOOK)
        self.ok(mode="refused")
        self.write_pause(int(time.time()) + 600)
        r = self.ok("--status")
        self.assertIn("상태: DOWN", r.stdout)
        self.assertIn("DOWN 알림: 보냄", r.stdout)
        self.assertIn("점검 창:", r.stdout)
        self.assertIn("까지 (알리지 않는다)", r.stdout)
        self.assertIn("웹훅: 설정됨", r.stdout)
        self.assertIn("감시 주소: %s" % DEFAULT_URL, r.stdout)
        self.assertNotIn(SECRET, r.stdout + r.stderr)
        n = len(self.health_calls())
        os.chmod(self.env_file, 0o644)
        r = self.ok("--status")
        self.assertIn("웹훅: 거부 (권한 0644", r.stdout)
        self.assertEqual(len(self.health_calls()), n, "--status 는 진입점을 보지 않는다")

    def test_test_alert_는_상태를_바꾸지_않는다(self):
        self.write_env("WEBHOOK_URL=%s\n" % HOOK)
        self.ok("--test-alert")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 감시 시험"])
        self.assertEqual(len(self.hook_calls()), 1)
        self.assertEqual(self.health_calls(), [])
        self.assertFalse(os.path.exists(self.state))

    def test_잘못된_환경변수와_옵션은_2(self):
        pwned = os.path.join(self.t, "pwned")
        for extra in ({"CONSOLE_WATCH_TRIES": "abc"}, {"CONSOLE_WATCH_TRIES": "0"}, {"CONSOLE_WATCH_GAP": "-1"},
                      {"CONSOLE_WATCH_RENOTIFY": "30m"}, {"CONSOLE_WATCH_GAP": "$(touch %s)" % pwned}):
            with self.subTest(extra=extra):
                r = self.run_watch(**extra)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("CONSOLE_WATCH_", r.stderr)
        self.assertFalse(os.path.exists(pwned))
        r = self.run_watch("--모름")
        self.assertEqual(r.returncode, 2)
        self.assertIn("모르는 옵션", r.stderr)
        self.assertEqual(self.curls(), [])
        self.assertEqual(self.osa(), [])
        r = self.ok("--help")
        self.assertIn("사용:", r.stdout)
        self.assertIn("--pause <분>", r.stdout)


class RealCurlTest(Base):
    """가짜 curl 을 빼고 진짜 curl 로 로컬 서버만 본다. 밖으로는 나가지 않는다."""

    def setUp(self):
        super().setUp()
        self.curl = shutil.which("curl", path="/usr/bin:/bin")
        if not self.curl:
            self.skipTest("curl 이 없다")
        os.remove(os.path.join(self.fake, "curl"))
        del self.env["BASH_FUNC_curl%%"]
        self.env["CONSOLE_WATCH_GAP"] = "0"
        self.posts = []

    def serve(self, code, tls=None):
        test = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                test.posts.append((self.path, self.headers.get("Content-Type"), body))
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_진짜_curl_로_200_503_연결_거부를_가른다(self):
        up = "http://127.0.0.1:%d/health" % self.serve(200)
        bad = "http://127.0.0.1:%d/health" % self.serve(503)
        closed = http.server.HTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        refused = "http://127.0.0.1:%d/health" % closed.server_address[1]
        closed.server_close()
        self.ok(CONSOLE_WATCH_URL=up)
        self.assertEqual(self.read_state()["state"], "UP")
        self.ok(CONSOLE_WATCH_URL=bad)
        self.assertIn("3번 모두 실패 (HTTP 503 · HTTP 503 · HTTP 503)", read(self.log))
        self.ok(CONSOLE_WATCH_URL=refused)
        self.assertIn("3번 모두 실패 (연결 실패 · 연결 실패 · 연결 실패)", read(self.log))
        self.ok(CONSOLE_WATCH_URL=up)
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN", "OpsLoop 콘솔 복구"])

    def test_진짜_curl_이_표준_입력_설정의_주소로_보낸다(self):
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl 이 없다")
        cert, key = os.path.join(self.t, "c.pem"), os.path.join(self.t, "k.pem")
        r = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                            "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                           capture_output=True, timeout=60)
        if r.returncode:
            self.skipTest("자체 서명 인증서를 만들지 못했다")
        hook = "https://127.0.0.1:%d/workflows/x?sig=%s" % (self.serve(202, (cert, key)), SECRET)
        self.write_env("WEBHOOK_URL=%s\n" % hook)
        r = self.ok("--test-alert", CURL_CA_BUNDLE=cert)
        self.assertIn("웹훅 보냄 (HTTP 202)", read(self.log))
        self.assertEqual(len(self.posts), 1)
        path, ctype, body = self.posts[0]
        self.assertEqual(path, "/workflows/x?sig=%s" % SECRET)
        self.assertEqual(ctype, "application/json")
        self.assertEqual(list(json.loads(body)), ["text"])
        self.assertIn("OpsLoop 콘솔 감시 시험", json.loads(body)["text"])
        self.assertNotIn(SECRET, r.stdout + r.stderr + read(self.log))


class ShellSyntaxTest(unittest.TestCase):
    SCRIPTS = (WATCH, INSTALL)

    def test_bash_문법(self):
        for sh in sorted({BASH, shutil.which("bash")} - {None}):
            for s in self.SCRIPTS:
                with self.subTest(bash=sh, script=os.path.basename(s)):
                    r = subprocess.run([sh, "-n", s], capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck 가 없다")
    def test_shellcheck(self):
        r = subprocess.run(["shellcheck", "-S", "warning", *self.SCRIPTS], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class LaunchdTest(Base):
    def setUp(self):
        super().setUp()
        if not shutil.which("plutil", path="/usr/bin:/bin"):
            write_exec(os.path.join(self.fake, "plutil"), "#!/bin/sh\nexit 0\n")
        self.bin = os.path.join(self.home, "Library", "Application Support", "OpsLoop", "bin")
        self.copy = os.path.join(self.bin, "console-watch.sh")
        self.plist = os.path.join(self.home, "Library", "LaunchAgents", LABEL + ".plist")
        self.uid = os.getuid()

    def install(self, *args):
        return subprocess.run([BASH, INSTALL, *args], env=self.env, capture_output=True, text=True, encoding="utf-8",
                              stdin=subprocess.DEVNULL, timeout=60)

    def test_설치_plist_사본_다시_설치_내림(self):
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.plist, "rb") as f:
            raw = f.read()
        p = plistlib.loads(raw)
        self.assertEqual(p["Label"], LABEL)
        self.assertEqual(p["ProgramArguments"], ["/bin/bash", self.copy])
        self.assertEqual(p["StartInterval"], 60)
        self.assertIs(p["RunAtLoad"], True)
        self.assertNotIn("StartCalendarInterval", p)
        self.assertEqual(p["StandardOutPath"], self.log)
        self.assertEqual(p["StandardErrorPath"], self.log)
        self.assertEqual(read(self.copy), read(WATCH))
        self.assertEqual(os.stat(self.copy).st_mode & 0o777, 0o700)
        for d in (os.path.dirname(self.log), self.conf):
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700, d)
        calls = ["bootout gui/%d/%s" % (self.uid, LABEL), "bootstrap gui/%d %s" % (self.uid, self.plist)]
        self.assertEqual(read(self.lc_log).splitlines(), calls)
        self.assertIn("60초마다", r.stdout)
        self.assertIn("웹훅: 없음", r.stdout)
        self.assertIn("--test-alert", r.stdout)
        self.assertEqual(self.curls(), [], "설치기는 진입점을 보지 않는다")
        self.assertEqual(self.osa(), [])

        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.plist, "rb") as f:
            self.assertEqual(f.read(), raw, "다시 설치해도 같다")
        self.assertEqual(read(self.lc_log).splitlines(), calls * 2)

        with open(self.log, "a") as f:
            f.write("기록\n")
        self.write_env("WEBHOOK_URL=%s\n" % HOOK)
        for opt in ("--uninstall", "--remove"):
            with self.subTest(opt=opt):
                r = self.install(opt)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse(os.path.exists(self.plist))
                self.assertFalse(os.path.exists(self.copy))
                self.assertTrue(os.path.exists(self.log), "기록은 지우지 않는다")
                self.assertTrue(os.path.exists(self.env_file), "설정은 지우지 않는다")
                self.assertEqual(read(self.lc_log).splitlines()[-1], "bootout gui/%d/%s" % (self.uid, LABEL))

    def test_웹훅_설정_권한을_설치_때_알린다(self):
        self.write_env("WEBHOOK_URL=%s\n" % HOOK, 0o644)
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("웹훅: 거부 (권한 0644", r.stdout)
        self.assertNotIn(SECRET, r.stdout + r.stderr)
        os.chmod(self.env_file, 0o600)
        r = self.install()
        self.assertIn("웹훅: 설정됨", r.stdout)
        self.assertNotIn(SECRET, r.stdout + r.stderr)

    def test_모르는_옵션은_2_이고_아무것도_하지_않는다(self):
        r = self.install("--now")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(read(self.lc_log), "")
        self.assertFalse(os.path.exists(self.plist))

    def test_사본은_저장소_없이_돈다(self):
        self.assertEqual(self.install().returncode, 0)
        self.ok(script=self.copy, mode="refused")
        self.assertEqual(self.titles(), ["OpsLoop 콘솔 DOWN"])
        self.assertEqual(self.read_state()["state"], "DOWN")


if __name__ == "__main__":
    unittest.main()
