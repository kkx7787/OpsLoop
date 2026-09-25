#!/usr/bin/env python3
"""자산 조사 수집(collect-assets.sh) · launchd 설치기 · 실행기 시험.  python3 infra/vmware/scripts/test_collect_assets.py

원격 없이 Mac 에서 돈다. HOME 은 임시 폴더이고 ssh · aws · launchctl · osascript 는 가짜로 바꾼다
(PATH 앞 가짜 실행기. launchd 쪽은 bash 내보낸 함수까지 겹쳐 진짜가 불리지 않게 한다).
  - 시험 실행   모든 노드 연결 실패 → 전부 error 인 묶음 · 종료 1 · 아무것도 보내지 않음 (가짜 ssh · 설정 파일 없는 진짜 ssh)
  - SSH 수집    ssh 인자 · 표준 입력이 probe.py · host 는 노드 호스트명 · 적재 명령과 묶음 · 종료 코드 0 · 1 · 2
                (적재기 종료 1 은 '일부 실패'로 1, sudo 거절은 2)
  - 출력 이상   JSON 아님 · 원격 실패 · 시간 초과 · 너무 큼 · 긴 오류 문구 자르기
  - 비신뢰 출력 짝 없는 대리 문자 · 깊은 중첩은 그 자산만 error (로케일 · 파이썬 판이 달라도) ·
                노드가 보낸 제어 문자는 요약 · error 에 남지 않음 · 도우미가 죽으면 보내지 않음
  - 적재기 호환 SSH · SSM 으로 만든 묶음을 적재기 검증(cti/opsloop_cti.py validate_bundle)에 그대로 넣어 본다
  - 옵션        --only · 모르는 자산 · 모르는 옵션 · 도움말
  - AWS         자격 없음(자동 · --aws) · --no-aws 는 aws 를 부르지 않음 · aws 없음 · 인스턴스 없음 · 여러 대
  - SSM         send-command 인자 · 실은 본문이 probe.py 그대로 · 실은 명령을 실제로 돌려 결과가 풀리는지 ·
                출력 한도 초과 · 명령 실패 · 풀 수 없는 출력
  - 셸 문법     bash -n (/bin/bash 3.2 포함) · shellcheck(있으면)
  - launchd     plist(05:10 · 기록 파일 · 사본 경로) · 사본 세 개 · --now · --remove
  - 실행기      종료 1 은 알리지 않고 2 는 알린다 · 종료 코드를 그대로 낸다
"""
import base64
import gzip
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECT = os.path.join(HERE, "collect-assets.sh")
INSTALL = os.path.join(HERE, "install-assets-agent.sh")
AGENT = os.path.join(HERE, "assets-agent.sh")
CTI = os.path.normpath(os.path.join(HERE, "..", "..", "..", "cti"))
PROBE = os.path.join(CTI, "probe.py")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
SSH_ASSETS = ["web-01", "fw", "console-a", "console-b", "data-01"]
ALL_ASSETS = SSH_ASSETS + ["gateway", "honeypot-dmz"]
LOAD_CMD = "sudo -n -u opsloop-cti /usr/local/bin/opsloop-cti load-assets"

FAKE_SSH = r'''#!{python}
import hashlib, json, os, sys, time
from datetime import datetime, timezone
args = sys.argv[1:]
opts, i = [], 0
while i < len(args) and args[i].startswith("-"):
    opts += args[i:i + 2]
    i += 2
alias, cmd = args[i], " ".join(args[i + 1:])
data = sys.stdin.buffer.read()
with open(os.environ["FAKE_SSH_LOG"], "a") as f:
    f.write(json.dumps({{"opts": opts, "alias": alias, "cmd": cmd,
                        "stdin_sha256": hashlib.sha256(data).hexdigest()}}) + "\n")
if "load-assets" in cmd:
    with open(os.environ["FAKE_LOAD_OUT"], "wb") as f:
        f.write(data)
    if os.environ.get("FAKE_LOAD_SUDO_DENY"):
        sys.stderr.write("sudo: a password is required\n")
        sys.exit(1)
    print("가짜 적재기: 받았다")
    sys.exit(int(os.environ.get("FAKE_LOAD_RC", "0")))
mode = json.loads(os.environ.get("FAKE_SSH_MODES", "{{}}")).get(alias, os.environ.get("FAKE_SSH_DEFAULT", "fail"))
if mode == "fail":
    sys.stderr.write("ssh: connect to host %s port 22: Operation timed out\n" % alias)
    sys.exit(255)
if mode == "fail-long":
    sys.stderr.write("오류" * 2000 + "\n")
    sys.exit(255)
if mode == "garbage":
    print("이건 JSON 이 아니다")
    sys.exit(0)
if mode == "remote-error":
    sys.stderr.write("bash: python3: command not found\n")
    sys.exit(127)
if mode == "flood-out":
    # 장악된 노드가 표준 출력으로 끝없이 흘린다. 도우미가 상한에서 끊어야 한다
    chunk = "a" * 65536
    for _ in range(4096):
        sys.stdout.write(chunk)
    sys.exit(0)
if mode == "flood-err":
    # 표준 오류로 수 MiB 를 흘린 뒤 정상 조사 출력을 낸다. 표준 오류는 앞부분만 남기고 조사는 받아야 한다
    sys.stderr.write("잡음" * (3 * 1024 * 1024))
    sys.stderr.flush()
    mode = "probe"
if mode == "big":
    sys.stdout.write('{{"probe_version":1,"x":"' + "a" * (2 * 1024 * 1024 + 10) + '"}}')
    sys.exit(0)
if mode == "slow":
    time.sleep(5)
if mode == "ctrl-fail":
    # 장악된 노드가 운영자 터미널을 흔드는 표준 오류: 창 제목(OSC) · 윗줄로 · 줄 지우기 · C1 CSI 로 가짜 '수집' 줄
    sys.stderr.write("\x1b]0;PWNED\x07\x1b[1A\x1b[2K  web-01 수집 opsloop-web-01 · 패키지 683\x9b31m\n")
    sys.exit(255)
# collected_at 은 지금 시각이다. 적재기는 미래 시각을 위조로 보고 거른다
rec = {{"probe_version": 1, "hostname": "opsloop-" + alias,
       "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
       "os": {{"id": "ubuntu", "version_id": "24.04", "codename": "noble", "pretty": "Ubuntu 24.04.5 LTS"}},
       "kernel": {{"running": "6.8.0-139-generic", "running_package": "linux-image-6.8.0-139-generic",
                  "running_version": "6.8.0-139.139", "installed": []}},
       "packages": [{{"name": "sudo", "version": "1.9.15p5-3ubuntu5.24.04.2", "source": "sudo",
                     "source_version": "1.9.15p5-3ubuntu5.24.04.2", "arch": "amd64"}}],
       "images": [], "errors": []}}
if mode == "ctrl-host":
    rec["hostname"] = "x\x1b[31mRED\x9b0m"
if mode in ("surrogate-hi", "surrogate-lo"):
    # 표준 출력에는 JSON 이스케이프(\ud800 · \udcff)로 나간다. json.loads 를 통과해 짝 없는 대리 문자가 된다
    rec["os"]["pretty"] = "\ud800" if mode == "surrogate-hi" else "\udcff"
body = json.dumps(rec)
if mode.startswith("deep:"):
    n = int(mode[5:])
    body = body[:-1] + ',"x":' + "[" * n + "]" * n + "}}"
print(body)
'''

FAKE_AWS = r'''#!{python}
import json, os, subprocess, sys
args = sys.argv[1:]
region = None
if args[:1] == ["--region"]:
    region, args = args[1], args[2:]
svc, op, rest = args[0], args[1], args[2:]
with open(os.environ["FAKE_AWS_LOG"], "a") as f:
    f.write(json.dumps({{"region": region, "svc": svc, "op": op, "args": rest}}) + "\n")
def opt(name):
    return rest[rest.index(name) + 1] if name in rest else None
state = os.environ["FAKE_AWS_STATE"]
if (svc, op) == ("sts", "get-caller-identity"):
    if os.environ.get("FAKE_AWS_STS") == "ok":
        print('{{"Account": "000000000000"}}')
        sys.exit(0)
    sys.stderr.write("Unable to locate credentials. You can configure credentials by running aws login.\n")
    sys.exit(255)
if (svc, op) == ("ec2", "describe-instances"):
    tag = [a for a in rest if a.startswith("Name=tag:Name,Values=")][0].split("Values=")[1]
    print(json.loads(os.environ.get("FAKE_AWS_INSTANCES", "{{}}")).get(tag, ""))
    sys.exit(0)
if (svc, op) == ("ssm", "send-command"):
    iid, p = opt("--instance-ids"), opt("--parameters")
    assert p.startswith('commands=["') and p.endswith('"]'), p
    with open(os.path.join(state, iid + ".cmd"), "w") as f:
        f.write(p[len('commands=["'):-2])
    print("cmd-" + iid)
    sys.exit(0)
if (svc, op) == ("ssm", "wait"):
    sys.exit(0)
if (svc, op) == ("ssm", "get-command-invocation"):
    iid = opt("--instance-id")
    mode = json.loads(os.environ.get("FAKE_AWS_SSM", "{{}}")).get(iid, "run")
    inv = {{"CommandId": opt("--command-id"), "InstanceId": iid, "Status": "Success", "ResponseCode": 0,
           "StandardOutputContent": "", "StandardErrorContent": ""}}
    if mode == "run":
        with open(os.path.join(state, iid + ".cmd")) as f:
            cmd = f.read()
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True,
                           env={{"PATH": os.environ["FAKE_REMOTE_PATH"], "FAKE_DPKG_OUT": os.environ["FAKE_DPKG_OUT"]}})
        inv.update(StandardOutputContent=r.stdout, StandardErrorContent=r.stderr)
        if r.returncode:
            inv.update(Status="Failed", ResponseCode=r.returncode)
    elif mode == "big":
        inv["StandardOutputContent"] = "A" * 24000
    elif mode == "failed":
        inv.update(Status="Failed", ResponseCode=1, StandardErrorContent="sh: 1: python3: not found\n")
    elif mode == "garbage":
        inv["StandardOutputContent"] = "!!!이건 base64 가 아니다"
    print(json.dumps(inv))
    sys.exit(0)
sys.stderr.write("가짜 aws: 모르는 호출 %s %s\n" % (svc, op))
sys.exit(2)
'''

FAKE_REMOTE_DPKG = """#!/bin/sh
/bin/cat "$FAKE_DPKG_OUT"
"""
REMOTE_DPKG_OUT = "ii \topenssh-server\t1:9.6p1-3ubuntu13.19\topenssh\t1:9.6p1-3ubuntu13.19\tamd64\n"


def write_exec(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def loader_entries(body):
    """묶음 바이트를 적재기 검증(cti/opsloop_cti.py 의 validate_bundle)에 그대로 넣는다.

    묶음 형식은 계약 6장으로 두 쪽이 나눠 가진다. 각자 따로 시험하면 한쪽이 필드 이름 · 형을 바꿔도 모두 통과하고
    운영 적재에서만 자산이 invalid 로 남는다. 그래서 수집 쪽 시험이 적재기 검증을 직접 부른다.
    """
    if CTI not in sys.path:
        sys.path.insert(0, CTI)
    import opsloop_cti
    _, entries = opsloop_cti.validate_bundle(body, datetime.now(timezone.utc))
    return entries


def helper_source():
    """collect-assets.sh 에 박힌 파이썬 도우미 본문."""
    with open(COLLECT, encoding="utf-8") as f:
        m = re.search(r"<<'EOF_PY' \|\| true\n(.*?)\nEOF_PY\n", f.read(), re.S)
    return m.group(1)


def pythons():
    """도우미를 돌려 볼 파이썬들. 이 시험의 파이썬과, 있으면 macOS 기본 /usr/bin/python3(3.9)."""
    out = [sys.executable]
    sysp = "/usr/bin/python3"
    if os.path.realpath(sysp) != os.path.realpath(sys.executable) and os.access(sysp, os.X_OK):
        r = subprocess.run([sysp, "-c", "import json, re"], capture_output=True, timeout=60)
        if r.returncode == 0:
            out.append(sysp)
    return out


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.home = os.path.join(self.t, "home")
        self.bin = os.path.join(self.t, "bin")
        self.remote = os.path.join(self.t, "remote")
        self.state = os.path.join(self.t, "aws-state")
        for d in (self.home, self.bin, self.remote, self.state):
            os.mkdir(d)
        # 셸 스크립트 안의 python3 는 이 시험을 돌리는 파이썬으로 고정한다
        os.symlink(sys.executable, os.path.join(self.bin, "python3"))
        self.ssh_log = os.path.join(self.t, "ssh.log")
        self.aws_log = os.path.join(self.t, "aws.log")
        self.load_out = os.path.join(self.t, "loaded.json")
        for p in (self.ssh_log, self.aws_log):
            open(p, "w").close()
        # SSM 흉내: 실은 명령을 이 PATH 로 실제로 돌린다 (probe.py 는 가짜 dpkg-query 를 본다)
        for tool in ("base64", "gzip", "gunzip"):
            os.symlink(shutil.which(tool, path="/usr/bin:/bin"), os.path.join(self.remote, tool))
        os.symlink(sys.executable, os.path.join(self.remote, "python3"))
        write_exec(os.path.join(self.remote, "dpkg-query"), FAKE_REMOTE_DPKG)
        self.dpkg_out = os.path.join(self.t, "dpkg.out")
        with open(self.dpkg_out, "w") as f:
            f.write(REMOTE_DPKG_OUT)
        self.env = {"HOME": self.home, "PATH": self.bin + ":/usr/bin:/bin", "TMPDIR": self.t, "LANG": "ko_KR.UTF-8",
                    "FAKE_SSH_LOG": self.ssh_log, "FAKE_AWS_LOG": self.aws_log, "FAKE_LOAD_OUT": self.load_out,
                    "FAKE_AWS_STATE": self.state, "FAKE_REMOTE_PATH": self.remote, "FAKE_DPKG_OUT": self.dpkg_out}

    # ── 도구 ────────────────────────────────────────────────
    def fake_ssh(self):
        write_exec(os.path.join(self.bin, "ssh"), FAKE_SSH.format(python=sys.executable))

    def fake_aws(self, sts="ok", instances=None, ssm=None):
        write_exec(os.path.join(self.bin, "aws"), FAKE_AWS.format(python=sys.executable))
        self.env.update(FAKE_AWS_STS=sts, FAKE_AWS_SSM=json.dumps(ssm or {}), FAKE_AWS_INSTANCES=json.dumps(
            instances if instances is not None else {"opsloop-gateway": "i-0gw", "opsloop-honeypot-dmz": "i-0hp"}))

    def run_collect(self, *args, unset=(), **env):
        e = dict(self.env, **env)
        for k in unset:
            e.pop(k, None)
        started = time.monotonic()
        r = subprocess.run([BASH, COLLECT, *args], env=e, capture_output=True, text=True, timeout=120)
        self.elapsed = time.monotonic() - started
        return r

    def lines(self, path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]

    def ssh_calls(self):
        return self.lines(self.ssh_log)

    def aws_calls(self):
        return self.lines(self.aws_log)

    def loaded(self):
        with open(self.load_out, encoding="utf-8") as f:
            return json.load(f)

    def loaded_bytes(self):
        with open(self.load_out, "rb") as f:
            return f.read()

    def use_python(self, python):
        """셸 스크립트 안의 python3 를 바꾼다 (launchd 는 /usr/local/bin/python3, 없으면 /usr/bin/python3 3.9)."""
        link = os.path.join(self.bin, "python3")
        os.remove(link)
        os.symlink(python, link)

    def assert_bundle(self, b, ids):
        self.assertEqual(list(b), ["schema", "collected_by", "sent_at", "assets"])
        self.assertEqual((b["schema"], b["collected_by"]), ("opsloop-assets/1", "collect-assets.sh"))
        self.assertEqual(datetime.fromisoformat(b["sent_at"]).utcoffset().total_seconds(), 0)
        self.assertEqual([a["asset_id"] for a in b["assets"]], ids)
        for a in b["assets"]:
            tail = "error" if "error" in a else "probe"
            self.assertEqual(list(a), ["asset_id", "role", "method", "host", tail], a)
            if tail == "error":
                self.assertIsInstance(a["error"], str)
                self.assertLessEqual(len(a["error"]), 500)
        return {a["asset_id"]: a for a in b["assets"]}

    # ── 시험 실행 (SSH 없이) ────────────────────────────────
    def test_시험_실행_모든_연결_실패는_error_묶음이고_보내지_않는다(self):
        self.fake_ssh()
        r = self.run_collect("--dry-run", "--no-aws")
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), SSH_ASSETS)
        for aid, a in by.items():
            self.assertIsNone(a["host"])
            self.assertTrue(a["error"].startswith("연결 실패: ssh: connect to host"), a["error"])
        self.assertEqual((by["web-01"]["role"], by["fw"]["role"], by["data-01"]["method"]), ("target", "platform", "ssh"))
        self.assertFalse([c for c in self.ssh_calls() if "load-assets" in c["cmd"]], "시험 실행은 보내지 않는다")
        self.assertIn("수집 0 · 실패 5", r.stderr)
        self.assertIn("시험 실행: 적재기에 보내지 않았다", r.stderr)
        self.assertEqual(self.aws_calls(), [])

    @unittest.skipUnless(shutil.which("ssh", path="/usr/bin:/bin"), "ssh 가 없다")
    def test_시험_실행_진짜_ssh_설정_파일이_없어도_끝까지_간다(self):
        # HOME 이 임시 폴더라 ~/.ssh/config.opsloop 가 없다. ssh 는 설정을 읽다가 바로 끝나고 어디에도 붙지 않는다
        r = self.run_collect("--dry-run", "--no-aws")
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), SSH_ASSETS)
        self.assertTrue(all(a["error"].startswith("연결 실패") for a in by.values()), by)

    # ── SSH 수집 · 적재 ─────────────────────────────────────
    def test_모두_수집하면_적재하고_0(self):
        self.fake_ssh()
        r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("opsloop-assets/1", r.stdout, "적재할 때는 묶음을 화면에 찍지 않는다")
        self.assertIn("가짜 적재기: 받았다", r.stdout)
        by = self.assert_bundle(self.loaded(), SSH_ASSETS)
        self.assertEqual(by["web-01"]["host"], "opsloop-web01")
        self.assertEqual(by["web-01"]["probe"]["packages"][0]["name"], "sudo")
        with open(PROBE, "rb") as f:
            probe_sha = hashlib.sha256(f.read()).hexdigest()
        calls = self.ssh_calls()
        probes = [c for c in calls if "load-assets" not in c["cmd"]]
        self.assertEqual([c["alias"] for c in probes], ["web01", "fw", "console-a", "console-b", "data01"])
        cfg = os.path.join(self.home, ".ssh", "config.opsloop")
        for c in probes:
            self.assertEqual(c["opts"], ["-F", cfg, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"])
            self.assertEqual(c["cmd"], "python3 -")
            self.assertEqual(c["stdin_sha256"], probe_sha, "표준 입력은 probe.py 그대로다")
        load = [c for c in calls if "load-assets" in c["cmd"]]
        self.assertEqual(len(load), 1)
        self.assertEqual((load[0]["alias"], load[0]["cmd"]), ("data01", LOAD_CMD))
        with open(self.load_out, "rb") as f:
            self.assertEqual(load[0]["stdin_sha256"], hashlib.sha256(f.read()).hexdigest())

    def test_일부_실패도_적재하고_1(self):
        self.fake_ssh()
        r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe", FAKE_SSH_MODES=json.dumps({"console-b": "fail"}))
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(self.loaded(), SSH_ASSETS)
        self.assertIn("error", by["console-b"])
        self.assertIn("probe", by["web-01"])
        self.assertIn("수집 4 · 실패 1", r.stderr)

    def test_적재가_실패하면_2(self):
        self.fake_ssh()
        for rc in ("2", "255"):
            with self.subTest(적재기_종료=rc):
                r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe", FAKE_LOAD_RC=rc)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("적재 실패 (data01 opsloop-cti load-assets 종료 %s)" % rc, r.stderr)

    def test_적재기가_일부_자산을_거르면_1_이고_sudo_거절은_2(self):
        self.fake_ssh()
        r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe", FAKE_LOAD_RC="1")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("적재는 됐다", r.stderr)
        r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe", FAKE_LOAD_SUDO_DENY="1")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("sudo: a password is required", r.stderr, "적재기 쪽 표준 오류도 보여 준다")
        self.assertIn("적재 실패 (data01 에서 sudo 가 거절했다", r.stderr)

    # ── 출력 이상 ───────────────────────────────────────────
    def test_조사_출력_이상은_그_자산만_error(self):
        self.fake_ssh()
        modes = {"web01": "garbage", "fw": "remote-error", "console-a": "big", "console-b": "fail-long"}
        r = self.run_collect("--dry-run", "--no-aws", FAKE_SSH_DEFAULT="probe", FAKE_SSH_MODES=json.dumps(modes))
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), SSH_ASSETS)
        self.assertEqual(by["web-01"]["error"], "조사 출력이 JSON 이 아니다")
        self.assertEqual(by["fw"]["error"], "조사 실패 (종료 127): bash: python3: command not found")
        self.assertTrue(by["console-a"]["error"].startswith("조사 출력이 너무 크다 ("), by["console-a"]["error"])
        self.assertTrue(by["console-b"]["error"].startswith("연결 실패: 오류오류"))
        self.assertEqual(len(by["console-b"]["error"]), 500)
        self.assertIn("probe", by["data-01"])

    def test_끝없이_흘리는_노드는_받는_도중에_끊는다(self):
        self.fake_ssh()
        modes = {"web01": "flood-out", "fw": "flood-err"}
        r = self.run_collect("--dry-run", "--no-aws", "--only", "web-01,fw", FAKE_SSH_DEFAULT="probe",
                             FAKE_SSH_MODES=json.dumps(modes))
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), ["web-01", "fw"])
        self.assertEqual(by["web-01"]["error"], "조사 출력이 너무 크다 (상한 2 MiB 를 넘어 받기를 멈췄다)")
        self.assertIn("probe", by["fw"], "표준 오류가 커도 조사 결과는 받는다")
        self.assertLess(self.elapsed, 30, "상한에서 끊고 끝까지 기다리지 않는다")

    def test_시간_초과(self):
        self.fake_ssh()
        r = self.run_collect("--dry-run", "--no-aws", "--only", "web-01", OPSLOOP_PROBE_TIMEOUT="1",
                             FAKE_SSH_DEFAULT="probe", FAKE_SSH_MODES=json.dumps({"web01": "slow"}))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(json.loads(r.stdout)["assets"][0]["error"], "시간 초과 (1초)")
        self.assertLess(self.elapsed, 4.5, "제한 시간이 지나면 기다리지 않는다")

    # ── 비신뢰 출력 (장악된 노드) ───────────────────────────
    def test_짝_없는_대리_문자_깊은_중첩은_그_자산만_error_이고_나머지는_적재된다(self):
        # 도우미가 묶음을 쓰다 죽으면 종료 1 이 '일부 실패'로 읽혀 빈 묶음 · 날바이트 섞인 묶음이 적재기로 가고,
        # 적재기가 묶음 전체를 거부해 그날 모든 자산이 갱신되지 않는다. 노드 하나는 그 자산에서 막혀야 한다.
        # 992단은 /usr/bin/python3 3.9 에서 json.loads 는 통과하고 다시 쓸 때 RecursionError 가 나던 깊이다
        self.fake_ssh()
        modes = json.dumps({"web01": "surrogate-hi", "fw": "surrogate-lo", "console-a": "deep:40",
                            "console-b": "deep:992"})
        surrogate = "조사 출력에 UTF-8 로 쓸 수 없는 문자가 있다 (짝 없는 대리 문자)"
        for python in pythons():
            self.use_python(python)
            # --dry-run 은 한국어 로케일, 적재는 launchd 처럼 LANG 없이
            for args, unset in ((["--dry-run"], ()), ([], ("LANG",))):
                with self.subTest(python=python, dry_run=bool(args)):
                    open(self.load_out, "w").close()
                    r = self.run_collect("--no-aws", *args, unset=unset, FAKE_SSH_DEFAULT="probe",
                                         FAKE_SSH_MODES=modes)
                    self.assertEqual(r.returncode, 1, r.stderr)
                    self.assertNotIn("Traceback", r.stderr)
                    if args:
                        body = r.stdout.encode("utf-8")
                    else:
                        self.assertIn("가짜 적재기: 받았다", r.stdout)
                        body = self.loaded_bytes()
                    self.assertTrue(body.isascii(), "묶음은 로케일과 무관하게 ASCII 로 나간다")
                    by = self.assert_bundle(json.loads(body), SSH_ASSETS)
                    self.assertEqual(by["web-01"]["error"], surrogate)
                    self.assertEqual(by["fw"]["error"], surrogate)
                    self.assertEqual(by["console-a"]["error"], "조사 출력의 중첩이 너무 깊다 (16단 초과)")
                    self.assertTrue(by["console-b"]["error"].startswith("조사 출력"), by["console-b"]["error"])
                    self.assertTrue(all(by[a]["host"] is None for a in ("web-01", "fw", "console-a", "console-b")))
                    self.assertEqual(by["data-01"]["probe"]["hostname"], "opsloop-data01")
                    self.assertIn("수집 1 · 실패 4", r.stderr)
                    kinds = [e["kind"] for e in loader_entries(body)]
                    self.assertEqual(kinds, ["error", "error", "error", "error", "probe"])

    def test_노드가_보낸_제어_문자는_요약과_error_에_남지_않는다(self):
        # 노드가 정하는 표준 오류 · hostname 의 터미널 제어 순서가 그대로 찍히면 '실패' 줄을 지우고 가짜 '수집' 줄을 보일 수 있다
        self.fake_ssh()
        r = self.run_collect("--dry-run", "--no-aws", "--only", "web-01,fw", FAKE_SSH_DEFAULT="probe",
                             FAKE_SSH_MODES=json.dumps({"web01": "ctrl-fail", "fw": "ctrl-host"}))
        self.assertEqual(r.returncode, 1, r.stderr)
        for out in (r.stdout, r.stderr):
            self.assertIsNone(re.search("[\x00-\x09\x0b-\x1f\x7f-\x9f]", out), repr(out))
        by = self.assert_bundle(json.loads(r.stdout), ["web-01", "fw"])
        self.assertEqual(by["web-01"]["error"],
                         "연결 실패: ?]0;PWNED??[1A?[2K web-01 수집 opsloop-web-01 · 패키지 683?31m")
        self.assertIn("  web-01        실패  연결 실패: ?]0;PWNED??[1A?[2K web-01", r.stderr)
        self.assertIn("  fw            수집  x?[31mRED?0m · 패키지 1", r.stderr)
        # 묶음의 host 는 노드가 준 값 그대로(JSON 이스케이프)이고, 받아들일지는 적재기가 정한다
        self.assertEqual(by["fw"]["host"], "x\x1b[31mRED\x9b0m")
        kinds = {e["asset_id"]: e["kind"] for e in loader_entries(r.stdout.encode("utf-8"))}
        self.assertEqual(kinds, {"web-01": "error", "fw": "invalid"})

    def test_도우미가_예상하지_못하게_죽으면_3_이고_셸은_보내지_않고_2(self):
        # 파이썬이 잡지 못한 예외의 종료 코드 1 은 '일부 자산 실패'와 겹친다
        for python in pythons():
            with self.subTest(python=python):
                r = subprocess.run([python, "-c", helper_source(), "bundle", self.t, "web-01:target"],
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertEqual(r.stdout, "")
                self.assertIn("도우미 오류 (bundle): ValueError", r.stderr)
                self.assertNotIn("Traceback", r.stderr)
        self.fake_ssh()
        link = os.path.join(self.bin, "python3")
        os.remove(link)
        write_exec(link, '#!/bin/sh\nif [ "$3" = bundle ]; then exit 3; fi\nexec "%s" "$@"\n' % sys.executable)
        r = self.run_collect("--no-aws", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("묶음을 만들지 못했다 (종료 3)", r.stderr)
        self.assertFalse([c for c in self.ssh_calls() if "load-assets" in c["cmd"]], "적재기에 보내지 않는다")

    # ── 옵션 ────────────────────────────────────────────────
    def test_only_는_고른_자산만_표_순서대로(self):
        self.fake_ssh()
        r = self.run_collect("--dry-run", "--only", "fw,web-01", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_bundle(json.loads(r.stdout), ["web-01", "fw"])
        self.assertEqual(self.aws_calls(), [], "AWS 자산을 고르지 않으면 aws 를 부르지 않는다")
        r = self.run_collect("--dry-run", "--only=console-a", FAKE_SSH_DEFAULT="probe")
        self.assert_bundle(json.loads(r.stdout), ["console-a"])

    def test_설정_오류는_2_이고_아무것도_부르지_않는다(self):
        self.fake_ssh()
        self.fake_aws()
        for args, msg in ((["--only", "web-01,nope"], "모르는 자산: 'nope'"),
                          (["--only"], "--only 뒤에 자산 ID 를 쓴다"),
                          (["--only", ""], "--only 에 자산 ID 가 없다"),
                          (["--only", ","], "모르는 자산: ''"),
                          (["--only", "web-01 fw"], "모르는 자산: 'web-01 fw'"),
                          (["--bogus"], "모르는 옵션: --bogus"),
                          (["--only", "gateway", "--no-aws"], "보낼 자산이 없다")):
            with self.subTest(args=args):
                r = self.run_collect(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn(msg, r.stderr)
                self.assertEqual(r.stdout, "")
        self.assertEqual(self.ssh_calls(), [])
        self.assertEqual(self.aws_calls(), [])

    def test_도움말(self):
        r = self.run_collect("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("자산 조사 수집 (이슈 #39)", r.stdout)
        self.assertIn("--dry-run", r.stdout)
        self.assertNotIn("=====", r.stdout)
        self.assertNotIn("set -euo", r.stdout)

    # ── AWS 자격 ────────────────────────────────────────────
    def test_자격이_없으면_AWS_두_대를_빼고_안내한다(self):
        self.fake_ssh()
        self.fake_aws(sts="fail")
        r = self.run_collect(FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_bundle(self.loaded(), SSH_ASSETS)
        self.assertIn("aws login 뒤 손으로 돌린다: infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws",
                      r.stderr)
        self.assertEqual([(c["svc"], c["op"]) for c in self.aws_calls()], [("sts", "get-caller-identity")])

    def test_aws_를_주었는데_자격이_없으면_1(self):
        self.fake_ssh()
        self.fake_aws(sts="fail")
        r = self.run_collect("--aws", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assert_bundle(self.loaded(), SSH_ASSETS)

    def test_no_aws_는_aws_를_부르지_않는다(self):
        self.fake_ssh()
        self.fake_aws()
        r = self.run_collect("--dry-run", "--no-aws", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_bundle(json.loads(r.stdout), SSH_ASSETS)
        self.assertEqual(self.aws_calls(), [])

    def test_aws_가_없으면_AWS_두_대를_뺀다(self):
        self.fake_ssh()
        r = self.run_collect("--dry-run", FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_bundle(json.loads(r.stdout), SSH_ASSETS)
        self.assertIn("AWS 자격이 없어", r.stderr)

    # ── SSM ─────────────────────────────────────────────────
    def test_SSM_명령_조립과_실제_실행(self):
        self.fake_ssh()
        self.fake_aws()
        r = self.run_collect("--dry-run", FAKE_SSH_DEFAULT="probe", AWS_DEFAULT_REGION="ap-northeast-2")
        self.assertEqual(r.returncode, 0, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), ALL_ASSETS)
        for aid, iid in (("gateway", "i-0gw"), ("honeypot-dmz", "i-0hp")):
            a = by[aid]
            self.assertEqual((a["method"], a["host"]), ("ssm", iid))
            self.assertEqual(a["probe"]["probe_version"], 1)
            self.assertEqual([p["name"] for p in a["probe"]["packages"]], ["openssh-server"],
                             "SSM 으로 실은 probe.py 가 실제로 돌아 결과가 풀렸다: %s" % a["probe"]["errors"])
        self.assertEqual((by["gateway"]["role"], by["honeypot-dmz"]["role"]), ("platform", "sensor"))
        calls = self.aws_calls()
        self.assertTrue(all(c["region"] == "ap-northeast-2" for c in calls))
        desc = [c["args"] for c in calls if c["op"] == "describe-instances"]
        self.assertIn("Name=tag:Name,Values=opsloop-gateway", desc[0])
        self.assertIn("Name=tag:Name,Values=opsloop-honeypot-dmz", desc[1])
        self.assertTrue(all("Name=instance-state-name,Values=running" in d for d in desc))
        sends = [c["args"] for c in calls if c["op"] == "send-command"]
        self.assertEqual(len(sends), 2)
        with open(PROBE, "rb") as f:
            probe_src = f.read()
        for args in sends:
            self.assertEqual(args[args.index("--document-name") + 1], "AWS-RunShellScript")
            param = args[args.index("--parameters") + 1]
            m = re.fullmatch(r'commands=\["echo ([A-Za-z0-9+/=]+) \| base64 -d \| gunzip \| python3 - '
                             r'\| gzip -9 \| base64 -w0"\]', param)
            self.assertIsNotNone(m, param)
            self.assertEqual(gzip.decompress(base64.b64decode(m.group(1))), probe_src, "실은 본문은 probe.py 그대로다")
        waits = [c for c in calls if c["op"] == "wait"]
        self.assertEqual([w["args"][0] for w in waits], ["command-executed", "command-executed"])
        inv = [c["args"] for c in calls if c["op"] == "get-command-invocation"]
        self.assertEqual([a[a.index("--instance-id") + 1] for a in inv], ["i-0gw", "i-0hp"])

    def test_묶음은_적재기_검증을_통과한다(self):
        # SSH 가짜 · SSM 으로 실제로 돈 probe.py · 연결 실패가 섞인 묶음. 모든 자산이 probe · error 여야 한다(invalid · reject 없음)
        self.fake_ssh()
        self.fake_aws()
        r = self.run_collect("--dry-run", FAKE_SSH_DEFAULT="probe", FAKE_SSH_MODES=json.dumps({"console-b": "fail"}))
        self.assertEqual(r.returncode, 1, r.stderr)
        entries = loader_entries(r.stdout.encode("utf-8"))
        self.assertEqual({e["asset_id"]: e["kind"] for e in entries},
                         {"web-01": "probe", "fw": "probe", "console-a": "probe", "console-b": "error",
                          "data-01": "probe", "gateway": "probe", "honeypot-dmz": "probe"},
                         [(e["asset_id"], e.get("error")) for e in entries])
        by = {e["asset_id"]: e for e in entries}
        self.assertEqual([p["source"] for p in by["gateway"]["probe"]["packages"]], ["openssh"])
        self.assertEqual(by["web-01"]["probe"]["kernel"]["running_version"], "6.8.0-139.139")
        self.assertEqual((by["honeypot-dmz"]["role"], by["honeypot-dmz"]["host"]), ("sensor", "i-0hp"))
        # 적재 경로: 적재기가 받은 바이트 그대로
        r = self.run_collect(FAKE_SSH_DEFAULT="probe")
        self.assertEqual(r.returncode, 0, r.stderr)
        entries = loader_entries(self.loaded_bytes())
        self.assertEqual([e["kind"] for e in entries], ["probe"] * len(ALL_ASSETS),
                         [(e["asset_id"], e.get("error")) for e in entries])

    def test_SSM_실패_모양(self):
        self.fake_ssh()
        cases = {"big": "출력 한도 초과 (SSM 표준 출력 24,000자)",
                 "failed": "SSM 명령 Failed (종료 1): sh: 1: python3: not found",
                 "garbage": "SSM 출력을 풀지 못했다 (base64 · gzip)"}
        for mode, msg in cases.items():
            with self.subTest(mode=mode):
                self.fake_aws(ssm={"i-0gw": mode})
                r = self.run_collect("--dry-run", "--only", "gateway,honeypot-dmz")
                self.assertEqual(r.returncode, 1, r.stderr)
                by = self.assert_bundle(json.loads(r.stdout), ["gateway", "honeypot-dmz"])
                self.assertEqual(by["gateway"]["error"], msg)
                self.assertEqual(by["gateway"]["host"], "i-0gw")
                self.assertIn("probe", by["honeypot-dmz"])

    def test_인스턴스가_없거나_여러_대면_error(self):
        self.fake_ssh()
        self.fake_aws(instances={"opsloop-gateway": "i-0a\ti-0b", "opsloop-honeypot-dmz": ""})
        r = self.run_collect("--dry-run", "--aws", "--only", "gateway,honeypot-dmz")
        self.assertEqual(r.returncode, 1, r.stderr)
        by = self.assert_bundle(json.loads(r.stdout), ["gateway", "honeypot-dmz"])
        self.assertEqual(by["gateway"]["error"], "실행 중인 인스턴스가 여러 대다 (Name=opsloop-gateway: i-0a i-0b)")
        self.assertEqual(by["honeypot-dmz"]["error"], "실행 중인 인스턴스가 없다 (Name=opsloop-honeypot-dmz)")
        self.assertIsNone(by["gateway"]["host"])
        self.assertIsNone(by["honeypot-dmz"]["host"])
        self.assertFalse([c for c in self.aws_calls() if c["op"] == "send-command"])


class ShellSyntaxTest(unittest.TestCase):
    SCRIPTS = (COLLECT, INSTALL, AGENT)

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


class LaunchdTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.home = os.path.join(self.t, "home")
        self.bin = os.path.join(self.t, "bin")
        os.makedirs(self.home)
        os.makedirs(self.bin)
        self.lc_log = os.path.join(self.t, "launchctl.log")
        self.osa_log = os.path.join(self.t, "osascript.log")
        for p in (self.lc_log, self.osa_log):
            open(p, "w").close()
        write_exec(os.path.join(self.bin, "launchctl"), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_LC_LOG"\n')
        if not shutil.which("plutil", path="/usr/bin:/bin"):
            write_exec(os.path.join(self.bin, "plutil"), "#!/bin/sh\nexit 0\n")
        # 진짜 launchctl · osascript 가 불리지 않게 PATH 에 더해 bash 내보낸 함수로도 덮는다
        self.env = {"HOME": self.home, "PATH": self.bin + ":/usr/bin:/bin", "TMPDIR": self.t,
                    "FAKE_LC_LOG": self.lc_log, "FAKE_OSA_LOG": self.osa_log,
                    "BASH_FUNC_launchctl%%": '() {  printf "%s\\n" "$*" >> "$FAKE_LC_LOG"; }',
                    "BASH_FUNC_osascript%%": '() {  printf "%s\\n" "$*" >> "$FAKE_OSA_LOG"; }'}

    def read(self, p):
        with open(p, encoding="utf-8") as f:
            return f.read()

    def test_설치_plist_사본_now_remove(self):
        r = subprocess.run([BASH, INSTALL, "--now"], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        binp = os.path.join(self.home, "Library", "Application Support", "OpsLoop", "bin")
        plist = os.path.join(self.home, "Library", "LaunchAgents", "local.opsloop.assets.plist")
        dest = os.path.join(self.home, "opsloop-assets")
        with open(plist, "rb") as f:
            p = plistlib.load(f)
        self.assertEqual(p["Label"], "local.opsloop.assets")
        self.assertEqual(p["ProgramArguments"], ["/bin/bash", os.path.join(binp, "assets-agent.sh")])
        self.assertEqual(p["StartCalendarInterval"], {"Hour": 5, "Minute": 10})
        self.assertEqual(p["StandardOutPath"], os.path.join(dest, "assets.log"))
        self.assertEqual(p["StandardErrorPath"], os.path.join(dest, "assets.log"))
        for name, src in (("collect-assets.sh", COLLECT), ("assets-agent.sh", AGENT), ("probe.py", PROBE)):
            self.assertEqual(self.read(os.path.join(binp, name)), self.read(src), name)
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o700)
        uid = os.getuid()
        calls = self.read(self.lc_log).splitlines()
        self.assertEqual(calls, ["bootout gui/%d/local.opsloop.assets" % uid, "bootstrap gui/%d %s" % (uid, plist),
                                 "kickstart gui/%d/local.opsloop.assets" % uid])
        self.assertIn("매일 05:10", r.stdout)
        self.assertIn("aws login 뒤 손으로", r.stdout)

        open(os.path.join(dest, "assets.log"), "w").close()
        r = subprocess.run([BASH, INSTALL, "--remove"], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(plist))
        self.assertTrue(os.path.exists(os.path.join(dest, "assets.log")), "기록은 지우지 않는다")
        self.assertEqual(self.read(self.lc_log).splitlines()[-1], "bootout gui/%d/local.opsloop.assets" % uid)

    def test_사본의_collect_는_같은_폴더의_probe_를_쓴다(self):
        r = subprocess.run([BASH, INSTALL], env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        binp = os.path.join(self.home, "Library", "Application Support", "OpsLoop", "bin")
        # 사본 폴더에서 시험 실행: 진짜 ssh 는 설정 파일이 없어 바로 끝난다. probe.py 를 못 찾으면 종료 2 다
        env = dict(self.env, PATH="/usr/bin:/bin")
        if not shutil.which("ssh", path="/usr/bin:/bin"):
            self.skipTest("ssh 가 없다")
        r = subprocess.run([BASH, os.path.join(binp, "collect-assets.sh"), "--dry-run", "--no-aws", "--only", "web-01"],
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(json.loads(r.stdout)["assets"][0]["asset_id"], "web-01")

    def agent(self, rc):
        binp = os.path.join(self.t, "agent-bin")
        os.makedirs(binp, exist_ok=True)
        shutil.copy(AGENT, binp)
        write_exec(os.path.join(binp, "collect-assets.sh"), '#!/bin/bash\necho "가짜 수집"\nexit "${FAKE_RC:-0}"\n')
        return subprocess.run([BASH, os.path.join(binp, "assets-agent.sh")], env=dict(self.env, FAKE_RC=str(rc)),
                              capture_output=True, text=True, timeout=60)

    def test_실행기_종료_코드와_알림(self):
        r = self.agent(0)
        self.assertEqual(r.returncode, 0)
        self.assertIn("가짜 수집", r.stdout)
        self.assertIn("자산 수집 성공", r.stdout)
        r = self.agent(1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("일부 실패", r.stdout)
        self.assertEqual(self.read(self.osa_log), "", "일부 실패(평소 꺼 둔 console-b)는 알리지 않는다")
        r = self.agent(2)
        self.assertEqual(r.returncode, 2)
        self.assertIn("자산 수집 실패 (종료 코드 2)", r.stdout)
        osa = self.read(self.osa_log)
        self.assertIn('with title "OpsLoop 자산 수집 실패"', osa)
        self.assertIn("종료 코드 2", osa)


if __name__ == "__main__":
    unittest.main()
