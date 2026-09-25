#!/usr/bin/env python3
"""콘솔 B 합류 · 떼기(console-join.sh) · 콘솔 역할 접속 한도 시험.  python3 infra/vmware/scripts/test_console_join.py

원격 없이 Mac 에서 돈다(이슈 #43). HOME 은 임시 폴더이고 ssh · vmrun · ansible-playbook · 자산 조사는 가짜로 바꾼다.
가짜 ssh 는 방화벽(master 소켓 · curl) · 데이터 노드(psql)를 흉내 내고, 콘솔 두 대의 명령은 호스트마다 따로 둔
임시 HOME 에서 bash 로 실제로 돌린다(docker · curl · stat · sha256sum 은 가짜). 그래서 .env 를 고치는 원격 스크립트가
실제로 어떤 파일을 남기는지 본다. sudo 가 붙은 원격 명령(chrony · apt · 재부팅)은 흉내만 낸다.
  - 셸 문법     bash -n (/bin/bash 3.2 포함) · 시험 실행도 /bin/bash 로 한다
  - 드라이런    기본이다 · ssh · vmrun · ansible 을 하나도 부르지 않는다 · 단계 순서
  - 인자        --list · --help · 모르는 인자 · 모르는 단계 · --step 과 --from 함께
  - 합류 전체   명령 순서(maint → VM → 옛 컨테이너 → chrony → upgrade → 가드 두 번 → 이미지 → .env → up → ready → 자산)
                · B 의 .env(0600 · A 의 비밀값 두 줄 · OPSLOOP_WORKER=opsloop-console-b · B 의 다른 줄 그대로 · A 의
                POSTGRES_PASSWORD 없음) · 이미지 · console.yml · HAProxy UP · 비밀값 · 그 해시가 화면 · 명령행 인자에 없음
  - 멈추는 경우 .env 두 값이 없음 · console.yml 을 받지 못함 · maint 아님 · 한도 20 · 가드 두 번째 changed ·
                이미지 ID 다름 · 재부팅 뒤 옛 컨테이너가 떠 있음
  - 떼기        drain → maint → 컨테이너 restart=no · 멈춤 → VM 끔 · 연결이 남아도 기다림 뒤 계속 ·
                maint 가 아니면 컨테이너 · VM 을 끄지 않음 · drain 은 maint 를 푼다(HAProxy 2.8 과 같은 가짜)
  - 접속 한도   db-console-role.sh · install-collector.sh · 마이그레이션 · verify-db-roles.sh 가 모두 30 ·
                마이그레이션을 두 번 적용해도 같고 역할이 없으면 만들지 않는다 (OPSLOOP_TEST_DATABASE_URL 이 있을 때)
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
JOIN = os.path.join(HERE, "console-join.sh")
ROLE_SH = os.path.join(HERE, "db-console-role.sh")
VERIFY_ROLES = os.path.join(HERE, "verify-db-roles.sh")
COLLECTOR = os.path.join(ROOT, "collector", "install-collector.sh")
MIGRATION = os.path.join(ROOT, "infra", "migrations", "20260926_console_connlimit.sql")
CHRONY_TPL = os.path.join(ROOT, "infra", "vmware", "netplan", "chrony-client.conf.template")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
JOIN_STEPS = ["precheck", "maint", "vm-start", "stop-old", "chrony", "upgrade", "guard", "image", "env", "up",
              "verify", "ready", "assets"]
LEAVE_STEPS = ["drain", "maint", "stop", "vm-stop", "state"]
CANARY = {"SESSION_SECRET": "canary-session-Zq81", "OPSLOOP_CONSOLE_DB_PASSWORD": "canary-db-Kp27",
          "POSTGRES_PASSWORD": "canary-pg-Wm55"}

# ── 가짜 실행기 ──────────────────────────────────────────────────────────
PY_HEAD = r'''#!{python}
import gzip, hashlib, json, os, re, subprocess, sys
ROOT = os.environ["FAKE_ROOT"]
def log(tool, **kw):
    with open(os.path.join(ROOT, "events.log"), "a") as f:
        f.write(json.dumps(dict(tool=tool, **kw)) + "\n")
def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
def dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)
STATE = os.path.join(ROOT, "state.json")
'''

FAKE_SSH = PY_HEAD + r'''
args = sys.argv[1:]
i = 0
while i < len(args) and args[i].startswith("-"):
    i += 2
alias, cmd = args[i], " ".join(args[i + 1:])
data = sys.stdin.buffer.read()
log("ssh", alias=alias, cmd=cmd, stdin_len=len(data), stdin_sha=hashlib.sha256(data).hexdigest())
st = load(STATE, {})
hosts = os.path.join(ROOT, "hosts")

def b_running():
    c = load(os.path.join(hosts, "console-b", "docker.json"), {}).get("container")
    return bool(c and c.get("running"))

def done(out="", rc=0):
    sys.stdout.write(out)
    dump(STATE, st)
    sys.exit(rc)

if alias == "fw":
    m = re.search(r'@1 ([^"]*)"', cmd)
    if m and "nc -N -U /run/haproxy-master.sock" in cmd:
        c = m.group(1)
        hap = st["hap"]
        if c == "show servers state consoles":
            done("1\n# be_id be_name srv_id srv_name srv_addr srv_op_state srv_admin_state srv_uweight\n"
                 "2 consoles 1 console-a 192.168.50.11 2 0 1 1 100 15 3 5 6 0 0 0 - 8000 - 0 0 - - 0\n"
                 "2 consoles 2 console-b 192.168.50.12 %d %d 1 1 100 7 2 0 6 0 0 0 - 8000 - 0 0 - - 0\n\n"
                 % (hap["op"], hap["admin"]))
        m2 = re.fullmatch(r"set server consoles/console-b state (maint|ready|drain)", c)
        if m2:
            # HAProxy 2.8 과 같게: maint 는 drain 을, drain 은 maint 를 푼다 (srv_adm_set_maint · srv_adm_set_drain).
            #   maint 동안은 운영 상태가 0 이다
            if m2.group(1) == "maint":
                hap["admin"] = (hap["admin"] | 1) & ~8
                hap["op"] = 0
            elif m2.group(1) == "drain":
                hap["admin"] = (hap["admin"] | 8) & ~1
            else:
                hap["admin"] = 0
                hap["op"] = 2 if b_running() else 0
            done("\n")
        if c == "show stat":
            done("# pxname,svname,qcur,qmax,scur,smax\nconsoles,console-a,0,0,4,9\nconsoles,console-b,0,0,%s,3\n"
                 % os.environ.get("FAKE_SCUR", "0"))
    if cmd.startswith("curl ") and "http://192.168.50.11:8000/health" in cmd:
        done("200")
    if cmd.startswith("curl ") and "http://192.168.50.12:8000/health" in cmd:
        done("200" if b_running() else "000")
elif alias == "data01":
    if "rolconnlimit" in cmd and "pg_stat_activity" in cmd:
        done("%s|%s\n" % (os.environ.get("FAKE_CONNS", "4"), os.environ.get("FAKE_LIMIT", "30")))
    if "rolconnlimit" in cmd:
        done(os.environ.get("FAKE_LIMIT", "30") + "\n")
elif alias in ("console-a", "console-b"):
    if "boot_id" in cmd:
        done(st["boot"] + "\n")
    if "systemctl reboot" in cmd:
        st["boot"] = "boot-2"
        done("", 255)
    if "apt-get" in cmd:
        done("    0 upgraded, 0 newly installed, 0 to remove\n")
    if "chronyc" in cmd:
        with open(os.path.join(hosts, alias, "chrony-received.conf"), "wb") as f:
            f.write(data)
        done("  시간원 설정은 이미 같다\n    Reference ID    : C0A83201 (192.168.50.1)\n")
    home = os.path.join(hosts, alias)
    env = {"HOME": home, "PATH": os.path.join(ROOT, "hostbin") + ":/usr/bin:/bin", "FAKE_ROOT": ROOT,
           "FAKE_HOST": alias, "LANG": "C"}
    for k in ("FAKE_LOAD_CORRUPT",):
        if k in os.environ:
            env[k] = os.environ[k]
    r = subprocess.run(["/bin/bash", "-c", cmd], input=data, env=env, cwd=home, capture_output=True)
    sys.stdout.buffer.write(r.stdout)
    sys.stderr.buffer.write(r.stderr)
    dump(STATE, st)
    sys.exit(r.returncode)
sys.stderr.write("가짜 ssh: 모르는 명령 %s: %s\n" % (alias, cmd))
sys.exit(97)
'''

FAKE_DOCKER = PY_HEAD + r'''
home, host = os.environ["HOME"], os.environ["FAKE_HOST"]
path = os.path.join(home, "docker.json")
st = load(path, {"image": None, "container": None})
a = sys.argv[1:]
log("docker", alias=host, args=a)
c = st.get("container")
def fin(out="", rc=0):
    sys.stdout.write(out)
    dump(path, st)
    sys.exit(rc)
if a[:1] == ["save"]:
    if not st["image"] or a[1:] != ["opsloop-api:latest"]:
        fin("", 1)
    sys.stdout.buffer.write(("FAKE-IMAGE " + st["image"]).encode())
    sys.exit(0)
if a[:1] == ["load"]:
    raw = sys.stdin.buffer.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    if not raw.startswith(b"FAKE-IMAGE "):
        sys.stderr.write("가짜 docker: 이미지가 아니다\n")
        fin("", 1)
    st["image"] = raw.split(b" ", 1)[1].decode() + ("-corrupt" if os.environ.get("FAKE_LOAD_CORRUPT") else "")
    fin("Loaded image: opsloop-api:latest\n")
if a[:2] == ["image", "inspect"]:
    fin(st["image"] + "\n") if st["image"] else fin("", 1)
if a[:1] == ["inspect"]:
    if not c:
        fin("", 1)
    if "-f" in a:
        fmt = a[a.index("-f") + 1]
        fin(fmt.replace("{{.State.Running}}", "true" if c["running"] else "false")
               .replace("{{.HostConfig.RestartPolicy.Name}}", c["restart"]) + "\n")
    fin("[]\n")
if a[:1] == ["update"]:
    if not c:
        fin("", 1)
    c["restart"] = [x.split("=", 1)[1] for x in a if x.startswith("--restart=")][0]
    fin("opsloop-api\n")
if a[:1] == ["stop"]:
    if not c:
        fin("", 1)
    c["running"] = False
    fin("opsloop-api\n")
if a[:1] == ["compose"] and "up" in a:
    if not os.path.exists("console.yml"):
        fin("", 14)
    if "--no-build" not in a or not st["image"]:
        sys.stderr.write("가짜 docker: 빌드하려 했다\n")
        fin("", 1)
    env = {}
    with open(os.path.join(home, "opsloop", ".env")) as f:
        for line in f:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                env[k] = v
    st["container"] = {"running": True, "restart": "always", "image": st["image"],
                       "worker": env.get("OPSLOOP_WORKER", ""),
                       "db_user": "opsloop_console" if env.get("OPSLOOP_CONSOLE_DB_PASSWORD") else ""}
    fin(" Container opsloop-api  Started\n")
if a[:1] == ["exec"]:
    if not c or not c["running"]:
        fin("", 1)
    if "printenv" in a:
        fin(c["worker"] + "\n")
    if "python3" in a:
        fin(c["db_user"] + "\n")
sys.stderr.write("가짜 docker: 모르는 명령 %r\n" % a)
sys.exit(97)
'''

FAKE_CURL = PY_HEAD + r'''
st = load(os.path.join(os.environ["HOME"], "docker.json"), {})
c = st.get("container")
sys.stdout.write("200" if c and c.get("running") else "000")
'''

FAKE_STAT = r'''#!{python}
import os, sys
a = sys.argv[1:]
assert a[:2] == ["-c", "%a"], a
print(oct(os.stat(a[2]).st_mode & 0o777)[2:])
'''

FAKE_SHA256SUM = r'''#!{python}
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + "  -")
'''

FAKE_VMRUN = PY_HEAD + r'''
a = sys.argv[1:]
log("vmrun", args=a)
st = load(STATE, {})
vms = st.setdefault("vms", [])
if a[:1] == ["list"]:
    print("Total running VMs: %d" % len(vms))
    for v in vms:
        print(v)
elif a[:1] == ["start"]:
    if a[1] not in vms:
        vms.append(a[1])
    # 옛 컨테이너는 restart: always 라 부팅과 함께 뜬다 (restart=no 로 바꿔 두었으면 뜨지 않는다)
    p = os.path.join(ROOT, "hosts", "console-b", "docker.json")
    d = load(p, {})
    if d.get("container") and d["container"]["restart"] == "always":
        d["container"]["running"] = True
        dump(p, d)
elif a[:1] == ["stop"]:
    if a[1] in vms:
        vms.remove(a[1])
else:
    sys.exit(97)
dump(STATE, st)
'''

FAKE_ANSIBLE = PY_HEAD + r'''
st = load(STATE, {})
st["ansible_runs"] = st.get("ansible_runs", 0) + 1
log("ansible-playbook", args=sys.argv[1:], cwd=os.getcwd())
dump(STATE, st)
changed = 2 if st["ansible_runs"] == 1 else int(os.environ.get("FAKE_GUARD_CHANGED2", "0"))
print("PLAY RECAP *********************************************************************")
print("console-b                  : ok=6    changed=%d    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0" % changed)
'''

FAKE_COLLECT = PY_HEAD + r'''
log("collect", args=sys.argv[1:])
print("가짜 자산 조사")
'''


def write_exec(path, body):
    with open(path, "w") as f:
        f.write(body.replace("{python}", sys.executable))
    os.chmod(path, 0o755)


def env_text(pairs):
    return "".join(f"{k}={v}\n" for k, v in pairs)


class JoinTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.home = os.path.join(self.t, "home")
        self.bin = os.path.join(self.t, "bin")
        self.hostbin = os.path.join(self.t, "hostbin")
        self.hosts = os.path.join(self.t, "hosts")
        self.vmdir = os.path.join(self.t, "vms")
        for d in (self.home, self.bin, self.hostbin, self.hosts, self.vmdir):
            os.mkdir(d)
        self.vmx = os.path.join(self.vmdir, "opsloop-console-b.vmwarevm", "opsloop-console-b.vmx")
        os.makedirs(os.path.dirname(self.vmx))
        open(self.vmx, "w").close()
        write_exec(os.path.join(self.bin, "ssh"), FAKE_SSH)
        write_exec(os.path.join(self.bin, "vmrun"), FAKE_VMRUN)
        write_exec(os.path.join(self.bin, "ansible-playbook"), FAKE_ANSIBLE)
        write_exec(os.path.join(self.bin, "collect-assets.sh"), FAKE_COLLECT)
        write_exec(os.path.join(self.hostbin, "docker"), FAKE_DOCKER)
        write_exec(os.path.join(self.hostbin, "curl"), FAKE_CURL)
        write_exec(os.path.join(self.hostbin, "stat"), FAKE_STAT)
        write_exec(os.path.join(self.hostbin, "sha256sum"), FAKE_SHA256SUM)
        open(os.path.join(self.t, "events.log"), "w").close()
        # 콘솔 A: 돌고 있는 새 이미지 · .env · console.yml
        self.a_env = [("POSTGRES_PASSWORD", CANARY["POSTGRES_PASSWORD"]),
                      ("SESSION_SECRET", CANARY["SESSION_SECRET"]),
                      ("OPSLOOP_CONSOLE_DB_PASSWORD", CANARY["OPSLOOP_CONSOLE_DB_PASSWORD"]),
                      ("OPSLOOP_WORKER", "opsloop-console-a")]
        self.host("console-a", env=self.a_env, compose="services:\n  api:\n    build: ./app  # 새 판\n",
                  docker={"image": "sha256:" + "a1" * 32,
                          "container": {"running": True, "restart": "always", "image": "sha256:" + "a1" * 32,
                                        "worker": "opsloop-console-a", "db_user": "opsloop_console"}})
        # 콘솔 B: 꺼져 있고, 옛 이미지 · 옛 값 · 자기 줄이 있다
        self.b_env_before = env_text([("POSTGRES_PASSWORD", "b-own-pg"), ("SESSION_SECRET", "old-session"),
                                      ("OPSLOOP_CONSOLE_DB_PASSWORD", "old-db"), ("OPSLOOP_WORKER", ""),
                                      ("OTHER_SETTING", "keep-me")])
        self.host("console-b", env_raw=self.b_env_before, compose="services:\n  api:\n    build: ./app  # 옛 판\n",
                  docker={"image": "sha256:" + "0b" * 32,
                          "container": {"running": False, "restart": "always", "image": "sha256:" + "0b" * 32,
                                        "worker": "", "db_user": "opsloop_console"}})
        self.set_state(hap={"op": 0, "admin": 0}, boot="boot-1", vms=[])
        self.env = {"HOME": self.home, "PATH": self.bin + ":/usr/bin:/bin", "TMPDIR": self.t, "LANG": "ko_KR.UTF-8",
                    "FAKE_ROOT": self.t, "VMDIR": self.vmdir, "VMRUN": os.path.join(self.bin, "vmrun"),
                    "CONSOLE_JOIN_POLL": "0", "COLLECT_ASSETS": os.path.join(self.bin, "collect-assets.sh")}

    # ── 도구 ────────────────────────────────────────────────
    def host(self, alias, env=None, env_raw=None, compose=None, docker=None):
        home = os.path.join(self.hosts, alias)
        os.makedirs(os.path.join(home, "opsloop"), exist_ok=True)
        p = os.path.join(home, "opsloop", ".env")
        with open(p, "w") as f:
            f.write(env_raw if env_raw is not None else env_text(env))
        os.chmod(p, 0o600)
        if compose is not None:
            with open(os.path.join(home, "opsloop", "console.yml"), "w") as f:
                f.write(compose)
        if docker is not None:
            with open(os.path.join(home, "docker.json"), "w") as f:
                json.dump(docker, f)

    def set_state(self, **kw):
        p = os.path.join(self.t, "state.json")
        st = {}
        if os.path.exists(p):
            with open(p) as f:
                st = json.load(f)
        st.update(kw)
        with open(p, "w") as f:
            json.dump(st, f)

    def state(self):
        with open(os.path.join(self.t, "state.json")) as f:
            return json.load(f)

    def docker_state(self, alias):
        with open(os.path.join(self.hosts, alias, "docker.json")) as f:
            return json.load(f)

    def read(self, *parts):
        with open(os.path.join(self.hosts, *parts)) as f:
            return f.read()

    def events(self):
        with open(os.path.join(self.t, "events.log")) as f:
            return [json.loads(x) for x in f if x.strip()]

    def run_join(self, *args, **env):
        return subprocess.run([BASH, JOIN, *args], env=dict(self.env, **env), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def first(self, pred, what):
        for i, e in enumerate(self.events()):
            if pred(e):
                return i
        self.fail(f"일어나지 않았다: {what}")

    def ssh_idx(self, alias, needle):
        return self.first(lambda e: e["tool"] == "ssh" and e["alias"] == alias and needle in e["cmd"],
                          f"ssh {alias} … {needle}")

    def assert_no_secret(self, r):
        text = r.stdout + r.stderr
        for v in CANARY.values():
            self.assertNotIn(v, text)
        for e in self.events():
            if e["tool"] == "ssh":
                for v in CANARY.values():
                    self.assertNotIn(v, e["cmd"], "비밀값이 ssh 명령행 인자에 들어갔다")

    # ── 문법 · 인자 ─────────────────────────────────────────
    def test_셸_문법(self):
        for sh in {BASH, shutil.which("bash")}:
            r = subprocess.run([sh, "-n", JOIN], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{sh}: {r.stderr}")

    def test_드라이런은_기본이고_아무것도_부르지_않는다(self):
        r = self.run_join()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.events(), [])
        heads = re.findall(r"^== (\S+) · ", r.stdout, re.M)
        self.assertEqual(heads, JOIN_STEPS)
        self.assertIn("드라이런", r.stdout.splitlines()[0])
        self.assertTrue(r.stdout.rstrip().endswith("실제로 돌리려면 --apply"))
        # 드라이런이 찍는 명령에도 비밀값 · 옛 값이 없다 (값은 원격에서만 읽는다)
        self.assert_no_secret(r)
        self.assertIn('echo "@1 set server consoles/console-b state maint" | sudo -n nc -N -U /run/haproxy-master.sock',
                      r.stdout)
        self.assertIn("docker compose -f console.yml up -d --no-build --force-recreate", r.stdout)
        r = self.run_join("--leave", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(re.findall(r"^== (\S+) · ", r.stdout, re.M), LEAVE_STEPS)
        self.assertEqual(self.events(), [])

    def test_단계_고르기(self):
        r = self.run_join("--from", "image")
        self.assertEqual(re.findall(r"^== (\S+) · ", r.stdout, re.M), JOIN_STEPS[JOIN_STEPS.index("image"):])
        r = self.run_join("--step", "env")
        self.assertEqual(re.findall(r"^== (\S+) · ", r.stdout, re.M), ["env"])
        r = self.run_join("--leave", "--step", "maint")
        self.assertEqual(re.findall(r"^== (\S+) · ", r.stdout, re.M), ["maint"])

    def test_목록_도움말_잘못된_인자(self):
        r = self.run_join("--list")
        self.assertEqual(r.returncode, 0)
        for s in JOIN_STEPS + LEAVE_STEPS:
            self.assertRegex(r.stdout, rf"(?m)^  {re.escape(s)} ")
        r = self.run_join("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--apply", r.stdout)
        for bad in (["--bogus"], ["--step", "nope"], ["--leave", "--step", "image"], ["--step"],
                    ["--step", "env", "--from", "up"]):
            r = self.run_join(*bad)
            self.assertEqual(r.returncode, 2, bad)
        self.assertEqual(self.events(), [])

    # ── 합류 ────────────────────────────────────────────────
    def test_합류_전체(self):
        r = self.run_join("--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.rstrip().endswith("끝."))
        # 순서
        order = [
            ("maint", self.ssh_idx("fw", "state maint")),
            ("vm start", self.first(lambda e: e["tool"] == "vmrun" and e["args"][:1] == ["start"], "vmrun start")),
            ("옛 컨테이너 restart=no", self.first(lambda e: e["tool"] == "docker" and e["alias"] == "console-b"
                                             and e["args"][:1] == ["update"], "docker update")),
            ("chrony", self.ssh_idx("console-b", "chronyc")),
            ("upgrade", self.ssh_idx("console-b", "full-upgrade")),
            ("reboot", self.ssh_idx("console-b", "systemctl reboot")),
            ("guard", self.first(lambda e: e["tool"] == "ansible-playbook", "ansible-playbook")),
            ("save", self.first(lambda e: e["tool"] == "docker" and e["alias"] == "console-a"
                                and e["args"][:1] == ["save"], "docker save")),
            ("load", self.first(lambda e: e["tool"] == "docker" and e["alias"] == "console-b"
                                and e["args"][:1] == ["load"], "docker load")),
            (".env", self.ssh_idx("console-b", "OPSLOOP_WORKER=opsloop-console-b")),
            ("up", self.first(lambda e: e["tool"] == "docker" and e["alias"] == "console-b"
                              and e["args"][:1] == ["compose"], "compose up")),
            ("ready", self.ssh_idx("fw", "state ready")),
            ("assets", self.first(lambda e: e["tool"] == "collect", "collect")),
        ]
        idx = [i for _, i in order]
        self.assertEqual(idx, sorted(idx), order)
        # 가드는 저장소 infra/ansible 에서 두 번
        runs = [e for e in self.events() if e["tool"] == "ansible-playbook"]
        self.assertEqual(len(runs), 2)
        for e in runs:
            self.assertEqual(e["args"], ["consoles.yml", "--limit", "console-b"])
            self.assertEqual(os.path.realpath(e["cwd"]), os.path.realpath(os.path.join(ROOT, "infra", "ansible")))
        self.assertEqual([e["args"] for e in self.events() if e["tool"] == "collect"], [["--only", "console-b"]])
        # B 의 .env: A 의 비밀값 두 줄 · 발송기 이름 · B 의 다른 줄은 그대로 · A 의 소유자 비밀번호는 없다
        p = os.path.join(self.hosts, "console-b", "opsloop", ".env")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        lines = self.read("console-b", "opsloop", ".env").splitlines()
        self.assertEqual(sorted(lines), sorted([
            "POSTGRES_PASSWORD=b-own-pg", "OTHER_SETTING=keep-me",
            f"SESSION_SECRET={CANARY['SESSION_SECRET']}",
            f"OPSLOOP_CONSOLE_DB_PASSWORD={CANARY['OPSLOOP_CONSOLE_DB_PASSWORD']}",
            "OPSLOOP_WORKER=opsloop-console-b"]))
        for dirpath, _, files in os.walk(os.path.join(self.hosts, "console-b")):
            for name in files:
                with open(os.path.join(dirpath, name), "rb") as f:
                    self.assertNotIn(CANARY["POSTGRES_PASSWORD"].encode(), f.read(), name)
        # A 에서 읽는 명령은 두 키만 고른다
        reads = [e["cmd"] for e in self.events() if e["tool"] == "ssh" and e["alias"] == "console-a"
                 and "grep" in e["cmd"] and ".env" in e["cmd"]]
        self.assertTrue(reads)
        for c in reads:
            self.assertNotIn("POSTGRES_PASSWORD", c)
        # 이미지 · compose 파일 · 컨테이너 · HAProxy
        a, b = self.docker_state("console-a"), self.docker_state("console-b")
        self.assertEqual(b["image"], a["image"])
        self.assertEqual(b["container"], {"running": True, "restart": "always", "image": a["image"],
                                          "worker": "opsloop-console-b", "db_user": "opsloop_console"})
        self.assertEqual(self.read("console-b", "opsloop", "console.yml"), self.read("console-a", "opsloop", "console.yml"))
        self.assertIn("옛 판", self.read("console-b", "opsloop", "console.yml.prev"))
        self.assertTrue(os.path.isdir(os.path.join(self.hosts, "console-b", "opsloop", "app")))
        self.assertEqual(self.state()["hap"], {"op": 2, "admin": 0})
        # 시간원: add-node.sh 와 같은 원본에 서비스망 방화벽 주소
        with open(CHRONY_TPL) as f:
            want = f.read().replace("__FW__", "192.168.50.1")
        self.assertEqual(self.read("console-b", "chrony-received.conf"), want)
        # 비밀값 · 비밀값 줄의 해시가 화면에 없다
        self.assert_no_secret(r)
        secret_lines = sorted(f"{k}={CANARY[k]}\n" for k in ("SESSION_SECRET", "OPSLOOP_CONSOLE_DB_PASSWORD"))
        digest = hashlib.sha256("".join(secret_lines).encode()).hexdigest()
        self.assertNotIn(digest, r.stdout + r.stderr)
        self.assertIn("✔ 비밀값 두 줄이 콘솔 A 와 같다", r.stdout)

    def test_env_두_값을_받지_못하면_바꾸지_않는다(self):
        self.host("console-a", env=[("SESSION_SECRET", CANARY["SESSION_SECRET"]), ("OPSLOOP_CONSOLE_DB_PASSWORD", "")])
        r = self.run_join("--step", "env", "--apply")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("두 값을 받지 못했다 (1/2)", r.stderr)
        self.assertEqual(self.read("console-b", "opsloop", ".env"), self.b_env_before)
        self.assert_no_secret(r)

    def test_maint_가_아니면_VM_을_켜지_않는다(self):
        r = self.run_join("--step", "vm-start", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertIn("maint 가 아니다", r.stderr)
        self.assertFalse([e for e in self.events() if e["tool"] == "vmrun" and e["args"][:1] == ["start"]])

    def test_maint_가_아니면_compose_up_하지_않는다(self):
        r = self.run_join("--step", "up", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertFalse([e for e in self.events() if e["tool"] == "docker" and e["args"][:1] == ["compose"]])

    def test_console_yml_을_받지_못하면_바꾸지_않는다(self):
        os.remove(os.path.join(self.hosts, "console-a", "opsloop", "console.yml"))
        self.set_state(hap={"op": 0, "admin": 1}, vms=[self.vmx])
        before = self.read("console-b", "opsloop", "console.yml")
        r = self.run_join("--step", "up", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertIn("console.yml 을 받지 못했다", r.stderr)
        self.assertEqual(self.read("console-b", "opsloop", "console.yml"), before)
        self.assertFalse(os.path.exists(os.path.join(self.hosts, "console-b", "opsloop", "console.yml.prev")))
        self.assertFalse([e for e in self.events() if e["tool"] == "docker" and e["args"][:1] == ["compose"]])

    def test_접속_한도가_낮으면_사전_점검에서_멈춘다(self):
        r = self.run_join("--step", "precheck", "--apply", FAKE_LIMIT="20")
        self.assertEqual(r.returncode, 1)
        self.assertIn("20260926_console_connlimit.sql", r.stdout)
        r = self.run_join("--step", "precheck", "--apply", FAKE_LIMIT="-1")
        self.assertEqual(r.returncode, 1)
        r = self.run_join("--step", "precheck", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VM: 꺼져 있다", r.stdout)

    def test_가드_두번째가_changed_0_이_아니면_멈춘다(self):
        r = self.run_join("--step", "guard", "--apply", FAKE_GUARD_CHANGED2="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("changed=0 이 아니다", r.stderr)

    def test_이미지_ID_가_다르면_멈춘다(self):
        r = self.run_join("--step", "image", "--apply", FAKE_LOAD_CORRUPT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("이미지 ID 가 콘솔 A 와 같다: 기대와 다르다", r.stderr)

    def test_재부팅_뒤_옛_컨테이너가_멈춘_채인지_본다(self):
        # restart=no 로 바꾸지 않았으면(stop-old 를 건너뜀) 재부팅 확인에서 멈춘다
        self.set_state(hap={"op": 0, "admin": 1}, vms=[self.vmx])
        d = self.docker_state("console-b")
        d["container"]["running"] = True
        with open(os.path.join(self.hosts, "console-b", "docker.json"), "w") as f:
            json.dump(d, f)
        r = self.run_join("--step", "upgrade", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertIn("옛 컨테이너가 멈춘 채다: 기대와 다르다", r.stderr)
        self.assertEqual(self.state()["boot"], "boot-2")

    # ── 떼기 ────────────────────────────────────────────────
    def serving(self):
        self.host("console-b", env=[("SESSION_SECRET", "s"), ("OPSLOOP_CONSOLE_DB_PASSWORD", "d"),
                                    ("OPSLOOP_WORKER", "opsloop-console-b")],
                  docker={"image": "sha256:" + "a1" * 32,
                          "container": {"running": True, "restart": "always", "image": "sha256:" + "a1" * 32,
                                        "worker": "opsloop-console-b", "db_user": "opsloop_console"}})
        self.set_state(hap={"op": 2, "admin": 0}, vms=[self.vmx])

    def test_떼기(self):
        self.serving()
        r = self.run_join("--leave", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        idx = [self.ssh_idx("fw", "state drain"), self.ssh_idx("fw", "state maint"),
               self.first(lambda e: e["tool"] == "docker" and e["args"][:1] == ["update"], "docker update"),
               self.first(lambda e: e["tool"] == "docker" and e["args"][:1] == ["stop"], "docker stop"),
               self.first(lambda e: e["tool"] == "vmrun" and e["args"][:1] == ["stop"], "vmrun stop")]
        self.assertEqual(idx, sorted(idx))
        vm_stop = [e["args"] for e in self.events() if e["tool"] == "vmrun" and e["args"][:1] == ["stop"]]
        self.assertEqual(vm_stop, [["stop", self.vmx, "soft"]])
        c = self.docker_state("console-b")["container"]
        self.assertEqual((c["running"], c["restart"]), (False, "no"))
        self.assertEqual(self.state()["vms"], [])
        # drain 뒤 maint 가 drain 을 풀어 관리 상태는 1 이다 (README '끄는 절차' state 줄)
        self.assertEqual(self.state()["hap"], {"op": 0, "admin": 1})
        self.assertIn("console-b  운영 0 · 관리 1", r.stdout)

    def test_떼기_drain_은_maint_를_풀므로_stop_앞에_maint_를_다시_건다(self):
        # maint 인 B 에 떼기를 다시 돌려도(합류가 중간에 멈춘 뒤) drain 이 maint 를 풀었다가 maint 단계가 다시 건다
        self.serving()
        self.set_state(hap={"op": 0, "admin": 1})
        r = self.run_join("--leave", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertLess(self.ssh_idx("fw", "state maint"),
                        self.first(lambda e: e["tool"] == "docker" and e["args"][:1] == ["stop"], "docker stop"))
        self.assertEqual(self.state()["hap"]["admin"], 1)
        r = self.run_join("--leave", "--step", "drain", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.state()["hap"]["admin"], 8)
        r = self.run_join("--leave", "--step", "stop", "--apply")
        self.assertEqual(r.returncode, 1, "drain 만 걸린 채로는 컨테이너를 멈추지 않는다")
        self.assertIn("maint 가 아니다", r.stderr)

    def test_떼기_연결이_남아도_기다린_뒤_계속한다(self):
        self.serving()
        r = self.run_join("--leave", "--apply", FAKE_SCUR="3")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("30번 기다렸다. 그대로 다음으로 간다", r.stdout)
        self.assertIn("console-b 연결 3", r.stdout)

    def test_떼기_maint_가_아니면_멈추지_않는다(self):
        self.serving()
        r = self.run_join("--leave", "--step", "stop", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertTrue(self.docker_state("console-b")["container"]["running"])

    def test_떼기_maint_가_아니면_VM_을_끄지_않는다(self):
        # --step vm-stop 만 돌려도 분배 중인 B 를 끄지 않는다
        self.serving()
        r = self.run_join("--leave", "--step", "vm-stop", "--apply")
        self.assertEqual(r.returncode, 1)
        self.assertIn("maint 가 아니다", r.stderr)
        self.assertFalse([e for e in self.events() if e["tool"] == "vmrun" and e["args"][:1] == ["stop"]])
        self.assertEqual(self.state()["vms"], [self.vmx])
        r = self.run_join("--leave", "--step", "maint", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.run_join("--leave", "--step", "vm-stop", "--apply")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.state()["vms"], [])


# ── 콘솔 역할 접속 한도 (C3) ─────────────────────────────────────────────
def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class RoleLimit(unittest.TestCase):
    def test_역할을_만드는_곳은_모두_30(self):
        role = read(ROLE_SH)
        self.assertRegex(role, r'(?m)^attrs = "LOGIN .*NOINHERIT CONNECTION LIMIT 30"$')
        self.assertNotIn("CONNECTION LIMIT 20", role)
        lines = [ln for ln in read(COLLECTOR).splitlines() if "CREATE ROLE opsloop_console" in ln]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].rstrip().endswith("CONNECTION LIMIT 30;"), lines[0])
        self.assertIn("LIMIT_MIN=30 ", read(JOIN))

    def test_마이그레이션_모양(self):
        sql = read(MIGRATION)
        code = "\n".join(ln.split("--", 1)[0] for ln in sql.splitlines()).strip()
        self.assertIn("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN", code)
        self.assertIn("ALTER ROLE opsloop_console WITH CONNECTION LIMIT 30;", code)
        self.assertNotIn("CREATE ROLE", code)
        self.assertNotRegex(code, r"(?i)\bPASSWORD\b")

    def test_검증_스크립트는_30_이상을_본다(self):
        text = read(VERIFY_ROLES)
        self.assertIn("SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console'", text)
        self.assertRegex(text, r'\[\[ "\$lim" =~ \^\[0-9\]\+\$ \]\] && \[ "\$lim" -ge 30 \]')
        for sh in {BASH, shutil.which("bash")}:
            r = subprocess.run([sh, "-n", VERIFY_ROLES], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "OPSLOOP_TEST_DATABASE_URL 이 없다 (임시 PostgreSQL)")
    def test_마이그레이션을_두_번_적용해도_같다(self):
        try:
            import psycopg2
        except ImportError:
            self.skipTest("psycopg2 가 없다")
        sql = read(MIGRATION)
        conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.addCleanup(conn.close)
        cur = conn.cursor()

        def limit():
            cur.execute("SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console'")
            row = cur.fetchone()
            return row[0] if row else None

        # 역할이 없으면 만들지 않는다 (트랜잭션 안에서 보고 되돌린다)
        dropped = True
        if limit() is not None:
            try:
                cur.execute("DROP ROLE opsloop_console")
            except psycopg2.Error:
                # 스키마 권한이 걸린 역할은 지우지 못한다. 이 부분만 건너뛰고 아래 20 → 30 은 본다
                conn.rollback()
                dropped = False
        if dropped:
            cur.execute(sql)
            self.assertIsNone(limit())
            conn.rollback()
        # 역할이 있으면 20 → 30, 두 번 적용해도 30
        if limit() is None:
            cur.execute("CREATE ROLE opsloop_console WITH LOGIN NOINHERIT CONNECTION LIMIT 20")
        else:
            cur.execute("ALTER ROLE opsloop_console WITH CONNECTION LIMIT 20")
        cur.execute(sql)
        self.assertEqual(limit(), 30)
        cur.execute(sql)
        self.assertEqual(limit(), 30)
        conn.rollback()


if __name__ == "__main__":
    unittest.main(verbosity=1)
