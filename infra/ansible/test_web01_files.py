#!/usr/bin/env python3
"""web-01 Ansible 파일 시험. 원격 노드 없이 Mac 에서 돈다.  python3 infra/ansible/test_web01_files.py

  - metrics.py        번호가 실행 · 재시작을 넘어 이어지는지, 줄 모양(키 순서 · 형식), CPU 차분
  - opsloop-agent-key 한 번만 만드는지, sha256 만 내는지, 파일 권한
  - opsloop-enroll    가짜 관문에 보내는 요청 모양, 등록 표식, 거부 · 재지정 · 연결 실패, 토큰이 출력에 없는지
  - 플레이북          작업이 가리키는 파일 · 처리기 · 위임 호스트가 있는지, 토큰이 환경변수로 넘어가지 않는지,
                      계약 6장의 nginx 형식 · 경로가 파일끼리 맞는지

PyYAML 이 없으면 플레이북 구조 시험만 건너뛴다.
"""
import contextlib
import grp
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, "files")
TEMPLATES = os.path.join(HERE, "templates")
METRICS = os.path.join(FILES, "metrics.py")
AGENT_KEY = os.path.join(FILES, "opsloop-agent-key")
ENROLL = os.path.join(FILES, "opsloop-enroll")

try:
    import yaml
except ImportError:
    yaml = None

sys.dont_write_bytecode = True       # files/ 에 __pycache__ 를 만들지 않는다


def load_metrics():
    spec = importlib.util.spec_from_file_location("opsloop_metrics", METRICS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def fake_proc(root, user=100, idle=900, boot="boot-a"):
    os.makedirs(os.path.join(root, "sys", "kernel", "random"), exist_ok=True)
    set_stat(root, user, idle)
    with open(os.path.join(root, "meminfo"), "w") as f:
        f.write("MemTotal:         786432 kB\nMemFree:          100000 kB\nMemAvailable:     393216 kB\n"
                "SwapTotal:        1048576 kB\nSwapFree:         786432 kB\n")
    with open(os.path.join(root, "loadavg"), "w") as f:
        f.write("0.05 0.10 0.12 1/123 4567\n")
    with open(os.path.join(root, "sys", "kernel", "random", "boot_id"), "w") as f:
        f.write(boot + "\n")


def set_stat(root, user, idle):
    # user nice system idle iowait irq softirq steal guest guest_nice
    with open(os.path.join(root, "stat"), "w") as f:
        f.write(f"cpu  {user} 0 0 {idle} 0 0 0 0 0 0\ncpu0 {user} 0 0 {idle} 0 0 0 0 0 0\n")


METRIC_KEYS = ["ts", "host", "seq", "cpu_pct", "mem_used_pct", "mem_avail_mb", "swap_used_pct",
               "disk_root_pct", "load1", "nginx_active", "sshd_active"]


class MetricsTest(unittest.TestCase):
    def setUp(self):
        self.m = load_metrics()
        self.tmp = tempfile.mkdtemp()
        self.proc = os.path.join(self.tmp, "proc")
        self.home = os.path.join(self.tmp, "state")
        os.makedirs(self.home)
        self.log = os.path.join(self.tmp, "metrics.jsonl")
        fake_proc(self.proc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_once(self, active=lambda *u: True):
        with contextlib.redirect_stdout(io.StringIO()):          # 경고 줄은 시험 출력에 섞지 않는다
            return self.m.run(self.log, self.home, self.proc, active=active, sample=0)

    def lines(self):
        with open(self.log, encoding="utf-8") as f:
            return f.read().splitlines()

    def test_줄_모양은_계약_6장과_같음(self):
        self.assertEqual(self.run_once(), 0)
        [raw] = self.lines()
        row = json.loads(raw)
        self.assertEqual(list(row), METRIC_KEYS)
        self.assertNotIn(" ", raw)                               # 구분자에 공백 없음
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00$")
        self.assertEqual(row["host"], socket.gethostname())
        self.assertEqual(row["seq"], 1)
        self.assertEqual(row["mem_used_pct"], 50.0)
        self.assertEqual(row["mem_avail_mb"], 384)
        self.assertEqual(row["swap_used_pct"], 25.0)
        self.assertEqual(row["load1"], 0.05)
        self.assertIs(row["nginx_active"], True)
        self.assertIs(row["sshd_active"], True)
        for k in ("cpu_pct", "mem_used_pct", "swap_used_pct", "disk_root_pct", "load1"):
            self.assertIsInstance(row[k], float, k)
        self.assertIsInstance(row["mem_avail_mb"], int)
        self.assertTrue(0.0 <= row["disk_root_pct"] <= 100.0)

    def test_번호는_실행과_재시작을_넘어_이어짐(self):
        for _ in range(3):
            self.run_once()
        self.m = load_metrics()                                  # 프로세스가 새로 뜬 것과 같다
        self.run_once()
        self.assertEqual([json.loads(x)["seq"] for x in self.lines()], [1, 2, 3, 4])
        self.assertEqual(read(os.path.join(self.home, "metrics.seq")), "4\n")

    def test_번호_파일이_없거나_깨지면_지표_파일에서_이음(self):
        self.run_once()
        self.run_once()
        os.unlink(os.path.join(self.home, "metrics.seq"))
        self.run_once()
        with open(os.path.join(self.home, "metrics.seq"), "w") as f:
            f.write("망가짐")
        self.run_once()
        self.assertEqual([json.loads(x)["seq"] for x in self.lines()], [1, 2, 3, 4])

    def test_CPU_는_지난_실행과의_차분(self):
        self.run_once()                                          # 이전 표본 없음 → 같은 표본 두 번 → 0.0
        self.assertEqual(json.loads(self.lines()[-1])["cpu_pct"], 0.0)
        set_stat(self.proc, user=100 + 30, idle=900 + 70)        # 100 틱 중 30 사용
        self.run_once()
        self.assertEqual(json.loads(self.lines()[-1])["cpu_pct"], 30.0)
        set_stat(self.proc, user=130 + 5, idle=970 + 195)        # 200 틱 중 5 사용
        self.run_once()
        self.assertEqual(json.loads(self.lines()[-1])["cpu_pct"], 2.5)

    def test_재부팅_뒤에는_이전_표본을_쓰지_않음(self):
        self.run_once()
        fake_proc(self.proc, user=10, idle=90, boot="boot-b")   # 카운터가 줄고 부팅 ID 가 바뀜
        self.run_once()
        self.assertEqual(json.loads(self.lines()[-1])["cpu_pct"], 0.0)
        st = json.loads(read(os.path.join(self.home, "metrics.cpu")))
        self.assertEqual((st["boot"], st["total"], st["idle"]), ("boot-b", 100, 90))

    def test_cpu_pct_계산(self):
        self.assertEqual(self.m.cpu_pct((1000, 800), (1200, 850)), 75.0)
        self.assertIsNone(self.m.cpu_pct((1000, 800), (1000, 800)))
        self.assertIsNone(self.m.cpu_pct((1000, 800), (900, 700)))

    def test_서비스_상태(self):
        self.run_once(active=lambda *u: "nginx.service" in u)
        row = json.loads(self.lines()[-1])
        self.assertEqual((row["nginx_active"], row["sshd_active"]), (True, False))

    def test_값을_못_읽으면_줄도_번호도_쓰지_않음(self):
        os.unlink(os.path.join(self.proc, "meminfo"))
        self.assertEqual(self.run_once(), 1)
        self.assertFalse(os.path.exists(self.log))
        self.assertFalse(os.path.exists(os.path.join(self.home, "metrics.seq")))

    def test_실행_파일로_돌려도_한_줄(self):
        env = dict(os.environ, OPSLOOP_METRICS_LOG=self.log, OPSLOOP_HOME=self.home, OPSLOOP_PROC=self.proc)
        r = subprocess.run([sys.executable, METRICS], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [raw] = self.lines()
        self.assertEqual(list(json.loads(raw)), METRIC_KEYS)
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode) & 0o007, 0)   # 남에게는 안 보임


def run_tool(path, env, args=(), stdin=None):
    return subprocess.run([sys.executable, path, *args], env=env, input=stdin,
                          capture_output=True, text=True, timeout=60)


class AgentKeyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "opsloop.token")
        self.group = grp.getgrgid(os.getgid()).gr_name
        self.env = dict(os.environ, OPSLOOP_TOKEN_FILE=self.path, OPSLOOP_TOKEN_GROUP=self.group)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_없을_때만_만들고_sha256_만_냄(self):
        r = run_tool(AGENT_KEY, self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        key = read(self.path)
        self.assertRegex(key, r"^olA_[A-Za-z0-9_-]{43}$")       # 줄바꿈 없이 키만
        h = hashlib.sha256(key.encode()).hexdigest()
        self.assertEqual(r.stdout, h + "\n")
        self.assertIn("새 에이전트 키", r.stderr)
        self.assertNotIn(key, r.stdout + r.stderr)
        self.assertNotIn(key[4:], r.stdout + r.stderr)
        st = os.stat(self.path)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
        self.assertEqual(st.st_gid, os.getgid())
        self.assertEqual([n for n in os.listdir(self.tmp) if n != "opsloop.token"], [])   # 임시 파일 없음

        r2 = run_tool(AGENT_KEY, self.env)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r2.stdout, h + "\n")
        self.assertIn("이미 있다", r2.stderr)
        self.assertNotIn("새 에이전트 키", r2.stderr)
        self.assertEqual(read(self.path), key)

    def test_형식이_틀린_파일은_고치지_않고_실패(self):
        with open(self.path, "w") as f:
            f.write("olE_이건등록토큰")
        r = run_tool(AGENT_KEY, self.env)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")
        self.assertEqual(read(self.path), "olE_이건등록토큰")

    def test_심볼릭_링크는_따라가지_않음(self):
        target = os.path.join(self.tmp, "other")
        with open(target, "w") as f:
            f.write("olA_" + secrets.token_urlsafe(32))
        os.symlink(target, self.path)
        r = run_tool(AGENT_KEY, self.env)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")

    def test_그룹이_없으면_만들지_않음(self):
        env = dict(self.env, OPSLOOP_TOKEN_GROUP="opsloop-없는-그룹")
        r = run_tool(AGENT_KEY, env)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.lexists(self.path))


class FakeGate:
    """응답을 차례로 내주는 가짜 관문. 받은 요청(경로 · 헤더 · 본문)을 기록한다."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                gate.requests.append({"method": "POST", "path": self.path,
                                      "headers": {k.lower(): v for k, v in self.headers.items()},
                                      "body": self.rfile.read(n)})
                code, body, extra = gate.responses.pop(0) if gate.responses else (500, b"", {})
                self.send_response(code)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                gate.requests.append({"method": "GET", "path": self.path, "headers": {}, "body": b""})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def ok(result="ok", code=200, **headers):
    return code, json.dumps({"result": result}).encode(), headers


class EnrollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.key_path = os.path.join(self.tmp, "opsloop.token")
        self.marker = os.path.join(self.tmp, "opsloop.enrolled")
        self.key = "olA_" + secrets.token_urlsafe(32)
        with open(self.key_path, "w") as f:
            f.write(self.key)
        self.sha = hashlib.sha256(self.key.encode()).hexdigest()
        self.token = "olE_" + secrets.token_urlsafe(32)
        self.env = dict(os.environ, OPSLOOP_TOKEN_FILE=self.key_path, OPSLOOP_ENROLL_MARKER=self.marker,
                        OPSLOOP_ENROLL_TRIES="1")
        self.env.pop("OPSLOOP_ENROLL_TOKEN", None)
        self.env.pop("http_proxy", None)
        self.gates = []

    def tearDown(self):
        for g in self.gates:
            g.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def gate(self, *responses):
        g = FakeGate(responses)
        self.gates.append(g)
        return g

    def enroll(self, gate_url, stdin=None, env=None, node="web-01"):
        args = ["--gate", gate_url, "--node", node]
        if stdin is not None:
            args.append("--token-stdin")
        r = run_tool(ENROLL, env or self.env, args, stdin)
        for secret in (self.token, self.key, self.token[4:], self.key[4:]):
            self.assertNotIn(secret, r.stdout + r.stderr)       # 토큰 · 키 원문은 어디에도 나오지 않는다
        return r

    def test_요청_모양과_등록_표식(self):
        g = self.gate(ok())
        r = self.enroll(g.url, stdin=self.token + "\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith("등록했다"))
        self.assertIn(self.sha[:8], r.stdout)
        [req] = g.requests
        self.assertEqual((req["method"], req["path"]), ("POST", "/opsloop/v1/enroll"))
        self.assertEqual(req["headers"]["authorization"], f"Bearer {self.token}")
        self.assertEqual(req["headers"]["content-type"], "application/json")
        self.assertNotIn("x-scope-orgid", req["headers"])
        self.assertLessEqual(len(req["body"]), 4096)
        self.assertEqual(json.loads(req["body"]), {"node_id": "web-01", "agent_sha256": self.sha})
        self.assertEqual(read(self.marker), self.sha + "\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.marker).st_mode), 0o644)

        # 두 번째: 표식이 키와 같으므로 관문에 가지 않는다 (토큰이 없어도 된다)
        r2 = self.enroll(g.url, stdin="")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertTrue(r2.stdout.startswith("이미 등록돼 있다"))
        self.assertEqual(len(g.requests), 1)

    def test_환경변수_토큰(self):
        g = self.gate(ok())
        r = self.enroll(g.url, env=dict(self.env, OPSLOOP_ENROLL_TOKEN=self.token))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(g.requests[0]["headers"]["authorization"], f"Bearer {self.token}")

    def test_키가_바뀌면_다시_등록(self):
        with open(self.marker, "w") as f:
            f.write("0" * 64 + "\n")
        g = self.gate(ok())
        r = self.enroll(g.url, stdin=self.token)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(g.requests), 1)
        self.assertEqual(read(self.marker), self.sha + "\n")

    def test_거부되면_사유를_내고_표식을_쓰지_않음(self):
        for code, reason in ((401, "enroll_used"), (401, "addr_mismatch"), (400, "bad_key")):
            g = self.gate(ok(reason, code))
            r = self.enroll(g.url, stdin=self.token)
            self.assertEqual(r.returncode, 1, reason)
            self.assertIn(reason, r.stdout)
            self.assertFalse(os.path.exists(self.marker))

    def test_이상한_사유는_그대로_옮기지_않음(self):
        g = self.gate((401, b'{"result":"x\\nFAKE LOG LINE"}', {}))
        r = self.enroll(g.url, stdin=self.token)
        self.assertEqual(r.returncode, 1)
        self.assertIn("http_401", r.stdout)
        self.assertNotIn("FAKE", r.stdout + r.stderr)

    def test_재지정은_따르지_않음(self):
        other = self.gate(ok())
        g = self.gate(ok("moved", 302, Location=other.url + "/steal"))
        r = self.enroll(g.url, stdin=self.token)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(other.requests, [])                     # Authorization 이 다른 곳으로 가지 않았다
        self.assertFalse(os.path.exists(self.marker))

    def test_503_은_다시_시도(self):
        g = self.gate(ok("unavailable", 503), ok())
        r = self.enroll(g.url, stdin=self.token, env=dict(self.env, OPSLOOP_ENROLL_TRIES="2"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(len(g.requests), 2)

    def test_관문에_닿지_않으면_3(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = self.enroll(f"http://127.0.0.1:{port}", stdin=self.token)
        self.assertEqual(r.returncode, 3)
        self.assertFalse(os.path.exists(self.marker))

    def test_준비가_안_됐으면_2_이고_보내지_않음(self):
        g = self.gate(ok())
        self.assertEqual(self.enroll(g.url, stdin="").returncode, 2)                  # 토큰 없음
        self.assertEqual(self.enroll(g.url, stdin=self.key).returncode, 2)            # 에이전트 키를 넣음
        self.assertEqual(self.enroll(g.url, stdin="아무거나").returncode, 2)
        self.assertEqual(self.enroll(g.url, stdin=self.token, node="Web 01").returncode, 2)
        self.assertEqual(self.enroll("file:///etc/passwd", stdin=self.token).returncode, 2)
        os.unlink(self.key_path)
        self.assertEqual(self.enroll(g.url, stdin=self.token).returncode, 2)          # 키 없음
        self.assertEqual(g.requests, [])


# --- 플레이북 · 파일 정합 ---

def walk_tasks(tasks):
    for t in tasks or []:
        yield t
        for k in ("block", "rescue", "always"):
            yield from walk_tasks(t.get(k))


def module_of(task):
    skip = {"name", "when", "loop", "register", "notify", "tags", "become", "delegate_to", "changed_when",
            "failed_when", "no_log", "environment", "listen", "block", "rescue", "always", "vars", "run_once",
            "ignore_errors", "until", "retries", "delay"}
    mods = [k for k in task if k not in skip]
    return (mods[0], task[mods[0]]) if mods else (None, None)


def inventory_hosts(path):
    hosts = set()
    for line in read(path).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")) or "=" in line.split()[0]:
            continue
        hosts.add(line.split()[0])
    return hosts


@unittest.skipIf(yaml is None, "PyYAML 없음")
class PlaybookTest(unittest.TestCase):
    PLAYBOOKS = ("web01.yml", "consoles.yml")

    def plays(self, name):
        with open(os.path.join(HERE, name), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_작업이_가리키는_파일이_있음(self):
        used = set()
        for pb in self.PLAYBOOKS:
            for play in self.plays(pb):
                for t in walk_tasks(play.get("tasks", []) + play.get("handlers", [])):
                    mod, args = module_of(t)
                    if mod not in ("ansible.builtin.copy", "ansible.builtin.template") or "src" not in args:
                        continue
                    srcs = t["loop"] if "{{ item }}" in args["src"] else [args["src"]]
                    base = TEMPLATES if mod.endswith("template") else FILES
                    for s in srcs:
                        self.assertTrue(os.path.isfile(os.path.join(base, s)), f"{pb}: {s}")
                        used.add(s)
        unused = set(os.listdir(FILES)) - used - {"__pycache__"}
        self.assertEqual(unused, set(), "플레이북이 쓰지 않는 파일")
        self.assertIn("config.alloy.j2", used)

    def test_처리기와_위임_호스트가_있음(self):
        hosts = inventory_hosts(os.path.join(HERE, "inventory.ini"))
        self.assertTrue({"fw", "web01", "data01", "console-a", "console-b"} <= hosts, hosts)
        for pb in self.PLAYBOOKS:
            for play in self.plays(pb):
                names = set()
                for h in play.get("handlers", []):
                    names.add(h["name"])
                    if "listen" in h:
                        names.add(h["listen"])
                pv = play.get("vars", {})
                for t in walk_tasks(play.get("tasks", [])):
                    notify = t.get("notify")
                    for n in ([notify] if isinstance(notify, str) else notify or []):
                        self.assertIn(n, names, f"{pb}: {t.get('name')}")
                    d = t.get("delegate_to")
                    if d:
                        d = re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: pv[m.group(1)], d)
                        self.assertIn(d, hosts, f"{pb}: {t.get('name')}")

    def test_등록_토큰은_표준_입력과_no_log_로만(self):
        [play] = self.plays("web01.yml")
        seen = 0
        for t in walk_tasks(play["tasks"]):
            self.assertNotIn("OPSLOOP_ENROLL_TOKEN", json.dumps(t.get("environment", {})), t.get("name"))
            mod, args = module_of(t)
            if isinstance(args, dict) and "OPSLOOP_ENROLL_TOKEN" in str(args.get("stdin", "")):
                seen += 1
                self.assertIs(t.get("no_log"), True, t.get("name"))
                self.assertIn("--token-stdin", args["argv"])
        self.assertEqual(seen, 1)

    def test_Alloy_는_등록_뒤에_켜고_구성_창은_항상_닫음(self):
        [play] = self.plays("web01.yml")
        [block] = [t for t in play["tasks"] if "block" in t]
        names = [t.get("name", "") for t in walk_tasks(block["block"])]
        enroll = names.index("자기 등록")
        starts = [i for i, t in enumerate(walk_tasks(block["block"]))
                  if module_of(t)[0] == "ansible.builtin.systemd_service" and module_of(t)[1].get("name") == "alloy"]
        self.assertTrue(starts and min(starts) > enroll)
        self.assertTrue(any("nft" in json.dumps(t, ensure_ascii=False) and t.get("delegate_to")
                            for t in block["always"]))
        self.assertLess(names.index("구성 창 열기 (방화벽 · 30분 뒤 저절로 닫힘)"), names.index("nginx 설치"))


class ConsistencyTest(unittest.TestCase):
    """계약 6장 형식과 파일 사이 경로가 맞는지."""

    def test_nginx_형식은_계약과_글자까지_같음(self):
        want = ('{"ts":"$msec","rid":"$request_id","host":"$hostname","src_ip":"$remote_addr",'
                '"src_port":"$remote_port","dst_port":"$server_port","method":"$request_method",'
                '"uri":"$request_uri","status":"$status","bytes":"$body_bytes_sent","ua":"$http_user_agent",'
                '"rt":"$request_time"}')
        conf = read(os.path.join(FILES, "nginx-opsloop.conf"))
        self.assertIn(f"log_format opsloop escape=json '{want}';", conf)
        self.assertIn("access_log /var/log/nginx/opsloop.json opsloop;", conf)
        self.assertRegex(conf, r"location \^~ /opsloop-first-receipt/ \{\s*return 204;\s*\}")

    def test_Alloy_세_파일과_라벨(self):
        tpl = read(os.path.join(TEMPLATES, "config.alloy.j2"))
        targets = dict((j, p) for p, j in re.findall(r'"__path__" = "([^"]+)", "job" = "(\w+)"', tpl))
        self.assertEqual(targets, {"nginx": "/var/log/nginx/opsloop.json", "auth": "/var/log/auth.log",
                                   "metrics": "/var/log/opsloop/metrics.jsonl"})
        self.assertIn(f'"{targets["metrics"]}"', read(METRICS))   # metrics.py 기본 경로
        self.assertIn('bearer_token_file   = "{{ token_file }}"', tpl)
        self.assertIn('url                 = "{{ gate_url }}/loki/api/v1/push"', tpl)
        self.assertIn("max_backoff_retries = 20", tpl)
        self.assertIn('batch_size          = "1MiB"', tpl)          # 관문 413(4MiB) · Loki 순간 한도(2MB)보다 작게
        self.assertNotIn("tenant_id", tpl)
        self.assertNotIn("stage.", tpl)                          # 줄 내용을 바꾸지 않는다
        self.assertIn(targets["metrics"], read(os.path.join(FILES, "metrics.logrotate")))
        self.assertIn(targets["nginx"], read(os.path.join(FILES, "nginx-opsloop.logrotate")))

    def test_키_경로는_세_곳이_같음(self):
        web = read(os.path.join(HERE, "web01.yml"))
        self.assertIn("token_file: /etc/alloy/opsloop.token", web)
        self.assertIn("enroll_marker: /etc/alloy/opsloop.enrolled", web)
        self.assertIn('"/etc/alloy/opsloop.token"', read(AGENT_KEY))
        self.assertIn('"/etc/alloy/opsloop.token"', read(ENROLL))
        self.assertIn('"/etc/alloy/opsloop.enrolled"', read(ENROLL))
        self.assertIn('alloy_version: "1.19.2-1"', web)

    def test_콘솔_가드(self):
        nft = read(os.path.join(FILES, "console-guard.nft"))
        rules = "\n".join(ln for ln in nft.splitlines() if not ln.lstrip().startswith("#"))
        self.assertNotIn("flush", rules)
        self.assertIn("type filter hook prerouting priority -150; policy accept;", nft)
        order = [nft.index(s) for s in ('iifname "lo" accept', "ip saddr 192.168.50.1 accept",
                                        "ip saddr 192.168.50.0/24 drop", "meta nfproto ipv6 drop")]
        self.assertEqual(order, sorted(order))
        unit = read(os.path.join(FILES, "opsloop-guard.service"))
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/opsloop/console-guard.nft", unit)
        self.assertNotIn("ExecStop", unit.replace("# ExecStop", ""))
        self.assertIn("Before=network-pre.target docker.service", unit)

    def test_지표_타이머는_단조_시계(self):
        # 달력 타이머는 부팅 직후 시계 되돌림(RTC 를 UTC 로 읽어 +9h)에 다음 실행이 8시간 뒤로 밀린다
        timer = read(os.path.join(FILES, "opsloop-metrics.timer"))
        self.assertNotIn("OnCalendar=", timer)
        self.assertIn("OnBootSec=1min", timer)
        self.assertIn("OnUnitActiveSec=1min", timer)
        self.assertIn("AccuracySec=1ms", timer)

    def test_인벤토리(self):
        inv = read(os.path.join(HERE, "inventory.ini"))
        for host, addr in (("fw", "192.168.70.254"), ("web01", "192.168.50.21"), ("data01", "192.168.60.11"),
                           ("console-a", "192.168.50.11"), ("console-b", "192.168.50.12")):
            self.assertRegex(inv, rf"(?m)^{host} ansible_host={re.escape(addr)}\b")
        self.assertIn("node_id=web-01", inv)
        self.assertIn("pipelining = True", read(os.path.join(HERE, "ansible.cfg")))


if __name__ == "__main__":
    unittest.main(verbosity=1)
