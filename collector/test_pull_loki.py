#!/usr/bin/env python3
"""다리(pull_loki.py) 단위 시험.  python3 collector/test_pull_loki.py

가짜 Loki(HTTP 서버) · 가짜 DB(메모리) · 가짜 탐지기를 둔 임시 APP 로 돌린다. psycopg2 가 없어도 돈다.
파서는 계약(7장)대로 만든 가짜로 먼저 돌리고, 저장소에 parser/parse_agent.py 가 있으면 진짜로 한 번 더 돌린다.

보는 것
  - 창과 워터마크: 처음 등록 시각-5분, 그다음 워터마크-5분, 15회째 워터마크-100분. 테넌트 머리글 · 조회식
  - 5000건씩 이어 읽기: 경계에서 같은 시각의 줄을 다시 받아도 한 번만 센다. 겹쳐 읽는 구간도 두 번 세지 않는다
  - 선언하지 않은 job 은 적재하지 않고 undeclared 로만 센다
  - 수신 기록(receipt): 사유별 수 · seq 공백 · first_loaded_at 은 한 번만
  - 원장 (inode, 오프셋) 이어 읽기: 쓰는 중인 줄 · 파일 교체 · 위조 줄 · 관리 원장 주인 · 너무 긴 줄
  - Loki 가 죽어도 원장 적재와 탐지(s1 · w2 · a1 · i2 · c1)는 한다
  - 탐지 순서는 s1 · w2 · a1 · i2 · c1 이고 n1 은 돌리지 않는다. 저장소 규칙 파일의 rule_version 과 맞는다
  - --node --since 재생성: 두 번째 실행 신규 0, DB 를 비운 뒤에는 빠진 만큼만 다시 들어간다
"""
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import types
import unittest
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
REAL_AGENT = os.path.join(REPO, "parser", "parse_agent.py")

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (다리는 PgStore 를 만들 때만 psycopg2 를 부른다)
if "psycopg2" not in sys.modules:
    _fake = types.ModuleType("psycopg2")
    _extras = types.ModuleType("psycopg2.extras")
    _extras.execute_values = lambda *a, **k: []
    _fake.extras = _extras

    # 같은 실행에서 뒤에 불러오는 모듈(collector/nodes.py 등)은 가져올 때 psycopg2.Error 를 읽는다.
    # 가짜에 Error 가 없으면 python -m unittest collector.test_pull_loki collector.test_nodes 가 불러오다 멈춘다
    class _Error(Exception):
        pass

    def _no_connect(*a, **k):
        raise _Error("가짜 psycopg2 는 접속하지 않는다")

    _fake.Error, _fake.connect = _Error, _no_connect
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = _fake, _extras

NS = 10 ** 9
MIN = 60 * NS
T0_DT = datetime(2026, 9, 21, 7, 0, 0, tzinfo=timezone.utc)
T0 = int(T0_DT.timestamp()) * NS
HOST = "opsloop-web-01"
# s1 · w2 · a1 · i2 · c1
RULESETS = ("rules_self.json", "rules_w1.json", "rules_audit.json", "rules_infra.json", "rules_cve.json")

STUB_AGENT = r'''
"""시험용 parse_agent. 계약 7장의 모양만 따른다."""
import hashlib, json, re
from datetime import datetime, timezone
EVENT_COLUMNS = ("line_hash", "ts", "eventid", "session", "src_ip", "src_port", "dst_port", "protocol",
                 "username", "password", "input", "url", "shasum", "duration_ms", "provenance", "message",
                 "http_method", "http_status", "user_agent", "sensor")
METRIC_COLUMNS = ("line_hash", "node_id", "ts", "seq", "cpu_pct", "mem_used_pct", "mem_avail_mb",
                  "swap_used_pct", "disk_root_pct", "load1", "nginx_active", "sshd_active")
HEAD = re.compile(r"(\S+) (\S+) (.*)")
TAG = re.compile(r"(sshd|sshd-session|sshd-auth)\[([0-9]+)\]: (.*)")

def _h(line):
    return hashlib.sha1(line.strip().encode("utf-8", "surrogatepass")).hexdigest()

def _ev(**kw):
    row = dict.fromkeys(EVENT_COLUMNS)
    row.update(kw)
    return row

def _obj(line):
    try:
        v = json.loads(line)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None

def parse(node_id, hostname, job, line, exclusions):
    if job == "nginx":
        v = _obj(line)
        if v is None or "host" not in v:
            return "skip", "malformed"
        if v["host"] != hostname:
            return "skip", "foreign_host"
        return "event", _ev(line_hash=_h(line), ts=datetime.fromtimestamp(float(v["ts"]), timezone.utc),
                            eventid="nginx.request", src_ip=v.get("src_ip"), url=v.get("uri"),
                            http_status=int(v.get("status", 0)), protocol="http", sensor=node_id,
                            provenance="fixture" if v.get("src_ip") in exclusions else "real")
    if job == "auth":
        m = HEAD.fullmatch(line.strip())
        if not m:
            return "skip", "malformed"
        if m[2] != hostname:
            return "skip", "foreign_host"
        t = TAG.fullmatch(m[3])
        if not t:
            return "skip", "unmatched"
        body = t[3]
        if body.startswith("message repeated "):
            return "skip", "repeated"
        if body.startswith("Failed password for invalid user "):
            return "skip", "unmatched"
        for eid, pre in (("sshd.login.failed", "Failed password for "), ("sshd.login.invalid_user", "Invalid user "),
                         ("sshd.login.success", "Accepted ")):
            if body.startswith(pre):
                return "event", _ev(line_hash=_h(line), ts=m[1], eventid=eid, session=f"{node_id}/sshd/{t[2]}",
                                    protocol="ssh", dst_port=22, sensor=node_id, provenance="real")
        return "skip", "unmatched"
    if job == "metrics":
        v = _obj(line)
        if v is None or "host" not in v:
            return "skip", "malformed"
        if v["host"] != hostname:
            return "skip", "foreign_host"
        if not isinstance(v.get("seq"), int) or not isinstance(v.get("ts"), str):
            return "skip", "malformed"
        row = dict.fromkeys(METRIC_COLUMNS)
        row.update(line_hash=_h(line), node_id=node_id, ts=v["ts"], seq=v["seq"])
        return "metric", row
    return "skip", "undeclared"

def parse_collector(line):
    v = _obj(line)
    if v is None or not str(v.get("eventid", "")).startswith("collector.") or "ts" not in v:
        return "skip", "malformed"
    return "event", _ev(line_hash=_h(line), ts=v["ts"], eventid=v["eventid"], src_ip=v.get("src_ip"),
                        sensor="collector", provenance="real")
'''

FAKE_DETECT = r'''import os, sys
args = [os.path.basename(a) if a.endswith(".json") else a for a in sys.argv[1:]]
with open(os.environ["OPSLOOP_TEST_DETECT_LOG"], "a") as f:
    f.write(" ".join(args) + (" db" if os.environ.get("DATABASE_URL") else " nodb") + "\n")
'''


# ----------------------------------------------------------------------
#  가짜 Loki · 가짜 DB
# ----------------------------------------------------------------------

class FakeLoki:
    """query_range 만 흉내 낸다. start 포함 · end 제외, forward, 전체에서 이른 limit 건, 스트림별로 묶는다."""

    def __init__(self):
        self.data = {}
        self.requests = []
        self.fail_over = None        # limit 이 이 값보다 크면 500 (Loki 내부 gRPC 한도 흉내)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                tenant = self.headers.get("X-Scope-OrgID")
                outer.requests.append({"path": u.path, "tenant": tenant, **q})
                start, end, limit = int(q["start"]), int(q["end"]), int(q["limit"])
                if outer.fail_over is not None and limit > outer.fail_over:
                    body = b"rpc error: code = ResourceExhausted desc = grpc: received message larger than max"
                    self.send_response(500)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                rows = sorted((e for e in outer.data.get(tenant, []) if start <= e[1] < end), key=lambda e: e[1])
                streams = {}
                for labels, ts, line in rows[:limit]:
                    k = json.dumps(labels, sort_keys=True)
                    streams.setdefault(k, {"stream": labels, "values": []})["values"].append([str(ts), line])
                body = json.dumps({"status": "success",
                                   "data": {"resultType": "streams", "result": list(streams.values())}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.up = True

    def add(self, tenant, job, ts, line, **labels):
        labels = dict(labels)
        if job is not None:
            labels["job"] = job
        self.data.setdefault(tenant, []).append((labels, ts, line))

    def stop(self):
        if self.up:
            self.srv.shutdown()
            self.srv.server_close()
            self.up = False

    def of(self, tenant):
        return [r for r in self.requests if r["tenant"] == tenant]


class FakeDB:
    def __init__(self):
        self.nodes = {}
        self.events = {}
        self.node_metrics = {}
        self.clock = 0
        self.reject = set()            # DB 가 값 문제로 받지 않는 line_hash


class FakeStore:
    """PgStore 와 같은 메서드. 바꾼 것을 되돌림 기록에 남겨 rollback 을 흉내 낸다."""

    def __init__(self, db, merge):
        self.db, self.merge, self.undo = db, merge, []

    def nodes(self, node=None):
        return [(nid, n["hostname"], list(n["logs"]), n["registered_at"])
                for nid, n in sorted(self.db.nodes.items())
                if n["status"] in ("active", "revoked") and n["logs"] and (node is None or nid == node)]

    def insert(self, table, cols, rows):
        t = getattr(self.db, table)
        new, bad = set(), set()
        for row in rows:
            r = dict(zip(cols, row))
            h = r["line_hash"]
            if h in self.db.reject:
                bad.add(h)
            elif h not in t:
                t[h] = r
                self.undo.append((table, h))
                new.add(h)
        return new, bad

    def update_receipt(self, node_id, deltas, declared, loaded):
        n = self.db.nodes[node_id]
        self.undo.append(("node", node_id, copy.deepcopy(n)))
        gaps = None
        if "metrics" in deltas:
            seqs = [r["seq"] for r in self.db.node_metrics.values() if r["node_id"] == node_id and r["seq"] is not None]
            gaps = (max(seqs) - min(seqs) + 1 - len(set(seqs))) if seqs else 0
        n["receipt"] = self.merge(n["receipt"], deltas, declared, gaps)
        if loaded:
            self.db.clock += 1
            n["first_loaded_at"] = n["first_loaded_at"] or self.db.clock
            n["last_loaded_at"] = n["last_seen_at"] = self.db.clock

    def savepoint(self):
        self._mark = len(self.undo)

    def release(self):
        pass

    def rollback_to(self):
        while len(self.undo) > self._mark:
            u = self.undo.pop()
            if u[0] == "node":
                self.db.nodes[u[1]] = u[2]

    def commit(self):
        self.undo = []

    def rollback(self):
        for u in reversed(self.undo):
            if u[0] == "node":
                self.db.nodes[u[1]] = u[2]
            else:
                getattr(self.db, u[0]).pop(u[1], None)
        self.undo = []

    def close(self):
        self.rollback()


# ----------------------------------------------------------------------
#  줄 만들기
# ----------------------------------------------------------------------

def nginx_line(i, host=HOST, uri="/", status="200", ts=1789977600.0):
    return json.dumps({"ts": f"{ts + i / 1000:.3f}", "rid": f"{i:032x}", "host": host, "src_ip": "192.168.50.1",
                       "src_port": "40000", "dst_port": "80", "method": "GET", "uri": uri, "status": status,
                       "bytes": "0", "ua": "curl/8.5.0", "rt": "0.001"}, separators=(",", ":"))


def auth_line(body, host=HOST, pid=1234, sec=31):
    return f"2026-09-21T16:54:{sec:02d}.123456+09:00 {host} sshd[{pid}]: {body}"


def metrics_line(seq, host=HOST):
    return json.dumps({"ts": f"2026-09-21T07:{seq % 60:02d}:00.123456+00:00", "host": host, "seq": seq,
                       "cpu_pct": 1.2, "mem_used_pct": 40.1, "mem_avail_mb": 400, "swap_used_pct": 0.0,
                       "disk_root_pct": 23.0, "load1": 0.05, "nginx_active": True, "sshd_active": True},
                      separators=(",", ":"))


def gate_line(seq, reason="unknown", eventid="collector.agent.rejected"):
    return json.dumps({"ts": f"2026-09-21T07:00:{seq % 60:02d}.000001+00:00", "boot": "b7c1e2", "seq": seq,
                       "eventid": eventid, "src_ip": "192.168.50.21", "dst_port": 3101,
                       "path": "/loki/api/v1/push", "reason": reason, "count": 1, "distinct_fp": 1,
                       "fps": ["3f9a1c0e"], "ua": "Alloy/v1.19.2"}, ensure_ascii=False)


def admin_line(eventid="collector.admin.issue"):
    return json.dumps({"ts": "2026-09-21T07:00:00.000001+00:00", "eventid": eventid, "node_id": "web-01",
                       "issued_by": "ops", "expires_at": "2026-09-21T08:00:00+00:00"})


def load_bridge():
    spec = importlib.util.spec_from_file_location("pull_loki_under_test", os.path.join(HERE, "pull_loki.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ----------------------------------------------------------------------
#  시험
# ----------------------------------------------------------------------

class BridgeTest(unittest.TestCase):
    AGENT = "stub"

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="pull-loki-")
        self.addCleanup(shutil.rmtree, self.t, True)
        self.app = os.path.join(self.t, "app")
        for d in ("parser", "detector"):
            os.makedirs(os.path.join(self.app, d))
        agent = os.path.join(self.app, "parser", "parse_agent.py")
        if self.AGENT == "real":
            shutil.copy(REAL_AGENT, agent)
        else:
            with open(agent, "w", encoding="utf-8") as f:
                f.write(STUB_AGENT)
        with open(os.path.join(self.app, "parser", "exclusions.txt"), "w") as f:
            f.write("127.0.0.1   # 첫 수신 탐침\n")
        with open(os.path.join(self.app, "detector", "detect.py"), "w") as f:
            f.write(FAKE_DETECT)
        for name in RULESETS:
            with open(os.path.join(self.app, "detector", name), "w") as f:
                f.write("{}\n")
        self.home = os.path.join(self.t, "home")
        self.gate = os.path.join(self.t, "gate")
        os.makedirs(self.home)
        os.makedirs(self.gate)
        self.detect_log = os.path.join(self.t, "detect.log")
        open(self.detect_log, "w").close()
        dbenv = os.path.join(self.t, "collector.env")
        with open(dbenv, "w") as f:
            f.write("DATABASE_URL=postgresql://opsloop:x@127.0.0.1:5432/opsloop\n")
        self._env = {k: os.environ.get(k) for k in ("DATABASE_URL", "OPSLOOP_TEST_DETECT_LOG")}
        os.environ.pop("DATABASE_URL", None)
        os.environ["OPSLOOP_TEST_DETECT_LOG"] = self.detect_log
        self.addCleanup(self._restore_env)

        self.loki = FakeLoki()
        self.addCleanup(self.loki.stop)
        self.db = FakeDB()
        self.clock = T0 + 10 * MIN
        self.logs = []
        m = self.m = load_bridge()
        self.admin = os.path.join(self.t, "admin")
        os.makedirs(self.admin, exist_ok=True)
        m.APP, m.HOME, m.GATE_DIR, m.DB_ENV, m.LOKI_URL = self.app, self.home, self.gate, dbenv, self.loki.url
        m.ADMIN_DIR = self.admin
        m.connect = lambda url: FakeStore(self.db, m.merge_receipt)
        m.now_ns = lambda: self.clock
        m.log = lambda msg, level=6: self.logs.append((level, msg))
        m.ADMIN_UID = os.getuid()

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def add_node(self, node_id="web-01", logs=("nginx", "auth", "metrics"), status="active", registered=T0_DT):
        self.db.nodes[node_id] = {"hostname": HOST, "logs": list(logs), "status": status, "registered_at": registered,
                                  "receipt": {}, "first_loaded_at": None, "last_loaded_at": None, "last_seen_at": None}

    def run_bridge(self, node=None, since=None):
        return self.m.run(node, self.m.parse_since(since) if since else None)

    def receipt(self, node_id="web-01"):
        return self.db.nodes[node_id]["receipt"]

    def state(self):
        with open(os.path.join(self.home, "agents-state.json")) as f:
            return json.load(f)

    def detects(self):
        with open(self.detect_log) as f:
            return f.read().splitlines()

    def events(self, sensor=None):
        return [e for e in self.db.events.values() if sensor is None or e["sensor"] == sensor]

    def write_ledger(self, name, text, mode="a", folder=None):
        # 관리 원장(admin-*)은 root 전용 폴더에, 관문 원장은 관문 폴더에 둔다
        folder = folder or (self.admin if name.startswith("admin-") else self.gate)
        with open(os.path.join(folder, name), mode, encoding="utf-8") as f:
            f.write(text)

    # ------------------------------------------------------------------

    def test_창과_워터마크(self):
        self.add_node()
        self.add_node("probe-01", status="pending")          # 등록 전 노드는 읽지 않는다
        self.add_node("old-01", status="revoked")            # 폐기한 노드는 남은 줄을 계속 읽는다
        self.assertEqual(self.run_bridge(), 0)
        [r] = self.loki.of("web-01")
        self.assertEqual((r["path"], r["query"], r["direction"], r["limit"]),
                         ("/loki/api/v1/query_range", '{job=~".+"}', "forward", "5000"))
        self.assertEqual(int(r["start"]), T0 - 5 * MIN)     # 처음: 등록 시각 앞 5분부터
        self.assertEqual(int(r["end"]), self.clock - 10 * NS)
        self.assertEqual(self.loki.of("probe-01"), [])
        self.assertEqual(len(self.loki.of("old-01")), 1)
        end = int(r["end"])
        self.assertEqual(self.state()["nodes"]["web-01"]["watermark"], end)

        self.clock += MIN
        self.assertEqual(self.run_bridge(), 0)
        r = self.loki.of("web-01")[-1]
        self.assertEqual(int(r["start"]), end - 5 * MIN)     # 평소: 워터마크-5분
        self.assertEqual(int(r["end"]), self.clock - 10 * NS)
        for _ in range(3, 15):
            end = self.clock - 10 * NS
            self.clock += MIN
            self.assertEqual(self.run_bridge(), 0)
            self.assertEqual(int(self.loki.of("web-01")[-1]["start"]), end - 5 * MIN)
        end = self.clock - 10 * NS
        self.clock += MIN
        self.assertEqual(self.run_bridge(), 0)               # 15회째
        self.assertEqual(int(self.loki.of("web-01")[-1]["start"]), end - self.m.DEEP)
        self.assertEqual(self.state()["runs"], 15)
        self.assertEqual(self.state()["nodes"]["web-01"]["watermark"], self.clock - 10 * NS)
        self.assertEqual(len(self.detects()), 15 * len(RULESETS))

    def test_5000건씩_이어_읽고_겹친_구간은_두번_세지_않음(self):
        self.add_node()
        base = self.clock - 3 * MIN
        n = 12003
        same = base + 4998 * 10 ** 7
        for i in range(n):
            ts = same if 4998 <= i <= 5001 else base + i * 10 ** 7      # 첫 쪽 경계에 같은 시각 네 줄
            self.loki.add("web-01", "nginx", ts, nginx_line(i), filename="/var/log/nginx/opsloop.json")
        self.assertEqual(self.run_bridge(), 0)
        reqs = self.loki.of("web-01")
        self.assertEqual(len(reqs), 3)
        self.assertEqual(int(reqs[1]["start"]), same)       # 마지막 시각부터 이어 읽는다
        self.assertEqual(len(self.events()), n)
        rc = self.receipt()["nginx"]
        self.assertEqual((rc["lines"], rc["new"]), (n, n))

        self.clock += MIN                                     # 다음 회차는 5분을 겹쳐 모두 다시 읽는다
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.loki.of("web-01")), 6)
        rc = self.receipt()["nginx"]
        self.assertEqual((rc["lines"], rc["new"]), (n, n))

        self.loki.add("web-01", "nginx", self.clock - 30 * NS, nginx_line(n))
        self.clock += MIN
        self.assertEqual(self.run_bridge(), 0)
        rc = self.receipt()["nginx"]
        self.assertEqual((rc["lines"], rc["new"]), (n + 1, n + 1))

    def test_선언하지_않은_job_은_적재하지_않음(self):
        self.add_node(logs=("nginx", "auth"))
        ts = self.clock - 2 * MIN
        self.loki.add("web-01", "nginx", ts, nginx_line(1))
        self.loki.add("web-01", "nginx", ts + 1, nginx_line(2))
        self.loki.add("web-01", "metrics", ts + 2, metrics_line(1))
        self.loki.add("web-01", "metrics", ts + 3, metrics_line(2))
        self.loki.add("web-01", "evil\nx", ts + 4, nginx_line(3))            # 라벨 값도 노드가 정한다
        self.loki.add("web-01", None, ts + 5, nginx_line(4), filename="/etc/passwd")
        self.assertEqual(self.run_bridge(), 0)
        rc = self.receipt()
        self.assertEqual((rc["nginx"]["lines"], rc["nginx"]["new"]), (2, 2))
        self.assertEqual((rc["metrics"]["lines"], rc["metrics"]["undeclared"], rc["metrics"]["new"]), (2, 2, 0))
        self.assertEqual((rc["_invalid"]["lines"], rc["_invalid"]["undeclared"]), (2, 2))
        self.assertEqual(self.db.node_metrics, {})
        self.assertEqual(len(self.events()), 2)

    def test_수신_기록(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        lines = [
            ("nginx", nginx_line(1)), ("nginx", nginx_line(2)), ("nginx", "{bad"),
            ("nginx", nginx_line(3, host="opsloop-base")),
            ("auth", auth_line("Failed password for root from 1.2.3.4 port 5555 ssh2", sec=1)),
            ("auth", auth_line("Accepted publickey for ops from 192.168.70.1 port 50000 ssh2: ED25519 SHA256:x", sec=2)),
            ("auth", auth_line("message repeated 3 times: [ Failed password for root from 1.2.3.4 port 5555 ssh2]", sec=3)),
            ("auth", auth_line("Connection closed by 1.2.3.4 port 5555 [preauth]", sec=4)),
            ("auth", auth_line("Failed password for root from 1.2.3.4 port 5555 ssh2", host="opsloop-base", sec=5)),
            ("metrics", metrics_line(1)), ("metrics", metrics_line(2)), ("metrics", metrics_line(4)),
            ("metrics", metrics_line(5, host="opsloop-base")),
        ]
        for i, (job, line) in enumerate(lines):
            self.loki.add("web-01", job, ts + i * NS, line)
        self.assertEqual(self.run_bridge(), 0)
        rc = self.receipt()
        pick = lambda j, *ks: tuple(rc[j][k] for k in ks)
        self.assertEqual(pick("nginx", "lines", "new", "malformed", "foreign_host"), (4, 2, 1, 1))
        self.assertEqual(pick("auth", "lines", "new", "repeated", "unmatched", "foreign_host"), (5, 2, 1, 1, 1))
        self.assertEqual(pick("metrics", "lines", "new", "foreign_host", "seq_gaps"), (4, 3, 1, 1))
        self.assertEqual(rc["nginx"]["first_line_at"], self.m.iso(ts))
        self.assertEqual(rc["metrics"]["last_line_at"], self.m.iso(ts + 12 * NS))
        self.assertEqual(sorted(e["eventid"] for e in self.events()),
                         ["nginx.request", "nginx.request", "sshd.login.failed", "sshd.login.success"])
        node = self.db.nodes["web-01"]
        first = node["first_loaded_at"]
        self.assertIsNotNone(first)

        self.loki.add("web-01", "metrics", self.clock + 20 * NS, metrics_line(3))     # 늦게 온 지표가 공백을 메운다
        self.clock += MIN
        self.assertEqual(self.run_bridge(), 0)
        rc = self.receipt()
        self.assertEqual(pick("metrics", "lines", "new", "seq_gaps"), (5, 4, 0))
        self.assertEqual(rc["nginx"]["first_line_at"], self.m.iso(ts))
        self.assertEqual(node["first_loaded_at"], first)                # 처음 적재 시각은 한 번만
        self.assertGreater(node["last_loaded_at"], first)

    def test_DB_가_받지_않은_행은_malformed_로_세고_나머지는_넣음(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        for i in range(3):
            self.loki.add("web-01", "nginx", ts + i, nginx_line(i))
        self.db.reject.add(hashlib.sha1(nginx_line(1).encode()).hexdigest())
        self.assertEqual(self.run_bridge(), 0)
        rc = self.receipt()["nginx"]
        self.assertEqual((rc["lines"], rc["new"], rc["malformed"]), (3, 2, 1))
        self.assertEqual(self.state()["nodes"]["web-01"]["watermark"], self.clock - 10 * NS)

    def test_원장_이어_읽기(self):
        name = "collector-2026-09-21.jsonl"
        self.write_ledger(name, gate_line(1) + "\n" + gate_line(2) + "\n")
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 2)
        size = os.path.getsize(os.path.join(self.gate, name))
        led = self.state()["ledgers"][name]
        self.assertEqual((led["ino"], led["offset"]), (os.stat(os.path.join(self.gate, name)).st_ino, size))

        self.write_ledger(name, gate_line(3))                              # 쓰는 중인 줄 (줄바꿈 없음)
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 2)
        self.assertEqual(self.state()["ledgers"][name]["offset"], size)
        self.write_ledger(name, "\n")
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 3)

        self.write_ledger(name, admin_line() + "\n")                       # 관문 원장에 끼운 관리 줄
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 3)
        self.assertTrue(any("위조 의심" in msg for _lv, msg in self.logs))

        # 파일이 바뀌면(inode) 처음부터 다시 읽는다. 이미 넣은 줄은 line_hash 로 걸러진다
        path = os.path.join(self.gate, name)
        with open(path, encoding="utf-8") as f:
            old = f.read()
        tmp = path + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(old + gate_line(4) + "\n")
        os.replace(tmp, path)
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 4)

        # 너무 긴 줄은 건너뛰고 다음 줄은 읽는다
        self.m.MAX_LINE = 400
        self.write_ledger(name, '{"x":"' + "a" * 2000 + '"}\n' + gate_line(5) + "\n")
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events("collector")), 5)

        admin = "admin-2026-09-21.jsonl"
        self.write_ledger(admin, admin_line() + "\n" + gate_line(6) + "\n")   # 관리 원장에 관문 줄은 받지 않는다
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual([e["eventid"] for e in self.events("collector") if e["eventid"].startswith("collector.admin.")],
                         ["collector.admin.issue"])
        self.assertEqual(len(self.events("collector")), 6)

        self.m.ADMIN_UID = os.getuid() + 1                                  # root 가 쓰지 않은 관리 원장
        self.write_ledger(admin, admin_line("collector.admin.revoke") + "\n")
        self.assertEqual(self.run_bridge(), 1)
        self.assertEqual(len(self.events("collector")), 6)

        # 관문 폴더에 둔 admin-* 는 관문이 만든 위조다. 읽지 않는다
        self.m.ADMIN_UID = os.getuid()
        self.assertEqual(self.run_bridge(), 0)                              # 앞에서 거부했던 관리 원장 줄을 이제 읽는다
        self.write_ledger("admin-2026-09-22.jsonl", admin_line("collector.admin.revoke") + "\n", folder=self.gate)
        before = len(self.events("collector"))
        self.run_bridge()
        self.assertEqual(len(self.events("collector")), before)
        self.assertTrue(any("제자리" in msg for _lv, msg in self.logs))
        os.unlink(os.path.join(self.gate, "admin-2026-09-22.jsonl"))

        os.unlink(path)                                                     # 지운 파일은 상태에서도 뺀다
        self.assertEqual(self.run_bridge(), 0)
        self.assertNotIn(name, self.state()["ledgers"])

    def test_원장_심볼릭_링크는_읽지_않음(self):
        secret = os.path.join(self.t, "collector.env.copy")
        with open(secret, "w") as f:
            f.write(gate_line(1) + "\n")
        os.symlink(secret, os.path.join(self.gate, "collector-2026-09-22.jsonl"))
        self.assertEqual(self.run_bridge(), 1)
        self.assertEqual(self.events(), [])

    def test_Loki_가_죽어도_원장과_탐지는_한다(self):
        self.add_node()
        self.write_ledger("collector-2026-09-21.jsonl", gate_line(1) + "\n")
        self.loki.stop()
        self.assertEqual(self.run_bridge(), 1)
        self.assertEqual(len(self.events("collector")), 1)
        self.assertEqual(self.detects(), ["--rules rules_self.json --run --quiet db",
                                          "--rules rules_w1.json --run --quiet db",
                                          "--rules rules_audit.json --run --quiet db",
                                          "--rules rules_infra.json --run --quiet db",
                                          "--rules rules_cve.json --run --quiet db"])
        self.assertNotIn("watermark", self.state()["nodes"].get("web-01", {}))
        self.assertTrue(any("Loki 조회 실패" in msg for _lv, msg in self.logs))

    def test_파서가_없어도_탐지는_한다(self):
        self.add_node()
        os.unlink(os.path.join(self.app, "parser", "parse_agent.py"))
        self.assertEqual(self.run_bridge(), 1)
        self.assertEqual(len(self.detects()), len(RULESETS))
        self.assertEqual(self.loki.requests, [])

    def test_탐지_하나가_실패해도_나머지는_돈다(self):
        self.add_node()
        with open(os.path.join(self.app, "detector", "detect.py"), "a") as f:
            f.write("sys.exit(3 if sys.argv[2].endswith('rules_w1.json') else 0)\n")
        self.assertEqual(self.run_bridge(), 1)
        self.assertEqual([d.split()[1] for d in self.detects()], list(RULESETS))
        self.assertTrue(any(lv == 3 and "탐지 실패 rules_w1.json (3)" in msg for lv, msg in self.logs))

    def test_재생성_두번째_신규_0(self):
        self.add_node()
        ts = T0 + MIN
        for i in range(3):
            self.loki.add("web-01", "nginx", ts + i * NS, nginx_line(i))
        self.loki.add("web-01", "auth", ts + 5 * NS, auth_line("Invalid user admin from 1.2.3.4 port 5555"))
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events()), 4)
        before = copy.deepcopy(self.receipt())

        self.clock += MIN
        self.assertEqual(self.run_bridge("web-01", "2026-09-21T06:00:00Z"), 0)
        self.assertEqual(int(self.loki.of("web-01")[-1]["start"]), T0 - 60 * MIN)
        self.assertEqual(self.receipt(), before)                          # 신규 0, 줄 수도 그대로
        self.assertTrue(any("신규 0" in msg for _lv, msg in self.logs))

        self.db.events.clear()                                            # DB 를 백업에서 복원해 events 가 빠졌다
        self.assertEqual(self.run_bridge("web-01", "2026-09-21T06:00:00Z"), 0)
        self.assertEqual(len(self.events()), 4)
        self.assertEqual(self.receipt()["nginx"]["new"], before["nginx"]["new"] + 3)
        self.assertEqual(self.receipt()["nginx"]["lines"], before["nginx"]["lines"])
        again = copy.deepcopy(self.receipt())
        self.assertEqual(self.run_bridge("web-01", "2026-09-21T06:00:00Z"), 0)
        self.assertEqual(self.receipt(), again)
        self.assertEqual(self.run_bridge("nobody", "2026-09-21T06:00:00Z"), 1)

    def test_큰_응답은_한도를_줄여_다시_묻는다(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        for i in range(20):
            self.loki.add("web-01", "nginx", ts + i, nginx_line(i))
        self.m.MAX_RESP = 3000
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events()), 20)
        self.assertEqual(self.receipt()["nginx"]["lines"], 20)
        self.assertEqual(self.loki.of("web-01")[-1]["limit"], "5")


    def test_Loki_5xx_면_건수를_줄여_다시_묻는다(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        for i in range(20):
            self.loki.add("web-01", "nginx", ts + i, nginx_line(i))
        self.loki.fail_over = 50
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events()), 20)
        self.assertEqual(self.loki.of("web-01")[-1]["limit"], "50")

    def test_가장_작은_건수에서도_5xx_면_실패하고_줄은_건너뛰지_않는다(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        self.loki.add("web-01", "nginx", ts, nginx_line(1))
        self.loki.fail_over = 0
        self.assertNotEqual(self.run_bridge(), 0)
        self.loki.fail_over = None
        self.assertEqual(self.run_bridge(), 0)
        self.assertEqual(len(self.events()), 1)

    def test_지표_번호_극단값에도_적재는_계속(self):
        self.add_node()
        ts = self.clock - 2 * MIN
        for i, seq in enumerate((0, 2**63 - 1, 5)):
            self.loki.add("web-01", "metrics", ts + i, metrics_line(seq))
        self.assertEqual(self.run_bridge(), 0)
        if getattr(self, "AGENT", None) == "real":            # 실제 파서는 2^53 을 넘는 번호를 받지 않는다
            seqs = sorted(r["seq"] for r in self.db.node_metrics.values())
            self.assertEqual(seqs, [0, 5])


class RealAgentTest(BridgeTest):
    """저장소의 parser/parse_agent.py 로 같은 시험을 돈다 (계약 7장과 다리가 맞물리는지)."""
    AGENT = "real"

    def setUp(self):
        if not os.path.exists(REAL_AGENT):
            self.skipTest("parser/parse_agent.py 가 아직 없다")
        super().setUp()


class RulesetTest(unittest.TestCase):
    """다리가 돌리는 규칙 파일. 시험 안의 가짜 파일이 아니라 저장소의 진짜 파일을 본다."""

    def test_탐지_순서는_s1_w2_a1_i2_c1(self):
        m = load_bridge()
        self.assertEqual(m.RULESETS, RULESETS)
        versions = []
        for name in m.RULESETS:
            with open(os.path.join(REPO, "detector", name), encoding="utf-8") as f:
                versions.append(json.load(f)["rule_version"])
        self.assertEqual(versions, ["s1", "w2", "a1", "i2", "c1"])

    def test_c1_은_웹_요청_두_발생원을_본다(self):
        # 다리가 전 기간을 매분 다시 보므로 5분 적재기가 넣은 디코이 요청도 여기서 잡힌다. 풀러에는 넣지 않는다
        with open(os.path.join(REPO, "detector", "rules_cve.json"), encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual([(r["id"], r["type"]) for r in doc["rules"]],
                         [("R105", "url_signature"), ("R106", "url_signature")])
        for rule in doc["rules"]:
            self.assertEqual(rule["params"]["eventids"], ["nginx.request", "decoy.request"])
            self.assertNotIn("sensors", rule["params"])

    def test_늦게_들어온_이른_디코이_요청의_한계가_적혀_있다(self):
        # 더 이른 디코이 요청이 늦게 들어오면 새 키 사건이 생기고 먼저 뜬 사건이 남는다(w2 R102 와 같은 구조적 한계).
        # 코드로 막지 않고 두 곳에 적는다. 동작은 detector/test_detect_sensors.py 의 DB 시험이 고정한다
        with open(os.path.join(REPO, "detector", "rules_cve.json"), encoding="utf-8") as f:
            note = json.load(f)["note"]
        doc = " ".join(load_bridge().__doc__.split())
        for text in (note, doc):
            for word in ("새 키", "미판정", "R102", "억제가 없어"):
                self.assertIn(word, text)

    def test_n1_은_돌리지_않는다(self):
        # 파일은 남긴다 (기존 시험 · rule_versions 이력). w1 R101 이 흡수했다
        self.assertNotIn("rules_node.json", load_bridge().RULESETS)
        self.assertTrue(os.path.exists(os.path.join(REPO, "detector", "rules_node.json")))


class ReceiptMergeTest(unittest.TestCase):
    def setUp(self):
        self.m = load_bridge()

    def test_누적과_처음_시각(self):
        d = self.m.new_delta()
        d.update(lines=2, new=1, malformed=1, first=T0, last=T0 + NS)
        r = self.m.merge_receipt({}, {"nginx": d}, ("nginx",))
        d2 = self.m.new_delta()
        d2.update(lines=1, first=T0 + 5 * NS, last=T0 + 5 * NS)
        r = self.m.merge_receipt(r, {"nginx": d2}, ("nginx",))
        self.assertEqual((r["nginx"]["lines"], r["nginx"]["new"], r["nginx"]["malformed"]), (3, 1, 1))
        self.assertEqual(r["nginx"]["first_line_at"], "2026-09-21T07:00:00.000000+00:00")
        self.assertEqual(r["nginx"]["last_line_at"], "2026-09-21T07:00:05.000000+00:00")

    def test_선언_밖_job_은_상한에서_묶는다(self):
        r = {}
        for i in range(40):
            d = self.m.new_delta()
            d["undeclared"] = d["lines"] = 1
            r = self.m.merge_receipt(r, {f"j{i}": d}, ("nginx",))
        self.assertEqual(len(r), self.m.JOB_CAP + 1)
        self.assertEqual(r["_other"]["undeclared"], 40 - self.m.JOB_CAP)

    def test_깨진_기존_값은_0_으로(self):
        d = self.m.new_delta()
        d["lines"] = 1
        r = self.m.merge_receipt({"auth": {"lines": "x", "new": True}, "nginx": 5}, {"auth": d, "nginx": d})
        self.assertEqual((r["auth"]["lines"], r["auth"]["new"], r["nginx"]["lines"]), (1, 0, 1))


class PgStoreTest(unittest.TestCase):
    """실제 DB 없이 PgStore 의 SQL 흐름만 본다 (자리표시자 수 · 저장점 · 거부 행 분리 · receipt 갱신)."""

    def setUp(self):
        class DataError(Exception):
            pass

        class Cursor:
            def __init__(cur):
                cur.sql, cur._rows = [], []

            def execute(cur, sql, params=None):
                cur.sql.append((sql, params))
                if params is not None:
                    self.assertEqual(sql.count("%s"), len(params))
                if sql.startswith("INSERT"):
                    if "BAD" in params:
                        raise DataError("invalid input syntax for type inet")
                    cur._rows = [(params[0],)]
                elif sql.startswith("SELECT receipt"):
                    cur._rows = [({"metrics": {"lines": 1}},)]
                elif "max(seq)" in sql:
                    cur._rows = [(2,)]
                elif sql.startswith("SELECT node_id"):
                    cur._rows = [("web-01", HOST, ["nginx"], T0_DT)]

            def fetchone(cur):
                return cur._rows[0] if cur._rows else None

            def fetchall(cur):
                return cur._rows

        class Conn:
            def __init__(conn):
                conn.cur = Cursor()
                conn.commits = 0

            def cursor(conn):
                return conn.cur

            def commit(conn):
                conn.commits += 1

        def execute_values(cur, sql, rows, page_size=100, fetch=False):
            self.assertIn("VALUES %s", sql)
            self.assertTrue(fetch)
            if any("BAD" in r for r in rows):
                raise DataError("bad")
            return [(r[0],) for r in rows]

        pg = types.ModuleType("psycopg2")
        ex = types.ModuleType("psycopg2.extras")
        pg.DataError, pg.IntegrityError, pg.extras = DataError, type("IntegrityError", (Exception,), {}), ex
        pg.connect = lambda url, connect_timeout=None: Conn()
        ex.execute_values = execute_values
        self._saved = (sys.modules.get("psycopg2"), sys.modules.get("psycopg2.extras"))
        sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = pg, ex
        self.addCleanup(self._restore)
        self.m = load_bridge()

    def _restore(self):
        sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = self._saved

    def test_묶음이_실패하면_한_줄씩(self):
        s = self.m.PgStore("postgresql://x")
        cols = ("line_hash", "src_ip")
        new, bad = s.insert("events", cols, [("h1", "1.2.3.4"), ("h2", "BAD"), ("h3", None)])
        self.assertEqual((new, bad), ({"h1", "h3"}, {"h2"}))
        sqls = [q for q, _p in s.cur.sql]
        self.assertIn("ROLLBACK TO SAVEPOINT ol_many", sqls)
        self.assertEqual(sqls.count("ROLLBACK TO SAVEPOINT ol_one"), 1)
        new, bad = s.insert("node_metrics", cols, [("h4", "1.2.3.4")])
        self.assertEqual((new, bad), ({"h4"}, set()))

    def test_노드와_receipt(self):
        s = self.m.PgStore("postgresql://x")
        self.assertEqual(s.nodes("web-01"), [("web-01", HOST, ["nginx"], T0_DT)])
        d = self.m.new_delta()
        d["lines"] = d["new"] = 1
        s.update_receipt("web-01", {"metrics": d}, ["metrics"], True)
        sql, params = s.cur.sql[-1]
        self.assertTrue(sql.startswith("UPDATE nodes SET receipt"))
        rec = json.loads(params[0])
        self.assertEqual((rec["metrics"]["lines"], rec["metrics"]["seq_gaps"]), (2, 2))
        self.assertEqual(params[1:], (True, True, True, "web-01"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
