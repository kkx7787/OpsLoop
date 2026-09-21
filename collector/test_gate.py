#!/usr/bin/env python3
"""수집 관문 단위 시험. 127.0.0.1 임시 포트에 관문과 가짜 Loki 를 띄우고, 가짜 DB 층을 끼운다.
python3 collector/test_gate.py

거부(missing · unknown · revoked · inactive · addr_mismatch · path)는 본문을 읽지 않고 닫아야 하고,
표식 문자열 · 토큰 원문은 Loki · 원장 · 로그 어디에도 나오면 안 된다.
"""
import glob
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (Store 시험은 이 가짜로 SQL 과 커밋만 본다)
if "psycopg2" not in sys.modules:
    sys.modules["psycopg2"] = types.ModuleType("psycopg2")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402

LOGS = []
gate.log = lambda msg, level=6: LOGS.append((level, msg))

MARKER = "OPSLOOP-MARKER-7f3c1b"
AGENT = "olA_" + "k" * 43             # web-01 에이전트 키
REVOKED = "olA_" + "r" * 43
PENDING = "olA_" + "p" * 43
ELSEWHERE = "olA_" + "e" * 43         # 다른 출발지(10.9.9.9)에 묶인 키
ENROLL_TOKEN = "olE_" + "t" * 43
TOKENS = (AGENT, REVOKED, PENDING, ELSEWHERE, ENROLL_TOKEN)


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeStore:
    def __init__(self):
        self.rows = [("web-01", h(AGENT), "active", "127.0.0.1"),
                     ("old-01", h(REVOKED), "revoked", "127.0.0.1"),
                     ("new-01", h(PENDING), "pending", "127.0.0.1"),
                     ("probe-01", h(ELSEWHERE), "active", "10.9.9.9")]
        self.loads = 0
        self.fail_load = False
        self.fail_enroll = False
        self.result = "ok"
        self.calls = []

    def load_tokens(self):
        self.loads += 1
        if self.fail_load:
            raise RuntimeError("DB 에 닿지 않음")
        return list(self.rows)

    def enroll(self, token_hash, node_id, agent, src):
        self.calls.append((token_hash, node_id, agent, src))
        if self.fail_enroll:
            raise RuntimeError("DB 에 닿지 않음")
        if self.result == "ok":
            self.rows = [r for r in self.rows if r[0] != node_id] + [(node_id, agent, "active", src)]
        return self.result


class FakeLoki(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        srv = self.server
        with srv.lock:
            srv.active += 1
            srv.peak = max(srv.peak, srv.active)
        try:
            time.sleep(srv.delay)
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            srv.got.append((self.path, self.headers, body))
        finally:
            with srv.lock:          # 답하기 전에 뺀다. 관문이 답을 받고 다음 요청을 넘기기 전에 줄어 있어야 한다
                srv.active -= 1
        code, data = srv.reply
        self.send_response(code)
        if code == 204:
            self.end_headers()
            return
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def raw(port, head, body=b"", timeout=5):
    """날 소켓으로 보내고 서버가 닫을 때까지 읽는다. 서버가 본문을 기다리면 timeout 으로 실패한다."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(head.encode("latin-1") + body)
        data = b""
        while True:
            try:
                chunk = s.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def status(data):
    return int(data.split(b" ", 2)[1])


def body_json(data):
    return json.loads(data.split(b"\r\n\r\n", 1)[1])


def req_head(path=gate.PUSH, token=None, length=None, method="POST", extra=""):
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: Alloy/v1.19.2\r\n"
    if path == gate.PUSH and "Content-Type" not in extra:
        head += "Content-Type: application/x-protobuf\r\n"
    if token is not None:
        head += f"Authorization: Bearer {token}\r\n"
    if length is not None:
        head += f"Content-Length: {length}\r\n"
    return head + extra + "\r\n"


class GateCase(unittest.TestCase):
    def setUp(self):
        LOGS.clear()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.loki = ThreadingHTTPServer(("127.0.0.1", 0), FakeLoki)
        self.loki.got, self.loki.reply = [], (204, b"")
        self.loki.lock, self.loki.active, self.loki.peak, self.loki.delay = threading.Lock(), 0, 0, 0
        threading.Thread(target=self.loki.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.store = FakeStore()
        self.clock = Clock()
        self.server, self.gate = gate.make_server(
            "127.0.0.1", 0, self.store, f"http://127.0.0.1:{self.loki.server_address[1]}", self.dir,
            clock=self.clock, max_conn=getattr(self, "max_conn", gate.MAX_CONN))
        self.port = self.server.server_address[1]
        self.assertTrue(self.gate.reload())
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.loki.shutdown()
        self.loki.server_close()

    # --- 도우미 ---
    def ledger(self):
        out = []
        for p in sorted(glob.glob(os.path.join(self.dir, "collector-*.jsonl"))):
            with open(p, encoding="utf-8") as f:
                out += [json.loads(line) for line in f]
        return out

    def ledger_bytes(self):
        out = b""
        for p in glob.glob(os.path.join(self.dir, "*")):
            with open(p, "rb") as f:
                out += f.read()
        return out

    def push(self, token=AGENT, body=b"\x00proto\xff" + MARKER.encode(), headers=None, conn=None):
        c = conn or http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hd = {"Content-Type": "application/x-protobuf", "User-Agent": "Alloy/v1.19.2"}
        if token is not None:
            hd["Authorization"] = f"Bearer {token}"
        hd.update(headers or {})
        c.request("POST", gate.PUSH, body=body, headers=hd)
        r = c.getresponse()
        data = r.read()
        if conn is None:
            c.close()
        return r.status, data, r

    def enroll(self, body, token=ENROLL_TOKEN):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hd = {"Content-Type": "application/json"}
        if token is not None:
            hd["Authorization"] = f"Bearer {token}"
        c.request("POST", gate.ENROLL, body=body if isinstance(body, bytes) else json.dumps(body).encode(), headers=hd)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, json.loads(data)

    def wait(self, cond, limit=3):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if cond():
                return True
            time.sleep(0.02)
        return cond()

    def assert_no_secret(self):
        blob = self.ledger_bytes().decode("utf-8", "replace") + "\n".join(m for _, m in LOGS)
        self.assertNotIn(MARKER, blob)
        for t in TOKENS:
            self.assertNotIn(t, blob)


class RejectTest(GateCase):
    def test_거부는_본문을_읽지_않고_닫는다(self):
        # 본문 100000 B 를 예고만 하고 보내지 않는다. 관문이 본문을 기다리면 5초 안에 답이 오지 않는다
        cases = [(None, "missing"), ("olA_" + "x" * 43, "unknown"), (ENROLL_TOKEN, "unknown"),
                 (REVOKED, "revoked"), (PENDING, "inactive"), (ELSEWHERE, "addr_mismatch")]
        for token, reason in cases:
            with self.subTest(reason=reason, token=(token or "")[:4]):
                data = raw(self.port, req_head(token=token, length=100000))
                self.assertEqual(status(data), 401)
                self.assertEqual(body_json(data), {"result": reason})
                self.assertIn(b"Connection: close", data)
        self.assertEqual(self.loki.got, [])

    def test_표식_문자열은_어디에도_넘어가지_않는다(self):
        body = ('{"streams":[{"stream":{"job":"nginx"},"values":[["1","' + MARKER + '"]]}]}').encode()
        for token in (None, "olA_" + "y" * 43, ENROLL_TOKEN, REVOKED, PENDING, ELSEWHERE):
            data = raw(self.port, req_head(token=token, length=len(body),
                                           extra="Content-Type: application/json\r\n"), body)
            self.assertEqual(status(data), 401)
        data = raw(self.port, req_head(path="/loki/api/v1/push?x=1", token=AGENT, length=len(body)), body)
        self.assertEqual(status(data), 404)
        self.gate.ledger.flush(force=True)
        self.assertEqual(self.loki.got, [])
        self.assert_no_secret()

    def test_경로와_메서드(self):
        for head in (req_head(path="/", method="GET"), req_head(path="/metrics", token=AGENT, length=10),
                     req_head(path=gate.PUSH, method="GET", token=AGENT), req_head(path="/x", method="FOO")):
            data = raw(self.port, head)
            self.assertEqual(status(data), 404)
            self.assertEqual(body_json(data), {"result": "path"})
        rows = self.ledger()
        self.assertEqual({r["reason"] for r in rows}, {"path"})
        self.assertEqual(rows[0]["path"], "/")

    def test_원장_줄에_사유와_노드(self):
        raw(self.port, req_head(token=REVOKED, length=10))
        raw(self.port, req_head(token=ELSEWHERE, length=10))
        raw(self.port, req_head(token="olA_" + "z" * 43, length=10))
        rows = {r["reason"]: r for r in self.ledger()}
        self.assertEqual(rows["revoked"]["node_id"], "old-01")
        self.assertEqual(rows["addr_mismatch"]["node_id"], "probe-01")
        self.assertNotIn("node_id", rows["unknown"])
        self.assertEqual(rows["unknown"]["fps"], [h("olA_" + "z" * 43)[:8]])
        for r in rows.values():
            self.assertEqual(r["eventid"], "collector.agent.rejected")
            self.assertEqual(r["src_ip"], "127.0.0.1")

    def test_Expect_100은_거부할_때_보내지_않는다(self):
        data = raw(self.port, req_head(token=None, length=5000, extra="Expect: 100-continue\r\n"))
        self.assertTrue(data.startswith(b"HTTP/1.1 401"), data[:40])


class ForwardTest(GateCase):
    def test_통과하면_바이트_그대로_테넌트는_덮어쓴다(self):
        body = bytes(range(256)) * 4
        code, _, _ = self.push(body=body, headers={"X-Scope-OrgID": "victim", "Content-Encoding": "snappy"})
        self.assertEqual(code, 204)
        [(path, headers, got)] = self.loki.got
        self.assertEqual(path, gate.PUSH)
        self.assertEqual(got, body)
        self.assertEqual(headers.get_all("X-Scope-OrgID"), ["web-01"])
        self.assertIsNone(headers.get("Authorization"))
        self.assertEqual(headers.get("Content-Type"), "application/x-protobuf")
        self.assertEqual(headers.get("Content-Encoding"), "snappy")          # Alloy 가 실제로 보내는 조합
        self.assertEqual(self.ledger(), [])

    def test_압축_인코딩은_415_거부하고_넘기지_않는다(self):
        import gzip
        bomb = gzip.compress(b"a" * (8 * 1024 * 1024))           # 8MiB 가 수 KB 로 줄어든다
        for enc in ("gzip", "deflate", "br", "GZIP ", "x-snappy-framed"):
            code, body, _ = self.push(body=bomb, headers={"Content-Encoding": enc})
            self.assertEqual((code, json.loads(body)["result"]), (415, "content_encoding"))
        self.assertEqual(self.loki.got, [])
        self.assertEqual({r["reason"] for r in self.ledger()}, {"content_encoding"})
        # 인증을 통과한 등록 노드 자신의 문제다. R202(rejected)가 아니라 제한으로 남는다
        self.assertEqual({(r["eventid"], r["node_id"]) for r in self.ledger()}, {("collector.agent.throttled", "web-01")})
        self.assertEqual(self.gate.usage, {})

    def test_예상_밖의_형식은_415(self):
        for ctype, enc in (("text/plain", ""), ("application/octet-stream", ""), ("", ""), ("text/plain", "gzip")):
            code, body, _ = self.push(headers={"Content-Type": ctype, "Content-Encoding": enc})
            self.assertEqual((code, json.loads(body)["result"]), (415, "content_type"), ctype)
        self.assertEqual(self.loki.got, [])
        self.assertEqual({(r["eventid"], r["reason"]) for r in self.ledger()},
                         {("collector.agent.throttled", "content_type")})
        self.assertEqual(self.push(headers={"Content-Type": "application/json; charset=utf-8"})[0], 204)
        # snappy 는 protobuf 에만. JSON 에 붙이면 거부
        self.assertEqual(self.push(headers={"Content-Type": "application/json", "Content-Encoding": "snappy"})[0], 415)

    def test_identity_와_대소문자는_정규화해_넘긴다(self):
        # Loki 3.7 은 "" 와 "snappy" 만 받는다. 받은 값을 그대로 넘기면 Loki 가 400 을 주고 Alloy 는 묶음을 버린다
        self.assertEqual(self.push(headers={"Content-Encoding": "identity"})[0], 204)
        self.assertEqual(self.push(headers={"Content-Encoding": " Snappy "})[0], 204)
        self.assertEqual(self.push(headers={"Content-Type": "application/json", "Content-Encoding": "IDENTITY"})[0], 204)
        encs = [hd.get("Content-Encoding") for _, hd, _ in self.loki.got]
        self.assertEqual(encs, [None, "snappy", None])
        self.assertEqual(self.ledger(), [])

    def test_형식_검사는_인증_뒤_본문_읽기_전(self):
        # 본문을 예고만 하고 보내지 않는다. 관문이 본문을 기다리면 raw 가 5초 뒤 실패한다
        data = raw(self.port, req_head(token=AGENT, length=100000, extra="Content-Type: text/plain\r\n"))
        self.assertEqual((status(data), body_json(data)), (415, {"result": "content_type"}))
        data = raw(self.port, req_head(token=AGENT, length=100000, extra="Content-Encoding: gzip\r\n"))
        self.assertEqual((status(data), body_json(data)), (415, {"result": "content_encoding"}))
        self.assertEqual(self.gate.usage, {})
        # 인증 전이면 형식보다 인증 결과가 먼저다 (지문과 함께 거부로 남는다)
        data = raw(self.port, req_head(token=None, length=10, extra="Content-Type: text/plain\r\n"))
        self.assertEqual(body_json(data), {"result": "missing"})
        data = raw(self.port, req_head(token="olA_" + "q" * 43, length=10, extra="Content-Encoding: gzip\r\n"))
        self.assertEqual(body_json(data), {"result": "unknown"})
        self.assertEqual(self.loki.got, [])

    def test_연결을_다시_쓴다(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        for _ in range(3):
            code, _, _ = self.push(conn=c)
            self.assertEqual(code, 204)
        c.close()
        self.assertEqual(len(self.loki.got), 3)

    def test_Loki_응답_코드를_그대로(self):
        self.loki.reply = (400, b"entry out of order")
        code, data, r = self.push()
        self.assertEqual((code, data), (400, b"entry out of order"))
        self.loki.reply = (429, b"rate limited")
        self.assertEqual(self.push()[0], 429)

    def test_Loki_에_닿지_않으면_503(self):
        self.gate.loki = f"http://127.0.0.1:{free_port()}{gate.PUSH}"
        code, data, _ = self.push()
        self.assertEqual(code, 503)
        self.assertEqual(self.ledger(), [])

    def test_Expect_100은_받기로_정한_뒤에_보낸다(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(req_head(token=AGENT, length=5, extra="Expect: 100-continue\r\nConnection: close\r\n").encode())
        self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 100"))
        s.sendall(b"hello")
        data = b""
        while chunk := s.recv(4096):
            data += chunk
        s.close()
        self.assertIn(b"HTTP/1.1 204", data)
        self.assertEqual(self.loki.got[0][2], b"hello")


class LimitTest(GateCase):
    def test_411_길이_없음(self):
        data = raw(self.port, req_head(token=AGENT))
        self.assertEqual(status(data), 411)
        data = raw(self.port, req_head(token=AGENT, extra="Transfer-Encoding: chunked\r\n"))
        self.assertEqual(status(data), 411)
        [row] = self.ledger()
        self.assertEqual((row["eventid"], row["reason"], row["node_id"]),
                         ("collector.agent.throttled", "length_required", "web-01"))

    def test_413_은_본문을_읽지_않는다(self):
        data = raw(self.port, req_head(token=AGENT, length=gate.MAX_PUSH + 1))
        self.assertEqual(status(data), 413)
        self.assertEqual(self.ledger()[0]["reason"], "too_large")
        self.assertEqual(self.loki.got, [])

    def test_429_하루_용량(self):
        old = gate.DAILY_QUOTA
        gate.DAILY_QUOTA = 150
        try:
            self.assertEqual(self.push(body=b"a" * 100)[0], 204)
            self.assertEqual(self.push(body=b"a" * 100)[0], 429)
            self.assertEqual(self.push(body=b"a" * 50)[0], 204)
        finally:
            gate.DAILY_QUOTA = old
        [row] = self.ledger()
        self.assertEqual((row["eventid"], row["reason"]), ("collector.agent.throttled", "daily_quota"))
        self.assertEqual(len(self.loki.got), 2)

    def test_Loki_가_거절한_바이트도_용량에_넣는다(self):
        # Alloy 가 다시 보내지 않는 4xx 본문을 끝없이 보내 Loki 를 괴롭히는 것을 막는다
        old = gate.DAILY_QUOTA
        gate.DAILY_QUOTA = 250
        try:
            self.loki.reply = (400, b"entry too far behind")
            for _ in range(2):
                self.assertEqual(self.push(body=b"a" * 100)[0], 400)
            self.loki.reply = (204, b"")
            self.assertEqual(self.push(body=b"a" * 100)[0], 429)
        finally:
            gate.DAILY_QUOTA = old

    def test_Loki_장애는_용량에_넣지_않는다(self):
        # Alloy 가 5xx · 연결 실패를 다시 보낸다. 장애 동안 같은 묶음이 시도마다 용량을 깎으면 복구 뒤 로그를 버린다
        old = gate.DAILY_QUOTA
        gate.DAILY_QUOTA = 250
        try:
            self.loki.reply = (500, b"boom")
            for _ in range(3):
                self.assertEqual(self.push(body=b"a" * 100)[0], 500)
            real = self.gate.loki
            self.gate.loki = f"http://127.0.0.1:{free_port()}{gate.PUSH}"
            for _ in range(3):
                self.assertEqual(self.push(body=b"a" * 100)[0], 503)
            self.gate.loki = real
            self.assertEqual(self.gate.usage, {})
            self.loki.reply = (204, b"")
            self.assertEqual(self.push(body=b"a" * 100)[0], 204)
            self.assertEqual(self.push(body=b"a" * 100)[0], 204)
            self.assertEqual(self.push(body=b"a" * 100)[0], 429)
        finally:
            gate.DAILY_QUOTA = old

    def test_인코딩이_없으면_2MiB_가_본문_상한(self):
        data = raw(self.port, req_head(token=AGENT, length=gate.MAX_DECODED + 1))
        self.assertEqual((status(data), body_json(data)), (413, {"result": "too_large"}))
        data = raw(self.port, req_head(token=AGENT, length=gate.MAX_DECODED + 1,
                                       extra="Content-Type: application/json\r\n"))
        self.assertEqual(status(data), 413)
        self.assertEqual(self.loki.got, [])

    def test_snappy_앞머리의_풀린_크기가_2MiB_를_넘으면_413(self):
        two = b"\x80\x80\x80\x01"                  # varint 2MiB
        over = b"\x81\x80\x80\x01"                 # 2MiB + 1
        self.assertEqual(self.push(body=two + b"x" * 10, headers={"Content-Encoding": "snappy"})[0], 204)
        code, body, _ = self.push(body=over + b"x" * 10, headers={"Content-Encoding": "snappy"})
        self.assertEqual((code, json.loads(body)["result"]), (413, "decoded_too_large"))
        for bad in (b"", b"\xff\xff\xff\xff\xff\x01", b"\xff\xff\xff\xff\x1f"):   # 비었음 · 5바이트 초과 · 32비트 초과
            code, body, _ = self.push(body=bad, headers={"Content-Encoding": "snappy"})
            self.assertEqual((code, json.loads(body)["result"]), (400, "bad_snappy"), bad)
        self.assertEqual(len(self.loki.got), 1)
        self.assertEqual({(r["eventid"], r["reason"]) for r in self.ledger()},
                         {("collector.agent.throttled", "decoded_too_large"), ("collector.agent.throttled", "bad_snappy")})
        self.assertEqual(self.gate.usage["web-01"][1], 14)          # 넘긴 한 건만 센다

    def test_snappy_len(self):
        for buf, n in ((b"\x00", 0), (b"\x7f", 127), (b"\x80\x01", 128), (b"\x80\x80\x80\x01rest", 2 * 1024 * 1024),
                       (b"\xff\xff\xff\xff\x0f", 0xFFFFFFFF)):
            self.assertEqual(gate.snappy_len(buf), n, buf)
        for buf in (b"", b"\x80", b"\x80\x80\x80\x80\x80", b"\xff\xff\xff\xff\x10"):
            self.assertIsNone(gate.snappy_len(buf), buf)

    def test_Loki_로는_한_번에_하나만_넘긴다(self):
        self.loki.delay = 0.2
        codes = []
        ts = [threading.Thread(target=lambda: codes.append(self.push()[0])) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(10)
        self.assertEqual(codes, [204] * 4)
        self.assertEqual(self.loki.peak, 1)

    def test_차례가_오지_않으면_429_busy(self):
        old = gate.LOKI_TIMEOUT
        gate.LOKI_TIMEOUT = 0.3
        self.gate.forward_slots.acquire()
        try:
            code, body, _ = self.push()
        finally:
            self.gate.forward_slots.release()
            gate.LOKI_TIMEOUT = old
        self.assertEqual((code, json.loads(body)["result"]), (429, "busy"))
        self.assertEqual(self.loki.got, [])
        self.assertEqual(self.gate.usage, {})
        self.assertEqual(self.push()[0], 204)

    def test_429_동시_본문_한도(self):
        old = gate.INFLIGHT_MAX
        gate.INFLIGHT_MAX = 10
        try:
            self.assertEqual(self.push(body=b"a" * 100)[0], 429)
        finally:
            gate.INFLIGHT_MAX = old
        self.assertEqual(self.ledger()[0]["reason"], "busy")

    def test_캐시가_오래되면_503_거부로_세지_않는다(self):
        self.clock.advance(gate.CACHE_STALE + 1)
        code, _, _ = self.push()
        self.assertEqual(code, 503)
        data = raw(self.port, req_head(token=None, length=10))
        self.assertEqual(status(data), 503)
        self.assertEqual(self.ledger(), [])
        self.assertTrue(self.gate.reload())
        self.assertEqual(self.push()[0], 204)

    def test_캐시를_한_번도_못_읽으면_503(self):
        self.gate.loaded_at = None
        self.store.fail_load = True
        self.assertFalse(self.gate.reload())
        self.assertEqual(self.push()[0], 503)

    def test_느린_클라이언트는_끊는다(self):
        old = gate.Handler.timeout
        gate.Handler.timeout = 0.5
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            s.sendall(req_head(token=AGENT, length=1000).encode() + b"x" * 10)
            t0 = time.monotonic()
            self.assertEqual(s.recv(100), b"")      # 답 없이 닫힌다
            self.assertLess(time.monotonic() - t0, 4)
            s.close()
        finally:
            gate.Handler.timeout = old
        self.assertTrue(self.wait(lambda: self.gate.inflight == 0))
        self.assertEqual(self.loki.got, [])
        self.assertFalse([m for level, m in LOGS if level <= 3])

    def test_중간에_끊긴_클라이언트(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(req_head(token=AGENT, length=1000).encode() + MARKER.encode())
        s.close()
        self.assertTrue(self.wait(lambda: self.gate.inflight == 0))
        self.assertTrue(self.wait(lambda: any("끊겼다" in m for _, m in LOGS)))
        self.assertEqual(self.loki.got, [])
        self.assertEqual(self.push()[0], 204)         # 관문은 계속 받는다


class ConnLimitTest(GateCase):
    max_conn = 1

    def test_동시_연결_한도(self):
        a = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        time.sleep(0.2)
        b = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            self.assertEqual(b.recv(100), b"")       # 곧바로 닫힌다
        except ConnectionResetError:
            pass
        b.close()
        a.close()
        self.assertTrue(self.wait(lambda: self.server.slots.acquire(blocking=False)))
        self.server.slots.release()
        self.assertEqual(self.gate.stats["refused"], 1)


class EnrollTest(GateCase):
    AGENT2 = "olA_" + "n" * 43

    def test_등록_성공은_캐시를_다시_읽은_뒤_200(self):
        loads = self.store.loads
        code, res = self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)})
        self.assertEqual((code, res), (200, {"result": "ok"}))
        self.assertEqual(self.store.loads, loads + 1)
        self.assertEqual(self.store.calls, [(h(ENROLL_TOKEN), "web-02", h(self.AGENT2), "127.0.0.1")])
        # 15초 주기나 HUP 을 기다리지 않고 바로 통과한다
        self.assertEqual(self.push(token=self.AGENT2)[0], 204)
        self.assertEqual(self.loki.got[0][1].get("X-Scope-OrgID"), "web-02")
        [row] = self.ledger()
        self.assertEqual((row["eventid"], row["reason"], row["node_id"], row["fps"], row["path"]),
                         ("collector.agent.enrolled", "ok", "web-02", [h(self.AGENT2)[:8]], gate.ENROLL))
        self.assert_no_secret()

    def test_등록_실패_사유(self):
        body = {"node_id": "web-02", "agent_sha256": h(self.AGENT2)}
        for result in ("enroll_unknown", "enroll_canceled", "enroll_node", "enroll_expired",
                       "addr_mismatch", "enroll_used"):
            self.store.result = result
            self.assertEqual(self.enroll(body), (401, {"result": result}))
        self.store.result = "bad_key"
        self.assertEqual(self.enroll(body), (400, {"result": "bad_key"}))
        rows = self.ledger()
        self.assertEqual(len(rows), 7)
        self.assertTrue(all(r["eventid"] == "collector.agent.rejected" for r in rows))
        self.assertTrue(all(r["fps"] == [h(ENROLL_TOKEN)[:8]] for r in rows))
        self.assertEqual(self.push(token=self.AGENT2)[0], 401)
        self.assert_no_secret()

    def test_본문_형식_오류는_DB_에_가지_않는다(self):
        cases = [(b"not json", "enroll_body"), (b"[1]", "enroll_body"),
                 ({"node_id": "web 02", "agent_sha256": h("x")}, "enroll_body"),
                 ({"node_id": "web-02"}, "enroll_body"),
                 ({"node_id": "web-02", "agent_sha256": h("x").upper()}, "bad_key"),
                 ({"node_id": "web-02", "agent_sha256": "ab"}, "bad_key")]
        for body, reason in cases:
            self.assertEqual(self.enroll(body), (400, {"result": reason}))
        self.assertEqual(self.store.calls, [])

    def test_토큰_없음_길이_초과는_본문을_읽지_않는다(self):
        data = raw(self.port, req_head(path=gate.ENROLL, length=100))
        self.assertEqual((status(data), body_json(data)), (401, {"result": "missing"}))
        data = raw(self.port, req_head(path=gate.ENROLL, token=ENROLL_TOKEN, length=gate.MAX_ENROLL + 1))
        self.assertEqual((status(data), body_json(data)), (413, {"result": "too_large"}))
        data = raw(self.port, req_head(path=gate.ENROLL, token=ENROLL_TOKEN))
        self.assertEqual(status(data), 411)
        self.assertEqual(self.store.calls, [])

    def test_DB_오류는_503_거부가_아니라_제한으로_남긴다(self):
        self.store.fail_enroll = True
        self.assertEqual(self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)}),
                         (503, {"result": "unavailable"}))
        [row] = self.ledger()
        self.assertEqual((row["eventid"], row["reason"]), ("collector.agent.throttled", "unavailable"))

    def test_인증_전_길이_문제는_거부로_남긴다(self):
        body = json.dumps({"node_id": "web-02", "agent_sha256": h(self.AGENT2)}).encode()
        head = req_head(gate.ENROLL, token="olE_guess", length=None, extra="Transfer-Encoding: chunked\r\n")
        self.assertEqual(status(raw(self.port, head)), 411)
        self.assertEqual(status(raw(self.port, req_head(gate.ENROLL, token="olE_guess", length=5000))), 413)
        rows = self.ledger()
        self.assertEqual({(r["eventid"], r["reason"]) for r in rows},
                         {("collector.agent.rejected", "length_required"), ("collector.agent.rejected", "too_large")})
        self.assertEqual(self.store.calls, [])

    def test_발급_형식이_아닌_토큰은_DB_에_묻지_않는다(self):
        code, _ = self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)}, token="olE_short")
        self.assertEqual(code, 401)
        self.assertEqual(self.store.calls, [])
        self.assertEqual(self.ledger()[0]["reason"], "enroll_unknown")

    def test_출발지별_분당_등록_횟수(self):
        body = {"node_id": "web-02", "agent_sha256": h(self.AGENT2)}
        self.store.result = "enroll_unknown"
        for _ in range(gate.ENROLL_RATE):
            self.assertEqual(self.enroll(body)[0], 401)
        self.assertEqual(self.enroll(body), (429, {"result": "enroll_rate"}))
        self.clock.advance(61)
        self.assertEqual(self.enroll(body)[0], 401)

    def test_동시_등록이_넘치면_DB_에_가지_않는다(self):
        for _ in range(gate.ENROLL_DB):
            self.assertTrue(self.gate.enroll_slots.acquire(blocking=False))
        try:
            self.assertEqual(self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)}),
                             (429, {"result": "enroll_busy"}))
            self.assertEqual(self.store.calls, [])
        finally:
            for _ in range(gate.ENROLL_DB):
                self.gate.enroll_slots.release()

    def test_등록_재시도는_원장에_다시_쓰지_않는다(self):
        body = {"node_id": "web-02", "agent_sha256": h(self.AGENT2)}
        self.assertEqual(self.enroll(body)[0], 200)
        for _ in range(3):
            self.assertEqual(self.enroll(body)[0], 200)
        self.assertEqual([r["eventid"] for r in self.ledger()], ["collector.agent.enrolled"])

    def test_등록은_됐는데_캐시를_못_읽으면_503(self):
        self.store.fail_load = True
        self.assertEqual(self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)}),
                         (503, {"result": "unavailable"}))
        self.assertEqual(self.ledger()[0]["eventid"], "collector.agent.enrolled")
        self.store.fail_load = False                 # 같은 키로 다시 부르면 DB 가 ok 를 준다
        self.assertEqual(self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)})[0], 200)
        self.assertEqual(self.push(token=self.AGENT2)[0], 204)

    def test_DB_가_모르는_값을_주면_503(self):
        self.store.result = "weird"
        self.assertEqual(self.enroll({"node_id": "web-02", "agent_sha256": h(self.AGENT2)})[0], 503)


class HardeningTest(GateCase):
    def test_큰_헤더는_431_거부(self):
        head = req_head(token=AGENT, length=4, extra="".join(f"X-Pad-{i}: {'a' * 100}\r\n" for i in range(80)))
        self.assertEqual(status(raw(self.port, head, b"abcd")), 431)
        self.assertEqual(self.ledger()[0]["reason"], "header_too_large")
        self.assertEqual(self.loki.got, [])

    def test_헤더를_흘려_보내면_기한에_끊는다(self):
        old = gate.HEADER_DEADLINE
        gate.HEADER_DEADLINE = 1
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            s.sendall(b"POST /loki/api/v1/push HTTP/1.1\r\nX-A: 1\r\n")
            t0 = time.monotonic()
            closed = False
            while time.monotonic() - t0 < 4:
                try:
                    s.sendall(b"X")
                    if s.recv(1, socket.MSG_DONTWAIT) == b"":
                        closed = True
                        break
                except BlockingIOError:
                    pass
                except OSError:
                    closed = True
                    break
                time.sleep(0.2)
            s.close()
            self.assertTrue(closed)
            deadline = time.monotonic() + 2
            while not self.ledger() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(self.ledger()[0]["reason"], "header_timeout")
        finally:
            gate.HEADER_DEADLINE = old

    def test_쉬는_재사용_연결은_거부로_남기지_않는다(self):
        old = gate.HEADER_DEADLINE
        gate.HEADER_DEADLINE = 0.5
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            self.assertEqual(self.push(conn=c)[0], 204)
            time.sleep(1.2)                                  # 다음 요청 줄 없이 쉰다
            c.close()
            self.assertEqual(self.ledger(), [])
        finally:
            gate.HEADER_DEADLINE = old

    def test_출발지별_동시_연결_한도(self):
        old = gate.PER_SRC_CONN
        gate.PER_SRC_CONN = 2
        try:
            held = [socket.create_connection(("127.0.0.1", self.port), timeout=5) for _ in range(2)]
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            try:
                s.sendall(req_head(token=AGENT, length=0).encode())
                got = s.recv(100)
            except (ConnectionResetError, BrokenPipeError):
                got = b""
            self.assertEqual(got, b"")                     # 바로 끊긴다 (FIN 또는 RST)
            s.close()
            for h_ in held:
                h_.close()
            time.sleep(0.2)
            self.assertIn("conn_limit", [r["reason"] for r in self.ledger()])
            self.assertEqual(self.push()[0], 204)          # 연결을 놓으면 다시 받는다
        finally:
            gate.PER_SRC_CONN = old

    def test_하루_용량은_재시작해도_이어진다(self):
        self.gate.charge("web-01", 1234)
        self.gate.save_usage(force=True)
        g2 = gate.Gate(self.store, "http://127.0.0.1:9", self.gate.ledger, self.clock,
                       usage_path=os.path.join(self.dir, gate.USAGE_FILE))
        self.assertEqual(g2.usage["web-01"][1], 1234)


class CacheTest(GateCase):
    def test_HUP_이면_곧바로_다시_읽는다(self):
        self.store.rows = [r for r in self.store.rows if r[0] != "web-01"] + [("web-01", h(AGENT), "revoked", "127.0.0.1")]
        self.assertEqual(self.push()[0], 204)        # 아직 옛 캐시
        self.gate.hup = True
        self.gate.tick()
        self.assertEqual(self.push()[0], 401)
        self.assertEqual(self.ledger()[0]["reason"], "revoked")

    def test_15초마다_다시_읽는다(self):
        loads = self.store.loads
        self.gate.tick()
        self.assertEqual(self.store.loads, loads)
        self.clock.advance(gate.CACHE_EVERY)
        self.gate.tick()
        self.assertEqual(self.store.loads, loads + 1)

    def test_주소_없는_노드는_addr_mismatch(self):
        self.store.rows.append(("noaddr-01", h("olA_noaddr"), "active", None))
        self.gate.reload()
        data = raw(self.port, req_head(token="olA_noaddr", length=10))
        self.assertEqual(body_json(data), {"result": "addr_mismatch"})


class GroupTest(GateCase):
    def test_출발지_사유별_60초_묶음(self):
        for _ in range(10):
            raw(self.port, req_head(token=None, length=10))
        unknown = ["olA_" + c * 43 for c in "fghij"]
        for t in unknown:
            raw(self.port, req_head(token=t, length=10))
        rows = self.ledger()
        self.assertEqual([(r["reason"], r["count"]) for r in rows], [("missing", 1), ("unknown", 1)])
        self.gate.ledger.flush()                     # 창이 아직 안 끝났다
        self.assertEqual(len(self.ledger()), 2)

        self.clock.advance(gate.WINDOW + 1)
        self.gate.ledger.flush()
        rows = self.ledger()
        self.assertEqual(len(rows), 4)
        agg = {r["reason"]: r for r in rows[2:]}
        self.assertEqual((agg["missing"]["count"], agg["missing"]["distinct_fp"], agg["missing"]["fps"]), (9, 0, []))
        self.assertEqual(agg["unknown"]["count"], 4)
        self.assertEqual(agg["unknown"]["distinct_fp"], 4)
        self.assertEqual(agg["unknown"]["fps"], [h(t)[:8] for t in unknown[1:4]])
        self.assertEqual(sum(r["count"] for r in rows), 15)

        self.gate.reload()                           # 시계를 옮겨 캐시가 오래됐다
        raw(self.port, req_head(token=None, length=10))
        self.assertEqual(self.ledger()[-1]["count"], 1)   # 새 창의 첫 건은 바로 쓴다

    def test_창이_끝났는데_남은_게_없으면_줄을_쓰지_않는다(self):
        raw(self.port, req_head(token=None, length=10))
        self.clock.advance(gate.WINDOW + 1)
        self.gate.ledger.flush()
        self.assertEqual(len(self.ledger()), 1)

    def test_끝낼_때_모두_쓴다(self):
        for _ in range(3):
            raw(self.port, req_head(token=None, length=10))
        self.gate.ledger.flush(force=True)
        self.assertEqual([r["count"] for r in self.ledger()], [1, 2])


class LedgerFormatTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.clock = Clock()
        self.ledger = gate.Ledger(self.dir, 3101, self.clock)

    def rows(self):
        [p] = glob.glob(os.path.join(self.dir, "collector-*.jsonl"))
        with open(p, encoding="utf-8") as f:
            return p, [json.loads(line) for line in f]

    def test_줄_형식(self):
        self.ledger.record(gate.REJECTED, "192.168.50.21", gate.PUSH, "unknown", "3f9a1c0e", "Alloy/v1.19.2")
        self.ledger.record(gate.ENROLLED, "192.168.50.21", gate.ENROLL, "ok", "0123abcd", "curl/8", "web-01",
                           group=False)
        p, rows = self.rows()
        self.assertRegex(os.path.basename(p), r"^collector-\d{4}-\d{2}-\d{2}\.jsonl$")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o640)
        r = rows[0]
        self.assertEqual(list(r), ["ts", "boot", "seq", "eventid", "src_ip", "dst_port", "path", "reason",
                                   "count", "distinct_fp", "fps", "ua"])
        self.assertRegex(r["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$")
        self.assertRegex(r["boot"], r"^[0-9a-f]{6}$")
        self.assertEqual((r["seq"], r["dst_port"], r["count"], r["distinct_fp"], r["fps"]), (1, 3101, 1, 1, ["3f9a1c0e"]))
        self.assertEqual((rows[1]["seq"], rows[1]["boot"], rows[1]["node_id"]), (2, r["boot"], "web-01"))
        with open(p, encoding="utf-8") as f:
            self.assertTrue(f.readline().startswith('{"ts":"'))   # 빈칸 없는 한 줄

    def test_에이전트가_정한_값은_길이를_자르고_제어문자를_바꾼다(self):
        self.ledger.record(gate.REJECTED, "1.2.3.4", "/a\nb\x85", "path", None, "U" * 300 + "\r\n{")
        _, [r] = self.rows()
        self.assertEqual(r["path"], "/a\\x0ab\\x85")
        self.assertEqual(len(r["ua"]), 256)
        with open(glob.glob(os.path.join(self.dir, "*"))[0], "rb") as f:
            self.assertEqual(f.read().count(b"\n"), 1)

    def test_묶음_상한을_넘으면_바로_쓴다(self):
        old = gate.MAX_GROUPS
        gate.MAX_GROUPS = 1
        try:
            for src in ("1.1.1.1", "2.2.2.2", "2.2.2.2"):
                self.ledger.record(gate.REJECTED, src, gate.PUSH, "missing")
        finally:
            gate.MAX_GROUPS = old
        _, rows = self.rows()
        self.assertEqual([r["src_ip"] for r in rows], ["1.1.1.1", "2.2.2.2", "2.2.2.2"])

    def test_노드가_섞인_묶음은_node_id_를_비운다(self):
        for node in ("a", "b", "c"):
            self.ledger.record(gate.REJECTED, "1.1.1.1", gate.PUSH, "revoked", "f" * 8, "", node)
        self.ledger.flush(force=True)
        _, rows = self.rows()
        self.assertEqual(rows[0]["node_id"], "a")
        self.assertNotIn("node_id", rows[1])        # 묶인 두 건(b · c)의 노드가 다르다
        self.assertEqual((rows[1]["count"], rows[1]["distinct_fp"]), (2, 1))

    def test_쓸_수_없어도_죽지_않는다(self):
        bad = gate.Ledger(os.path.join(self.dir, "없는폴더"), 3101, self.clock)
        LOGS.clear()
        bad.record(gate.REJECTED, "1.1.1.1", gate.PUSH, "missing")
        self.assertTrue(any(level == 3 for level, _ in LOGS))


class HelperTest(unittest.TestCase):
    def test_bearer(self):
        self.assertIsNone(gate.bearer(None))
        self.assertIsNone(gate.bearer("  "))
        self.assertIsNone(gate.bearer("Bearer "))
        self.assertEqual(gate.bearer("bearer abc"), "abc")
        self.assertEqual(gate.bearer("Basic abc"), "Basic abc")

    def test_content_length(self):
        msg = http.client.parse_headers
        import io

        def hd(s):
            return msg(io.BytesIO(s.encode("latin-1") + b"\r\n"))
        self.assertEqual(gate.content_length(hd("Content-Length: 12\r\n")), 12)
        self.assertIsNone(gate.content_length(hd("")))
        self.assertIsNone(gate.content_length(hd("Content-Length: -1\r\n")))
        self.assertIsNone(gate.content_length(hd("Content-Length: \xb2\r\n")))     # 윗첨자 2
        self.assertIsNone(gate.content_length(hd("Content-Length: 1\r\nContent-Length: 1\r\n")))

    def test_parse_bind(self):
        self.assertEqual(gate.parse_bind("192.168.60.11:3101"), ("192.168.60.11", 3101))
        with self.assertRaises(SystemExit):
            gate.parse_bind("3101")


class StoreTest(unittest.TestCase):
    """실제 Store 가 부르는 SQL · 커밋 · 닫기를 가짜 psycopg2 로 본다."""

    def setUp(self):
        self.log = []
        log = self.log

        class Cur:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=None):
                log.append(("execute", sql, params))

            def fetchall(self):
                return [("web-01", "a" * 64, "active", "192.168.50.21")]

            def fetchone(self):
                return ("ok",)

        class Conn:
            def cursor(self):
                return Cur()

            def commit(self):
                log.append(("commit",))

            def close(self):
                log.append(("close",))

        def connect(url, **kw):
            log.append(("connect", url, kw))
            return Conn()
        sys.modules["psycopg2"].connect = connect

    def test_캐시_질의(self):
        rows = gate.Store("postgresql://x").load_tokens()
        self.assertEqual(rows[0][0], "web-01")
        self.assertEqual(self.log[1], ("execute", gate.TOKENS_SQL, None))
        self.assertIn("SELECT node_id, token_hash, status, host(addr) FROM nodes WHERE token_hash IS NOT NULL",
                      gate.TOKENS_SQL)
        self.assertEqual(self.log[-1], ("close",))
        self.assertEqual(self.log[0][2]["connect_timeout"], 5)

    def test_등록_함수는_한_번_부르고_커밋(self):
        res = gate.Store("postgresql://x").enroll("h" * 64, "web-01", "a" * 64, "192.168.50.21")
        self.assertEqual(res, "ok")
        _, sql, params = self.log[1]
        self.assertTrue(re.fullmatch(r"SELECT enroll_node\(%s, %s, %s, %s(::inet)?\)", sql))
        self.assertEqual(params, ("h" * 64, "web-01", "a" * 64, "192.168.50.21"))
        self.assertEqual([x[0] for x in self.log[2:]], ["commit", "close"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
