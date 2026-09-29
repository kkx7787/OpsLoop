#!/usr/bin/env python3
"""잘못된 입력은 500 이 아니라 422 다 (이슈 #62). DB 없이 돈다.  python3 app/test_inputs.py

보는 것
  1. 사건 목록(GET /api/incidents): offset 상한(cti.MAX_OFFSET) · rule_id · rule_version · target 의 NUL 과 길이 ·
     장비(device) 형식 밖은 DB 에 닿기 전에 422. 상한까지는 받는다. 장비 조건은 가벼운 질의로 거른 뒤 쪽 키만 읽는다
  2. 조치(POST …/actions): 해제할 출발지의 IPv6 영역 표기(fe80::1%eth0)는 422(sources.parse_ip 와 같은 기준).
     메모 · 판정 사유의 NUL 도 422
  3. 본문의 짝 없는 서로게이트(원문 바이트 \\ud800): 판정 · 조치 · 노드 등록 모두 422 이고 본문은 type · loc · msg 만
     (입력값을 되돌려 싣지 않는다, access.masked_validation). 질의 인자의 422 도 같은 모양이다(화면은 msg 만 읽는다)
  4. 노드 등록 본문의 주소: IPv6 영역 표기는 422. 감사 조회의 offset 상한 · 검색어 NUL 은 422
  5. 규칙 품질 상세(operations.quality details=True): 규칙 정의 rules 의 객체가 아닌 항목 · id 가 없는 항목은 건너뛴다.
     rules 가 배열이 아니거나 정의가 객체가 아니어도 500 이 아니다(reports.VERSIONS_SQL 과 같은 기준)
TestClient 는 처리되지 않은 예외를 그대로 던지므로 422 가 나오면 서버 쪽 예외도 없다.

실행: python -m unittest discover -s app
"""
import asyncio
import json
import os
import sys
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_web  # noqa: E402  asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

import cti  # noqa: E402
import operations  # noqa: E402

main, auth = test_web.main, test_web.auth
SAME = test_web.SAME
JSON = {**SAME, "content-type": "application/json"}
T0 = datetime(2026, 9, 29, 0, 0, tzinfo=timezone.utc)


class FakeConn:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql, *args):
        self.pool.calls.append(("execute", sql, args))
        return "SELECT 1"

    async def fetchval(self, sql, *args):
        self.pool.calls.append(("fetchval", sql, args))
        return 0

    async def fetchrow(self, sql, *args):
        self.pool.calls.append(("fetchrow", sql, args))
        return None

    async def fetch(self, sql, *args):
        self.pool.calls.append(("fetch", sql, args))
        return self.pool.rows(sql)

    @asynccontextmanager
    async def transaction(self, **_kw):
        yield


class FakePool:
    """부른 질의를 모은다. by_sql 은 질의 글자 → 돌려줄 행(없으면 빈 목록)."""

    def __init__(self, rows=None):
        self.calls = []
        self.by_sql = rows or {}

    def rows(self, sql):
        return next((value for key, value in self.by_sql.items() if key in sql), [])

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self)


class AppBase(unittest.TestCase):
    role = "operator"

    def setUp(self):
        self.pool = FakePool()
        patcher = patch.object(main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(self.client.close)
        test_web.FakeAccounts().patch(self)["han"] = test_web.account_row(self.role)
        self.client.cookies.set(auth.COOKIE, auth.issue("han", self.role))

    def assert_masked(self, response, where):
        """422 이고 본문은 type · loc · msg 만. 화면(console api/errors.ts)이 읽는 msg 는 있다."""
        self.assertEqual(response.status_code, 422, (where, response.text))
        detail = response.json()["detail"]
        self.assertTrue(detail and all(set(item) <= {"type", "loc", "msg"} and item.get("msg") for item in detail),
                        (where, detail))
        self.assertEqual(response.headers.get("cache-control"), "no-store", where)

    def assert_no_db(self):
        self.assertEqual(self.pool.calls, [])


# ----------------------------------------------------------------------
#  1. 사건 목록
# ----------------------------------------------------------------------

class IncidentListTests(AppBase):
    role = "viewer"

    def test_offset_상한을_넘으면_DB_에_닿기_전에_422(self):
        for offset in (cti.MAX_OFFSET + 1, 2 ** 63, 10 ** 20, -1):
            with self.subTest(offset=offset):
                self.assert_masked(self.client.get("/api/incidents", params={"offset": offset}), offset)
        self.assert_no_db()

    def test_offset_상한까지는_받는다(self):
        response = self.client.get("/api/incidents", params={"offset": cti.MAX_OFFSET})
        self.assertEqual((response.status_code, response.json()["offset"]), (200, cti.MAX_OFFSET))

    def test_규칙_버전_대상의_NUL_은_422(self):
        for name in ("rule_id", "rule_version", "target"):
            for value in ("R1\x00", "\x00", "user:\x00han"):
                with self.subTest(name=name, value=value):
                    response = self.client.get("/api/incidents", params={name: value})
                    self.assertEqual((response.status_code, response.json()),
                                     (422, {"detail": f"{name} 에 NUL 글자를 넣을 수 없습니다"}))
        self.assert_no_db()

    def test_너무_긴_값은_422(self):
        for name, size in (("rule_id", 129), ("rule_version", 129), ("target", 257)):
            with self.subTest(name=name):
                self.assert_masked(self.client.get("/api/incidents", params={name: "a" * size}), name)
        self.assert_no_db()

    def test_보통_값은_그대로_조건이_된다(self):
        response = self.client.get("/api/incidents", params={"rule_id": "R107", "rule_version": "sg1",
                                                             "target": "node:web-01"})
        self.assertEqual(response.status_code, 200)
        sql, args = next((c[1], c[2]) for c in self.pool.calls if c[0] == "fetch" and "pending_seconds" in c[1])
        self.assertIn("i.rule_id = $1", sql)
        self.assertEqual(args[:3], ("R107", "sg1", "node:web-01"))

    def test_장비_형식_밖은_DB_에_닿기_전에_422(self):
        for value in ("WEB-01", "a" * 64, "web\x00", "../x", "_x", "-web", "web-01\n", "_unconfirmed-x"):
            with self.subTest(device=value):
                self.assert_masked(self.client.get("/api/incidents", params={"device": value}), value)
        self.assert_no_db()
        for value in ("web-01", "_unconfirmed", "a" * 63, "0"):
            with self.subTest(device=value):
                self.assertEqual(self.client.get("/api/incidents", params={"device": value}).status_code, 200)

    def test_장비_조건은_가벼운_질의_다음에_쪽_키만_읽는다(self):
        light = {"incident_key": "k1", "rule_id": "R301", "rule_version": "i2", "actor_ip": None, "target": "node:web-01",
                 "first_ts": T0, "last_ts": T0, "sensors": None, "sessions": None}
        page = light | {"rule_name": "노드 무응답", "severity": "high", "signal_count": 1, "session_count": 0,
                        "status": "open", "created_at": T0, "verdict": None, "pending_seconds": 60}
        self.pool.by_sql = {"pending_seconds": [page], "FROM incidents i": [light]}
        response = self.client.get("/api/incidents", params={"judged": "false", "device": "web-01", "limit": 10})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["total"], [x["incident_key"] for x in body["items"]]), (1, ["k1"]))
        item = body["items"][0]
        self.assertEqual((item["device_state"], [d["id"] for d in item["devices"]], item["device_fallback"]),
                         ("confirmed", ["web-01"], []))
        self.assertNotIn("sensors", item)
        self.assertEqual([o["id"] for o in body["device_options"]], ["web-01", "aws-sensor", "console", "data-node"])
        fetched = [(i, c[1], c[2]) for i, c in enumerate(self.pool.calls) if c[0] == "fetch" and "FROM incidents i" in c[1]]
        [(li, light_sql, light_args), (pi, page_sql, page_args)] = fetched
        self.assertLess(li, pi)
        self.assertNotIn("pending_seconds", light_sql)
        self.assertIn("v.verdict IS NULL", light_sql)
        self.assertEqual(light_args, ())
        self.assertIn("i.incident_key = ANY($1::text[])", page_sql)
        self.assertEqual(page_args, (["k1"],))
        # 전체 수는 키 수다(count 질의를 따로 하지 않는다)
        self.assertFalse([c for c in self.pool.calls if c[0] == "fetchval" and "FROM incidents i" in c[1]])

    def test_질의_인자_422_도_입력값을_싣지_않는다(self):
        response = self.client.get("/api/incidents", params={"limit": 0, "status": "<b>x</b>"})
        self.assert_masked(response, "limit · status")
        self.assertNotIn("<b>x</b>", response.text)


# ----------------------------------------------------------------------
#  2 · 3. 판정 · 조치 본문
# ----------------------------------------------------------------------

class IncidentBodyTests(AppBase):
    role = "admin"

    def test_해제할_출발지의_IPv6_영역_표기는_422(self):
        for bad in ("fe80::1%eth0", "fe80::1%1", "abc", "198.51.100.0/24"):
            with self.subTest(actor_ip=bad):
                response = self.client.post("/api/incidents/k1/actions",
                                            json={"action": "unblock_ip", "actor_ip": bad}, headers=SAME)
                self.assert_masked(response, bad)
                self.assertIn("actor_ip 는 IP 주소여야 합니다", response.json()["detail"][0]["msg"])
        self.assert_no_db()

    def test_메모_판정_사유의_NUL_은_422(self):
        for path, body in (("/api/incidents/k1/actions", {"action": "note", "note": "a\x00b"}),
                           ("/api/incidents/k1/actions", {"action": "block_ip", "note": "\x00"}),
                           ("/api/incidents/k1/verdict", {"verdict": "threat", "reason": "a\x00"})):
            with self.subTest(path=path, body=body):
                self.assert_masked(self.client.post(path, json=body, headers=SAME), body)
        self.assert_no_db()

    def test_짝_없는_서로게이트는_500_이_아니라_422(self):
        # 기본 처리기는 입력을 되돌려 싣다가 UnicodeEncodeError 로 500 이 된다. 원문 바이트로 보낸다(json= 은 서로게이트를 못 싣는다)
        for path, raw in (("/api/incidents/k1/actions", b'{"action":"\\ud800"}'),
                          ("/api/incidents/k1/actions", b'{"action":"note","note":"\\ud800"}'),
                          ("/api/incidents/k1/actions", b'{"action":"unblock_ip","actor_ip":"\\udc00"}'),
                          ("/api/incidents/k1/verdict", b'{"verdict":"\\ud800"}'),
                          ("/api/incidents/k1/verdict", b'{"verdict":"threat","reason":"a\\ud800b"}'),
                          ("/api/incidents/k1/verdict", b'{"verdict":"threat","proposed":"\\ud800"}')):
            with self.subTest(path=path, raw=raw):
                self.assert_masked(self.client.post(path, content=raw, headers=JSON), raw)
        self.assert_no_db()


    def test_관측값_NaN_무한대는_422(self):
        # 받으면 저장은 되고 응답 JSON 을 만들지 못해, 그 뒤 사건 상세가 계속 500 이 된다
        for raw in (b'{"verdict":"threat","observed_value":NaN}', b'{"verdict":"threat","observed_value":Infinity}',
                    b'{"verdict":"threat","observed_value":-Infinity}'):
            with self.subTest(raw=raw):
                self.assert_masked(self.client.post("/api/incidents/k1/verdict", content=raw, headers=JSON), raw)
        self.assert_no_db()

    def test_사건_키의_NUL_은_DB_에_닿기_전에_404(self):
        for method, path, body in (("get", "/api/incidents/a%00b", None), ("get", "/api/incidents/a%00b/cti", None),
                                   ("post", "/api/incidents/a%00b/actions", {"action": "note", "note": "x"}),
                                   ("post", "/api/incidents/a%00b/verdict", {"verdict": "threat"})):
            with self.subTest(path=path):
                response = self.client.request(method.upper(), path, json=body, headers=SAME if body else None)
                self.assertEqual((response.status_code, response.json()), (404, {"detail": "인시던트를 찾을 수 없습니다"}))
        self.assertEqual(self.client.get("/api/cti/badges", params={"key": "a\x00b"}).status_code, 422)
        self.assert_no_db()

# ----------------------------------------------------------------------
#  4. 운영 API (노드 등록 · 감사)
# ----------------------------------------------------------------------

NODE = {"node_id": "web-02", "hostname": "web-02", "addr": "192.0.2.12", "logs": ["nginx"]}


class OperationsApiTests(AppBase):
    role = "admin"

    def test_노드_등록_본문의_짝_없는_서로게이트는_422(self):
        for raw in (b'{"node_id":"\\ud800","hostname":"web-02","addr":"192.0.2.12","logs":["nginx"]}',
                    b'{"node_id":"web-02","hostname":"\\ud800","addr":"192.0.2.12","logs":["nginx"]}',
                    b'{"node_id":"web-02","hostname":"web-02","addr":"\\ud800","logs":["nginx"]}',
                    b'{"node_id":"web-02","hostname":"web-02","addr":"192.0.2.12","logs":["\\ud800"]}',
                    b'{"node_id":"web-02","hostname":"web-02","addr":"192.0.2.12","logs":["nginx"],"\\ud800":1}'):
            with self.subTest(raw=raw):
                self.assert_masked(self.client.post("/api/nodes/enrollments", content=raw, headers=JSON), raw)
        self.assert_no_db()

    def test_노드_등록_주소의_IPv6_영역_표기는_422(self):
        for addr in ("fe80::1%eth0", "fe80::1%2"):
            with self.subTest(addr=addr):
                response = self.client.post("/api/nodes/enrollments", json=NODE | {"addr": addr}, headers=SAME)
                self.assert_masked(response, addr)
                self.assertNotIn("eth0", response.text)
        self.assert_no_db()

    def test_등록_취소_경로의_노드_이름_번호_검사(self):
        for path in ("/api/nodes/a%00b/enrollments/1/cancel", "/api/nodes/Web_02/enrollments/1/cancel",
                     f"/api/nodes/web-02/enrollments/{2**63}/cancel", "/api/nodes/web-02/enrollments/0/cancel"):
            with self.subTest(path=path):
                self.assert_masked(self.client.post(path, headers=SAME), path)
        self.assert_no_db()

    def test_감사_조회의_offset_상한과_NUL_은_422(self):
        self.assert_masked(self.client.get("/api/audit", params={"offset": cti.MAX_OFFSET + 1}), "offset")
        for name in ("actor", "target"):
            with self.subTest(name=name):
                response = self.client.get("/api/audit", params={name: "op\x00"})
                self.assertEqual((response.status_code, response.json()),
                                 (422, {"detail": "검색어에 NUL 글자를 넣을 수 없습니다"}))
        self.assert_no_db()
        self.assertEqual(self.client.get("/api/audit", params={"offset": cti.MAX_OFFSET}).status_code, 200)


class EnrollmentInTests(unittest.TestCase):
    def test_주소의_IPv6_영역_표기는_거부하고_링크_로컬_주소는_받는다(self):
        for addr in ("fe80::1%eth0", "fe80::1%2"):
            with self.subTest(addr=addr), self.assertRaises(ValidationError):
                operations.EnrollmentIn(**(NODE | {"addr": addr}))
        self.assertEqual(operations.EnrollmentIn(**(NODE | {"addr": "fe80::1"})).addr, "fe80::1")

    def test_발생원_상태판_대상_이름은_노드_이름으로_쓸_수_없다(self):
        # 겹치면 그 노드의 사건 · 카드가 고정 대상으로 가거나 카드가 생기지 않는다(이슈 #64). 명령줄(collector/nodes.py)과 같은 목록이다
        for name in ("audit", "aws-sensor", "data-node", "console", "gateway"):
            with self.subTest(node_id=name), self.assertRaises(ValidationError):
                operations.EnrollmentIn(**(NODE | {"node_id": name, "hostname": name}))
        import importlib.util
        spec = importlib.util.spec_from_file_location("collector_nodes", os.path.join(os.path.dirname(__file__), "..", "collector", "nodes.py"))
        if spec and os.path.exists(spec.origin):
            nodes = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(nodes)
            self.assertEqual(nodes.RESERVED, operations.RESERVED)


# ----------------------------------------------------------------------
#  5. 규칙 품질 상세
# ----------------------------------------------------------------------

class QualityDefinitionTests(unittest.TestCase):
    def quality(self, definitions):
        versions = [{"rule_version": f"v{i}", "definition": d, "reason": None, "created_at": T0}
                    for i, d in enumerate(definitions)]
        pool = FakePool({"FROM rule_versions": versions})
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=pool)))
        result = asyncio.run(operations.quality(request, True))
        return [v["rules"] for v in result["versions"]]

    def test_객체가_아닌_항목과_id_없는_항목은_건너뛴다(self):
        rules = [1, "R9", None, ["R8"], {"name": "id 없음"}, {"id": "R1", "name": "하나", "severity": "low"}, {"id": "R2"}]
        got = self.quality([json.dumps({"rules": rules}), {"rules": rules}])
        want = [{"id": "R1", "name": "하나", "enabled": True, "severity": "low", "rationale": None, "change": None},
                {"id": "R2", "name": "R2", "enabled": True, "severity": None, "rationale": None, "change": None}]
        self.assertEqual(got, [want, want])

    def test_rules_가_배열이_아니거나_정의가_객체가_아니면_빈_목록(self):
        got = self.quality([json.dumps({"rules": "R1"}), json.dumps({"rules": {"id": "R1"}}), json.dumps({}),
                            json.dumps([{"id": "R1"}]), json.dumps("R1"), "null", None])
        self.assertEqual(got, [[]] * 7)


if __name__ == "__main__":
    unittest.main()
