"""기간 보고서 API(reports.py · 이슈 #58) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 기간: until = 출력 시각 · since = until - 기간(24시간 · 7 · 14 · 30일)
  2. 구역 고르기: 없으면 역할이 볼 수 있는 전부(관리자만 운영 기록) · 정해진 순서 · 같은 이름은 한 번 ·
     관리자가 아닌데 운영 기록을 달라면 403 · 세션 없으면 401. 둘 다 DB 에 닿기 전이다
  3. 라우터: 모르는 기간 · 구역 · 기간 없음은 DB 에 닿기 전에 422 · 한 트랜잭션(반복 읽기 · 읽기 전용) 첫 줄이 statement_timeout ·
     표가 없는 구역은 available=false 와 빠진 표 이름 · 출력자는 세션 사용자
  4. 다른 모듈과 같은 글자: 차단 상태 분류(main.BLOCK_STATES_SQL) · 규칙별 판정(operations.quality 의 질의)
SQL 이 맞는지는 test_reports_db.py 가 시험 DB 로 본다.
"""
import inspect
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import operations
import reports as r

NOW = datetime(2026, 9, 28, 3, 0, tzinfo=timezone.utc)
ALL = ["overview", "rules", "blocks", "targets", "cti", "ops"]


def request(role):
    return SimpleNamespace(state=SimpleNamespace(user={"u": "tester", "r": role} if role else None))


class PureTests(unittest.TestCase):
    def test_기간은_출력_시각에서_거꾸로_잰다(self):
        for period, delta in [("24h", timedelta(hours=24)), ("7d", timedelta(days=7)), ("14d", timedelta(days=14)),
                              ("30d", timedelta(days=30))]:
            with self.subTest(period=period):
                self.assertEqual(r.window(NOW, period), (NOW - delta, NOW))

    def test_구역을_고르지_않으면_역할이_볼_수_있는_전부다(self):
        for role in ["viewer", "operator"]:
            with self.subTest(role=role):
                self.assertEqual(r.chosen(request(role), None), ALL[:-1])
                self.assertEqual(r.chosen(request(role), []), ALL[:-1])
        self.assertEqual(r.chosen(request("admin"), None), ALL)

    def test_고른_구역은_정해진_순서로_한_번씩(self):
        self.assertEqual(r.chosen(request("viewer"), ["cti", "overview", "cti", "rules"]), ["overview", "rules", "cti"])
        self.assertEqual(r.chosen(request("admin"), ["ops", "blocks"]), ["blocks", "ops"])

    def test_관리자가_아니면_운영_기록은_403_세션이_없으면_401(self):
        for role, sections, status in [("viewer", ["ops"], 403), ("operator", ["overview", "ops"], 403),
                                       (None, None, 401), (None, ["overview"], 401), ("guest", None, 403)]:
            with self.subTest(role=role, sections=sections), self.assertRaises(HTTPException) as error:
                r.chosen(request(role), sections)
            self.assertEqual(error.exception.status_code, status)

    def test_숫자는_소수_한_자리_실수로(self):
        self.assertEqual(r.num(Decimal("1199.96")), 1200.0)
        self.assertEqual(r.num(3120.0000001), 3120.0)
        self.assertIsNone(r.num(None))

    def test_표가_없는_구역은_빠진_표를_밝힌다(self):
        self.assertEqual(r.unavailable(["audit_log", "events"]),
                         {"available": False, "reason": "표가 없거나 읽기 권한이 없음: audit_log · events"})

    def test_구역마다_선검사_표와_만드는_함수가_있다(self):
        self.assertEqual(list(r.SECTIONS), ALL)
        self.assertEqual(set(r.TABLES), set(ALL))
        self.assertEqual(set(r.BUILDERS), set(ALL))
        # nodes 는 콘솔에 열 권한만 있어 표 권한 검사가 늘 거짓이다. 선검사에 넣으면 운영에서 대상 구역이 늘 빠진다
        self.assertFalse(any("nodes" in tables for tables in r.TABLES.values()))


class SameTextTests(unittest.TestCase):
    def test_차단_상태_분류는_main_과_같다(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        main = test_web.main
        self.assertEqual(r.BLOCK_STATES_SQL, main.BLOCK_STATES_SQL)
        self.assertEqual((r.ENFORCE_EXCLUDED, r.ENFORCE_MISMATCH), (main.ENFORCE_EXCLUDED, main.ENFORCE_MISMATCH))

    def test_규칙별_판정은_규칙_화면과_같은_질의다(self):
        self.assertIn(r.QUALITY_SQL, inspect.getsource(operations.quality))


class FakeConn:
    """표가 하나도 없는 DB. 선검사(MISSING_SQL)는 물은 표를 모두 돌려주고, 그 밖의 조회는 오지 않아야 한다."""

    def __init__(self, calls):
        self.calls = calls

    async def execute(self, sql, *args):
        self.calls.append(sql)

    async def fetchval(self, sql, *args):
        self.calls.append(sql)
        if sql == "SELECT now()":
            return NOW
        if sql == r.MISSING_SQL:
            return sorted(args[0])      # 질의처럼 이름순
        raise AssertionError(f"표가 없는 구역에서 조회했다: {sql}")

    @asynccontextmanager
    async def transaction(self, **kw):
        self.calls.append(("transaction", kw))
        yield


class FakePool:
    def __init__(self):
        self.calls = []

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.calls)


class RouterTests(unittest.TestCase):
    """라우터만 붙인 앱. 세션 미들웨어 대신 self.role 로 사용자를 넣는다(None 이면 세션 없음)."""

    def setUp(self):
        self.pool, self.role = FakePool(), "viewer"
        app = FastAPI()
        app.include_router(r.router)
        app.state.pool = self.pool

        @app.middleware("http")
        async def as_user(req, call_next):
            if self.role:
                req.state.user = {"u": "han", "r": self.role}
            return await call_next(req)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def get(self, query):
        return self.client.get("/api/reports/period" + query)

    def test_잘못된_인자는_DB_에_닿기_전에_422_다(self):
        for query in ["", "?period=1d", "?period=7D", "?period=", "?period=7d&sections=foo", "?period=7d&sections=OPS",
                      "?period=7d&sections=overview&sections=", "?sections=overview"]:
            with self.subTest(query=query):
                self.assertEqual(self.get(query).status_code, 422)
        self.assertEqual(self.pool.calls, [])

    def test_세션이_없으면_401_이다(self):
        self.role = None
        response = self.get("?period=7d")
        self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual(self.pool.calls, [])

    def test_관리자가_아니면_운영_기록은_403_이다(self):
        for role in ["viewer", "operator"]:
            self.role = role
            for query in ["?period=7d&sections=ops", "?period=24h&sections=overview&sections=ops"]:
                with self.subTest(role=role, query=query):
                    self.assertEqual(self.get(query).status_code, 403)
        self.assertEqual(self.pool.calls, [])

    def test_구역을_고르지_않으면_역할이_볼_수_있는_전부다(self):
        body = self.get("?period=7d").json()
        self.assertEqual(list(body["sections"]), ALL[:-1])
        self.role = "admin"
        body = self.get("?period=30d").json()
        self.assertEqual(list(body["sections"]), ALL)
        self.assertEqual((body["as_of"], body["since"], body["until"], body["period"], body["tz"], body["generated_by"]),
                         (NOW.isoformat(), (NOW - timedelta(days=30)).isoformat(), NOW.isoformat(), "30d", "Asia/Seoul", "han"))

    def test_고른_구역만_정해진_순서로_낸다(self):
        body = self.get("?period=24h&sections=rules&sections=overview&sections=rules").json()
        self.assertEqual(list(body["sections"]), ["overview", "rules"])
        self.role = "admin"
        self.assertEqual(list(self.get("?period=24h&sections=ops").json()["sections"]), ["ops"])

    def test_한_트랜잭션에서_시간_제한을_먼저_건다(self):
        self.get("?period=7d&sections=overview")
        self.assertEqual(self.pool.calls[:3], [("transaction", {"isolation": "repeatable_read", "readonly": True}),
                                               "SET LOCAL statement_timeout = '5s'", "SELECT now()"])
        self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                         [("transaction", {"isolation": "repeatable_read", "readonly": True})])

    def test_표가_없는_구역은_사유만_낸다(self):
        self.role = "admin"
        sections = self.get("?period=7d").json()["sections"]
        for name in ALL:
            with self.subTest(name=name):
                self.assertEqual(sections[name], r.unavailable(sorted(r.TABLES[name])))
        # 선검사 말고는 아무것도 묻지 않는다
        self.assertEqual({c for c in self.pool.calls if isinstance(c, str)},
                         {"SET LOCAL statement_timeout = '5s'", "SELECT now()", r.MISSING_SQL})

    def test_경로는_GET_하나다(self):
        self.assertEqual(self.client.post("/api/reports/period?period=7d").status_code, 405)
        self.assertEqual([(route.path, route.methods) for route in r.router.routes],
                         [("/api/reports/period", {"GET"})])


if __name__ == "__main__":
    unittest.main()
