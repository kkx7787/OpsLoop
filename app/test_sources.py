"""출발지 분석(sources.py · 이슈 #58) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 순수 함수: 주소 인자(정규화 · 주소 아님 · 대역 · NUL · IPv6 영역 표기는 422) · 노린 대상(카드 순서 · 모르는 발생원 버림) ·
     차단 행 모양(사건 상세 blocked 와 같은 열 · 시각 ISO · 지점 결과 객체) · 차단 제외(상수 대역은 참 · 표를 못 읽으면 null) ·
     집행기 확인 멈춤(10분 경계 · 기록 없음은 멈춤 · 표를 못 읽으면 null) · 목록 항목(순위 → 심각도 이름 · 판정 분포 · 마지막 관측) ·
     감사 기록은 어느 이벤트 질의에도 들지 않고 콘솔 기록은 사건 없는 주소의 판정 · 마지막 관측에서만 빠진다
  2. 인자 검사: q 패턴 · 정렬 · 지문 종류와 값은 함께 · 값 길이 · NUL · 쪽 크기 · 상세 주소 · 지문 종류. 모두 DB 에 닿기 전에 422
  3. 가짜 풀: 한 트랜잭션(반복 읽기 · 읽기 전용) · 첫 문장이 시간 상한 · 조건 인자(q 소문자 앞부분 · 지문 값 · 시험 대역 기본 제외) ·
     응답 모양 · 쪽에 나온 주소만 따로 묻기 · 상세 404 · 이벤트만 있는 출발지는 요약 null · 표가 없으면 null ·
     상세 머리의 마지막 관측 · 차단 제외(exempt_flag, 요약이 없어도 목록과 같은 판단)
  4. 라우터: 세 경로가 처리기로 간다 · 세션이 없으면 401 이고 DB 호출이 없다 · main 앱에 붙었으면 main 에서도 같다
  5. main.py 곁일: 사건 목록 actor_ip 가 주소가 아니면 422(DB 호출 없음) · 주소는 정규화해 넘김 · 빈 값은 조건 없음 ·
     요약 상위 출발지가 글자 max 가 아니라 순위로 심각도를 고른다(정확성은 test_sources_db 가 본다)
main 이 필요한 시험은 test_web 을 먼저 불러 asyncpg 가 없는 곳에서도 가짜를 넣는다(main 보다 먼저).
"""
import json
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import absorbed
import cti
import sources as s
import targets

NOW = datetime(2026, 9, 29, 3, 0, tzinfo=timezone.utc)
PATHS = ("/api/sources", "/api/sources/detail", "/api/sources/fingerprints")


def row(ip="198.51.100.7", rank=0, **kw):
    """SOURCES_SQL 의 s 한 행과 같은 꼴."""
    base = {"ip": ip, "actor_ip": ip, "incidents": 3, "unjudged": 1, "rank": rank, "rules": ["R001", "R003"],
            "first_ts": NOW - timedelta(hours=5), "last_ts": NOW - timedelta(minutes=40),
            "threat": 1, "non_actionable": 0, "false_positive": 1, "benign_positive": 0, "undetermined": 0,
            "test_source": False}
    return {**base, **kw}


def block_row(ip="198.51.100.7"):
    return {"ip": ip, "reason": "SSH 무차별 대입", "method": "nft", "created_at": NOW - timedelta(hours=1),
            "expires_at": NOW + timedelta(hours=23), "released_at": None, "enforced_at": NOW - timedelta(minutes=59),
            "enforce_note": "관문 반영 · 0123abcd · 2026-09-29T02:01:00Z", "requested_by": "han",
            "enforcement": json.dumps({"gateway": {"state": "confirmed", "since": "2026-09-29T02:01:00Z"}})}


def seen(sensors, minutes=10):
    """SENSORS_SQL 한 행(발생원 · 마지막 관측)과 같은 꼴."""
    return {"ip": "198.51.100.7", "sensors": sensors, "last_seen": NOW - timedelta(minutes=minutes)}


def hb(source, minutes, kind="block_report"):
    return {"source": source, "kind": kind, "role": "gateway", "host": "x", "seen_at": None,
            "checked_at": NOW - timedelta(minutes=minutes), "problem": None}


# ----------------------------------------------------------------------
#  1. 순수 함수
# ----------------------------------------------------------------------

class PureTests(unittest.TestCase):
    def test_주소_인자는_정규화하고_주소가_아니면_422_다(self):
        self.assertEqual(s.parse_ip(" 198.51.100.7 "), "198.51.100.7")
        self.assertEqual(s.parse_ip("2001:DB8:0:0::1"), "2001:db8::1")
        for bad in ("abc", "", "198.51.100.0/24", "198.51.100.7\x00", "1.2.3", "fe80::1%eth0", "198.51.100.256"):
            with self.subTest(value=bad), self.assertRaises(HTTPException) as caught:
                s.parse_ip(bad)
            self.assertEqual((caught.exception.status_code, caught.exception.detail), (422, "ip 는 IP 주소여야 합니다"))

    def test_노린_대상은_카드_순서이고_모르는_발생원은_버린다(self):
        self.assertEqual(s.targets_of(["web-01", "gateway", "cowrie", "decoy", "web-09"]), ["aws-sensor", "web-01"])
        self.assertEqual(s.targets_of(["audit", "console", "collector"]), ["console", "data-node"])
        self.assertEqual(s.targets_of(None), [])
        self.assertEqual(s.targets_of(["simulator"]), [])

    def test_차단_행은_사건_상세와_같은_모양이다(self):
        self.assertIsNone(s.block_of(None))
        block = s.block_of(block_row())
        self.assertEqual(set(block), {"reason", "method", "created_at", "expires_at", "released_at", "enforced_at",
                                      "enforce_note", "requested_by", "enforcement"})
        self.assertEqual(block["created_at"], (NOW - timedelta(hours=1)).isoformat())
        self.assertIsNone(block["released_at"])
        self.assertEqual(block["enforcement"], {"gateway": {"state": "confirmed", "since": "2026-09-29T02:01:00Z"}})
        self.assertIsNone(s.block_of({**block_row(), "enforcement": None})["enforcement"])

    def test_차단_제외는_표를_못_읽으면_모른다(self):
        self.assertIs(s.exempt_flag(True, False), True)      # 코드 상수 대역은 표 없이도 안다
        self.assertIs(s.exempt_flag(True, True), True)
        self.assertIs(s.exempt_flag(False, True), False)
        self.assertIsNone(s.exempt_flag(False, False))       # 표에만 있는 대역을 놓쳤을 수 있다

    def test_집행기_확인_멈춤(self):
        self.assertEqual(s.checkers_of(False, [], NOW), {"gateway_stale": None, "fw_stale": None})
        # 기록이 없으면 멈춘 것으로 본다(targets.response_block 과 같다). 10분 정각은 아직 확인 중
        self.assertEqual(s.checkers_of(True, [hb("block:gateway", 10)], NOW), {"gateway_stale": False, "fw_stale": True})
        self.assertEqual(s.checkers_of(True, [hb("block:gateway", 11), hb("block:fw", 1)], NOW),
                         {"gateway_stale": True, "fw_stale": False})
        # 업로더 신호는 집행기 확인이 아니다
        self.assertEqual(s.checkers_of(True, [hb("block:fw", 1, kind="uploader")], NOW)["fw_stale"], True)

    def test_목록_항목(self):
        item = s.source_item(row(rank=2), seen(["cowrie"]), block_row(), False, True)
        self.assertEqual(item["severity"], "medium")
        self.assertEqual(item["verdicts"], {"threat": 1, "non_actionable": 0, "false_positive": 1,
                                            "benign_positive": 0, "undetermined": 0})
        self.assertEqual((item["ip"], item["incidents"], item["unjudged"], item["rules"], item["targets"]),
                         ("198.51.100.7", 3, 1, ["R001", "R003"], ["aws-sensor"]))
        # 마지막 사건(last_ts)과 마지막 관측(last_seen, 실제 이벤트)은 따로다
        self.assertEqual((item["first_ts"], item["last_ts"], item["last_seen"]),
                         ((NOW - timedelta(hours=5)).isoformat(), (NOW - timedelta(minutes=40)).isoformat(),
                          (NOW - timedelta(minutes=10)).isoformat()))
        self.assertEqual((item["test_source"], item["exempt"]), (False, False))
        self.assertEqual(item["block"]["method"], "nft")
        self.assertEqual([s.source_item(row(rank=r), None, None, False, True)["severity"] for r in range(4)],
                         ["critical", "high", "medium", "low"])
        # 실제 이벤트가 없으면 노린 대상은 비고 마지막 관측은 모른다
        bare = s.source_item(row(), None, None, False, True)
        self.assertEqual((bare["block"], bare["targets"], bare["last_seen"]), (None, [], None))

    def test_심각도는_글자가_아니라_순위로_고른다(self):
        self.assertIn(f"min({s.SEVERITY_RANK})", s.SOURCES_SQL)
        self.assertNotIn("max(i.severity)", s.SOURCES_SQL)
        # 사건 목록 정렬(main.list_incidents)과 같은 순위다
        self.assertEqual(s.SEVERITY_RANK.replace("i.severity", "x"),
                         "CASE x WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END")

    def test_감사_기록은_늘_빼고_콘솔_기록은_사건_없는_주소에서만_뺀다(self):
        # 감사 행의 src_ip 는 우리 DB 접속 주소다. 이 주소의 events 를 읽는 모든 질의에서 뺀다
        for sql in (s.SENSORS_SQL, s.HAS_EVENTS_SQL, s.LAST_SEEN_SQL, s.EVENT_KINDS_SQL,
                    *(s.fp_events(k) for k in s.FINGERPRINTS)):
            with self.subTest(sql=sql):
                self.assertIn("provenance = 'real' AND sensor <> 'audit'", sql)
        # 사건 없는 주소의 판정 · 마지막 관측은 콘솔 기록도 뺀다. 목록(사건 있는 주소)은 콘솔을 노린 대상으로 둔다
        for sql in (s.HAS_EVENTS_SQL, s.LAST_SEEN_SQL):
            self.assertIn("sensor <> 'console'", sql)
        self.assertNotIn("console", s.SENSORS_SQL)
        # 이벤트 종류는 사건이 있을 때만 콘솔 기록을 싣는다($3)
        self.assertIn("($3::boolean OR sensor <> 'console')", s.EVENT_KINDS_SQL)

    def test_지문은_실제_이벤트에서_꺼낸다(self):
        for kind in s.FINGERPRINTS:
            with self.subTest(kind=kind):
                self.assertIn("provenance = 'real'", s.fp_events(kind))
        self.assertIn("eventid = 'cowrie.client.kex'", s.fp_events("hassh"))
        self.assertIn("sensor = 'decoy'", s.fp_events("user_agent"))
        # 비신뢰 글자는 512자로 자른다(묶는 값과 거르는 값이 같은 식)
        self.assertIn("left(user_agent, 512)", s.fp_events("user_agent"))
        self.assertIn("), 512)", s.fp_events("ssh_version"))


# ----------------------------------------------------------------------
#  2 · 3. 가짜 풀
# ----------------------------------------------------------------------

class FakeConn:
    """질의 · 인자를 남기고 pool.reply 로 답한다."""

    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql, *args):
        self.pool.calls.append(("execute", sql, args))

    async def fetchval(self, sql, *args):
        self.pool.calls.append(("fetchval", sql, args))
        return self.pool.reply("fetchval", sql)

    async def fetchrow(self, sql, *args):
        self.pool.calls.append(("fetchrow", sql, args))
        return self.pool.reply("fetchrow", sql)

    async def fetch(self, sql, *args):
        self.pool.calls.append(("fetch", sql, args))
        return self.pool.reply("fetch", sql)

    @asynccontextmanager
    async def transaction(self, **kw):
        self.pool.calls.append(("transaction", kw))
        yield


class FakePool:
    """answers: {질의: 답}. 출발지 집계(SOURCES_SQL 로 시작)는 rows · total 로 답한다. 없는 질의는 빈 답이다
    (선검사는 거짓 = 표 · 권한 없음)."""

    def __init__(self, rows=(), total=None, answers=None):
        self.calls, self.rows, self.answers = [], list(rows), answers or {}
        self.total = len(self.rows) if total is None else total

    def reply(self, kind, sql):
        if sql == "SELECT now()":
            return NOW
        if sql.startswith(s.SOURCES_SQL):
            return {"fetchval": self.total, "fetchrow": self.rows[0] if self.rows else None, "fetch": self.rows}[kind]
        value = self.answers.get(sql)
        if kind == "fetch":
            return value or []
        if kind == "fetchrow":
            return value[0] if value else None
        return value

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self)

    def sql(self, kind=None):
        return [c[1] for c in self.calls if c[0] != "transaction" and (kind is None or c[0] == kind)]


class Base(unittest.TestCase):
    """시험 앱에 main 의 세션 검사와 이 라우터를 붙인다(main.app 에 붙이는 것은 통합 담당이 한다)."""

    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        self.app = FastAPI()
        self.app.middleware("http")(self.main.require_session)
        self.app.include_router(s.router)
        self.app.state.pool = self.pool
        # 세션 검사가 요청마다 계정을 다시 본다(이슈 #59). 계정 표는 가짜로 두고, 세션 없는 요청이 조회하지 않는지도 본다
        self.accounts = test_web.FakeAccounts().patch(self)
        self.client = TestClient(self.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def login(self, role="viewer"):
        import test_web
        self.accounts["han"] = test_web.account_row(role)
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", role))

    def use(self, pool):
        self.pool = self.app.state.pool = pool


class ArgumentTests(Base):
    def setUp(self):
        super().setUp()
        self.login()

    def assert_422(self, path, params):
        response = self.client.get(path, params=params)
        self.assertEqual(response.status_code, 422, (path, params, response.text))
        self.assertEqual(self.pool.calls, [])

    def test_목록_인자(self):
        for params in ({"q": "198.51.100.0/24"}, {"q": "abc_"}, {"q": "g"}, {"q": "%"}, {"q": ""}, {"q": "1" * 46},
                       {"q": "1.2\n"}, {"sort": "ip"}, {"include_test": "maybe"},
                       {"fp_kind": "hassh"}, {"fp": "abc"}, {"fp_kind": "ja3", "fp": "abc"},
                       {"fp_kind": "user_agent", "fp": ""}, {"fp_kind": "user_agent", "fp": "x" * 513},
                       {"fp_kind": "user_agent", "fp": "curl\x00"},
                       {"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": cti.MAX_OFFSET + 1}):
            with self.subTest(params=params):
                self.assert_422("/api/sources", params)

    def test_지문_종류와_값은_함께다(self):
        for params in ({"fp_kind": "hassh"}, {"fp": "0" * 32}):
            with self.subTest(params=params):
                response = self.client.get("/api/sources", params=params)
                self.assertEqual(response.json(), {"detail": "지문 종류(fp_kind)와 값(fp)을 함께 지정해 주세요"})

    def test_상세_인자(self):
        for params in ({}, {"ip": "abc"}, {"ip": "198.51.100.0/24"}, {"ip": "fe80::1%eth0"}, {"ip": "1" * 65}):
            with self.subTest(params=params):
                self.assert_422("/api/sources/detail", params)

    def test_지문_묶음_인자(self):
        for params in ({}, {"kind": "ja3"}, {"kind": "hassh", "limit": 0}, {"kind": "hassh", "limit": 101},
                       {"kind": "hassh", "offset": -1}):
            with self.subTest(params=params):
                self.assert_422("/api/sources/fingerprints", params)


class ListTests(Base):
    def setUp(self):
        super().setUp()
        self.login()

    def test_한_트랜잭션에서_시간_상한을_먼저_건다(self):
        response = self.client.get("/api/sources")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"as_of": NOW.isoformat(), "total": 0, "limit": 50, "offset": 0,
                                           "checkers": {"gateway_stale": None, "fw_stale": None}, "items": []})
        self.assertEqual(self.pool.calls[0], ("transaction", {"isolation": "repeatable_read", "readonly": True}))
        self.assertEqual(self.pool.calls[1], ("execute", s.STATEMENT_TIMEOUT, ()))
        self.assertEqual(s.STATEMENT_TIMEOUT, "SET LOCAL statement_timeout = '5s'")
        self.assertEqual([c for c in self.pool.calls if c[0] == "transaction"], [self.pool.calls[0]])
        # 쪽이 비면 이벤트 · 차단은 묻지 않는다. 생존 신호 표가 없으면 읽지 않는다
        for sql in (s.SENSORS_SQL, s.BLOCKS_SQL, targets.HEARTBEATS_SQL):
            self.assertNotIn(sql, self.pool.sql())
        self.assertIn(targets.HEARTBEATS_READABLE_SQL, self.pool.sql())

    def test_조건은_인자로_넘기고_시험_대역은_기본으로_뺀다(self):
        self.client.get("/api/sources", params={"q": "2001:DB8", "fp_kind": "user_agent", "fp": "curl/8.0",
                                                "sort": "severity", "limit": 20, "offset": 40})
        count, page = [c for c in self.pool.calls if c[0] in ("fetchval", "fetch") and c[1].startswith(s.SOURCES_SQL)]
        self.assertEqual(count[2], ("2001:db8%", "curl/8.0"))
        self.assertEqual(page[2], ("2001:db8%", "curl/8.0", 20, 40))
        self.assertIn("NOT s.test_source", page[1])
        self.assertIn("s.ip LIKE $1", page[1])
        self.assertIn(f"({s.fp_events('user_agent')}) f WHERE f.value = $2", page[1])
        self.assertIn(f"ORDER BY {s.ORDERS['severity']} LIMIT $3 OFFSET $4", page[1])
        # 조건이 없으면 인자도 없다. 시험 대역을 넣으면 거르지 않는다
        self.use(FakePool())
        self.client.get("/api/sources", params={"include_test": "true"})
        page = [c for c in self.pool.calls if c[0] == "fetch" and c[1].startswith(s.SOURCES_SQL)][0]
        self.assertEqual(page[2], (50, 0))
        self.assertNotIn("NOT s.test_source", page[1])

    def test_항목은_쪽에_나온_주소만_따로_묻는다(self):
        rows = [row(), row(ip="2001:db8::1", rank=1, test_source=True)]
        self.use(FakePool(rows, total=7, answers={
            s.SENSORS_SQL: [seen(["cowrie", "web-01"], minutes=3)],
            s.BLOCKS_SQL: [block_row()],
            targets.HEARTBEATS_READABLE_SQL: True,
            targets.HEARTBEATS_SQL: [hb("block:gateway", 1)],
        }))
        body = self.client.get("/api/sources", params={"include_test": "true"}).json()
        self.assertEqual((body["total"], len(body["items"])), (7, 2))
        self.assertEqual(body["checkers"], {"gateway_stale": False, "fw_stale": True})
        first, second = body["items"]
        self.assertEqual((first["ip"], first["severity"], first["targets"], first["block"]["reason"]),
                         ("198.51.100.7", "critical", ["aws-sensor", "web-01"], "SSH 무차별 대입"))
        self.assertEqual(first["block"]["enforcement"]["gateway"]["state"], "confirmed")
        self.assertEqual((second["ip"], second["severity"], second["targets"], second["block"], second["test_source"]),
                         ("2001:db8::1", "high", [], None, True))
        # 마지막 관측은 발생원과 같은 질의에서 온다. 이벤트가 없는 주소는 null
        self.assertEqual([i["last_seen"] for i in body["items"]], [(NOW - timedelta(minutes=3)).isoformat(), None])
        # block_exempt 를 읽을 수 없고 상수 대역에도 들지 않으면 모른다(null)
        self.assertEqual([i["exempt"] for i in body["items"]], [None, None])
        for sql in (s.SENSORS_SQL, s.BLOCKS_SQL, targets.EXEMPT_SQL):
            args = [c[2] for c in self.pool.calls if c[1] == sql]
            self.assertEqual(args[0][0], ["198.51.100.7", "2001:db8::1"], sql)
        # 차단 제외 대역은 코드 상수(표가 없을 때)를 넘긴다
        self.assertEqual([c[2][1] for c in self.pool.calls if c[1] == targets.EXEMPT_SQL], [absorbed.NO_BLOCK_NETS])

    def test_상수_대역에_들면_표가_없어도_제외다(self):
        self.use(FakePool([row(ip="10.0.0.5")], answers={targets.EXEMPT_SQL: [{"ip": "10.0.0.5"}]}))
        self.assertIs(self.client.get("/api/sources").json()["items"][0]["exempt"], True)


class DetailTests(Base):
    def setUp(self):
        super().setUp()
        self.login()

    def test_사건도_이벤트도_없으면_404_다(self):
        response = self.client.get("/api/sources/detail", params={"ip": "2001:DB8::9"})
        self.assertEqual((response.status_code, response.json()), (404, {"detail": "이 출발지의 사건이나 이벤트가 없습니다"}))
        # 정규화한 주소로 묻는다
        self.assertEqual([c[2] for c in self.pool.calls if c[1] == s.HAS_EVENTS_SQL], [("2001:db8::9",)])

    def test_이벤트만_있으면_요약이_null_이고_표가_없으면_null_이다(self):
        kinds = [{"sensor": "cowrie", "eventid": "cowrie.client.kex", "count": 2, "first_ts": NOW, "last_ts": NOW}]
        self.use(FakePool(answers={s.HAS_EVENTS_SQL: True, s.EVENT_KINDS_SQL: kinds,
                                   s.LAST_SEEN_SQL: NOW - timedelta(minutes=7),
                                   s.fp_counts_sql("hassh"): [{"value": "0" * 32, "count": 2}]}))
        response = self.client.get("/api/sources/detail", params={"ip": "198.51.100.200"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # 요약이 없어도 마지막 관측과 차단 제외(표를 못 읽고 상수 대역에도 들지 않으면 모름)는 머리에 있다
        self.assertEqual({k: body[k] for k in ("as_of", "ip", "summary", "last_seen", "incidents", "incidents_total",
                                               "actions", "block", "exempt", "exempt_flag", "absorbed", "checkers")},
                         {"as_of": NOW.isoformat(), "ip": "198.51.100.200", "summary": None,
                          "last_seen": (NOW - timedelta(minutes=7)).isoformat(), "incidents": [],
                          "incidents_total": 0, "actions": [], "block": None, "exempt": None, "exempt_flag": None,
                          "absorbed": None, "checkers": {"gateway_stale": None, "fw_stale": None}})
        # 사건이 없으니 이벤트 종류에서 콘솔 기록을 뺀다(셋째 인자 거짓)
        self.assertEqual([c[2] for c in self.pool.calls if c[1] == s.EVENT_KINDS_SQL], [("198.51.100.200", 50, False)])
        self.assertEqual(body["event_kinds"], [{"sensor": "cowrie", "eventid": "cowrie.client.kex", "count": 2,
                                                "first_ts": NOW.isoformat(), "last_ts": NOW.isoformat()}])
        self.assertEqual(body["fingerprints"], {"hassh": [{"value": "0" * 32, "count": 2}], "ssh_version": [],
                                                "user_agent": []})
        # 흡수 기록 표가 없으면 세지 않는다. 한 트랜잭션 · 시간 상한이 먼저다
        self.assertNotIn(s.ABSORBED_SQL, self.pool.sql())
        self.assertEqual(self.pool.calls[1], ("execute", s.STATEMENT_TIMEOUT, ()))

    def test_요약은_목록_항목과_같은_모양이다(self):
        self.use(FakePool([row()], answers={s.BLOCKS_SQL: [block_row()], cti.TABLES_SQL: True, s.ABSORBED_SQL: 4,
                                            s.SENSORS_SQL: [seen(["cowrie"])]}))
        body = self.client.get("/api/sources/detail", params={"ip": "198.51.100.7"}).json()
        self.assertEqual(set(body["summary"]), {"ip", "incidents", "unjudged", "severity", "rules", "targets",
                                                "first_ts", "last_ts", "last_seen", "verdicts", "test_source", "exempt",
                                                "block"})
        self.assertEqual((body["incidents_total"], body["absorbed"], body["block"]), (3, 4, body["summary"]["block"]))
        # 머리의 마지막 관측 · 차단 제외는 요약 값이다
        self.assertEqual((body["last_seen"], body["exempt_flag"]),
                         ((NOW - timedelta(minutes=10)).isoformat(), body["summary"]["exempt"]))
        # 요약이 있으면 이벤트 유무 · 마지막 관측은 따로 묻지 않고, 이벤트 종류는 콘솔 기록을 싣는다(셋째 인자 참)
        self.assertNotIn(s.HAS_EVENTS_SQL, self.pool.sql())
        self.assertNotIn(s.LAST_SEEN_SQL, self.pool.sql())
        self.assertEqual([c[2] for c in self.pool.calls if c[1] == s.EVENT_KINDS_SQL], [("198.51.100.7", 50, True)])
        self.assertEqual([c[2] for c in self.pool.calls if c[1] == s.ACTIONS_SQL],
                         [("198.51.100.7", ["block_ip", "unblock_ip"], 50)])

    def test_요약이_없어도_차단_제외는_목록과_같이_판단한다(self):
        # 표를 못 읽어도 코드 상수 대역에 들면 참이다. exempt(든 대역 객체)는 표를 못 읽으니 null 이다
        self.use(FakePool(answers={s.HAS_EVENTS_SQL: True, targets.EXEMPT_SQL: [{"ip": "10.0.0.5"}]}))
        body = self.client.get("/api/sources/detail", params={"ip": "10.0.0.5"}).json()
        self.assertEqual((body["summary"], body["exempt"], body["exempt_flag"], body["last_seen"]),
                         (None, None, True, None))
        self.assertEqual([c[2] for c in self.pool.calls if c[1] == targets.EXEMPT_SQL],
                         [(["10.0.0.5"], absorbed.NO_BLOCK_NETS)])


class FingerprintTests(Base):
    def test_묶음_응답(self):
        self.login()
        groups = s.fp_groups_sql("ssh_version")
        item = {"value": "SSH-2.0-Go", "sources": 3, "connections": 9, "incident_sources": 1,
                "first_ts": NOW - timedelta(days=1), "last_ts": NOW}
        self.use(FakePool(answers={f"{groups} SELECT count(*) FROM g": 1,
                                   f"{groups} SELECT * FROM g ORDER BY sources DESC, value LIMIT $1 OFFSET $2": [item]}))
        body = self.client.get("/api/sources/fingerprints", params={"kind": "ssh_version", "limit": 10}).json()
        self.assertEqual(body, {"as_of": NOW.isoformat(), "kind": "ssh_version", "total": 1, "limit": 10, "offset": 0,
                                "items": [{**item, "first_ts": (NOW - timedelta(days=1)).isoformat(),
                                           "last_ts": NOW.isoformat()}]})
        self.assertEqual(self.pool.calls[1], ("execute", s.STATEMENT_TIMEOUT, ()))
        self.assertEqual([c[2] for c in self.pool.calls if c[0] == "fetch"], [(10, 0)])


# ----------------------------------------------------------------------
#  4. 라우터
# ----------------------------------------------------------------------

class RouterTests(Base):
    def endpoint(self, app, path):
        from starlette.routing import Match
        scope = {"type": "http", "path": path, "method": "GET", "root_path": "", "headers": []}
        return next(r for r in app.routes if r.matches(scope)[0] == Match.FULL).endpoint

    def test_경로는_처리기로_간다(self):
        self.assertEqual([self.endpoint(self.app, p) for p in PATHS],
                         [s.list_sources, s.source_detail, s.fingerprint_groups])

    def test_세션이_없으면_401_이고_DB_에_닿지_않는다(self):
        for path in PATHS:
            with self.subTest(path=path):
                response = self.client.get(path, params={"ip": "198.51.100.7", "kind": "hassh"})
                self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual((self.pool.calls, self.accounts.calls), ([], []))

    def test_읽기_조회라_모든_역할이_본다(self):
        for role in ("viewer", "operator", "admin"):
            with self.subTest(role=role):
                self.login(role)
                self.assertEqual(self.client.get("/api/sources").status_code, 200)

    def test_main_앱에_붙었으면_거기서도_같다(self):
        paths = {getattr(r, "path", None) for r in self.main.app.routes}
        if not set(PATHS) <= paths:
            self.skipTest("main.app 에 아직 붙지 않았다(통합 담당)")
        self.assertEqual([self.endpoint(self.main.app, p) for p in PATHS],
                         [s.list_sources, s.source_detail, s.fingerprint_groups])
        client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(client.close)
        with patch.object(self.main.app.state, "pool", self.pool, create=True):
            for path in PATHS:
                with self.subTest(path=path):
                    self.assertEqual(client.get(path, params={"ip": "198.51.100.7", "kind": "hassh"}).status_code, 401)
        self.assertEqual(self.pool.calls, [])


# ----------------------------------------------------------------------
#  5. main.py 곁일
# ----------------------------------------------------------------------

class MainTests(unittest.TestCase):
    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        patcher = patch.object(self.main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(self.client.close)
        test_web.FakeAccounts().patch(self)["han"] = test_web.account_row("viewer")
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))

    def listing(self):
        """사건 목록의 쪽 질의 (질의, 인자)."""
        return [(c[1], c[2]) for c in self.pool.calls if c[0] == "fetch" and "pending_seconds" in c[1]][0]

    def test_사건_목록_actor_ip_가_주소가_아니면_422_다(self):
        for bad in ("abc", "198.51.100.0/24", "198.51.100.7'--", "fe80::1%eth0", "1.2.3.4\x00"):
            with self.subTest(actor_ip=bad):
                response = self.client.get("/api/incidents", params={"actor_ip": bad})
                self.assertEqual((response.status_code, response.json()),
                                 (422, {"detail": "actor_ip 는 IP 주소여야 합니다"}))
        self.assertEqual(self.pool.calls, [])

    def test_사건_목록_actor_ip_는_정규화해_넘긴다(self):
        response = self.client.get("/api/incidents", params={"actor_ip": " 2001:DB8:0::7 "})
        self.assertEqual(response.status_code, 200)
        sql, args = self.listing()
        self.assertIn("i.actor_ip = $1::inet", sql)
        self.assertEqual(args[0], "2001:db8::7")

    def test_사건_목록_actor_ip_가_비면_조건이_없다(self):
        self.assertEqual(self.client.get("/api/incidents", params={"actor_ip": ""}).status_code, 200)
        sql, args = self.listing()
        self.assertNotIn("actor_ip = $", sql)
        self.assertEqual(args, (50, 0))

    def test_요약_상위_출발지는_순위로_심각도를_고른다(self):
        self.assertNotIn("max(severity)", self.main.TOP_ACTORS_SQL)
        self.assertIn("min(CASE severity WHEN 'critical' THEN 1", self.main.TOP_ACTORS_SQL)
        self.assertIn("ORDER BY n DESC, actor_ip", self.main.TOP_ACTORS_SQL)


if __name__ == "__main__":
    unittest.main()
