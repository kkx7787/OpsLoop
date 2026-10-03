#!/usr/bin/env python3
"""차단 적용 지점(이슈 #77 · app/block_points.py) 시험.  python3 app/test_block_points.py

보는 것
  1. 기본값 · 까닭 · 정규화(DB 없이): default_points 표(R004 → 두 지점, 나머지 → 내부 방화벽), basis_of 표(허니팟 남용 · 센서만 ·
     보호 대상 · 관제 시스템 · 미확인 · 섞임), normalize
  2. 입력(DB 없이): points 없음 → 두 지점, ["fw"], ["fw", "gateway"] 정규화, ["gateway"] · [] · 중복 · 모르는 값은 DB 에 닿기 전에 422,
     차단 밖의 조치(unblock_ip 등)에 points 는 400
  3. 같은 상수: 종합 상태(main · reports 가 block_points.BLOCK_STATES_SQL 을 그대로 쓴다) · 집행 말머리 · BLOCK_SQL 의 합집합
  4. 종합 상태 경우 표(STATE_CASES) · 지점 칸 경우 표(POINT_CASES, targets.BLOCKS_SQL 의 적용 · 실패 · 미확인 · 미요청 · 빠짐 확인 전,
     임시 표): 화면(console format.ts blockState · pointCounts)이 같은 표로 시험한다
  5. 실제 스키마(무작위 데이터베이스에 infra/schema.sql 전체를 넣고 콘솔 역할로 돈다. 슈퍼유저 연결일 때만):
     BLOCK_SQL(새 요청은 받은 값 · 살아 있는 행은 합집합이라 좁힌 요청도 넓은 채 · 넓히면 console.block.points 한 줄 · 해제 · 만료 행
     재요청은 받은 값 · 감사 detail 의 points=) · 관리자 관문 빼기(한 트랜잭션에서 released · rearmed, 다른 연결은 중간 상태를 보지
     못함, 커밋 뒤 살아 있는 {fw}, 관문 세 열 · 지점 결과는 그대로라 unenforced 가 요청 시각에 남지 않음) · 해제 · 만료 행을 다시
     걸기(관문 포함 여부와 무관하게 관문 세 열 · 지점 결과 그대로 · unenforced 없음, 결정 2) · operator 403 · 지점만
     좁히는 갱신은 트리거가 거부 · kept 행 넓히기(지점만, console.block.points
     한 줄, 내부 방화벽만 요청이면 그대로) · 사건 상세 block_points(기본값 · 까닭 · 살아 있는 요청) · blocked.points · /api/blocklist
DB 스키마 자체(열 · CHECK · 트리거 · 재적용)는 infra/test_block_points_choice_db.py 가 본다.

실행: python -m unittest discover -s app
"""
import asyncio
import json
import os
import re
import secrets
import sys
import unittest
from collections import Counter
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_web  # noqa: E402  asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
import test_inputs  # noqa: E402
from pydantic import ValidationError  # noqa: E402

import absorbed  # noqa: E402
import block_points as bp  # noqa: E402
import reports  # noqa: E402
import targets  # noqa: E402

main = test_web.main
URL = os.environ.get("OPSLOOP_TEST_DATABASE_URL")
SCHEMA = Path(__file__).resolve().parents[1] / "infra" / "schema.sql"
BLOCK_HEADER = "-- 차단 적용 지점 선택 (이슈 #77)"
ADMIN = SimpleNamespace(state=SimpleNamespace(user={"u": "boss", "r": "admin"}))
OPERATOR = SimpleNamespace(state=SimpleNamespace(user={"u": "han", "r": "operator"}))

# 종합 상태 경우 표(결정 b). (이름, 요청 지점, 만료 있음, 관문 확인 시각 있음, enforce_note, enforcement, 기대 상태)
#   요청한 지점이 모두 확인이어야 적용. 제외 > 실패 > 불일치 > 대기 > 적용. 관문의 확인 · 불일치 쪽지는 관문 세 열, 실패 · 지연은
#   enforcement.gateway(대기 · 남은 빠짐 확인 전은 확인 시각이 남아도 대기, 결정 2), 내부 방화벽은 enforcement.fw 로 본다.
#   요청하지 않은 지점은 보지 않는다
GF, F = ["gateway", "fw"], ["fw"]
C, P, S, X, R = ({"state": s} for s in ("confirmed", "pending", "stale", "failed", "removing"))
APPLIED, MISMATCH, EXCLUDED = "관문 반영 · abcd1234 · x", "관문 불일치 · 5분 넘게 반영되지 않음", "집행 제외 · 금지 대역"
KEPT, UNCERTAIN = APPLIED + " · 기존 차단 유지", APPLIED + " · 연속성 확인 불가"
STATE_CASES = [
    ("두 지점 · 모두 확인", GF, True, True, APPLIED, {"gateway": C, "fw": C}, "enforced"),
    ("두 지점 · 관문 확인 · 내부 방화벽 대기", GF, True, True, APPLIED, {"gateway": C, "fw": P}, "pending"),
    ("두 지점 · 관문 확인 · 내부 방화벽 기록 없음", GF, True, True, APPLIED, None, "pending"),
    ("두 지점 · 내부 방화벽 확인 · 관문 확인 전", GF, True, False, None, {"fw": C}, "pending"),
    ("두 지점 · 다시 건 직후 남은 빠짐 확인 전", GF, True, False, None, {"gateway": R, "fw": R}, "pending"),
    ("두 지점 · 관문 빼기 뒤 다시 요청(집행기 회차 전)", GF, True, True, APPLIED, {"gateway": R, "fw": C}, "pending"),
    ("두 지점 · 다시 건 뒤 관문 새 목록 확인 전(남은 확인 시각)", GF, True, True, APPLIED, {"gateway": P, "fw": C}, "pending"),
    ("두 지점 · 관문이 뺀 뒤 다시 건 행(확인 시각 없이 남은 쪽지)", GF, True, False, APPLIED, {"gateway": P, "fw": C}, "pending"),
    ("두 지점 · 기존 차단 유지로 다시 확인", GF, True, True, KEPT, {"gateway": C, "fw": C}, "enforced"),
    ("두 지점 · 연속성 확인 불가로 다시 확인", GF, True, True, UNCERTAIN, {"gateway": C, "fw": C}, "enforced"),
    ("두 지점 · 내부 방화벽 지연", GF, True, True, APPLIED, {"gateway": C, "fw": S}, "mismatch"),
    ("두 지점 · 관문 불일치 쪽지", GF, True, False, MISMATCH, {"gateway": S, "fw": C}, "mismatch"),
    ("두 지점 · 관문 지연(쪽지 전)", GF, True, True, APPLIED, {"gateway": S, "fw": C}, "mismatch"),
    ("두 지점 · 내부 방화벽 실패", GF, True, True, APPLIED, {"gateway": C, "fw": X}, "failed"),
    ("두 지점 · 관문 실패가 불일치 쪽지보다 먼저", GF, True, False, "관문 불일치 · 관문 거부 · x", {"gateway": X, "fw": S},
     "failed"),
    ("내부 방화벽만 · 확인(관문 열 없음)", F, True, False, None, {"fw": C}, "enforced"),
    ("내부 방화벽만 · 대기", F, True, False, None, {"fw": P}, "pending"),
    ("내부 방화벽만 · 기록 없음", F, True, False, None, None, "pending"),
    ("내부 방화벽만 · 지연", F, True, False, None, {"fw": S}, "mismatch"),
    ("내부 방화벽만 · 실패", F, True, False, None, {"fw": X}, "failed"),
    ("내부 방화벽만 · 남은 관문 쪽지 · 관문 실패는 보지 않음", F, True, True, MISMATCH, {"gateway": X, "fw": C}, "enforced"),
    ("내부 방화벽만 · 관문 빠짐 확인 전은 보지 않음", F, True, True, APPLIED, {"gateway": R, "fw": C}, "enforced"),
    ("내부 방화벽만 · 관문 빠짐 확인 전 · 내부 방화벽 대기", F, True, True, APPLIED, {"gateway": R, "fw": P}, "pending"),
    ("두 지점 · 만료 없음", GF, False, True, APPLIED, {"gateway": C, "fw": C}, "excluded"),
    ("내부 방화벽만 · 집행 제외 쪽지가 실패보다 먼저", F, True, False, EXCLUDED, {"fw": X}, "excluded"),
]

# 지점 칸 경우 표(이슈 #77 결정 14, 살아 있는 집행 대상 행). (이름, 요청 지점, 관문 확인 시각 있음, enforcement, 관문 칸, 내부 방화벽 칸)
#   칸은 targets.BLOCKS_SQL 의 applied · failed · unverified · unrequested · removing 가운데 이 행이 드는 곳이다. 요청하지 않은 지점에
#   기록(state 가 글자인 결과 기록, 관문은 확인 시각도)이 남았으면 빠짐 확인 전(removing)이고 요청 행 · 미요청 어디에도 들지 않는다
POINT_CASES = [
    ("두 지점 · 모두 확인", GF, True, {"gateway": C, "fw": C}, "applied", "applied"),
    ("두 지점 · 관문 실패 · 내부 방화벽 대기", GF, False, {"gateway": X, "fw": P}, "failed", "unverified"),
    ("두 지점 · 다시 건 직후 남은 빠짐 확인 전", GF, False, {"gateway": R, "fw": R}, "unverified", "unverified"),
    ("두 지점 · 관문 빼기 뒤 다시 요청(집행기 회차 전)", GF, True, {"gateway": R, "fw": C}, "unverified", "applied"),
    ("두 지점 · 다시 건 뒤 관문 새 목록 확인 전(남은 확인 시각)", GF, True, {"gateway": P, "fw": C}, "unverified", "applied"),
    ("내부 방화벽만 · 관문 기록 없음", F, False, {"fw": C}, "unrequested", "applied"),
    ("내부 방화벽만 · 관문 기록의 state 가 글자가 아님", F, False, {"gateway": {"state": 1}, "fw": C}, "unrequested", "applied"),
    ("내부 방화벽만 · 관문 빼기 직후(관문 세 열 · 관문 결과 남음)", F, True, {"gateway": C, "fw": C}, "removing", "applied"),
    ("내부 방화벽만 · 관문 빠짐 확인 전", F, True, {"gateway": R, "fw": C}, "removing", "applied"),
    ("내부 방화벽만 · 관문 확인 전에 뺌(결과만 남음)", F, False, {"gateway": R, "fw": X}, "removing", "failed"),
    ("내부 방화벽만 · 관문 확인 시각만 남음(옛 집행기)", F, True, {"fw": S}, "removing", "unverified"),
    ("내부 방화벽만 · 남은 관문 실패 기록", F, False, {"gateway": X}, "removing", "unverified"),
]
CELLS = ("applied", "failed", "unverified", "unrequested", "removing")


# ----------------------------------------------------------------------
#  1 · 2 · 3. DB 없이
# ----------------------------------------------------------------------

class DefaultsTests(unittest.TestCase):
    def test_기본값은_규칙만으로_정한다(self):
        self.assertEqual(bp.HONEYPOT_ABUSE_RULES, frozenset({"R004"}))
        self.assertEqual(bp.default_points("R004"), ["gateway", "fw"])
        for rule in ("R001", "R002", "R003", "R005", "R006", "R101", "R102", "R105", "R107", "R201", "R202", "R301", None):
            with self.subTest(rule=rule):
                self.assertEqual(bp.default_points(rule), ["fw"])
        bp.default_points("R004").append("x")                  # 돌려준 목록을 고쳐도 기본값은 그대로다
        self.assertEqual(bp.DEFAULT, ["gateway", "fw"])

    def test_까닭은_규칙이_먼저이고_장비_무리로_고른다(self):
        def devices(*groups):
            return [{"id": f"d{i}", "part": None, "group": g} for i, g in enumerate(groups)]
        for rule, found, state, want in [
                ("R004", devices("protected"), "confirmed", "honeypot_abuse"),     # 규칙이 먼저(장비는 까닭에만)
                ("R004", [], "unconfirmed", "honeypot_abuse"),
                ("R001", devices("sensor"), "confirmed", "sensor_only"),
                ("R003", devices("sensor", "sensor"), "rule_scope", "sensor_only"),
                ("R102", devices("protected"), "confirmed", "protected"),
                ("R101", devices("sensor", "protected"), "confirmed", "protected"),   # 섞임: 보호 대상이 있으면 보호 대상
                ("R202", devices("protected", "monitor"), "confirmed", "protected"),
                ("R201", devices("monitor"), "confirmed", "monitor"),
                ("R005", devices("sensor", "monitor"), "rule_scope", "monitor"),      # 센서 + 관제 시스템
                ("R001", [], "unconfirmed", "unconfirmed"),
                ("R001", None, None, "unconfirmed")]:
            with self.subTest(rule=rule, groups=[d["group"] for d in found or []]):
                self.assertEqual(bp.basis_of(rule, found, state), want)
                self.assertIn(want, bp.BASES)

    def test_정규화(self):
        self.assertEqual(bp.normalize(["fw"]), ["fw"])
        self.assertEqual(bp.normalize(["fw", "gateway"]), ["gateway", "fw"])
        self.assertEqual(bp.normalize(("gateway", "fw")), ["gateway", "fw"])
        for bad in (["gateway"], [], ["fw", "fw"], ["x"], ["fw", "x"], ["gateway", "gateway", "fw"], "fw", None):
            with self.subTest(points=bad), self.assertRaises(ValueError):
                bp.normalize(bad)

    def test_조치_입력(self):
        self.assertIsNone(main.ActionIn(action="block_ip").points)                  # 없으면 두 지점(옛 화면 호환)
        self.assertEqual(main.ActionIn(action="block_ip", points=["fw"]).points, ["fw"])
        self.assertEqual(main.ActionIn(action="block_ip", points=["fw", "gateway"]).points, ["gateway", "fw"])
        for bad in (["gateway"], [], ["fw", "fw"], ["x"], [1]):
            with self.subTest(points=bad), self.assertRaises(ValidationError):
                main.ActionIn(action="block_ip", points=bad)


class SameConstantTests(unittest.TestCase):
    def test_종합_상태는_한_상수다(self):
        self.assertIs(main.BLOCK_STATES_SQL, bp.BLOCK_STATES_SQL)
        self.assertIs(reports.BLOCK_STATES_SQL, bp.BLOCK_STATES_SQL)
        self.assertIn(bp.STATE_CASE, bp.BLOCK_STATES_SQL)
        self.assertEqual(bp.STATES, ("enforced", "pending", "excluded", "mismatch", "failed"))
        for module in (main, targets, reports):
            with self.subTest(module=module.__name__):
                self.assertEqual((module.ENFORCE_EXCLUDED, module.ENFORCE_MISMATCH),
                                 (bp.ENFORCE_EXCLUDED, bp.ENFORCE_MISMATCH))

    def test_BLOCK_SQL_은_살아_있으면_합집합이다(self):
        self.assertIn(f"points       = CASE WHEN {main._LIVE} THEN {bp.UNION_SQL} ELSE EXCLUDED.points END",
                      main.BLOCK_SQL)
        self.assertIn("$6::text[]", main.BLOCK_SQL)

    def test_다시_걸기는_관문_세_열을_건드리지_않는다(self):
        # 콘솔 차단 · 흡수 차단(후속 차단 포함)이 같다(triage 사본은 test_triage 가 맞춰 본다). 관문 포함 여부와 무관하게 요청 시각에
        # 비우지 않고 집행기가 판단한다(결정 2). 관문 빼기($7)는 만료에만 쓴다
        for sql in (main.BLOCK_SQL, absorbed.BLOCK_ABSORBED_SQL):
            update = sql.split("DO UPDATE", 1)[1]
            for col in ("method", "enforced_at", "enforce_note", "enforcement"):
                with self.subTest(col=col):
                    self.assertIsNone(re.search(rf"\b{col}\s*=", update), col)
        self.assertEqual(main.BLOCK_SQL.count("$7"), 1)


class HttpTests(test_inputs.AppBase):
    role = "admin"

    def test_지점_형식_밖은_DB_에_닿기_전에_422(self):
        for bad in (["gateway"], [], ["fw", "fw"], ["fw", "x"], "fw", [None]):
            with self.subTest(points=bad):
                response = self.client.post("/api/incidents/k1/actions", json={"action": "block_ip", "points": bad},
                                            headers=test_inputs.SAME)
                self.assert_masked(response, bad)
        self.assert_no_db()

    def test_차단_밖의_조치에_지점은_400(self):
        for action in ("unblock_ip", "note", "acknowledge", "suppress_rule"):
            with self.subTest(action=action):
                response = self.client.post("/api/incidents/k1/actions", json={"action": action, "points": ["fw"]},
                                            headers=test_inputs.SAME)
                self.assertEqual((response.status_code, response.json()), (400, {"detail": "points 는 차단에만 씁니다"}))
        self.assert_no_db()


# ----------------------------------------------------------------------
#  4. 종합 상태 경우 표(임시 표)
# ----------------------------------------------------------------------

def temp_blocklist() -> str:
    """schema.sql 의 blocklist 정의(첫 CREATE TABLE 과 뒤따른 ADD COLUMN, #77 블록 DO 안의 points 포함)를 임시 표로."""
    schema = SCHEMA.read_text(encoding="utf-8")
    body = re.search(r"^CREATE TABLE IF NOT EXISTS blocklist \(\n.*?\n\);", schema, re.S | re.M).group(0)
    alters = [a.strip() for a in re.findall(r"^\s*ALTER TABLE blocklist ADD COLUMN .*?;$", schema, re.M)]
    assert any(" points " in a for a in alters), "schema.sql 에 blocklist.points 가 없다"
    return "\n".join([body.replace("CREATE TABLE IF NOT EXISTS", "CREATE TEMP TABLE", 1), *alters])


@unittest.skipUnless(URL, "PostgreSQL 시험 연결 미지정")
class StateCaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_종합_상태_경우_표(self):
        import asyncpg
        conn = await asyncpg.connect(URL)
        try:
            await conn.execute("SET search_path TO pg_temp")
            await conn.execute(temp_blocklist())
            for n, (_, points, expires, enforced, note, enforcement, _) in enumerate(STATE_CASES, 1):
                await conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforced_at, enforce_note, enforcement,
                    points) VALUES ($1, CASE WHEN $2::boolean THEN now() + interval '1 hour' END,
                            CASE WHEN $3::boolean THEN now() END, $4, $5::jsonb, $6)""",
                                   f"198.51.100.{n}", expires, enforced, note,
                                   json.dumps(enforcement) if enforcement is not None else None, points)
            got = {r["ip"]: r["s"] for r in await conn.fetch(
                f"SELECT host(actor_ip) AS ip, {bp.STATE_CASE} AS s FROM blocklist")}
            for n, case in enumerate(STATE_CASES, 1):
                with self.subTest(case=case[0]):
                    self.assertEqual(got[f"198.51.100.{n}"], case[-1])
            want = Counter(case[-1] for case in STATE_CASES)
            counts = dict(await conn.fetchrow(bp.BLOCK_STATES_SQL, await conn.fetchval("SELECT now()")))
            self.assertEqual(counts, {"total": len(STATE_CASES), **{s: want[s] for s in bp.STATES}})
            self.assertTrue(all(want[s] for s in bp.STATES))              # 다섯 상태가 모두 표에 있다
        finally:
            await conn.close()

    async def test_지점_칸_경우_표(self):
        import asyncpg
        conn = await asyncpg.connect(URL)
        try:
            await conn.execute("SET search_path TO pg_temp")
            await conn.execute(temp_blocklist())
            for name, points, enforced, enforcement, gateway, fw in POINT_CASES:
                with self.subTest(case=name):
                    await conn.execute("TRUNCATE blocklist")
                    await conn.execute("""INSERT INTO blocklist (actor_ip, expires_at, enforced_at, enforce_note, enforcement,
                        points) VALUES ('198.51.100.1', now() + interval '1 hour', CASE WHEN $1::boolean THEN now() END,
                                CASE WHEN $1::boolean THEN $2::text END, $3::jsonb, $4)""",
                                       enforced, APPLIED, json.dumps(enforcement), points)
                    row = dict(await conn.fetchrow(targets.BLOCKS_SQL, await conn.fetchval("SELECT now()")))
                    for point, cell in (("gateway", gateway), ("fw", fw)):
                        self.assertEqual([c for c in CELLS if row[f"{point}_{c}"]], [cell], point)
                        self.assertEqual(sum(row[f"{point}_{c}"] for c in CELLS), 1, point)
            self.assertEqual({c for case in POINT_CASES for c in case[4:]}, set(CELLS))   # 다섯 칸이 모두 표에 있다
        finally:
            await conn.close()


# ----------------------------------------------------------------------
#  5. 실제 스키마
# ----------------------------------------------------------------------

def db_url(dbname: str) -> str:
    return urlunsplit(urlsplit(URL)._replace(path="/" + dbname))


async def create_db(dbname, role):
    import asyncpg
    schema = SCHEMA.read_text(encoding="utf-8")
    if BLOCK_HEADER not in schema:
        raise unittest.SkipTest("schema.sql 에 차단 적용 지점 블록(이슈 #77)이 없다")
    admin = await asyncpg.connect(URL)
    try:
        if not await admin.fetchval("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"):
            raise unittest.SkipTest("시험 연결이 슈퍼유저가 아니다(데이터베이스 · 역할 생성)")
        await admin.execute(f"CREATE DATABASE {dbname}")
        await admin.execute(f"CREATE ROLE {role} NOLOGIN NOINHERIT")
    finally:
        await admin.close()
    c = await asyncpg.connect(db_url(dbname))
    try:
        await c.execute("SET client_min_messages = warning")
        await c.execute(re.sub(r"\bopsloop_console\b", role, schema))
    finally:
        await c.close()


async def drop_db(dbname, role):
    import asyncpg
    admin = await asyncpg.connect(URL)
    try:
        await admin.execute(f"DROP DATABASE IF EXISTS {dbname} WITH (FORCE)")
        await admin.execute(f"DROP ROLE IF EXISTS {role}")
    finally:
        await admin.close()


class Gated:
    """콘솔 연결을 감싼다. 관문 빼기의 해제 문장 바로 뒤(다시 걸기 전)에 after_release 를 부른다."""

    def __init__(self, conn, after_release):
        self.conn, self.after_release = conn, after_release

    def __getattr__(self, name):
        return getattr(self.conn, name)

    async def execute(self, sql, *args):
        out = await self.conn.execute(sql, *args)
        if sql == main.RELEASE_FOR_NARROW_SQL:
            await self.after_release()
        return out


@unittest.skipUnless(URL, "PostgreSQL 시험 연결 미지정")
class SchemaTests(unittest.IsolatedAsyncioTestCase):
    """무작위 데이터베이스 · 콘솔 역할. 시험마다 사건 · 차단 · 감사를 비운다."""

    @classmethod
    def setUpClass(cls):
        tag = secrets.token_hex(4)
        cls.dbname, cls.role = f"opsloop_t77_{tag}", f"t77_{tag}_console"
        cls.addClassCleanup(lambda: asyncio.run(drop_db(cls.dbname, cls.role)))
        asyncio.run(create_db(cls.dbname, cls.role))

    async def asyncSetUp(self):
        import asyncpg
        self.owner = await asyncpg.connect(db_url(self.dbname))
        await self.owner.execute("TRUNCATE incidents, blocklist, absorbed_blocks, incident_absorbed, events CASCADE")
        self.console = await asyncpg.connect(db_url(self.dbname))
        await self.console.execute(f"SET SESSION AUTHORIZATION {self.role}")
        self.conn = self.console
        self.now = await self.owner.fetchval("SELECT now()")

    async def asyncTearDown(self):
        await self.console.close()
        await self.owner.close()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def act(self, key, body, request=OPERATOR):
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True), \
                patch.object(main.hub, "broadcast", AsyncMock()):
            body.expected_version = await self.conn.fetchval(main.workflow.VERSION_SQL, key)
            return await main.add_action(key, body, request)

    async def incident(self, key, rule, ip, *, target=None, sensors=None, version="v3"):
        await self.owner.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip,
            target, first_ts, last_ts, signal_count, evidence) VALUES ($1, $2, $3, '시험 규칙', 'high', $4, $5, $6, $6, 1, $7)""",
            key, rule, version, ip, target, self.now - timedelta(minutes=5),
            json.dumps({"sensors": sensors}) if sensors else None)

    async def row(self, ip):
        return await self.owner.fetchrow("""SELECT points, released_at, released_by, expires_at, incident_key, requested_by,
            reason FROM blocklist WHERE actor_ip = $1""", ip)

    async def audit(self, ip=None):
        rows = await self.owner.fetch("""SELECT eventid, actor, detail FROM audit_log
            WHERE ($1::text IS NULL OR detail LIKE '%ip=' || $1 || ' %' OR detail LIKE '%ip=' || $1) ORDER BY ts""", ip)
        return [(r["eventid"], r["actor"], r["detail"]) for r in rows]

    async def block(self, ip, points, hours=1):
        async with self.console.transaction():
            await self.console.execute("SELECT set_config('opsloop.actor', 'han', true)")
            await self.console.execute(main.BLOCK_SQL, ip, "시험", None, "han", hours, points, False)

    async def test_BLOCK_SQL_은_새_요청이면_받은_값_살아_있으면_합집합이다(self):
        ip = "198.51.100.10"
        await self.block(ip, ["fw"], hours=5)
        self.assertEqual((await self.row(ip))["points"], ["fw"])
        # 넓히기: console.block.points 한 줄(만료는 앞당기지 않아 그대로다)
        await self.block(ip, ["gateway", "fw"])
        self.assertEqual((await self.row(ip))["points"], ["gateway", "fw"])
        # 좁힌 요청(내부 방화벽만)을 BLOCK_SQL 로 다시 걸어도 넓은 채다(트리거 거부도 감사도 없다)
        await self.block(ip, ["fw"])
        self.assertEqual((await self.row(ip))["points"], ["gateway", "fw"])
        events = await self.audit(ip)
        self.assertEqual([e for e, _, _ in events], ["console.block.created", "console.block.points"])
        self.assertIn(f"ip={ip} incident=- expires=", events[0][2])
        self.assertIn(" points=fw requested_by=han", events[0][2])
        self.assertTrue(events[1][2].endswith(f"ip={ip} from=fw to=gateway,fw"))
        self.assertEqual(events[1][1], "han")
        # 해제된 행 · 만료된 행에 다시 걸면 받은 값이다(rearmed · 만료 뒤 extended 의 points=)
        await self.owner.execute("UPDATE blocklist SET released_at = now(), released_by = 'boss' WHERE actor_ip = $1", ip)
        await self.block(ip, ["fw"])
        self.assertEqual((await self.row(ip))["points"], ["fw"])
        await self.owner.execute("UPDATE blocklist SET expires_at = now() - interval '1 second' WHERE actor_ip = $1", ip)
        await self.block(ip, ["gateway", "fw"], hours=2)
        self.assertEqual((await self.row(ip))["points"], ["gateway", "fw"])
        events = await self.audit(ip)
        rearmed = next(d for e, _, d in events if e == "console.block.rearmed")
        extended = [d for e, _, d in events if e == "console.block.extended"][-1]
        self.assertIn(" points=fw released_by=boss requested_by=han", rearmed)
        self.assertTrue(extended.endswith(" points=gateway,fw"))
        self.assertEqual([e for e, _, _ in events].count("console.block.points"), 1)   # 죽은 행을 다시 건 것은 넓히기가 아니다

    async def test_지점만_좁히는_갱신은_트리거가_거부한다(self):
        import asyncpg
        ip = "198.51.100.11"
        await self.block(ip, ["gateway", "fw"])
        with self.assertRaises(asyncpg.CheckViolationError) as error:
            await self.console.execute("UPDATE blocklist SET points = '{fw}' WHERE actor_ip = $1", ip)
        self.assertEqual(error.exception.constraint_name, "blocklist_points_narrow")

    async def test_관리자_관문_빼기는_한_요청에서_해제_뒤_다시_건다(self):
        key, ip = "R001|v3|198.51.100.12|x", "198.51.100.12"
        await self.incident(key, "R001", ip, sensors=["cowrie"])
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24))            # 옛 화면: 두 지점
        # 집행기가 관문 · 내부 방화벽 적용을 확인했다(소유자 연결이 집행기 대신 쓴다)
        await self.owner.execute("""UPDATE blocklist SET enforced_at = now(), method = 'nft', enforce_note = $2,
            enforcement = '{"gateway": {"state": "confirmed"}, "fw": {"state": "confirmed"}}' WHERE actor_ip = $1""",
                                 ip, APPLIED)
        enforce = "SELECT enforced_at, method, enforce_note, enforcement FROM blocklist WHERE actor_ip = $1"
        enforced = dict(await self.owner.fetchrow(enforce, ip))
        before = dict(await self.row(ip))
        self.assertEqual(before["points"], ["gateway", "fw"])
        # operator 는 403 이고 아무것도 바뀌지 않는다
        with self.assertRaises(main.HTTPException) as error:
            await self.act(key, main.ActionIn(action="block_ip", points=["fw"]))
        self.assertEqual(error.exception.status_code, 403)
        self.assertEqual(dict(await self.row(ip)), before)
        mark = len(await self.audit(ip))
        seen = []

        async def peek():
            seen.append(tuple(await self.owner.fetchrow(
                "SELECT released_at IS NULL, points FROM blocklist WHERE actor_ip = $1", ip)))
        self.conn = Gated(self.console, peek)
        out = await self.act(key, main.ActionIn(action="block_ip", expires_hours=2, points=["fw"]), ADMIN)
        # 해제 문장 뒤 · 다시 걸기 전에 다른 연결이 본 행은 커밋 전이라 그대로 살아 있는 두 지점이다
        self.assertEqual(seen, [(True, ["gateway", "fw"])])
        after = await self.row(ip)
        self.assertEqual((after["points"], after["released_at"], after["requested_by"]), (["fw"], None, "boss"))
        # 만료는 살아 있는 차단에 다시 걸 때처럼 앞당기지 않는다(24시간 차단을 2시간으로 빼도 24시간 그대로, shortened 없음)
        self.assertEqual(after["expires_at"], before["expires_at"])
        events = (await self.audit(ip))[mark:]
        self.assertEqual([(e, a) for e, a, _ in events], [("console.block.released", "boss"),
                                                          ("console.block.rearmed", "boss")])
        self.assertIn(" points=fw released_by=boss requested_by=boss", events[1][2])
        self.assertEqual(out["note"], "[관문 빼기 · 해제 뒤 다시 걸기]")
        # 관문 세 열 · 지점 결과는 그대로다(결정 14). 관문 칸은 관문이 실제로 뺐다고 확인될 때까지 빠짐 확인 전이고, 세 열은 그 뒤
        # 집행기가 비운다(unenforced 감사가 그때 남는다. 요청 시각에는 없다)
        self.assertEqual(dict(await self.owner.fetchrow(enforce, ip)), enforced)
        row = dict(await self.owner.fetchrow(targets.BLOCKS_SQL, await self.owner.fetchval("SELECT now()")))
        self.assertEqual({c: row[f"gateway_{c}"] for c in CELLS}, {"applied": 0, "failed": 0, "unverified": 0,
                                                                    "unrequested": 0, "removing": 1})
        self.assertEqual(row["fw_applied"], 1)

    async def test_관문_빼기는_만료를_늦추기만_하고_만료_없는_옛_차단은_그대로_없다(self):
        key, ip = "R001|v3|198.51.100.13|x", "198.51.100.13"
        await self.incident(key, "R001", ip, sensors=["cowrie"])
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=1))                # 옛 화면: 두 지점
        before = (await self.row(ip))["expires_at"]
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["fw"]), ADMIN)
        after = await self.row(ip)
        self.assertEqual(after["points"], ["fw"])
        self.assertGreater(after["expires_at"], before + timedelta(hours=20))                # 더 늦은 만료는 받는다
        # 만료 없는 옛 두 지점 차단(운영 13건 꼴): 관문을 빼도 만료가 생기지 않는다(집행 제외 그대로)
        await self.owner.execute("UPDATE blocklist SET expires_at = NULL, points = '{gateway,fw}' WHERE actor_ip = $1", ip)
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["fw"]), ADMIN)
        after = await self.row(ip)
        self.assertEqual((after["points"], after["expires_at"], after["released_at"]), (["fw"], None, None))
        self.assertNotIn("console.block.shortened", [e for e, _, _ in await self.audit(ip)])

    async def test_해제_만료_행을_다시_걸면_관문_포함_여부와_무관하게_관문_세_열을_둔다(self):
        # 2026-10-01 결정 · 결정 2: 요청 시각에는 다시 걸기 기록만 남는다. 관문 세 열은 관문이 실제로 뺐다고 확인한 뒤 집행기가 비우고
        # (unenforced 도 그때), 아니면 새 보고로 기존 차단 유지 · 연속성 확인 불가를 적는다(결정 3, enforcer RearmPgTest)
        key, ip = "R001|v3|198.51.100.14|x", "198.51.100.14"
        await self.incident(key, "R001", ip, sensors=["cowrie"])
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["gateway", "fw"]))
        await self.owner.execute("""UPDATE blocklist SET enforced_at = now(), method = 'nft', enforce_note = $2,
            enforcement = '{"gateway": {"state": "removing"}, "fw": {"state": "removing"}}',
            released_at = now(), released_by = 'boss' WHERE actor_ip = $1""", ip, APPLIED)
        enforce = "SELECT enforced_at, method, enforce_note, enforcement FROM blocklist WHERE actor_ip = $1"
        kept = dict(await self.owner.fetchrow(enforce, ip))
        mark = len(await self.audit(ip))
        out = await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["fw"]))   # operator 도 된다
        after = await self.row(ip)
        self.assertEqual((after["points"], after["released_at"], out["note"]), (["fw"], None, None))
        self.assertEqual(dict(await self.owner.fetchrow(enforce, ip)), kept)
        self.assertEqual([e for e, _, _ in (await self.audit(ip))[mark:]], ["console.block.rearmed"])
        # 만료된 뒤 관문을 요청해 다시 걸어도 그대로다(unenforced 없음, 결정 2)
        await self.owner.execute("UPDATE blocklist SET expires_at = now() - interval '1 second' WHERE actor_ip = $1", ip)
        mark = len(await self.audit(ip))
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["gateway", "fw"]))
        self.assertEqual((await self.row(ip))["points"], ["gateway", "fw"])
        self.assertEqual(dict(await self.owner.fetchrow(enforce, ip)), kept)
        self.assertEqual([e for e, _, _ in (await self.audit(ip))[mark:]], ["console.block.extended"])
        # 사람이 푼 뒤 관문을 요청해 다시 걸어도 그대로다
        await self.owner.execute("UPDATE blocklist SET released_at = now(), released_by = 'boss' WHERE actor_ip = $1", ip)
        mark = len(await self.audit(ip))
        await self.act(key, main.ActionIn(action="block_ip", expires_hours=24, points=["gateway", "fw"]))
        self.assertEqual(dict(await self.owner.fetchrow(enforce, ip)), kept)
        self.assertEqual([e for e, _, _ in (await self.audit(ip))[mark:]], ["console.block.rearmed"])

    async def test_kept_행은_관문을_요청하면_지점만_넓힌다(self):
        first, own, kept = "R006|v3|198.51.100.20|x", "198.51.100.20", "198.51.100.21"
        await self.owner.execute("""INSERT INTO rule_versions (rule_version, definition) VALUES ('v3', '{"rules": [
            {"id": "R006", "params": {"absorb_same_payload": {"window_hours": 24, "max_sources": 100}}}]}')
            ON CONFLICT DO NOTHING""")
        await self.incident(first, "R006", own, sensors=["cowrie"])
        await self.owner.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version, actor_ip,
            first_ts, last_ts, signal_count) VALUES ($1, 'm1', 'absorbed', 'R006', 'v3', $2, $3, $3, 1)""",
                                 first, kept, self.now)
        await self.block(kept, ["fw"], hours=5)                      # 다른 사유로 살아 있는 차단(내부 방화벽만)
        before = dict(await self.row(kept))
        out = await self.act(first, main.ActionIn(action="block_ip", include_absorbed=True, points=["fw"]))
        self.assertEqual((out["absorbed"]["kept"], dict(await self.row(kept))), (1, before))
        mark = len(await self.audit(kept))
        out = await self.act(first, main.ActionIn(action="block_ip", expires_hours=48, include_absorbed=True,
                                                  points=["gateway", "fw"]))
        after = await self.row(kept)
        self.assertEqual(dict(after), before | {"points": ["gateway", "fw"]})
        self.assertEqual(out["absorbed"]["kept"], 1)
        self.assertEqual([(e, a, d.split(" ", 1)[1]) for e, a, d in (await self.audit(kept))[mark:]],
                         [("console.block.points", "han", f"ip={kept} from=fw to=gateway,fw")])
        promise = await self.owner.fetchval("SELECT points FROM absorbed_blocks WHERE first_key = $1", first)
        self.assertEqual(promise, ["gateway", "fw"])

    async def test_사건_상세의_적용_지점(self):
        cases = [("R004|v3|198.51.100.30|x", "R004", "198.51.100.30", None, ["cowrie"], ["gateway", "fw"], "honeypot_abuse"),
                 ("R001|v3|198.51.100.31|x", "R001", "198.51.100.31", None, ["cowrie"], ["fw"], "sensor_only"),
                 ("R102|w2|198.51.100.32|x", "R102", "198.51.100.32", "node:web-01", None, ["fw"], "protected"),
                 ("R201|a1|198.51.100.33|x", "R201", "198.51.100.33", "user:han", None, ["fw"], "monitor"),
                 ("R999|v3|198.51.100.34|x", "R999", "198.51.100.34", None, None, ["fw"], "unconfirmed")]
        for key, rule, ip, target, sensors, _, _ in cases:
            await self.incident(key, rule, ip, target=target, sensors=sensors)
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
            for key, _, _, _, _, default, basis in cases:
                with self.subTest(key=key):
                    d = await main.get_incident(key)
                    self.assertEqual(d["block_points"], {"default": default, "basis": basis, "requested": None})
                    self.assertIsNone(d["actor"]["blocked"])
        key, ip = cases[1][0], cases[1][2]
        await self.act(key, main.ActionIn(action="block_ip", points=["fw"]))
        with patch.object(main.app.state, "pool", SimpleNamespace(acquire=self.acquire), create=True):
            d = await main.get_incident(key)
            listed = {r["actor_ip"]: r for r in await main.blocklist(True)}
            self.assertEqual((d["actor"]["blocked"]["points"], d["block_points"]["requested"], listed[ip]["points"]),
                             (["fw"], ["fw"], ["fw"]))
            # 만료되면 살아 있는 요청이 아니다(행의 points 는 그대로 보인다)
            await self.owner.execute("UPDATE blocklist SET expires_at = now() - interval '1 second'")
            d = await main.get_incident(key)
        self.assertEqual((d["actor"]["blocked"]["points"], d["block_points"]["requested"]), (["fw"], None))


if __name__ == "__main__":
    unittest.main()
