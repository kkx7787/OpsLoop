#!/usr/bin/env python3
"""계정 관리(이슈 #59 · #63) 시험 DB 시험.  python3 app/test_accounts_db.py

OPSLOOP_TEST_DATABASE_URL 이 슈퍼유저 연결이면 이름이 무작위인 데이터베이스와 콘솔 역할을 만들어 infra/schema.sql 전체를
적용한다(콘솔 역할 이름만 바꿔 넣는다. 다른 역할은 없어 그 권한 블록은 건너뛴다). 끝나면 지운다. 운영 DB · 운영 역할은 건드리지 않는다.

보는 것
  1. 화면 경로: 계정 API 처리기(accounts.set_role · set_active · list_accounts)를 콘솔 역할 연결로 돌린다. 함수 결과 매핑,
     감사 행(행위자 = 관리자, by= · target=), 같은 값은 감사 없음, 거부는 감사 없음, 감사 화면 대상 필터(target=)로 찾아진다
  2. 세션: 콘솔 역할로 로그인(authenticate) · 조회(lookup). 로그인 기록 갱신으로 변경 시각이 바뀌지 않고, 역할 변경 뒤 옛 쿠키는
     무효 · 다시 로그인하면 유효(낮춘 역할), 비활성 계정은 비밀번호가 맞아도 실패하고 로그인 기록도 고치지 않는다,
     비밀번호를 확인하는 동안 비밀번호가 바뀌면 로그인은 실패한다
  3. 명령줄(소유자 접속): add(있으면 거부 · 비밀번호를 묻지 않음) · passwd(해시는 감사에 없음) · role · disable · enable · list,
     마지막 활성 관리자 보호, 행위자 cli:<--by> · 없으면 cli, main() 종료 코드
  4. 화면의 추가 · 삭제 · 비밀번호 재설정(#63). 처리기와 main.app(세션 검사 · 출처 확인 포함)을 콘솔 역할 연결로 돌린다:
     추가한 계정은 그 비밀번호로 로그인된다 · 있는 아이디(비활성 포함)는 409 · 관리자 역할 · 평문은 함수가 다시 막는다 ·
     재설정 뒤 옛 쿠키는 401 이고 새 비밀번호로만 로그인된다 · 이력(로그인 · 판정 · 조치 · 차단 요청 · 해제) 없는 계정만 지워지고
     있으면 409 · 목록의 deletable 이 함수의 기준과 같다 · 이력 표를 못 읽으면 deletable 은 null 이고 변경은 된다 ·
     감사 한 줄씩(행위자 = 관리자), 평문 · 해시 없음
DB 스키마 자체(권한 · 트리거 · 두 번 적용)는 infra/test_console_accounts_db.py · test_console_accounts_manage_db.py 가 본다.

실행: python -m unittest discover -s app
"""
import asyncio
import io
import os
import re
import secrets
import sys
import unittest
from contextlib import asynccontextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_web  # noqa: E402,F401  auth 가 asyncpg 를 첫머리에서 부른다. 없는 곳에서는 가짜를 넣어 이 파일이 건너뛰어지게 한다
import accounts  # noqa: E402
import auth  # noqa: E402
import operations  # noqa: E402

URL = os.environ.get("OPSLOOP_TEST_DATABASE_URL")
SCHEMA = Path(__file__).resolve().parents[1] / "infra" / "schema.sql"
PASSWORD = "correct-horse-battery"
HASH = auth.hash_password(PASSWORD) if URL else None


def db_url(dbname: str) -> str:
    parts = urlsplit(URL)
    return urlunsplit(parts._replace(path="/" + dbname))


async def create_db(dbname, role):
    import asyncpg
    schema = SCHEMA.read_text(encoding="utf-8")
    if "console_account_set" not in schema:
        raise unittest.SkipTest("schema.sql 에 계정 블록(이슈 #59)이 없다")
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


def make_db(cls):
    """cls 에 무작위 데이터베이스(dbname) · 콘솔 역할(role)을 만들어 두고, 클래스가 끝나면(도중에 실패해도) 지운다."""
    tag = secrets.token_hex(4)
    cls.dbname, cls.role = f"opsloop_t59_{tag}", f"t59_{tag}_console"
    cls.addClassCleanup(lambda: asyncio.run(drop_db(cls.dbname, cls.role)))
    asyncio.run(create_db(cls.dbname, cls.role))


@unittest.skipUnless(URL, "PostgreSQL 시험 연결 미지정")
class DbCase(unittest.IsolatedAsyncioTestCase):
    """무작위 데이터베이스 · 콘솔 역할. 시험마다 계정 · 이벤트 표를 비운다."""

    @classmethod
    def setUpClass(cls):
        make_db(cls)

    async def asyncSetUp(self):
        import asyncpg
        self.owner = await asyncpg.connect(db_url(self.dbname))
        await self.owner.execute("TRUNCATE console_users, events, incidents, blocklist CASCADE")
        await self.owner.execute("TRUNCATE console_login_limits")
        # 콘솔과 같은 권한으로 붙은 연결. 계정 표는 읽기 · last_login_at 갱신 · 함수 실행만 된다
        self.console = await asyncpg.connect(db_url(self.dbname))
        await self.console.execute(f"SET SESSION AUTHORIZATION {self.role}")
        self.pool = SimpleNamespace(acquire=self.acquire)

    async def asyncTearDown(self):
        await self.console.close()
        await self.owner.close()

    @asynccontextmanager
    async def acquire(self):
        yield self.console

    def request(self, user="boss"):
        return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=self.pool)),
                               state=SimpleNamespace(user={"u": user, "r": "admin"}))

    async def seed(self, *rows):
        async with self.owner.transaction():
            await self.owner.execute("SELECT set_config('opsloop.actor', 'seed', true)")
            for name, role in rows:
                await self.owner.execute("INSERT INTO console_users (username, password_hash, role) VALUES ($1, $2, $3)",
                                         name, HASH, role)

    async def audit(self):
        rows = await self.owner.fetch("SELECT eventid, actor, detail FROM audit_log WHERE actor <> 'seed' ORDER BY ts")
        return [tuple(r) for r in rows]


class ConsolePathTest(DbCase):
    async def test_화면_변경은_함수로_하고_감사에_관리자가_남는다(self):
        await self.seed(("boss", "admin"), ("root", "admin"), ("op", "operator"), ("view", "viewer"))
        req = self.request()
        before = await self.owner.fetchval("SELECT updated_at FROM console_users WHERE username = 'op'")
        out = await accounts.set_role(accounts.RoleIn(username="op", role="viewer"), req)
        self.assertEqual((out["result"], out["account"]["role"], out["account"]["locked"]), ("ok", "viewer", None))
        self.assertGreater(out["account"]["updated_at"], before)
        out = await accounts.set_role(accounts.RoleIn(username="op", role="viewer"), req)
        self.assertEqual(out["result"], "unchanged")
        out = await accounts.set_active(accounts.ActiveIn(username="op", active=False), req)
        self.assertEqual((out["result"], out["account"]["active"]), ("ok", False))
        self.assertIsNotNone(out["account"]["disabled_at"])
        out = await accounts.set_active(accounts.ActiveIn(username="op", active=True), req)
        self.assertEqual((out["result"], out["account"]["active"], out["account"]["disabled_at"]), ("ok", True, None))
        refused = [(accounts.RoleIn(username="root", role="viewer"), 409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
                   (accounts.ActiveIn(username="root", active=False), 409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
                   (accounts.ActiveIn(username="boss", active=False), 409, "본인 계정은 여기서 바꿀 수 없습니다"),
                   (accounts.ActiveIn(username="ghost", active=True), 404, "계정을 찾을 수 없습니다")]
        for body, status, detail in refused:
            with self.subTest(body=body):
                handler = accounts.set_role if isinstance(body, accounts.RoleIn) else accounts.set_active
                with self.assertRaises(HTTPException) as caught:
                    await handler(body, req)
                self.assertEqual((caught.exception.status_code, caught.exception.detail), (status, detail))
        self.assertEqual(await self.audit(), [
            ("console.account.role.changed", "boss", "by=boss target=op from=operator to=viewer"),
            ("console.account.disabled", "boss", "by=boss target=op"),
            ("console.account.enabled", "boss", "by=boss target=op")])
        # 감사 화면(/api/audit)의 대상 필터로 찾아진다
        found = await operations.audit_log(req, actor="", target="op", since=None, until=None, limit=25, offset=0)
        self.assertEqual([r["eventid"] for r in found["rows"]],
                         ["console.account.enabled", "console.account.disabled", "console.account.role.changed",
                          "console.account.created"])
        listing = await accounts.list_accounts(req)
        self.assertEqual([(a["username"], a["role"], a["active"], a["locked"]) for a in listing["accounts"]],
                         [("boss", "admin", True, "self"), ("op", "viewer", True, None),
                          ("root", "admin", True, "admin"), ("view", "viewer", True, None)])
        self.assertNotIn("password_hash", repr(listing))

    async def test_콘솔_역할은_계정_표를_직접_고치지_못한다(self):
        await self.seed(("boss", "admin"), ("op", "operator"))
        import asyncpg
        for sql in ("UPDATE console_users SET role = 'admin' WHERE username = 'op'",
                    "UPDATE console_users SET disabled_at = now() WHERE username = 'op'",
                    "UPDATE console_users SET password_hash = 'x' WHERE username = 'op'",
                    "INSERT INTO console_users (username, password_hash, role) VALUES ('x', 'x', 'admin')",
                    "DELETE FROM console_users WHERE username = 'op'"):
            with self.subTest(sql=sql), self.assertRaises(asyncpg.InsufficientPrivilegeError):
                await self.console.execute(sql)


class SessionPathTest(DbCase):
    async def test_로그인_쿠키는_변경_뒤_무효이고_다시_로그인하면_유효(self):
        await self.seed(("boss", "admin"), ("op", "operator"))
        user = await auth.authenticate(self.pool, "op", PASSWORD)
        self.assertEqual(user["role"], "operator")
        cookie = auth.read(auth.issue(user["username"], user["role"], user["issued_at"]))
        row = await auth.lookup(self.pool, "op")
        self.assertTrue(auth.session_valid(cookie, row))
        # 로그인 기록 갱신으로는 변경 시각이 바뀌지 않는다
        await auth.authenticate(self.pool, "op", PASSWORD)
        self.assertEqual((await auth.lookup(self.pool, "op"))["updated_at"], row["updated_at"])

        await accounts.set_role(accounts.RoleIn(username="op", role="viewer"), self.request())
        row = await auth.lookup(self.pool, "op")
        self.assertEqual(row["role"], "viewer")
        self.assertFalse(auth.session_valid(cookie, row), "바뀌기 전에 받은 쿠키")
        user = await auth.authenticate(self.pool, "op", PASSWORD)
        again = auth.read(auth.issue(user["username"], user["role"], user["issued_at"]))
        self.assertTrue(auth.session_valid(again, await auth.lookup(self.pool, "op")))

        await accounts.set_active(accounts.ActiveIn(username="op", active=False), self.request())
        last = await self.owner.fetchval("SELECT last_login_at FROM console_users WHERE username = 'op'")
        self.assertIsNone(await auth.authenticate(self.pool, "op", PASSWORD))
        self.assertIsNone(await auth.authenticate(self.pool, "op", "wrong-password-123"))
        self.assertEqual(await self.owner.fetchval("SELECT last_login_at FROM console_users WHERE username = 'op'"), last)
        self.assertFalse(auth.session_valid(again, await auth.lookup(self.pool, "op")))
        # 재활성해도 비활성 전에 받은 쿠키는 되살아나지 않는다
        await accounts.set_active(accounts.ActiveIn(username="op", active=True), self.request())
        self.assertFalse(auth.session_valid(again, await auth.lookup(self.pool, "op")))
        self.assertIsNotNone(await auth.authenticate(self.pool, "op", PASSWORD))

    async def test_비밀번호_확인_중에_비밀번호가_바뀌면_로그인이_실패한다(self):
        await self.seed(("boss", "admin"), ("op", "operator"))
        acquired = 0

        @asynccontextmanager
        async def acquire():
            # 계정을 읽은 뒤(첫 번째) 로그인 기록을 고치기 전(두 번째)에 명령줄이 비밀번호를 바꾼다(비밀번호 확인이 수백 ms 걸린다)
            nonlocal acquired
            acquired += 1
            if acquired == 2:
                await self.owner.execute("UPDATE console_users SET password_hash = $1 WHERE username = 'op'",
                                         auth.hash_password("another-long-password"))
            yield self.console

        last = await self.owner.fetchval("SELECT last_login_at FROM console_users WHERE username = 'op'")
        # 옛 비밀번호로 받은 쿠키는 발급 시각(로그인 UPDATE 의 now())이 바뀐 시각보다 뒤라 유효하게 남는다. 그래서 실패여야 한다
        self.assertIsNone(await auth.authenticate(SimpleNamespace(acquire=acquire), "op", PASSWORD))
        self.assertEqual(acquired, 2)
        self.assertEqual(await self.owner.fetchval("SELECT last_login_at FROM console_users WHERE username = 'op'"), last)


class CliTest(DbCase):
    async def cli(self, *argv, answers=(PASSWORD, PASSWORD)):
        args = auth.build_parser().parse_args(list(argv))
        with patch.object(auth.getpass, "getpass", side_effect=list(answers)) as ask:
            try:
                return await args.func(self.owner, args), ask.call_count
            except auth.CliError as error:
                return error, ask.call_count

    async def test_추가와_비밀번호(self):
        await self.seed(("boss", "admin"))
        self.assertEqual(await self.cli("add", "kim", "operator", "--by", "han"), ("등록: kim (operator)", 2))
        out, asked = await self.cli("add", "kim", "admin")
        self.assertIsInstance(out, auth.CliError)
        self.assertIn("passwd", str(out))
        self.assertEqual(asked, 0, "있는 계정이면 비밀번호를 묻지 않는다")
        self.assertEqual(await self.owner.fetchval("SELECT role FROM console_users WHERE username = 'kim'"), "operator")

        before = await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'kim'")
        for answers, why in ((("short",), "12자"), ((PASSWORD, PASSWORD + "x"), "일치")):
            out, _ = await self.cli("passwd", "kim", answers=answers)
            self.assertIn(why, str(out))
        out, asked = await self.cli("passwd", "ghost")
        self.assertEqual((str(out), asked), ("없는 계정입니다: ghost", 0))
        self.assertEqual(await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'kim'"),
                         before)
        new = "another-long-password"
        out, _ = await self.cli("passwd", "kim", answers=(new, new))
        self.assertIn("비밀번호 변경: kim", out)
        after = await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'kim'")
        self.assertNotEqual(after["password_hash"], before["password_hash"])
        self.assertGreater(after["updated_at"], before["updated_at"])
        self.assertTrue(auth.verify_password(new, after["password_hash"]))
        rows = await self.audit()
        self.assertEqual(rows, [("console.account.created", "cli:han", "by=cli:han target=kim role=operator"),
                                ("console.account.password.changed", "cli", "by=cli target=kim")])
        details = await self.owner.fetchval("SELECT string_agg(input, chr(10)) FROM events")
        for secret in (before["password_hash"], after["password_hash"], "pbkdf2", new, PASSWORD):
            self.assertNotIn(secret, details)

    async def test_마지막_활성_관리자는_낮추거나_끄지_못한다(self):
        await self.seed(("boss", "admin"), ("op", "operator"))
        out, _ = await self.cli("role", "boss", "operator")
        self.assertIn("마지막 활성 관리자", str(out))
        out, _ = await self.cli("disable", "boss")
        self.assertIn("마지막 활성 관리자", str(out))
        self.assertEqual((await self.cli("role", "op", "admin", "--by", "han"))[0], "역할 변경: op operator → admin (전에 받은 세션은 끊깁니다)")
        self.assertIn("바뀐 것 없음", (await self.cli("role", "op", "admin"))[0])
        self.assertIn("비활성: boss", (await self.cli("disable", "boss", "--by", "han"))[0])
        # 비활성 관리자는 세지 않는다. 남은 활성 관리자 op 는 낮추거나 끌 수 없다
        out, _ = await self.cli("role", "op", "viewer")
        self.assertIn("마지막 활성 관리자", str(out))
        self.assertIn("바뀐 것 없음", (await self.cli("disable", "boss"))[0])
        self.assertIn("재활성: boss", (await self.cli("enable", "boss", "--by", "han"))[0])
        self.assertIn("바뀐 것 없음", (await self.cli("enable", "boss"))[0])
        self.assertIn("역할 변경: op admin → viewer", (await self.cli("role", "op", "viewer", "--by", "han"))[0])
        self.assertIn("없는 계정", str((await self.cli("disable", "ghost"))[0]))
        self.assertEqual(await self.audit(), [
            ("console.account.role.changed", "cli:han", "by=cli:han target=op from=operator to=admin"),
            ("console.account.disabled", "cli:han", "by=cli:han target=boss"),
            ("console.account.enabled", "cli:han", "by=cli:han target=boss"),
            ("console.account.role.changed", "cli:han", "by=cli:han target=op from=admin to=viewer")])
        listing, _ = await self.cli("list")
        self.assertEqual([line.split()[:3] for line in listing.splitlines()[1:]],
                         [["boss", "admin", "활성"], ["op", "viewer", "활성"]])
        self.assertNotIn("pbkdf2", listing)


NEW_PASSWORD = "another-long-password"


class ManagePathTest(DbCase):
    """화면의 추가 · 삭제 · 비밀번호 재설정(#63). 처리기와 main.app 을 콘솔 역할 연결로 돌린다."""

    @classmethod
    def setUpClass(cls):
        if "console_account_create" not in SCHEMA.read_text(encoding="utf-8"):
            raise unittest.SkipTest("schema.sql 에 계정 추가 · 삭제 · 비밀번호 블록(이슈 #63)이 없다")
        super().setUpClass()

    async def http(self, method, path, token=None, **kw):
        """main.app 을 이 이벤트 루프에서 그대로 부른다(세션 검사 · 출처 확인 · 보안 헤더). DB 는 콘솔 역할 연결이다."""
        import httpx
        main = test_web.main
        with patch.object(main.app.state, "pool", self.pool, create=True):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://testserver",
                                         cookies={auth.COOKIE: token} if token else None) as client:
                return await client.request(method, path, headers=test_web.SAME, **kw)

    async def login(self, username, password=PASSWORD):
        """/login 으로 들어가 받은 쿠키. 틀리면 None."""
        with redirect_stdout(io.StringIO()):
            r = await self.http("POST", "/login", data={"username": username, "password": password})
        return r.cookies.get(auth.COOKIE) if r.status_code == 302 else None

    async def refused(self, handler, body, result):
        with self.assertRaises(HTTPException) as caught:
            await handler(body, self.request())
        self.assertEqual((caught.exception.status_code, caught.exception.detail), accounts.REFUSED[result])

    async def assert_no_secret(self, *hashes):
        # 감사 · 로그인 기록 어디에도 평문 · 해시가 없다(행 전체를 글자로 본다)
        text = await self.owner.fetchval("SELECT coalesce(string_agg(e::text, chr(10)), '') FROM events e")
        for secret in ("pbkdf2", PASSWORD, NEW_PASSWORD, *hashes):
            self.assertNotIn(secret, text)

    async def test_추가한_계정은_그_비밀번호로_로그인된다(self):
        await self.seed(("boss", "admin"))
        boss = await self.login("boss")
        r = await self.http("POST", "/api/accounts", boss, json={"username": "kim", "role": "operator", "password": PASSWORD})
        self.assertEqual((r.status_code, r.headers["cache-control"]), (201, "no-store"))
        body = r.json()
        self.assertEqual((body["result"], {k: body["account"][k] for k in ("username", "role", "active", "locked", "deletable",
                                                                            "last_login_at")}),
                         ("ok", {"username": "kim", "role": "operator", "active": True, "locked": None, "deletable": True,
                                 "last_login_at": None}))
        stored = await self.owner.fetchval("SELECT password_hash FROM console_users WHERE username = 'kim'")
        self.assertTrue(auth.verify_password(PASSWORD, stored))
        self.assertNotIn(stored, r.text)
        kim = await self.login("kim")
        me = await self.http("GET", "/api/me", kim)
        self.assertEqual((me.status_code, me.json()["username"], me.json()["role"]), (200, "kim", "operator"))
        self.assertIsNone(await self.login("kim", NEW_PASSWORD))
        # 로그인했으니 이력이 생겼다. 이제 지울 수 없다
        listing = await accounts.list_accounts(self.request())
        self.assertEqual({a["username"]: a["deletable"] for a in listing["accounts"]}, {"boss": False, "kim": False})

        # 있는 아이디는 비활성이어도 거부한다. 역할 · 비밀번호를 덮지 않는다
        again = accounts.NewAccountIn(username="kim", role="viewer", password=NEW_PASSWORD)
        await self.refused(accounts.create_account, again, "exists")
        await accounts.set_active(accounts.ActiveIn(username="kim", active=False), self.request())
        await self.refused(accounts.create_account, again, "exists")
        await self.refused(accounts.create_account, accounts.NewAccountIn(username="boss", role="viewer", password=PASSWORD),
                           "exists")
        row = await self.owner.fetchrow("SELECT role, password_hash FROM console_users WHERE username = 'kim'")
        self.assertEqual((row["role"], row["password_hash"]), ("operator", stored))
        # 입력 검사를 지나도 함수가 다시 막는다: 관리자 역할 · 평문(해시 형식이 아님)
        user = {"u": "boss", "r": "admin"}
        for args, result in ((("evil", "admin", auth.hash_password(PASSWORD)), "cli_only"),
                             (("evil", "viewer", PASSWORD), "invalid")):
            with self.subTest(result=result), self.assertRaises(HTTPException) as caught:
                await accounts.call(self.request(), user, accounts.CREATE_SQL, *args, target="evil")
            self.assertEqual((caught.exception.status_code, caught.exception.detail), accounts.REFUSED[result])
        self.assertIsNone(await self.owner.fetchval("SELECT 1 FROM console_users WHERE username = 'evil'"))
        self.assertEqual(await self.audit(), [
            ("console.account.created", "boss", "by=boss target=kim role=operator"),
            ("console.account.disabled", "boss", "by=boss target=kim")])
        await self.assert_no_secret(stored)

    async def test_비밀번호_재설정_뒤_옛_쿠키는_401_이고_새_비밀번호로만_로그인된다(self):
        await self.seed(("boss", "admin"), ("root", "admin"), ("op", "operator"))
        boss, old = await self.login("boss"), await self.login("op")
        self.assertEqual((await self.http("GET", "/api/me", old)).status_code, 200)
        before = await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'op'")
        r = await self.http("POST", "/api/accounts/password", boss, json={"username": "op", "password": NEW_PASSWORD})
        self.assertEqual((r.status_code, r.headers["cache-control"]), (200, "no-store"))
        self.assertEqual((r.json()["result"], r.json()["account"]["username"], r.json()["account"]["deletable"]),
                         ("ok", "op", False))
        after = await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'op'")
        self.assertGreater(after["updated_at"], before["updated_at"])
        self.assertTrue(auth.verify_password(NEW_PASSWORD, after["password_hash"]))
        # 재설정 전에 받은 쿠키는 401, 옛 비밀번호로는 들어가지 못한다. 새 비밀번호로 받은 쿠키는 된다
        self.assertEqual((await self.http("GET", "/api/me", old)).status_code, 401)
        self.assertIsNone(await self.login("op", PASSWORD))
        new = await self.login("op", NEW_PASSWORD)
        self.assertEqual((await self.http("GET", "/api/me", new)).status_code, 200)
        # 관리자 · 본인 · 없는 계정은 거부하고 아무것도 바꾸지 않는다
        root = await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'root'")
        for username, result in (("root", "cli_only"), ("boss", "self"), ("ghost", "not_found")):
            with self.subTest(username=username):
                await self.refused(accounts.set_password, accounts.PasswordIn(username=username, password=PASSWORD), result)
        self.assertEqual(await self.owner.fetchrow("SELECT password_hash, updated_at FROM console_users WHERE username = 'root'"),
                         root)
        self.assertEqual((await self.http("GET", "/api/me", boss)).status_code, 200, "거부된 본인 재설정은 세션을 끊지 않는다")
        self.assertEqual(await self.audit(), [("console.account.password.changed", "boss", "by=boss target=op")])
        await self.assert_no_secret(before["password_hash"], after["password_hash"])

    async def test_이력이_없는_계정만_지운다(self):
        names = ("fresh", "logged", "judged", "acted", "requested", "released")
        await self.seed(("boss", "admin"), ("root", "admin"), *((name, "viewer") for name in names))
        await auth.authenticate(self.pool, "logged", PASSWORD)
        async with self.owner.transaction():
            await self.owner.execute("SELECT set_config('opsloop.actor', 'seed', true)")
            await self.owner.execute("INSERT INTO incidents (incident_key, rule_id, rule_version, severity, first_ts, last_ts,"
                                     " signal_count) VALUES ('k1', 'R001', 'v1', 'low', now(), now(), 1)")
            await self.owner.execute("INSERT INTO verdicts (incident_key, verdict, operator) VALUES ('k1', 'threat', 'judged')")
            await self.owner.execute("INSERT INTO actions (incident_key, action, operator) VALUES ('k1', 'note', 'acted')")
            await self.owner.execute("INSERT INTO blocklist (actor_ip, reason, requested_by)"
                                     " VALUES ('198.51.100.7', 'x', 'requested')")
            await self.owner.execute("INSERT INTO blocklist (actor_ip, reason, released_at, released_by)"
                                     " VALUES ('198.51.100.8', 'x', now(), 'released')")
        # 목록의 deletable 은 함수의 in_use 와 같은 기준이다(관리자 · 본인도 이력만 본다. 화면은 잠금으로 가린다)
        listing = await accounts.list_accounts(self.request())
        self.assertEqual({a["username"]: a["deletable"] for a in listing["accounts"]},
                         {"boss": True, "root": True, "fresh": True, "logged": False, "judged": False, "acted": False,
                          "requested": False, "released": False})
        for name in names[1:]:
            with self.subTest(name=name):
                await self.refused(accounts.delete_account, accounts.Target(username=name), "in_use")
        for name, result in (("root", "cli_only"), ("boss", "self"), ("ghost", "not_found")):
            with self.subTest(name=name):
                await self.refused(accounts.delete_account, accounts.Target(username=name), result)

        boss = await self.login("boss")
        r = await self.http("POST", "/api/accounts/delete", boss, json={"username": "judged"})
        self.assertEqual((r.status_code, r.json(), r.headers["cache-control"]),
                         (409, {"detail": "판정 · 조치 · 로그인 기록이 있는 계정은 지울 수 없습니다. 비활성으로 막아 주세요"},
                          "no-store"))
        r = await self.http("POST", "/api/accounts/delete", boss, json={"username": "fresh"})
        self.assertEqual((r.status_code, r.json()), (200, {"result": "ok"}))
        await self.refused(accounts.delete_account, accounts.Target(username="fresh"), "not_found")
        left = [row["username"] for row in await self.owner.fetch("SELECT username FROM console_users ORDER BY username")]
        self.assertEqual(left, sorted(["boss", "root", *names[1:]]))
        self.assertEqual(await self.audit(), [("console.account.deleted", "boss", "by=boss target=fresh role=viewer")])

    async def test_이력_표를_못_읽으면_deletable_은_null_이고_변경은_된다(self):
        import asyncpg
        await self.seed(("boss", "admin"))
        # 세 표를 하나씩 거둔다. 권한 확인(READABLE_SQL)에서 한 표라도 빠지면 그 표를 못 읽을 때 목록 · 변경이 500 이 된다
        for table in ("verdicts", "actions", "blocklist"):
            op = f"op_{table}"
            with self.subTest(table=table):
                await self.seed((op, "operator"))
                await self.owner.execute(f"REVOKE SELECT ON {table} FROM {self.role}")
                try:
                    # 이력 표가 든 문장은 문장 전체가 거부된다. 그래서 먼저 권한을 묻고 문장을 고른다
                    with self.assertRaises(asyncpg.InsufficientPrivilegeError):
                        await self.console.fetch(accounts.LIST_SQL)
                    listing = await accounts.list_accounts(self.request())
                    self.assertEqual({a["username"]: a["deletable"] for a in listing["accounts"]}, {"boss": None, op: None})
                    # 변경 트랜잭션은 깨지지 않는다
                    out = await accounts.set_password(accounts.PasswordIn(username=op, password=NEW_PASSWORD), self.request())
                    self.assertEqual((out["result"], out["account"]["deletable"]), ("ok", None))
                    stored = await self.owner.fetchval("SELECT password_hash FROM console_users WHERE username = $1", op)
                    self.assertTrue(auth.verify_password(NEW_PASSWORD, stored))
                    # 함수는 소유자 권한으로 돌아 이력을 그대로 가른다
                    out = await accounts.delete_account(accounts.Target(username=op), self.request())
                    self.assertEqual(out, {"result": "ok"})
                finally:
                    await self.owner.execute(f"GRANT SELECT ON {table} TO {self.role}")


@unittest.skipUnless(URL, "PostgreSQL 시험 연결 미지정")
class CliMainTest(unittest.TestCase):
    """main() 을 그대로(asyncio.run) 돌린다. 종료 코드 · 표준 출력 · 표준 오류."""

    @classmethod
    def setUpClass(cls):
        make_db(cls)

    def test_종료_코드(self):
        with patch.dict(os.environ, {"DATABASE_URL": db_url(self.dbname)}):
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(auth.main(["list"]), 0)
            self.assertTrue(out.getvalue().startswith("아이디"))
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(auth.main(["disable", "ghost", "--by", "han"]), 1)
            self.assertEqual(err.getvalue(), "없는 계정입니다: ghost\n")


if __name__ == "__main__":
    unittest.main()
