#!/usr/bin/env python3
"""계정 관리(이슈 #59) 시험 DB 시험.  python3 app/test_accounts_db.py

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
DB 스키마 자체(권한 · 트리거 · 두 번 적용)는 infra/test_console_accounts_db.py 가 본다.

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
        await self.owner.execute("TRUNCATE console_users, events CASCADE")
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
                    "INSERT INTO console_users (username, password_hash, role) VALUES ('x', 'x', 'admin')"):
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
