#!/usr/bin/env python3
"""계정 관리(이슈 #59) 시험. DB 없이 돈다.  python3 app/test_accounts.py

보는 것
  1. 계정 API(accounts.py): 세션 없음 401 · 관리자가 아니면 403(DB 를 보지 않는다) · 목록 모양(해시 없음 · 잠금 표시 · 활성) ·
     변경은 한 트랜잭션에서 행위자를 건 뒤 console_account_set 한 번 · 결과 매핑(ok · unchanged 200, not_found 404,
     cli_only · self 409 문구, no_actor · 모르는 값 500) · 입력 422(DB 를 보지 않는다) · 출처 확인 · 아이디는 매개변수로만
  2. 세션 순수 함수(auth): 쿠키의 발급 시각 i · session_valid(없음 · 비활성 · 변경 전 쿠키 · i 없는 옛 쿠키)
  3. 로그인(auth.authenticate): 비활성 계정은 비밀번호가 맞아도 실패(해시 계산은 같게, 로그인 기록 갱신 없음) ·
     발급 시각은 UPDATE … RETURNING 의 DB 시각 · 확인과 갱신 사이에 계정이 바뀌면(updated_at 이 다르면) 실패
  4. 계정 조회(auth.lookup): 한 문장 · 옛 연결 오류만 한 번 더 빌린다
  5. 명령줄 인자(auth.build_parser): 아이디 형식 · --by 형식 · 역할 선택지 · 비밀번호는 인자로 받지 않는다
명령줄 명령의 DB 동작(마지막 관리자 · 감사 행위자)은 app/test_accounts_db.py 가 시험 DB 에서 본다.

실행: python -m unittest discover -s app
"""
import asyncio
import io
import json
import os
import sys
import unittest
from contextlib import asynccontextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_web  # noqa: E402  asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
from fastapi.testclient import TestClient  # noqa: E402

import accounts  # noqa: E402
import auth  # noqa: E402

main = test_web.main
SAME = test_web.SAME
T0 = datetime(2026, 9, 20, 1, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 29, 3, 0, tzinfo=timezone.utc)


def row(username, role, disabled_at=None, last_login_at=None, updated_at=T0):
    # 가짜 DB 는 해시까지 돌려준다. 응답에 실리지 않는지 본다(목록 문장에는 애초에 없다)
    return {"username": username, "role": role, "disabled_at": disabled_at, "created_at": T0,
            "last_login_at": last_login_at, "updated_at": updated_at,
            "password_hash": "pbkdf2_sha256$240000$00$11"}


class FakeConn:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql, *args):
        self.pool.calls.append((sql, args))
        return "SELECT 1"

    async def fetchval(self, sql, *args):
        self.pool.calls.append((sql, args))
        return self.pool.result

    async def fetchrow(self, sql, *args):
        self.pool.calls.append((sql, args))
        return self.pool.rows.get(args[0])

    async def fetch(self, sql, *args):
        self.pool.calls.append((sql, args))
        return list(self.pool.rows.values())

    @asynccontextmanager
    async def transaction(self):
        # 끝도 남겨 행위자 설정 · 함수 호출이 같은 트랜잭션 안인지 가른다(set_config 세 번째 인자 true 는 커밋과 함께 사라진다)
        self.pool.calls.append(("transaction", ()))
        yield
        self.pool.calls.append(("commit", ()))


class FakePool:
    def __init__(self):
        self.calls, self.result = [], "ok"
        self.rows = {r["username"]: r for r in (
            row("boss", "admin", last_login_at=T1), row("root", "admin"), row("op", "operator"),
            row("view", "viewer", disabled_at=T1, updated_at=T1))}

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self)


# ──────────────────────────────────────────────────────────────
#  1. 계정 API
# ──────────────────────────────────────────────────────────────
class AccountsApiTest(unittest.TestCase):
    def setUp(self):
        self.pool = FakePool()
        patcher = patch.object(main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.accounts = test_web.FakeAccounts().patch(self)
        for name, role in (("boss", "admin"), ("op", "operator"), ("view2", "viewer")):
            self.accounts[name] = test_web.account_row(role)
        self.client = TestClient(main.app, follow_redirects=False, raise_server_exceptions=False)
        self.addCleanup(self.client.close)

    def login(self, username="boss"):
        self.client.cookies.set(auth.COOKIE, auth.issue(username, self.accounts[username]["role"]))

    def post(self, path, body):
        return self.client.post(path, json=body, headers=SAME)

    def test_세션이_없으면_401_이고_DB_를_보지_않는다(self):
        self.assertEqual(self.client.get("/api/accounts").status_code, 401)
        self.assertEqual(self.post("/api/accounts/role", {"username": "op", "role": "viewer"}).status_code, 401)
        self.assertEqual(self.post("/api/accounts/active", {"username": "op", "active": False}).status_code, 401)
        self.assertEqual((self.pool.calls, self.accounts.calls), ([], []))

    def test_관리자가_아니면_403_이고_DB_를_보지_않는다(self):
        for name in ("op", "view2"):
            with self.subTest(name=name):
                self.login(name)
                self.assertEqual(self.client.get("/api/accounts").status_code, 403)
                self.assertEqual(self.post("/api/accounts/role", {"username": "op", "role": "viewer"}).status_code, 403)
                self.assertEqual(self.post("/api/accounts/active", {"username": "op", "active": True}).status_code, 403)
        self.assertEqual(self.pool.calls, [])

    def test_쿠키가_관리자여도_DB_역할이_관제사면_403(self):
        self.client.cookies.set(auth.COOKIE, auth.issue("op", "admin"))
        self.assertEqual(self.client.get("/api/accounts").status_code, 403)
        self.assertEqual(self.pool.calls, [])

    def test_목록은_해시_없이_잠금_표시와_함께(self):
        self.login()
        r = self.client.get("/api/accounts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["cache-control"], "no-store")
        body = r.json()
        self.assertEqual(list(body), ["accounts"])
        self.assertEqual([a["username"] for a in body["accounts"]], ["boss", "root", "op", "view"])
        self.assertEqual({a["username"]: a["locked"] for a in body["accounts"]},
                         {"boss": "self", "root": "admin", "op": None, "view": None})
        self.assertEqual({a["username"]: a["active"] for a in body["accounts"]},
                         {"boss": True, "root": True, "op": True, "view": False})
        view = body["accounts"][3]
        self.assertEqual(view, {"username": "view", "role": "viewer", "active": False,
                                "disabled_at": T1.isoformat(), "created_at": T0.isoformat(), "last_login_at": None,
                                "updated_at": T1.isoformat(), "locked": None})
        self.assertNotIn("password_hash", r.text)
        self.assertNotIn("pbkdf2", r.text)
        self.assertEqual(self.pool.calls, [(accounts.LIST_SQL, ())])
        for sql in (accounts.LIST_SQL, accounts.ONE_SQL, auth.LOOKUP_SQL):
            self.assertNotIn("password_hash", sql)
        self.assertIn("ORDER BY username", accounts.LIST_SQL)

    def test_역할_변경은_행위자를_건_한_트랜잭션에서_함수_한_번(self):
        self.login()
        r = self.post("/api/accounts/role", {"username": "op", "role": "viewer"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"result": "ok", "account": {
            "username": "op", "role": "operator", "active": True, "disabled_at": None, "created_at": T0.isoformat(),
            "last_login_at": None, "updated_at": T0.isoformat(), "locked": None}})
        self.assertEqual(self.pool.calls, [
            ("transaction", ()),
            ("SELECT set_config('opsloop.actor', $1, true)", ("boss",)),
            (accounts.SET_SQL, ("op", "viewer", None)),
            (accounts.ONE_SQL, ("op",)),
            ("commit", ())])
        self.assertNotIn("pbkdf2", r.text)

    def test_활성_변경은_역할_인자가_비어_있다(self):
        self.login()
        for active in (False, True):
            self.pool.calls.clear()
            r = self.post("/api/accounts/active", {"username": "op", "active": active})
            self.assertEqual(r.status_code, 200)
            self.assertIn((accounts.SET_SQL, ("op", None, active)), self.pool.calls)

    def test_바뀐_것이_없으면_200_unchanged(self):
        self.login()
        self.pool.result = "unchanged"
        r = self.post("/api/accounts/role", {"username": "op", "role": "operator"})
        self.assertEqual((r.status_code, r.json()["result"], r.json()["account"]["username"]), (200, "unchanged", "op"))

    def test_함수_결과_매핑(self):
        self.login()
        cases = {"not_found": (404, "계정을 찾을 수 없습니다"),
                 "cli_only": (409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
                 "self": (409, "본인 계정은 여기서 바꿀 수 없습니다"),
                 "no_actor": (500, "서버 오류"),
                 "모르는 값": (500, "서버 오류")}
        for result, want in cases.items():
            with self.subTest(result=result), redirect_stdout(io.StringIO()):
                self.pool.result = result
                self.pool.calls.clear()
                r = self.post("/api/accounts/active", {"username": "root", "active": False})
                self.assertEqual((r.status_code, r.json()), (want[0], {"detail": want[1]}))
                # 거부면 계정 행을 다시 읽지 않는다
                self.assertNotIn(accounts.ONE_SQL, [sql for sql, _ in self.pool.calls])

    def test_입력이_틀리면_422_이고_DB_를_보지_않는다(self):
        self.login()
        bad_role = [{}, {"username": "op"}, {"role": "viewer"}, {"username": "", "role": "viewer"},
                    {"username": "a" * 129, "role": "viewer"}, {"username": "a\x00b", "role": "viewer"},
                    {"username": "op", "role": "admin"}, {"username": "op", "role": "Viewer"},
                    {"username": "op", "role": None}, {"username": 5, "role": "viewer"},
                    {"username": "op", "role": "viewer", "active": False}]
        bad_active = [{"username": "op"}, {"username": "op", "active": "false"}, {"username": "op", "active": 0},
                      {"username": "op", "active": None}, {"username": "op", "active": True, "role": "viewer"}]
        for path, bodies in (("/api/accounts/role", bad_role), ("/api/accounts/active", bad_active)):
            for body in bodies:
                with self.subTest(path=path, body=body):
                    self.assertEqual(self.post(path, body).status_code, 422)
        self.assertEqual(self.pool.calls, [])
        # 128 자까지는 받는다(로그인이 자르는 길이). 검증을 지나 함수까지 간다
        self.pool.result = "not_found"
        self.assertEqual(self.post("/api/accounts/role", {"username": "a" * 128, "role": "viewer"}).status_code, 404)

    def test_짝_없는_서로게이트는_500_이_아니라_422(self):
        # 기본 422 처리기는 입력을 되돌려 싣다가 인코딩 오류로 500 이 된다. 가림 라우트는 type · loc · msg 만 싣는다
        self.login()
        for path, raw in (("/api/accounts/role", b'{"username":"\\ud800","role":"viewer"}'),
                          ("/api/accounts/active", b'{"username":"\\udc00x","active":false}'),
                          ("/api/accounts/role", b'{"username":"op","role":"\\ud800"}')):
            with self.subTest(path=path, raw=raw):
                r = self.client.post(path, content=raw, headers={**SAME, "content-type": "application/json"})
                self.assertEqual(r.status_code, 422)
                self.assertTrue(all(set(item) <= {"type", "loc", "msg"} for item in r.json()["detail"]))
        self.assertEqual(self.pool.calls, [])

    def test_다른_출처의_변경은_막는다(self):
        self.login()
        for headers in ({}, test_web.EVIL):
            r = self.client.post("/api/accounts/active", json={"username": "op", "active": False}, headers=headers)
            self.assertEqual(r.status_code, 403)
        self.assertEqual(self.pool.calls, [])

    def test_아이디는_매개변수로만_넘긴다(self):
        self.login()
        for name in ("x' OR '1'='1", "../../etc/passwd", "<img src=x onerror=alert(1)>", "a/b%2Fc", "관제 사용자"):
            self.pool.calls.clear()
            self.pool.result = "not_found"
            r = self.post("/api/accounts/role", {"username": name, "role": "viewer"})
            self.assertEqual(r.status_code, 404)
            self.assertIn((accounts.SET_SQL, (name, "viewer", None)), self.pool.calls)
            self.assertNotIn(name, json.dumps(r.json(), ensure_ascii=False))


# ──────────────────────────────────────────────────────────────
#  2. 세션 순수 함수
# ──────────────────────────────────────────────────────────────
class SessionTest(unittest.TestCase):
    def test_쿠키에_발급_시각이_있다(self):
        with patch.object(auth.time, "time", return_value=1790000000.5):
            data = auth.read(auth.issue("han", "operator"))
            self.assertEqual((data["i"], data["e"]), (1790000000.5, 1790000000 + auth.SESSION_HOURS * 3600))
            given = auth.read(auth.issue("han", "operator", 1789999999.125))
        self.assertEqual((given["u"], given["r"], given["i"]), ("han", "operator", 1789999999.125))

    def test_session_valid(self):
        at = T1.timestamp()
        ok = test_web.account_row
        cookie = {"u": "han", "r": "operator", "i": at, "e": int(at) + 3600}
        cases = [
            (None, False, "계정이 없다"),
            (ok(disabled_at=T1), False, "비활성"),
            (ok(updated_at=None), True, "바뀐 적 없음"),
            (ok(updated_at=T1), True, "바뀐 때와 같은 시각에 받았다"),
            (ok(updated_at=datetime.fromtimestamp(at + 0.000001, timezone.utc)), False, "바뀐 뒤(1마이크로초)"),
            (ok(updated_at=datetime.fromtimestamp(at - 60, timezone.utc)), True, "바뀐 뒤에 받았다"),
        ]
        for account, want, why in cases:
            with self.subTest(why=why):
                self.assertIs(auth.session_valid(cookie, account), want)

    def test_i_가_없는_옛_쿠키는_만료에서_거꾸로_센다(self):
        e = int(T1.timestamp()) + auth.SESSION_HOURS * 3600      # T1 에 받은 쿠키
        for cookie in ({"u": "han", "r": "admin", "e": e}, {"u": "han", "r": "admin", "e": e, "i": True},
                       {"u": "han", "r": "admin", "e": e, "i": "9999999999"}):
            with self.subTest(cookie=cookie):
                self.assertTrue(auth.session_valid(cookie, test_web.account_row(updated_at=T1)))
                later = datetime.fromtimestamp(T1.timestamp() + 1, timezone.utc)
                self.assertFalse(auth.session_valid(cookie, test_web.account_row(updated_at=later)))


# ──────────────────────────────────────────────────────────────
#  3. 로그인 · 4. 계정 조회
# ──────────────────────────────────────────────────────────────
PASSWORD = "correct-horse-battery"


class AuthPool:
    """authenticate · lookup 용 가짜 풀. fetchrow 는 계정 행, fetchval 은 UPDATE … RETURNING 값. fails 번은 옛 연결 오류."""

    def __init__(self, account=None, returning=Decimal("1790000123.456789"), fails=0, error=OSError):
        self.account, self.returning, self.fails, self.error = account, returning, fails, error
        self.calls, self.acquired = [], 0

    @asynccontextmanager
    async def acquire(self):
        self.acquired += 1
        broken = self.acquired <= self.fails
        pool = self

        class Conn:
            async def fetchrow(self, sql, *args):
                pool.calls.append((sql, args))
                if broken:
                    raise pool.error("connection was closed in the middle of operation")
                return pool.account

            async def fetchval(self, sql, *args):
                pool.calls.append((sql, args))
                return pool.returning

        yield Conn()


class AuthenticateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stored = auth.hash_password(PASSWORD)

    def account(self, **kw):
        return {"username": "han", "password_hash": self.stored, "role": "operator", "disabled_at": None,
                "updated_at": T0} | kw

    def run_auth(self, pool, password=PASSWORD):
        with patch.object(auth, "verify_password", wraps=auth.verify_password) as verify:
            user = asyncio.run(test_web.REAL_AUTHENTICATE(pool, "han", password))
        return user, verify.call_count

    def test_비밀번호가_맞으면_DB_시각을_발급_시각으로(self):
        pool = AuthPool(self.account())
        user, verified = self.run_auth(pool)
        self.assertEqual(user, {"username": "han", "role": "operator", "issued_at": 1790000123.456789})
        self.assertIsInstance(user["issued_at"], float)
        (select, _), (update, args) = pool.calls
        self.assertIn("disabled_at", select)
        self.assertNotIn("password_hash", update)
        self.assertIn("SET last_login_at = now()", update)
        self.assertIn("AND disabled_at IS NULL", update)
        # 읽은 뒤 바뀐 계정(비밀번호 재설정 등)이면 갱신할 행이 없어 실패한다. 읽은 변경 시각을 그대로 넘긴다
        self.assertIn("AND updated_at IS NOT DISTINCT FROM $2", update)
        self.assertIn("RETURNING extract(epoch FROM now())", update)
        self.assertEqual((args, verified), (("han", T0), 1))

    def test_비활성_계정은_비밀번호가_맞아도_실패하고_기록을_고치지_않는다(self):
        for password in (PASSWORD, "wrong-password-123"):
            with self.subTest(password=password):
                pool = AuthPool(self.account(disabled_at=T1))
                user, verified = self.run_auth(pool, password)
                # 틀린 비밀번호와 같이 해시를 한 번 계산하고 None 이다(시간 · 응답이 같다)
                self.assertEqual((user, verified, len(pool.calls)), (None, 1, 1))

    def test_틀린_비밀번호는_실패(self):
        pool = AuthPool(self.account())
        self.assertEqual(self.run_auth(pool, "wrong-password-123")[0], None)
        self.assertEqual(len(pool.calls), 1)

    def test_확인과_갱신_사이에_계정이_바뀌면_실패(self):
        pool = AuthPool(self.account(), returning=None)
        self.assertEqual(self.run_auth(pool)[0], None)
        self.assertEqual(len(pool.calls), 2)


class LookupTest(unittest.TestCase):
    ROW = test_web.account_row("viewer")

    def test_한_문장으로_읽는다(self):
        pool = AuthPool(self.ROW)
        self.assertEqual(asyncio.run(auth.lookup(pool, "han")), self.ROW)
        self.assertEqual(pool.calls, [(auth.LOOKUP_SQL, ("han",))])
        self.assertEqual(auth.LOOKUP_SQL,
                         "SELECT role, disabled_at, updated_at FROM console_users WHERE username = $1")

    def test_옛_연결_오류면_한_번_더_빌린다(self):
        pool = AuthPool(self.ROW, fails=1)
        self.assertEqual((asyncio.run(auth.lookup(pool, "han")), pool.acquired), (self.ROW, 2))
        pool = AuthPool(self.ROW, fails=5)
        with self.assertRaises(OSError):
            asyncio.run(auth.lookup(pool, "han"))
        self.assertEqual(pool.acquired, 2)

    def test_그_밖의_오류는_다시_하지_않는다(self):
        pool = AuthPool(self.ROW, fails=1, error=ValueError)
        with self.assertRaises(ValueError):
            asyncio.run(auth.lookup(pool, "han"))
        self.assertEqual(pool.acquired, 1)
        self.assertIs(main.STALE_CONNECTION_ERRORS, auth.STALE_CONNECTION_ERRORS)


# ──────────────────────────────────────────────────────────────
#  5. 명령줄 인자
# ──────────────────────────────────────────────────────────────
class PasswordInputTest(unittest.TestCase):
    """명령줄 비밀번호는 로그인이 자르는 길이(MAX_PASSWORD)를 넘지 못한다. 넘으면 그 계정은 로그인할 수 없다."""

    def ask(self, pw):
        with patch.object(auth.getpass, "getpass", side_effect=[pw, pw]):
            return auth.ask_password()

    def test_길이_경계(self):
        self.assertEqual(auth.MAX_PASSWORD, 256)
        self.assertEqual(self.ask("a" * 256), "a" * 256)
        self.assertEqual(self.ask("가" * 12), "가" * 12)
        for bad in ("a" * 257, "a" * 11):
            with self.subTest(n=len(bad)), self.assertRaises(auth.CliError):
                self.ask(bad)


class CliArgsTest(unittest.TestCase):
    def parse(self, *argv):
        return auth.build_parser().parse_args(list(argv))

    def rejected(self, *argv):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(*argv)

    def test_명령과_행위자(self):
        a = self.parse("add", "kim.ops-1", "operator", "--by", "han")
        self.assertEqual((a.cmd, a.username, a.role, a.by, a.func), ("add", "kim.ops-1", "operator", "han", auth.cmd_add))
        self.assertIsNone(self.parse("role", "kim", "admin").by)
        for cmd, func in (("passwd", auth.cmd_passwd), ("disable", auth.cmd_disable), ("enable", auth.cmd_enable)):
            self.assertIs(self.parse(cmd, "kim", "--by", "lee").func, func)
        self.assertIs(self.parse("list").func, auth.cmd_list)

    def test_새_아이디는_형식을_지킨다(self):
        for bad in ("a b", "a" * 65, "", "관리자", "a;b", "a\x00b", "-x"):
            with self.subTest(bad=bad):
                self.rejected("add", bad, "viewer")
        self.parse("add", "a" * 64, "viewer")
        # 이미 있는 계정은 로그인과 같은 길이 · 제어 문자만 본다(형식 검사 전에 만든 계정도 다룬다)
        self.assertEqual(self.parse("disable", "관제 사용자").username, "관제 사용자")
        for bad in ("a" * 129, "a\nb"):
            self.rejected("disable", bad)

    def test_행위자_이름과_역할(self):
        for bad in ("ops lead", "a=b", "x" * 65):
            with self.subTest(bad=bad):
                self.rejected("disable", "kim", "--by", bad)
        self.rejected("add", "kim", "root")
        self.rejected("role", "kim", "superuser")
        self.rejected("list", "--by", "han")

    def test_비밀번호는_인자로_받지_않는다(self):
        self.rejected("add", "kim", "viewer", "--password", "correct-horse-battery")
        self.rejected("passwd", "kim", "correct-horse-battery")

    def test_DB_주소가_없으면_1(self):
        with patch.dict(os.environ, {}, clear=True), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(auth.main(["list"]), 1)
        self.assertIn("DATABASE_URL", err.getvalue())


if __name__ == "__main__":
    unittest.main()
