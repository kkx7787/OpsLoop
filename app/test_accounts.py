#!/usr/bin/env python3
"""계정 관리(이슈 #59 · #63) 시험. DB 없이 돈다.  python3 app/test_accounts.py

보는 것
  1. 계정 API(accounts.py): 세션 없음 401 · 관리자가 아니면 403(DB 를 보지 않고 해시도 만들지 않는다) · 목록 모양(해시 없음 ·
     잠금 표시 · 활성 · 삭제 가능, 이력 표를 못 읽으면 null) · 변경은 한 트랜잭션에서 행위자를 건 뒤 계정 함수 한 번 ·
     추가 · 삭제 · 비밀번호 재설정(#63): 해시는 서버가 만들어 함수 인자로만 넘기고 응답 · 로그에 평문 · 해시가 없다 ·
     결과 매핑(ok · unchanged 200 · 추가 201, invalid 422, not_found 404, exists · in_use · cli_only · self 409 문구,
     no_actor · 모르는 값 · DB 오류 500, DB 오류 로그는 첫 줄만) · 입력 422(짧은 · 긴 비밀번호 · 아이디 형식 · 관리자 역할,
     DB 를 보지 않는다) · Cache-Control no-store · 출처 확인 · 아이디는 매개변수로만
  2. 세션 순수 함수(auth): 쿠키의 발급 시각 i · session_valid(없음 · 비활성 · 변경 전 쿠키 · i 없는 옛 쿠키)
  3. 로그인(auth.authenticate): 비활성 계정은 비밀번호가 맞아도 실패(해시 계산은 같게, 로그인 기록 갱신 없음) ·
     발급 시각은 UPDATE … RETURNING 의 DB 시각 · 확인과 갱신 사이에 계정이 바뀌면(updated_at 이 다르면) 실패 ·
     해시 · 확인은 어느 길이든(NUL 아이디 · 없는 계정 · 비활성 · 틀린 · 맞는 비밀번호) 한 번, 이벤트 루프 스레드 밖에서 돈다 ·
     느린 가짜 해시로 로그인하는 동안 /health · /api/me 가 먼저 답한다(main.app 을 httpx ASGITransport 로 부른다)
  4. 계정 조회(auth.lookup): 한 문장 · 옛 연결 오류만 한 번 더 빌린다
  5. 명령줄 인자(auth.build_parser): 아이디 형식 · --by 형식 · 역할 선택지 · 비밀번호는 인자로 받지 않는다
명령줄 명령의 DB 동작(마지막 관리자 · 감사 행위자)은 app/test_accounts_db.py 가 시험 DB 에서 본다.

실행: python -m unittest discover -s app
"""
import asyncio
import io
import json
import os
import re
import sys
import threading
import time
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


PASSWORD = "correct-horse-battery"
NEW_PASSWORD = "another-long-password"
HASHED = re.compile(r"pbkdf2_sha256\$[0-9]+\$[0-9a-f]+\$[0-9a-f]+")


def row(username, role, disabled_at=None, last_login_at=None, updated_at=T0, deletable=True):
    # 가짜 DB 는 해시까지 돌려준다. 응답에 실리지 않는지 본다(목록 문장에는 애초에 없다)
    return {"username": username, "role": role, "disabled_at": disabled_at, "created_at": T0,
            "last_login_at": last_login_at, "updated_at": updated_at, "deletable": deletable,
            "password_hash": "pbkdf2_sha256$240000$00$11"}


class FakeConn:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql, *args):
        self.pool.calls.append((sql, args))
        return "SELECT 1"

    async def fetchval(self, sql, *args):
        self.pool.calls.append((sql, args))
        if sql == accounts.READABLE_SQL:
            return self.pool.readable
        if self.pool.error is not None:
            raise self.pool.error
        return self.pool.result

    async def fetchrow(self, sql, *args):
        self.pool.calls.append((sql, args))
        found = self.pool.rows.get(args[0])
        # 이력 표를 못 읽으면 고른 문장(ONE_PLAIN_SQL)이 삭제 가능 여부를 NULL 로 준다
        return found if found is None or sql == accounts.ONE_SQL else {**found, "deletable": None}

    async def fetch(self, sql, *args):
        self.pool.calls.append((sql, args))
        rows = list(self.pool.rows.values())
        return rows if sql == accounts.LIST_SQL else [{**r, "deletable": None} for r in rows]

    @asynccontextmanager
    async def transaction(self):
        # 끝도 남겨 행위자 설정 · 함수 호출이 같은 트랜잭션 안인지 가른다(set_config 세 번째 인자 true 는 커밋과 함께 사라진다)
        self.pool.calls.append(("transaction", ()))
        yield
        self.pool.calls.append(("commit", ()))


class FakePool:
    """result: 계정 함수가 돌려줄 값, error: 계정 함수가 던질 DB 오류, readable: 이력 표(판정 · 조치 · 차단)를 읽을 수 있는가."""

    def __init__(self):
        self.calls, self.result, self.error, self.readable = [], "ok", None, True
        self.rows = {r["username"]: r for r in (
            row("boss", "admin", last_login_at=T1, deletable=False), row("root", "admin"),
            row("op", "operator", deletable=False), row("view", "viewer", disabled_at=T1, updated_at=T1))}

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self)


# ──────────────────────────────────────────────────────────────
#  1. 계정 API
# ──────────────────────────────────────────────────────────────
NEW = {"username": "kim", "role": "operator", "password": PASSWORD}


class AccountsApiTest(unittest.TestCase):
    def setUp(self):
        self.pool = FakePool()
        patcher = patch.object(main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # 해시를 언제 만드는지 센다(권한 · 입력 검사를 지난 뒤에만). 값은 진짜 함수가 만든다
        hasher = patch.object(auth, "hash_password", wraps=auth.hash_password)
        self.hash = hasher.start()
        self.addCleanup(hasher.stop)
        self.accounts = test_web.FakeAccounts().patch(self)
        for name, role in (("boss", "admin"), ("op", "operator"), ("view2", "viewer")):
            self.accounts[name] = test_web.account_row(role)
        self.client = TestClient(main.app, follow_redirects=False, raise_server_exceptions=False)
        self.addCleanup(self.client.close)

    def login(self, username="boss"):
        self.client.cookies.set(auth.COOKIE, auth.issue(username, self.accounts[username]["role"]))

    def post(self, path, body):
        return self.client.post(path, json=body, headers=SAME)

    def function_args(self, sql):
        """계정 함수에 넘긴 인자. 한 번만 불렸어야 한다."""
        [args] = [args for called, args in self.pool.calls if called == sql]
        return args

    def assert_no_secret(self, text, *hashes):
        for secret in (PASSWORD, NEW_PASSWORD, "pbkdf2", *hashes):
            self.assertNotIn(secret, text)

    def test_세션이_없으면_401_이고_DB_를_보지_않는다(self):
        self.assertEqual(self.client.get("/api/accounts").status_code, 401)
        for path, body in (("/api/accounts/role", {"username": "op", "role": "viewer"}),
                           ("/api/accounts/active", {"username": "op", "active": False}),
                           ("/api/accounts", NEW), ("/api/accounts/delete", {"username": "op"}),
                           ("/api/accounts/password", {"username": "op", "password": PASSWORD})):
            with self.subTest(path=path):
                self.assertEqual(self.post(path, body).status_code, 401)
        self.assertEqual((self.pool.calls, self.accounts.calls, self.hash.call_count), ([], [], 0))

    def test_관리자가_아니면_403_이고_DB_를_보지_않는다(self):
        for name in ("op", "view2"):
            with self.subTest(name=name):
                self.login(name)
                self.assertEqual(self.client.get("/api/accounts").status_code, 403)
                self.assertEqual(self.post("/api/accounts/role", {"username": "op", "role": "viewer"}).status_code, 403)
                self.assertEqual(self.post("/api/accounts/active", {"username": "op", "active": True}).status_code, 403)
                self.assertEqual(self.post("/api/accounts", NEW).status_code, 403)
                self.assertEqual(self.post("/api/accounts/delete", {"username": "view"}).status_code, 403)
                r = self.post("/api/accounts/password", {"username": "view", "password": PASSWORD})
                self.assertEqual(r.status_code, 403)
        # 관리자가 아니면 해시도 만들지 않는다(수백 ms 계산을 아무나 시키지 못한다)
        self.assertEqual((self.pool.calls, self.hash.call_count), ([], 0))

    def test_쿠키가_관리자여도_DB_역할이_관제사면_403(self):
        self.client.cookies.set(auth.COOKIE, auth.issue("op", "admin"))
        self.assertEqual(self.client.get("/api/accounts").status_code, 403)
        self.assertEqual(self.post("/api/accounts", NEW).status_code, 403)
        self.assertEqual((self.pool.calls, self.hash.call_count), ([], 0))

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
        self.assertEqual({a["username"]: a["deletable"] for a in body["accounts"]},
                         {"boss": False, "root": True, "op": False, "view": True})
        view = body["accounts"][3]
        self.assertEqual(view, {"username": "view", "role": "viewer", "active": False,
                                "disabled_at": T1.isoformat(), "created_at": T0.isoformat(), "last_login_at": None,
                                "updated_at": T1.isoformat(), "locked": None, "deletable": True})
        self.assertNotIn("password_hash", r.text)
        self.assert_no_secret(r.text)
        self.assertEqual(self.pool.calls, [(accounts.READABLE_SQL, ()), (accounts.LIST_SQL, ())])
        for sql in (accounts.LIST_SQL, accounts.ONE_SQL, accounts.LIST_PLAIN_SQL, accounts.ONE_PLAIN_SQL, auth.LOOKUP_SQL):
            self.assertNotIn("password_hash", sql)
        self.assertIn("ORDER BY username", accounts.LIST_SQL)
        self.assertIn("ORDER BY username", accounts.LIST_PLAIN_SQL)

    def test_삭제_가능은_함수의_이력_기준과_같다(self):
        # console_account_delete 의 in_use: 로그인 기록 · 판정 처리자 · 조치 처리자 · 차단 요청자 · 해제자
        for part in ("last_login_at IS NOT NULL", "FROM verdicts WHERE operator = u.username",
                     "FROM actions WHERE operator = u.username",
                     "FROM blocklist WHERE requested_by = u.username OR released_by = u.username"):
            self.assertIn(part, accounts.DELETABLE)
        for sql in (accounts.LIST_SQL, accounts.ONE_SQL):
            self.assertIn(accounts.DELETABLE + " AS deletable", sql)
        for sql in (accounts.LIST_PLAIN_SQL, accounts.ONE_PLAIN_SQL):
            self.assertIn("NULL::boolean AS deletable", sql)
            self.assertNotIn("verdicts", sql)

    def test_이력_표를_못_읽으면_삭제_가능은_null(self):
        self.login()
        self.pool.readable = False
        r = self.client.get("/api/accounts")
        self.assertEqual(r.status_code, 200)
        self.assertEqual({a["deletable"] for a in r.json()["accounts"]}, {None})
        self.assertEqual(self.pool.calls, [(accounts.READABLE_SQL, ()), (accounts.LIST_PLAIN_SQL, ())])
        # 변경 뒤 계정 행도 같다. 변경 자체는 그대로 된다
        self.pool.calls.clear()
        r = self.post("/api/accounts/role", {"username": "op", "role": "viewer"})
        self.assertEqual((r.status_code, r.json()["account"]["deletable"]), (200, None))
        self.assertIn((accounts.ONE_PLAIN_SQL, ("op",)), self.pool.calls)
        self.assertNotIn(accounts.ONE_SQL, [sql for sql, _ in self.pool.calls])

    def test_역할_변경은_행위자를_건_한_트랜잭션에서_함수_한_번(self):
        self.login()
        r = self.post("/api/accounts/role", {"username": "op", "role": "viewer"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"result": "ok", "account": {
            "username": "op", "role": "operator", "active": True, "disabled_at": None, "created_at": T0.isoformat(),
            "last_login_at": None, "updated_at": T0.isoformat(), "locked": None, "deletable": False}})
        self.assertEqual(self.pool.calls, [
            ("transaction", ()),
            ("SELECT set_config('opsloop.actor', $1, true)", ("boss",)),
            (accounts.SET_SQL, ("op", "viewer", None)),
            (accounts.READABLE_SQL, ()),
            (accounts.ONE_SQL, ("op",)),
            ("commit", ())])
        self.assert_no_secret(r.text)
        self.assertEqual(self.hash.call_count, 0)

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

    # ── 추가 · 삭제 · 비밀번호 재설정 (이슈 #63) ──
    def test_계정_추가는_서버가_만든_해시를_함수에_넘긴다(self):
        self.login()
        self.pool.rows["kim"] = row("kim", "operator")      # 가짜 함수는 행을 넣지 않는다. 함수가 넣었을 행을 둔다
        with redirect_stdout(io.StringIO()) as out:
            r = self.post("/api/accounts", NEW)
        self.assertEqual((r.status_code, r.headers["cache-control"]), (201, "no-store"))
        self.assertEqual(r.json(), {"result": "ok", "account": {
            "username": "kim", "role": "operator", "active": True, "disabled_at": None, "created_at": T0.isoformat(),
            "last_login_at": None, "updated_at": T0.isoformat(), "locked": None, "deletable": True}})
        name, role, password_hash = self.function_args(accounts.CREATE_SQL)
        self.assertEqual((name, role), ("kim", "operator"))
        self.assertRegex(password_hash, rf"^{HASHED.pattern}$")
        self.assertTrue(auth.verify_password(PASSWORD, password_hash))
        self.assertEqual(self.pool.calls, [
            ("transaction", ()),
            ("SELECT set_config('opsloop.actor', $1, true)", ("boss",)),
            (accounts.CREATE_SQL, ("kim", "operator", password_hash)),
            (accounts.READABLE_SQL, ()),
            (accounts.ONE_SQL, ("kim",)),
            ("commit", ())])
        self.assertEqual(self.hash.call_count, 1)
        self.assert_no_secret(r.text + out.getvalue(), password_hash)

    def test_비밀번호_재설정도_해시만_넘기고_계정_행을_돌려준다(self):
        self.login()
        with redirect_stdout(io.StringIO()) as out:
            r = self.post("/api/accounts/password", {"username": "view", "password": NEW_PASSWORD})
        self.assertEqual((r.status_code, r.headers["cache-control"]), (200, "no-store"))
        self.assertEqual((r.json()["result"], r.json()["account"]["username"], r.json()["account"]["deletable"]),
                         ("ok", "view", True))
        name, password_hash = self.function_args(accounts.PASSWORD_SQL)
        self.assertEqual(name, "view")
        self.assertTrue(auth.verify_password(NEW_PASSWORD, password_hash))
        self.assertEqual(self.pool.calls[:3], [
            ("transaction", ()),
            ("SELECT set_config('opsloop.actor', $1, true)", ("boss",)),
            (accounts.PASSWORD_SQL, ("view", password_hash))])
        self.assertEqual(self.pool.calls[-1], ("commit", ()))
        self.assert_no_secret(r.text + out.getvalue(), password_hash)
        # 같은 비밀번호라도 소금이 달라 해시가 다르다
        self.pool.calls.clear()
        self.post("/api/accounts/password", {"username": "view", "password": NEW_PASSWORD})
        self.assertNotEqual(self.function_args(accounts.PASSWORD_SQL)[1], password_hash)

    def test_계정_삭제는_함수_한_번이고_행을_다시_읽지_않는다(self):
        self.login()
        r = self.post("/api/accounts/delete", {"username": "view"})
        self.assertEqual((r.status_code, r.json(), r.headers["cache-control"]), (200, {"result": "ok"}, "no-store"))
        self.assertEqual(self.pool.calls, [
            ("transaction", ()),
            ("SELECT set_config('opsloop.actor', $1, true)", ("boss",)),
            (accounts.DELETE_SQL, ("view",)),
            ("commit", ())])
        self.assertEqual(self.hash.call_count, 0)

    def test_추가_삭제_비밀번호_결과_매핑(self):
        self.login()
        refused = {"invalid": (422, "아이디 · 비밀번호 형식이 맞지 않습니다"),
                   "exists": (409, "이미 있는 아이디입니다"),
                   "in_use": (409, "판정 · 조치 · 로그인 기록이 있는 계정은 지울 수 없습니다. 비활성으로 막아 주세요"),
                   "not_found": (404, "계정을 찾을 수 없습니다"),
                   "cli_only": (409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
                   "self": (409, "본인 계정은 여기서 바꿀 수 없습니다"),
                   "no_actor": (500, "서버 오류"),
                   # 역할 · 활성만 unchanged 를 받는다. 추가 · 삭제 · 비밀번호는 ok 만 성공이다
                   "unchanged": (500, "서버 오류"),
                   "모르는 값": (500, "서버 오류")}
        endpoints = {"/api/accounts": (NEW, accounts.CREATE_SQL, ("invalid", "exists", "cli_only", "self")),
                     "/api/accounts/delete": ({"username": "root"}, accounts.DELETE_SQL,
                                              ("in_use", "not_found", "cli_only", "self")),
                     "/api/accounts/password": ({"username": "root", "password": PASSWORD}, accounts.PASSWORD_SQL,
                                                ("invalid", "not_found", "cli_only", "self"))}
        for path, (body, sql, results) in endpoints.items():
            for result in (*results, "no_actor", "unchanged", "모르는 값"):
                with self.subTest(path=path, result=result), redirect_stdout(io.StringIO()) as out:
                    self.pool.result = result
                    self.pool.calls.clear()
                    r = self.post(path, body)
                    status, detail = refused[result]
                    self.assertEqual((r.status_code, r.json()), (status, {"detail": detail}))
                    self.assertEqual(r.headers["cache-control"], "no-store")
                    self.assertIn(sql, [called for called, _ in self.pool.calls])
                    self.assertNotIn(accounts.ONE_SQL, [called for called, _ in self.pool.calls])
                    self.assertEqual("처리하지 못함" in out.getvalue(), status == 500)
                    self.assert_no_secret(r.text + out.getvalue())

    def test_DB_오류는_종류와_첫_줄만_남기고_500(self):
        asyncpg = accounts.asyncpg
        if not hasattr(asyncpg, "PostgresError"):
            self.skipTest("asyncpg 가 없다(가짜 모듈)")
        self.login()
        # 오류 상세(DETAIL)에는 실패한 행이 실릴 수 있다(해시 포함). 그 줄은 로그에 남기지 않는다
        fake_hash = "pbkdf2_sha256$1$ab$cd"
        self.pool.error = asyncpg.PostgresError.new(
            {"C": "23514", "M": "new row violates check constraint", "D": f"Failing row contains (kim, {fake_hash})."})
        with redirect_stdout(io.StringIO()) as out:
            r = self.post("/api/accounts", NEW)
        self.assertEqual((r.status_code, r.json(), r.headers["cache-control"]), (500, {"detail": "서버 오류"}, "no-store"))
        self.assertEqual(out.getvalue(),
                         "[accounts] 계정 함수 DB 오류: CheckViolationError: new row violates check constraint\n")
        self.assert_no_secret(r.text + out.getvalue(), fake_hash)

    def test_같은_아이디를_함께_추가해_고유_제약에_걸리면_409(self):
        asyncpg = accounts.asyncpg
        if not hasattr(asyncpg, "UniqueViolationError"):
            self.skipTest("asyncpg 가 없다(가짜 모듈)")
        self.login()
        self.pool.error = asyncpg.PostgresError.new({"C": "23505", "M": "duplicate key value violates unique constraint"})
        with redirect_stdout(io.StringIO()) as out:
            r = self.post("/api/accounts", NEW)
        self.assertEqual((r.status_code, r.json()), (409, {"detail": "이미 있는 아이디입니다"}))
        self.assertEqual(out.getvalue(), "")

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

    def test_추가_삭제_비밀번호_입력이_틀리면_422_이고_DB_도_해시도_없다(self):
        self.login()
        short, long_ = "s" * (auth.MIN_PASSWORD - 1), "l" * (auth.MAX_PASSWORD + 1)
        bad_create = [
            ({}, None), ({"username": "kim", "role": "viewer"}, None), ({"role": "viewer", "password": PASSWORD}, None),
            ({**NEW, "password": short}, "비밀번호는 12자 이상이어야 합니다"),
            ({**NEW, "password": long_}, "비밀번호는 256자 이하여야 합니다"),
            ({**NEW, "role": "admin"}, None), ({**NEW, "role": "Viewer"}, None), ({**NEW, "role": None}, None),
            ({**NEW, "username": ""}, "아이디는 영문"), ({**NEW, "username": "a b"}, "아이디는 영문"),
            ({**NEW, "username": "a" * 65}, "아이디는 영문"), ({**NEW, "username": "관리자"}, "아이디는 영문"),
            ({**NEW, "username": "../x"}, "아이디는 영문"), ({**NEW, "username": "kim\n"}, "아이디는 영문"),
            ({**NEW, "username": "a\x00b"}, "아이디는 영문"), ({**NEW, "username": "<b>x</b>"}, "아이디는 영문"),
            ({**NEW, "username": 5}, None), ({**NEW, "password": 123456789012345}, None),
            ({**NEW, "password": None}, None), ({**NEW, "password": [PASSWORD]}, None),
            ({**NEW, "password_hash": "pbkdf2_sha256$1$ab$cd"}, None)]     # 해시를 직접 넣지 못한다
        bad_delete = [({}, None), ({"username": ""}, None), ({"username": "a" * 129}, None),
                      ({"username": "a\x00b"}, "NUL"), ({"username": None}, None), ({"username": "op", "force": True}, None)]
        bad_password = [({"username": "op"}, None), ({"password": PASSWORD}, None),
                        ({"username": "op", "password": short}, "비밀번호는 12자 이상이어야 합니다"),
                        ({"username": "op", "password": long_}, "비밀번호는 256자 이하여야 합니다"),
                        ({"username": "", "password": PASSWORD}, None), ({"username": "a\x00b", "password": PASSWORD}, "NUL"),
                        ({"username": "op", "password": PASSWORD, "role": "admin"}, None),
                        ({"username": "op", "password": ""}, "비밀번호는 12자 이상")]
        for path, cases in (("/api/accounts", bad_create), ("/api/accounts/delete", bad_delete),
                            ("/api/accounts/password", bad_password)):
            for body, msg in cases:
                with self.subTest(path=path, body=body):
                    r = self.post(path, body)
                    self.assertEqual((r.status_code, r.headers["cache-control"]), (422, "no-store"))
                    # 가림 라우트: type · loc · msg 만. 입력한 비밀번호 · 아이디가 되돌아오지 않는다
                    self.assertTrue(all(set(item) <= {"type", "loc", "msg"} for item in r.json()["detail"]))
                    self.assert_no_secret(r.text)
                    for secret in (short, long_):
                        self.assertNotIn(secret, r.text)
                    if msg:
                        self.assertIn(msg, " ".join(item["msg"] for item in r.json()["detail"]))
        self.assertEqual((self.pool.calls, self.hash.call_count), ([], 0))

    def test_경계값은_받는다(self):
        self.login()
        for username, password in (("a" * 64, "a" * auth.MIN_PASSWORD), ("A.b_c-9", "a" * auth.MAX_PASSWORD),
                                   ("kim", "가" * auth.MIN_PASSWORD), ("kim", " spaces and\ttab ")):
            with self.subTest(username=username, n=len(password)):
                self.pool.rows[username] = row(username, "viewer")
                self.pool.calls.clear()
                r = self.post("/api/accounts", {"username": username, "role": "viewer", "password": password})
                self.assertEqual(r.status_code, 201)
                self.assertTrue(auth.verify_password(password, self.function_args(accounts.CREATE_SQL)[2]))
        # 재설정은 이미 있는 계정이라 로그인과 같은 길이(128)까지 받는다. 검증을 지나 함수까지 간다
        self.pool.result = "not_found"
        r = self.post("/api/accounts/password", {"username": "a" * 128, "password": "p" * auth.MAX_PASSWORD})
        self.assertEqual(r.status_code, 404)

    def test_짝_없는_서로게이트는_500_이_아니라_422(self):
        # 기본 422 처리기는 입력을 되돌려 싣다가 인코딩 오류로 500 이 된다. 가림 라우트는 type · loc · msg 만 싣는다
        self.login()
        for path, raw in (("/api/accounts/role", b'{"username":"\\ud800","role":"viewer"}'),
                          ("/api/accounts/active", b'{"username":"\\udc00x","active":false}'),
                          ("/api/accounts/role", b'{"username":"op","role":"\\ud800"}'),
                          ("/api/accounts", b'{"username":"kim","role":"viewer","password":"\\ud800aaaaaaaaaaaaaa"}'),
                          ("/api/accounts/delete", b'{"username":"\\ud800"}'),
                          ("/api/accounts/password", b'{"username":"op","password":"aaaaaaaaaaaaaa\\udc00"}')):
            with self.subTest(path=path, raw=raw):
                r = self.client.post(path, content=raw, headers={**SAME, "content-type": "application/json"})
                self.assertEqual(r.status_code, 422)
                self.assertTrue(all(set(item) <= {"type", "loc", "msg"} for item in r.json()["detail"]))
                if b"password" in raw:
                    # 비밀번호 칸은 제약 없는 str 이라 서로게이트가 그대로 들어온다. 해시 전에 검사가 막는다
                    self.assertIn("쓸 수 없는 문자", r.json()["detail"][0]["msg"])
        self.assertEqual((self.pool.calls, self.hash.call_count), ([], 0))

    def test_다른_출처의_변경은_막는다(self):
        self.login()
        for headers in ({}, test_web.EVIL):
            for path, body in (("/api/accounts/active", {"username": "op", "active": False}), ("/api/accounts", NEW),
                               ("/api/accounts/delete", {"username": "op"}),
                               ("/api/accounts/password", {"username": "op", "password": PASSWORD})):
                with self.subTest(path=path, headers=headers):
                    r = self.client.post(path, json=body, headers=headers)
                    self.assertEqual(r.status_code, 403)
        self.assertEqual((self.pool.calls, self.hash.call_count), ([], 0))

    def test_아이디는_매개변수로만_넘긴다(self):
        self.login()
        for name in ("x' OR '1'='1", "../../etc/passwd", "<img src=x onerror=alert(1)>", "a/b%2Fc", "관제 사용자"):
            self.pool.result = "not_found"
            for path, body, sql, args in (
                    ("/api/accounts/role", {"username": name, "role": "viewer"}, accounts.SET_SQL, (name, "viewer", None)),
                    ("/api/accounts/delete", {"username": name}, accounts.DELETE_SQL, (name,)),
                    ("/api/accounts/password", {"username": name, "password": PASSWORD}, accounts.PASSWORD_SQL, None)):
                with self.subTest(name=name, path=path):
                    self.pool.calls.clear()
                    r = self.post(path, body)
                    self.assertEqual(r.status_code, 404)
                    self.assertEqual(self.function_args(sql)[0], name)
                    if args is not None:
                        self.assertEqual(self.function_args(sql), args)
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
class AuthPool:
    """authenticate · lookup 용 가짜 풀. fetchrow 는 계정 행, fetchval 은 UPDATE … RETURNING 값. fails 번은 옛 연결 오류.
    execute 는 인증 기록(log_event)이다. /login 을 부를 때 쓴다."""

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
                if sql == main.login_limits.TAKE:
                    return 0
                return pool.returning

            async def execute(self, sql, *args):
                pool.calls.append((sql, args))
                return "INSERT 0 1"

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

    def test_해시와_확인은_이벤트_루프_스레드_밖에서_한_번_돈다(self):
        # 이벤트 루프에서 계산하면 그동안 다른 요청이 모두 기다린다(콘솔은 작업자 1개). 시간 맞추기도 같이 본다: 어느 길이든 한 번
        #   계산하고, 계산이 끝난 뒤에 돌려준다(기다리지 않고 먼저 돌려주면 응답 시간으로 계정 유무가 드러난다)
        real = {name: getattr(auth, name) for name in ("hash_password", "verify_password")}
        seen = []

        def spy(name):
            def call(*args):
                result = real[name](*args)
                seen.append((name, threading.get_ident()))   # 계산이 끝난 뒤에 적는다
                return result
            return call

        async def run(pool, username, password):
            user = await test_web.REAL_AUTHENTICATE(pool, username, password)
            return threading.get_ident(), user, list(seen)   # 돌려준 순간까지 끝난 계산

        cases = [("NUL 아이디", "ad\x00min", None, PASSWORD, "hash_password"),
                 ("없는 계정", "han", None, PASSWORD, "hash_password"),
                 ("비활성 계정", "han", self.account(disabled_at=T1), PASSWORD, "verify_password"),
                 ("틀린 비밀번호", "han", self.account(), "wrong-password-123", "verify_password"),
                 ("맞는 비밀번호", "han", self.account(), PASSWORD, "verify_password")]
        with patch.object(auth, "hash_password", spy("hash_password")), \
                patch.object(auth, "verify_password", spy("verify_password")):
            for why, username, account, password, want in cases:
                with self.subTest(why=why):
                    seen.clear()
                    loop_thread, user, done = asyncio.run(run(AuthPool(account), username, password))
                    self.assertEqual([name for name, _ in done], [want], "돌려주기 전에 해시를 한 번 계산하지 않았다")
                    self.assertEqual(seen, done, "돌려준 뒤에 더 계산했다")
                    self.assertNotEqual(done[0][1], loop_thread, "이벤트 루프 스레드에서 계산했다")
                    self.assertEqual(user is not None, why == "맞는 비밀번호")


class LoginWhileHashingTest(unittest.TestCase):
    """로그인 해시를 계산하는 동안에도 다른 요청이 답한다. 콘솔은 uvicorn 작업자 1개라 해시가 이벤트 루프를 막으면
    HAProxy 검사(/health)와 화면(/api/me)이 함께 기다린다. main.app 을 httpx ASGITransport 로 한 이벤트 루프에서 부른다
    (test_accounts_db.ManagePathTest.http 와 같은 방식). DB 는 가짜다."""

    SLOW = 0.5   # 느린 가짜 해시(초)

    def test_느린_해시로_로그인하는_동안_health_와_api_me_가_먼저_답한다(self):
        import httpx
        pool = AuthPool({"username": "han", "password_hash": auth.hash_password(PASSWORD), "role": "operator",
                         "disabled_at": None, "updated_at": T0})
        real, started, order = auth.verify_password, threading.Event(), []

        def slow_verify(*args):
            order.append("해시 시작")
            started.set()
            time.sleep(self.SLOW)
            order.append("해시 끝")
            return real(*args)

        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app),
                                         base_url="http://testserver") as client:
                async def call(method, path, **kw):
                    r = await client.request(method, path, **kw)
                    order.append(path)
                    return r

                login = asyncio.create_task(call("POST", "/login", headers=SAME,
                                                 data={"username": "han", "password": PASSWORD}))
                # 로그인이 해시에 들어갈 때까지 기다린다. 해시가 루프를 막으면 해시가 끝난 뒤에야 여기로 돌아온다
                while not started.is_set() and not login.done():
                    await asyncio.sleep(0.005)
                health = await call("GET", "/health")
                # 먼저 로그인해 둔 다른 화면의 세션
                me = await call("GET", "/api/me", headers={"cookie": f"{auth.COOKIE}={auth.issue('han', 'operator')}"})
                return await login, health, me

        with patch.object(main.app.state, "pool", pool, create=True), patch.object(auth, "verify_password", slow_verify):
            login, health, me = asyncio.run(run())
        self.assertEqual((login.status_code, health.status_code, health.json(), me.status_code, me.json()["username"]),
                         (302, 200, {"status": "ok"}, 200, "han"))
        self.assertIn(auth.COOKIE, login.cookies)
        # 해시를 계산하는 동안 두 요청이 답하고, 로그인은 해시가 끝난 뒤에 답한다
        self.assertEqual(order, ["해시 시작", "/health", "/api/me", "해시 끝", "/login"])


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
        for bad in ("a" * 257, "a" * 11, "a" * 12 + "\udc80"):
            with self.subTest(n=len(bad)), self.assertRaises(auth.CliError):
                self.ask(bad)

    def test_화면과_같은_검사(self):
        # 명령줄(ask_password)과 화면(accounts.checked_password)이 같이 쓴다. 문장에 값이 없다
        self.assertIsNone(auth.password_problem("a" * 12))
        self.assertIsNone(auth.password_problem("\x00" * 12))
        cases = {"b" * 11: "비밀번호는 12자 이상이어야 합니다", "c" * 257: "비밀번호는 256자 이하여야 합니다",
                 "d" * 12 + "\ud800": "비밀번호에 쓸 수 없는 문자가 있습니다"}
        for bad, want in cases.items():
            with self.subTest(n=len(bad)):
                self.assertEqual(auth.password_problem(bad), want)


class VerifyPasswordTest(unittest.TestCase):
    """반복 수가 범위 밖인 해시는 계산하지 않고 거부한다(계산 한 번에 콘솔이 멈추는 해시를 심는 길을 막는다)."""

    def test_반복_수_범위(self):
        stored = auth.hash_password("correct horse battery")
        self.assertTrue(auth.verify_password("correct horse battery", stored))
        _, iters, salt, value = stored.split("$")
        for bad in ("999999999999", "10000000", "9999", "0"):
            with self.subTest(iters=bad), patch.object(auth.hashlib, "pbkdf2_hmac", side_effect=AssertionError("계산하면 안 된다")):
                self.assertFalse(auth.verify_password("correct horse battery", f"pbkdf2_sha256${bad}${salt}${value}"))
        self.assertEqual((auth.MIN_ITERATIONS, auth.MAX_ITERATIONS), (10_000, 9_999_999))
        self.assertTrue(auth.MIN_ITERATIONS <= auth.ITERATIONS <= auth.MAX_ITERATIONS)


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
