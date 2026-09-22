#!/usr/bin/env python3
"""콘솔 웹 계층(web.py) 시험.  python3 app/test_web.py

main.app 을 FastAPI TestClient 로 그대로 부른다. lifespan 은 돌리지 않는다(TestClient 를 with 로 열지 않으면
돌지 않는다). DB 풀은 가짜로 바꾸고 계정 확인(auth.authenticate)은 가짜로 대신한다. 인증 기록(auth.log_event)은
진짜를 돌려 가짜 풀에 들어온 값으로 형식을 본다. asyncpg 가 없는 곳에서는 가짜 모듈을 넣는다.

보는 것
  1. 보안 헤더: CSP · nosniff · 틀 금지 · 참조 정책. /docs · /openapi.json 은 CSP 없음. /api 는 no-store
  2. 출처 확인: 같은 출처 통과 · 다른 출처 · 출처 없음 · null 은 403. Referer 대체. 포트까지 비교.
     /login · /logout · /api POST 포함. GET 은 보지 않는다. TRUSTED_ORIGINS. /ws 핸드셰이크
  3. CORS: CORS_ORIGINS 가 있을 때만 건다. 기본값(localhost:5173)은 없다
  4. /api/me: 세션이 있으면 아이디 · 역할, 없거나 위조면 401
  5. 화면 서빙: 빌드가 없으면 자리표시 그대로. 있으면 화면 경로는 index.html(no-cache), /assets 는 파일,
     폴더 밖은 막고 제외 경로(/api · /health · /login · /docs …)는 그대로. 로그인 전에는 /login(next 포함)
  6. 로그인: 새 화면(스크립트 없음) · next 는 같은 출처 상대 경로만 · 기록(console.login.*) 형식 그대로
"""
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# main 은 asyncpg 를 모듈 첫머리에서 부른다. 시험은 DB 에 붙지 않으므로 없으면 가짜를 넣는다.
try:
    import asyncpg  # noqa: F401
except ImportError:
    _fake = types.ModuleType("asyncpg")

    class _Record(dict):
        pass

    async def _no_db(*_a, **_k):
        raise RuntimeError("시험에서는 DB 에 붙지 않는다")

    _fake.Record = _Record
    _fake.create_pool = _fake.connect = _no_db
    sys.modules["asyncpg"] = _fake

# 개발자 환경의 값이 main 의 미들웨어 구성에 새지 않게 한다.
for _k in ("CORS_ORIGINS", "TRUSTED_ORIGINS"):
    os.environ.pop(_k, None)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

import auth  # noqa: E402
import main  # noqa: E402
import web  # noqa: E402

SAME = {"Origin": "http://testserver"}
EVIL = {"Origin": "http://evil.example"}
PASSWORD = "correct-horse-battery"


class FakeConn:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql, *args):
        self.pool.executed.append((sql, args))
        return "INSERT 0 1"

    async def fetchval(self, sql, *args):
        return 1

    async def fetchrow(self, sql, *args):
        return None

    async def fetch(self, sql, *args):
        return []


class FakePool:
    def __init__(self):
        self.executed = []

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                return FakeConn(pool)

            async def __aexit__(self, *_exc):
                return False

        return _Acquire()

    def events(self):
        """auth.INSERT_EVENT 로 들어온 인증 기록을 필드 이름으로 풀어 돌려준다."""
        out = []
        for sql, args in self.executed:
            if sql == auth.INSERT_EVENT:
                (line_hash, ts, eventid, session, src_ip, src_port, dst_port, username,
                 method, status, ua, url, message) = args
                out.append({"eventid": eventid, "session": session, "username": username,
                            "http_method": method, "http_status": status, "url": url,
                            "src_ip": src_ip, "line_hash": line_hash})
        return out


async def fake_authenticate(_pool, username, password):
    if username == "han" and password == PASSWORD:
        return {"username": "han", "role": "operator"}
    return None


class Base(unittest.TestCase):
    def setUp(self):
        self.pool = FakePool()
        main.app.state.pool = self.pool
        patcher = mock.patch.object(auth, "authenticate", fake_authenticate)
        patcher.start()
        self.addCleanup(patcher.stop)
        # 저장소에 실제 빌드(app/static)가 있어도 시험이 흔들리지 않게 빈 폴더로 시작한다.
        self.tmp = Path(tempfile.mkdtemp(prefix="opsloop-web-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        static_patch = mock.patch.object(web, "STATIC_DIR", self.tmp / "static")
        static_patch.start()
        self.addCleanup(static_patch.stop)
        self.client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def login_as(self, username="han", role="operator"):
        self.client.cookies.set(auth.COOKIE, auth.issue(username, role))

    def build_console(self):
        root = self.tmp / "static"
        (root / "assets").mkdir(parents=True)
        (root / "index.html").write_text(
            '<!doctype html><html lang="ko"><head><title>OpsLoop 관제</title>'
            '<script type="module" src="/assets/index-abc123.js"></script>'
            '<link rel="stylesheet" href="/assets/index-abc123.css"></head>'
            '<body><div id="root"></div></body></html>', encoding="utf-8")
        (root / "assets" / "index-abc123.js").write_text("console.log('opsloop')")
        (root / "assets" / "index-abc123.css").write_text("body{margin:0}")
        (root / "favicon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
        # 폴더 밖에 있어서는 안 보여야 하는 파일
        (self.tmp / "secret.txt").write_text("secret")
        return root


# ──────────────────────────────────────────────────────────────
#  1. 보안 헤더
# ──────────────────────────────────────────────────────────────
class SecurityHeadersTest(Base):
    def test_login_page_headers(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-security-policy"], web.CSP)
        for part in ("default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'",
                     "img-src 'self' data:", "connect-src 'self'", "font-src 'self'",
                     "object-src 'none'", "base-uri 'self'", "form-action 'self'",
                     "frame-ancestors 'none'"):
            self.assertIn(part, r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertEqual(r.headers["referrer-policy"], "same-origin")

    def test_docs_without_csp(self):
        for path in ("/docs", "/openapi.json"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertNotIn("content-security-policy", r.headers, path)
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    def test_api_no_store(self):
        r = self.client.get("/api/me")          # 세션 없음 → 인증 미들웨어의 401 에도 붙는다
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.login_as()
        r = self.client.get("/api/me")
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertIn("content-security-policy", r.headers)

    def test_redirect_has_headers(self):
        r = self.client.get("/incidents")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["x-frame-options"], "DENY")


# ──────────────────────────────────────────────────────────────
#  2. 출처 확인
# ──────────────────────────────────────────────────────────────
class BoomPool(FakePool):
    """acquire 에서 터지는 풀. DB 연결이 끊긴 상황이다."""

    def acquire(self):
        raise RuntimeError("DB 연결 없음")


class ServerErrorTest(Base):
    def test_500_keeps_headers(self):
        main.app.state.pool = BoomPool()
        client = TestClient(main.app, follow_redirects=False, raise_server_exceptions=False)
        self.addCleanup(client.close)
        client.cookies.set(auth.COOKIE, auth.issue("han", "operator"))
        for path, no_store in (("/health", False), ("/api/stats/summary", True)):
            with self.subTest(path=path):
                r = client.get(path)
                self.assertEqual(r.status_code, 500)
                self.assertEqual(r.json(), {"detail": "서버 오류"})
                self.assertEqual(r.headers.get("x-content-type-options"), "nosniff")
                self.assertEqual(r.headers.get("x-frame-options"), "DENY")
                self.assertIn("default-src 'self'", r.headers.get("content-security-policy", ""))
                self.assertEqual(r.headers.get("cache-control") == "no-store", no_store)


class OriginCheckTest(Base):
    def login_post(self, headers=None, **fields):
        data = {"username": "han", "password": PASSWORD} | fields
        return self.client.post("/login", data=data, headers=headers or {})

    def test_login_post_needs_origin(self):
        r = self.login_post()
        self.assertEqual(r.status_code, 403)
        self.assertIn("detail", r.json())
        self.assertEqual(self.pool.events(), [], "거부된 요청은 로그인 처리까지 가지 않는다")

    def test_login_post_cross_origin(self):
        for origin in ("http://evil.example", "null", "http://testserver.evil.example",
                       "http://testserver:8443", "ftp://testserver"):
            r = self.login_post({"Origin": origin})
            self.assertEqual(r.status_code, 403, origin)
        self.assertEqual(self.pool.events(), [])

    def test_login_post_same_origin(self):
        r = self.login_post(SAME)
        self.assertEqual(r.status_code, 302)
        r = self.login_post({"Origin": "https://testserver"})   # 앞단 TLS 종료: 기본 포트끼리 같다
        self.assertEqual(r.status_code, 302)

    def test_referer_fallback(self):
        r = self.login_post({"Referer": "http://testserver/login?next=/incidents"})
        self.assertEqual(r.status_code, 302)
        r = self.login_post({"Referer": "http://evil.example/login"})
        self.assertEqual(r.status_code, 403)

    def test_origin_wins_over_referer(self):
        r = self.login_post({"Origin": "http://evil.example", "Referer": "http://testserver/login"})
        self.assertEqual(r.status_code, 403)

    def test_host_with_port(self):
        # 운영: 브라우저는 http://192.168.70.254:8443 에서 연다. HAProxy 는 Host 를 그대로 넘긴다.
        host = {"Host": "192.168.70.254:8443"}
        r = self.login_post(host | {"Origin": "http://192.168.70.254:8443"})
        self.assertEqual(r.status_code, 302)
        r = self.login_post(host | {"Origin": "http://192.168.70.254:8404"})
        self.assertEqual(r.status_code, 403)
        r = self.login_post(host | {"Origin": "http://192.168.70.254"})
        self.assertEqual(r.status_code, 403)

    def test_logout_needs_origin(self):
        self.login_as()
        r = self.client.post("/logout")
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/logout", headers=SAME)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/login")
        self.assertEqual([e["eventid"] for e in self.pool.events()], ["console.logout"])

    def test_api_post_checked_before_handler(self):
        self.login_as()
        for method in ("post", "put", "patch", "delete"):
            r = self.client.request(method.upper(), "/api/incidents/k1/verdict",
                                    json={"verdict": "threat"}, headers=EVIL)
            self.assertEqual(r.status_code, 403, method)
            self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(self.pool.executed, [], "DB 까지 가지 않는다")

    def test_get_not_checked(self):
        self.login_as()
        r = self.client.get("/api/me", headers=EVIL)
        self.assertEqual(r.status_code, 200)

    def test_websocket_origin(self):
        self.login_as()
        with self.client.websocket_connect("/ws", headers={"origin": "http://testserver"}) as ws:
            self.assertEqual(ws.receive_json()["type"], "hello")
        # 세션 쿠키가 있어도 다른 출처나 출처 없는 핸드셰이크는 수락 전에 닫는다.
        for headers in ({"origin": "http://evil.example"}, {}):
            with self.assertRaises(WebSocketDisconnect) as caught:
                with self.client.websocket_connect("/ws", headers=headers):
                    pass
            self.assertEqual(caught.exception.code, 1008)

    def test_parse_helpers(self):
        self.assertEqual(web.parse_origin("https://Console.Example"), ("https", "console.example", 443))
        self.assertEqual(web.parse_origin("http://[::1]:8000"), ("http", "::1", 8000))
        for bad in ("null", "", "localhost:5173", "192.168.70.254:8443", "http://h:99999",
                    "javascript:alert(1)"):
            self.assertIsNone(web.parse_origin(bad), bad)


def guarded_app(**env):
    """web.guard 만 붙인 작은 앱. 환경변수는 붙이는 순간에만 읽는다."""
    with mock.patch.dict(os.environ):
        for key in ("CORS_ORIGINS", "TRUSTED_ORIGINS"):
            os.environ.pop(key, None)
        os.environ.update(env)
        app = FastAPI()

        @app.get("/x")
        async def read_x():
            return {"ok": True}

        @app.post("/x")
        async def write_x():
            return {"ok": True}

        web.guard(app)
    return TestClient(app)


class TrustedOriginsTest(unittest.TestCase):
    def test_trusted_origins(self):
        client = guarded_app(TRUSTED_ORIGINS=" https://console.example:8443/ , http://10.0.0.5:8443,bad-entry")
        self.assertEqual(client.post("/x", headers={"Origin": "https://console.example:8443"}).status_code, 200)
        self.assertEqual(client.post("/x", headers={"Origin": "http://10.0.0.5:8443"}).status_code, 200)
        # scheme · 포트가 다르면 신뢰 목록과 다르다
        self.assertEqual(client.post("/x", headers={"Origin": "http://console.example:8443"}).status_code, 403)
        self.assertEqual(client.post("/x", headers={"Origin": "https://console.example"}).status_code, 403)
        self.assertEqual(client.post("/x").status_code, 403)


# ──────────────────────────────────────────────────────────────
#  3. CORS
# ──────────────────────────────────────────────────────────────
class CorsTest(unittest.TestCase):
    DEV = "http://localhost:5173"

    def test_off_by_default(self):
        client = guarded_app()
        r = client.get("/x", headers={"Origin": self.DEV})
        self.assertNotIn("access-control-allow-origin", r.headers)
        r = client.options("/x", headers={"Origin": self.DEV, "Access-Control-Request-Method": "POST"})
        self.assertNotIn("access-control-allow-origin", r.headers)
        # 옛 기본값(localhost:5173)도 신뢰하지 않는다
        self.assertEqual(client.post("/x", headers={"Origin": self.DEV}).status_code, 403)

    def test_main_app_has_no_cors(self):
        r = TestClient(main.app).get("/login", headers={"Origin": self.DEV})
        self.assertNotIn("access-control-allow-origin", r.headers)

    def test_on_when_configured(self):
        client = guarded_app(CORS_ORIGINS=self.DEV)
        r = client.get("/x", headers={"Origin": self.DEV})
        self.assertEqual(r.headers["access-control-allow-origin"], self.DEV)
        self.assertEqual(r.headers["access-control-allow-credentials"], "true")
        r = client.options("/x", headers={"Origin": self.DEV, "Access-Control-Request-Method": "POST"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["access-control-allow-origin"], self.DEV)
        # 자격 증명까지 허락한 출처는 상태 변경 요청도 받는다
        self.assertEqual(client.post("/x", headers={"Origin": self.DEV}).status_code, 200)
        self.assertEqual(client.post("/x", headers={"Origin": "http://evil.example"}).status_code, 403)


# ──────────────────────────────────────────────────────────────
#  4. /api/me
# ──────────────────────────────────────────────────────────────
class MeTest(Base):
    def test_me(self):
        self.login_as("kim", "admin")
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"username": "kim", "role": "admin"})

    def test_me_without_session(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json(), {"detail": "인증이 필요합니다"})

    def test_me_forged_session(self):
        token = auth.issue("han", "viewer")
        payload, _, sig = token.rpartition(".")
        self.client.cookies.set(auth.COOKIE, payload + "." + ("0" * len(sig)))
        self.assertEqual(self.client.get("/api/me").status_code, 401)


# ──────────────────────────────────────────────────────────────
#  5. 화면 서빙
# ──────────────────────────────────────────────────────────────
class ConsoleFilesTest(Base):
    def test_without_build_placeholder_stays(self):
        self.login_as()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("화면 구현 예정", r.text)
        self.assertEqual(self.client.get("/incidents").status_code, 404)
        self.assertEqual(self.client.get("/assets/index-abc123.js").status_code, 404)

    def test_screen_paths_get_index(self):
        self.build_console()
        self.login_as()
        for path in ("/", "/incidents", "/incidents/web-01:R002:1.2.3.4", "/accounts",
                     "/no/such/screen", "/index.html", "/apiary"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn('<div id="root">', r.text, path)
            self.assertEqual(r.headers["cache-control"], "no-cache", path)
            self.assertTrue(r.headers["content-type"].startswith("text/html"), path)
            self.assertEqual(r.headers["content-security-policy"], web.CSP, path)
        self.assertEqual(self.client.head("/incidents").status_code, 200)

    def test_assets(self):
        self.build_console()
        self.login_as()
        r = self.client.get("/assets/index-abc123.js")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/javascript"))
        self.assertIn("immutable", r.headers["cache-control"])
        r = self.client.get("/assets/index-abc123.css")
        self.assertTrue(r.headers["content-type"].startswith("text/css"))
        r = self.client.get("/favicon.svg")
        self.assertEqual(r.headers["content-type"], "image/svg+xml")
        # 없는 번들은 index.html 이 아니라 404
        r = self.client.get("/assets/missing.js")
        self.assertEqual(r.status_code, 404)

    def test_assets_stay_in_folder(self):
        self.build_console()
        self.login_as()
        for path in ("/assets/%2e%2e/index.html", "/assets/%2e%2e/%2e%2e/secret.txt",
                     "/assets/..%5c..%5csecret.txt"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 404, path)
            self.assertNotIn("secret", r.text, path)
        # 맨 위 파일도 폴더 밖은 주지 않는다. 화면 경로로 보고 index.html 을 준다
        r = self.client.get("/%2e%2e/secret.txt")
        self.assertNotIn("secret", r.text)
        self.assertIn('<div id="root">', r.text)

    def test_server_paths_not_shadowed(self):
        self.build_console()
        self.login_as()
        r = self.client.get("/api/nope")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json(), {"detail": "Not Found"})
        r = self.client.get("/health")
        self.assertEqual(r.json()["status"], "ok")
        r = self.client.get("/login")
        self.assertIn('action="/login"', r.text)
        r = self.client.get("/docs")
        self.assertIn("swagger", r.text.lower())
        self.assertEqual(self.client.get("/openapi.json").json()["info"]["title"], "OpsLoop API")
        # 화면 경로라도 GET · HEAD 가 아니면 index.html 을 주지 않는다
        r = self.client.post("/incidents", headers=SAME)
        self.assertNotEqual(r.status_code, 200)

    def test_bundle_needs_login(self):
        self.build_console()
        r = self.client.get("/incidents/k1?tab=raw")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/login?next=%2Fincidents%2Fk1%3Ftab%3Draw")
        r = self.client.get("/")
        self.assertEqual(r.headers["location"], "/login")
        r = self.client.get("/assets/index-abc123.js")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/login", "번들 경로는 next 로 삼지 않는다")
        self.assertEqual(self.client.get("/api/incidents").status_code, 401)

    def test_login_redirect_keeps_encoded_path(self):
        r = self.client.get("/incidents/a%2Fb")
        self.assertEqual(r.headers["location"], "/login?next=%2Fincidents%2Fa%252Fb")
        # 경로가 // 로 시작하면 next 로 삼지 않는다 (httpx 가 //host 를 주소로 읽지 않게 전체 URL 로 보낸다)
        r = self.client.get("http://testserver//evil.example/x")
        self.assertEqual(r.headers["location"], "/login")


# ──────────────────────────────────────────────────────────────
#  6. 로그인
# ──────────────────────────────────────────────────────────────
class LoginTest(Base):
    def post(self, **fields):
        data = {"username": "han", "password": PASSWORD} | fields
        return self.client.post("/login", data=data, headers=SAME)

    def test_login_page(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["cache-control"], "no-store")
        body = r.text
        self.assertNotIn("<script", body.lower(), "CSP: 인라인 스크립트가 없다")
        self.assertNotIn("fonts.googleapis", body, "외부 글꼴을 쓰지 않는다")
        self.assertIn('<form method="post" action="/login">', body)
        self.assertIn('name="username"', body)
        self.assertIn('name="password" type="password"', body)
        self.assertIn('<input type="hidden" name="next" value="/">', body)
        self.assertIn("OpsLoop 관제 콘솔", body)
        self.assertNotIn(web.LOGIN_ERROR, body)

    def test_success_goes_to_next(self):
        r = self.post(next="/incidents/k1?tab=raw")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/incidents/k1?tab=raw")
        cookie = r.headers["set-cookie"]
        self.assertIn(auth.COOKIE + "=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("samesite=lax", cookie.lower())
        token = r.cookies.get(auth.COOKIE) or cookie.split(auth.COOKIE + "=", 1)[1].split(";", 1)[0]
        self.assertEqual(auth.read(token)["u"], "han")

        # 기록 형식은 그대로다: 같은 이벤트 · 필드 · 상태
        (event,) = self.pool.events()
        self.assertEqual(event["eventid"], "console.login.success")
        self.assertEqual(event["username"], "han")
        self.assertEqual(event["http_status"], 302)
        self.assertEqual(event["http_method"], "POST")
        self.assertEqual(event["url"], "/login")
        self.assertEqual(event["session"], token[:17])

    def test_success_without_next(self):
        r = self.post()
        self.assertEqual(r.headers["location"], "/")

    def test_open_redirect_blocked(self):
        for bad in ("https://evil.example", "//evil.example", "///evil.example", "/\\evil.example",
                    "\\\\evil.example", "/\t/evil.example", "/\n/evil.example", "javascript:alert(1)",
                    "evil.example", "/login", "/login?next=/x", "/logout", "", "/" + "a" * 3000):
            r = self.post(next=bad)
            self.assertEqual(r.status_code, 302, repr(bad))
            self.assertEqual(r.headers["location"], "/", repr(bad))

    def test_failure_keeps_next_and_logs(self):
        r = self.post(password="wrong", next="/incidents/k1")
        self.assertEqual(r.status_code, 401)
        self.assertIn(web.LOGIN_ERROR, r.text)
        self.assertIn('role="alert"', r.text)
        self.assertIn('<input type="hidden" name="next" value="/incidents/k1">', r.text)
        self.assertIn('value="han"', r.text)
        self.assertNotIn("set-cookie", r.headers)
        (event,) = self.pool.events()
        self.assertEqual(event["eventid"], "console.login.failed")
        self.assertEqual(event["username"], "han")
        self.assertEqual(event["http_status"], 401)
        self.assertEqual(event["session"], None)

    def test_page_escapes_values(self):
        r = self.client.get("/login", params={"next": '/x"><img src=x onerror=alert(1)>'})
        self.assertNotIn('"><img', r.text)
        self.assertIn("/x&quot;&gt;&lt;img", r.text)
        r = self.client.get("/login", params={"next": "https://evil.example"})
        self.assertIn('name="next" value="/"', r.text)
        r = self.post(username='a"><script>alert(1)</script>', password="x")
        self.assertNotIn("<script>", r.text)

    def test_safe_next_unit(self):
        for good in ("/", "/incidents", "/incidents/a%2Fb?x=1#y", "/rules?v=2"):
            self.assertEqual(web.safe_next(good), good)
        for bad in (None, 3, "", "x", "//a", "/\\a", "http://a", "/login", "/logout/", "/\x7f"):
            self.assertEqual(web.safe_next(bad), "/", repr(bad))


if __name__ == "__main__":
    unittest.main(verbosity=1)
