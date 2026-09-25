#!/usr/bin/env python3
"""콘솔 웹 계층(web.py) 시험.  python3 app/test_web.py

main.app 을 FastAPI TestClient 로 그대로 부른다. lifespan 은 돌리지 않는다(TestClient 를 with 로 열지 않으면
돌지 않는다). DB 풀은 가짜로 바꾸고 계정 확인(auth.authenticate)은 가짜로 대신한다. 인증 기록(auth.log_event)은
진짜를 돌려 가짜 풀에 들어온 값으로 형식을 본다. asyncpg 가 없는 곳에서는 가짜 모듈을 넣는다.

보는 것
  1. 보안 헤더: CSP · nosniff · 틀 금지 · 참조 정책 · DNS 프리페치 끔 · COOP · CORP · 권한 정책.
     화면 · 번들 · 로그인 · 302 · /api 200/401/403/404/422 · 500 · csp-report 행렬. /api 는 no-store.
     CSP 는 'unsafe-inline' · data: · 외부 호스트 없음 · 보고는 같은 출처 report-uri 만. 로그인 화면만 <style> 해시.
     API 문서(/docs · /openapi.json)는 기본으로 없음(404). OPSLOOP_API_DOCS=1 이면 켜지되 세션 뒤. /health 는 상태만
  2. 출처 확인: 같은 출처 통과 · 다른 출처 · 출처 없음 · null 은 403. Referer 대체. 포트까지 비교.
     /login · /logout · /api POST 포함. GET 은 보지 않는다. TRUSTED_ORIGINS. /ws 핸드셰이크
  3. CORS: CORS_ORIGINS 가 있을 때만 건다. 기본값(localhost:5173)은 없다
  4. /api/me: 세션이 있으면 아이디 · 역할 · 콘솔 이름(헤더로는 안 냄), 없거나 위조면 401
     /ws: 세션이 없으면 수락한 뒤 1008 로 닫는다(브라우저가 1008 을 받는다). hello 에 콘솔 이름(이슈 #43)
  5. 화면 서빙: 빌드가 없으면 자리표시 그대로. 있으면 화면 경로는 index.html(no-cache), /assets 는 파일,
     폴더 밖은 막고 제외 경로(/api · /health · /login · /docs …)는 그대로. 로그인 전에는 /login(next 포함)
  6. 로그인: 새 화면(스크립트 없음) · next 는 같은 출처 상대 경로만 · 기록(console.login.*) 형식 그대로.
     아이디 · UA 의 NUL 은 지우고 파서와 같은 길이로 자른다(기록이 빠지지 않는다)
  7. CSP 위반 보고(POST /api/csp-report): 세션 · 출처 없이 받음(이 경로만) · 형식 · 8 KiB · 분당 60건 · 한 줄 로그 정리
  8. 로그인 기록의 출발지(이슈 #43): uvicorn 은 FORWARDED_ALLOW_IPS 에 든 곳(HAProxy)에서 온 X-Forwarded-For 만 믿는다.
     믿는 프록시 → 실제 주소 · 다른 곳 → 무시 · "위조, 실제" → 오른쪽 실제 값

실행: python -m unittest discover -s app
"""
import asyncio
import base64
import hashlib
import importlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
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
for _k in ("CORS_ORIGINS", "TRUSTED_ORIGINS", "OPSLOOP_API_DOCS"):
    os.environ.pop(_k, None)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

import auth  # noqa: E402
import live  # noqa: E402
import main  # noqa: E402
import web  # noqa: E402

# 시험마다 가짜로 바꾸기 전의 진짜 계정 확인
REAL_AUTHENTICATE = auth.authenticate
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
EXPECTED_BASE = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "same-origin",
    "x-dns-prefetch-control": "off",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
}
# 브라우저가 밖으로 요청할 수 있는 지시어. 값은 'self' 나 'none'(로그인 style-src 는 해시 하나 더)뿐이어야 한다.
FETCH_DIRECTIVES = ("default-src", "script-src", "style-src", "img-src", "connect-src", "font-src",
                    "object-src", "base-uri", "form-action", "frame-ancestors")


def directives(csp: str) -> dict:
    return {name: rest for name, _, rest in (part.partition(" ") for part in csp.split("; "))}


class SecurityHeadersTest(Base):
    def assert_headers(self, r, label, csp=web.CSP, api=False):
        for name, value in EXPECTED_BASE.items():
            self.assertEqual(r.headers.get(name), value, f"{label}: {name}")
        self.assertEqual(r.headers.get("content-security-policy"), csp, label)
        if api:
            self.assertEqual(r.headers.get("cache-control"), "no-store", label)

    def test_csp_directives(self):
        """'unsafe-inline' · data: · 외부 호스트가 없다. 위반은 같은 출처로만 보고한다."""
        for csp in (web.CSP, web.LOGIN_CSP):
            found = directives(csp)
            self.assertNotIn("unsafe-inline", csp)
            self.assertNotIn("unsafe-eval", csp)
            self.assertNotIn("data:", csp)
            self.assertNotIn("http", csp)
            self.assertEqual(found["img-src"], "'self'")
            self.assertEqual(found["report-uri"], "/api/csp-report")
            # report-to 가 있으면 Chrome 이 report-uri 를 버리고, 평문 HTTP 에서는 report-to 도 못 쓴다
            self.assertNotIn("report-to", found)
            for name in FETCH_DIRECTIVES:
                for source in found[name].split():
                    self.assertTrue(source in ("'self'", "'none'") or source.startswith("'sha256-"), (name, source))
        self.assertEqual(directives(web.CSP)["style-src"], "'self'")
        self.assertEqual(directives(web.LOGIN_CSP)["style-src"], f"'self' 'sha256-{web.LOGIN_STYLE_HASH}'")
        # 로그인 CSP 는 style-src 만 다르다
        self.assertEqual({k: v for k, v in directives(web.LOGIN_CSP).items() if k != "style-src"},
                         {k: v for k, v in directives(web.CSP).items() if k != "style-src"})

    def test_login_style_hash_matches_page(self):
        """로그인 응답의 CSP 해시가 실제로 나간 <style> 본문의 SHA-256 과 같다. 스타일을 고쳐도 모양이 깨지지 않는다."""
        for r in (self.client.get("/login"),
                  self.client.post("/login", data={"username": "han", "password": "x"}, headers=SAME)):
            styles = re.findall(r"<style>(.*?)</style>", r.text, re.S)
            self.assertEqual(len(styles), 1)
            digest = base64.b64encode(hashlib.sha256(styles[0].encode("utf-8")).digest()).decode()
            self.assertEqual(digest, web.LOGIN_STYLE_HASH)
            self.assertIn(f"style-src 'self' 'sha256-{digest}';", r.headers["content-security-policy"])
            self.assertNotIn("style=", r.text, "style 속성은 해시로 열리지 않는다")

    def test_header_matrix(self):
        """콘솔이 내는 응답 종류마다 헤더가 모두 붙는다."""
        self.build_console()
        # 세션 없음: 로그인 화면 · 302 · 401 · 위반 보고
        self.assert_headers(self.client.get("/login"), "로그인 화면", csp=web.LOGIN_CSP)
        r = self.client.post("/login", data={"username": "han", "password": "x"}, headers=SAME)
        self.assertEqual(r.status_code, 401)
        self.assert_headers(r, "로그인 실패", csp=web.LOGIN_CSP)
        r = self.client.get("/incidents")
        self.assertEqual(r.status_code, 302)
        self.assert_headers(r, "302 로그인으로")
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)
        self.assert_headers(r, "/api 401", api=True)
        with redirect_stdout(io.StringIO()):
            r = self.client.post("/api/csp-report", json={"csp-report": {"blocked-uri": "inline"}})
        self.assertEqual(r.status_code, 204)
        self.assert_headers(r, "csp-report 204", api=True)
        # 세션 있음
        self.login_as()
        r = self.client.get("/incidents/k1")
        self.assertEqual((r.status_code, r.headers["content-type"].split(";")[0]), (200, "text/html"))
        self.assert_headers(r, "화면")
        r = self.client.get("/assets/index-abc123.js")
        self.assertEqual(r.status_code, 200)
        self.assert_headers(r, "번들")
        r = self.client.post("/login", data={"username": "han", "password": PASSWORD}, headers=SAME)
        self.assertEqual(r.status_code, 302)
        self.assert_headers(r, "로그인 성공 302")
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 200)
        self.assert_headers(r, "/api 200", api=True)
        r = self.client.post("/api/incidents/k1/verdict", json={"verdict": "threat"}, headers=EVIL)
        self.assertEqual(r.status_code, 403)
        self.assert_headers(r, "/api 403", api=True)
        r = self.client.get("/api/nope")
        self.assertEqual(r.status_code, 404)
        self.assert_headers(r, "/api 404", api=True)
        r = self.client.get("/api/incidents", params={"limit": 0})
        self.assertEqual(r.status_code, 422)
        self.assert_headers(r, "/api 422", api=True)
        r = self.client.get("/health")
        self.assert_headers(r, "/health")

    def test_api_no_store(self):
        r = self.client.get("/api/me")          # 세션 없음 → 인증 미들웨어의 401 에도 붙는다
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.login_as()
        r = self.client.get("/api/me")
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertIn("content-security-policy", r.headers)

    def test_no_server_header_in_container(self):
        """uvicorn 의 server: uvicorn 을 빼고 띄운다(콘솔 구성이 드러나지 않게)."""
        cmd = [line for line in (Path(HERE) / "Dockerfile").read_text(encoding="utf-8").splitlines()
               if line.startswith("CMD")]
        self.assertEqual(len(cmd), 1)
        self.assertIn('"--no-server-header"', cmd[0])

    def test_redirect_has_headers(self):
        r = self.client.get("/incidents")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["x-frame-options"], "DENY")


class ApiDocsTest(Base):
    DOCS = ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect")

    def test_off_by_default(self):
        self.assertEqual((main.app.docs_url, main.app.redoc_url, main.app.openapi_url), (None, None, None))
        self.assertFalse(any(web._under(p, main.OPEN_PATHS) for p in self.DOCS))
        for path in self.DOCS:
            r = self.client.get(path)
            self.assertEqual((r.status_code, r.headers["location"]), (302, "/login"), path)
        self.login_as()
        for path in self.DOCS:
            r = self.client.get(path)
            self.assertEqual(r.status_code, 404, path)
            self.assertNotIn("swagger", r.text.lower(), path)
            self.assertEqual(r.headers.get("content-security-policy"), web.CSP, path)

    def test_on_only_behind_session(self):
        with mock.patch.dict(os.environ, {"OPSLOOP_API_DOCS": "1"}):
            docs_main = importlib.reload(main)
        # 다음 시험은 기본(끔) 앱으로 돈다
        self.addCleanup(importlib.reload, main)
        client = TestClient(docs_main.app, follow_redirects=False)
        self.addCleanup(client.close)
        for path in ("/docs", "/openapi.json"):
            r = client.get(path)
            self.assertEqual((r.status_code, r.headers["location"]), (302, "/login"), path)
        client.cookies.set(auth.COOKIE, auth.issue("han", "viewer"))
        r = client.get("/docs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("swagger", r.text.lower())
        # 문서 화면은 CDN 스크립트를 쓰므로 켜졌을 때만 이 경로의 CSP 를 뺀다. 다른 헤더는 그대로다
        self.assertNotIn("content-security-policy", r.headers)
        self.assertEqual(r.headers["x-dns-prefetch-control"], "off")
        self.assertEqual(client.get("/openapi.json").json()["info"]["title"], "OpsLoop API")
        self.assertEqual(client.get("/redoc").status_code, 404)
        self.assertEqual(client.get("/login").headers["content-security-policy"], web.LOGIN_CSP)


class HealthTest(Base):
    def test_ws_prefix_paths_need_a_session(self):
        # /ws 만 세션 검사를 건너뛴다(웹소켓이 스스로 본다). /wsx · /ws-x/… 는 다른 화면 경로와 같다
        client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(client.close)
        for path in ("/wsx", "/ws-anything/incidents", "/wss"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 302)
        self.assertEqual(client.get("/api/wsx").status_code, 401)

    def test_health_shows_status_only_without_session(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200, "HAProxy option httpchk GET /health · expect status 200")
        self.assertEqual(r.json(), {"status": "ok"}, "실시간 접속 수 등 다른 값은 내지 않는다")


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
                self.assertEqual(r.headers.get("x-dns-prefetch-control"), "off")
                self.assertEqual(r.headers.get("cross-origin-opener-policy"), "same-origin")
                self.assertEqual(r.headers.get("cross-origin-resource-policy"), "same-origin")
                self.assertIn("camera=()", r.headers.get("permissions-policy", ""))


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
        with mock.patch.object(live, "CONSOLE_NAME", "opsloop-console-b"):
            r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"username": "kim", "role": "admin", "console": "opsloop-console-b"})
        # 콘솔 이름은 본문으로만 나간다. 응답 헤더로 내면 밖에서 콘솔을 가려내는 단서가 된다(이슈 #41)
        for name, value in r.headers.items():
            self.assertNotIn("console-b", value, name)

    def test_console_name_needs_session(self):
        with mock.patch.object(live, "CONSOLE_NAME", "opsloop-console-b"):
            for path in ("/api/me", "/health", "/login"):
                r = self.client.get(path)
                self.assertNotIn("opsloop-console-b", r.text, path)
                for name, value in r.headers.items():
                    self.assertNotIn("console-b", value, (path, name))

    def test_me_without_session(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json(), {"detail": "인증이 필요합니다"})

    def test_me_forged_session(self):
        token = auth.issue("han", "viewer")
        payload, _, sig = token.rpartition(".")
        self.client.cookies.set(auth.COOKIE, payload + "." + ("0" * len(sig)))
        self.assertEqual(self.client.get("/api/me").status_code, 401)


class WebSocketSessionTest(Base):
    """세션이 없는 웹소켓은 수락한 뒤 1008 로 닫는다. 수락 전에 닫으면 브라우저는 403 · 1006 만 받아 화면(live.ts)의
    1008 분기(로그인으로)가 돌지 않고 다시 잇기만 되풀이한다(2026-09-25 74분 · 403 292번)."""
    WS = {"origin": "http://testserver"}

    def assert_closed_1008_after_accept(self):
        # 수락 전에 닫히면 websocket_connect 가 들어가면서 끊김을 던진다. 수락 뒤라면 첫 수신에서 1008 을 받는다
        with self.client.websocket_connect("/ws", headers=self.WS) as ws:
            with self.assertRaises(WebSocketDisconnect) as caught:
                ws.receive_json()
        self.assertEqual(caught.exception.code, 1008)
        self.assertEqual(main.hub.clients, set(), "화면 목록에 넣지 않는다")

    def test_no_session(self):
        self.assert_closed_1008_after_accept()

    def test_forged_and_expired_session(self):
        token = auth.issue("han", "viewer")
        payload, _, sig = token.rpartition(".")
        self.client.cookies.set(auth.COOKIE, payload + "." + ("0" * len(sig)))
        self.assert_closed_1008_after_accept()
        with mock.patch.object(auth.time, "time", return_value=0):
            expired = auth.issue("han", "viewer")
        self.client.cookies.set(auth.COOKIE, expired)
        self.assert_closed_1008_after_accept()

    def test_hello_names_the_console(self):
        self.login_as()
        with mock.patch.object(live, "CONSOLE_NAME", "opsloop-console-a"):
            with self.client.websocket_connect("/ws", headers=self.WS) as ws:
                self.assertEqual(ws.receive_json(), {"type": "hello", "data": {"channel": "opsloop_incident",
                                                                             "console": "opsloop-console-a"}})


# ──────────────────────────────────────────────────────────────
#  5. 화면 서빙
# ──────────────────────────────────────────────────────────────
class ConsoleFilesTest(Base):
    def test_without_build_placeholder_stays(self):
        self.login_as()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("화면 구현 예정", r.text)
        # 인라인 스타일은 CSP 가 막으므로 쓰지 않는다
        self.assertNotIn("<style", r.text)
        self.assertNotIn("style=", r.text)
        self.assertEqual(self.client.get("/incidents").status_code, 404)
        self.assertEqual(self.client.get("/assets/index-abc123.js").status_code, 404)

    def test_screen_paths_get_index(self):
        self.build_console()
        self.login_as()
        for path in ("/", "/incidents", "/incidents/web-01:R002:1.2.3.4", "/accounts", "/inventory",
                     "/no/such/screen", "/index.html", "/apiary"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn('<div id="root">', r.text, path)
            self.assertEqual(r.headers["cache-control"], "no-cache", path)
            self.assertTrue(r.headers["content-type"].startswith("text/html"), path)
            self.assertEqual(r.headers["content-security-policy"], web.CSP, path)
        self.assertEqual(self.client.head("/incidents").status_code, 200)

    def test_screen_routes_do_not_collide_with_server_paths(self):
        """화면 라우터의 맨 위 경로가 서버 경로(SERVER_PATHS) 아래에 있으면 새로고침 · 새 탭에서 404 가 난다.

        이슈 #39 에서 자산 화면을 /assets 로 두었다가 번들 폴더(/assets)와 겹친 일이 있어 경로를 /inventory 로 바꿨다.
        """
        import re
        router = (Path(__file__).resolve().parent.parent / "console" / "src" / "app" / "router.tsx")
        if not router.exists():
            self.skipTest("console 소스가 없다")
        paths = re.findall(r"path: '([^':/][^']*)'", router.read_text(encoding="utf-8"))
        self.assertIn("inventory", paths)
        for p in paths:
            top = "/" + p.split("/")[0]
            self.assertFalse(web._under(top, web.SERVER_PATHS), top)

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
        self.assertEqual(r.json(), {"status": "ok"})
        r = self.client.get("/login")
        self.assertIn('action="/login"', r.text)
        # 문서 경로는 꺼져 있어도 화면(index.html)으로 빠지지 않는다
        for path in ("/docs", "/openapi.json"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 404, path)
            self.assertNotIn('<div id="root">', r.text, path)
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

    def test_nul_username_is_still_logged(self):
        """아이디의 NUL(%00)은 지우고 기록한다. 그대로 넣으면 INSERT 가 실패해 실패 기록이 빠진다."""
        r = self.post(username="ad\x00min", password="wrong")
        self.assertEqual(r.status_code, 401)
        (event,) = self.pool.events()
        self.assertEqual(event["eventid"], "console.login.failed")
        self.assertEqual(event["username"], "admin")
        # 화면 재표시는 이스케이프한다
        r = self.post(username='a\x00"><img src=//a.attacker.test/p.png>', password="wrong")
        self.assertNotIn("<img", r.text)
        self.assertIn("&quot;&gt;&lt;img", r.text)

    def test_log_event_clips_like_parser(self):
        request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.8", port=50000), method="POST",
                                  url=SimpleNamespace(path="/login" + "x" * 3000),
                                  headers={"user-agent": "Mozilla\x00" + "U" * 1000})
        asyncio.run(auth.log_event(self.pool, request, "console.login.failed",
                                   username="u\x00" + "n" * 400, status=401, session="s" * 300,
                                   message="m\x00" * 600))
        ((sql, args),) = self.pool.executed
        (line_hash, _ts, eventid, session, src_ip, _src_port, _dst_port, username,
         method, status, ua, url, message) = args
        self.assertEqual(eventid, "console.login.failed")
        self.assertEqual(username, "u" + "n" * 255)
        self.assertEqual(ua, "Mozilla" + "U" * 505)
        self.assertEqual((len(session), len(url), len(message)), (128, 2048, 512))
        for value in (session, username, method, ua, url, message):
            self.assertNotIn("\x00", value)
        self.assertEqual(auth.clip("a\ud800b", 10), "a?b")
        self.assertIsNone(auth.clip(None, 10))

    def test_authenticate_skips_db_for_nul(self):
        """계정 이름에 NUL 이 있으면 DB 에 묻지 않고 실패로 돌려준다(DB 오류로 500 · 기록 누락이 나지 않는다)."""
        class NulPool:
            def acquire(self):
                raise AssertionError("NUL 아이디로 DB 에 붙으면 안 된다")
        self.assertIsNone(asyncio.run(REAL_AUTHENTICATE(NulPool(), "ad\x00min", "pw")))

    def test_safe_next_unit(self):
        for good in ("/", "/incidents", "/incidents/a%2Fb?x=1#y", "/rules?v=2"):
            self.assertEqual(web.safe_next(good), good)
        for bad in (None, 3, "", "x", "//a", "/\\a", "http://a", "/login", "/logout/", "/\x7f"):
            self.assertEqual(web.safe_next(bad), "/", repr(bad))


# ──────────────────────────────────────────────────────────────
#  7. CSP 위반 보고
# ──────────────────────────────────────────────────────────────
class CspReportTest(Base):
    def setUp(self):
        super().setUp()
        web._csp_seen.clear()
        self.addCleanup(web._csp_seen.clear)

    def report(self, body, kind="application/csp-report", headers=None):
        out = io.StringIO()
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        with redirect_stdout(out):
            r = self.client.post("/api/csp-report", content=data,
                                 headers={"Content-Type": kind} | (headers or {}))
        return r, [line for line in out.getvalue().splitlines() if line.startswith("[csp]")]

    def test_formats(self):
        legacy = {"csp-report": {"document-uri": "http://192.168.70.254:8443/incidents/k1",
                                 "violated-directive": "img-src", "blocked-uri": "http://a.attacker.test/p.png",
                                 "source-file": "http://192.168.70.254:8443/assets/index.js", "line-number": 12,
                                 "original-policy": "x" * 100}}
        r, lines = self.report(legacy)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.content, b"")
        self.assertEqual(lines, ['[csp] 위반 보고 document-uri="http://192.168.70.254:8443/incidents/k1" '
                                 'violated-directive="img-src" blocked-uri="http://a.attacker.test/p.png" '
                                 'source-file="http://192.168.70.254:8443/assets/index.js" line=12'])
        reports = [{"type": "csp-violation", "url": "http://c/x", "body": {
            "documentURL": "http://c/incidents/k2", "effectiveDirective": "style-src-elem", "blockedURL": "inline",
            "lineNumber": 3}}, {"type": "csp-violation", "body": {"blockedURL": "eval"}}]
        r, lines = self.report(reports, "application/reports+json")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(len(lines), 2)
        self.assertIn('violated-directive="style-src-elem" blocked-uri="inline" source-file=- line=3', lines[0])
        self.assertIn("document-uri=- violated-directive=- blocked-uri=\"eval\"", lines[1])
        r, lines = self.report(legacy, "application/json; charset=utf-8")
        self.assertEqual((r.status_code, len(lines)), (204, 1))
        # 모르는 모양은 204 로 받고 남기지 않는다
        r, lines = self.report({"hello": "world"}, "application/json")
        self.assertEqual((r.status_code, lines), (204, []))

    def test_rejects_other_types_and_bad_bodies(self):
        for kind in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""):
            r, lines = self.report({"csp-report": {}}, kind)
            self.assertEqual((r.status_code, lines), (415, []), kind)
        r, lines = self.report("{not json", "application/json")
        self.assertEqual((r.status_code, lines), (400, []))
        r, lines = self.report(b"\xff\xfe", "application/json")
        self.assertEqual((r.status_code, lines), (400, []))
        # 8 KiB 안의 깊은 중첩. 파이썬 판에 따라 모르는 모양(204)이거나 거절(400)이다. 500 이 아니고 남기지 않는다
        r, lines = self.report("[" * 4000 + "]" * 4000, "application/json")
        self.assertIn(r.status_code, (204, 400))
        self.assertEqual(lines, [])

    def test_size_limit(self):
        body = json.dumps({"csp-report": {"blocked-uri": "x" * (8 * 1024)}})
        r, lines = self.report(body)
        self.assertEqual((r.status_code, lines), (413, []))
        # Content-Length 가 없어도(나눠 보내기) 읽는 중에 끊는다
        def chunks():
            for _ in range(20):
                yield b"x" * 1024
        with redirect_stdout(io.StringIO()):
            r = self.client.post("/api/csp-report", content=chunks(),
                                 headers={"Content-Type": "application/csp-report"})
        self.assertEqual(r.status_code, 413)
        ok = json.dumps({"csp-report": {"blocked-uri": "x" * 7000}})
        self.assertEqual(self.report(ok)[0].status_code, 204)

    def test_rate_limit(self):
        body = {"csp-report": {"blocked-uri": "inline"}}
        for n in range(60):
            self.assertEqual(self.report(body)[0].status_code, 204, n)
        r, lines = self.report(body)
        self.assertEqual((r.status_code, lines), (429, []))
        # 1분이 지나면 다시 받는다
        with mock.patch.object(web.time, "monotonic", return_value=web._csp_seen[-1] + 61):
            self.assertEqual(self.report(body)[0].status_code, 204)

    def test_rejected_reports_do_not_use_the_quota(self):
        # 형식 · 크기 · JSON 이 틀린 요청은 한도를 쓰지 않는다. 쓰레기 요청으로 진짜 보고를 밀어내지 못한다
        for _ in range(100):
            self.assertEqual(self.report("x", kind="text/plain")[0].status_code, 415)
            self.assertEqual(self.report("{", kind="application/json")[0].status_code, 400)
        self.assertEqual(len(web._csp_seen), 0)
        self.assertEqual(self.report({"csp-report": {"blocked-uri": "inline"}})[0].status_code, 204)

    def test_quota_counts_log_lines(self):
        # reports+json 한 요청이 여러 줄을 남기면 그 줄 수만큼 센다. 남은 한도만큼만 남기고, 다 쓰면 429
        many = [{"type": "csp-violation", "body": {"blockedURL": f"http://a.attacker.test/{i}"}} for i in range(10)]
        for n in range(6):
            r, lines = self.report(many, kind="application/reports+json")
            self.assertEqual((r.status_code, len(lines)), (204, 10), n)
        r, lines = self.report(many, kind="application/reports+json")
        self.assertEqual((r.status_code, lines), (429, []))

    def test_integer_line_is_bounded(self):
        r, (line,) = self.report({"csp-report": {"blocked-uri": "inline", "line-number": 10 ** 4000}})
        self.assertEqual(r.status_code, 204)
        self.assertLess(len(line), 600)
        self.assertEqual(self.report({"csp-report": {"line-number": 42}})[1], [
            "[csp] 위반 보고 document-uri=- violated-directive=- blocked-uri=- source-file=- line=42"])

    def test_log_line_is_one_clean_line(self):
        hostile = {"csp-report": {
            "document-uri": "http://c/incidents/admin\u202egnp.exe",
            "violated-directive": "img-src\n2026-09-18 15:00:00 decoy login.success",
            "blocked-uri": "http://a.attacker.test/\u200b\u2066x\u2069\ufeff\x1b[31m\x9b2K\U000E0041\r\n" + "y" * 5000,
            "source-file": "<svg onload=alert(1)>", "line-number": "12\n가짜"}}
        r, lines = self.report(hostile)
        self.assertEqual(r.status_code, 204)
        (line,) = lines
        for ch in ("\u202e", "\u200b", "\u2066", "\u2069", "\ufeff", "\x1b", "\x9b", "\U000E0041", "\r", "\n"):
            self.assertNotIn(ch, line, repr(ch))
        for mark in ("⟨U+202E⟩", "⟨U+200B⟩", "⟨U+2066⟩", "⟨U+2069⟩", "⟨U+FEFF⟩", "⟨U+001B⟩", "⟨U+009B⟩",
                     "⟨U+E0041⟩", "⟨U+000D⟩", "img-src↵2026-09-18"):
            self.assertIn(mark, line)
        self.assertIn('line="12↵가짜"', line)
        blocked = json.loads(re.search(r'blocked-uri=("(?:[^"\\]|\\.)*")', line).group(1))
        self.assertEqual(len(blocked), web.CSP_FIELD_MAX)
        self.assertTrue(blocked.endswith("…"))

    def test_entries_capped_per_request(self):
        reports = [{"type": "csp-violation", "body": {"blockedURL": f"inline-{n}"}} for n in range(50)]
        r, lines = self.report(reports, "application/reports+json")
        self.assertEqual((r.status_code, len(lines)), (204, web.CSP_REPORT_ENTRIES))

    def test_open_without_session_or_origin_only_here(self):
        """보고는 쿠키 · Origin 없이 온다. 출처 확인 예외는 POST /api/csp-report 하나뿐이다."""
        body = {"csp-report": {"blocked-uri": "inline"}}
        for headers in ({}, EVIL, {"Origin": "null"}):
            self.assertEqual(self.report(body, headers=headers)[0].status_code, 204, headers)
        self.login_as()
        for method, path in (("POST", "/api/csp-report/x"), ("POST", "/api/csp-reportx"), ("PUT", "/api/csp-report"),
                             ("DELETE", "/api/csp-report"), ("POST", "/api/incidents/k1/verdict")):
            with redirect_stdout(io.StringIO()):
                r = self.client.request(method, path, json=body, headers=EVIL)
            self.assertEqual(r.status_code, 403, (method, path))
        self.assertEqual(self.pool.executed, [], "보고는 DB 에 넣지 않는다")


# ──────────────────────────────────────────────────────────────
#  8. 로그인 기록의 출발지 (X-Forwarded-For)
# ──────────────────────────────────────────────────────────────
class ForwardedForTest(Base):
    """콘솔 컨테이너는 코드 변경 없이 uvicorn 의 ProxyHeadersMiddleware 로 X-Forwarded-For 를 읽는다(이슈 #43).
    compose 가 FORWARDED_ALLOW_IPS 로 HAProxy 주소(192.168.50.1)를 주고, HAProxy 는 받은 X-Forwarded-For 를 지우고
    제 것을 붙인다(option forwardfor). auth.log_event 는 request.client.host 를 쓰므로 기록의 src_ip 가 실제 주소가 된다.
    uvicorn 0.34 의 Config 가 환경변수를 읽어 앱을 감싸는 길을 그대로 쓴다(Dockerfile CMD 에 --forwarded-allow-ips 없음)."""
    PROXY = "192.168.50.1"

    def setUp(self):
        super().setUp()
        import uvicorn
        with mock.patch.dict(os.environ, {"FORWARDED_ALLOW_IPS": self.PROXY}):
            config = uvicorn.Config("main:app", proxy_headers=True)
            config.load()
        self.config = config

    def post_login(self, peer, headers, password="wrong"):
        import httpx
        transport = httpx.ASGITransport(app=self.config.loaded_app, client=(peer, 40000))

        async def go():
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.post("/login", data={"username": "han", "password": password},
                                         headers=SAME | headers)
        return asyncio.run(go())

    def login_from(self, peer, xff=None):
        r = self.post_login(peer, {"X-Forwarded-For": xff} if xff is not None else {})
        self.assertEqual(r.status_code, 401)
        (event,) = self.pool.events()
        self.pool.executed.clear()
        return event["src_ip"]

    def test_env_configures_trusted_proxy(self):
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
        self.assertEqual(self.config.forwarded_allow_ips, self.PROXY)
        self.assertIsInstance(self.config.loaded_app, ProxyHeadersMiddleware)
        self.assertIn(self.PROXY, self.config.loaded_app.trusted_hosts)
        self.assertNotIn("127.0.0.1", self.config.loaded_app.trusted_hosts)
        # 환경변수가 없으면 기본은 127.0.0.1 뿐이다(지금 운영: 기록이 모두 192.168.50.1)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FORWARDED_ALLOW_IPS", None)
            import uvicorn
            self.assertEqual(uvicorn.Config("main:app").forwarded_allow_ips, "127.0.0.1")

    def test_trusted_proxy_forwards_real_address(self):
        self.assertEqual(self.login_from(self.PROXY, "203.0.113.7"), "203.0.113.7")

    def test_untrusted_peer_header_is_ignored(self):
        self.assertEqual(self.login_from("198.51.100.9", "203.0.113.7"), "198.51.100.9")
        self.assertEqual(self.login_from("192.168.50.12", "203.0.113.7"), "192.168.50.12")

    def test_forged_left_value_is_ignored(self):
        # HAProxy 가 지우지 못한 위조 값이 앞에 남아도 오른쪽 끝(HAProxy 가 붙인 실제 값)을 쓴다
        self.assertEqual(self.login_from(self.PROXY, "10.9.9.9, 203.0.113.7"), "203.0.113.7")
        self.assertEqual(self.login_from(self.PROXY, "192.168.50.1, 203.0.113.7"), "203.0.113.7")

    def test_without_header_proxy_address_stays(self):
        self.assertEqual(self.login_from(self.PROXY), self.PROXY)

    def test_forwarded_proto_changes_nothing_visible(self):
        """믿는 프록시를 거친 X-Forwarded-Proto 도 uvicorn 이 믿는다(HAProxy 가 지우지 않으면 클라이언트 값). 앱은 요청의
        scheme 으로 주소 · 쿠키를 만들지 않으므로 로그인 동작이 그대로다. 이 가정이 깨지면 여기서 드러난다."""
        r = self.post_login(self.PROXY, {"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"},
                            password=PASSWORD)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["location"], "/")
        self.assertNotIn("secure", r.headers["set-cookie"].lower())
        (event,) = self.pool.events()
        self.assertEqual((event["eventid"], event["src_ip"]), ("console.login.success", "203.0.113.7"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
