"""
콘솔 웹 계층 (WBS 3.6.1 · 이슈 #7)

화면 번들 서빙 · 보안 헤더 · 출처 확인 · 로그인 화면을 이곳에 모은다. main.py 는 부르기만 한다.

  serve(app)  화면 번들과 /api/me. 세션 검사(main.require_session)보다 먼저 붙여 그 안쪽에 둔다.
              화면 번들도 로그인 뒤에만 나간다.
  guard(app)  보안 헤더 · CORS(설정 시) · 출처 확인. 세션 검사보다 나중에 붙여 그 바깥에 둔다.

미들웨어는 나중에 붙인 것이 바깥에 선다. 요청은 바깥부터 거친다.
  보안 헤더 → CORS(설정 시) → 출처 확인 → 세션 검사 → 화면 번들 → 경로

화면은 API 와 같은 출처로 나간다(HAProxy :8443 → 콘솔 A · B :8000). 그래서 CORS 는 기본으로 끄고,
상태를 바꾸는 요청은 출처가 같을 때만 받는다. 쿠키의 SameSite=Lax 는 같은 사이트의 다른 포트
(같은 방화벽 주소의 :8404 같은 곳)에서 오는 요청까지는 막지 못한다. 주소가 IP 이면 포트만 달라도 같은 사이트다.
"""

import html
import mimetypes
import os
from pathlib import Path
from string import Template
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.websockets import WebSocketClose

# 화면 빌드 결과. Mac 에서 console/ 의 npm run build 가 만든다. git 에는 넣지 않는다.
# 없으면 main.py 의 자리표시 화면이 그대로 나온다. 요청마다 보므로 시험에서 바꿔 끼울 수 있다.
STATIC_DIR = Path(__file__).resolve().parent / "static"

# 서버가 답하는 경로. 이 밖의 GET 은 화면 경로로 보고 index.html 을 준다.
SERVER_PATHS = ("/api", "/ws", "/login", "/logout", "/docs", "/redoc",
                "/openapi.json", "/health", "/assets")


def _under(path: str, prefixes) -> bool:
    """path 가 prefixes 중 하나이거나 그 아래인가. /api 는 /api/x 를 품지만 /apiary 는 품지 않는다."""
    return any(path == p or path.startswith(p + "/") for p in prefixes)


# ──────────────────────────────────────────────────────────────
#  보안 헤더
# ──────────────────────────────────────────────────────────────
CSP = "; ".join([
    "default-src 'self'",
    # 인라인 스크립트를 막는다. 화면 번들은 파일로만 나가고 로그인 화면은 스크립트가 없다.
    "script-src 'self'",
    # 스크립트는 막고 스타일만 연다. 로그인 화면과 화면 라이브러리가 인라인 스타일을 쓴다.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    # 내부망에는 인터넷이 없다. 외부 글꼴을 쓰지 않는다.
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

BASE_HEADERS = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "same-origin"),
)

# Swagger UI · ReDoc 은 CDN 스크립트와 인라인 스크립트를 쓴다. 이 경로만 CSP 를 뺀다.
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeaders:
    """모든 HTTP 응답에 보안 헤더를 붙인다. 응답이 이미 정한 값은 덮지 않는다."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        extra = list(BASE_HEADERS)
        if not _under(path, DOCS_PATHS):
            extra.append(("content-security-policy", CSP))
        # 판정 · 조치 기록이 공용 PC 의 캐시에 남지 않게 한다.
        if _under(path, ("/api",)):
            extra.append(("cache-control", "no-store"))

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in extra:
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ──────────────────────────────────────────────────────────────
#  출처 확인 (CSRF · 교차 사이트 웹소켓 탈취)
#
#  상태를 바꾸는 요청과 웹소켓 핸드셰이크는 Origin(없으면 Referer)이 요청의 Host 와 같거나
#  신뢰 목록에 있어야 한다. 둘 다 없으면 거부한다. 브라우저는 같은 출처의 POST 에도 Origin 을 붙인다.
#
#  Host 와 비교할 때 scheme 은 보지 않는다. 앞단에서 TLS 를 끝내면 콘솔이 받는 요청은 http 인데
#  브라우저의 출처는 https 이기 때문이다. 대신 Host 에 포트가 없으면 출처 scheme 의 기본 포트여야 한다.
#  신뢰 목록(TRUSTED_ORIGINS)은 scheme 까지 맞춘다.
# ──────────────────────────────────────────────────────────────
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DEFAULT_PORT = {"http": 80, "https": 443}


def parse_origin(value):
    """'scheme://host[:port]' 를 (scheme, host, port) 로 푼다. 풀 수 없으면 None. 'null' 도 None."""
    try:
        parts = urlsplit(str(value).strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORT or not parts.hostname:
        return None
    return scheme, parts.hostname.lower(), port or DEFAULT_PORT[scheme]


def _parse_host(value):
    """Host 머리글을 (host, port) 로 푼다. 포트가 없으면 port 는 None."""
    value = (value or "").strip()
    if not value or any(c in value for c in "/@?#\\"):
        return None
    try:
        parts = urlsplit("//" + value)
        port = parts.port
    except ValueError:
        return None
    if not parts.hostname:
        return None
    return parts.hostname.lower(), port


def origin_problem(headers: Headers, trusted=frozenset()):
    """출처가 맞으면 None, 아니면 거부 사유를 돌려준다."""
    raw = headers.get("origin") or headers.get("referer")
    if not raw:
        return "출처(Origin · Referer)가 없는 요청은 받지 않습니다"
    origin = parse_origin(raw)
    if origin is None:
        return "출처를 확인할 수 없는 요청은 받지 않습니다"
    if origin in trusted:
        return None
    host = _parse_host(headers.get("host"))
    if host is not None:
        scheme, name, port = origin
        if name == host[0] and port == (host[1] or DEFAULT_PORT[scheme]):
            return None
    return "다른 출처에서 온 요청은 받지 않습니다"


class OriginCheck:
    """POST · PUT · PATCH · DELETE 와 웹소켓 핸드셰이크의 출처를 본다. /login · /logout 도 포함한다."""

    def __init__(self, app, trusted=frozenset()):
        self.app = app
        self.trusted = frozenset(trusted)

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind == "websocket" or (kind == "http" and scope["method"] in UNSAFE_METHODS):
            headers = Headers(scope=scope)
            problem = origin_problem(headers, self.trusted)
            if problem:
                # 설정이 틀려 정상 요청이 막힐 때 원인을 찾을 수 있게 남긴다.
                seen = (headers.get("origin") or headers.get("referer") or "-")[:120]
                print(f"[web] 출처 거부: {scope.get('method', 'WS')} {scope['path'][:120]} "
                      f"출처={seen!r} host={headers.get('host', '-')[:80]!r}", flush=True)
                if kind == "websocket":
                    # 수락 전에 닫으면 핸드셰이크가 403 으로 끝난다.
                    await WebSocketClose(code=1008)(scope, receive, send)
                else:
                    await JSONResponse({"detail": problem}, status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _env_origins(name: str) -> list:
    return [o.strip().rstrip("/") for o in os.environ.get(name, "").split(",") if o.strip()]


def _server_error(request: Request, exc: Exception) -> JSONResponse:
    """처리되지 않은 예외의 500. Starlette 는 이 처리기를 ServerErrorMiddleware(사용자 미들웨어 바깥)에 넘기므로
    SecurityHeaders 를 지나지 않는다. 그래서 여기서 헤더를 직접 붙인다. 예외는 미들웨어가 다시 던져 기록된다."""
    headers = dict(BASE_HEADERS) | {"content-security-policy": CSP}
    if _under(request.url.path, ("/api",)):
        headers["cache-control"] = "no-store"
    return JSONResponse({"detail": "서버 오류"}, status_code=500, headers=headers)


def guard(app) -> None:
    """보안 헤더 · CORS · 출처 확인을 붙인다. 세션 검사 미들웨어를 붙인 뒤에 불러 그 바깥에 둔다.
    첫 요청 전에 불러야 한다. 미들웨어 스택과 500 처리기는 첫 요청 때 굳는다.

    CORS 는 CORS_ORIGINS 가 있을 때만 건다. 개발은 Vite 프록시로 같은 출처를 만든다.
    CORS 로 자격 증명까지 허락한 출처는 응답을 읽을 수도 있으므로 상태 변경 요청의 신뢰 출처에도 넣는다.
    """
    cors = _env_origins("CORS_ORIGINS")
    trusted = set()
    for value in _env_origins("TRUSTED_ORIGINS") + cors:
        origin = parse_origin(value)
        if origin is None:
            print(f"[web] 출처 설정을 해석하지 못해 뺍니다 (scheme://host[:port] 형식): {value!r}",
                  flush=True)
            continue
        trusted.add(origin)

    app.add_middleware(OriginCheck, trusted=trusted)
    if cors:
        app.add_middleware(CORSMiddleware, allow_origins=cors, allow_credentials=True,
                           allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(SecurityHeaders)
    app.add_exception_handler(Exception, _server_error)


# ──────────────────────────────────────────────────────────────
#  화면 번들
#
#  index.html 은 매번 확인하게(no-cache) 하고, 이름에 해시가 붙은 /assets 는 오래 둔다.
#  배포 직후에도 새 index.html 이 새 번들 이름을 가리키므로 옛 번들이 남지 않는다.
# ──────────────────────────────────────────────────────────────
ASSET_CACHE = "private, max-age=31536000, immutable"
INDEX_CACHE = "no-cache"

# 컨테이너(python:3.12-slim)에는 /etc/mime.types 가 없을 수 있다. nosniff 아래에서 형식이
# 틀리면 브라우저가 스크립트를 버리므로 번들에 나오는 형식은 직접 정한다.
CONTENT_TYPES = {
    ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
    ".html": "text/html", ".json": "application/json", ".map": "application/json",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".webp": "image/webp", ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
    ".txt": "text/plain",
}


def _file_in(base: Path, rel: str):
    """base 안의 파일이면 그 경로, 아니면 None. ../ 나 링크로 폴더 밖에 나가는 것은 내주지 않는다."""
    if not rel or "\x00" in rel or "\\" in rel:
        return None
    try:
        root = base.resolve()
        target = (root / rel).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    if root not in target.parents or not target.is_file():
        return None
    return target


def _file_response(path: Path, cache: str) -> FileResponse:
    kind = (CONTENT_TYPES.get(path.suffix.lower())
            or mimetypes.guess_type(path.name)[0] or "application/octet-stream")
    return FileResponse(path, media_type=kind, headers={"Cache-Control": cache})


def has_console() -> bool:
    return (STATIC_DIR / "index.html").is_file()


def console_response(path: str):
    """GET · HEAD 요청에 화면 번들로 답할 것이 있으면 응답을, 없으면 None 을 돌려준다."""
    if not has_console():
        return None
    if path.startswith("/assets/"):
        found = _file_in(STATIC_DIR / "assets", path[len("/assets/"):])
        return _file_response(found, ASSET_CACHE) if found else None
    if _under(path, SERVER_PATHS):
        return None
    # 번들 바깥 맨 위의 파일(favicon 등)은 그대로 준다. 나머지는 화면 경로다.
    name = path[1:]
    if name and "/" not in name and name != "index.html":
        found = _file_in(STATIC_DIR, name)
        if found:
            return _file_response(found, INDEX_CACHE)
    return _file_response(STATIC_DIR / "index.html", INDEX_CACHE)


class ConsoleFiles:
    """화면 번들을 내준다. 세션 검사 안쪽에 있으므로 여기까지 온 요청은 로그인된 요청이다."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] in ("GET", "HEAD"):
            response = console_response(scope["path"])
            if response is not None:
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


router = APIRouter()


@router.get("/api/me")
async def me(request: Request):
    """화면이 처음 부르는 곳. 누가 어떤 역할로 들어왔는지 돌려준다. 세션은 인증 미들웨어가 채운다."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="인증이 필요합니다")
    return {"username": user["u"], "role": user["r"]}


def serve(app) -> None:
    """화면 번들과 /api/me 를 붙인다. 세션 검사 미들웨어보다 먼저 불러 그 안쪽에 둔다."""
    app.include_router(router)
    app.add_middleware(ConsoleFiles)


# ──────────────────────────────────────────────────────────────
#  로그인 뒤 돌아갈 곳
#
#  같은 출처의 상대 경로만 받는다. //evil.example · /\evil.example · https://… 는 모두 / 로 바꾼다.
#  브라우저는 경로 안의 \ 를 / 로 읽고 탭 · 줄바꿈을 지우므로 둘 다 받지 않는다.
# ──────────────────────────────────────────────────────────────
NEXT_MAX = 2048


def safe_next(value) -> str:
    if not isinstance(value, str) or not value or len(value) > NEXT_MAX:
        return "/"
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if any(c == "\\" or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    # 로그인 · 로그아웃으로 돌아가면 제자리를 돈다.
    if _under(parts.path, ("/login", "/logout")):
        return "/"
    return value


def to_login(request: Request) -> RedirectResponse:
    """로그인으로 보낸다. 화면을 열던 GET 이면 돌아올 곳(next)을 붙인다. 알림의 인시던트 링크가 이 길로 온다."""
    target = "/login"
    path = request.url.path
    if request.method in ("GET", "HEAD") and path != "/" and not _under(path, SERVER_PATHS):
        raw = request.scope.get("raw_path")
        here = raw.decode("utf-8", "replace") if raw else path
        if request.url.query:
            here += "?" + request.url.query
        if safe_next(here) == here:
            target += "?" + urlencode({"next": here})
    return RedirectResponse(target, status_code=302)


# ──────────────────────────────────────────────────────────────
#  로그인 화면 (S-01)
#
#  서버가 그린다. 모양은 와이어프레임 Login 을 따른다. 스크립트가 없고 스타일은 인라인이다(CSP).
#  필드 이름(username · password)과 기록(console.login.*)은 바꾸지 않는다. next 만 숨은 필드로 더한다.
# ──────────────────────────────────────────────────────────────
LOGIN_ERROR = "아이디 또는 비밀번호가 올바르지 않습니다."

LOGIN_PAGE = Template("""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>로그인 · OpsLoop 관제</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px 16px;
 font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",system-ui,sans-serif;
 color:#1d1d1f;background:#f5f5f7;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:380px;display:flex;flex-direction:column;gap:24px}
.head{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center}
.mark{width:56px;height:56px;border-radius:14px;background:#0164b2;display:flex;align-items:center;justify-content:center;margin-bottom:10px}
h1{margin:0;font-size:30px;font-weight:700;letter-spacing:-0.025em}
.sub{margin:0;font-size:14px;color:#6e6e73}
form{background:#ffffff;border-radius:18px;box-shadow:0 0 0 .5px rgba(0,0,0,.06),0 2px 8px rgba(0,0,0,.04);padding:28px;display:flex;flex-direction:column;gap:16px}
label{display:flex;flex-direction:column;gap:6px;font-size:13px}
input{height:40px;border:0;box-shadow:0 0 0 .5px rgba(0,0,0,.16);border-radius:10px;padding:0 12px;font-size:14px;font-family:inherit;color:inherit;background:#ffffff}
input:focus{outline:2px solid #0164b2;outline-offset:1px}
.err{margin:0;font-size:13px;color:#d70015;background:#fff1f0;border-radius:10px;padding:10px 12px}
button{height:44px;border:0;border-radius:10px;background:#0164b2;color:#ffffff;font-size:14px;font-weight:500;font-family:inherit;cursor:pointer}
button:hover{background:#01518f}
button:focus-visible{outline:2px solid #01518f;outline-offset:2px}
.note{margin:0;font-size:12px;line-height:20px;text-align:center;color:#6e6e73}
@media (max-width:420px){h1{font-size:24px}form{padding:20px}}
</style></head>
<body><main>
<div class="head">
<span class="mark" aria-hidden="true"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 12a7.5 7.5 0 0 1 13.2-4.9M19.5 12a7.5 7.5 0 0 1-13.2 4.9"></path><path d="M18 3.5v4h-4M6 20.5v-4h4"></path></svg></span>
<h1>OpsLoop 관제 콘솔</h1>
<p class="sub">판정과 조치는 계정에 기록됩니다.</p>
</div>
<form method="post" action="/login">
<label for="username">아이디<input id="username" name="username" type="text" value="$username" autocomplete="username" autocapitalize="off" spellcheck="false"$user_focus></label>
<label for="password">비밀번호<input id="password" name="password" type="password" autocomplete="current-password"$password_focus></label>
$error<input type="hidden" name="next" value="$next">
<button type="submit">로그인</button>
</form>
<p class="note">가입 화면은 없습니다. 계정은 관리자가 명령줄로 발급합니다.<br>로그인 시도는 디코이와 같은 형식으로 기록되어 규칙 검증에 쓰입니다.</p>
</main></body></html>""")


def login_page(*, error: bool = False, next_path=None, username: str = "",
               status_code: int = 200) -> HTMLResponse:
    """로그인 화면. 실패하면 아이디를 남기고 비밀번호 칸에 초점을 둔다."""
    username = username or ""
    body = LOGIN_PAGE.substitute(
        username=html.escape(username, quote=True),
        next=html.escape(safe_next(next_path), quote=True),
        error=f'<p class="err" role="alert">{LOGIN_ERROR}</p>\n' if error else "",
        user_focus="" if username else " autofocus",
        password_focus=" autofocus" if username else "",
    )
    return HTMLResponse(body, status_code=status_code, headers={"Cache-Control": "no-store"})
