"""
콘솔 웹 계층 (WBS 3.6.1 · 이슈 #7)

화면 번들 서빙 · 보안 헤더 · 출처 확인 · 로그인 화면을 이곳에 모은다. main.py 는 부르기만 한다.

  serve(app)  화면 번들 · /api/me · /api/csp-report. 세션 검사(main.require_session)보다 먼저 붙여 그 안쪽에 둔다.
              화면 번들도 로그인 뒤에만 나간다. 위반 보고만 세션 없이 받는다(main.OPEN_PATHS).
  guard(app)  보안 헤더 · CORS(설정 시) · 출처 확인. 세션 검사보다 나중에 붙여 그 바깥에 둔다.

미들웨어는 나중에 붙인 것이 바깥에 선다. 요청은 바깥부터 거친다.
  보안 헤더 → CORS(설정 시) → 출처 확인 → 세션 검사 → 화면 번들 → 경로

화면은 API 와 같은 출처로 나간다(HAProxy :8443 → 콘솔 A · B :8000). 그래서 CORS 는 기본으로 끄고,
상태를 바꾸는 요청은 출처가 같을 때만 받는다. 쿠키의 SameSite=Lax 는 같은 사이트의 다른 포트
(같은 방화벽 주소의 다른 포트)에서 오는 요청까지는 막지 못한다. 주소가 IP 이면 포트만 달라도 같은 사이트다.
"""

import base64
import hashlib
import html
import json
import mimetypes
import os
import time
from collections import deque
from pathlib import Path
from string import Template
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.datastructures import Headers, MutableHeaders
from starlette.websockets import WebSocketClose

from untrusted import reveal

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
#  공격자 문자열이 화면에 섞여 들어와도 담당자 브라우저가 밖으로 요청하지 않게 하는 두 번째 방어선이다(이슈 #41).
#  서버에는 인터넷이 없지만 담당자 단말(관리망 · VPN)은 인터넷에 닿는다. 브라우저 쪽 방어는 CSP 와 화면 렌더가 전부다.
#  위반은 같은 출처의 /api/csp-report 로만 보고한다. 외부 수집 서비스로 보내면 그 자체가 콘솔을 드러내는 경로가 된다.
CSP_REPORT_PATH = "/api/csp-report"


def _csp(style: str) -> str:
    return "; ".join([
        "default-src 'self'",
        # 인라인 스크립트를 막는다. 화면 번들은 파일로만 나가고 로그인 화면은 스크립트가 없다.
        "script-src 'self'",
        # 화면 번들은 CSS 파일과 CSSOM(style 속성 설정)만 쓴다. 주입된 <style> · style 속성으로 버튼을 가리는
        # 표시 위조를 막는다. 로그인 화면의 <style> 하나만 그 응답에 해시로 연다(LOGIN_CSP).
        f"style-src {style}",
        # data: 이미지는 번들이 쓰지 않는다. 주입된 가짜 경고 그림을 막는다.
        "img-src 'self'",
        "connect-src 'self'",
        # 외부 글꼴을 쓰지 않는다.
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        # 위반 보고. report-to 는 넣지 않는다. report-to 가 있으면 Chrome 은 report-uri 를 무시하는데,
        # Reporting-Endpoints 는 보안 문맥(https · localhost)에서만 받으므로 평문 HTTP 콘솔(:8443)에서는 보고가 하나도
        # 나가지 않는다(2026-09-25 Chromium 에서 확인). 콘솔을 https 로 옮기면 report-to 와 Reporting-Endpoints 를 더한다.
        f"report-uri {CSP_REPORT_PATH}",
    ])


CSP = _csp("'self'")

BASE_HEADERS = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "same-origin"),
    # 링크 · link 요소의 호스트 이름을 미리 조회하지 않는다. DNS 조회는 CSP 로 막히지 않고,
    # 공격자 호스트가 그려지면 열람만으로 공격자 DNS 에 시각이 찍힌다. 콘솔은 평문 HTTP 라 기본으로 켜진다.
    ("x-dns-prefetch-control", "off"),
    ("cross-origin-opener-policy", "same-origin"),
    # 같은 사이트의 다른 포트에서 /api 응답을 끼워 넣지 못하게 한다.
    ("cross-origin-resource-policy", "same-origin"),
    ("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()"),
)


class SecurityHeaders:
    """모든 HTTP 응답에 보안 헤더를 붙인다. 응답이 이미 정한 값은 덮지 않는다.

    docs_paths 는 API 문서 화면(OPSLOOP_API_DOCS=1 일 때만 켜짐)의 경로다. Swagger UI 는 CDN 스크립트와
    인라인 스크립트를 쓰므로 이 경로만 CSP 를 뺀다. 문서가 꺼져 있으면 비어 있어 모든 응답에 CSP 가 붙는다.
    """

    def __init__(self, app, docs_paths=()):
        self.app = app
        self.docs_paths = tuple(docs_paths)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        extra = list(BASE_HEADERS)
        if not _under(path, self.docs_paths):
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
    """POST · PUT · PATCH · DELETE 와 웹소켓 핸드셰이크의 출처를 본다. /login · /logout 도 포함한다.

    예외는 POST /api/csp-report 하나뿐이다. 브라우저가 보내는 위반 보고에는 Origin · 쿠키가 없을 수 있다.
    이 경로는 상태를 바꾸지 않고 로그 한 줄만 남긴다(크기 · 빈도 상한).
    """

    def __init__(self, app, trusted=frozenset()):
        self.app = app
        self.trusted = frozenset(trusted)

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        exempt = kind == "http" and scope["method"] == "POST" and scope["path"] == CSP_REPORT_PATH
        if not exempt and (kind == "websocket" or (kind == "http" and scope["method"] in UNSAFE_METHODS)):
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
    # 문서 화면이 켜진 앱(main 은 OPSLOOP_API_DOCS=1 일 때만)에서만 그 경로의 CSP 를 뺀다.
    docs = tuple(p for p in (getattr(app, name, None) for name in ("docs_url", "redoc_url", "openapi_url")) if p)
    app.add_middleware(SecurityHeaders, docs_paths=docs)
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


# ──────────────────────────────────────────────────────────────
#  CSP 위반 보고 수집 (이슈 #41)
#
#  세션 없이 받는다(main.OPEN_PATHS). 출처 확인도 이 경로만 건너뛴다(OriginCheck).
#  보고에는 공격자가 넣은 주소가 들어 있다. 필요한 필드만 숨은 문자를 표식으로 바꾸고 잘라 한 줄로 남긴다(도커 로그).
#  DB 에는 넣지 않는다. 받는 형식 · 크기 · 빈도를 묶어 로그 넘치기를 막는다.
# ──────────────────────────────────────────────────────────────
CSP_REPORT_TYPES = frozenset({"application/csp-report", "application/reports+json", "application/json"})
CSP_REPORT_MAX = 8 * 1024        # 본문 상한(바이트)
CSP_REPORT_PER_MINUTE = 60       # 프로세스 전체에서 1분에 남기는 보고 줄 수. 넘치면 429
CSP_REPORT_ENTRIES = 10          # 요청 하나에서 남기는 보고 수(reports+json 은 여러 건을 묶어 보낸다)
CSP_FIELD_MAX = 200              # 필드 하나의 글자 수(표식으로 바꾼 뒤)
_csp_seen = deque()


def _csp_take(now: float, n: int) -> int:
    """지난 60초 안에 남긴 줄 수가 상한 아래면 이번 요청에서 남길 줄 수(최대 n)를 세고 돌려준다. 0 이면 한도가 찼다.
    형식 · 크기를 통과한 보고만 센다. 쓰레기 요청으로 한도를 채워 진짜 보고를 밀어내지 못하게 한다."""
    while _csp_seen and now - _csp_seen[0] >= 60:
        _csp_seen.popleft()
    take = min(n, CSP_REPORT_PER_MINUTE - len(_csp_seen))
    _csp_seen.extend([now] * max(take, 0))
    return max(take, 0)


def csp_entries(data) -> list:
    """application/csp-report({"csp-report": …})와 Reporting API([{"type": "csp-violation", "body": …}])를
    같은 필드(document-uri · violated-directive · blocked-uri · source-file · line)로 푼다. 다른 모양은 버린다."""
    out = []
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("csp-report"), dict):
            r = item["csp-report"]
            out.append({"document-uri": r.get("document-uri"),
                        "violated-directive": r.get("violated-directive") or r.get("effective-directive"),
                        "blocked-uri": r.get("blocked-uri"), "source-file": r.get("source-file"),
                        "line": r.get("line-number")})
        elif isinstance(item.get("body"), dict):
            b = item["body"]
            out.append({"document-uri": b.get("documentURL") or item.get("url"),
                        "violated-directive": b.get("effectiveDirective") or b.get("violatedDirective"),
                        "blocked-uri": b.get("blockedURL"), "source-file": b.get("sourceFile"),
                        "line": b.get("lineNumber")})
    return out[:CSP_REPORT_ENTRIES]


def csp_log_line(entry: dict) -> str:
    """보고 한 건을 한 줄로 쓴다. 값은 숨은 문자 · 줄바꿈을 표식으로 바꾸고 자른 뒤 따옴표로 감싼다."""
    parts = []
    for name in ("document-uri", "violated-directive", "blocked-uri", "source-file", "line"):
        value = entry.get(name)
        if value is None or value == "":
            parts.append(f"{name}=-")
        elif name == "line" and isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10 ** 7:
            parts.append(f"{name}={value}")
        else:
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            parts.append(f"{name}={json.dumps(reveal(text, limit=CSP_FIELD_MAX), ensure_ascii=False)}")
    return "[csp] 위반 보고 " + " ".join(parts)


def _report_error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


@router.post(CSP_REPORT_PATH, status_code=204)
async def csp_report(request: Request):
    kind = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if kind not in CSP_REPORT_TYPES:
        return _report_error(415, "위반 보고 형식이 아닙니다")
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > CSP_REPORT_MAX:
        return _report_error(413, "위반 보고가 너무 큽니다")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > CSP_REPORT_MAX:
            return _report_error(413, "위반 보고가 너무 큽니다")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):   # 깨진 JSON · 글자 부호 · 8 KiB 안의 깊은 중첩
        return _report_error(400, "위반 보고를 해석할 수 없습니다")
    entries = csp_entries(data)
    take = _csp_take(time.monotonic(), len(entries)) if entries else 0
    if entries and take == 0:
        return _report_error(429, "위반 보고가 너무 많습니다")
    for entry in entries[:take]:
        print(csp_log_line(entry), flush=True)
    return Response(status_code=204)


def serve(app) -> None:
    """화면 번들과 /api/me · /api/csp-report 를 붙인다. 세션 검사 미들웨어보다 먼저 불러 그 안쪽에 둔다."""
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
#  서버가 그린다. 모양은 와이어프레임 Login 을 따른다. 스크립트가 없고 스타일은 <style> 하나다.
#  그 <style> 만 이 응답의 CSP 에 해시로 연다(LOGIN_CSP). 스타일을 고치면 해시는 모듈을 읽을 때 다시 계산된다.
#  style= 속성은 쓰지 않는다('unsafe-hashes' 없이 막힌다).
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

LOGIN_STYLE = LOGIN_PAGE.template.split("<style>", 1)[1].split("</style>", 1)[0]
# 치환이 스타일을 바꾸면 해시가 어긋나 로그인 화면이 모양 없이 나온다.
assert "$" not in LOGIN_STYLE, "로그인 화면 <style> 에 치환 자리가 있으면 해시가 어긋난다"
LOGIN_STYLE_HASH = base64.b64encode(hashlib.sha256(LOGIN_STYLE.encode("utf-8")).digest()).decode()
LOGIN_CSP = _csp(f"'self' 'sha256-{LOGIN_STYLE_HASH}'")


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
    return HTMLResponse(body, status_code=status_code,
                        headers={"Cache-Control": "no-store", "Content-Security-Policy": LOGIN_CSP})
