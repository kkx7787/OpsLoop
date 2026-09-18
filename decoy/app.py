#!/usr/bin/env python3
"""
OpsLoop 웹 디코이 (WBS 3.2.1)

관문 뒤에 두는 미끼다. 목적은 방어가 아니라 관측이며, 관제 콘솔과 같은 형식의
인증 로그를 정상 트래픽이 없는 환경에서 얻는 것이다.

설계 원칙 (docs/2026-09-18-웹-디코이-설계.md)
  - 실제 기능을 제공하지 않는다. DB 에 연결하지 않고 파일을 저장하지 않는다.
  - 입력을 실행하지 않는다. 진단 화면은 정해진 문구만 돌려준다.
  - 업로드된 바이트는 해시만 계산하고 버린다. 검체 수집은 허니팟의 일이다.
  - 한 파일로 유지한다. 공격을 직접 받는 코드는 전부 읽어서 확인할 수 있어야 한다.
  - 로그는 Cowrie 와 같은 방식으로 남긴다. 날짜별 JSON 한 줄씩.

환경변수
  DECOY_LOG_DIR   로그 디렉터리 (기본 /var/log/decoy)
  DECOY_MAX_BODY  업로드에서 읽을 최대 바이트 (기본 10MB)
"""

import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

LOG_DIR = Path(os.environ.get("DECOY_LOG_DIR", "/var/log/decoy"))
MAX_BODY = int(os.environ.get("DECOY_MAX_BODY", 10 * 1024 * 1024))

# 통과시킬 자격증명. 로그인에서 막으면 문을 두드린 기록만 남고 들어온 뒤의 행위를
# 관측할 수 없다. 목록을 바꾸면 통과율이 바뀌므로 변경 시점을 문서에 남긴다.
# 최종 변경 2026-09-18 (최초 설정)
WEAK_CREDENTIALS = {
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("root", "toor"),
}

FILENAME_RE = re.compile(rb'filename="([^"]*)"')

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# ──────────────────────────────────────────────────────────────
#  기록
#
#  로그 파일이 원장이다. 기록 실패가 서비스 동작에 영향을 주면 안 되므로
#  예외를 삼키되, 무엇이 실패했는지는 표준 출력에 남긴다.
# ──────────────────────────────────────────────────────────────
def log_event(request: Request, eventid: str, **fields) -> None:
    now = datetime.now(timezone.utc)
    client = request.client
    record = {
        "ts": now.isoformat(),
        "eventid": eventid,
        "session": request.cookies.get("sid") or fields.pop("session", None),
        # 방화벽이 포트를 그대로 전달하므로 연결 주소가 공격자의 주소다.
        # 역방향 프록시를 두게 되면 전달 헤더의 신뢰 경계를 먼저 정해야 한다.
        "src_ip": client.host if client else None,
        "src_port": client.port if client else None,
        "dst_port": int(os.environ.get("DECOY_PORT", 8080)),
        "protocol": "http",
        "sensor": "decoy",
        "user_agent": request.headers.get("user-agent"),
        "url": str(request.url.path),
        "http_method": request.method,
    }
    record.update(fields)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        path = LOG_DIR / f"decoy.json.{now:%Y-%m-%d}"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"[decoy] 기록 실패: {exc}", flush=True)


@app.middleware("http")
async def record_request(request: Request, call_next):
    """모든 요청을 남긴다. 처음 보는 방문자에게는 세션을 부여한다.

    상태 확인 경로만 예외다. 우리가 거는 점검이 관측값에 섞이면 그만큼
    실측이 아닌 것이 분포에 들어간다.
    """
    if request.url.path == "/health":
        return await call_next(request)

    sid = request.cookies.get("sid")
    new_session = sid is None
    if new_session:
        sid = "d" + secrets.token_hex(8)
        request.scope["decoy_sid"] = sid
        # 쿠키가 아직 없으므로 log_event 가 읽지 못한다. 직접 넘긴다.
        log_event(request, "decoy.session.connect", session=sid)

    response = await call_next(request)

    request.scope.setdefault("decoy_sid", sid)
    log_event(request, "decoy.request", session=sid, http_status=response.status_code)
    if new_session:
        response.set_cookie("sid", sid, httponly=True, samesite="lax")
    return response


def authed(request: Request) -> bool:
    return request.cookies.get("auth") == "1"


# ──────────────────────────────────────────────────────────────
#  화면
#
#  특정 제품을 흉내 내지 않는다. 일반적인 관리 콘솔의 모양이면 충분하며,
#  알려진 제품 경로를 사칭하면 오히려 설명할 수 없는 문제가 생긴다.
# ──────────────────────────────────────────────────────────────
PAGE = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#f4f5f7;color:#232f3e;margin:0}}
 .wrap{{max-width:720px;margin:64px auto;background:#fff;border:1px solid #dfe3e8;padding:32px}}
 h1{{font-size:18px;margin:0 0 4px}} p.sub{{color:#6e7681;font-size:13px;margin:0 0 24px}}
 label{{display:block;font-size:13px;margin:12px 0 4px}}
 input[type=text],input[type=password]{{width:100%;padding:8px;border:1px solid #c9ced6;box-sizing:border-box}}
 button{{margin-top:16px;padding:8px 20px;background:#232f3e;color:#fff;border:0;cursor:pointer}}
 table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}}
 th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef1}}
 nav a{{font-size:13px;margin-right:16px;color:#147eba}}
 .err{{color:#dd3522;font-size:13px;margin-top:12px}}
</style></head><body><div class="wrap">{body}</div></body></html>
"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=title, body=body), status_code=status)


LOGIN_BODY = """
<h1>Server Admin</h1><p class="sub">관리자 계정으로 로그인하십시오.</p>
<form method="post" action="/admin/login">
  <label>아이디</label><input type="text" name="username" autocomplete="off">
  <label>비밀번호</label><input type="password" name="password">
  <button type="submit">로그인</button>
</form>{error}
"""

NAV = ('<nav><a href="/admin/dashboard">대시보드</a><a href="/admin/users">계정</a>'
       '<a href="/admin/files">파일</a><a href="/admin/tools">진단</a></nav>')


@app.get("/")
async def root():
    return RedirectResponse("/admin", status_code=302)


@app.get("/admin")
async def login_form():
    return page("로그인", LOGIN_BODY.format(error=""))


@app.post("/admin/login")
async def login(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))[:128]
    password = str(form.get("password", ""))[:128]

    if (username, password) in WEAK_CREDENTIALS:
        log_event(request, "decoy.login.success", username=username, password=password)
        response = RedirectResponse("/admin/dashboard", status_code=302)
        response.set_cookie("auth", "1", httponly=True, samesite="lax")
        return response

    log_event(request, "decoy.login.failed", username=username, password=password)
    return page("로그인", LOGIN_BODY.format(
        error='<p class="err">아이디 또는 비밀번호가 올바르지 않습니다.</p>'), status=401)


@app.get("/admin/dashboard")
async def dashboard(request: Request):
    if not authed(request):
        return RedirectResponse("/admin", status_code=302)
    log_event(request, "decoy.action.view")
    return page("대시보드", NAV + """
<h1>대시보드</h1><p class="sub">최근 24시간 요약</p>
<table><tr><th>항목</th><th>값</th></tr>
<tr><td>등록 계정</td><td>14</td></tr>
<tr><td>디스크 사용률</td><td>62%</td></tr>
<tr><td>대기 작업</td><td>3</td></tr></table>""")


@app.get("/admin/users")
async def users(request: Request):
    if not authed(request):
        return RedirectResponse("/admin", status_code=302)
    log_event(request, "decoy.action.view")
    rows = "".join(
        f"<tr><td>svc{i:02d}</td><td>운영</td><td>2026-09-{10 + i % 8:02d}</td></tr>"
        for i in range(1, 9))
    return page("계정", NAV + f"""
<h1>계정</h1><p class="sub">실제 사람의 정보는 담지 않는다</p>
<table><tr><th>계정</th><th>역할</th><th>최근 접속</th></tr>{rows}</table>""")


@app.get("/admin/files")
async def files_form(request: Request):
    if not authed(request):
        return RedirectResponse("/admin", status_code=302)
    log_event(request, "decoy.action.view")
    return page("파일", NAV + """
<h1>파일</h1><p class="sub">업로드된 파일은 저장되지 않는다</p>
<form method="post" action="/admin/files/upload" enctype="multipart/form-data">
  <input type="file" name="file"><button type="submit">업로드</button>
</form>""")


@app.post("/admin/files/upload")
async def upload(request: Request):
    """받은 바이트는 해시만 계산하고 버린다.

    다중 파트를 정식으로 해석하지 않는다. 해석기를 두면 그것이 곧 공격 표면이 되고,
    여기서 필요한 것은 파일 자체가 아니라 '무엇을 올리려 했는가'이기 때문이다.
    따라서 해시는 파일이 아니라 요청 본문의 해시이며, 허니팟이 수집한 검체 해시와
    직접 대조할 수 없다. 규칙이 쓰는 것은 시도 사실과 파일명, 크기다.
    """
    digest = hashlib.sha256()
    size = 0
    filename = None
    truncated = False

    async for chunk in request.stream():
        if filename is None:
            match = FILENAME_RE.search(chunk)
            if match:
                filename = match.group(1).decode("utf-8", "replace")[:256]
        remaining = MAX_BODY - size
        if remaining <= 0:
            truncated = True
            continue
        piece = chunk[:remaining]
        digest.update(piece)
        size += len(piece)

    log_event(request, "decoy.action.upload",
              shasum=digest.hexdigest(),
              input=f"filename={filename or '(불명)'} size={size}",
              message="본문 해시 · 잘림" if truncated else "본문 해시")
    return page("파일", NAV + """
<h1>파일</h1><p class="sub">업로드가 접수되었습니다. 처리까지 몇 분이 걸립니다.</p>""")


@app.get("/admin/tools")
async def tools_form(request: Request):
    if not authed(request):
        return RedirectResponse("/admin", status_code=302)
    log_event(request, "decoy.action.view")
    return page("진단", NAV + """
<h1>진단</h1><p class="sub">점검 명령을 입력하십시오</p>
<form method="post" action="/admin/tools/run">
  <label>명령</label><input type="text" name="command" autocomplete="off">
  <button type="submit">실행</button>
</form>""")


@app.post("/admin/tools/run")
async def tools_run(request: Request):
    """입력을 실행하지 않는다. 기록하고 정해진 문구만 돌려준다."""
    form = await request.form()
    command = str(form.get("command", ""))[:2048]
    log_event(request, "decoy.action.command", input=command)
    return page("진단", NAV + """
<h1>진단</h1><p class="sub">작업이 대기열에 등록되었습니다. 결과는 로그에서 확인하십시오.</p>""")


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    """알려진 제품 경로를 흉내 내지 않되, 탐색 행위는 남긴다.

    404 를 돌려주는 것만으로도 어떤 경로를 얼마나 두드렸는지가 기록되며,
    그것이 경로 탐색 규칙(R102)의 재료가 된다.
    """
    return page("찾을 수 없음", "<h1>404</h1><p class=\"sub\">요청한 경로가 없습니다.</p>", status=404)
