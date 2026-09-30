"""
OpsLoop API (WBS 3.1)

관제 콘솔이 붙는 지점. 폐루프의 각 단계가 엔드포인트로 드러난다.

  탐지 →  GET  /api/incidents
  통보 →  WS   /ws                      (PostgreSQL LISTEN/NOTIFY)
  조치 →  POST /api/incidents/{key}/actions
  판정 →  POST /api/incidents/{key}/verdict
  환류 →  GET  /api/rules/quality        (오탐률·비조치율)

실시간 통보에 별도 메시지 브로커를 두지 않고 PostgreSQL LISTEN/NOTIFY 를 쓴다.
운영할 구성요소가 하나 줄고, 알림이 데이터와 같은 트랜잭션에서 발생해
"저장은 됐는데 알림은 안 갔다"는 구간이 생기지 않는다. 판정 · 조치 통보도 같은 길로 보내
두 콘솔의 화면이 모두 받는다. 듣기 · 다시 붙기 · 화면 목록은 live.py 에 있다(이슈 #43).
"""

import asyncio
import html
import ipaddress
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal, Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

import auth
import block_points
import cti
import node_logs
import targets
import web
from proposals import CIRCULAR_RULES, SSH_RULES, propose
from dashboard import HUMAN_UNDETERMINED, dashboard_metrics
from access import masked_validation, require_role
from operations import router as operations_router
from notify import router as notify_router
from cti import router as cti_router
from targets import router as targets_router
from node_logs import router as node_logs_router
from sources import router as sources_router
from reports import router as reports_router
from accounts import router as accounts_router
from notifier import Notifier
import live
from live import EVENT_CHANNEL, INCIDENT_CHANNEL, Listener, event_payload, hub
from absorbed import (ABSORBED_STATE_SQL, FOLLOW_RELEASE_SQL, FOLLOW_STATE_SQL, FOLLOW_UPSERT_SQL,
                      RELEASE_ABSORBED_SQL, UNBLOCKED_AFTER_VERDICT_SQL, AbsorbedFollower, absorbed_note,
                      absorbed_reason_tag, block_absorbed, block_nets, exempt_of, is_refused, refused_text)

DATABASE_URL = os.environ.get("DATABASE_URL")
NOTIFY_CHANNEL = INCIDENT_CHANNEL

ACTIONS = Literal["block_ip", "unblock_ip", "acknowledge", "suppress_rule", "escalate", "note"]
# 판정값 다섯 개. 정확히 탐지했으나 악의가 없는 경우(양성 정탐)와 근거가
# 부족한 경우(미결)를 오탐과 섞으면 규칙 정확도가 실제와 달라진다.
VERDICTS = Literal["threat", "non_actionable", "false_positive",
                   "benign_positive", "undetermined"]
SEVERITIES = Literal["critical", "high", "medium", "low"]
STATUSES = Literal["open", "acknowledged", "in_progress", "resolved", "suppressed"]


# 화면 목록(Hub)은 live.py 에 있다. main.hub 는 live.hub 와 같은 것이다(시험이 main.hub.broadcast 를 바꿔 끼운다).


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL 이 설정되지 않았습니다")

    # 서버 쪽 TCP keepalive · 전송 한도(live.DB_KEEPALIVE, 이슈 #56). 이 콘솔이 꺼지거나 끊기면 DB 가 약 1분 안에 연결을 닫는다
    app.state.pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10, server_settings=live.DB_KEEPALIVE)

    # LISTEN 전용 연결(live.Listener). 사건 · 판정 · 조치 두 채널을 듣고, 끊기면 다시 붙어 화면에 resync 를 보낸다.
    # 첫 연결이 안 되면 풀과 같이 기동을 실패시킨다. 헬스체크가 빠져 HAProxy 가 다른 콘솔로 보낸다.
    # 통보 연결이 끊겼다 다시 붙으면 풀 연결도 새 세대로 바꾼다(이슈 #56). 30초 넘게 끊겼으면 DB 가 keepalive 로 이 콘솔의 풀 연결을
    #   이미 닫았을 수 있다. 끊긴 동안이라 닫힘을 모르는 연결을 그대로 빌려주면 첫 질의가 실패한다. 옛 연결은 다음에 빌릴 때 닫고 새로 붙는다
    async def renew_pool():
        await app.state.pool.expire_connections()
    app.state.listener = Listener(DATABASE_URL, hub, on_reconnect=renew_pool)
    try:
        await app.state.listener.start()
    except BaseException:
        await app.state.pool.close()
        raise

    # 알림 발송기 (이슈 #33). 큐 채우기 · 보내기 두 루프를 여기서 띄우고 종료 때 취소한다.
    app.state.notifier = Notifier(app.state.pool)
    await app.state.notifier.start()
    # 흡수 후속 차단 (absorbed.py). 함께 차단을 고른 첫 사건에 뒤늦게 흡수된 출발지를 같은 만료로 올린다
    app.state.follower = AbsorbedFollower(app.state.pool)
    await app.state.follower.start()

    try:
        yield
    finally:
        await app.state.follower.stop()
        await app.state.notifier.stop()
        await app.state.listener.stop()
        await app.state.pool.close()


# API 문서 화면(/docs · /openapi.json)은 기본으로 끈다(이슈 #41). 경로 전체 구조와 'OpsLoop API' 이름으로 콘솔이
# 드러나고, Swagger UI 는 CSP 없이 외부 CDN 스크립트를 콘솔 출처에서 돌린다. 개발에서만 OPSLOOP_API_DOCS=1 로 켠다.
# 켜도 세션 뒤에 있다(OPEN_PATHS 에 없다). ReDoc 은 켜지 않는다.
API_DOCS = os.environ.get("OPSLOOP_API_DOCS") == "1"
app = FastAPI(title="OpsLoop API", version="0.1.0", lifespan=lifespan,
              docs_url="/docs" if API_DOCS else None, redoc_url=None,
              openapi_url="/openapi.json" if API_DOCS else None)

# 화면 번들 · /api/me (web.py). 미들웨어는 나중에 붙인 것이 바깥이므로 세션 검사보다 먼저 붙여
# 세션 검사 안쪽에 둔다. 화면 번들도 로그인 뒤에만 나간다.
web.serve(app)
app.include_router(operations_router)
app.include_router(notify_router)
# CVE · KEV 연계 (cti.py). 상세 조회 /api/incidents/{incident_key:path} 보다 먼저 붙어야 …/cti 가 상세로 빠지지 않는다
app.include_router(cti_router)
# 관제 대상별 상태판 (targets.py · 이슈 #52). GET /api/dashboard/targets
app.include_router(targets_router)
# 보호 대상 장비 최근 로그 (node_logs.py · 이슈 #73). GET /api/devices/{device_id}/logs
app.include_router(node_logs_router)
# 출발지 분석 · 도구 지문 묶음 (sources.py) · 기간 보고서 (reports.py) · 이슈 #58
app.include_router(sources_router)
app.include_router(reports_router)
# 계정 관리 (accounts.py · 이슈 #59 · #63). GET /api/accounts · POST /api/accounts(추가) · /api/accounts/delete ·
#   /api/accounts/password · /api/accounts/role · /api/accounts/active (admin)
app.include_router(accounts_router)


# 세션 없이 여는 경로. /health 는 HAProxy 헬스체크가 부르므로 상태 말고는 아무것도 내지 않는다.
# /api/csp-report 는 브라우저의 CSP 위반 보고다(쿠키가 없을 수 있다. web.csp_report).
OPEN_PATHS = ("/health", "/login", "/logout", web.CSP_REPORT_PATH)
# 요청마다 하는 계정 확인(auth.lookup)이 DB 오류로 끝났을 때(503)
ACCOUNT_CHECK_FAILED = "계정 상태를 확인하지 못했습니다. 잠시 뒤 다시 시도해 주세요"

# 규칙 조건과 판정 근거가 겹치는 규칙. 여기서 나오는 위협 판정은 규칙의
# 정확성을 증명하지 않는다. 같은 것을 두 번 센 것이다. detector/triage.py 와
# 같은 판단이며, 콘솔도 같은 경고를 보여야 판정자가 같은 기준으로 본다.
# 판정 기준 §6. R003 은 v3 에서도 순환이다(키 심기를 R006 으로 떼었을 뿐 남은 조건이 파일 투하다).
# 키는 proposals.CIRCULAR_RULES 와 같다(아래 assert).
CIRCULAR = {
    "R002": "규칙 조건이 '로그인 성공 + 명령 실행'이고 판정 기준의 위협 조건도 같다",
    "R003": "규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다",
    "R004": "규칙 조건이 경유 시도이고 판정 기준의 위협 조건도 같다",
    "R006": "규칙 조건이 authorized_keys 쓰기이고 판정 기준의 위협 조건(SSH 키 심기)도 같다",
}
assert set(CIRCULAR) == CIRCULAR_RULES, "순환 규칙 목록이 proposals.py 와 다르다"
# 중복 후보를 찾는 규칙(SSH 판정 기준을 쓰는 허니팟 규칙). 상수라 문장에 그대로 넣는다.
SSH_RULES_SQL = ", ".join(f"'{r}'" for r in sorted(SSH_RULES))

# 인시던트 구간 앞뒤로 볼 여유. 한 세션에서 나온 인시던트는 폭이 0초라
# 구간만 보면 그 세션의 로그인과 명령이 범위 밖으로 빠진다.
# 매개변수에 interval 을 더할 때는 형을 밝힌다. 밝히지 않으면 PostgreSQL 이
# date · timestamp · timestamptz 중 무엇의 연산인지 정하지 못해 질의가 실패한다.
WINDOW_BEFORE = "5 minutes"
WINDOW_AFTER = "30 minutes"

# "규칙이 보지 않은 증거"로 보여줄 행위. 접속·요청 같은 배경 이벤트는 빼고
# 실제로 무언가를 한 흔적만 남긴다.
BEHAVIOR_LIKE = ["%.login.success", "%.command.input", "%.session.file_%",
                 "%direct-tcpip%", "%.action.%"]

# ----------------------------------------------------------------------
#  같은 페이로드 흡수 (규칙 v3 · incident_absorbed)
# ----------------------------------------------------------------------
#  차단 · 해제 · 후속 차단의 문장과 규칙은 absorbed.py 에 있다. detector/triage.py record 도 같은 규칙이다.
#  흡수 차단 행은 incident_key = 첫 사건 키 · reason = '흡수: <첫 사건 키>' 로 남는다. 이 둘이 함께 · 한 곳 풀 때 고르는 표시다.
#  억제(kind = suppressed) 행의 출발지는 가린 흡수 인시던트의 출발지와 같아 따로 넣지 않는다.

ABSORBED_SHOWN = 200   # 상세에 보이는 흡수 기록 행 수. 수(total · sources · blocked)는 전체를 센다

# 규칙이 같은 페이로드 흡수를 쓰는가(규칙 정의의 params.absorb_same_payload). 흡수 기록이 아직 없는 첫 사건도
# 함께 차단(후속 차단 약속)을 고를 수 있어야 한다. 판정 · 차단이 흡수보다 먼저 오는 것이 보통이다.
ABSORBS_SQL = """
    SELECT EXISTS (SELECT 1 FROM rule_versions rv, jsonb_array_elements(rv.definition -> 'rules') r
                   WHERE rv.rule_version = $1 AND r ->> 'id' = $2 AND (r -> 'params') ? 'absorb_same_payload')"""


def absorbed_reason(row) -> str:
    """흡수 기록 한 행을 화면의 '흡수 사유' 한 줄로 쓴다."""
    if row["kind"] == "suppressed":
        via = (row["via_key"] or "").split("|")[0] or "흡수 사건"
        return f"흡수된 {via} 사건과 같은 출발지 · 같은 구간의 낮은 알림(억제)"
    what = {"R003": "같은 파일을 24시간 안에 다시 투하",
            "R006": "같은 SSH 키를 24시간 안에 다시 심음"}.get(row["rule_id"], "같은 페이로드를 24시간 안에 반복")
    return f"{what}(흡수)"


@app.middleware("http")
async def require_session(request: Request, call_next):
    """열어 둔 경로를 뺀 나머지는 세션을 요구한다.

    화면과 API 의 실패 방식을 나눈다. 화면은 로그인으로 보내고 API 는 401 을
    돌려준다. 화면에서 401 을 받으면 사용자는 아무것도 못 하고, API 가
    로그인 HTML 을 받으면 파싱에서 엉뚱한 곳이 깨진다.

    쿠키의 서명 · 만료가 맞으면 계정 행을 한 번 읽어 확인한다(이슈 #59). 비활성 · 없는 계정 · 역할 등이 바뀌기 전에 받은
    쿠키는 세션이 없는 것과 같다. 역할은 쿠키가 아니라 DB 값으로 덮는다. require_role · /api/me 가 모두 따라온다.
    쿠키가 없거나 위조면 DB 를 보지 않는다(로그인하지 않은 요청이 DB 를 두드리지 못한다).
    확인 중 DB 오류는 503 이다. 401 로 답하면 화면이 멀쩡한 세션을 로그인으로 보낸다.
    """
    path = request.url.path
    if path in OPEN_PATHS or path == "/ws" or path.startswith("/ws/"):
        return await call_next(request)

    session = auth.read(request.cookies.get(auth.COOKIE, ""))
    if session is not None:
        try:
            row = await auth.lookup(request.app.state.pool, session["u"])
        except Exception as exc:
            print(f"[auth] 계정 확인 실패: {type(exc).__name__}: {exc}", flush=True)
            if path.startswith("/api"):
                return JSONResponse({"detail": ACCOUNT_CHECK_FAILED}, status_code=503)
            return PlainTextResponse(ACCOUNT_CHECK_FAILED, status_code=503)
        # 역할은 쿠키(발급 때 값)가 아니라 DB 값이다
        session = {**session, "r": row["role"]} if auth.session_valid(session, row) else None
    if session is None:
        if path.startswith("/api"):
            return JSONResponse({"detail": "인증이 필요합니다"}, status_code=401)
        return web.to_login(request)

    request.state.user = session
    return await call_next(request)


# 보안 헤더 · CORS · 출처 확인 (web.py). 세션 검사보다 나중에 붙여 그 바깥에 둔다.
web.guard(app)
# 입력 검증 오류(422)는 앱 전체에서 type · loc · msg 만 싣는다(access.masked_validation, 이슈 #62). 기본 처리기는 입력값을 되돌려
#   싣다가 짝 없는 서로게이트(\ud800)에서 인코딩 오류로 500 이 된다. 알림 · 계정 API 의 가림 라우트와 같은 모양이다
app.add_exception_handler(RequestValidationError, masked_validation)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return web.login_page(next_path=request.query_params.get("next"))


@app.post("/login")
async def login(request: Request):
    form = await auth.form_fields(request)
    username = str(form.get("username", ""))[:128]
    password = str(form.get("password", ""))[:auth.MAX_PASSWORD]
    # 로그인 뒤 돌아갈 곳. 같은 출처의 상대 경로만 받는다(열린 리디렉션 금지).
    next_path = web.safe_next(form.get("next"))

    user = await auth.authenticate(app.state.pool, username, password)
    if user is None:
        await auth.log_event(app.state.pool, request, "console.login.failed",
                             username=username, status=401)
        return web.login_page(error=True, next_path=next_path, username=username,
                              status_code=401)

    # 발급 시각은 로그인 때 DB 가 찍은 시각이다(auth.authenticate). 계정 변경 시각과 같은 시계로 견준다
    token = auth.issue(user["username"], user["role"], user["issued_at"])
    await auth.log_event(app.state.pool, request, "console.login.success",
                         username=user["username"], status=302, session=token[:17])
    response = RedirectResponse(next_path, status_code=302)
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="lax",
                        max_age=auth.SESSION_HOURS * 3600)
    return response


@app.post("/logout")
async def logout(request: Request):
    # /logout 은 OPEN_PATHS 라 세션 검사를 거치지 않아 state.user 가 없다. 쿠키를 직접 읽어 누가 나갔는지 남긴다.
    # 서명 · 만료만 본다. 나가는 길에 계정 확인(DB 조회)을 더하지 않는다
    session = auth.read(request.cookies.get(auth.COOKIE, ""))
    await auth.log_event(app.state.pool, request, "console.logout",
                         username=session["u"] if session else None, status=302)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(auth.COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
async def shell(request: Request):
    """화면 빌드(app/static)가 없을 때만 나오는 자리표시. CSP 가 인라인 스타일을 막으므로 스타일 없이 그린다."""
    user = request.state.user
    who = html.escape(f"{user['u']} · {user['r']}")
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>OpsLoop</title></head><body>
<header><strong>OpsLoop</strong> <span>{who}</span>
 <form method="post" action="/logout"><button>로그아웃</button></form></header>
<main><p>화면 구현 예정 (WBS 3.6.2~3.6.4)</p></main></body></html>"""


# 끊긴 동안 DB 가 닫은 연결을 처음 쓸 때 나는 오류. 정의는 auth.py 에 있다(계정 확인 auth.lookup 도 같은 기준으로 한 번 더 빌린다)
STALE_CONNECTION_ERRORS = auth.STALE_CONNECTION_ERRORS

# jsonb 열. asyncpg 는 코덱을 두지 않으면 글자로 준다. 화면이 객체로 받게 여기서 푼다 (이슈 #51 enforcement)
JSON_COLUMNS = frozenset({"enforcement"})


def row_to_dict(r: asyncpg.Record) -> dict:
    out = {}
    for k, v in dict(r).items():
        if isinstance(v, datetime):
            out[k] = v.astimezone(timezone.utc).isoformat()
        elif k in JSON_COLUMNS and isinstance(v, str):
            try:
                out[k] = json.loads(v)
            except ValueError:
                out[k] = None
        else:
            out[k] = v
    return out


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------

@app.get("/health")
async def health():
    """HAProxy 헬스체크(GET /health → 200). 세션 없이 열리므로 DB 가 닿는지만 보고 상태 말고는 내지 않는다.
    실시간 접속 수는 담당자가 지금 보고 있는지를 드러내므로 넣지 않는다(이슈 #41)."""
    # 연결 오류면 한 번 더 빌려 본다(이슈 #56). 망이 끊겼던 동안 DB 가 닫은 풀 연결을 처음 쓰면 한 번 실패하고, 그 연결은 다음에
    #   빌릴 때 새로 붙는다. 한 번의 옛 연결 때문에 헬스체크가 실패해 복귀(rise 3)가 늦어지지 않게 한다. DB 가 정말 없으면 둘 다 실패한다
    for attempt in (1, 2):
        try:
            async with app.state.pool.acquire() as c:
                await c.fetchval("SELECT 1")
            return {"status": "ok"}
        except STALE_CONNECTION_ERRORS:
            if attempt == 2:
                raise


# 목록 장비 필터 값: 장비 미확인(targets.UNCONFIRMED) 또는 대상 id(고정 넷 · 등록 노드 id 형식). 형식 밖은 DB 에 닿기 전에 422
DEVICE_PATTERN = r"^(?:_unconfirmed|[a-z0-9][a-z0-9-]{0,62})$"
# 목록 한 쪽의 열. 근거(sensors · sessions)는 장비 계산에만 쓰고 내보내지 않는다
PAGE_COLUMNS = f"""i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity,
                   host(i.actor_ip) AS actor_ip, i.target, i.first_ts, i.last_ts,
                   i.signal_count, i.session_count, i.status, i.created_at,
                   v.verdict,
                   extract(epoch FROM (now() - i.first_ts))::bigint AS pending_seconds,
                   {targets.EVIDENCE_COLUMNS}"""


@app.get("/api/incidents")
async def list_incidents(
    status: Optional[STATUSES] = None,
    severity: Optional[SEVERITIES] = None,
    rule_id: Optional[str] = Query(None, max_length=128),
    rule_version: Optional[str] = Query(None, max_length=128),
    actor_ip: Optional[str] = None,
    target: Optional[str] = Query(None, max_length=256),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    judged: Optional[bool] = None,
    undetermined: Optional[bool] = None,
    device: Optional[str] = Query(None, pattern=DEVICE_PATTERN),
    sort: Literal["pending", "severity", "recent"] = "pending",
    limit: int = Query(50, ge=1, le=500),
    # 상한이 없으면 int64 를 넘는 값이 DB 에 닿아 422 가 아니라 500 이 된다(cti.MAX_OFFSET, 이슈 #62)
    offset: int = Query(0, ge=0, le=cti.MAX_OFFSET),
):
    """기본 정렬은 미판정 경과 시간이다. 심각도순이 아니다.

    판정이 사람의 일인 이상 가장 오래 밀린 건이 가장 위험하다. 심각도순으로
    두면 낮은 등급의 오래된 건이 영영 아래에 깔린다. (화면 설계 4장)
    항목마다 관련 장비(devices · device_state · device_fallback)를 싣는다. 조회 때 기존 근거로 계산하고 저장하지 않는다.
    undetermined=true 는 최신 판정이 사람이 남긴 미결(판단 유보)인 사건만이다(대시보드 미결 수와 같은 기준, false 는 그 밖).
    judged 와 함께 주면 둘 다 건다(AND).
    """
    # 출발지는 주소여야 한다. 그대로 ::inet 으로 넘기면 캐스팅 오류가 500 이 된다(화면이 주소창의 actor_ip 를 읽는다, 이슈 #58).
    #   IPv6 영역 표기(fe80::1%eth0)는 파이썬은 받지만 inet 이 받지 않아 함께 거른다. 빈 값은 전처럼 조건 없음이다
    if actor_ip:
        try:
            ip = ipaddress.ip_address(actor_ip.strip())
        except ValueError:
            ip = None
        if ip is None or getattr(ip, "scope_id", None):
            raise HTTPException(422, "actor_ip 는 IP 주소여야 합니다")
        actor_ip = str(ip)
    # 글자 열에 NUL 은 들어가지 못해 그대로 넘기면 DB 오류가 500 이 된다(이슈 #62). 그런 규칙 · 대상은 없으므로 입력 오류다
    for name, value in (("rule_id", rule_id), ("rule_version", rule_version), ("target", target)):
        if value and "\x00" in value:
            raise HTTPException(422, f"{name} 에 NUL 글자를 넣을 수 없습니다")

    async with app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        return await incident_page(c, status=status, severity=severity, rule_id=rule_id, rule_version=rule_version,
                                   actor_ip=actor_ip, target=target, since=since, until=until, judged=judged,
                                   undetermined=undetermined, device=device, sort=sort, limit=limit, offset=offset)


async def incident_page(c, *, status=None, severity=None, rule_id=None, rule_version=None, actor_ip=None, target=None,
                        since=None, until=None, judged=None, undetermined=None, device=None, sort="pending", limit=50,
                        offset=0) -> dict:
    """사건 목록 한 쪽(입력 검사 뒤). 부른 쪽이 반복 읽기 트랜잭션을 연다.

    장비 필터(device)는 쪽을 나누기 전에 거른다. 조건에 맞는 사건을 가볍게(키 · 근거만) 모두 읽어 장비를 한 번 계산하고, 그 장비가
    shown 에 든 사건만 순서대로 남긴 뒤 쪽 키만 다시 읽는다. 전체 수는 키 수라 중복이 없다(사건 키가 PK 다).
    대상별 카드 수(targets.tally)와 같은 매핑 · 같은 기준이다."""
    as_of = await c.fetchval("SELECT now()")
    where, params = [], []

    def add(clause, value):
        params.append(value)
        where.append(clause.format(n=len(params)))

    if status:       add("i.status = ${n}", status)
    if severity:     add("i.severity = ${n}", severity)
    if rule_id:      add("i.rule_id = ${n}", rule_id)
    if rule_version: add("i.rule_version = ${n}", rule_version)
    if actor_ip:     add("i.actor_ip = ${n}::inet", actor_ip)
    if target:       add("i.target = ${n}", target)
    if since:        add("i.first_ts >= ${n}", since)
    if until:        add("i.first_ts < ${n}", until)
    if judged is True:  where.append("v.verdict IS NOT NULL")
    if judged is False: where.append("v.verdict IS NULL")
    # 미결: 최신 판정이 사람이 남긴 판단 유보(dashboard.HUMAN_UNDETERMINED, 시스템 전환 기록 제외)
    if undetermined is not None:
        where.append(("" if undetermined else "NOT ") + HUMAN_UNDETERMINED.format(v="v"))

    w = ("WHERE " + " AND ".join(where)) if where else ""
    order = {
        "pending":  "(v.verdict IS NULL) DESC, i.first_ts ASC",
        "severity": "CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 ELSE 3 END, i.first_ts DESC",
        "recent":   "i.first_ts DESC",
    }[sort] + ", i.incident_key ASC"  # 같은 시각·등급도 페이지 사이 순서가 바뀌지 않게 한다.
    # 최근 판정 하나만 붙인다. 재판정이 생겨도 목록에는 마지막 판단이 보여야 한다. 판정자(operator)는 미결 필터에만 쓰고 싣지 않는다
    latest = """LEFT JOIN LATERAL (
            SELECT verdict, operator FROM verdicts WHERE incident_key = i.incident_key
            ORDER BY created_at DESC, id DESC LIMIT 1) v ON true"""
    base = f"""FROM incidents i
        {latest}
        {w}"""

    # 필터 선택지는 필터링된 첫 쪽에 없는 규칙도 포함한다. 별도 API를 요구하지 않는다.
    rules_sql = """
        SELECT DISTINCT ON (rule_id) rule_id, rule_name FROM incidents
        ORDER BY rule_id, last_ts DESC, incident_key"""
    if device is None:
        total = await c.fetchval(f"SELECT count(*) {base}", *params)
        rules = await c.fetch(rules_sql)
        rows = await c.fetch(f"""
            SELECT {PAGE_COLUMNS}
            {base}
            ORDER BY {order}
            LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}""", *params, limit, offset)
        devices, cards = await targets.incident_devices(c, rows, as_of)
    else:
        rules = await c.fetch(rules_sql)
        # 가벼운 질의: 조건에 맞는 사건 전부의 키 · 근거(쪽 질의와 같은 조건 · 순서)
        light = [dict(r) for r in await c.fetch(f"""
            SELECT i.incident_key, i.rule_id, i.rule_version, host(i.actor_ip) AS actor_ip, i.target, i.first_ts,
                   i.last_ts, {targets.EVIDENCE_COLUMNS}
            {base}
            ORDER BY {order}""", *params)]
        _, cards = await targets.read_nodes(c, as_of)
        links, specs = await targets.link_incidents(c, light, targets.node_sources(cards))
        keys = [r["incident_key"] for r in light if targets.device_matches(device, links[r["incident_key"]])]
        total, page = len(keys), keys[offset:offset + limit]
        found = {r["incident_key"]: r for r in await c.fetch(f"""
            SELECT {PAGE_COLUMNS}
            FROM incidents i
            {latest}
            WHERE i.incident_key = ANY($1::text[])""", page)} if page else {}
        rows = [found[key] for key in page if key in found]
        rule_of = {r["incident_key"]: (r["rule_version"], r["rule_id"]) for r in light}
        devices = {key: targets.devices_of(links[key], specs.get(rule_of[key]), cards) for key in page}

    items = []
    for r in rows:
        item = row_to_dict(r)
        for key in ("sensors", "sessions"):
            item.pop(key, None)
        items.append(item | devices[r["incident_key"]])
    return {"total": total, "limit": limit, "offset": offset, "items": items,
            "rules": [row_to_dict(r) for r in rules], "device_options": targets.device_options(cards)}


@app.get("/api/incidents/{incident_key:path}")
async def get_incident(incident_key: str):
    if "\x00" in incident_key:  # 키에 NUL 은 없다. DB 에 넘기면 오류가 500 이 된다(이슈 #62)
        raise HTTPException(404, "인시던트를 찾을 수 없습니다")
    async with app.state.pool.acquire() as c:
        inc = await c.fetchrow("""
            SELECT incident_key, rule_id, rule_version, rule_name, severity,
                   host(actor_ip) AS actor_ip, target, first_ts, last_ts,
                   signal_count, session_count, evidence, status, created_at
            FROM incidents WHERE incident_key = $1""", incident_key)
        if inc is None:
            raise HTTPException(404, "인시던트를 찾을 수 없습니다")

        # 관련 장비(목록 항목과 같은 계산). 근거는 evidence 가 객체일 때만 쓰고, sensors · sessions 는 목록의
        # EVIDENCE_COLUMNS 처럼 배열일 때만 넘긴다(글자 값을 다시 JSON 으로 읽으면 목록과 다른 장비 · 500 이 된다)
        as_of = await c.fetchval("SELECT now()")
        ev = json.loads(inc["evidence"]) if isinstance(inc["evidence"], str) else inc["evidence"]
        ev = ev if isinstance(ev, dict) else {}
        sensors, sessions = ev.get("sensors"), ev.get("sessions")
        devices, _ = await targets.incident_devices(c, [{
            "incident_key": inc["incident_key"], "rule_id": inc.get("rule_id"), "rule_version": inc.get("rule_version"),
            "actor_ip": inc.get("actor_ip"), "target": inc.get("target"), "first_ts": inc["first_ts"],
            "last_ts": inc["last_ts"], "sensors": sensors if isinstance(sensors, list) else None,
            "sessions": sessions if isinstance(sessions, list) else None}], as_of)

        actions = await c.fetch(
            "SELECT id, action, operator, note, created_at FROM actions "
            "WHERE incident_key = $1 ORDER BY created_at", incident_key)
        verdicts = await c.fetch(
            "SELECT id, verdict, reason, observed_value, operator, proposed, decision_seconds, created_at FROM verdicts "
            "WHERE incident_key = $1 ORDER BY created_at, id", incident_key)
        # 같은 출발지의 다른 인시던트. 관제자가 제일 먼저 궁금해하는 것.
        related = await c.fetch("""
            SELECT incident_key, rule_id, severity, first_ts, signal_count, status
            FROM incidents
            WHERE actor_ip = $1::inet AND incident_key <> $2
            ORDER BY first_ts DESC LIMIT 20""", inc["actor_ip"], incident_key)

        actor = inc["actor_ip"]
        window = (inc["first_ts"], inc["last_ts"])

        # 화면 표본의 200/300행 제한으로 '행위 없음'을 추론하지 않고 전체 구간을 센다.
        # fixture는 실제 판정의 근거에 섞지 않는다. SSH 기준은 Cowrie에만 적용한다.
        counts = await c.fetch(f"""
            SELECT eventid, count(*) AS n FROM events
            WHERE src_ip = $1::inet AND provenance = 'real'
              AND ts BETWEEN $2::timestamptz - interval '{WINDOW_BEFORE}' AND $3::timestamptz + interval '{WINDOW_AFTER}'
              AND eventid LIKE 'cowrie.%'
            GROUP BY eventid""", actor, *window) if actor else []
        # 중복 제안의 근거는 같은 규칙 버전의 사건에서만 찾는다. 버전이 바뀌면 사건을 가르는
        # 조건이 달라 앞 버전의 위협 판정이 이 사건의 대표라는 보장이 없다.
        covered = await c.fetchval(f"""
            SELECT i.incident_key FROM incidents i
            JOIN LATERAL (
                SELECT verdict FROM verdicts WHERE incident_key = i.incident_key
                ORDER BY created_at DESC, id DESC LIMIT 1
            ) v ON v.verdict = 'threat'
            WHERE i.actor_ip = $1::inet AND i.incident_key <> $2
              AND i.rule_version = $5
              AND i.rule_id IN ({SSH_RULES_SQL})
              AND i.first_ts <= $4::timestamptz + interval '15 minutes'
              AND i.last_ts >= $3::timestamptz - interval '15 minutes'
            ORDER BY i.first_ts, i.incident_key LIMIT 1""",
            actor, incident_key, *window, inc["rule_version"]) if actor else None

        # ② 규칙이 보지 않은 증거. 규칙이 본 것만으로 판정하면 규칙의 시야를
        #    그대로 물려받는다. 같은 구간에 같은 출발지가 실제로 한 일을 모은다.
        behavior = await c.fetch(f"""
            SELECT ts, sensor, eventid, session, username, input, url, shasum,
                   http_method, http_status
            FROM events
            WHERE src_ip = $1::inet AND provenance = 'real'
              AND ts BETWEEN $2::timestamptz - interval '{WINDOW_BEFORE}' AND $3::timestamptz + interval '{WINDOW_AFTER}'
              AND eventid LIKE ANY($4::text[])
            ORDER BY ts LIMIT 200""", actor, *window, BEHAVIOR_LIKE) if actor else []

        # ③ 행위자 이력. 허니팟·디코이에 접근한 이력은 결정적 근거다. 그 자산에
        #    접근한 출발지가 정상 사용자일 가능성은 사실상 없다.
        history = await c.fetchrow("""
            SELECT min(ts) AS first_seen, max(ts) AS last_seen, count(*) AS events,
                   array_agg(DISTINCT sensor) AS sensors,
                   count(DISTINCT session) AS sessions
            FROM events WHERE src_ip = $1::inet AND provenance = 'real'""",
            actor) if actor else None
        rules_hit = await c.fetch("""
            SELECT rule_id, count(*) AS incidents FROM incidents
            WHERE actor_ip = $1::inet GROUP BY rule_id ORDER BY incidents DESC""",
            actor) if actor else []
        # 차단 행과 집행 결과(이슈 #47). 화면은 요청 지점(points · 이슈 #77)과 enforce_note · enforced_at · expires_at ·
        # 지점별 결과(enforcement · 이슈 #51)로 종합 상태(block_points.STATE_CASE 와 같은 규칙)와 관문 · 내부 방화벽 표를 그린다
        blocked = await c.fetchrow("""
            SELECT reason, method, created_at, expires_at, released_at, enforced_at, enforce_note, requested_by,
                   enforcement, points
            FROM blocklist WHERE actor_ip = $1::inet""", actor) if actor else None
        # 이 출발지가 드는 차단 금지 대역(block_exempt). 있으면 화면이 차단 단추를 흐리고 사유를 보인다
        exempt = await exempt_of(c, actor) if actor else None

        # 같은 페이로드 흡수 (규칙 v3). 이 사건이 첫 사건이면, 지운 인시던트(kind = absorbed)와 가린 것이 그것뿐이라
        # 억제한 같은 출발지의 낮은 알림(kind = suppressed)이 incident_absorbed 에 남는다. 근거(evidence.absorbed)는
        # 판정 때 굳고 max_sources 에서 잘리므로 차단 근거는 이 표에서 읽는다. 판정 뒤에 붙은 흡수도 여기 보인다.
        # 흡수는 출발지가 있는 사건(허니팟 규칙)에만 생긴다. 목록은 흡수 · 첫 시각 순 200행, 수는 전체를 센다.
        absorbed = await c.fetch(f"""
            SELECT host(actor_ip) AS actor_ip, kind, rule_id, member_key, via_key, first_ts, last_ts,
                   signal_count, cardinality(sessions) AS sessions, payloads[1] AS payload
            FROM incident_absorbed WHERE first_key = $1
            ORDER BY kind, first_ts, member_key LIMIT {ABSORBED_SHOWN}""", incident_key) if actor else []
        absorbed_n = await c.fetchrow("""
            SELECT count(*) AS total,
                   count(DISTINCT actor_ip) FILTER (WHERE kind = 'absorbed'
                                                    AND actor_ip IS DISTINCT FROM $2::inet) AS sources
            FROM incident_absorbed WHERE first_key = $1""", incident_key, actor) if actor else None
        # 흡수 출발지의 차단 상태(absorbed.py ABSORBED_STATE_SQL). 함께 차단 확인 창이 넣지 않을 곳(사람이 푼 곳 ·
        # 차단 금지 대역 · 다른 사건 차단)을 미리 보인다. 후속 차단 약속이 살아 있으면 그 만료를 함께 낸다
        absorbed_state = await c.fetchrow(ABSORBED_STATE_SQL, incident_key, absorbed_reason_tag(incident_key),
                                          actor, await block_nets(c), 20) if actor else None
        follow = await c.fetchrow(FOLLOW_STATE_SQL, incident_key) if actor else None
        absorbs = await c.fetchval(ABSORBS_SQL, inc["rule_version"], inc["rule_id"]) if actor else False

        # ④ 원문. 요약이 아니라 근거가 된 원본 줄이다(관제 대상 로그 줄은 아래에서 가려 보낸다).
        raw = await c.fetch(f"""
            SELECT ts, sensor, eventid, session, username, password IS NOT NULL AS has_password,
                   input, url, shasum, http_method, http_status, user_agent, message
            FROM events
            WHERE src_ip = $1::inet
              AND ts BETWEEN $2::timestamptz - interval '{WINDOW_BEFORE}' AND $3::timestamptz + interval '{WINDOW_AFTER}'
            ORDER BY ts LIMIT 300""", actor, *window) if actor else []

    d = row_to_dict(inc)
    # ① 근거 표본 · ② · ④ 는 장비 최근 로그(node_logs, 이슈 #73)와 같은 규칙으로 가린다(① 은 요청 경로 서명 규칙이 남긴 url).
    #   원문은 허니팟 · 디코이 · 관문(공격 증거)과 콘솔 · 감사 · 수집 관문 줄뿐이고 노드 카드 · 상태와 관계없다(이슈 #81)
    d["evidence"] = node_logs.mask_evidence(json.loads(inc["evidence"]) if inc["evidence"] else None)
    d["actions"] = [row_to_dict(r) for r in actions]
    d["verdicts"] = [row_to_dict(r) for r in verdicts]
    d["related"] = [row_to_dict(r) for r in related]
    d["behavior"] = node_logs.mask_incident_lines([row_to_dict(r) for r in behavior])
    d["actor"] = {
        "history": row_to_dict(history) if history else None,
        "rules": [row_to_dict(r) for r in rules_hit],
        "blocked": row_to_dict(blocked) if blocked else None,
        "exempt": exempt,
    }
    # 비밀번호 원문은 화면에 내지 않는다. 타인의 실제 자격증명일 수 있다.
    d["raw"] = node_logs.mask_incident_lines([row_to_dict(r) for r in raw])
    st = dict(absorbed_state) if absorbed_state else {}
    d["absorbed"] = {
        "items": [row_to_dict(r) | {"reason": absorbed_reason(r)} for r in absorbed],
        # total: 기록 전체(억제 포함) · sources: 흡수 출발지(이 사건 출발지 제외 · 중복 제거) · blocked: 이 사건 흡수
        # 차단으로 살아 있는 곳(함께 · 한 곳 풀 수) · kept: 다른 사건 차단으로 살아 있는 곳 · skipped: 사람이 풀어 함께
        # 차단에서 빼는 곳(앞 20곳) · unblockable: 차단 금지 대역
        **{k: (absorbed_n[k] if absorbed_n else 0) for k in ("total", "sources")},
        "blocked": st.get("blocked", 0),
        "kept": st.get("kept", 0),
        "skipped": list(st.get("skipped") or []),
        "skipped_total": st.get("skipped_total", 0),
        "unblockable": st.get("unblockable", 0),
        # 규칙이 흡수를 쓰는가(흡수 기록이 아직 없어도 함께 차단 · 후속 차단을 고를 수 있다) · 살아 있는 후속 차단 약속과
        # 첫 사건의 마지막 판정(위협이 아니면 후속 차단이 멈춘다)
        "absorbs": bool(absorbs),
        "follow": row_to_dict(follow) if follow else None,
    }
    d["circular"] = CIRCULAR.get(inc["rule_id"])
    d["proposal"] = propose(inc["rule_id"], {r["eventid"]: r["n"] for r in counts}, covered)
    d |= devices[inc["incident_key"]]
    # 차단 적용 지점(이슈 #77). default 는 규칙만으로 정한 기본값, basis 는 그 까닭(확인 창 ⓘ, 장비는 여기만 쓴다),
    #   requested 는 이 출발지의 살아 있는 차단이 요청한 지점(없으면 null)이다
    alive = blocked is not None and blocked["released_at"] is None \
        and (blocked["expires_at"] is None or blocked["expires_at"] > as_of)
    d["block_points"] = {"default": block_points.default_points(inc["rule_id"]),
                         "basis": block_points.basis_of(inc["rule_id"], d["devices"], d["device_state"]),
                         "requested": list(blocked["points"]) if alive else None}
    return d


# 집행기(enforcer/block_enforcer.py)가 enforce_note 에 쓰는 말머리(이슈 #47). 화면(format.ts blockState)도 같은 말머리로 가른다
#   '관문 반영 · <digest 앞 8자> · <관문 적용 시각>' 관문 집합에 들어간 것을 확인했다(enforced_at 도 채운다). 앞 확인을 비운 적 없이
#                                                 다시 확인했으면(다시 걸기 · 연장) 끝에 ' · 기존 차단 유지'(이슈 #77 결정 2)
#   '관문 불일치 · <사유>'                       관문 상태가 목록과 5분 넘게 다르거나 관문이 거부했다(enforced_at 은 그대로)
#   '집행 제외 · 만료 없음 | 금지 대역 | 대역 주소'  집행하지 않는 행(만료 없는 옛 차단 등)
ENFORCE_EXCLUDED = "집행 제외"
ENFORCE_MISMATCH = "관문 불일치"

# 살아 있는 차단 요청을 종합 상태로 나눈다(block_points.STATE_CASE, 이슈 #77). 요청한 지점이 모두 확인이어야 적용이고 우선순위는
# 제외 > 실패 > 불일치 > 대기 > 적용이다. 화면 blockState · 보고서(reports.BLOCK_STATES_SQL)가 같은 규칙이다. 만료 없는 옛 차단
# (운영 13건)은 집행 대상이 아니라 제외로 센다. $1 기준 시각
BLOCK_STATES_SQL = block_points.BLOCK_STATES_SQL


# 요약의 상위 출발지. 최고 심각도는 글자 max 가 아니라 순위로 고른다(글자순이면 medium > low > high > critical 이라
#   critical 이 있어도 medium 이 나온다, 이슈 #58). 순위는 사건 목록 정렬의 CASE 와 같다. 같은 수면 주소 순
TOP_ACTORS_SQL = """
    SELECT host(actor_ip) ip, count(*) n,
           (ARRAY['critical', 'high', 'medium', 'low'])[
               min(CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END)] sev
    FROM incidents WHERE actor_ip IS NOT NULL
    GROUP BY actor_ip ORDER BY n DESC, actor_ip LIMIT 10"""

# 요약의 실제 이벤트 수 · 출발지 수 · 최근 원문 수집. 최근 원문 수집은 앞선 시각 줄(기준 시각 + 5분 넘게, 장비 로그 목록과 같은
#   기준 targets.FUTURE_LIMIT)을 빼고 고른다. 수는 그대로 센다. $1 기준 시각
EVENTS_SQL = f"""
    SELECT count(*) events, count(DISTINCT src_ip) actors,
           max(ts) FILTER (WHERE ts <= $1::timestamptz + {targets.FUTURE_LIMIT}) latest
    FROM events WHERE provenance = 'real'"""


@app.get("/api/stats/summary")
async def summary():
    async with app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        metrics = await dashboard_metrics(c, as_of)
        by_sev = await c.fetch(
            "SELECT severity, count(*) FROM incidents WHERE status = 'open' GROUP BY 1")
        by_status = await c.fetch("SELECT status, count(*) FROM incidents GROUP BY 1")
        daily = await c.fetch("""
            SELECT to_char(first_ts, 'YYYY-MM-DD') d, count(*)
            FROM incidents GROUP BY 1 ORDER BY 1 DESC LIMIT 14""")
        top = await c.fetch(TOP_ACTORS_SQL)
        ev = await c.fetchrow(EVENTS_SQL, as_of)
        blocks = await c.fetchrow(BLOCK_STATES_SQL, as_of)
        # 판정 뒤에 흡수됐는데 차단이 없는 출발지(absorbed.py). 흡수는 첫 사건이 판정 · 차단된 뒤에도 붙고 알림이
        # 없으므로, 함께 차단을 고르지 않았으면 여기서만 드러난다. 흡수 기록 표가 없는 DB(v3 전)에서는 생략한다
        unblocked = await c.fetchrow(UNBLOCKED_AFTER_VERDICT_SQL, await block_nets(c)) \
            if await c.fetchval("SELECT to_regclass('incident_absorbed') IS NOT NULL") else None
        # 지점별 적용 결과(상태판 카드 대응과 같은 정의 targets.point_counts). 집행기가 멈추면 적용 · 실패를 미확인에 합친다
        heartbeats_available = bool(await c.fetchval(targets.HEARTBEATS_READABLE_SQL))
        reports = targets.reports_of([dict(r) for r in await c.fetch(targets.HEARTBEATS_SQL)]) \
            if heartbeats_available else {}
        by_point = await c.fetchrow(targets.BLOCKS_SQL, as_of)

    return {
        **metrics,
        "open_by_severity": {r["severity"]: r["count"] for r in by_sev},
        "by_status": {r["status"]: r["count"] for r in by_status},
        "daily": [{"date": r["d"], "count": r["count"]} for r in daily],
        "top_actors": [dict(r) for r in top],
        "events": ev["events"],
        "actors": ev["actors"],
        "latest_event": ev["latest"].isoformat() if ev["latest"] else None,
        # 살아 있는 차단 요청 수와 그 종합 상태. 요청 수는 실제로 막은 수가 아니다(적용은 요청한 지점이 모두 확인한 것이다)
        "blocked_ips": blocks["total"],
        "blocks": {k: blocks[k] for k in block_points.STATES},
        # 지점별 합(applied + failed + unverified) = 살아 있는 요청 − 제외 − 그 지점 미요청(unrequested) − 그 지점 빠짐 확인 전
        # (removing, 관문 빼기 뒤 관문이 뺐다고 확인하기 전). 만료 없음 · 집행 제외는 어느 지점도 집행하지 않는다
        "blocks_by_point": [targets.point_counts(p, by_point, reports.get(p), as_of, heartbeats_available)
                            for p in targets.POINT_LABELS],
        **({"absorbed_unblocked": dict(unblocked)} if unblocked else {}),
    }


# ----------------------------------------------------------------------
#  조치와 판정 - 폐루프의 입력
# ----------------------------------------------------------------------

def no_nul(value: Optional[str], name: str) -> Optional[str]:
    """메모 · 판정 사유의 NUL 은 글자 열에 들어가지 못해 INSERT 가 DB 오류(500)로 끝난다. 입력 오류(422)로 돌려준다(이슈 #62)."""
    if value is not None and "\x00" in value:
        raise ValueError(f"{name}에 NUL 글자를 넣을 수 없습니다")
    return value


# 판정자와 조치자는 본문이 아니라 세션에서 가져온다. 본문 값을 믿으면 남의 이름으로
# 판정할 수 있고, 판정이 계정에 귀속된다는 전제가 깨진다.
class ActionIn(BaseModel):
    action: ACTIONS
    note: Optional[str] = Field(default=None, max_length=1000)
    # 차단은 되돌릴 수 있는 완화 조치다. 만료 없는 차단은 언젠가 정상 사용자를 막는다.
    expires_hours: int = Field(default=24, ge=1, le=720)
    # 첫 사건의 차단 · 해제에 같은 페이로드로 흡수된 출발지(incident_absorbed)를 함께 넣는가. 기본은 이 사건 출발지만.
    #   흡수된 인시던트는 지워져 상세가 없으므로 첫 사건에서만 걸고 푼다. 차단 · 해제 밖의 조치에서는 쓰지 않는다.
    #   차단에 주면 만료 전까지 새로 흡수되는 출발지도 같은 만료로 올린다(후속 차단 약속, absorbed.py).
    include_absorbed: bool = False
    # 해제할 차단 행의 출발지. 차단 목록 화면은 행마다 이 값을 넘긴다. 행의 incident_key 가 가리키는 사건의 출발지와
    # 행의 출발지가 다를 수 있기 때문이다(흡수 차단 행: 출발지 = 흡수 출발지, 근거 사건 = 첫 사건).
    #   없거나 이 사건 출발지와 같으면 이 사건 출발지의 차단을 푼다. 다르면 이 사건의 흡수 차단 한 행만 푼다.
    actor_ip: Optional[str] = Field(default=None, max_length=64)
    # 차단 적용 지점(이슈 #77). ["fw"] 또는 ["gateway", "fw"](순서 무관, 정규 순서로 바꾼다). 관문이 빠진 것은 되지만 내부 방화벽이
    #   빠지거나 모르는 값 · 중복 · 빈 목록은 422 다. 없으면 두 지점(옛 화면 호환). 차단 밖의 조치에서는 쓰지 않는다(400).
    #   흡수 함께 차단 · 후속 차단 약속도 같은 지점이다. 이 출발지의 살아 있는 차단보다 좁으면(관문 빼기) 관리자만 한다
    points: Optional[list[str]] = None

    @field_validator("points")
    @classmethod
    def _points(cls, v):
        return None if v is None else block_points.normalize(v)

    @field_validator("actor_ip")
    @classmethod
    def _ip(cls, v):
        if v is None:
            return v
        try:
            ip = ipaddress.ip_address(v.strip())
        except ValueError:
            ip = None
        # IPv6 영역 표기(fe80::1%eth0)는 파이썬은 받지만 inet 에는 영역이 없다. 매개변수로 넘기면 asyncpg 가 영역을 버려 다른 주소(fe80::1)를
        #   다루고, 글자로 넘기면 캐스팅 오류다. sources.parse_ip 와 같은 기준으로 거른다(이슈 #62)
        if ip is None or getattr(ip, "scope_id", None):
            raise ValueError("actor_ip 는 IP 주소여야 합니다")
        return str(ip)

    @field_validator("note")
    @classmethod
    def _note(cls, v):
        return no_nul(v, "메모")


class VerdictIn(BaseModel):
    verdict: VERDICTS
    reason: Optional[str] = Field(default=None, max_length=1000)
    # NaN · 무한대는 저장은 되지만 응답 JSON 을 만들지 못해 판정 뒤 그 사건 상세가 계속 500 이 된다(이슈 #62)
    observed_value: Optional[float] = Field(None, allow_inf_nan=False)
    # 뒤집힘 비율과 판정 비용을 재려면 제안값과 소요 시간이 판정과 함께 남아야 한다.
    proposed: Optional[VERDICTS] = None
    decision_seconds: Optional[int] = Field(default=None, ge=0, le=86400)

    @field_validator("reason")
    @classmethod
    def _reason(cls, v):
        return no_nul(v, "판정 사유")


# 조치가 인시던트 상태를 어떻게 바꾸는지. 규칙을 코드 한 곳에 모아둔다.
# 차단은 종결이 아니다. 종결은 판정이 기록될 때만 일어난다.
ACTION_STATUS = {
    "acknowledge": "acknowledged",
    "block_ip": "in_progress",
    "suppress_rule": "suppressed",
}

# 되돌리는 행위와 기준을 바꾸는 행위는 admin 만 한다.
ADMIN_ACTIONS = {"unblock_ip", "suppress_rule"}

# 판정 · 조치는 트랜잭션 첫머리에서 사건 행을 잠근다(이슈 #43). 같은 사건의 판정 · 조치가 겹치면 차례로 처리해
# 뒤에 온 것이 앞의 결과(상태 · 차단)를 보고 쓴다. 잠그지 않으면 두 트랜잭션이 서로의 상태를 덮는다.
# 잠금 순서는 incidents → blocklist 하나다. 거꾸로 잡는 곳이 없어 교착이 없다.
#   FOR UPDATE 는 외래 키 확인의 KEY SHARE(verdicts · actions 행을 넣을 때 incidents 행에 건다)와도 충돌한다.
#   그래서 판정 · 조치 행을 넣는 다른 쪽도 사건 행을 먼저 잡은 뒤 차단 목록으로 간다.
#   - detector/triage.py record: 판정 행을 먼저 넣어(외래 키 KEY SHARE) 사건 행을 잡고 차단 목록 · 상태를 쓴다
#   - absorbed.AbsorbedFollower: 후속 차단할 첫 사건 행을 FOLLOW_DUE_SQL 에서 KEY SHARE 로 먼저 잡고 차단 목록으로 간다.
#     잡지 않으면 차단 목록 → 조치 행(외래 키) 순서가 되어 같은 첫 사건의 함께 차단과 교착한다
#   absorbed.py 의 나머지 문장은 incidents 를 읽기만 하고 잠그지 않는다.
LOCK_INCIDENT = "SELECT host(actor_ip) actor_ip, rule_id, rule_version FROM incidents WHERE incident_key = $1 FOR UPDATE"

# 이 출발지의 차단(콘솔 block_ip). $1 출발지 · $2 사유 · $3 사건 키 · $4 요청자 · $5 만료 시간(시) · $6 적용 지점 · $7 관문 빼기
#   살아 있는 차단에 다시 걸 때 만료를 앞당기지 않는다. 앞당기면 차단 조치로 차단을 줄이는 셈이고(감사에는 shortened 로
#   남아 R201 이 센다), 만료 없는 옛 차단도 24시간 뒤에 풀린다. 풀리거나 만료된 차단은 새로 건다.
#   관문 빼기($7 참, 이 트랜잭션에서 살아 있던 행을 막 풀었다)도 살아 있던 차단을 다시 거는 것이라 만료는 같은 규칙이고
#   지점은 받은 값이다(이슈 #77).
#   집행 정보(관문 세 열 method · enforced_at · enforce_note)는 요청 시각에 비우지 않는다(이슈 #77 결정 2). 살아 있는 차단은 같은
#   주소가 관문에 이미 올라 있고, 해제 · 만료 행도 관문이 아직 옛 목록으로 막고 있을 수 있다. 비우면 막힌 채인데도 감사에
#   console.block.unenforced 가 남는다. 집행기가 판단한다: 관문이 이 주소가 빠진 목록을 오류 없이 적용했다고 확인하면 그때 비우고
#   (unenforced) 새로 확인하며, 뺀 적 없이 이어졌으면 다시 건 뒤 올린 목록의 새 보고로 확인해 '기존 차단 유지' 로 적는다.
#   관문을 요청하지 않는 다시 걸기(관문 빼기 · 관문 없이)는 관문이 뺐다고 확인할 때까지 관문 칸이 빠짐 확인 전이다(결정 14).
#   사람이 푼 차단도 콘솔 차단은 다시 건다(사람이 고른 조치다). triage 는 되살리지 않는다(detector/triage.py OWN_BLOCK_SQL).
#   적용 지점(이슈 #77)은 살아 있는 차단이면 합집합(넓히기만, 좁히기는 DB 트리거가 거부한다), 새 요청이면 받은 값이다.
#   차단 금지 대역 · 대역 주소는 blocklist 트리거(blocklist_guard)가 SQLSTATE 23514 로 거부한다. ON CONFLICT 로 기존 행을
#   고치는 경우에도 BEFORE INSERT 트리거가 먼저 돌아 같은 거부가 난다.
_LIVE = "(blocklist.released_at IS NULL AND (blocklist.expires_at IS NULL OR blocklist.expires_at > now()))"
BLOCK_SQL = f"""
    INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at, points)
    VALUES ($1::inet, $2, $3, $4, now() + make_interval(hours => $5), $6::text[])
    ON CONFLICT (actor_ip) DO UPDATE
    SET reason = EXCLUDED.reason, incident_key = EXCLUDED.incident_key,
        requested_by = EXCLUDED.requested_by,
        expires_at = CASE WHEN ({_LIVE} OR $7::boolean)
                               AND (blocklist.expires_at IS NULL OR blocklist.expires_at > EXCLUDED.expires_at)
                          THEN blocklist.expires_at ELSE EXCLUDED.expires_at END,
        points       = CASE WHEN {_LIVE} THEN {block_points.UNION_SQL} ELSE EXCLUDED.points END,
        released_at = NULL, released_by = NULL, created_at = now()"""


# 이 출발지의 살아 있는 차단을 잠그고 요청 지점을 읽는다(관문 빼기 판단). 살아 있음은 BLOCK_SQL 의 _LIVE 와 같은 기준이다. $1 출발지
LIVE_POINTS_SQL = """
    SELECT points FROM blocklist
    WHERE actor_ip = $1::inet AND released_at IS NULL AND (expires_at IS NULL OR expires_at > now())
    FOR UPDATE"""
# 관문 빼기의 해제(같은 트랜잭션에서 BLOCK_SQL 로 다시 건다). $1 출발지 · $2 해제자
RELEASE_FOR_NARROW_SQL = "UPDATE blocklist SET released_at = now(), released_by = $2 WHERE actor_ip = $1::inet"


async def notify_event(c, kind: str, incident_key: str, row_id) -> None:
    """판정 · 조치 통보를 같은 트랜잭션에서 보낸다(live.EVENT_CHANNEL). 커밋 때 나가고 되돌리면 나가지 않는다.
    이 콘솔 화면도 제 LISTEN 으로 받는다. 요청을 받은 콘솔의 화면에만 가던 것을 두 콘솔 모두로 넓힌다."""
    await c.execute("SELECT pg_notify($1, $2)", EVENT_CHANNEL, event_payload(kind, incident_key, row_id))


@app.post("/api/incidents/{incident_key:path}/actions", status_code=201)
async def add_action(incident_key: str, body: ActionIn, request: Request):
    if "\x00" in incident_key:  # 키에 NUL 은 없다. DB 에 넘기면 오류가 500 이 된다(이슈 #62)
        raise HTTPException(404, "인시던트를 찾을 수 없습니다")
    user = require_role(request, "operator", "admin")
    if body.action in ADMIN_ACTIONS:
        require_role(request, "admin")
    if body.points is not None and body.action != "block_ip":
        raise HTTPException(400, "points 는 차단에만 씁니다")
    async with app.state.pool.acquire() as c:
        async with c.transaction():
            # 차단 목록 감사 트리거(sensor=audit)가 행위자를 여기서 읽는다. 트랜잭션이 끝나면 풀린다.
            # 넘기지 않으면 감사 행의 행위자가 'db:<DB 역할>' 로 남아 R201 이 사람별로 세지 못한다.
            await c.execute("SELECT set_config('opsloop.actor', $1, true)", user["u"])
            inc = await c.fetchrow(LOCK_INCIDENT, incident_key)
            if inc is None:
                raise HTTPException(404, "인시던트를 찾을 수 없습니다")
            inc_rule, inc_version = inc["rule_id"], inc["rule_version"]

            with_absorbed = body.include_absorbed and body.action in ("block_ip", "unblock_ip")
            # 요청한 행이 이 사건 출발지의 차단인가, 이 사건의 흡수 차단 한 행인가
            single = None
            if body.actor_ip is not None:
                if body.action != "unblock_ip":
                    raise HTTPException(400, "actor_ip 는 차단 해제에만 씁니다")
                same = bool(inc["actor_ip"]) and await c.fetchval("SELECT $1::inet = $2::inet",
                                                                   body.actor_ip, inc["actor_ip"])
                if not same:
                    if with_absorbed:
                        raise HTTPException(400, "흡수 차단 한 곳 해제와 함께 해제는 같이 쓸 수 없습니다")
                    single = body.actor_ip

            own_live = False
            if body.action == "unblock_ip" and single is None:
                # 확인 창을 연 뒤 만료·해제·재차단됐을 수 있다. 같은 행을 잠근 뒤 최신 상태를 검사한다.
                blocked = await c.fetchrow("""
                    SELECT incident_key, released_at, expires_at,
                           expires_at IS NULL OR expires_at > clock_timestamp() AS unexpired
                    FROM blocklist WHERE actor_ip = $1::inet FOR UPDATE""", inc["actor_ip"])
                own_live = bool(blocked and blocked["released_at"] is None and blocked["unexpired"]
                                and blocked["incident_key"] == incident_key)
                # 흡수 차단을 함께 풀 때는 이 출발지의 차단이 이미 풀렸어도 흡수 차단만 풀 수 있다(아래에서 0곳이면 409)
                if not own_live and not with_absorbed:
                    raise HTTPException(409, "차단이 만료·해제되었거나 근거 사건이 변경됐습니다. 목록을 새로 확인해 주세요")

            # 차단은 목록에 실제 상태로 남는다. 조치가 기록으로만 끝나지 않게. 만료 · 집행 정보 규칙은 BLOCK_SQL 에 있다.
            absorbed = None
            follow_expires = None
            narrowed = False
            if body.action == "block_ip" and inc["actor_ip"]:
                points = body.points or list(block_points.DEFAULT)
                # 이 출발지의 살아 있는 차단이 요청보다 넓으면(관문 빼기) 관리자만 한다. 지점만 좁히는 것은 감사 없는 부분 해제라
                # DB 트리거가 거부하므로, 같은 트랜잭션에서 풀고(released) 요청 지점으로 다시 건다(rearmed). 두 요청으로 나누면 사이에
                # 집행기 회차가 끼어 내부 방화벽에서도 풀린다. 행을 잠그고 보므로 확인 창을 연 뒤 바뀐 지점도 여기서 다시 본다
                current = await c.fetchrow(LIVE_POINTS_SQL, inc["actor_ip"])
                if current is not None and not set(points) >= set(current["points"]):
                    if user["r"] != "admin":
                        raise HTTPException(403, "살아 있는 차단의 관문 빼기는 관리자만 합니다")
                    await c.execute(RELEASE_FOR_NARROW_SQL, inc["actor_ip"], user["u"])
                    narrowed = True
                # 차단 금지 대역 · 대역 주소는 트리거가 거부한다(23514). 저장점 안에서 넣어, 거부되면 이 문장만 되돌리고
                # 걸린 대역을 읽어 400 과 사유로 돌려준다. 조치 행은 남지 않는다(바깥 트랜잭션도 되돌린다)
                try:
                    async with c.transaction():
                        await c.execute(BLOCK_SQL, inc["actor_ip"], body.note or "console", incident_key, user["u"],
                                        body.expires_hours, points, narrowed)
                except asyncpg.PostgresError as error:
                    if not is_refused(error):
                        raise
                    raise HTTPException(400, refused_text(inc["actor_ip"], error.constraint_name,
                                                          await exempt_of(c, inc["actor_ip"])))
                # 흡수된 출발지도 같은 만료 · 같은 지점으로 올린다(absorbed.py BLOCK_ABSORBED_SQL). 흡수를 쓰는 규칙이면 후속
                # 차단 약속을 남겨, 만료 전까지 새로 흡수되는 출발지도 콘솔이 같은 만료로 올린다. 약속이 살아 있으면 만료는
                # 늦추기만 하고 지점은 넓히기만 한다. 흡수 차단은 관문 빼기로 좁히지 않는다.
                # 첫 사건이 아니거나 흡수를 쓰지 않는 규칙이면 0곳이고 약속도 없다.
                if with_absorbed:
                    if await c.fetchval(ABSORBS_SQL, inc_version, inc_rule):
                        follow_expires = await c.fetchval(FOLLOW_UPSERT_SQL, incident_key, body.expires_hours,
                                                          user["u"], points)
                    expires = follow_expires or await c.fetchval(
                        "SELECT now() + make_interval(hours => $1)", body.expires_hours)
                    # 흡수 출발지는 차단 금지 대역(block_nets = 상수 + block_exempt)을 미리 빼고 넣는다. 그래도 트리거가
                    # 거부하면 그 사이 금지 대역이 바뀐 것이다. 이 요청 전체를 되돌리고 다시 해 달라고 한다
                    try:
                        absorbed = await block_absorbed(c, incident_key, inc["actor_ip"], user["u"], expires,
                                                        points=points)
                    except asyncpg.PostgresError as error:
                        if not is_refused(error):
                            raise
                        raise HTTPException(409, "흡수 출발지 가운데 차단 금지 대역 · 대역 주소가 있어 함께 차단하지 "
                                                 "못했습니다. 금지 대역이 방금 바뀌었을 수 있습니다. 다시 시도해 주세요")
                    absorbed = {k: absorbed[k] for k in ("blocked", "kept", "skipped", "skipped_total", "unblockable")}
                    absorbed["follow_expires_at"] = follow_expires.isoformat() if follow_expires else None
            elif body.action == "unblock_ip" and single is not None:
                # 흡수 차단 한 곳 해제. 이 사건의 살아 있는 흡수 차단 행만 푼다. 잘못 묶인 한 곳을 첫 사건 전체 해제 없이
                # 푼다. 사람이 푼 행(released_by)은 후속 차단 · 다시 함께 차단에서 빠진다(absorbed.py).
                row = await c.fetchrow("""
                    SELECT incident_key, reason, released_at,
                           expires_at IS NULL OR expires_at > clock_timestamp() AS unexpired
                    FROM blocklist WHERE actor_ip = $1::inet FOR UPDATE""", single)
                if not (row and row["released_at"] is None and row["unexpired"]
                        and row["incident_key"] == incident_key and row["reason"] == absorbed_reason_tag(incident_key)):
                    raise HTTPException(409, "이 사건의 살아 있는 흡수 차단이 아닙니다. 만료·해제됐거나 다른 사건의 "
                                             "차단입니다. 목록을 새로 확인해 주세요")
                await c.execute("UPDATE blocklist SET released_at = now(), released_by = $2 WHERE actor_ip = $1::inet",
                                single, user["u"])
                absorbed = {"released": 1, "actor_ip": single}
            elif body.action == "unblock_ip":
                # 살아 있는 차단만 푼다. 이미 풀린 차단을 다시 풀면 처음 해제한 시각과 사람이 덮인다
                if own_live:
                    changed = await c.execute(
                        "UPDATE blocklist SET released_at = now(), released_by = $2 "
                        "WHERE actor_ip = $1::inet AND released_at IS NULL "
                        "AND (expires_at IS NULL OR expires_at > clock_timestamp()) AND incident_key = $3",
                        inc["actor_ip"], user["u"], incident_key)
                    if changed != "UPDATE 1":
                        raise HTTPException(409, "차단 상태가 변경됐습니다. 목록을 새로 확인해 주세요")
                # 흡수 차단 함께 해제와 R201(차단 대량 해제, detector/rules_audit.json a1)
                #   풀리는 행마다 감사 트리거가 console.block.released 를 같은 사람 · 같은 시각으로 남기므로, 흡수 차단
                #   3곳 이상을 함께 풀면 R201(한 사람 10분 3건)이 뜬다. 의도된 동작이다. R201 은 건별 검토 없는 해제를
                #   다른 사람이 보게 하는 규칙이고, 첫 사건 하나의 판단으로 수십 곳을 푸는 것이 바로 그 경우다.
                #   흡수 차단을 R201 에서 빼면(사유 · 사건 키로 거르면) 흡수 차단을 걸었다 푸는 것으로 대량 해제를
                #   감출 수 있다. R201 인시던트의 항목에는 풀린 행마다 incident=<첫 사건 키> 가 남아, 판정자가 한 번의
                #   흡수 해제임을 확인하고 정상 업무면 양성 정탐으로 닫는다.
                #   평소의 해제 경로는 만료다. 흡수 차단은 콘솔 · triage 모두 만료가 있고(후속 차단도 약속의 만료),
                #   만료는 released_at 을 쓰지 않는다. 집행기가 관문에서 빼며 console.block.expired 를 한 번 남기고
                #   (이슈 #47) R201 은 이것을 세지 않는다. 함께 풀기는 첫 사건 판정을 뒤집는 등 흡수 전체가 틀렸을 때 쓴다.
                #   판정을 위협이 아닌 것으로 고치면 후속 차단은 저절로 멈추고(absorbed.FOLLOW_DUE_SQL) 이미 올린 곳은
                #   만료로 풀린다. 잘못 묶인 한 곳은 actor_ip 로 그 행만 푼다(위). 함께 풀면 후속 차단 약속도 거둔다.
                if with_absorbed:
                    released = await c.execute(RELEASE_ABSORBED_SQL, incident_key, user["u"],
                                               absorbed_reason_tag(incident_key))
                    stopped = await c.execute(FOLLOW_RELEASE_SQL, incident_key, user["u"])
                    absorbed = {"released": int(released.split()[-1]), "follow_stopped": stopped == "UPDATE 1"}
                    if not own_live and absorbed["released"] == 0 and not absorbed["follow_stopped"]:
                        raise HTTPException(409, "풀 차단이 없습니다. 이 출발지와 흡수 차단이 이미 만료·해제됐거나 "
                                                 "근거 사건이 변경됐습니다. 목록을 새로 확인해 주세요")

            # 조치 기록. 흡수 출발지를 함께 다룬 조치는 이력에서 알아보게 메모 끝에 곳 수를 붙인다.
            note = body.note
            tag = None
            if absorbed and "actor_ip" in absorbed:
                tag = f"[흡수 차단 {absorbed['actor_ip']} 한 곳 해제]"
            elif absorbed and "released" in absorbed and (absorbed["released"] or absorbed["follow_stopped"]):
                tag = f"[흡수 차단 {absorbed['released']}곳 함께 해제" + (" · 후속 차단 중지" if absorbed["follow_stopped"]
                                                                   else "") + "]"
            elif absorbed and "blocked" in absorbed and (follow_expires or any(
                    absorbed[k] for k in ("blocked", "kept", "skipped_total", "unblockable"))):
                tag = absorbed_note(absorbed)
                if follow_expires:
                    tag = tag[:-1] + " · 만료 전 새 흡수도 차단]"
            if narrowed:
                tag = "[관문 빼기 · 해제 뒤 다시 걸기]" + (f" {tag}" if tag else "")
            if tag:
                note = f"{note} {tag}" if note else tag
            rec = await c.fetchrow("""
                INSERT INTO actions (incident_key, action, operator, note)
                VALUES ($1, $2, $3, $4)
                RETURNING id, action, operator, note, created_at""",
                incident_key, body.action, user["u"], note)

            new_status = ACTION_STATUS.get(body.action)
            if new_status:
                await c.execute("UPDATE incidents SET status = $1 WHERE incident_key = $2",
                                new_status, incident_key)
            await notify_event(c, "action.created", incident_key, rec["id"])

    payload = row_to_dict(rec) | {"incident_key": incident_key}
    if absorbed is not None:
        payload["absorbed"] = absorbed
    return payload


@app.post("/api/incidents/{incident_key:path}/verdict", status_code=201)
async def add_verdict(incident_key: str, body: VerdictIn, request: Request):
    if "\x00" in incident_key:  # 키에 NUL 은 없다. DB 에 넘기면 오류가 500 이 된다(이슈 #62)
        raise HTTPException(404, "인시던트를 찾을 수 없습니다")
    user = require_role(request, "operator", "admin")
    async with app.state.pool.acquire() as c:
        async with c.transaction():
            # 사건 행을 먼저 잠근다(LOCK_INCIDENT). 겹친 판정 · 조치는 이 판정이 커밋될 때까지 기다린다.
            exists = await c.fetchrow(LOCK_INCIDENT, incident_key)
            if not exists:
                raise HTTPException(404, "인시던트를 찾을 수 없습니다")
            rec = await c.fetchrow("""
                INSERT INTO verdicts (incident_key, verdict, reason, observed_value, operator,
                                      proposed, decision_seconds)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id, verdict, reason, observed_value, operator, proposed,
                          decision_seconds, created_at""",
                incident_key, body.verdict, body.reason, body.observed_value, user["u"],
                body.proposed, body.decision_seconds)
            # 판정이 곧 종결이다. 판정 없이 종결되는 경로를 두지 않는다.
            await c.execute("UPDATE incidents SET status = 'resolved' WHERE incident_key = $1",
                            incident_key)
            await notify_event(c, "verdict.created", incident_key, rec["id"])

    return row_to_dict(rec) | {"incident_key": incident_key}


@app.get("/api/blocklist")
async def blocklist(active_only: bool = True):
    q = """SELECT host(actor_ip) actor_ip, reason, incident_key,
                  created_at, expires_at, released_at, method, requested_by,
                  enforced_at, enforce_note, enforcement, released_by, points, now() AS checked_at
           FROM blocklist {} ORDER BY created_at DESC, actor_ip"""
    q = q.format("WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > now())" if active_only else "")
    async with app.state.pool.acquire() as c:
        rows = await c.fetch(q)
    return [row_to_dict(r) for r in rows]


# ----------------------------------------------------------------------
#  실시간 통보
# ----------------------------------------------------------------------

# 열린 실시간 연결의 세션을 다시 보는 간격(초, 이슈 #59). 비활성 · 강등된 계정의 화면이 이 안에 끊긴다
WS_RECHECK_SECONDS = 30
# 닫힘 코드. 1008 은 세션이 없다는 뜻이라 화면(live.ts)이 다시 잇지 않고 로그인으로 간다. 1011(서버 오류)은 다시 잇는다
WS_UNAUTHORIZED = 1008
WS_SERVER_ERROR = 1011


async def ws_session_valid(token: str) -> bool:
    """웹소켓 쿠키가 지금도 유효한가(서명 · 만료 · 계정 상태). DB 오류는 그대로 던진다. 무효(1008)로 보지 않는다."""
    session = auth.read(token)
    if session is None:
        return False
    return auth.session_valid(session, await auth.lookup(app.state.pool, session["u"]))


async def ws_recheck(ws: WebSocket, token: str):
    """연결 하나의 점검 작업. WS_RECHECK_SECONDS 마다 쿠키 만료 · 계정 상태를 다시 보고 무효면 1008 로 닫는다.

    DB 오류면 그 회차는 건너뛴다. 1008 로 닫으면 화면이 새로고침 전까지 다시 잇지 않으므로, DB 가 잠깐 흔들린 것으로
    실시간을 끊지 않는다. 연결이 끝나면 ws_endpoint 가 이 작업을 취소한다.
    """
    while True:
        await asyncio.sleep(WS_RECHECK_SECONDS)
        try:
            valid = await ws_session_valid(token)
        except Exception as exc:
            print(f"[ws] 세션 점검을 건너뜀 (DB 오류): {type(exc).__name__}: {exc}", flush=True)
            continue
        if not valid:
            await hub.leave(ws)
            try:
                await ws.close(code=WS_UNAUTHORIZED)
            except Exception:   # 그 사이 화면이 먼저 끊었다
                pass
            return


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # 실시간 보드도 인증 대상이다. 미들웨어는 웹소켓 연결을 거치지 않으므로
    # 여기서 직접 본다. 요청과 같이 계정 상태까지 보고(이슈 #59), 연결 뒤에도 ws_recheck 가 주기적으로 다시 본다.
    # 세션이 없으면 수락한 뒤 1008 로 닫는다(이슈 #43). 수락 전에 닫으면 핸드셰이크가 403 으로 끝나 브라우저는 1006 만
    # 받고, 화면(live.ts)의 1008 분기가 돌지 않아 로그인으로 가지 않고 다시 잇기만 되풀이한다(2026-09-25 74분 · 403 292번).
    # 계정 확인 중 DB 오류면 1011 로 닫는다. 화면이 다시 잇는다. 1008 이면 세션이 멀쩡해도 실시간이 멈춘다.
    # 출처가 다른 핸드셰이크는 그대로 수락 전에 막는다(web.OriginCheck). 같은 출처 화면에는 생기지 않는 일이다.
    token = ws.cookies.get(auth.COOKIE, "")
    try:
        valid = await ws_session_valid(token)
    except Exception as exc:
        print(f"[ws] 계정 확인 실패: {type(exc).__name__}: {exc}", flush=True)
        await ws.accept()
        await ws.close(code=WS_SERVER_ERROR)
        return
    if not valid:
        await ws.accept()
        await ws.close(code=WS_UNAUTHORIZED)
        return
    await hub.join(ws)
    recheck = asyncio.create_task(ws_recheck(ws, token))
    try:
        # 어느 콘솔에 붙었는지 화면 연결 표시에 보인다(live.CONSOLE_NAME, 세션 뒤에서만 나간다).
        await ws.send_json({"type": "hello", "data": {"channel": NOTIFY_CHANNEL, "console": live.CONSOLE_NAME}})
        while True:
            # 클라이언트가 보내는 것은 없다. 끊김 감지를 위해 수신만 대기한다.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        recheck.cancel()
        await hub.leave(ws)
