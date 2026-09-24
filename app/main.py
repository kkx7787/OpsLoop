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
"저장은 됐는데 알림은 안 갔다"는 구간이 생기지 않는다.
"""

import asyncio
import ipaddress
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal, Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

import auth
import web
from proposals import CIRCULAR_RULES, SSH_RULES, propose
from dashboard import dashboard_metrics
from access import require_role
from operations import router as operations_router
from notify import router as notify_router
from notifier import Notifier
from absorbed import (ABSORBED_STATE_SQL, FOLLOW_RELEASE_SQL, FOLLOW_STATE_SQL, FOLLOW_UPSERT_SQL, NO_BLOCK_NETS,
                      RELEASE_ABSORBED_SQL, UNBLOCKED_AFTER_VERDICT_SQL, AbsorbedFollower, absorbed_note,
                      absorbed_reason_tag, block_absorbed)

DATABASE_URL = os.environ.get("DATABASE_URL")
NOTIFY_CHANNEL = "opsloop_incident"

ACTIONS = Literal["block_ip", "unblock_ip", "acknowledge", "suppress_rule", "escalate", "note"]
# 판정값 다섯 개. 정확히 탐지했으나 악의가 없는 경우(양성 정탐)와 근거가
# 부족한 경우(미결)를 오탐과 섞으면 규칙 정확도가 실제와 달라진다.
VERDICTS = Literal["threat", "non_actionable", "false_positive",
                   "benign_positive", "undetermined"]
SEVERITIES = Literal["critical", "high", "medium", "low"]
STATUSES = Literal["open", "acknowledged", "in_progress", "resolved", "suppressed"]


class Hub:
    """접속한 콘솔들에게 인시던트를 밀어준다."""

    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def join(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.clients.add(ws)

    async def leave(self, ws: WebSocket):
        async with self.lock:
            self.clients.discard(ws)

    async def broadcast(self, payload: dict):
        async with self.lock:
            targets = list(self.clients)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self.lock:
                for ws in dead:
                    self.clients.discard(ws)


hub = Hub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL 이 설정되지 않았습니다")

    app.state.pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)

    # LISTEN 전용 연결. 풀에서 빌린 연결로 LISTEN 하면 반납될 때 끊긴다.
    listener = await asyncpg.connect(DATABASE_URL)

    def on_notify(_conn, _pid, _channel, payload):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return
        asyncio.create_task(hub.broadcast({"type": "incident.created", "data": data}))

    await listener.add_listener(NOTIFY_CHANNEL, on_notify)
    app.state.listener = listener

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
        await listener.remove_listener(NOTIFY_CHANNEL, on_notify)
        await listener.close()
        await app.state.pool.close()


app = FastAPI(title="OpsLoop API", version="0.1.0", lifespan=lifespan)

# 화면 번들 · /api/me (web.py). 미들웨어는 나중에 붙인 것이 바깥이므로 세션 검사보다 먼저 붙여
# 세션 검사 안쪽에 둔다. 화면 번들도 로그인 뒤에만 나간다.
web.serve(app)
app.include_router(operations_router)
app.include_router(notify_router)


OPEN_PATHS = ("/health", "/login", "/logout", "/docs", "/openapi.json")

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
    """
    path = request.url.path
    if path in OPEN_PATHS or path.startswith("/ws"):
        return await call_next(request)

    session = auth.read(request.cookies.get(auth.COOKIE, ""))
    if session is None:
        if path.startswith("/api"):
            return JSONResponse({"detail": "인증이 필요합니다"}, status_code=401)
        return web.to_login(request)

    request.state.user = session
    return await call_next(request)


# 보안 헤더 · CORS · 출처 확인 (web.py). 세션 검사보다 나중에 붙여 그 바깥에 둔다.
web.guard(app)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return web.login_page(next_path=request.query_params.get("next"))


@app.post("/login")
async def login(request: Request):
    form = await auth.form_fields(request)
    username = str(form.get("username", ""))[:128]
    password = str(form.get("password", ""))[:256]
    # 로그인 뒤 돌아갈 곳. 같은 출처의 상대 경로만 받는다(열린 리디렉션 금지).
    next_path = web.safe_next(form.get("next"))

    user = await auth.authenticate(app.state.pool, username, password)
    if user is None:
        await auth.log_event(app.state.pool, request, "console.login.failed",
                             username=username, status=401)
        return web.login_page(error=True, next_path=next_path, username=username,
                              status_code=401)

    token = auth.issue(user["username"], user["role"])
    await auth.log_event(app.state.pool, request, "console.login.success",
                         username=user["username"], status=302, session=token[:17])
    response = RedirectResponse(next_path, status_code=302)
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="lax",
                        max_age=auth.SESSION_HOURS * 3600)
    return response


@app.post("/logout")
async def logout(request: Request):
    user = getattr(request.state, "user", None)
    await auth.log_event(app.state.pool, request, "console.logout",
                         username=user["u"] if user else None, status=302)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(auth.COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
async def shell(request: Request):
    user = request.state.user
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>OpsLoop</title>
<style>body{{font-family:system-ui,sans-serif;margin:0;background:#f4f5f7;color:#232f3e}}
 header{{background:#232f3e;color:#fff;padding:12px 20px;display:flex;justify-content:space-between}}
 main{{padding:24px}}</style></head><body>
<header><strong>OpsLoop</strong><span>{user['u']} · {user['r']}
 <form method="post" action="/logout" style="display:inline">
 <button style="background:none;border:0;color:#9dc3e6;cursor:pointer">로그아웃</button></form>
</span></header>
<main><p>화면 구현 예정 (WBS 3.6.2~3.6.4)</p></main></body></html>"""


def row_to_dict(r: asyncpg.Record) -> dict:
    out = {}
    for k, v in dict(r).items():
        if isinstance(v, datetime):
            out[k] = v.astimezone(timezone.utc).isoformat()
        else:
            out[k] = v
    return out


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------

@app.get("/health")
async def health():
    async with app.state.pool.acquire() as c:
        await c.fetchval("SELECT 1")
    return {"status": "ok", "clients": len(hub.clients)}


@app.get("/api/incidents")
async def list_incidents(
    status: Optional[STATUSES] = None,
    severity: Optional[SEVERITIES] = None,
    rule_id: Optional[str] = None,
    rule_version: Optional[str] = None,
    actor_ip: Optional[str] = None,
    target: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    judged: Optional[bool] = None,
    sort: Literal["pending", "severity", "recent"] = "pending",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """기본 정렬은 미판정 경과 시간이다. 심각도순이 아니다.

    판정이 사람의 일인 이상 가장 오래 밀린 건이 가장 위험하다. 심각도순으로
    두면 낮은 등급의 오래된 건이 영영 아래에 깔린다. (화면 설계 4장)
    """
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

    w = ("WHERE " + " AND ".join(where)) if where else ""
    order = {
        "pending":  "(v.verdict IS NULL) DESC, i.first_ts ASC",
        "severity": "CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 ELSE 3 END, i.first_ts DESC",
        "recent":   "i.first_ts DESC",
    }[sort] + ", i.incident_key ASC"  # 같은 시각·등급도 페이지 사이 순서가 바뀌지 않게 한다.
    # 최근 판정 하나만 붙인다. 재판정이 생겨도 목록에는 마지막 판단이 보여야 한다.
    base = f"""FROM incidents i
        LEFT JOIN LATERAL (
            SELECT verdict FROM verdicts WHERE incident_key = i.incident_key
            ORDER BY created_at DESC, id DESC LIMIT 1) v ON true
        {w}"""
    params.extend([limit, offset])

    async with app.state.pool.acquire() as c:
        total = await c.fetchval(f"SELECT count(*) {base}", *params[:-2])
        # 필터 선택지는 필터링된 첫 쪽에 없는 규칙도 포함한다. 별도 API를 요구하지 않는다.
        rules = await c.fetch("""
            SELECT DISTINCT ON (rule_id) rule_id, rule_name FROM incidents
            ORDER BY rule_id, last_ts DESC, incident_key""")
        rows = await c.fetch(f"""
            SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity,
                   host(i.actor_ip) AS actor_ip, i.target, i.first_ts, i.last_ts,
                   i.signal_count, i.session_count, i.status, i.created_at,
                   v.verdict,
                   extract(epoch FROM (now() - i.first_ts))::bigint AS pending_seconds
            {base}
            ORDER BY {order}
            LIMIT ${len(params) - 1} OFFSET ${len(params)}""", *params)

    return {"total": total, "limit": limit, "offset": offset,
            "items": [row_to_dict(r) for r in rows],
            "rules": [row_to_dict(r) for r in rules]}


@app.get("/api/incidents/{incident_key:path}")
async def get_incident(incident_key: str):
    async with app.state.pool.acquire() as c:
        inc = await c.fetchrow("""
            SELECT incident_key, rule_id, rule_version, rule_name, severity,
                   host(actor_ip) AS actor_ip, target, first_ts, last_ts,
                   signal_count, session_count, evidence, status, created_at
            FROM incidents WHERE incident_key = $1""", incident_key)
        if inc is None:
            raise HTTPException(404, "인시던트를 찾을 수 없습니다")

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
        blocked = await c.fetchrow("""
            SELECT reason, method, created_at, expires_at, released_at, enforced_at
            FROM blocklist WHERE actor_ip = $1::inet""", actor) if actor else None

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
                                          actor, NO_BLOCK_NETS, 20) if actor else None
        follow = await c.fetchrow(FOLLOW_STATE_SQL, incident_key) if actor else None
        absorbs = await c.fetchval(ABSORBS_SQL, inc["rule_version"], inc["rule_id"]) if actor else False

        # ④ 원문. 요약이 아니라 근거가 된 원본 줄이다.
        raw = await c.fetch(f"""
            SELECT ts, sensor, eventid, session, username, password IS NOT NULL AS has_password,
                   input, url, shasum, http_method, http_status, user_agent, message
            FROM events
            WHERE src_ip = $1::inet
              AND ts BETWEEN $2::timestamptz - interval '{WINDOW_BEFORE}' AND $3::timestamptz + interval '{WINDOW_AFTER}'
            ORDER BY ts LIMIT 300""", actor, *window) if actor else []

    d = row_to_dict(inc)
    d["evidence"] = json.loads(inc["evidence"]) if inc["evidence"] else None
    d["actions"] = [row_to_dict(r) for r in actions]
    d["verdicts"] = [row_to_dict(r) for r in verdicts]
    d["related"] = [row_to_dict(r) for r in related]
    d["behavior"] = [row_to_dict(r) for r in behavior]
    d["actor"] = {
        "history": row_to_dict(history) if history else None,
        "rules": [row_to_dict(r) for r in rules_hit],
        "blocked": row_to_dict(blocked) if blocked else None,
    }
    # 비밀번호 원문은 화면에 내지 않는다. 타인의 실제 자격증명일 수 있다.
    d["raw"] = [row_to_dict(r) for r in raw]
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
        # 규칙이 흡수를 쓰는가(흡수 기록이 아직 없어도 함께 차단 · 후속 차단을 고를 수 있다) · 살아 있는 후속 차단 약속
        "absorbs": bool(absorbs),
        "follow": row_to_dict(follow) if follow else None,
    }
    d["circular"] = CIRCULAR.get(inc["rule_id"])
    d["proposal"] = propose(inc["rule_id"], {r["eventid"]: r["n"] for r in counts}, covered)
    return d


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
        top = await c.fetch("""
            SELECT host(actor_ip) ip, count(*) n, max(severity) sev
            FROM incidents WHERE actor_ip IS NOT NULL
            GROUP BY 1 ORDER BY n DESC LIMIT 10""")
        ev = await c.fetchrow("""
            SELECT count(*) events, count(DISTINCT src_ip) actors, max(ts) latest
            FROM events WHERE provenance = 'real'""")
        blocked = await c.fetchval(
            "SELECT count(*) FROM blocklist WHERE released_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > $1)", as_of)
        # 판정 뒤에 흡수됐는데 차단이 없는 출발지(absorbed.py). 흡수는 첫 사건이 판정 · 차단된 뒤에도 붙고 알림이
        # 없으므로, 함께 차단을 고르지 않았으면 여기서만 드러난다. 흡수 기록 표가 없는 DB(v3 전)에서는 생략한다
        unblocked = await c.fetchrow(UNBLOCKED_AFTER_VERDICT_SQL, NO_BLOCK_NETS) \
            if await c.fetchval("SELECT to_regclass('incident_absorbed') IS NOT NULL") else None

    return {
        **metrics,
        "open_by_severity": {r["severity"]: r["count"] for r in by_sev},
        "by_status": {r["status"]: r["count"] for r in by_status},
        "daily": [{"date": r["d"], "count": r["count"]} for r in daily],
        "top_actors": [dict(r) for r in top],
        "events": ev["events"],
        "actors": ev["actors"],
        "latest_event": ev["latest"].isoformat() if ev["latest"] else None,
        "blocked_ips": blocked,
        **({"absorbed_unblocked": dict(unblocked)} if unblocked else {}),
    }


# ----------------------------------------------------------------------
#  조치와 판정 - 폐루프의 입력
# ----------------------------------------------------------------------

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

    @field_validator("actor_ip")
    @classmethod
    def _ip(cls, v):
        if v is None:
            return v
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("actor_ip 는 IP 주소여야 합니다")


class VerdictIn(BaseModel):
    verdict: VERDICTS
    reason: Optional[str] = Field(default=None, max_length=1000)
    observed_value: Optional[float] = None
    # 뒤집힘 비율과 판정 비용을 재려면 제안값과 소요 시간이 판정과 함께 남아야 한다.
    proposed: Optional[VERDICTS] = None
    decision_seconds: Optional[int] = Field(default=None, ge=0, le=86400)


# 조치가 인시던트 상태를 어떻게 바꾸는지. 규칙을 코드 한 곳에 모아둔다.
# 차단은 종결이 아니다. 종결은 판정이 기록될 때만 일어난다.
ACTION_STATUS = {
    "acknowledge": "acknowledged",
    "block_ip": "in_progress",
    "suppress_rule": "suppressed",
}

# 되돌리는 행위와 기준을 바꾸는 행위는 admin 만 한다.
ADMIN_ACTIONS = {"unblock_ip", "suppress_rule"}


@app.post("/api/incidents/{incident_key:path}/actions", status_code=201)
async def add_action(incident_key: str, body: ActionIn, request: Request):
    user = require_role(request, "operator", "admin")
    if body.action in ADMIN_ACTIONS:
        require_role(request, "admin")
    async with app.state.pool.acquire() as c:
        async with c.transaction():
            # 차단 목록 감사 트리거(sensor=audit)가 행위자를 여기서 읽는다. 트랜잭션이 끝나면 풀린다.
            # 넘기지 않으면 감사 행의 행위자가 'db:<DB 역할>' 로 남아 R201 이 사람별로 세지 못한다.
            await c.execute("SELECT set_config('opsloop.actor', $1, true)", user["u"])
            inc = await c.fetchrow(
                "SELECT host(actor_ip) actor_ip, rule_id, rule_version FROM incidents WHERE incident_key = $1",
                incident_key)
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

            # 차단은 목록에 실제 상태로 남는다. 조치가 기록으로만 끝나지 않게.
            # 살아 있는 차단에 다시 차단을 걸 때 만료를 앞당기지 않는다. 앞당기면 차단 조치로 차단을 줄이는 셈이고
            # (감사에는 shortened 로 남아 R201 이 센다), 만료 없는 차단(triage)도 24시간 뒤에 풀린다. 풀린 차단은 새로 건다.
            absorbed = None
            follow_expires = None
            if body.action == "block_ip" and inc["actor_ip"]:
                await c.execute("""
                    INSERT INTO blocklist (actor_ip, reason, incident_key, requested_by, expires_at)
                    VALUES ($1::inet, $2, $3, $4, now() + make_interval(hours => $5))
                    ON CONFLICT (actor_ip) DO UPDATE
                    SET reason = EXCLUDED.reason, incident_key = EXCLUDED.incident_key,
                        requested_by = EXCLUDED.requested_by,
                        expires_at = CASE WHEN blocklist.released_at IS NULL
                                           AND (blocklist.expires_at IS NULL
                                                OR blocklist.expires_at > EXCLUDED.expires_at)
                                          THEN blocklist.expires_at ELSE EXCLUDED.expires_at END,
                        method = NULL, enforced_at = NULL, enforce_note = NULL,
                        released_at = NULL, released_by = NULL, created_at = now()""",
                    inc["actor_ip"], body.note or "console", incident_key, user["u"],
                    body.expires_hours)
                # 흡수된 출발지도 같은 만료로 올린다(absorbed.py BLOCK_ABSORBED_SQL). 흡수를 쓰는 규칙이면 후속 차단 약속을
                # 남겨, 만료 전까지 새로 흡수되는 출발지도 콘솔이 같은 만료로 올린다. 약속이 살아 있으면 만료는 늦추기만 한다.
                # 첫 사건이 아니거나 흡수를 쓰지 않는 규칙이면 0곳이고 약속도 없다.
                if with_absorbed:
                    if await c.fetchval(ABSORBS_SQL, inc_version, inc_rule):
                        follow_expires = await c.fetchval(FOLLOW_UPSERT_SQL, incident_key, body.expires_hours,
                                                          user["u"])
                    expires = follow_expires or await c.fetchval(
                        "SELECT now() + make_interval(hours => $1)", body.expires_hours)
                    absorbed = await block_absorbed(c, incident_key, inc["actor_ip"], user["u"], expires)
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
                #   만료는 행을 고치지 않아 감사 이벤트가 없다(R201 과 무관). 함께 풀기는 첫 사건 판정을 뒤집는 등 흡수
                #   전체가 틀렸을 때 쓴다. 잘못 묶인 한 곳은 actor_ip 로 그 행만 푼다(위). 함께 풀면 후속 차단 약속도 거둔다.
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

    payload = row_to_dict(rec) | {"incident_key": incident_key}
    if absorbed is not None:
        payload["absorbed"] = absorbed
    await hub.broadcast({"type": "action.created", "data": payload})
    return payload


@app.post("/api/incidents/{incident_key:path}/verdict", status_code=201)
async def add_verdict(incident_key: str, body: VerdictIn, request: Request):
    user = require_role(request, "operator", "admin")
    async with app.state.pool.acquire() as c:
        async with c.transaction():
            exists = await c.fetchval(
                "SELECT 1 FROM incidents WHERE incident_key = $1", incident_key)
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

    payload = row_to_dict(rec) | {"incident_key": incident_key}
    await hub.broadcast({"type": "verdict.created", "data": payload})
    return payload


@app.get("/api/blocklist")
async def blocklist(active_only: bool = True):
    q = """SELECT host(actor_ip) actor_ip, reason, incident_key,
                  created_at, expires_at, released_at, method, requested_by,
                  enforced_at, enforce_note, released_by, now() AS checked_at
           FROM blocklist {} ORDER BY created_at DESC, actor_ip"""
    q = q.format("WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > now())" if active_only else "")
    async with app.state.pool.acquire() as c:
        rows = await c.fetch(q)
    return [row_to_dict(r) for r in rows]


# ----------------------------------------------------------------------
#  실시간 통보
# ----------------------------------------------------------------------

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # 실시간 보드도 인증 대상이다. 미들웨어는 웹소켓 연결을 거치지 않으므로
    # 여기서 직접 본다.
    if auth.read(ws.cookies.get(auth.COOKIE, "")) is None:
        await ws.close(code=1008)
        return
    await hub.join(ws)
    try:
        await ws.send_json({"type": "hello", "data": {"channel": NOTIFY_CHANNEL}})
        while True:
            # 클라이언트가 보내는 것은 없다. 끊김 감지를 위해 수신만 대기한다.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await hub.leave(ws)
