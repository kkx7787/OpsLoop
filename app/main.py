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
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal, Optional

import asyncpg
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

import auth
import web

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

    try:
        yield
    finally:
        await listener.remove_listener(NOTIFY_CHANNEL, on_notify)
        await listener.close()
        await app.state.pool.close()


app = FastAPI(title="OpsLoop API", version="0.1.0", lifespan=lifespan)

# 화면 번들 · /api/me (web.py). 미들웨어는 나중에 붙인 것이 바깥이므로 세션 검사보다 먼저 붙여
# 세션 검사 안쪽에 둔다. 화면 번들도 로그인 뒤에만 나간다.
web.serve(app)


OPEN_PATHS = ("/health", "/login", "/logout", "/docs", "/openapi.json")

# 규칙 조건과 판정 근거가 겹치는 규칙. 여기서 나오는 위협 판정은 규칙의
# 정확성을 증명하지 않는다. 같은 것을 두 번 센 것이다. detector/triage.py 와
# 같은 판단이며, 콘솔도 같은 경고를 보여야 판정자가 같은 기준으로 본다.
CIRCULAR = {
    "R002": "규칙 조건이 '로그인 성공 + 명령 실행'이고 판정 기준의 위협 조건도 같다",
    "R003": "규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다",
    "R004": "규칙 조건이 경유 시도이고 판정 기준의 위협 조건도 같다",
}

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


def require_role(request: Request, *roles: str) -> dict:
    """되돌리는 행위와 기준을 바꾸는 행위를 나눈다 (화면 설계 9장)."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="인증이 필요합니다")
    if user["r"] not in roles:
        raise HTTPException(status_code=403, detail=f"권한이 없습니다 ({user['r']})")
    return user


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
    }[sort]
    # 최근 판정 하나만 붙인다. 재판정이 생겨도 목록에는 마지막 판단이 보여야 한다.
    base = f"""FROM incidents i
        LEFT JOIN LATERAL (
            SELECT verdict FROM verdicts WHERE incident_key = i.incident_key
            ORDER BY created_at DESC LIMIT 1) v ON true
        {w}"""
    params.extend([limit, offset])

    async with app.state.pool.acquire() as c:
        total = await c.fetchval(f"SELECT count(*) {base}", *params[:-2])
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
            "items": [row_to_dict(r) for r in rows]}


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
            "SELECT id, verdict, reason, observed_value, operator, created_at FROM verdicts "
            "WHERE incident_key = $1 ORDER BY created_at", incident_key)
        # 같은 출발지의 다른 인시던트. 관제자가 제일 먼저 궁금해하는 것.
        related = await c.fetch("""
            SELECT incident_key, rule_id, severity, first_ts, signal_count, status
            FROM incidents
            WHERE actor_ip = $1::inet AND incident_key <> $2
            ORDER BY first_ts DESC LIMIT 20""", inc["actor_ip"], incident_key)

        actor = inc["actor_ip"]
        window = (inc["first_ts"], inc["last_ts"])

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
    d["circular"] = CIRCULAR.get(inc["rule_id"])
    return d


@app.get("/api/stats/summary")
async def summary():
    async with app.state.pool.acquire() as c:
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
            "SELECT count(*) FROM blocklist WHERE released_at IS NULL")

    return {
        "open_by_severity": {r["severity"]: r["count"] for r in by_sev},
        "by_status": {r["status"]: r["count"] for r in by_status},
        "daily": [{"date": r["d"], "count": r["count"]} for r in daily],
        "top_actors": [dict(r) for r in top],
        "events": ev["events"],
        "actors": ev["actors"],
        "latest_event": ev["latest"].isoformat() if ev["latest"] else None,
        "blocked_ips": blocked,
    }


@app.get("/api/rules/quality")
async def rule_quality():
    async with app.state.pool.acquire() as c:
        rows = await c.fetch("SELECT * FROM rule_quality ORDER BY rule_id, rule_version")
    return [dict(r) for r in rows]


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
                "SELECT host(actor_ip) actor_ip FROM incidents WHERE incident_key = $1",
                incident_key)
            if inc is None:
                raise HTTPException(404, "인시던트를 찾을 수 없습니다")

            rec = await c.fetchrow("""
                INSERT INTO actions (incident_key, action, operator, note)
                VALUES ($1, $2, $3, $4)
                RETURNING id, action, operator, note, created_at""",
                incident_key, body.action, user["u"], body.note)

            new_status = ACTION_STATUS.get(body.action)
            if new_status:
                await c.execute("UPDATE incidents SET status = $1 WHERE incident_key = $2",
                                new_status, incident_key)

            # 차단은 목록에 실제 상태로 남는다. 조치가 기록으로만 끝나지 않게.
            # 살아 있는 차단에 다시 차단을 걸 때 만료를 앞당기지 않는다. 앞당기면 차단 조치로 차단을 줄이는 셈이고
            # (감사에는 shortened 로 남아 R201 이 센다), 만료 없는 차단(triage)도 24시간 뒤에 풀린다. 풀린 차단은 새로 건다.
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
            elif body.action == "unblock_ip" and inc["actor_ip"]:
                # 살아 있는 차단만 푼다. 이미 풀린 차단을 다시 풀면 처음 해제한 시각과 사람이 덮인다
                await c.execute(
                    "UPDATE blocklist SET released_at = now(), released_by = $2 "
                    "WHERE actor_ip = $1::inet AND released_at IS NULL",
                    inc["actor_ip"], user["u"])

    payload = row_to_dict(rec) | {"incident_key": incident_key}
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
                  created_at, expires_at, released_at
           FROM blocklist {} ORDER BY created_at DESC"""
    q = q.format("WHERE released_at IS NULL" if active_only else "")
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