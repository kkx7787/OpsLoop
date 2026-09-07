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
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL")
NOTIFY_CHANNEL = "opsloop_incident"

ACTIONS = Literal["block_ip", "unblock_ip", "acknowledge", "suppress_rule", "escalate", "note"]
VERDICTS = Literal["threat", "non_actionable", "false_positive"]
SEVERITIES = Literal["critical", "high", "medium", "low"]
STATUSES = Literal["open", "acknowledged", "resolved", "suppressed"]


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

# 콘솔은 개발 중 다른 포트에서 돈다. 운영에서는 실제 오리진으로 좁힌다.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    where, params = [], []

    def add(clause, value):
        params.append(value)
        where.append(clause.format(n=len(params)))

    if status:       add("status = ${n}", status)
    if severity:     add("severity = ${n}", severity)
    if rule_id:      add("rule_id = ${n}", rule_id)
    if rule_version: add("rule_version = ${n}", rule_version)
    if actor_ip:     add("actor_ip = ${n}::inet", actor_ip)
    if since:        add("first_ts >= ${n}", since)
    if until:        add("first_ts < ${n}", until)

    w = ("WHERE " + " AND ".join(where)) if where else ""
    params.extend([limit, offset])

    async with app.state.pool.acquire() as c:
        total = await c.fetchval(f"SELECT count(*) FROM incidents {w}", *params[:-2])
        rows = await c.fetch(f"""
            SELECT incident_key, rule_id, rule_version, rule_name, severity,
                   host(actor_ip) AS actor_ip, first_ts, last_ts,
                   signal_count, session_count, status, created_at
            FROM incidents {w}
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END,
                     first_ts DESC
            LIMIT ${len(params) - 1} OFFSET ${len(params)}""", *params)

    return {"total": total, "limit": limit, "offset": offset,
            "items": [row_to_dict(r) for r in rows]}


@app.get("/api/incidents/{incident_key:path}")
async def get_incident(incident_key: str):
    async with app.state.pool.acquire() as c:
        inc = await c.fetchrow("""
            SELECT incident_key, rule_id, rule_version, rule_name, severity,
                   host(actor_ip) AS actor_ip, first_ts, last_ts,
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

    d = row_to_dict(inc)
    d["evidence"] = json.loads(inc["evidence"]) if inc["evidence"] else None
    d["actions"] = [row_to_dict(r) for r in actions]
    d["verdicts"] = [row_to_dict(r) for r in verdicts]
    d["related"] = [row_to_dict(r) for r in related]
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

class ActionIn(BaseModel):
    action: ACTIONS
    operator: str = Field(default="operator", max_length=64)
    note: Optional[str] = Field(default=None, max_length=1000)


class VerdictIn(BaseModel):
    verdict: VERDICTS
    reason: Optional[str] = Field(default=None, max_length=1000)
    observed_value: Optional[float] = None
    operator: str = Field(default="operator", max_length=64)


# 조치가 인시던트 상태를 어떻게 바꾸는지. 규칙을 코드 한 곳에 모아둔다.
ACTION_STATUS = {
    "acknowledge": "acknowledged",
    "block_ip": "resolved",
    "suppress_rule": "suppressed",
}


@app.post("/api/incidents/{incident_key:path}/actions", status_code=201)
async def add_action(incident_key: str, body: ActionIn):
    async with app.state.pool.acquire() as c:
        async with c.transaction():
            inc = await c.fetchrow(
                "SELECT host(actor_ip) actor_ip FROM incidents WHERE incident_key = $1",
                incident_key)
            if inc is None:
                raise HTTPException(404, "인시던트를 찾을 수 없습니다")

            rec = await c.fetchrow("""
                INSERT INTO actions (incident_key, action, operator, note)
                VALUES ($1, $2, $3, $4)
                RETURNING id, action, operator, note, created_at""",
                incident_key, body.action, body.operator, body.note)

            new_status = ACTION_STATUS.get(body.action)
            if new_status:
                await c.execute("UPDATE incidents SET status = $1 WHERE incident_key = $2",
                                new_status, incident_key)

            # 차단은 목록에 실제 상태로 남는다. 조치가 기록으로만 끝나지 않게.
            if body.action == "block_ip" and inc["actor_ip"]:
                await c.execute("""
                    INSERT INTO blocklist (actor_ip, reason, incident_key)
                    VALUES ($1::inet, $2, $3)
                    ON CONFLICT (actor_ip) DO UPDATE
                    SET reason = EXCLUDED.reason, incident_key = EXCLUDED.incident_key,
                        released_at = NULL, created_at = now()""",
                    inc["actor_ip"], body.note or "console", incident_key)
            elif body.action == "unblock_ip" and inc["actor_ip"]:
                await c.execute(
                    "UPDATE blocklist SET released_at = now() WHERE actor_ip = $1::inet",
                    inc["actor_ip"])

    payload = row_to_dict(rec) | {"incident_key": incident_key}
    await hub.broadcast({"type": "action.created", "data": payload})
    return payload


@app.post("/api/incidents/{incident_key:path}/verdict", status_code=201)
async def add_verdict(incident_key: str, body: VerdictIn):
    async with app.state.pool.acquire() as c:
        exists = await c.fetchval(
            "SELECT 1 FROM incidents WHERE incident_key = $1", incident_key)
        if not exists:
            raise HTTPException(404, "인시던트를 찾을 수 없습니다")
        rec = await c.fetchrow("""
            INSERT INTO verdicts (incident_key, verdict, reason, observed_value, operator)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, verdict, reason, observed_value, operator, created_at""",
            incident_key, body.verdict, body.reason, body.observed_value, body.operator)

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