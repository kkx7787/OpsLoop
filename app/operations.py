"""규칙 결과 · 수집 노드 · 감사 조회. 수집 관문의 기존 자기 등록 계약을 사용한다."""
import hashlib
import ipaddress
import json
import secrets
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from access import require_role

router = APIRouter()
RESERVED = {"cowrie", "decoy", "gateway", "console", "collector", "puller"}


def interval(since, until):
    if (since is None) != (until is None):
        raise HTTPException(422, "시작과 종료 시각을 함께 지정해 주세요")
    if since is not None and (since.tzinfo is None or until.tzinfo is None or since >= until):
        raise HTTPException(422, "시간대가 있는 시각으로 시작 < 종료를 지정해 주세요")


@router.get("/api/rules/quality")
async def quality(request: Request, details: bool = False,
                  since: datetime | None = None, until: datetime | None = None):
    interval(since, until)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        # 기존 상세 화면의 배열 계약을 유지한다. 확장 화면만 details=true를 요청한다.
        if not details and since is None:
            return [dict(row) for row in await c.fetch("SELECT * FROM rule_quality ORDER BY rule_id, rule_version")]
        versions = await c.fetch("SELECT rule_version, definition, reason, created_at FROM rule_versions ORDER BY created_at, rule_version")
        rows = await c.fetch("""
            WITH latest AS (
                SELECT DISTINCT ON (incident_key) incident_key, verdict FROM verdicts
                ORDER BY incident_key, created_at DESC, id DESC
            )
            SELECT i.rule_id, i.rule_version, count(*) AS incidents, count(v.verdict) AS judged,
                count(*) FILTER (WHERE v.verdict='threat') AS threats,
                count(*) FILTER (WHERE v.verdict='non_actionable') AS non_actionable,
                count(*) FILTER (WHERE v.verdict='false_positive') AS false_positives,
                count(*) FILTER (WHERE v.verdict='benign_positive') AS benign_positives,
                count(*) FILTER (WHERE v.verdict='undetermined') AS undetermined,
                count(v.verdict) FILTER (WHERE v.verdict<>'undetermined') AS judged_effective,
                round(100.0*count(*) FILTER (WHERE v.verdict='false_positive') /
                      nullif(count(v.verdict) FILTER (WHERE v.verdict<>'undetermined'),0),1) AS false_positive_rate,
                round(100.0*count(*) FILTER (WHERE v.verdict IN ('non_actionable','false_positive','benign_positive')) /
                      nullif(count(v.verdict) FILTER (WHERE v.verdict<>'undetermined'),0),1) AS non_action_rate
            FROM incidents i LEFT JOIN latest v USING (incident_key)
            WHERE ($1::timestamptz IS NULL OR i.first_ts >= $1) AND ($2::timestamptz IS NULL OR i.first_ts < $2)
            GROUP BY i.rule_id,i.rule_version ORDER BY i.rule_id,i.rule_version
        """, since, until)
        runs = await c.fetch("""SELECT id, rule_version, since, until, started_at, finished_at, incidents
            FROM detector_runs ORDER BY started_at DESC,id DESC LIMIT 30""")
        as_of = await c.fetchval("SELECT now()")
    if not details:
        return [dict(row) for row in rows]
    definitions = []
    for row in versions:
        definition = json.loads(row['definition']) if isinstance(row['definition'], str) else row['definition']
        definitions.append({"version": row['rule_version'], "created_at": row['created_at'], "reason": row['reason'],
                            "rules": [{"id": r['id'], "name": r.get('name', r['id']),
                                       "enabled": r.get('enabled', True), "severity": r.get('severity'),
                                       "rationale": r.get('rationale'), "change": r.get('changed_from_v1')}
                                      for r in definition.get('rules', [])]})
    return {"as_of": as_of, "since": since, "until": until, "rows": [dict(row) for row in rows],
            "versions": definitions, "runs": [dict(row) for row in runs]}


@router.get("/api/nodes")
async def nodes(request: Request):
    async with request.app.state.pool.acquire() as c:
        rows = await c.fetch("""SELECT n.node_id,n.hostname,n.role,n.sensor,host(n.addr) AS addr,n.logs,
            n.status,n.registered_at,n.last_seen_at,n.first_loaded_at,n.last_loaded_at,
            CASE WHEN n.status='revoked' THEN 'revoked' WHEN n.status='pending' THEN 'waiting'
                 WHEN coalesce(n.last_seen_at,n.registered_at) < now()-interval '10 minutes' THEN 'silent'
                 WHEN n.last_seen_at IS NULL THEN 'waiting' ELSE 'normal' END AS reception,
            (SELECT max(e.expires_at) FROM node_enrollments e WHERE e.node_id=n.node_id
             AND e.used_at IS NULL AND e.canceled_at IS NULL AND e.expires_at>now()) AS enrollment_expires_at,
            now() AS checked_at FROM nodes n ORDER BY n.node_id""")
        as_of = await c.fetchval("SELECT now()")
    return {"as_of": as_of, "rows": [dict(row) for row in rows]}


class EnrollmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    hostname: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
    addr: str = Field(max_length=45)
    logs: list[Literal['nginx', 'auth', 'metrics']] = Field(min_length=1, max_length=3)

    @field_validator('node_id')
    @classmethod
    def valid_node(cls, value):
        if value in RESERVED:
            raise ValueError('기존 센서 이름은 노드 이름으로 사용할 수 없습니다')
        return value

    @field_validator('addr')
    @classmethod
    def valid_addr(cls, value):
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError('수집 관문에 접속할 노드의 IP 주소 하나를 입력해 주세요')
        return str(address)

    @field_validator('logs')
    @classmethod
    def valid_logs(cls, value):
        return sorted(set(value))


async def audit(c, actor, event, detail):
    # 토큰·해시는 감사 기록이나 로그에 넘기지 않는다. 감사 실패 시 발급도 롤백한다.
    await c.execute("SELECT set_config('opsloop.actor',$1,true)", actor)
    await c.execute("SELECT audit_event($1,$2)", event, detail)


@router.post('/api/nodes/enrollments', status_code=201)
async def issue_enrollment(body: EnrollmentIn, request: Request, response: Response):
    user = require_role(request, 'admin')
    token = 'olE_' + secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    async with request.app.state.pool.acquire() as c, c.transaction():
        # CLI·enroll_node와 동일하게 nodes → node_enrollments 순서로 잠근다.
        await c.execute("""INSERT INTO nodes(node_id,hostname,sensor,addr,logs,status)
            VALUES($1,$2,$1,$3::inet,$4,'pending') ON CONFLICT(node_id) DO NOTHING""",
            body.node_id, body.hostname, body.addr, body.logs)
        node = await c.fetchrow("SELECT hostname,host(addr) AS addr,logs FROM nodes WHERE node_id=$1 FOR UPDATE", body.node_id)
        if node['hostname'] != body.hostname or node['addr'] != body.addr or sorted(node['logs']) != body.logs:
            raise HTTPException(409, '기존 노드의 대상 정보와 다릅니다. 등록된 호스트·주소·로그를 확인해 주세요')
        await c.execute("""UPDATE node_enrollments SET canceled_at=now()
            WHERE node_id=$1 AND used_at IS NULL AND canceled_at IS NULL""", body.node_id)
        row = await c.fetchrow("""INSERT INTO node_enrollments(node_id,token_hash,issued_by,expires_at)
            VALUES($1,$2,$3,now()+interval '1 hour') RETURNING id,issued_at,expires_at""", body.node_id,digest,user['u'])
        await audit(c,user['u'],'console.node.token.issued',f"node={body.node_id} enrollment={row['id']} addr={body.addr}")
    response.headers['Cache-Control'] = 'no-store'
    return dict(row) | {"node_id": body.node_id, "token": token}


@router.post('/api/nodes/{node_id}/enrollments/{enrollment_id}/cancel')
async def cancel_enrollment(node_id: str, enrollment_id: int, request: Request):
    user = require_role(request, 'admin')
    async with request.app.state.pool.acquire() as c, c.transaction():
        await c.fetchrow("SELECT node_id FROM nodes WHERE node_id=$1 FOR UPDATE", node_id)
        row = await c.fetchrow("""SELECT used_at,canceled_at FROM node_enrollments
            WHERE id=$1 AND node_id=$2 FOR UPDATE""", enrollment_id,node_id)
        if row is None:
            raise HTTPException(404,'등록 토큰을 찾을 수 없습니다')
        if row['used_at'] is not None:
            raise HTTPException(409,'이미 사용된 등록 토큰입니다. 등록된 에이전트는 이 취소로 폐기되지 않습니다')
        if row['canceled_at'] is None:
            await c.execute('UPDATE node_enrollments SET canceled_at=now() WHERE id=$1',enrollment_id)
            await audit(c,user['u'],'console.node.token.canceled',f'node={node_id} enrollment={enrollment_id}')
    return {"canceled": True}


@router.get('/api/audit')
async def audit_log(request: Request, actor: str = Query(default='',max_length=128),
                    target: str = Query(default='',max_length=128),
                    since: datetime | None = None, until: datetime | None = None,
                    limit: int = Query(default=25,ge=1,le=100), offset: int = Query(default=0,ge=0)):
    require_role(request,'admin')
    interval(since,until)
    # LIKE와 달리 %·_도 문자 그대로 검색한다. 대상은 detail 전체가 아니라 node/ip 필드다.
    source = """WITH records AS (SELECT *, substring(detail from '(?:^|[[:space:]])(?:node|ip|target)=([^[:space:]]+)') AS target
                              FROM audit_log) """
    where = """WHERE ($1='' OR position(lower($1) in lower(coalesce(actor,'')))>0)
        AND ($2='' OR position(lower($2) in lower(coalesce(target,'')))>0)
        AND ($3::timestamptz IS NULL OR ts >= $3) AND ($4::timestamptz IS NULL OR ts < $4)"""
    args = (actor.strip(),target.strip(),since,until)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation='repeatable_read',readonly=True):
        total = await c.fetchval(source+'SELECT count(*) FROM records '+where,*args)
        rows = await c.fetch(source+'SELECT * FROM records '+where+
            ' ORDER BY ts DESC,eventid,actor,detail LIMIT $5 OFFSET $6',*args,limit,offset)
    return {"rows": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}
