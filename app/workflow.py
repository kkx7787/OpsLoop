"""관제 작업 변경 검사. 사건 행 잠금 뒤 이력 토큰을 비교한다 (#105)."""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from access import MaskedValidationRoute, require_role
from live import EVENT_CHANNEL, event_payload

router = APIRouter(route_class=MaskedValidationRoute)
TOKEN_PATTERN = r"^[0-9]{1,20}:[0-9]{1,20}$"
VERSION_SQL = """SELECT
    coalesce((SELECT max(id) FROM actions WHERE incident_key=$1), 0)::text || ':' ||
    coalesce((SELECT max(id) FROM verdicts WHERE incident_key=$1), 0)::text"""
LOCK_SQL = "SELECT assigned_to FROM incidents WHERE incident_key=$1 FOR UPDATE"
AVAILABLE_SQL = "SELECT username FROM console_users WHERE username=$1 AND disabled_at IS NULL AND role IN ('operator','admin') FOR SHARE"


class ChangeIn(BaseModel):
    expected_version: str | None = Field(None, pattern=TOKEN_PATTERN)


def version(actions, verdicts):
    return f"{max((r['id'] for r in actions), default=0)}:{max((r['id'] for r in verdicts), default=0)}"


async def check(c, key, expected):
    if expected is None:
        raise HTTPException(428, "변경 확인 정보가 없습니다. 화면을 새로고침한 뒤 다시 확인해 주세요")
    if await c.fetchval(VERSION_SQL, key) != expected:
        raise HTTPException(409, "다른 판정·조치·담당 변경이 저장됐습니다. 입력은 유지됩니다. 최신 이력을 확인한 뒤 다시 저장해 주세요")


@router.get('/api/incident-operators')
async def operators(request: Request):
    require_role(request, 'operator', 'admin')
    async with request.app.state.pool.acquire() as c:
        rows = await c.fetch("SELECT username, role FROM console_users WHERE disabled_at IS NULL AND role IN ('operator','admin') ORDER BY username")
    return [dict(row) for row in rows]


class AssignmentIn(ChangeIn):
    username: str | None = Field(None, min_length=1, max_length=128, pattern=r'^[^\x00]+$')

    @field_validator('username')
    @classmethod
    def valid_text(cls, value):
        if value is not None:
            try:
                value.encode('utf-8')
            except UnicodeError:
                raise ValueError('아이디에 유효하지 않은 문자가 있습니다') from None
        return value


@router.post('/api/incidents/{incident_key:path}/assignment')
async def assign(incident_key: str, body: AssignmentIn, request: Request):
    user = require_role(request, 'operator', 'admin')
    if '\x00' in incident_key:
        raise HTTPException(404, '인시던트를 찾을 수 없습니다')
    async with request.app.state.pool.acquire() as c, c.transaction():
        incident = await c.fetchrow(LOCK_SQL, incident_key)
        if incident is None:
            raise HTTPException(404, '인시던트를 찾을 수 없습니다')
        await check(c, incident_key, body.expected_version)
        before = incident['assigned_to']
        # 계정 비활성/강등과 배정 사이에 상태가 바뀌지 않게 대상 계정도 잠근다.
        current_available = await c.fetchval(AVAILABLE_SQL, before) if before else None
        if user['r'] != 'admin':
            if body.username not in (None, user['u']):
                raise HTTPException(403, '다른 사람에게 배정하는 작업은 관리자만 합니다')
            if before not in (None, user['u']) and (current_available or body.username is None):
                raise HTTPException(403, '다른 담당자의 사건입니다. 재배정은 관리자에게 요청해 주세요')
        if body.username and not await c.fetchval(AVAILABLE_SQL, body.username):
            raise HTTPException(409, '활성 관제사 또는 관리자에게만 배정할 수 있습니다. 계정 상태를 다시 확인해 주세요')
        if before == body.username:
            return {'assigned_to': before, 'workflow_version': body.expected_version}
        await c.execute('UPDATE incidents SET assigned_to=$2 WHERE incident_key=$1', incident_key, body.username)
        action_id = await c.fetchval("""INSERT INTO actions (incident_key, action, operator, note)
            VALUES ($1, 'assign', $2, $3) RETURNING id""", incident_key, user['u'],
            f"담당 {before or '미배정'} → {body.username or '미배정'}")
        updated = await c.fetchval(VERSION_SQL, incident_key)
        await c.execute('SELECT pg_notify($1, $2)', EVENT_CHANNEL, event_payload('action.created', incident_key, action_id))
        return {'assigned_to': body.username, 'workflow_version': updated}
