"""계정 관리 API (이슈 #59 · #63 · 화면 S-15). 모두 admin 전용.

화면에서 하는 일은 관제사 · 조회자 계정의 추가 · 삭제 · 비밀번호 재설정(#63)과 관제사 ↔ 조회자 역할 변경 · 비활성 · 재활성(#59)이다.
관리자 계정 추가 · 관리자 부여 · 해제 · 관리자 계정의 비활성 · 재활성 · 비밀번호 · 본인 계정은 명령줄(auth.py)에서만 한다.
콘솔 DB 역할은 console_users 를 직접 고치지 못하고(INSERT · DELETE 없음, UPDATE 는 last_login_at 열만) 정해진 변경만 하는
DB 함수 console_account_set · create · delete · password 의 실행 권한만 받는다. 관리자 역할 · 관리자 계정 · 자기 자신 변경은 함수가
거부한다. 콘솔이 뚫려도 스스로 관리자가 될 수 없게 하는 경계다.

감사는 DB 트리거(audit_console_users)가 남긴다. 누가 했는지는 같은 트랜잭션에서 opsloop.actor 로 넘긴다.
역할 · 활성 · 비밀번호가 바뀌면 그 계정이 전에 받은 쿠키는 무효다(auth.session_valid). 열린 실시간 연결은 main.ws_recheck 가 끊는다.

비밀번호는 서버가 해시(auth.hash_password)해 함수에 넘긴다. 평문 · 해시는 응답 · 감사 · 로그에 싣지 않는다. 계정 행을 읽는
문장에도 password_hash 가 없다. /api 응답은 거부 · 오류까지 모두 Cache-Control: no-store 다(web.SecurityHeaders).
아이디에 '/' 등이 있을 수 있어 경로가 아니라 본문으로 받는다.
"""
import asyncio
from typing import Literal

import asyncpg
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

import auth
from access import MaskedValidationRoute, require_role

router = APIRouter(route_class=MaskedValidationRoute)

COLUMNS = "username, role, disabled_at, created_at, last_login_at, updated_at"
# 지울 수 있는가(이력 없음). console_account_delete 의 in_use 와 같은 기준이다. 로그인한 적이 있거나, 판정 · 조치를 남겼거나,
# 차단을 요청 · 해제한 계정은 지우지 않는다(기록이 계정에 귀속된다). 화면은 참인 행에만 삭제 단추를 보이고, 함수가 다시 가른다
DELETABLE = ("NOT (u.last_login_at IS NOT NULL"
             " OR EXISTS (SELECT 1 FROM verdicts WHERE operator = u.username)"
             " OR EXISTS (SELECT 1 FROM actions WHERE operator = u.username)"
             " OR EXISTS (SELECT 1 FROM incidents WHERE assigned_to = u.username)"
             " OR EXISTS (SELECT 1 FROM blocklist WHERE requested_by = u.username OR released_by = u.username))")
LIST_SQL = f"SELECT {COLUMNS}, {DELETABLE} AS deletable FROM console_users u ORDER BY username"
ONE_SQL = f"SELECT {COLUMNS}, {DELETABLE} AS deletable FROM console_users u WHERE username = $1"
# 이력 표를 읽을 권한이 없으면 deletable 은 NULL(모름)이다. 권한 없는 표가 문장에 있으면 문장 전체가 거부되므로(실행 전에 문장의
# 모든 표 권한을 본다) 먼저 묻고 문장을 고른다. 거부된 문장이 변경 트랜잭션을 깨지 않는다. 콘솔 역할은 역할 블록에서 셋 다 읽는다
READABLE_SQL = ("SELECT coalesce(has_table_privilege(to_regclass('verdicts'), 'SELECT')"
                " AND has_table_privilege(to_regclass('actions'), 'SELECT')"
                " AND has_table_privilege(to_regclass('incidents'), 'SELECT')"
                " AND has_table_privilege(to_regclass('blocklist'), 'SELECT'), false)")
LIST_PLAIN_SQL = f"SELECT {COLUMNS}, NULL::boolean AS deletable FROM console_users ORDER BY username"
ONE_PLAIN_SQL = f"SELECT {COLUMNS}, NULL::boolean AS deletable FROM console_users WHERE username = $1"

SET_SQL = "SELECT console_account_set($1, $2, $3)"
CREATE_SQL = "SELECT console_account_create($1, $2, $3)"
DELETE_SQL = "SELECT console_account_delete($1)"
PASSWORD_SQL = "SELECT console_account_password($1, $2)"

# 함수 결과 → 응답. ok(역할 · 활성은 unchanged 도)는 성공이다. no_actor 는 행위자를 넘기지 않았다는 뜻이라 이 코드의 잘못이다(500)
REFUSED = {
    "invalid": (422, "아이디 · 비밀번호 형식이 맞지 않습니다"),
    "not_found": (404, "계정을 찾을 수 없습니다"),
    "exists": (409, "이미 있는 아이디입니다"),
    "assigned": (409, "담당 사건이 있는 계정은 지울 수 없습니다. 담당을 해제·재배정하거나 계정을 비활성으로 바꿔 주세요"),
    "in_use": (409, "판정 · 조치 · 로그인 기록이 있는 계정은 지울 수 없습니다. 비활성으로 막아 주세요"),
    "cli_only": (409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
    "self": (409, "본인 계정은 여기서 바꿀 수 없습니다"),
    "no_actor": (500, "서버 오류"),
}

# 시험의 가짜 asyncpg 모듈에는 없을 수 있어 있는 것만 모은다(auth.STALE_CONNECTION_ERRORS 와 같다). 빈 튜플은 아무것도 잡지 않는다
UNIQUE_VIOLATION = tuple(e for e in (getattr(asyncpg, "UniqueViolationError", None),) if isinstance(e, type))
DB_ERRORS = tuple(e for e in (getattr(asyncpg, "PostgresError", None),) if isinstance(e, type))


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def no_nul(cls, value):
        # 글자 열에 NUL 은 들어가지 못해 DB 오류(500)가 난다. 그런 계정은 없으므로 입력 오류로 돌려준다
        if "\x00" in value:
            raise ValueError("아이디에 NUL 문자를 쓸 수 없습니다")
        return value


class RoleIn(Target):
    role: Literal["viewer", "operator"]


class ActiveIn(Target):
    active: StrictBool


def checked_password(value: str) -> str:
    # 명령줄과 같은 검사다(auth.password_problem: 로그인이 자르는 길이까지, UTF-8 로 바꿀 수 있는 글자만).
    # 제약 없는 str 은 짝 없는 서로게이트를 그대로 넘긴다. 검증 오류 응답에는 문장만 실린다(access.masked_422)
    problem = auth.password_problem(value)
    if problem:
        raise ValueError(problem)
    return value


class NewAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    role: Literal["viewer", "operator"]
    password: str

    @field_validator("username")
    @classmethod
    def new_username(cls, value):
        # 명령줄 add 와 같은 형식(auth.NEW_USERNAME). 함수도 같은 형식을 본다(invalid)
        if not auth.NEW_USERNAME.fullmatch(value):
            raise ValueError("아이디는 영문 · 숫자 · '._-' 로 64자 이하입니다")
        return value

    @field_validator("password")
    @classmethod
    def valid_password(cls, value):
        return checked_password(value)


class PasswordIn(Target):
    password: str

    @field_validator("password")
    @classmethod
    def valid_password(cls, value):
        return checked_password(value)


def locked(row, me: str):
    """화면이 바꿀 수 없는 행. 본인(self) · 관리자(admin). 버튼 대신 까닭을 보인다. 함수도 같은 순서로 거부한다."""
    if row["username"] == me:
        return "self"
    if row["role"] == "admin":
        return "admin"
    return None


def account(row, me: str) -> dict:
    return {"username": row["username"], "role": row["role"], "active": row["disabled_at"] is None,
            "disabled_at": row["disabled_at"], "created_at": row["created_at"],
            "last_login_at": row["last_login_at"], "updated_at": row["updated_at"], "locked": locked(row, me),
            "deletable": row["deletable"]}


async def readable(c) -> bool:
    return bool(await c.fetchval(READABLE_SQL))


@router.get("/api/accounts")
async def list_accounts(request: Request):
    user = require_role(request, "admin")
    async with request.app.state.pool.acquire() as c:
        rows = await c.fetch(LIST_SQL if await readable(c) else LIST_PLAIN_SQL)
    return {"accounts": [account(row, user["u"]) for row in rows]}


async def call(request: Request, user: dict, sql: str, *args, target: str, done=("ok",), read_back=True):
    """행위자를 건 한 트랜잭션에서 계정 함수를 한 번 부르고 (결과, 바뀐 계정 행)을 돌려준다. 거부면 HTTPException.

    DB 오류는 종류 · 첫 줄만 남기고 500 이다. 오류 상세(detail)에는 실패한 행이 실릴 수 있다(해시 포함, auth.main 과 같다).
    같은 아이디를 두 관리자가 함께 추가하면 늦은 쪽의 INSERT 가 고유 제약에 걸린다. 함수의 exists 와 같이 409 다.
    """
    row = None
    try:
        async with request.app.state.pool.acquire() as c, c.transaction():
            # 행위자는 이 트랜잭션에만 건다(세 번째 인자 true). 감사 트리거가 by= 로 남기고, 함수가 자기 자신 변경을 가른다
            await c.execute("SELECT set_config('opsloop.actor', $1, true)", user["u"])
            result = await c.fetchval(sql, *args)
            if read_back and result in done:
                row = await c.fetchrow(ONE_SQL if await readable(c) else ONE_PLAIN_SQL, target)
    except UNIQUE_VIOLATION:
        result = "exists"
    except DB_ERRORS as error:
        text = str(error)
        print(f"[accounts] 계정 함수 DB 오류: {type(error).__name__}: {text.splitlines()[0] if text else ''}", flush=True)
        raise HTTPException(500, "서버 오류") from None
    if result not in done or (read_back and row is None):
        status, detail = REFUSED.get(result, (500, "서버 오류"))
        if status == 500:
            print(f"[accounts] 계정 함수 결과를 처리하지 못함: {result!r}", flush=True)
        raise HTTPException(status, detail)
    return result, row


async def hashed(password: str) -> str:
    # 해시 계산(수백 ms)이 이벤트 루프를 막지 않게 따로 돈다. 권한 확인(require_role) 뒤에 부른다
    return await asyncio.to_thread(auth.hash_password, password)


async def change(request: Request, username: str, role, active) -> dict:
    user = require_role(request, "admin")
    result, row = await call(request, user, SET_SQL, username, role, active, target=username, done=("ok", "unchanged"))
    return {"result": result, "account": account(row, user["u"])}


@router.post("/api/accounts/role")
async def set_role(body: RoleIn, request: Request):
    return await change(request, body.username, body.role, None)


@router.post("/api/accounts/active")
async def set_active(body: ActiveIn, request: Request):
    return await change(request, body.username, None, body.active)


@router.post("/api/accounts", status_code=201)
async def create_account(body: NewAccountIn, request: Request):
    """관제사 · 조회자 계정 추가. 관리자 역할은 입력에서 막고(422) 함수도 거부한다(cli_only)."""
    user = require_role(request, "admin")
    password_hash = await hashed(body.password)
    result, row = await call(request, user, CREATE_SQL, body.username, body.role, password_hash, target=body.username)
    return {"result": result, "account": account(row, user["u"])}


@router.post("/api/accounts/delete")
async def delete_account(body: Target, request: Request):
    """이력(로그인 · 판정 · 조치 · 차단 요청 · 해제)이 없는 관제사 · 조회자 계정만 지운다. 있으면 in_use(409), 비활성을 안내한다."""
    user = require_role(request, "admin")
    result, _ = await call(request, user, DELETE_SQL, body.username, target=body.username, read_back=False)
    return {"result": result}


@router.post("/api/accounts/password")
async def set_password(body: PasswordIn, request: Request):
    """관제사 · 조회자 비밀번호 재설정. 도장 트리거가 updated_at 을 찍어 그 계정이 전에 받은 쿠키는 무효가 된다."""
    user = require_role(request, "admin")
    password_hash = await hashed(body.password)
    result, row = await call(request, user, PASSWORD_SQL, body.username, password_hash, target=body.username)
    return {"result": result, "account": account(row, user["u"])}
