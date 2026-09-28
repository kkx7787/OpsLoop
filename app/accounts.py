"""계정 관리 API (이슈 #59 · 화면 S-15). 모두 admin 전용.

화면에서 하는 일은 관제사 ↔ 조회자 역할 변경과 비활성 · 재활성뿐이다. 계정 추가 · 관리자 부여 · 해제 · 관리자 계정의
비활성 · 재활성 · 비밀번호는 명령줄(auth.py)에서만 한다. 콘솔 DB 역할은 console_users 를 직접 고치지 못하고(UPDATE 는
last_login_at 열만) 정해진 변경만 하는 DB 함수 console_account_set 의 실행 권한만 받는다. 높이기 · 관리자 계정 · 자기 자신
변경은 함수가 거부한다. 콘솔이 뚫려도 스스로 관리자가 될 수 없게 하는 경계다.

감사는 DB 트리거(audit_console_users)가 남긴다. 누가 했는지는 같은 트랜잭션에서 opsloop.actor 로 넘긴다.
역할 · 활성이 바뀌면 그 계정이 전에 받은 쿠키는 무효다(auth.session_valid). 열린 실시간 연결은 main.ws_recheck 가 끊는다.

비밀번호 해시는 읽지도 내보내지도 않는다(조회 문장에 password_hash 가 없다).
아이디에 '/' 등이 있을 수 있어 경로가 아니라 본문으로 받는다.
"""
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from access import MaskedValidationRoute, require_role

router = APIRouter(route_class=MaskedValidationRoute)

COLUMNS = "username, role, disabled_at, created_at, last_login_at, updated_at"
LIST_SQL = f"SELECT {COLUMNS} FROM console_users ORDER BY username"
ONE_SQL = f"SELECT {COLUMNS} FROM console_users WHERE username = $1"
SET_SQL = "SELECT console_account_set($1, $2, $3)"

# 함수 결과 → 응답. ok · unchanged 는 200 이다. no_actor 는 행위자를 넘기지 않았다는 뜻이라 이 코드의 잘못이다(500)
REFUSED = {
    "not_found": (404, "계정을 찾을 수 없습니다"),
    "cli_only": (409, "관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다"),
    "self": (409, "본인 계정은 여기서 바꿀 수 없습니다"),
    "no_actor": (500, "서버 오류"),
}


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
            "last_login_at": row["last_login_at"], "updated_at": row["updated_at"], "locked": locked(row, me)}


@router.get("/api/accounts")
async def list_accounts(request: Request):
    user = require_role(request, "admin")
    async with request.app.state.pool.acquire() as c:
        rows = await c.fetch(LIST_SQL)
    return {"accounts": [account(row, user["u"]) for row in rows]}


async def change(request: Request, username: str, role, active) -> dict:
    user = require_role(request, "admin")
    async with request.app.state.pool.acquire() as c, c.transaction():
        # 행위자는 이 트랜잭션에만 건다(세 번째 인자 true). 감사 트리거가 by= 로 남기고, 함수가 자기 자신 변경을 가른다
        await c.execute("SELECT set_config('opsloop.actor', $1, true)", user["u"])
        result = await c.fetchval(SET_SQL, username, role, active)
        row = await c.fetchrow(ONE_SQL, username) if result in ("ok", "unchanged") else None
    if row is None:
        status, detail = REFUSED.get(result, (500, "서버 오류"))
        if status == 500:
            print(f"[accounts] 계정 함수 결과를 처리하지 못함: {result!r}", flush=True)
        raise HTTPException(status, detail)
    return {"result": result, "account": account(row, user["u"])}


@router.post("/api/accounts/role")
async def set_role(body: RoleIn, request: Request):
    return await change(request, body.username, body.role, None)


@router.post("/api/accounts/active")
async def set_active(body: ActiveIn, request: Request):
    return await change(request, body.username, None, body.active)
