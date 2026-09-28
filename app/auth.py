"""
콘솔 인증 (WBS 3.6.1)

판정과 조치가 계정에 귀속되어야 이력이 근거가 된다. 그래서 콘솔에는
로그인이 필요하고, 그 로그인 기록은 디코이와 **같은 형식**으로 남는다.
형식이 같아야 디코이에서 뽑은 규칙을 콘솔 로그에 리플레이할 수 있다.
(docs/2026-09-18-웹-디코이-설계.md 2장)

의존성을 늘리지 않는다. 해시와 서명은 표준 라이브러리로 처리한다.

계정 관리 (컨테이너 안에서, 소유자 접속 DATABASE_URL. 이슈 #59)
  python3 auth.py add <아이디> <역할> [--by <이름>]    새 계정만. 역할: viewer · operator · admin
  python3 auth.py passwd <아이디> [--by <이름>]       비밀번호 재설정
  python3 auth.py role <아이디> <역할> [--by <이름>]   관리자 부여 · 해제 포함
  python3 auth.py disable <아이디> [--by <이름>]      비활성 · enable 은 재활성
  python3 auth.py list                               아이디 · 역할 · 상태 · 마지막 로그인
  --by 는 감사에 남는 행위자(cli:<이름>)다. 없으면 cli. 화면(accounts.py)은 관제사 ↔ 조회자 · 비활성 · 재활성만 한다.
"""

import argparse
import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone

import asyncpg

COOKIE = "opsloop_session"
SESSION_HOURS = 12
ITERATIONS = 240_000
ROLES = ("viewer", "operator", "admin")

# 서명 키가 없으면 매 기동마다 새로 만든다. 그러면 재시작 시 모든 세션이
# 끊기지만, 키를 코드에 두는 것보다는 낫다. 운영에서는 환경변수로 준다.
SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)


# ──────────────────────────────────────────────────────────────
#  비밀번호
# ──────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
    except (ValueError, AttributeError):
        return False
    # 길이가 달라도 시간이 같도록 비교한다.
    return hmac.compare_digest(dk.hex(), want)


# ──────────────────────────────────────────────────────────────
#  세션 쿠키
#
#  서버에 세션 저장소를 두지 않는다. 쿠키에 사용자·역할·발급·만료를 담고
#  서명해서, 위조는 막되 상태는 갖지 않는다. 콘솔이 두 대로 이중화되므로
#  어느 쪽에 붙어도 같은 쿠키가 통해야 한다.
#
#  쿠키만 믿지는 않는다(이슈 #59). 서명 · 만료가 맞으면 요청마다 계정 행을 한 번 읽어(lookup) 확인한다(session_valid).
#  비활성이거나, 역할 · 활성 · 비밀번호가 마지막으로 바뀐 때(updated_at)보다 먼저 받은 쿠키는 무효다. 역할은 DB 값을 쓴다.
#  i(발급 시각)는 로그인 때 DB 의 now() 다(authenticate). updated_at 도 DB 시각이라 콘솔 시계가 어긋나도 방금 받은 쿠키가 무효가 되지 않는다.
# ──────────────────────────────────────────────────────────────
def issue(username: str, role: str, issued_at: float | None = None) -> str:
    now = time.time()
    body = json.dumps({"u": username, "r": role, "i": now if issued_at is None else issued_at,
                       "e": int(now) + SESSION_HOURS * 3600},
                      separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(body).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def read(token: str):
    """쿠키의 서명 · 만료를 검증해 {"u": 아이디, "r": 역할, "i": 발급, "e": 만료} 를 돌려준다. 아니면 None.
    계정 상태는 보지 않는다(lookup · session_valid). i 는 이슈 #59 전에 받은 쿠키에는 없다."""
    if not token or "." not in token:
        return None
    payload, _, sig = token.rpartition(".")
    want = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, want):
        return None
    try:
        pad = "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + pad))
    except (ValueError, json.JSONDecodeError):
        return None
    if data.get("e", 0) < time.time():
        return None
    return data


def session_valid(data: dict, row) -> bool:
    """read() 를 통과한 쿠키가 계정 행(lookup) 기준으로도 유효한가.

    계정이 없거나 비활성(disabled_at)이면 무효다. 역할 · 활성 · 비밀번호가 마지막으로 바뀐 때(updated_at)보다 먼저 받은
    쿠키도 무효다. 강등 · 재활성 · 비밀번호 재설정 뒤에는 다시 로그인해야 한다. i 가 없는 옛 쿠키는 만료에서 거꾸로 센다.
    """
    if row is None or row["disabled_at"] is not None:
        return False
    if row["updated_at"] is None:
        return True
    issued = data.get("i")
    if not isinstance(issued, (int, float)) or isinstance(issued, bool):
        issued = data.get("e", 0) - SESSION_HOURS * 3600
    return issued >= row["updated_at"].timestamp()


# 끊긴 동안 DB 가 닫은 연결을 처음 쓸 때 나는 오류. asyncpg 0.30 은 ConnectionResetError 를 ConnectionDoesNotExistError 로 감싸고,
#   그 부모는 PostgresConnectionError(SQLSTATE 08 계열)다. 닫힌 연결을 다시 쓰면 InterfaceError, 소켓 오류는 OSError 다.
#   시험의 가짜 asyncpg 모듈에는 없을 수 있어 있는 것만 모은다. 헬스체크(main.health)와 계정 확인(lookup)이 같이 쓴다
STALE_CONNECTION_ERRORS = tuple(e for e in (getattr(asyncpg, "PostgresConnectionError", None),
                                            getattr(asyncpg, "InterfaceError", None), OSError) if isinstance(e, type))

LOOKUP_SQL = "SELECT role, disabled_at, updated_at FROM console_users WHERE username = $1"


async def lookup(pool, username: str):
    """계정 행 하나(role · disabled_at · updated_at). 없으면 None. 세션이 있는 요청과 실시간 연결 점검마다 부른다.

    캐시를 두지 않는다. 다른 콘솔에서 바꾼 것도 다음 요청에 바로 보인다. DB 가 없으면 /health 도 실패해 두 콘솔이 함께
    빠지므로 캐시로 버틸 이유도 없다. 옛 연결 오류면 한 번 더 빌린다(main.health 와 같다, 이슈 #56).
    그 밖의 DB 오류는 그대로 던진다. 무효로 보지 않는다. 부르는 쪽이 503(요청) · 이번 회차 건너뛰기(실시간 점검)로 가른다.
    """
    for attempt in (1, 2):
        try:
            async with pool.acquire() as c:
                return await c.fetchrow(LOOKUP_SQL, username)
        except STALE_CONNECTION_ERRORS:
            if attempt == 2:
                raise


# ──────────────────────────────────────────────────────────────
#  인증 로그
#
#  디코이와 같은 표, 같은 필드에 남긴다. 다른 점은 sensor 뿐이다.
#  규칙은 발생원이 아니라 범주와 동작(%.login.failed)으로 매칭하므로
#  같은 규칙이 양쪽에서 돈다.
#
#  글자 값은 파서(parser/parse_decoy.clip)와 같은 규칙으로 정리한다(이슈 #41).
#  폼 아이디의 NUL(%00)은 PostgreSQL 글자 열에 들어가지 못해 INSERT 가 실패하고 기록이 빠진다.
#  그러면 콘솔 로그인 반복 실패(R101) 집계를 피할 수 있다. 그래서 지우고, 길이도 파서와 같게 자른다.
# ──────────────────────────────────────────────────────────────
INSERT_EVENT = """
INSERT INTO events (line_hash, ts, eventid, session, src_ip, src_port, dst_port,
                    protocol, username, provenance, http_method, http_status,
                    user_agent, sensor, url, message)
VALUES ($1,$2,$3,$4,$5,$6,$7,'http',$8,'real',$9,$10,$11,'console',$12,$13)
ON CONFLICT (line_hash) DO NOTHING
"""


def clip(v, n):
    """DB 에 넣을 글자 값. parser/parse_decoy.clip 과 같은 규칙이다.

    - NUL(\\x00)은 지운다. 글자 열에 들어가지 못해 INSERT 가 실패한다.
    - 짝 없는 서로게이트("\\ud800")는 UTF-8 로 바꿀 수 없다. 대체 문자로 바꾼다.
    - n 글자에서 자른다.
    """
    if v is None:
        return None
    v = str(v).replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    return v if len(v) <= n else v[:n]


# 필드별 글자 수 상한. parser/parse_decoy.py 가 디코이 로그를 넣을 때와 같다.
LIMITS = {"session": 128, "username": 256, "http_method": 16, "user_agent": 512, "url": 2048, "message": 512}


async def log_event(pool, request, eventid: str, *, username=None, status=None,
                    session=None, message=None):
    client = request.client
    ts = datetime.now(timezone.utc)
    session = clip(session, LIMITS["session"])
    username = clip(username, LIMITS["username"])
    method = clip(request.method, LIMITS["http_method"])
    ua = clip(request.headers.get("user-agent"), LIMITS["user_agent"])
    url = clip(request.url.path, LIMITS["url"])
    message = clip(message, LIMITS["message"])
    record = {
        "ts": ts.isoformat(), "eventid": eventid, "session": session,
        "src_ip": client.host if client else None, "username": username,
        "url": url, "status": status, "ua": ua,
    }
    line_hash = hashlib.sha1(
        json.dumps(record, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    try:
        async with pool.acquire() as c:
            await c.execute(
                INSERT_EVENT, line_hash, ts, eventid, session,
                client.host if client else None,
                client.port if client else None,
                int(os.environ.get("CONSOLE_PORT", 8000)),
                username, method, status, ua, url, message)
    except Exception as exc:  # 기록 실패가 로그인 자체를 막지는 않는다
        print(f"[auth] 인증 로그 기록 실패: {exc}", flush=True)


# ──────────────────────────────────────────────────────────────
#  폼 해석
#
#  프레임워크의 폼 해석기는 urlencoded 에도 다중 파트 라이브러리를 요구한다.
#  로그인 폼에 필요한 것은 키·값 두 개뿐이므로 표준 라이브러리로 처리한다.
# ──────────────────────────────────────────────────────────────
MAX_FORM = 8 * 1024


async def form_fields(request) -> dict:
    from urllib.parse import parse_qsl
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) >= MAX_FORM:
            body = body[:MAX_FORM]
            break
    try:
        return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    except Exception:
        return {}


# ──────────────────────────────────────────────────────────────
#  사용자 조회
# ──────────────────────────────────────────────────────────────
async def authenticate(pool, username: str, password: str):
    if "\x00" in username:
        # 계정 이름에는 NUL 이 없다(글자 열에 들어가지 못한다). 질의하면 DB 오류로 500 이 나고
        # 실패 기록(console.login.failed)도 빠진다. 없는 계정과 같은 시간을 쓰고 실패로 돌려준다.
        hash_password(password)
        return None
    async with pool.acquire() as c:
        row = await c.fetchrow(
            "SELECT username, password_hash, role, disabled_at, updated_at FROM console_users WHERE username = $1",
            username)
    if row is None:
        # 존재하지 않는 계정도 같은 시간이 걸리도록 한 번 계산한다.
        # 응답 시간 차이로 계정 존재 여부가 드러나는 것을 막는다.
        hash_password(password)
        return None
    # 비활성 계정도 비밀번호를 끝까지 확인한 뒤 틀린 비밀번호와 같은 실패로 돌려준다(이슈 #59).
    # 응답 · 시간으로 비활성인지(= 계정이 있고 비밀번호가 맞는지) 드러나지 않게 한다. 기록도 같은 console.login.failed 다
    if not verify_password(password, row["password_hash"]) or row["disabled_at"] is not None:
        return None
    # 쿠키의 발급 시각(i)은 DB 의 now() 로 준다. 계정 변경 시각(updated_at)도 DB 시각이라 콘솔 시계가 늦어도 새 쿠키가 바로
    # 무효가 되지 않는다. 확인과 이 UPDATE 사이에 계정이 바뀌었으면(비활성 · 역할 · 비밀번호, updated_at 이 다르다) 행이 없어 실패다.
    # 비밀번호 확인(수백 ms) 동안 명령줄이 비밀번호를 바꿨는데, 옛 비밀번호로 받은 쿠키가 바뀐 시각보다 뒤라 유효하게 남는 일을 막는다
    async with pool.acquire() as c:
        issued_at = await c.fetchval(
            "UPDATE console_users SET last_login_at = now() WHERE username = $1 AND disabled_at IS NULL"
            " AND updated_at IS NOT DISTINCT FROM $2 RETURNING extract(epoch FROM now())", username, row["updated_at"])
    if issued_at is None:
        return None
    return {"username": row["username"], "role": row["role"], "issued_at": float(issued_at)}


# ──────────────────────────────────────────────────────────────
#  계정 관리 (명령줄, 이슈 #59)
#
#  소유자 접속(DATABASE_URL)으로 표를 직접 고친다. 화면(accounts.py)은 콘솔 역할이라 console_account_set 함수로만
#  바꾸고 관리자 계정 · 관리자 부여는 못 한다. 그것은 여기서만 한다.
#  바꾸는 명령은 한 트랜잭션에서 행위자(cli:<--by>)를 건 뒤 쓴다. 감사 트리거(audit_console_users)가 by= 로 남긴다.
#  컨테이너는 USER app 으로 돌아 OS 사용자 이름은 늘 app 이다. 누가 했는지는 --by 로 받는다.
#  역할 · 활성 · 비밀번호가 바뀌면 도장 트리거가 updated_at 을 찍어 그 전에 받은 쿠키가 무효가 된다(session_valid).
#  마지막 활성 관리자를 낮추거나 비활성하면 거부한다. 활성 관리자 행을 먼저 잠가 두 명령이 겹쳐도 관리자가 0명이 되지 않는다.
#  비밀번호는 getpass 로만 받는다(인자 · 환경변수로 받지 않는다). 해시는 출력하지 않는다.
# ──────────────────────────────────────────────────────────────
NEW_USERNAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MIN_PASSWORD = 12
# 로그인은 입력을 이 길이에서 자른다(main.login). 더 긴 비밀번호를 받으면 그 계정은 로그인할 수 없다
MAX_PASSWORD = 256


class CliError(Exception):
    """명령을 거부한 이유. 표준 오류로 내고 종료 코드 1 로 끝난다."""


def arg_new_username(v):
    if not NEW_USERNAME.fullmatch(v):
        raise argparse.ArgumentTypeError(f"아이디 {v!r}: 영문 · 숫자 · '._-' 64자 이하")
    return v


def arg_username(v):
    # 이미 있는 계정. 형식 검사 전에 만든 계정도 다룰 수 있게 로그인과 같은 길이(128)와 제어 문자만 본다
    if not 1 <= len(v) <= 128 or CONTROL.search(v):
        raise argparse.ArgumentTypeError(f"아이디 {v!r}: 제어 문자 없이 128자 이하")
    return v


def arg_by(v):
    # 감사 detail 은 key=value 를 공백으로 가른다. 공백 · 제어 문자가 들어가지 않게 아이디와 같은 형식만 받는다
    if not NEW_USERNAME.fullmatch(v):
        raise argparse.ArgumentTypeError(f"--by {v!r}: 영문 · 숫자 · '._-' 64자 이하")
    return v


def printable(v) -> str:
    return CONTROL.sub("?", str(v))


def fmt_ts(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ") if dt else "-"


def ask_password() -> str:
    pw = getpass.getpass("비밀번호: ")
    if len(pw) < MIN_PASSWORD:
        raise CliError(f"비밀번호는 {MIN_PASSWORD}자 이상이어야 합니다")
    if len(pw) > MAX_PASSWORD:
        raise CliError(f"비밀번호는 {MAX_PASSWORD}자 이하여야 합니다")
    if pw != getpass.getpass("다시 입력: "):
        raise CliError("입력이 일치하지 않습니다")
    return pw


async def set_actor(c, by):
    """이 트랜잭션에만 행위자를 건다(set_config 세 번째 인자 true). 감사 트리거가 읽는다."""
    await c.execute("SELECT set_config('opsloop.actor', $1, true)", f"cli:{by}" if by else "cli")


async def locked_account(c, username):
    """활성 관리자 행 · 대상 행을 잠그고 (대상 행, 활성 관리자 수) 를 돌려준다. 트랜잭션 안에서 부른다.
    관리자 행을 이름 순으로 먼저 잠가 겹친 명령이 차례로 판단한다. 앞 명령이 커밋하면 뒤 명령은 바뀐 행으로 다시 센다."""
    admins = await c.fetch("SELECT username FROM console_users WHERE role = 'admin' AND disabled_at IS NULL"
                           " ORDER BY username FOR UPDATE")
    row = await c.fetchrow("SELECT username, role, disabled_at FROM console_users WHERE username = $1 FOR UPDATE",
                           username)
    if row is None:
        raise CliError(f"없는 계정입니다: {printable(username)}")
    return row, len(admins)


def last_admin(row, admins: int) -> bool:
    return row["role"] == "admin" and row["disabled_at"] is None and admins <= 1


async def cmd_add(c, args):
    # 있는 계정을 말없이 덮지 않는다(역할 · 비밀번호가 바뀌어 마지막 관리자가 낮춰질 수 있었다). 비밀번호를 묻기 전에 본다
    if await c.fetchval("SELECT 1 FROM console_users WHERE username = $1", args.username):
        raise CliError(f"이미 있는 계정입니다: {args.username}. 비밀번호는 passwd, 역할은 role 로 바꿉니다")
    pw = ask_password()
    async with c.transaction():
        await set_actor(c, args.by)
        await c.execute("INSERT INTO console_users (username, password_hash, role) VALUES ($1, $2, $3)",
                        args.username, hash_password(pw), args.role)
    return f"등록: {args.username} ({args.role})"


async def cmd_passwd(c, args):
    if not await c.fetchval("SELECT 1 FROM console_users WHERE username = $1", args.username):
        raise CliError(f"없는 계정입니다: {printable(args.username)}")
    pw = ask_password()
    async with c.transaction():
        await set_actor(c, args.by)
        done = await c.execute("UPDATE console_users SET password_hash = $2 WHERE username = $1",
                               args.username, hash_password(pw))
    if done == "UPDATE 0":
        raise CliError(f"없는 계정입니다: {printable(args.username)}")
    return f"비밀번호 변경: {printable(args.username)} (전에 받은 세션은 끊깁니다)"


async def cmd_role(c, args):
    async with c.transaction():
        await set_actor(c, args.by)
        row, admins = await locked_account(c, args.username)
        if row["role"] == args.role:
            return f"바뀐 것 없음: {printable(args.username)} 는 이미 {args.role}"
        if last_admin(row, admins):
            raise CliError("마지막 활성 관리자는 낮출 수 없습니다. 다른 관리자를 먼저 두세요")
        await c.execute("UPDATE console_users SET role = $2 WHERE username = $1", args.username, args.role)
    return f"역할 변경: {printable(args.username)} {row['role']} → {args.role} (전에 받은 세션은 끊깁니다)"


async def cmd_disable(c, args):
    async with c.transaction():
        await set_actor(c, args.by)
        row, admins = await locked_account(c, args.username)
        if row["disabled_at"] is not None:
            return f"바뀐 것 없음: {printable(args.username)} 는 이미 비활성"
        if last_admin(row, admins):
            raise CliError("마지막 활성 관리자는 비활성할 수 없습니다. 다른 관리자를 먼저 두세요")
        await c.execute("UPDATE console_users SET disabled_at = now() WHERE username = $1", args.username)
    return f"비활성: {printable(args.username)} (열린 세션은 끊기고 로그인할 수 없습니다)"


async def cmd_enable(c, args):
    async with c.transaction():
        await set_actor(c, args.by)
        row, _admins = await locked_account(c, args.username)
        if row["disabled_at"] is None:
            return f"바뀐 것 없음: {printable(args.username)} 는 이미 활성"
        await c.execute("UPDATE console_users SET disabled_at = NULL WHERE username = $1", args.username)
    return f"재활성: {printable(args.username)} (비활성 전에 받은 세션은 되살아나지 않습니다)"


async def cmd_list(c, _args):
    rows = await c.fetch("SELECT username, role, disabled_at, last_login_at FROM console_users ORDER BY username")
    lines = [f"{'아이디':<24} {'역할':<9} {'상태':<32} 마지막 로그인"]
    for r in rows:
        state = "활성" if r["disabled_at"] is None else f"비활성 {fmt_ts(r['disabled_at'])}"
        lines.append(f"{printable(r['username']):<24} {r['role']:<9} {state:<32} {fmt_ts(r['last_login_at'])}")
    return "\n".join(lines)


def build_parser():
    ap = argparse.ArgumentParser(prog="auth.py", description="콘솔 계정 관리 (소유자 접속 DATABASE_URL)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    by = argparse.ArgumentParser(add_help=False)
    by.add_argument("--by", type=arg_by, default=None, help="감사에 남길 행위자 이름 (cli:<이름>, 없으면 cli)")

    p = sub.add_parser("add", parents=[by], help="새 계정 (있으면 거부)")
    p.add_argument("username", type=arg_new_username)
    p.add_argument("role", choices=ROLES)
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("passwd", parents=[by], help="비밀번호 재설정")
    p.add_argument("username", type=arg_username)
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("role", parents=[by], help="역할 변경 (관리자 부여 · 해제 포함)")
    p.add_argument("username", type=arg_username)
    p.add_argument("role", choices=ROLES)
    p.set_defaults(func=cmd_role)

    p = sub.add_parser("disable", parents=[by], help="비활성")
    p.add_argument("username", type=arg_username)
    p.set_defaults(func=cmd_disable)

    p = sub.add_parser("enable", parents=[by], help="재활성")
    p.add_argument("username", type=arg_username)
    p.set_defaults(func=cmd_enable)

    p = sub.add_parser("list", help="계정 목록 (해시 없음)")
    p.set_defaults(func=cmd_list)
    return ap


async def run(args) -> str:
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        return await args.func(conn, args)
    finally:
        await conn.close()


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not os.environ.get("DATABASE_URL"):
        print("DATABASE_URL(소유자 접속)이 필요합니다", file=sys.stderr)
        return 1
    try:
        print(asyncio.run(run(args)))
    except CliError as error:
        print(error, file=sys.stderr)
        return 1
    except asyncpg.PostgresError as error:
        # 오류 상세(detail)에는 실패한 행이 실릴 수 있다(해시 포함). 종류 · 첫 줄만 낸다
        print(f"DB 오류: {type(error).__name__}: {str(error).splitlines()[0] if str(error) else ''}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
