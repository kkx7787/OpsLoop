"""
콘솔 인증 (WBS 3.6.1)

판정과 조치가 계정에 귀속되어야 이력이 근거가 된다. 그래서 콘솔에는
로그인이 필요하고, 그 로그인 기록은 디코이와 **같은 형식**으로 남는다.
형식이 같아야 디코이에서 뽑은 규칙을 콘솔 로그에 리플레이할 수 있다.
(docs/2026-09-18-웹-디코이-설계.md 2장)

의존성을 늘리지 않는다. 해시와 서명은 표준 라이브러리로 처리한다.

사용자 추가 (컨테이너 안에서)
  python3 auth.py add <아이디> <역할>       역할: viewer · operator · admin
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone

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
#  서버에 세션 저장소를 두지 않는다. 쿠키에 사용자·역할·만료를 담고
#  서명해서, 위조는 막되 상태는 갖지 않는다. 콘솔이 두 대로 이중화되므로
#  어느 쪽에 붙어도 같은 쿠키가 통해야 한다.
# ──────────────────────────────────────────────────────────────
def issue(username: str, role: str) -> str:
    body = json.dumps({"u": username, "r": role,
                       "e": int(time.time()) + SESSION_HOURS * 3600},
                      separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(body).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def read(token: str):
    """쿠키를 검증해 {"u": 아이디, "r": 역할} 을 돌려준다. 아니면 None."""
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
            "SELECT username, password_hash, role FROM console_users WHERE username = $1",
            username)
    if row is None:
        # 존재하지 않는 계정도 같은 시간이 걸리도록 한 번 계산한다.
        # 응답 시간 차이로 계정 존재 여부가 드러나는 것을 막는다.
        hash_password(password)
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    async with pool.acquire() as c:
        await c.execute("UPDATE console_users SET last_login_at = now() WHERE username = $1",
                        username)
    return {"username": row["username"], "role": row["role"]}


# ──────────────────────────────────────────────────────────────
#  사용자 추가 (명령줄)
# ──────────────────────────────────────────────────────────────
async def _add(username: str, role: str):
    import getpass
    import asyncpg

    if role not in ROLES:
        sys.exit(f"역할은 {' · '.join(ROLES)} 중 하나여야 합니다")
    pw = getpass.getpass("비밀번호: ")
    if len(pw) < 12:
        sys.exit("비밀번호는 12자 이상이어야 합니다")
    if pw != getpass.getpass("다시 입력: "):
        sys.exit("입력이 일치하지 않습니다")

    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    await conn.execute("""
        INSERT INTO console_users (username, password_hash, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (username) DO UPDATE
           SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
    """, username, hash_password(pw), role)
    await conn.close()
    print(f"등록: {username} ({role})")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "add":
        sys.exit("사용법: python3 auth.py add <아이디> <역할>")
    asyncio.run(_add(sys.argv[2], sys.argv[3]))
