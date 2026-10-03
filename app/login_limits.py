"""#103 로그인 계산 전 공유 제한. 계정 존재 여부를 조회하지 않는다."""
import asyncio
import hashlib
import hmac
import ipaddress

import auth

TAKE = "SELECT console_login_take($1, $2, $3)"


def keys(request, username):
    # request.client는 uvicorn이 신뢰한 프록시만 해석한 값이다. XFF를 직접 읽지 않는다.
    host = request.client.host if request.client else "unknown"
    try:
        address = ipaddress.ip_address(host)
        host = str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)
    except ValueError:
        host = "unknown"
    def digest(value):
        return hmac.new(auth.SECRET.encode(), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
    return digest(host), digest(username), digest(host + "\x00" + username)


async def take(pool, request, username):
    async with asyncio.timeout(3):
        async with pool.acquire() as conn:
            value = await conn.fetchval(TAKE, *keys(request, username))
    if type(value) is not int or not 0 <= value <= 60:
        raise ValueError("InvalidLoginLimit")
    return value
