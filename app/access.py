"""화면과 독립적으로 검사하는 API 역할 권한."""
from fastapi import HTTPException, Request


def require_role(request: Request, *roles: str) -> dict:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "인증이 필요합니다")
    if user["r"] not in roles:
        raise HTTPException(403, f"권한이 없습니다 ({user['r']})")
    return user
