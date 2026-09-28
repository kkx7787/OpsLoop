"""화면과 독립적으로 검사하는 API 역할 권한."""
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute


def require_role(request: Request, *roles: str) -> dict:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "인증이 필요합니다")
    if user["r"] not in roles:
        raise HTTPException(403, f"권한이 없습니다 ({user['r']})")
    return user


class MaskedValidationRoute(APIRoute):
    """입력 검증 오류(422)에서 입력값(input · ctx)을 뺀다. 기본 처리기는 본문을 되돌려 주어 채널 주소가 응답에 실린다(notify).
    짝 없는 서로게이트 같은 입력은 되돌려 싣다가 인코딩 오류로 500 이 되므로 계정 API(accounts)도 같이 쓴다."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def masked(request: Request):
            try:
                return await handler(request)
            except RequestValidationError as error:
                detail = [{key: value for key, value in item.items() if key in ("type", "loc", "msg")}
                          for item in error.errors()]
                return JSONResponse({"detail": detail}, status_code=422, headers={"Cache-Control": "no-store"})
        return masked
