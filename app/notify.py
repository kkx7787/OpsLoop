"""알림 채널 · 발송 이력 API (이슈 #33). admin 전용. 채널 주소는 비밀값이라 응답 · 감사 · 이력에 원문을 넣지 않는다."""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Literal

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_validator

import notifier
from access import require_role
from operations import audit


class MaskedValidationRoute(APIRoute):
    """입력 검증 오류(422)에서 입력값(input · ctx)을 뺀다. 기본 처리기는 본문을 되돌려 주어 채널 주소가 응답에 실린다."""

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


router = APIRouter(route_class=MaskedValidationRoute)

KINDS = Literal["teams", "webhook"]
GRADES = Literal["immediate", "daily"]
EVENT = Literal["incident.created", "pending.overdue", "node.silent"]
SEVERITY = Literal["critical", "high", "medium", "low"]
DELIVERY_STATUS = Literal["queued", "sending", "sent", "failed"]
FIELDS = ("name", "kind", "url", "grade", "events", "min_severity", "batch_seconds",
          "template_header", "template_item", "enabled")


class ChannelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    kind: KINDS
    url: str = Field(min_length=1, max_length=2048)
    grade: GRADES
    events: list[EVENT] = Field(min_length=1)
    min_severity: SEVERITY = "low"
    batch_seconds: int = Field(default=300, ge=0, le=86400)
    template_header: str = Field(default="[OpsLoop] {event_label} {count}건", max_length=300)
    template_item: str = Field(default="{rule_id} {rule_name} · {severity} · {who} · {elapsed}", max_length=300)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("채널 이름을 입력해 주세요")
        return value

    @field_validator("events")
    @classmethod
    def valid_events(cls, value):
        return sorted(set(value))

    @field_validator("template_header", "template_item")
    @classmethod
    def valid_template(cls, value):
        return notifier.validate_template(value)

    @field_validator("url")
    @classmethod
    def strip_url(cls, value):
        # 주소 규칙 검사는 엔드포인트에서 한다(checked_url). 모델 검증 오류는 입력 본문을 함께 싣기 때문이다.
        return value.strip() if isinstance(value, str) else value


class ChannelUpdate(ChannelIn):
    # 비어 있으면 저장된 주소를 유지한다. 화면은 저장된 주소를 받지 못하므로 되돌려 보낼 수 없다.
    url: str | None = Field(default=None, max_length=2048)


def checked_url(kind: str, url: str) -> str:
    """주소를 검사하고 호스트를 돌려준다. 오류 문장에는 주소 원문이 없다."""
    try:
        return notifier.validate_url(kind, url)
    except ValueError as error:
        raise HTTPException(422, str(error), headers={"Cache-Control": "no-store"}) from None


def audit_name(name: str) -> str:
    """감사 상세는 key=value 를 공백으로 가른다. 이름의 공백은 _ 로 바꾼다."""
    return re.sub(r"\s+", "_", name)


def public_channel(row) -> dict:
    """응답 모양. url 원문은 절대 넣지 않는다."""
    url = row["url"]
    last = None
    if row.get("last_status") is not None:
        # at: 보낸 시각, 없으면 집은 시각 · 만든 시각(실패 · 대기도 언제였는지 보인다)
        last = {"status": row["last_status"], "sent_at": row["last_sent_at"], "response_code": row["last_response_code"],
                "error": row.get("last_error"), "at": row.get("last_at")}
    return {"id": row["id"], "name": row["name"], "kind": row["kind"], "grade": row["grade"], "events": list(row["events"]),
            "min_severity": row["min_severity"], "batch_seconds": row["batch_seconds"],
            "template_header": row["template_header"], "template_item": row["template_item"], "enabled": row["enabled"],
            "url_tail": notifier.url_tail(url), "url_host": notifier.url_host(url),
            "created_at": row["created_at"], "updated_at": row["updated_at"], "updated_by": row["updated_by"],
            "last_delivery": last}


CHANNEL_SELECT = """
SELECT ch.*, d.status AS last_status, d.sent_at AS last_sent_at, d.response_code AS last_response_code,
       d.error AS last_error, d.at AS last_at
  FROM notify_channels ch
  LEFT JOIN LATERAL (
       SELECT status, sent_at, response_code, error, coalesce(sent_at, claimed_at, created_at) AS at
         FROM notify_deliveries WHERE channel_id = ch.id
        ORDER BY coalesce(sent_at, claimed_at, created_at) DESC, id DESC LIMIT 1) d ON true
"""


@router.get("/api/notify/channels")
async def list_channels(request: Request, response: Response):
    require_role(request, "admin")
    async with request.app.state.pool.acquire() as c:
        rows = await c.fetch(CHANNEL_SELECT + " ORDER BY ch.name, ch.id")
    response.headers["Cache-Control"] = "no-store"
    return [public_channel(dict(row)) for row in rows]


async def fetch_channel(c, channel_id: int) -> dict:
    row = await c.fetchrow(CHANNEL_SELECT + " WHERE ch.id = $1", channel_id)
    if row is None:
        raise HTTPException(404, "알림 채널을 찾을 수 없습니다")
    return dict(row)


@router.post("/api/notify/channels", status_code=201)
async def create_channel(body: ChannelIn, request: Request, response: Response):
    user = require_role(request, "admin")
    host = checked_url(body.kind, body.url)
    try:
        async with request.app.state.pool.acquire() as c, c.transaction():
            channel_id = await c.fetchval("""
                INSERT INTO notify_channels (name, kind, url, grade, events, min_severity, batch_seconds,
                                             template_header, template_item, enabled, created_by, updated_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11) RETURNING id""",
                body.name, body.kind, body.url, body.grade, body.events, body.min_severity, body.batch_seconds,
                body.template_header, body.template_item, body.enabled, user["u"])
            await audit(c, user["u"], "console.notify.channel.created",
                        f"channel={audit_name(body.name)} id={channel_id} kind={body.kind} host={host} grade={body.grade}")
            row = await fetch_channel(c, channel_id)
    except asyncpg.UniqueViolationError:
        raise HTTPException(409, "같은 이름의 채널이 있습니다")
    response.headers["Cache-Control"] = "no-store"
    return public_channel(row)


@router.put("/api/notify/channels/{channel_id}")
async def update_channel(channel_id: int, body: ChannelUpdate, request: Request, response: Response):
    user = require_role(request, "admin")
    try:
        async with request.app.state.pool.acquire() as c, c.transaction():
            current = await c.fetchrow("SELECT * FROM notify_channels WHERE id = $1 FOR UPDATE", channel_id)
            if current is None:
                raise HTTPException(404, "알림 채널을 찾을 수 없습니다")
            values = body.model_dump()
            if values["url"]:
                checked_url(values["kind"], values["url"])
            else:
                values["url"] = current["url"]
                # 종류를 바꾸면 저장된 주소가 새 종류의 호스트 규칙에 맞아야 한다
                try:
                    notifier.validate_url(values["kind"], values["url"])
                except ValueError as error:
                    raise HTTPException(422, f"저장된 주소가 새 종류에 맞지 않습니다. 주소를 함께 입력해 주세요 ({error})")
            changed = [name for name in FIELDS
                       if (sorted(current[name]) if name == "events" else current[name]) != values[name]]
            if changed:
                # 다시 켜거나 알림 범위를 넓히면 기준 시각을 옮긴다. 그 전의 사건 · 목표 초과는 한꺼번에 보내지 않는다.
                widened = values["enabled"] and (
                    not current["enabled"] or values["grade"] != current["grade"]
                    or bool(set(values["events"]) - set(current["events"]))
                    or notifier.SEVERITY_RANK[values["min_severity"]] > notifier.SEVERITY_RANK[current["min_severity"]])
                await c.execute("""
                    UPDATE notify_channels SET name = $2, kind = $3, url = $4, grade = $5, events = $6, min_severity = $7,
                           batch_seconds = $8, template_header = $9, template_item = $10, enabled = $11,
                           updated_by = $12, updated_at = now(), enabled_at = CASE WHEN $13 THEN now() ELSE enabled_at END
                     WHERE id = $1""",
                    channel_id, values["name"], values["kind"], values["url"], values["grade"], values["events"],
                    values["min_severity"], values["batch_seconds"], values["template_header"], values["template_item"],
                    values["enabled"], user["u"], widened)
                await c.execute(notifier.CANCEL_QUEUED, channel_id,
                                "ChannelDisabled" if not values["enabled"] else "ChannelChanged",
                                values["enabled"], values["grade"], values["events"])
                # 바뀐 필드 이름만 남긴다. 주소 · 틀의 값은 감사에 넣지 않는다.
                await audit(c, user["u"], "console.notify.channel.changed",
                            f"channel={audit_name(current['name'])} id={channel_id} fields={','.join(changed)}")
            row = await fetch_channel(c, channel_id)
    except asyncpg.UniqueViolationError:
        raise HTTPException(409, "같은 이름의 채널이 있습니다")
    response.headers["Cache-Control"] = "no-store"
    return public_channel(row)


@router.post("/api/notify/channels/{channel_id}/test")
async def test_channel(channel_id: int, request: Request):
    """그 채널의 틀로 예시 값을 그려 한 번 보낸다. 결과는 이력에 event='test' 로 남는다."""
    require_role(request, "admin")
    async with request.app.state.pool.acquire() as c:
        channel = await c.fetchrow(
            "SELECT id, name, kind, grade, url, template_header, template_item FROM notify_channels WHERE id = $1",
            channel_id)
        if channel is None:
            raise HTTPException(404, "알림 채널을 찾을 수 없습니다")
        now = datetime.now(timezone.utc)
        payload = notifier.example_payload(now, channel["grade"])
        body = notifier.build_body(channel, "test", [payload], now)
        code, error = await notifier.deliver(channel["url"], body)
        status = "sent" if notifier.is_success(code) else "failed"
        await c.execute("""
            INSERT INTO notify_deliveries (channel_id, event, subject_key, payload, status, attempts, response_code, error,
                                           claimed_at, claimed_by, sent_at)
            VALUES ($1, 'test', $2, $3::jsonb, $4, 1, $5, $6, now(), $7,
                    CASE WHEN $4 = 'sent' THEN now() END)""",
            channel_id, f"test:{uuid.uuid4()}", json.dumps(payload, ensure_ascii=False), status, code, error,
            getattr(getattr(request.app.state, "notifier", None), "worker", "console"))
    return {"status": status, "response_code": code, "error": error}


@router.get("/api/notify/deliveries")
async def list_deliveries(request: Request, channel_id: int | None = None, status: DELIVERY_STATUS | None = None,
                          limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    require_role(request, "admin")
    where = "WHERE ($1::bigint IS NULL OR d.channel_id = $1) AND ($2::text IS NULL OR d.status = $2)"
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        total = await c.fetchval(f"SELECT count(*) FROM notify_deliveries d {where}", channel_id, status)
        rows = await c.fetch(f"""
            SELECT d.id, d.channel_id, ch.name AS channel_name, d.event, d.subject_key, d.status, d.attempts,
                   d.response_code, d.error, d.created_at, d.sent_at, d.next_attempt_at
              FROM notify_deliveries d JOIN notify_channels ch ON ch.id = d.channel_id
              {where}
             ORDER BY d.created_at DESC, d.id DESC LIMIT $3 OFFSET $4""", channel_id, status, limit, offset)
    return {"rows": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}
