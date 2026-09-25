"""알림 발송기 (이슈 #33). 채널 주소 검증 · 메시지 틀 렌더 · Teams/웹훅 페이로드 · 큐 채우기 · 보내기.

콘솔 API 안에서 두 루프가 돈다. 큐 채우기(30초)는 사건을 notify_deliveries 에 한 번만 넣고,
보내기(15초)는 FOR UPDATE SKIP LOCKED 로 집어 채널 · 사건 종류별로 한 메시지로 보낸다.
콘솔 두 대가 같은 행을 집지 않는다. 채널 주소는 비밀값이라 로그 · 오류 · 이력 어디에도 넣지 않는다.
"""
import asyncio
import ipaddress
import json
import logging
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

from dashboard import PENDING
from live import console_name
from untrusted import reveal

log = logging.getLogger("opsloop.notify")

KST = timezone(timedelta(hours=9))
EVENTS = ("incident.created", "pending.overdue", "node.silent")
EVENT_LABELS = {"incident.created": "새 인시던트", "pending.overdue": "판정 지연", "node.silent": "노드 수신 끊김",
                "daily.summary": "일일 요약", "test": "시험 발송"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# 재시도 간격. n회째 실패 뒤 기다리는 초. 표에 없으면(4회째 실패) failed 다.
RETRY_SECONDS = {1: 60, 2: 300, 3: 900}
MAX_ITEMS = 20
# 소켓 연산마다 걸리는 한도(urllib). 이름 해석까지 포함한 한 번 보내기의 전체 한도는 HTTP_DEADLINE 이다.
HTTP_TIMEOUT = 10
HTTP_DEADLINE = 15
FILL_INTERVAL = 30
SEND_INTERVAL = 15
# 한 번에 집는 행 수. 묶음 하나가 이보다 크면 나머지는 다음 틱에 따로 나간다.
CLAIM_LIMIT = 500
# 이 시간 넘게 sending 인 행은 죽은 콘솔이 집은 것이다. 묶음마다 보내기 직전에 claimed_at 을 다시 찍고
# 한 번 보내기는 HTTP_DEADLINE 을 넘지 않으므로 살아 있는 콘솔의 행이 풀리지 않는다.
STALE_CLAIM = "5 minutes"
# 채널을 켜거나 범위를 넓힌 시각보다 이만큼 앞선 사건까지 넣는다(직전 채우기 틱과의 틈을 메운다).
FILL_SLACK = timedelta(minutes=1)
DAILY_HOUR = 9
DEFAULT_CONSOLE_URL = "http://192.168.70.254:8443"
PLACEHOLDERS = frozenset({"event_label", "count", "severity_counts", "rule_id", "rule_name", "severity",
                          "who", "elapsed", "first_ts", "incident_key", "link"})
# Power Automate Workflows 의 HTTP · Teams 웹훅 트리거 주소. 옛 logic.azure.com 주소는 2025-11-30 부터 동작하지 않고
# Office 365 커넥터(webhook.office.com)도 없어졌다. 흐름을 다시 저장하면 새 주소가 나온다.
TEAMS_SUFFIX = ".environment.api.powerplatform.com"
LEGACY_TEAMS_SUFFIXES = (".logic.azure.com", ".webhook.office.com")
# 해석기(glibc inet_aton)가 IPv4 로 읽는 숫자 이름표: 10진 · 0x 16진 · 0 으로 시작하는 8진
NUMERIC_LABEL_RE = re.compile(r"0x[0-9a-f]*|[0-9]+")
PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
BRACE_RE = re.compile(r"\{([^{}]*)\}")
# 틀에 넣는 값 하나의 글자 수 상한(표식으로 바꾼 뒤). 넘치면 '…' 로 끝난다.
VALUE_MAX = 200


# ----------------------------------------------------------------------
#  채널 주소 검증
# ----------------------------------------------------------------------

def validate_url(kind: str, url: str) -> str:
    """주소를 검사하고 호스트를 돌려준다. 문제는 ValueError 로 알린다(원문 주소는 메시지에 넣지 않는다)."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ValueError("주소를 입력해 주세요 (2048자 이내)")
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        raise ValueError("주소 형식이 올바르지 않습니다") from None
    if parts.scheme.lower() != "https":
        raise ValueError("https 주소만 받습니다")
    if parts.username is not None or parts.password is not None:
        raise ValueError("주소에 사용자 정보를 넣을 수 없습니다")
    if not host:
        raise ValueError("호스트가 없는 주소입니다")
    if kind == "teams":
        if host.endswith(TEAMS_SUFFIX):
            return host
        if host.endswith(LEGACY_TEAMS_SUFFIXES):
            raise ValueError("옛 Teams 웹훅 주소(logic.azure.com · webhook.office.com)는 더 이상 동작하지 않습니다. "
                             "Power Automate 에서 흐름을 다시 저장해 나온 *.environment.api.powerplatform.com 주소를 넣어 주세요")
        raise ValueError("Teams 웹훅은 Power Automate 워크플로 주소(*.environment.api.powerplatform.com)여야 합니다")
    if kind != "webhook":
        raise ValueError("알 수 없는 채널 종류입니다")
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("localhost 주소는 받지 않습니다")
    # 이름은 해석하지 않는다. 주소가 IP 일 때만 공인 인터넷 주소인지 본다.
    if all(NUMERIC_LABEL_RE.fullmatch(label) for label in host.split(".")):
        # 127.1 · 0x7f.1 · 2130706433 · 192.168.070.254 같은 줄임 · 16진 · 8진 표기는 해석기가 IP 로 읽으므로
        # 정식 점 네 개 10진 표기만 받는다.
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            raise ValueError("IP 주소는 점 네 개 10진 표기(예 203.0.113.10)로만 받습니다") from None
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return host
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (not address.is_global or address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified):
        raise ValueError("사설 · 링크로컬 · 루프백 등 공인 인터넷이 아닌 주소는 받지 않습니다")
    return host


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def url_tail(url: str) -> str:
    return url[-4:]


# ----------------------------------------------------------------------
#  메시지 틀
# ----------------------------------------------------------------------

def validate_template(template: str) -> str:
    """중괄호 안은 소문자 이름만 허용한다. {x:>5} 같은 형식 지정자와 속성 접근은 값 노출 위험이라 거부한다."""
    if not isinstance(template, str) or not template.strip():
        raise ValueError("메시지 틀을 입력해 주세요")
    if len(template) > 300:
        raise ValueError("메시지 틀은 300자 이내입니다")
    for inner in BRACE_RE.findall(template):
        if not re.fullmatch(r"[a-z_]+", inner):
            raise ValueError("자리표시자는 {이름} 꼴만 쓸 수 있습니다 (형식 지정자 불가)")
    return template


def clean_value(value) -> str:
    """틀에 넣을 값 하나를 정리한다(이슈 #41). 숨은 문자(방향 제어 · 제로폭 · 제어 문자)는 ⟨U+XXXX⟩ 표식,
    줄바꿈 · 탭은 공백, VALUE_MAX 글자 상한. 한 값이 알림 안에서 가짜 줄 · 뒤집힌 글자를 만들지 못한다.
    지금 값(규칙 이름 · 출발지 IP · user:<콘솔 계정> · node:<id>)은 공격자가 정하지 못하지만 규칙이 늘어도 막히게 둔다."""
    return reveal(value, newline=" ", limit=VALUE_MAX)


def clean_payload(payload: dict) -> dict:
    """웹훅 items 의 글자 값도 틀 값과 같게 정리한다. 받는 쪽이 마크다운 · HTML 로 그릴 수 있다.
    incident_key 는 받는 쪽이 DB · 콘솔 주소와 맞춰 보는 식별자라 원문 그대로 둔다(JSON 문자열로만 나간다)."""
    return {k: clean_value(v) if isinstance(v, str) and k != "incident_key" else v for k, v in payload.items()}


def render(template: str, values: dict) -> str:
    """문자 치환만 한다. str.format 은 쓰지 않는다. 아는 자리표시자만 바꾸고 값이 없으면 '-' 다.

    값은 clean_value 로 정리한다. {link} 만 그대로 둔다. 콘솔 주소(OPSLOOP_CONSOLE_URL) 뒤에 사건 키를
    quote(safe='') 로 붙인 것이라 콘솔 경로를 벗어나지 못하고, 자르면 링크가 깨진다.
    """
    def swap(match):
        name = match.group(1)
        if name not in PLACEHOLDERS:
            return match.group(0)
        value = values.get(name)
        if value is None or value == "":
            return "-"
        return str(value) if name == "link" else clean_value(value)
    return PLACEHOLDER_RE.sub(swap, template)


def parse_ts(value):
    if value is None or isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def elapsed_text(then, now) -> str:
    then = parse_ts(then)
    if then is None:
        return "-"
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return "방금"
    if seconds < 3600:
        return f"{seconds // 60}분 전"
    if seconds < 86400:
        return f"{seconds // 3600}시간 전"
    return f"{seconds // 86400}일 전"


def kst_text(value) -> str:
    parsed = parse_ts(value)
    return parsed.astimezone(KST).strftime("%Y-%m-%d %H:%M") if parsed else "-"


def console_url() -> str:
    return os.environ.get("OPSLOOP_CONSOLE_URL", DEFAULT_CONSOLE_URL).rstrip("/")


def item_link(event: str, payload: dict) -> str:
    base = console_url()
    if event == "test":
        # 시험 발송의 사건 키는 예시라 상세가 없다. 알림 설정 화면으로 보낸다.
        return f"{base}/alerts"
    if event == "node.silent":
        return f"{base}/nodes"
    if event == "daily.summary":
        return f"{base}/"
    key = payload.get("incident_key")
    return f"{base}/incidents/{quote(str(key), safe='')}" if key else f"{base}/incidents"


def item_values(event: str, payload: dict, now) -> dict:
    """항목 줄에 넣을 값. 요약 payload 만 보며 원문 로그 · 비밀번호 · 내부 주소는 없다."""
    if event == "node.silent":
        return {"rule_id": "-", "rule_name": payload.get("hostname") or payload.get("node_id"), "severity": "-",
                "who": f"node:{payload.get('node_id')}", "elapsed": elapsed_text(payload.get("since"), now),
                "first_ts": kst_text(payload.get("since")), "incident_key": "-", "link": item_link(event, payload)}
    return {"rule_id": payload.get("rule_id"), "rule_name": payload.get("rule_name"), "severity": payload.get("severity"),
            "who": payload.get("who"), "elapsed": elapsed_text(payload.get("first_ts"), now),
            "first_ts": kst_text(payload.get("first_ts")), "incident_key": payload.get("incident_key"),
            "link": item_link(event, payload)}


def severity_counts(payloads) -> str:
    counts = {}
    for p in payloads:
        sev = p.get("severity")
        if sev in SEVERITY_RANK:
            counts[sev] = counts.get(sev, 0) + 1
    return " · ".join(f"{sev} {counts[sev]}" for sev in sorted(counts, key=SEVERITY_RANK.get)) or "-"


def daily_line(payload: dict, now) -> str:
    oldest = int(payload.get("oldest_seconds") or 0)
    oldest_text = elapsed_text(now - timedelta(seconds=oldest), now) if oldest else "-"
    return (f"미판정 {payload.get('pending_total', 0)}건 · 최고 경과 {oldest_text} · "
            f"목표 초과 {payload.get('overdue', 0)}건 · 최근 24시간 사건 {payload.get('incidents_24h', 0)}건")


def is_daily_message(channel, event: str) -> bool:
    """일일 요약 모양(머리말 + 고정 요약 줄)으로 그릴지. 일일 채널의 시험 발송도 이 모양이다."""
    return event == "daily.summary" or (event == "test" and channel.get("grade") == "daily")


def build_message(channel, event: str, payloads: list, now=None) -> dict:
    """머리말 한 번 · 항목 줄은 사건마다(최대 20개, 넘으면 '외 n건') · 마지막에 콘솔 링크."""
    now = now or datetime.now(timezone.utc)
    link = item_link(event, payloads[0] if len(payloads) == 1 else {})
    if is_daily_message(channel, event):
        payload = payloads[0]
        header_values = {"event_label": EVENT_LABELS[event], "count": payload.get("pending_total", 0),
                         "severity_counts": payload.get("severity_counts") or "-", "link": link}
        return {"title": render(channel["template_header"], header_values), "lines": [daily_line(payload, now)], "link": link}
    header_values = {"event_label": EVENT_LABELS.get(event, event), "count": len(payloads),
                     "severity_counts": severity_counts(payloads), "link": link}
    if len(payloads) == 1:
        header_values |= item_values(event, payloads[0], now)
    lines = [render(channel["template_item"], item_values(event, p, now)) for p in payloads[:MAX_ITEMS]]
    if len(payloads) > MAX_ITEMS:
        lines.append(f"외 {len(payloads) - MAX_ITEMS}건")
    return {"title": render(channel["template_header"], header_values), "lines": lines, "link": link}


def text_block(text: str, **run) -> dict:
    """마크다운을 해석하지 않는 글 한 덩이. TextBlock 은 [글](주소) · **굵게** · 목록 기호를 해석해
    값 안에 링크 · 가짜 줄을 만들 수 있다. RichTextBlock 의 TextRun 은 글자를 그대로 보인다(Adaptive Card 1.2+)."""
    return {"type": "RichTextBlock", "inlines": [{"type": "TextRun", "text": text} | run]}


def teams_card(message: dict) -> dict:
    """Power Automate 'Teams 웹훅 요청을 받으면' 트리거가 받는 Adaptive Card 모양.
    머리말 한 덩이 뒤에 항목 줄마다 한 덩이. 줄을 \\n 으로 잇지 않으므로 줄바꿈 해석에 기대지 않는다.
    링크는 Action.OpenUrl 하나뿐이고 콘솔 주소다."""
    body = [text_block(message["title"], weight="Bolder", size="Medium")]
    body += [text_block(line) for line in message["lines"]]
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                    "body": body,
                    "actions": [{"type": "Action.OpenUrl", "title": "콘솔에서 보기", "url": message["link"]}]}}]}


def webhook_body(event: str, message: dict, payloads: list) -> dict:
    return {"source": "opsloop", "event": event, "title": message["title"], "lines": message["lines"],
            "items": [clean_payload(p) for p in payloads], "console_url": message["link"]}


def build_body(channel, event: str, payloads: list, now=None) -> dict:
    message = build_message(channel, event, payloads, now)
    return teams_card(message) if channel["kind"] == "teams" else webhook_body(event, message, payloads)


def example_payload(now=None, grade: str = "immediate") -> dict:
    """시험 발송 값. 운영 값이 아니다. 일일 채널이면 요약 모양 값이다."""
    now = now or datetime.now(timezone.utc)
    if grade == "daily":
        return {"date": now.astimezone(KST).strftime("%Y-%m-%d"), "pending_total": 4, "oldest_seconds": 3 * 3600,
                "overdue": 1, "incidents_24h": 9, "severity_counts": "high 1 · low 3"}
    return {"incident_key": "R001|v2|192.0.2.8|example", "rule_id": "R001", "rule_name": "예시 규칙", "severity": "high",
            "who": "192.0.2.8", "first_ts": (now - timedelta(minutes=12)).isoformat()}


# ----------------------------------------------------------------------
#  HTTP
# ----------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post_json(url: str, body: dict):
    """(응답 코드, 오류) 를 돌려준다. 오류에는 예외 이름 · 응답 코드만 넣고 주소 · 응답 본문은 넣지 않는다."""
    data = json.dumps(body, ensure_ascii=False).encode()
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "OpsLoop"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, None
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, f"HTTP {error.code}"
    except urllib.error.URLError as error:
        # urllib 은 이름 해석 실패 · 연결 거부 · 시간 초과 · 인증서 오류를 모두 URLError 로 감싼다. 원인 이름만 남긴다.
        reason = error.reason
        return None, type(reason).__name__ if isinstance(reason, BaseException) else "URLError"
    except Exception as error:
        return None, type(error).__name__


async def deliver(url: str, body: dict):
    """post_json 을 스레드에서 돌리고 이름 해석까지 포함해 HTTP_DEADLINE 안에 끝낸다."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(post_json, url, body), HTTP_DEADLINE)
    except TimeoutError:
        return None, "TimeoutError"


def retry_after(attempts: int):
    """attempts 회째 실패 뒤 기다릴 초. None 이면 더 보내지 않는다(failed)."""
    return RETRY_SECONDS.get(attempts)


def is_success(code) -> bool:
    return code is not None and 200 <= code < 300


# ----------------------------------------------------------------------
#  큐 채우기 · 보내기
# ----------------------------------------------------------------------

# 채널 기준 시각($3 = enabled_at - FILL_SLACK) 뒤에 생긴 사건만 넣는다. 만들거나 다시 켜자마자
# 지난 하루치가 한꺼번에 나가지 않게 한다.
FILL_INCIDENT = """
INSERT INTO notify_deliveries (channel_id, event, subject_key, payload)
SELECT $1, 'incident.created', i.incident_key,
       jsonb_build_object('incident_key', i.incident_key, 'rule_id', i.rule_id, 'rule_name', i.rule_name,
                          'severity', i.severity, 'who', coalesce(host(i.actor_ip), i.target), 'first_ts', i.first_ts)
  FROM incidents i
 WHERE i.created_at >= now() - interval '24 hours' AND i.created_at >= $3
   AND CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END <= $2
ON CONFLICT (channel_id, event, subject_key) DO NOTHING
"""

# 대시보드의 미판정 목표 시간(critical · R2xx 1h, high 4h, medium 12h, low 24h)을 넘긴 건.
# 목표를 넘긴 시각이 채널 기준 시각($4) 뒤인 것만 넣는다. 채널을 만들거나 켤 때 밀린 미판정이 쏟아지지 않게 한다.
FILL_OVERDUE = PENDING + """
INSERT INTO notify_deliveries (channel_id, event, subject_key, payload)
SELECT $2, 'pending.overdue', incident_key,
       jsonb_build_object('incident_key', incident_key, 'rule_id', rule_id, 'rule_name', rule_name,
                          'severity', severity, 'who', coalesce(host(actor_ip), target), 'first_ts', first_ts,
                          'target_seconds', target_seconds)
  FROM pending
 WHERE age >= target_seconds
   AND first_ts + make_interval(secs => target_seconds) >= $4
   AND CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END <= $3
ON CONFLICT (channel_id, event, subject_key) DO NOTHING
"""

FILL_SILENT = """
INSERT INTO notify_deliveries (channel_id, event, subject_key, payload)
SELECT $1, 'node.silent', 'node:' || node_id || '@' || (to_jsonb(coalesce(last_seen_at, registered_at)) #>> '{}'),
       jsonb_build_object('node_id', node_id, 'hostname', hostname, 'since', coalesce(last_seen_at, registered_at))
  FROM nodes
 WHERE status = 'active' AND 'metrics' = ANY(logs)
   AND coalesce(last_seen_at, registered_at) < now() - interval '10 minutes'
ON CONFLICT (channel_id, event, subject_key) DO NOTHING
"""

DAILY_COUNTS = PENDING + """
SELECT count(*) AS pending_total, coalesce(max(age), 0)::bigint AS oldest_seconds,
       count(*) FILTER (WHERE age >= target_seconds) AS overdue,
       count(*) FILTER (WHERE severity = 'critical') AS critical, count(*) FILTER (WHERE severity = 'high') AS high,
       count(*) FILTER (WHERE severity = 'medium') AS medium, count(*) FILTER (WHERE severity = 'low') AS low,
       (SELECT count(*) FROM incidents WHERE created_at >= $1::timestamptz - interval '24 hours') AS incidents_24h
  FROM pending
"""

FILL_DAILY = """
INSERT INTO notify_deliveries (channel_id, event, subject_key, payload)
VALUES ($1, 'daily.summary', $2, $3::jsonb)
ON CONFLICT (channel_id, event, subject_key) DO NOTHING
"""

RECOVER_OWN = """
UPDATE notify_deliveries SET status = 'queued', claimed_at = NULL, claimed_by = NULL
 WHERE status = 'sending' AND claimed_by = $1
"""

# 되돌리기 전에 본다. 같은 이름으로 최근에 집은 행이 있으면 그 이름의 다른 발송기가 지금 보내는 중일 수 있다.
# 한 번 보내기는 HTTP_DEADLINE(15초) 안에 끝나고 묶음마다 claimed_at 을 다시 찍으므로 2분이면 넉넉하다.
PEER_ALIVE = """
SELECT count(*) FROM notify_deliveries
 WHERE status = 'sending' AND claimed_by = $1 AND claimed_at > now() - interval '2 minutes'
"""

RELEASE_STALE = f"""
UPDATE notify_deliveries SET status = 'queued', claimed_at = NULL, claimed_by = NULL
 WHERE status = 'sending' AND claimed_at < now() - interval '{STALE_CLAIM}'
"""

# 묶음 단위로 집는다. (채널, 사건 종류) 무리에서 가장 오래된 첫 시도 행이 묶음 시간을 지나면 그 무리의
# 대기 행을 모두 집어 한 메시지로 보낸다. 창은 무리의 첫 행이 들어온 때부터 잰다.
# 재시도 행은 제 시각에 집는다. 일일 요약은 묶을 것이 없어 바로 보낸다. 꺼진 채널은 집지 않는다.
CLAIM = f"""
UPDATE notify_deliveries d SET status = 'sending', claimed_at = now(), claimed_by = $1
 WHERE d.id IN (
       SELECT q.id FROM notify_deliveries q JOIN notify_channels ch ON ch.id = q.channel_id
        WHERE q.status = 'queued' AND q.next_attempt_at <= now() AND ch.enabled
          AND (q.attempts > 0 OR q.event = 'daily.summary'
               OR EXISTS (SELECT 1 FROM notify_deliveries o
                           WHERE o.channel_id = q.channel_id AND o.event = q.event AND o.status = 'queued'
                             AND o.attempts = 0 AND o.created_at <= now() - make_interval(secs => ch.batch_seconds)))
        ORDER BY q.channel_id, q.event, q.created_at, q.id
        FOR UPDATE OF q SKIP LOCKED LIMIT {CLAIM_LIMIT})
RETURNING d.id, d.channel_id, d.event, d.subject_key, d.payload, d.attempts
"""

# 보내기 직전에 아직 내 것인 행만 남기고 claimed_at 을 다시 찍는다. 앞 묶음이 오래 걸려도 이 묶음이 풀리지 않는다.
TOUCH = """
UPDATE notify_deliveries SET claimed_at = now()
 WHERE id = ANY($1::bigint[]) AND status = 'sending' AND claimed_by = $2
RETURNING id
"""

# 결과 기록은 내가 집은 행(status='sending' AND claimed_by=나)에만 한다. 다른 콘솔이 되찾아 간 행은 건드리지 않는다.
MARK_SENT = """
UPDATE notify_deliveries SET status = 'sent', attempts = attempts + 1, sent_at = now(), response_code = $2, error = NULL
 WHERE id = ANY($1::bigint[]) AND status = 'sending' AND claimed_by = $3
"""

MARK_RETRY = """
UPDATE notify_deliveries SET status = 'queued', attempts = $2, response_code = $3, error = $4,
       next_attempt_at = now() + make_interval(secs => $5), claimed_at = NULL, claimed_by = NULL
 WHERE id = $1 AND status = 'sending' AND claimed_by = $6
"""

MARK_FAILED = """
UPDATE notify_deliveries SET status = 'failed', attempts = $2, response_code = $3, error = $4
 WHERE id = $1 AND status = 'sending' AND claimed_by = $5
"""

# 채널을 끄거나 등급 · 사건 종류를 바꾸면 이제 보내지 않을 대기 행을 보내지 않음으로 닫는다.
# 끈 채널의 알림이 다시 켤 때 뒤늦게 나가지 않게 한다.
CANCEL_QUEUED = """
UPDATE notify_deliveries SET status = 'failed', error = $2
 WHERE channel_id = $1 AND status = 'queued'
   AND (NOT $3::boolean
        OR (event = 'daily.summary') <> ($4::text = 'daily')
        OR (event <> 'daily.summary' AND event <> ALL($5::text[])))
"""


def updated_count(status: str) -> int:
    """asyncpg execute 의 'UPDATE n' 에서 n."""
    try:
        return int(status.rsplit(" ", 1)[-1])
    except (ValueError, AttributeError):
        return 0


def load_payload(value):
    return value if isinstance(value, dict) else json.loads(value)


class Notifier:
    def __init__(self, pool, worker: str | None = None):
        self.pool = pool
        # 콘솔마다 다른 고정 이름(live.console_name: OPSLOOP_WORKER, 없으면 hostname). 화면에 보이는 콘솔 이름과 같다.
        # 컨테이너 hostname 은 다시 만들 때마다 바뀌어 시작 때 되돌리기가 빗나간다.
        self.named = bool(worker or os.environ.get("OPSLOOP_WORKER"))
        self.worker = (worker or console_name())[:64]
        self.tasks: list[asyncio.Task] = []

    async def start(self):
        if not self.named:
            log.warning("알림 발송기 이름(OPSLOOP_WORKER)이 비어 hostname %r 을 씁니다. 컨테이너를 다시 만들면 이름이 "
                        "바뀌어 시작 때 되돌리기가 빗나갑니다(5분 뒤 풀림). 콘솔마다 다른 값을 주세요", self.worker)
        # 재기동 전 이 콘솔이 집었던 행은 다시 queued 다. 다른 콘솔이 집은 행은 건드리지 않는다.
        # 표가 아직 없거나 권한이 빠져도 콘솔의 다른 기능은 떠야 하므로 경고만 남긴다(5분 뒤 RELEASE_STALE 이 푼다).
        # 같은 이름의 발송기가 둘이면(콘솔 B 에 A 의 .env 를 그대로 옮긴 경우) 서로의 보내는 중 행을 되돌려 두 번 보낼 수
        # 있다. 되돌리기 전에 최근 2분 안에 이 이름으로 집은 행이 있으면 경고한다. 동작은 그대로 둔다.
        try:
            async with self.pool.acquire() as c:
                recent = await c.fetchval(PEER_ALIVE, self.worker)
                if recent:
                    log.warning("같은 이름(%r)의 다른 발송기가 살아 있을 수 있습니다: 최근 2분 안에 이 이름으로 집은 보내는 중 "
                                "행 %d건. OPSLOOP_WORKER 를 콘솔마다 다르게 주세요", self.worker, recent)
                await c.execute(RECOVER_OWN, self.worker)
        except Exception as error:
            log.warning("알림 시작 때 되돌리기 실패: %s", type(error).__name__)
        self.tasks = [asyncio.create_task(self.loop(FILL_INTERVAL, self.fill), name="notify-fill"),
                      asyncio.create_task(self.loop(SEND_INTERVAL, self.send), name="notify-send")]

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self.tasks = []

    async def loop(self, interval, step):
        while True:
            try:
                async with self.pool.acquire() as c:
                    await step(c)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # 주소 · 응답 본문은 여기까지 오지 않는다. 예외 이름만 남긴다.
                log.warning("알림 %s 실패: %s", step.__name__, type(error).__name__)
            await asyncio.sleep(interval)

    async def fill(self, c) -> None:
        """활성 채널마다 사건을 큐에 넣는다. (channel, event, subject) 가 같으면 넣지 않는다."""
        now = await c.fetchval("SELECT now()")
        channels = await c.fetch(
            "SELECT id, grade, events, min_severity, enabled_at FROM notify_channels WHERE enabled ORDER BY id")
        for ch in channels:
            rank = SEVERITY_RANK.get(ch["min_severity"], 3)
            since = ch["enabled_at"] - FILL_SLACK
            if ch["grade"] == "immediate":
                if "incident.created" in ch["events"]:
                    await c.execute(FILL_INCIDENT, ch["id"], rank, since)
                if "pending.overdue" in ch["events"]:
                    await c.execute(FILL_OVERDUE, now, ch["id"], rank, since)
                if "node.silent" in ch["events"]:
                    await c.execute(FILL_SILENT, ch["id"])
            elif ch["grade"] == "daily":
                await self.fill_daily(c, ch["id"], now)

    async def fill_daily(self, c, channel_id, now) -> None:
        """09:00 KST 가 지나면 그날 한 번. 미판정 수 · 최고 경과 · 목표 초과 수 · 최근 24시간 사건 수."""
        local = now.astimezone(KST)
        if local.hour < DAILY_HOUR:
            return
        counts = dict(await c.fetchrow(DAILY_COUNTS, now))
        payload = {"date": local.strftime("%Y-%m-%d"), "pending_total": counts["pending_total"],
                   "oldest_seconds": counts["oldest_seconds"], "overdue": counts["overdue"],
                   "incidents_24h": counts["incidents_24h"],
                   "severity_counts": " · ".join(f"{sev} {counts[sev]}" for sev in SEVERITY_RANK if counts[sev]) or "-"}
        await c.execute(FILL_DAILY, channel_id, payload["date"], json.dumps(payload, ensure_ascii=False))

    async def send(self, c) -> int:
        """집은 행을 채널 · 사건 종류별로 묶어 보낸다. 보낸 묶음 수를 돌려준다."""
        await c.execute(RELEASE_STALE)
        rows = await c.fetch(CLAIM, self.worker)
        groups: dict[tuple, list] = {}
        for row in rows:
            groups.setdefault((row["channel_id"], row["event"]), []).append(row)
        sent = 0
        for (channel_id, event), items in groups.items():
            sent += await self.send_group(c, channel_id, event, items)
        return sent

    async def send_group(self, c, channel_id, event, items) -> bool:
        """한 묶음을 한 메시지로 보낸다. 보내기 직전에 아직 내 것인 행만 남긴다. 보냈으면 True."""
        mine = {row["id"] for row in await c.fetch(TOUCH, [row["id"] for row in items], self.worker)}
        items = [row for row in items if row["id"] in mine]
        if not items:
            return False
        channel = await c.fetchrow(
            "SELECT id, name, kind, grade, url, template_header, template_item FROM notify_channels WHERE id = $1",
            channel_id)
        if channel is None:
            for row in items:
                await c.execute(MARK_FAILED, row["id"], row["attempts"] + 1, None, "ChannelMissing", self.worker)
            return False
        now = await c.fetchval("SELECT now()")
        payloads = [load_payload(row["payload"]) for row in items]
        body = build_body(channel, event, payloads, now)
        code, error = await deliver(channel["url"], body)
        await self.settle(c, items, code, error)
        log.info("알림 채널=%s 사건=%s %d건 → %s", channel_id, event, len(items), code if code is not None else error)
        return True

    async def settle(self, c, items, code, error) -> None:
        written = 0
        if is_success(code):
            written = updated_count(await c.execute(MARK_SENT, [row["id"] for row in items], code, self.worker))
        else:
            for row in items:
                attempts = row["attempts"] + 1
                delay = retry_after(attempts)
                if delay is None:
                    status = await c.execute(MARK_FAILED, row["id"], attempts, code, error, self.worker)
                else:
                    status = await c.execute(MARK_RETRY, row["id"], attempts, code, error, float(delay), self.worker)
                written += updated_count(status)
        if written < len(items):
            # 보내는 사이 다른 콘솔이 되찾아 간 행이다. 그쪽 결과를 덮어쓰지 않는다.
            log.warning("알림 결과 기록 건너뜀 %d건 (다른 콘솔이 가져감)", len(items) - written)
