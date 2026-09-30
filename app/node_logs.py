"""보호 대상 장비 최근 로그 (이슈 #73). GET /api/devices/{device_id}/logs

보호 대상 장비(#72 의 group=protected: web-01 · 등록 노드 카드)의 웹 접근(nginx.*) · SSH 인증(sshd.*) 줄을 최근 7일에서 최신 N줄
(기본 100, 상한 200) 읽는다. 화면은 5초마다 이 창을 다시 받아 줄 id 로 합친다(events 에 적재 시각 열이 없어 ts 커서로 이어 받지 않는다).
반복 읽기 · 읽기 전용 트랜잭션 하나에서 읽는다(상태판과 같다). 권한은 사건 상세(GET /api/incidents/{key})처럼 로그인한 모든 역할이다.

  - 발생원(events.sensor)은 장비 id 그대로다. 다리는 관문이 토큰으로 증명한 테넌트(node_id)를 parse_agent.parse 에 넘기고
    파서가 sensor=node_id 로 적재한다. 줄 속 호스트명 · nodes.sensor 는 쓰지 않는다. web-01 은 'web-01' 이다
  - provenance 는 real 만이다. 이벤트 이름은 늘 허용 목록(nginx. · sshd.)으로 거른다. 감사 · 콘솔 기록은 발생원이 달라 빠진다
  - 가림은 응답에서 한다(브라우저에 원문을 보내지 않는다). password 열은 IS NOT NULL 로만 읽는다(has_password, 사건 상세 원문과 같다).
    url · user_agent · message · username · http_method 는 mask_url · mask_text 를 지난 값이다. SSH 사용자 이름은 보인다.
    쿼리 값 · '=' 없는 쿼리 조각 · 키 모양이 아닌 조각은 모두 가려 쿼리 속 공격 문자열도 가려진다. 사건 상세(① 근거 표본 · ② 행위 ·
    ④ 원문)도 같은 가림을 쓴다(mask_evidence · mask_incident_lines). 원문으로 두는 것은 정해진 발생원(RAW_SOURCES: 허니팟 · 디코이 ·
    관문 · 콘솔 · 감사 · 수집 관문)뿐이고, 노드 카드 · 상태와 관계없이 정한다(폐기한 노드의 과거 줄도 가린 채다, 이슈 #81)
  - 줄 id 는 line_hash 에서 만든 HMAC 이다(SESSION_SECRET 에서 떼어 낸 키). auth 줄은 시각 · 호스트 · pid 말고는 본문뿐이라
    line_hash 를 그대로 내면 가린 짧은 값을 해시로 되짚을 수 있다. 두 콘솔은 같은 비밀을 써 같은 id 를 낸다
  - 시각 네 가지는 서로 다른 칸이다: 마지막 적재(nodes.last_loaded_at) · 로그 종류별 마지막 줄(nodes.receipt[job].last_line_at,
    Alloy 가 읽은 시각. 시험 · 형식 밖 · sshd 외 줄도 올린다) · 이 장비 탐지 경로의 마지막 탐지(1분 다리가 돌려야 할 버전
    (targets.BRIDGE_VERSIONS) 가운데 가장 오래된 것. 24시간 안 기록이 없는 버전이 있으면 없음 · 멈춤이다) · 화면 갱신(as_of, DB now())
  - 5분 넘게 앞선 시각의 줄(노드가 적은 시각)은 목록에서 빼고 수만 센다(1,001 에서 멈춘다)

한계: 최신 N 줄보다 한 회차에 많이 들어오면 사이 줄을 건너뛴다(화면이 사이 끊김으로 알린다). 늦게 도착한 줄은 최신 N 줄 안에 들 때만
보인다.
"""
import hashlib
import hmac
import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request

import auth
import cti
import targets

router = APIRouter()

WINDOW_DAYS = 7                # 조회 창(최근 7일)
DEFAULT_LIMIT = 100            # 한 번에 받는 최신 줄 수(화면은 100 고정)
MAX_LIMIT = 200
FUTURE_CAP = 1001              # 앞선 시각 줄은 여기까지만 센다. 화면은 이 값이면 '1,000건 넘게' 로 적는다
NOT_FOUND = "보호 대상 장비를 찾을 수 없습니다"
BAD_SRC_IP = "src_ip 는 IP 주소여야 합니다"
SRC_IP_MAX = 64
# 장비 id 형식(operations.EnrollmentIn.node_id 와 같다). 형식 밖은 DB 에 닿기 전에 404 다(결정 1: 모르는 id 와 같은 답)
DEVICE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# 로그 종류: (키, 이벤트 이름 접두, receipt 의 job). 이름은 targets.PREFIX_KIND 와 같다
KINDS = (("web", "nginx.", "nginx"), ("ssh", "sshd.", "auth"))
KIND_PREFIX = {key: prefix for key, prefix, _ in KINDS}
KIND_LABEL = {key: targets.PREFIX_KIND[prefix] for key, prefix, _ in KINDS}
# 칸별 자르기 길이(parse_agent 가 적재 때 자르는 길이와 같다). 적재된 값은 이미 이 안이다. 가림 비용의 상한을 지키려고 한 번 더 둔다
CLIP = {"url": 2048, "user_agent": 512, "message": 512, "username": 256, "http_method": 16}
# 줄 id 의 키를 SESSION_SECRET 에서 떼어 낼 때 쓰는 이름표
LINE_ID_LABEL = b"opsloop:node-logs:line-id"

# nodes 에서 읽는 열(콘솔은 열 권한만 있다, schema.sql). 읽을 수 없으면 시각 칸이 '노드 표를 읽을 수 없음' 이다
NODE_TIMES_COLUMNS = ["node_id", "logs", "receipt", "last_loaded_at"]
NODE_TIMES_SQL = "SELECT logs, receipt, last_loaded_at FROM nodes WHERE node_id = $1"

# 최근 줄. 발생원 · 시각 색인(idx_events_sensor_ts)으로 내려가고 같은 시각 사이의 순서는 Incremental Sort 가 맡는다.
#   line_hash 는 id 를 만드는 데만 쓰고 내보내지 않는다. password 는 있었는지만 읽는다.
#   $1 장비 id · $2 기준 시각 · $3 창(일) · $4 이벤트 이름 LIKE 들 · {extra} 출발지 · 응답 코드 · 마지막이 LIMIT
LINES_SQL = """
    SELECT e.line_hash, e.ts, e.eventid, host(e.src_ip) AS src_ip, e.src_port, e.http_method, e.url,
           e.http_status, e.user_agent, e.username, e.password IS NOT NULL AS has_password, e.message
    FROM events e
    WHERE e.sensor = $1 AND e.provenance = 'real'
      AND e.ts >= $2::timestamptz - make_interval(days => $3)
      AND e.ts <= $2::timestamptz + interval '5 minutes'
      AND e.eventid LIKE ANY($4::text[]){extra}
    ORDER BY e.ts DESC, e.line_hash DESC
    LIMIT ${limit}"""
# 5분 넘게 앞선 시각의 줄 수(목록과 같은 필터). 노드가 먼 미래 줄을 대량으로 넣어도 5초마다 모두 훑지 않게 FUTURE_CAP 에서 멈춘다.
#   $1 장비 id · $2 기준 시각 · $3 이벤트 이름 LIKE 들 · {extra} · 마지막이 상한
FUTURE_SQL = """
    SELECT count(*) FROM (SELECT 1 FROM events e
        WHERE e.sensor = $1 AND e.provenance = 'real' AND e.ts > $2::timestamptz + interval '5 minutes'
          AND e.eventid LIKE ANY($3::text[]){extra}
        LIMIT ${limit}) f"""


# ----------------------------------------------------------------------
#  가림 (순수 함수, DB 없이 시험한다)
# ----------------------------------------------------------------------
#  모든 함수는 None 을 받으면 None 이고 멱등이다(f(f(x)) == f(x)). 키 이름 · Bearer · Basic · 사용자 정보는 넓게, 토큰 모양은 경로
#  오탐을 줄이려고 좁게 잡는다. 식마다 되돌아보기(앞 글자가 같은 무리가 아닐 때만 시작)와 길이 상한을 두어 적대 입력에서도 선형이다
#  (시작점마다 끝까지 훑는 식은 'a.' · 'eyJ-' 반복에서 이차 시간이 되어 비동기 처리기가 다른 요청까지 멈춘다).

MASK = "…(가림)"
QMASK = "…"
# message 끝의 SSH 키 지문(Accepted publickey … ssh2: ED25519 SHA256:…). 비밀이 아니라 남긴다. 다른 칸 · message 가운데의 SHA256:… 는
#   예외가 아니다(이름 칸에 SHA256: 을 붙여 토큰을 빼돌리거나 username 과 message 의 가림이 어긋나지 않게)
FINGERPRINT = re.compile(r"(?<=ssh2: )[A-Z0-9-]{2,20} SHA256:[A-Za-z0-9+/]{43}$")
HOLD = re.compile("\x00([0-9]+)\x00")     # 지문 자리표. DB 글자 칸에는 NUL 이 없다(parse_agent.clip)
# URL 사용자 정보(scheme://이름:비밀번호@ · 스킴 없는 //이름:비밀번호@). 마지막 '@' 까지 먹어 비밀번호 속 '@' 도 가린다
USERINFO = re.compile(r"(?i)((?:(?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}:)?//)[^/\s@:]*:[^/\s]*@")
# 단독 Bearer · Basic 값
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+(?!…)[A-Za-z0-9._~+/\-]+=*")
# 키=값 · 키: 값 · 키%3D값 · 키%3A값의 머리(따옴표 · 키 · 구분자). 키는 64자까지, 앞 글자가 키 글자가 아닐 때만 시작하고 비밀 키 낱말
#   조각(HINTS, SECRET_LONG · SECRET_SHORT 를 모두 덮는다)이 들고 뒤에 값이 올 때만 맞는다(판정은 secret_key). 따옴표는 한 번 더
#   이스케이프한 JSON(\")도 받는다. 경로에서는 '/' 로 시작하는 값이 없다
HINTS = ("pass", "pw", "auth", "key", "sid", "token", "secret", "session", "credential", "cookie")
_HEAD = (r"""(?<![A-Za-z0-9_.\-\[\]])(\\?["']|)(?=[A-Za-z0-9_.\-\[\]]{0,63}?(?i:""" + "|".join(HINTS) + "))"
         r"""([A-Za-z0-9_.\-\[\]]{1,64})\1(\s*(?:=|:|%3[dDaA])\s*)""")
PAIR = {False: re.compile(_HEAD + r"(?=[^\s&;,<>])"), True: re.compile(_HEAD + r"(?=[^\s&;,<>/])")}
# 비밀 키의 값: 인증 스킴 낱말(대소문자 무시, authorization 키는 모르는 스킴도)을 앞에 둘 수 있는 따옴표 묶음 또는 구분 글자 전까지.
#   글자 칸의 따옴표 묶음은 역빗금 이스케이프를 건너뛰고, 닫는 따옴표가 없으면(적재 때 잘림 등) 끝까지다.
#   경로에서는 값이 '/' 에서 멈춘다(뒤따르는 경로 조각은 남긴다)
_SCHEME = {False: r"(?:(?i:bearer|basic|digest|token)\s+)?", True: r"(?:[A-Za-z][A-Za-z0-9._\-]{0,31}\s+)?"}
_VALUE = {False: r"""(?:"(?:[^"\\]|\\[\s\S]?)*(?:"|\Z)|'(?:[^'\\]|\\[\s\S]?)*(?:'|\Z)"""
                 r"""|\\"(?:[^\\]|\\(?!")[\s\S]?)*(?:\\"|\Z)|[^\s&;,"'<>]+)""",
          True: r"""(?:\\?"[^"/]*"?|'[^'/]*'?|[^\s&;,"'<>/]+)"""}
VALUE = {(path, auth): re.compile(_SCHEME[auth] + _VALUE[path]) for path in (False, True) for auth in (False, True)}
# 쿼리 키로 남기는 모양(글자 · 숫자 · _ . - [ ] · 퍼센트로 쓴 [ ]). 그 밖(%3D · %26 · ':' · '{' · '"' · '/' …)이 들거나 토큰 모양인 키는
#   비밀이 키 자리에 붙었을 수 있어 조각 전체를 '…' 로 바꾼다
QUERY_KEY = re.compile(r"(?:[A-Za-z0-9_.\-\[\]]|%5[BbDd]){1,64}")
# 비밀 키: 소문자 키에 부분 문자열로 들거나(LONG) 낱말 경계로 드는 것(SHORT)
SECRET_LONG = ("password", "passwd", "passphrase", "token", "secret", "session", "sessid", "apikey", "api_key", "api-key",
               "authorization", "credential", "cookie")
SECRET_SHORT = re.compile(r"(?:^|[^a-z])(?:pass|pwd|pw|auth|key|sid)(?:$|[^a-z])")
# 토큰 모양: JWT · 16진 32자 이상 · base64(url) 40자 이상. url 경로에서는 '/' 가 구분자라 base64 글자에서 뺀다
JWT = re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
HEX = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")
B64_PATH = re.compile(r"(?<![0-9A-Za-z+_\-])[0-9A-Za-z+_\-]{40,}={0,2}(?![0-9A-Za-z+_=\-])")
B64_TEXT = re.compile(r"(?<![0-9A-Za-z+/_\-])[0-9A-Za-z+/_\-]{40,}={0,2}(?![0-9A-Za-z+/_=\-])")


def secret_key(key: str) -> bool:
    key = key.lower()
    return any(word in key for word in SECRET_LONG) or SECRET_SHORT.search(key) is not None


def token_like(value: str) -> bool:
    """base64 모양 후보가 토큰 같은가: 숫자 2개 이상 · 대소문자 모두 · '-' '_' '/' 합이 길이/10 이하(낱말을 이은 경로 조각은 빠진다)."""
    core = value.rstrip("=")
    return (sum(ch.isdigit() for ch in core) >= 2 and any(ch.isupper() for ch in core)
            and any(ch.islower() for ch in core)
            and core.count("-") + core.count("_") + core.count("/") <= len(core) // 10)


def shapes(text: str, path: bool = False) -> str:
    """토큰 모양(JWT · 16진 · base64)을 MASK 로 바꾼다. path 면 url 경로의 base64 식('/' 는 구분자)이다."""
    text = JWT.sub(MASK, text)
    text = HEX.sub(MASK, text)
    return (B64_PATH if path else B64_TEXT).sub(lambda m: MASK if token_like(m.group()) else m.group(), text)


def mask_pairs(text: str, path: bool = False) -> str:
    """비밀 키의 값을 MASK 로 바꾼다. 비밀이 아닌 키는 구분자까지만 넘기고 그 뒤부터 다시 찾는다(값 속의 '키=값' 도 본다).
    이미 MASK 인 값은 그대로다(멱등). 비밀 키 낱말 조각이 없는 글자는 식을 돌리지 않는다."""
    low = text.lower()
    if not any(word in low for word in HINTS):
        return text
    out, pos = [], 0
    while (m := PAIR[path].search(text, pos)) is not None:
        quote, key, sep = m.groups()
        value = VALUE[path, "authoriz" in key.lower()].match(text, m.end()) if secret_key(key) else None
        if value is None or value.group().startswith(MASK):
            out.append(text[pos:m.end()])
            pos = m.end()
        else:
            out.append(f"{text[pos:m.start()]}{quote}{key}{quote}{sep}{MASK}")
            pos = value.end()
    out.append(text[pos:])
    return "".join(out)


def mask_text(value: str | None, *, path: bool = False, fingerprint: bool = False) -> str | None:
    """글자 칸 가림. 순서: (0) fingerprint 면 message 끝 키 지문을 자리표로 뺌 (1) URL 사용자 정보 (2) 단독 Bearer · Basic
    (3) 비밀 키의 값 (4) 토큰 모양. username 과 message 는 같은 1~4단계를 거쳐 이름 칸에서 가린 값은 message 에서도 가려진다."""
    if value is None:
        return None
    kept: list[str] = []

    def hold(m):
        kept.append(m.group())
        return f"\x00{len(kept) - 1}\x00"

    text = FINGERPRINT.sub(hold, value) if fingerprint else value
    text = USERINFO.sub(lambda m: m.group(1) + MASK + "@", text)
    text = BEARER.sub(lambda m: m.group(1) + " " + MASK, text)
    text = mask_pairs(text, path)
    text = shapes(text, path)
    if not kept:
        return text
    return HOLD.sub(lambda m: kept[int(m.group(1))] if int(m.group(1)) < len(kept) else m.group(), text)


def mask_url(value: str | None) -> str | None:
    """url 가림. '#' 뒤는 '#…'. 경로는 남기되 경로 속 비밀 · 토큰 모양은 가린다(결정 4 '어느 필드에 있어도 지운다' 가 먼저다).
    쿼리는 '&' 조각마다: 빈 조각은 그대로, k=v 는 키 모양(QUERY_KEY)이고 토큰 모양이 아닌 키만 남기고 값이 있으면 '…' 다.
    그 밖의 키와 '=' 없는 조각은 모두 '…' 다(키인지 값인지 모르거나 비밀이 키 자리에 붙었을 수 있다)."""
    if value is None:
        return None
    frag = ""
    if "#" in value:
        value, frag = value.split("#", 1)[0], "#" + QMASK
    if "?" not in value:
        return mask_text(value, path=True) + frag
    path, query = value.split("?", 1)
    pieces = []
    for piece in query.split("&"):
        if piece == "":
            pieces.append(piece)
        elif "=" in piece:
            key, val = piece.split("=", 1)
            plain = QUERY_KEY.fullmatch(key) is not None and shapes(key, path=True) == key
            pieces.append(f"{key}=" + (QMASK if val else "") if plain else QMASK)
        else:
            pieces.append(QMASK)
    return mask_text(path, path=True) + "?" + "&".join(pieces) + frag


def _clip(value, n):
    return value if value is None or len(value) <= n else value[:n]


# 칸별 가림 함수. 목록(mask_row)과 사건 상세(mask_event)가 같은 표를 쓴다. input 은 목록이 내보내지 않는 칸이다
#   (이 장비 줄은 파서가 채우지 않지만 결정 4 '어느 문자열 칸에 있어도' 대로 상세에 있으면 가린다)
MASKERS = {"http_method": mask_text, "url": mask_url, "user_agent": mask_text, "username": mask_text,
           "message": lambda value: mask_text(value, fingerprint=True), "input": mask_text}
# 상세 행의 자르기 길이. input 은 수집 관문 줄의 자르기 길이(parse_agent.parse_collector)와 같다
DETAIL_CLIP = {**CLIP, "input": 4096}


def mask_row(row) -> dict:
    """줄 한 행(LINES_SQL)의 비신뢰 글자 칸을 가린 값. 칸별 자르기 길이 안에서 가린다."""
    return {key: mask(_clip(row[key], CLIP[key])) for key, mask in MASKERS.items() if key in CLIP}


def mask_event(row: dict) -> dict:
    """사건 상세(① 근거 표본 · ② 행위 · ④ 원문) 한 행을 목록과 같은 규칙으로 가린 새 행. 행에 있는 글자 칸만 가리고(② 에는
    user_agent · message 가 없다) 시각 · 발생원 · 이벤트 이름 · 세션(파서가 만든 '노드/sshd/pid') · has_password 등은 그대로다.
    글자 · None 이 아닌 값(근거 표본은 JSON 이라 수 · 목록이 올 수 있다)은 무엇이 들었는지 몰라 통째로 MASK 다."""
    return {**row, **{key: mask(_clip(row[key], DETAIL_CLIP[key])) if row[key] is None or isinstance(row[key], str) else MASK
                      for key, mask in MASKERS.items() if key in row}}


# 사건 상세에서 원문으로 두는 발생원. 고정 대상 가운데 보호 대상(web-01)이 아닌 것이다: 허니팟 · 디코이 · 관문 줄은 공격 증거이고
#   콘솔 · 감사 · 수집 관문 · 원장 가져오기 줄은 관제 대상 서버의 로그가 아니다. 모두 노드 이름으로 쓸 수 없다(operations.RESERVED)
RAW_SOURCES = frozenset({"cowrie", "decoy", "gateway", "console", "audit", "collector", "puller"})


def raw_source(item: dict) -> bool:
    """사건 상세에서 원문으로 둘 줄 · 표본인가. 발생원이 RAW_SOURCES 이고 관제 대상 로그 이벤트(nginx. · sshd.)가 아닐 때만이다.
    그 밖(web-01 · 등록 노드 · 폐기하거나 카드에서 빠진 노드 · 모르는 발생원 · 발생원이 없거나 글자가 아님)은 노드 카드 · 상태와
    관계없이 가린다(이슈 #81). 노드 상태가 바뀌어도 과거 줄의 가림은 그대로다. 이벤트 이름 조건은 RESERVED 검사를 거치지 않고 넣은
    노드 · 발생원 기본값('cowrie')으로 적재된 옛 노드 줄까지 가리기 위한 것이다(원문 발생원은 nginx. · sshd. 를 내지 않는다)."""
    sensor, eventid = item.get("sensor"), item.get("eventid")
    return (isinstance(sensor, str) and sensor in RAW_SOURCES
            and not (isinstance(eventid, str) and eventid.startswith(targets.NODE_PREFIXES)))


def mask_incident_lines(rows: list[dict]) -> list[dict]:
    """사건 상세(main.get_incident)의 ② 행위 · ④ 원문 행 가운데 원문 발생원(raw_source)이 아닌 줄을 mask_event 로 가린다."""
    return [row if raw_source(row) else mask_event(row) for row in rows]


def mask_evidence(evidence):
    """사건 상세 ① 규칙 근거(evidence)의 표본(sample) 가운데 원문 발생원(raw_source)이 아닌 객체 항목을 mask_event 로 가린 새 근거.
    요청 경로 서명 규칙(url_signature: c1 R105 · R106 · sg1 R107)은 신호 detail(발생원 · 메서드 · url · 응답 코드 · 서명)을 그대로
    표본에 남겨(detect.signals_url_signature) 가리지 않으면 ④ 에서 가린 관제 대상 요청의 url 원문이 같은 응답에 다시 나온다.
    디코이 표본은 공격 증거라 원문 그대로다. 발생원 칸이 없는 객체 표본(건수 · 이벤트 글자 등 다른 규칙의 detail)은 가릴 칸이 없어
    값이 그대로이고, 글자 표본도 그대로다 — 글자를 표본에 남기는 규칙(event_match)이 관제 대상 이벤트를 보지 않는 것은 시험이
    지킨다. 표본 밖 칸(sessions · signatures · sensors · 관측값)은 식별자 · 수라 그대로다. 근거가 객체가 아니거나 표본이 목록이
    아니면 받은 것 그대로다."""
    if not isinstance(evidence, dict) or not isinstance(evidence.get("sample"), list):
        return evidence
    return {**evidence, "sample": [mask_event(item) if isinstance(item, dict) and not raw_source(item) else item
                                   for item in evidence["sample"]]}


# ----------------------------------------------------------------------
#  응답 조립 (순수 함수)
# ----------------------------------------------------------------------

def line_id_key(secret: str | None = None) -> bytes:
    """줄 id 의 HMAC 키. SESSION_SECRET(auth.SECRET)에서 떼어 낸다. 비밀을 바꾸면 세션도 끊겨 화면을 다시 연다."""
    return hmac.new((auth.SECRET if secret is None else secret).encode(), LINE_ID_LABEL, hashlib.sha256).digest()


def line_id(line_hash: str, key: bytes) -> str:
    """줄 id(32자 16진). 같은 줄은 같은 id 다. line_hash 원값은 내보내지 않는다."""
    return hmac.new(key, line_hash.encode(), hashlib.sha256).hexdigest()[:32]


def line_kind(eventid: str) -> str:
    return "web" if eventid.startswith(KIND_PREFIX["web"]) else "ssh"


def line_ts(value: datetime) -> str:
    """줄 시각. 화면이 글자로 견주므로 마이크로초까지 고정 자릿수다."""
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def line_item(row, key: bytes) -> dict:
    return {"id": line_id(row["line_hash"], key), "ts": line_ts(row["ts"]), "kind": line_kind(row["eventid"]),
            "eventid": row["eventid"], "src_ip": row["src_ip"], "src_port": row["src_port"],
            "http_status": row["http_status"], "has_password": bool(row["has_password"]), **mask_row(row)}


def line_items(rows, key: bytes) -> list[dict]:
    """SQL 순서(ts, line_hash)로 고른 줄을 (ts, id) 내림차순으로 낸다. 화면의 합치기 순서와 같다."""
    items = [line_item(r, key) for r in rows]
    items.sort(key=lambda x: (x["ts"], x["id"]), reverse=True)
    return items


def protected_device(device_id: str, cards) -> dict | None:
    """보호 대상 장비면 {id, label, kind}, 아니면 None. #72 목록 장비 필터의 선택지(device_options)에서 group 이 protected 인 것,
    곧 web-01 과 등록 노드 카드다(폐기 · 발생원이 겹친 노드 · nodes 를 읽을 수 없을 때의 등록 노드는 카드가 없다)."""
    for option in targets.device_options(cards):
        if option["id"] == device_id and option["group"] == "protected":
            return {"id": device_id, "label": option["label"],
                    "kind": "fixed" if device_id == targets.WEB_NODE else "node"}
    return None


def receipt_times(receipt) -> dict:
    """nodes.receipt → {job: 마지막 줄 시각 또는 None}(nginx · auth 만, targets.receipt_at). 사전이 아니거나 last_line_at 이 글자가
    아니거나 ISO 시각이 아니면(시간대가 없는 것 포함) None 이다."""
    return {job: targets.receipt_at(receipt, job) for _, _, job in KINDS}


def times_lines(state: str, node) -> list[dict]:
    """로그 종류별 마지막 줄. state 가 ok 가 아니면 선언 · 시각이 모두 null 이다. declared 는 job ∈ nodes.logs 다."""
    ok = state == "ok"
    logs = list(node["logs"] or []) if ok else []
    last = receipt_times(node["receipt"]) if ok else {}
    return [{"key": key, "job": job, "label": KIND_LABEL[key], "declared": (job in logs) if ok else None,
             "last_line_at": cti.iso(last.get(job)) if ok else None} for key, _, job in KINDS]


def device_detect(path_rows, spec_rows, device_id: str, nodes, as_of) -> dict:
    """이 장비 탐지 경로의 마지막 탐지. path_rows 는 targets.DETECT_PATHS_SQL 행, spec_rows 는 1분 다리 버전의 targets.RULES_SQL 행,
    nodes 는 등록 노드 {발생원: 노드 id}(targets.node_sources) 다.
    1분 다리가 돌려야 할 버전(targets.bridge_rows, 24시간 안 기록이 없으면 last_at 없음) 가운데 규칙 하나라도 발생원 후보
    (targets.candidate_sources)가 이 장비에 붙으면(targets.attach) 이 장비의 버전이다. last_at 은 그 버전들 가운데 가장 오래된
    값(보수적 기준, 기록 없는 버전이 있으면 없음)이고, 버전이 없거나 하나라도 15분 넘게 멈추거나 기록이 없으면 멈춤이다.
    reason · versions 는 targets.detect_paths 의 1분 다리 경로와 같은 모양이다."""
    specs: dict[str, list] = {}
    for row in spec_rows:
        specs.setdefault(row["rule_version"], []).append(targets.rule_spec(row))

    def sees(spec) -> bool:
        return device_id in {tid for tid, _ in targets.attach(targets.candidate_sources(spec, nodes), nodes)}

    mine = [r for r in targets.bridge_rows(path_rows)
            if any(sees(spec) for spec in specs.get(r["rule_version"], []))]
    times = [r["last_at"] for r in mine if r["last_at"] is not None]
    last = min(times) if times and len(times) == len(mine) else None
    late = [r for r in mine if targets.older(as_of, r["last_at"], targets.HEARTBEAT_STALE)]
    stale = not mine or bool(late)
    reason = None
    if not mine:
        reason = "24시간 안 실행 기록 없음"
    elif late:
        reason = targets.late_reason(late, as_of)
    versions = [{"rule_version": r["rule_version"], "last_at": cti.iso(r["last_at"]),
                 "stale": targets.older(as_of, r["last_at"], targets.HEARTBEAT_STALE)} for r in mine]
    return {"last_at": cti.iso(last), "stale": stale, "reason": reason, "versions": versions}


# ----------------------------------------------------------------------
#  입력 검사 · 질의
# ----------------------------------------------------------------------

def parse_src_ip(value: str | None) -> str | None:
    """출발지 인자 → 정규화한 주소(빈 값은 조건 없음). 64자 초과 · 주소 아님 · IPv6 영역 표기 · NUL 은 모두 한국어 한 문장 422 다
    (FastAPI 검증 msg 는 영어라 화면이 그대로 보이면 안 된다). main.list_incidents 의 actor_ip 와 같은 규칙이다."""
    if not value:
        return None
    if len(value) > SRC_IP_MAX or "\x00" in value:
        raise HTTPException(422, BAD_SRC_IP)
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        ip = None
    if ip is None or getattr(ip, "scope_id", None):
        raise HTTPException(422, BAD_SRC_IP)
    return str(ip)


def filter_sql(start: int, src_ip: str | None, status: int | None) -> tuple[str, list]:
    """출발지 · 응답 코드 조건(목록 · 앞선 시각 수가 같이 쓴다). start 는 첫 인자 번호다."""
    extra, params = "", []
    if src_ip is not None:
        params.append(src_ip)
        extra += f"\n      AND e.src_ip = ${start + len(params) - 1}::inet"
    if status is not None:
        params.append(status)
        extra += f"\n      AND e.http_status = ${start + len(params) - 1}"
    return extra, params


def patterns(kind: str | None) -> list[str]:
    """이벤트 이름 LIKE 들(허용 목록). 응답 코드 조건이 있으면 SSH 줄은 http_status 가 없어 저절로 빠진다."""
    return [prefix + "%" for key, prefix, _ in KINDS if kind in (None, key)]


async def read_times(c, device_id: str) -> tuple[str, object]:
    """(시각 상태, nodes 행). ok · no_node(행 없음) · unreadable(표 없음 · 열 권한 없음)."""
    if not await c.fetchval(targets.NODES_READABLE_SQL, NODE_TIMES_COLUMNS):
        return "unreadable", None
    node = await c.fetchrow(NODE_TIMES_SQL, device_id)
    return ("ok" if node is not None else "no_node"), node


async def logs_view(c, device_id: str, *, kind=None, src_ip=None, status=None, limit=DEFAULT_LIMIT) -> dict:
    """본문(입력 검사 뒤). 부른 쪽이 반복 읽기 트랜잭션을 연다. 보호 대상이 아니면 404 다(질의 3개로 끝)."""
    as_of = await c.fetchval("SELECT now()")
    _, cards = await targets.read_nodes(c, as_of)
    device = protected_device(device_id, cards)
    if device is None:
        raise HTTPException(404, NOT_FOUND)
    state, node = await read_times(c, device_id)

    names = patterns(kind)
    extra, params = filter_sql(5, src_ip, status)
    rows = await c.fetch(LINES_SQL.format(extra=extra, limit=5 + len(params)),
                         device_id, as_of, WINDOW_DAYS, names, *params, limit)
    extra, params = filter_sql(4, src_ip, status)
    future = await c.fetchval(FUTURE_SQL.format(extra=extra, limit=4 + len(params)),
                              device_id, as_of, names, *params, FUTURE_CAP)

    paths = list(await c.fetch(targets.DETECT_PATHS_SQL, as_of))
    bridge = [r["rule_version"] for r in targets.bridge_rows(paths)]
    specs = await c.fetch(targets.RULES_SQL, bridge) if bridge else []
    detect = device_detect(paths, specs, device_id, targets.node_sources(cards), as_of)

    return {
        "as_of": cti.iso(as_of), "device": device, "limit": limit, "window_days": WINDOW_DAYS,
        "filters": {"kind": kind, "src_ip": src_ip, "status": status},
        "kinds": [{"key": key, "label": KIND_LABEL[key]} for key, _, _ in KINDS],
        "times": {"state": state,
                  "loaded_at": cti.iso(node["last_loaded_at"]) if state == "ok" else None,
                  "lines": times_lines(state, node),
                  "detect": detect},
        "future": int(future or 0),
        "items": line_items(rows, line_id_key()),
    }


@router.get("/api/devices/{device_id}/logs")
async def device_logs(request: Request, device_id: str,
                      kind: Optional[Literal["web", "ssh"]] = None,
                      src_ip: Optional[str] = None,
                      status: Optional[int] = Query(None, ge=100, le=599),
                      limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)):
    """보호 대상 장비의 최근 로그. 읽기 조회라 역할 검사 없이 세션 미들웨어만 둔다(사건 상세와 같다).
    입력 오류(422)와 형식 밖 장비 id(404)는 풀을 빌리기 전에 답한다."""
    src_ip = parse_src_ip(src_ip)
    if not DEVICE_ID.fullmatch(device_id):
        raise HTTPException(404, NOT_FOUND)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        return await logs_view(c, device_id, kind=kind, src_ip=src_ip, status=status, limit=limit)
