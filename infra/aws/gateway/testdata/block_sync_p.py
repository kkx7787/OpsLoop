"""P 판 block-sync.py 의 load_list · recheck · canonical_digest 사본 (이슈 #77 교차 판 시험 자료).

P 는 #77 직전 main 의 infra/aws/gateway/block-sync.py 다. 관문은 #77 판으로 바꾸지 않으므로 새 목록 문서를
이 판이 받는지(digest 통과 · entries 만 적용) 본다. 상수 · 함수는 P 판 글자 그대로다(test_block_sync.py 가 git 으로 대조한다).
고치지 않는다.
"""
import hashlib
import ipaddress
import json
import math
from datetime import datetime, timezone

P_COMMIT = "a1a0c27"

LIST_KEY = "block/v1/latest.json"
MAX_ENTRIES = 4096
MAX_LIST_BYTES = 4 * 1024 * 1024
EXEMPT = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "15.164.37.49/32",            # 관문 EIP
    "::1/128", "fc00::/7", "fe80::/10",
))


def parse_time(v):
    """시간대가 있는 ISO 시각 → UTC. 틀리면 None."""
    if not isinstance(v, str) or not 10 <= len(v) <= 40:
        return None
    s = v[:-1] + "+00:00" if v[-1] in "Zz" else v
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t.astimezone(timezone.utc)


def remaining(until, now):
    """until 까지 남은 초(올림)."""
    return math.ceil((until - now).total_seconds())


def canonical_digest(entries):
    canon = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


def error_code(e):
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        code = (resp.get("Error") or {}).get("Code")
        if code:
            return str(code)[:40]
    return type(e).__name__


def _no_const(name):
    raise ValueError(name)


def load_list(s3, bucket, key=LIST_KEY):
    """(목록, None) 또는 (None, 사유). 판 번호 · 형식 · digest 까지 본다."""
    try:
        r = s3.get_object(Bucket=bucket, Key=key)
        body = r["Body"].read(MAX_LIST_BYTES + 1)
    except Exception as e:           # 네트워크 · 권한 · 없음. 어느 것이든 집합을 건드리지 않는다
        return None, f"목록을 읽지 못함 ({error_code(e)})"
    if len(body) > MAX_LIST_BYTES:
        return None, "목록 크기 초과"
    try:
        doc = json.loads(body, parse_constant=_no_const)
    except (ValueError, RecursionError):
        return None, "목록이 JSON 이 아니다"
    if not isinstance(doc, dict) or type(doc.get("v")) is not int or doc["v"] != 1:
        return None, "목록 판 번호가 1 이 아니다"
    entries, digest = doc.get("entries"), doc.get("digest")
    if not isinstance(entries, list) or not isinstance(digest, str):
        return None, "목록 형식이 틀리다"
    if parse_time(doc.get("generated_at")) is None:
        return None, "목록 generated_at 형식이 틀리다"
    try:
        ok = canonical_digest(entries) == digest.lower()
    except (ValueError, RecursionError):
        ok = False
    if not ok:
        return None, "목록 digest 불일치"
    return doc, None


def check_ip(raw):
    """(표준형 IPv4 문자열, None) 또는 (None, 사유)."""
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return None, "주소 형식"
    if "/" in raw:
        return None, "대역 주소"
    try:
        a = ipaddress.ip_address(raw)
    except ValueError:
        return None, "주소 형식"
    if a.version == 4 and str(a) != raw:
        return None, "주소 형식"          # 앞자리 0 같은 표준형이 아닌 표기
    for n in EXEMPT:
        if a.version == n.version and a in n:
            return None, f"금지 대역 {n}"
    if a.version != 4:
        return None, "IPv4 아님"          # 관문 유입은 IPv4 뿐이고 집합도 ipv4_addr 다
    return str(a), None


def recheck(entries, now):
    """({ip: until}, rejected, 중복 수). 목록 순서대로 본다."""
    want, rejected, dup = {}, [], 0
    for e in entries:
        raw = e.get("ip") if isinstance(e, dict) else None
        ip, why = check_ip(raw)
        if ip is not None:
            until = parse_time(e.get("until"))
            if until is None:
                why = "만료 형식"
            elif remaining(until, now) < 1:
                why = "만료 지남"             # 관문 시각 기준. 두 노드 시각이 어긋났으면 여기서 드러난다
            elif ip in want:
                dup += 1                      # 집합에는 들어간다. 행이 불일치로 보이지 않게 rejected 에 넣지 않는다
                continue
            elif len(want) >= MAX_ENTRIES:
                why = "상한 초과"
        if why:
            # ip 는 늘 문자열이다(집행기는 문자열이 아닌 ip 가 있으면 보고 전체를 버린다). 주소로 못 읽는 값은 행에 닿지 않는다
            rejected.append({"ip": raw[:64] if isinstance(raw, str) else "", "why": why})
            continue
        want[ip] = until
    return want, rejected, dup
