"""P 판 enforcer/block_enforcer.py 의 validate_status · list_doc 과 그 도우미 사본 (이슈 #77 교차 판 시험 자료).

P 는 #77 직전 main 의 enforcer/block_enforcer.py 다. 되돌린 옛 집행기가 #77 판 동기화의 보고(list 가 든)를 받는지, 모든 행이
두 지점일 때 #77 판 목록의 entries digest 가 옛 list_doc 의 digest 와 같은지 본다. 상수 · 함수는 P 판 글자 그대로다
(test_block_enforcer.py 가 git 으로 대조한다). 고치지 않는다.
"""
import hashlib
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone

P_COMMIT = "a1a0c27"

FUTURE_SLACK = timedelta(minutes=2)
REJECTED_MAX = 4096
ERRORS_MAX = 100
TEXT_MAX = 160
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
MODES = ("fail2ban", "nft")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SURROGATE = re.compile("[\ud800-\udfff]")


def clean(v, n=TEXT_MAX):
    """관문 · S3 가 준 문구를 로그 · DB 쪽지에 넣을 때. 제어 · 형식(Cf) · 줄 구분 문자를 '?' 로 바꾸고 자른다."""
    s = _SURROGATE.sub("?", _CTRL.sub("?", str(v)))
    s = "".join("?" if unicodedata.category(c) in ("Cf", "Zl", "Zp") else c for c in s)
    return s[:n]


def iso(dt):
    """초 단위로 내린 UTC ISO (…Z). 목록의 until · 쪽지의 시각에 쓴다."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?"
                 r"(Z|[+-][0-9]{2}:?[0-9]{2})")


def parse_ts(v):
    """시간대가 있는 ISO 8601 → UTC datetime. 못 읽으면 None (시간대 없는 값도 받지 않는다)."""
    if not isinstance(v, str) or len(v) > 40:
        return None
    m = _TS.fullmatch(v.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), int((frac or "0")[:6].ljust(6, "0")))
        if tz != "Z":
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))
            return dt.replace(tzinfo=timezone(off if tz[0] == "+" else -off)).astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10 ** 9 else None


def validate_status(d, now, label="관문"):
    """(보고, None) 또는 (None, 까닭). 관문이 장악돼도 이 값으로 DB 에 쓰는 것은 검증한 시각 · 방식 · 짧은 문구뿐이다."""
    if not isinstance(d, dict) or d.get("v") != 1:
        return None, "형식 틀림 (v)"
    at = parse_ts(d.get("at"))
    if at is None:
        return None, "형식 틀림 (at)"
    if at > now + FUTURE_SLACK:
        return None, f"{label} 시각이 앞섬"
    mode = d.get("mode")
    if mode not in MODES:
        return None, "형식 틀림 (mode)"
    dg = d.get("list_digest")
    if dg is not None and not (isinstance(dg, str) and DIGEST_RE.fullmatch(dg)):
        return None, "형식 틀림 (list_digest)"
    rej = d.get("rejected") or []
    errs = d.get("errors") or []
    if not isinstance(rej, list) or len(rej) > REJECTED_MAX or not isinstance(errs, list):
        return None, "형식 틀림 (rejected · errors)"
    if _int(d.get("applied")) is None:
        return None, "형식 틀림 (applied)"    # 셈 대조의 기준이라 없으면 보고를 믿지 않는다 (set_count 는 집합을 못 읽으면 null)
    rejected = {}
    for x in rej:
        # 관문은 형식이 틀린 목록 항목도 거부로 돌려준다(주소 칸이 빈 문자열 등). 그런 항목만 건너뛰고 보고는 쓴다
        if not isinstance(x, dict) or not isinstance(x.get("ip"), str):
            continue
        try:
            ip = str(ipaddress.ip_address(x["ip"]))
        except ValueError:
            continue
        rejected[ip] = clean(x.get("why") or "사유 없음", 80)
    selftest = d.get("selftest")
    return {"at": at, "mode": mode, "digest": dg, "list_generated_at": parse_ts(d.get("list_generated_at")),
            "applied": _int(d["applied"]), "set_count": _int(d.get("set_count")), "rejected": rejected,
            "errors": [clean(e, 120) for e in errs[:ERRORS_MAX]] + (["오류 더 있음"] if len(errs) > ERRORS_MAX else []),
            "selftest": clean(selftest, 80) if isinstance(selftest, str) else None}, None


def canonical(entries):
    return json.dumps(sorted(entries, key=lambda e: e["ip"]), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(entries):
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def list_doc(entries, now):
    entries = sorted(entries, key=lambda e: e["ip"])
    return {"v": 1, "generated_at": iso(now), "entries": entries, "digest": digest_of(entries)}
