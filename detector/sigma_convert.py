#!/usr/bin/env python3
"""
OpsLoop - 공개 웹 규칙(Sigma) 변환기 (이슈 #54)

SigmaHQ 의 webserver 규칙(YAML)을 요청 경로 서명(url_signature, detector/detect.py)으로 옮긴다. 개발 PC 에서만
돈다(pyyaml 이 필요하다). 운영은 이 도구가 만든 규칙 파일(detector/rules_sigma.json)만 읽는다.

옮기는 것
  logsource.category 가 webserver 인 규칙만. 필드는 셋으로 모은다.
    url     cs-uri-query · cs-uri-stem · cs-uri · c-uri · c-uri-query · c-uri-stem 과 목록 선택(keywords).
            우리 url 은 경로와 질의가 한 값이다(web-01 은 원시 요청 대상, 디코이는 1회 디코딩된 경로이고 질의가 없다).
            그래서 경로(stem) · 질의(query) 구분을 잃는다. keywords 는 원래 로그 줄 전체에서 찾는 값인데 url 에만 댄다.
            둘 다 서명 notes 에 적는다
    method  cs-method        status  sc-status
  그 밖의 필드(User-Agent · host · referer · cookie …)는 옮기지 못한다.
  조건자는 contains · startswith · endswith · all · re(detect.regex_gap 을 통과하고 대괄호 밖에 $ 가 없을 때만).
  re 는 원본처럼 포함(검색)으로 옮기고, 원본은 대소문자를 가리지만 엔진은 가리지 않는다(notes). 값 와일드카드는 * → .* ,
  ? → . 이고 \\* \\? \\\\ 는 글자다. 정규식 이스케이프는 두 엔진(PostgreSQL · 파이썬)이 같게 읽는 것만 쓴다(메타 문자
  . ^ $ * + ? ( ) [ ] { } | \\ 앞에만 역슬래시). 대소문자는 가리지 않는다(Sigma 문자열 비교와 같고 엔진이 ~* 로 맞춘다).

condition
  이름(와일드카드 *) · and · or · not · 괄호 · "1 of X" · "all of X" · "them"(밑줄로 시작하는 이름을 뺀 전부).
  not 을 필드 조건까지 밀어 넣은 뒤 논리합 표준형(DNF)으로 펴서 갈래마다 서명 하나를 만든다. 필드 조건 하나는
  필드 · 조건자 · 값 목록이고, 값 목록은 정규식 하나의 선택지가 된다(|all 이면 값마다 따로 AND).
  갈래 하나를 서명으로
    양의 url 조건        첫째가 pattern, 나머지가 all_patterns
    음의 url 조건        not_patterns
    메서드 · 응답 코드    양의 조건의 교집합(methods · statuses). 음의 조건은 옮기지 못한다
    옮기지 못하는 조건    양의 조건이면 그 갈래를 버린다(좁아짐). 음의 조건(필터)이면 그 조건만 뺀다(넓어짐)
    양의 url 조건이 없는 갈래(메서드 · 응답 코드만)는 너무 넓어 서명으로 만들지 않는다
  버리거나 뺀 것은 서명 notes 와 보고에 남긴다. 갈래가 20개를 넘으면 변환하지 않는다.

서명
  id 는 "sg-" + 파일 이름에서 web_ · .yml 을 뗀 것(소문자 · [a-z0-9-] · 40자 안, 넘으면 낱말 경계에서 자른다).
  갈래가 여럿이면 -1 -2 … 를 붙인다. cves 는 tags 의 cve.YYYY-NNNN(꼴이 맞는 것만). mapping 은 sigma 이고 sigma 객체에
  원본 출처(id · 제목 · 경로 · 커밋 · 주소 · 작성자 · status · level · 라이선스 · notes)를 남긴다. product · vendor ·
  asset_match 는 선정표(detector/sigma/selection.json)에 사람이 적은 값이다. 만든 규칙은 detect.url_signature_args 로
  다시 검사한다(탐지기가 받지 않는 파일은 쓰지 않는다).

재현
  build 는 선정표 · 원본(detector/sigma/, manifest.json 의 git blob sha1 과 대조)만 읽는다. 같은 입력이면 글자가 같은
  파일이 나온다(시험). 규칙 파일을 손으로 고치지 않는다. 서명을 바꾸면 선정표 · 변환기를 고치고 rule_version 을 올린다.

사용 (저장소 루트)
  python3 detector/sigma_convert.py build              선정표 → detector/rules_sigma.json
  python3 detector/sigma_convert.py build --check      다시 만들어 저장된 파일과 글자가 같은지만 본다
  python3 detector/sigma_convert.py report <yml…>      변환 결과 · notes 를 표로
  python3 detector/sigma_convert.py lab <원본 폴더> --out <파일>
                                                      webserver 규칙 전부를 실험용 rule_version sgx 로. 운영에 쓰지 않는다
"""

import argparse
import hashlib
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SIGMA_DIR = os.path.join(HERE, "sigma")
SELECTION = os.path.join(SIGMA_DIR, "selection.json")
MANIFEST = os.path.join(SIGMA_DIR, "manifest.json")
OUT = os.path.join(HERE, "rules_sigma.json")

URL_FIELDS = ("cs-uri-query", "cs-uri-stem", "cs-uri", "c-uri", "c-uri-query", "c-uri-stem")
SPLIT_FIELDS = ("cs-uri-query", "cs-uri-stem", "c-uri-query", "c-uri-stem")     # 경로 · 질의 가운데 한쪽만 뜻하는 필드
QUERY_FIELDS = ("cs-uri-query", "c-uri-query")
STEM_FIELDS = ("cs-uri-stem", "c-uri-stem")
METHOD_FIELDS = ("cs-method",)
STATUS_FIELDS = ("sc-status",)
MATCHERS = ("contains", "startswith", "endswith", "re")
MAX_BRANCHES = 20
ID_MAX = 40
REGEX_META = frozenset(".^$*+?()[]{}|\\")
METHOD_VALUE_RE = re.compile(r"[A-Za-z]+")
CVE_TAG_RE = re.compile(r"cve\.([0-9]{4}-[0-9]{4,})", re.I)
TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")
NOT_SELECTIONS = ("condition", "timeframe")

RULE_ID = "R107"
RULE_NAME = "공개 규칙(Sigma) 웹 공격 요청"
EVENTIDS = ["nginx.request", "decoy.request"]
LICENSE = "DRL-1.1"
BLOB_URL = "https://github.com/SigmaHQ/sigma/blob/"

NOTE = (
    "공개 탐지 규칙(SigmaHQ) 가운데 웹 서버 로그 규칙을 요청 경로 서명(url_signature)으로 옮긴 규칙 (이슈 #54). "
    "원본은 SigmaHQ/sigma 커밋 {commit} 이고 규칙 라이선스는 Detection Rule License(DRL) 1.1 이다. 서명마다 원본 규칙 "
    "id · 제목 · 작성자 · 경로 · 커밋 주소 · 라이선스를 sigma 객체에 남기고, 원본 {n}개와 SigmaHQ LICENSE 파일은 "
    "detector/sigma/ 에 그대로 두었다(manifest.json 에 git blob sha1). 이 파일은 detector/sigma_convert.py build 가 "
    "선정표(detector/sigma/selection.json)와 원본으로 만든다. 손으로 고치지 않는다. 같은 입력이면 글자가 같다. "
    "c1(rules_cve.json)과 버전 · 파일을 나눈 것은 공개 규칙과 우리 서명을 같은 요청에 대 보는 비교(리플레이)를 위해서이고, "
    "c1 의 사건 키 · 판정이 바뀌지 않게 하려는 것이다. 이 파일에는 억제가 없어 R105 · R106 · w2 R102 와 서로 지우지 않는다. "
    "1분 다리(opsloop-agents)가 c1 다음에 돌린다. 판정 · 심각도를 CVE 나 Sigma level 로 정하지 않는다(level 은 sigma 객체에 "
    "참고로만 둔다). 변환의 한계: Sigma 는 경로(cs-uri-stem)와 질의(cs-uri-query)를 나누지만 우리 url 은 한 값이라 그 구분을 "
    "잃는다. 웹 디코이(decoy.request)의 url 은 1회 퍼센트 디코딩된 경로만이고 질의 문자열이 없어, 질의에 든 값이나 퍼센트 "
    "인코딩 그대로를 찾는 조건은 web-01(nginx.request, 원시 요청 대상) 요청에서만 맞는다. 서명은 url · 메서드 · 응답 코드만 "
    "본다. User-Agent 는 저장하지만 서명이 보지 않고 그 밖의 요청 헤더 · 본문은 저장하지 않아, 그런 조건(User-Agent · host · "
    "referer · cookie …)은 옮기지 못한다. 옮기지 못한 조건이 양의 조건이면 그 갈래를 버리고(좁아짐), 필터(음의 조건)면 "
    "그 조건만 빼고(넓어짐) 서명 sigma.notes 에 적는다. 원본의 응답 코드(sc-status) 조건은 statuses 로 옮겼다. c1 은 응답 "
    "코드를 보지 않는다. 대소문자는 가리지 않는다(Sigma 문자열 비교와 같다). 서명을 더하거나 고치면 rule_version 을 올린다"
    "(sg2). 알려진 한계(c1 · w2 R102 와 같은 구조): 사건 키는 묶음의 첫 신호 시각이다. 같은 출발지의 더 이른 디코이 요청이 "
    "5분 적재기로 늦게 들어오면 다음 회차에 새 키 사건이 생기고 먼저 뜬 사건은 미판정으로 남는다. 억제가 없어 옛 키 사건을 "
    "지우지 않는다."
)
AGGREGATION_COMMENT = ("c1 과 같은 15분에서 시작한다. 같은 출발지가 15분 안에 여러 공개 규칙에 맞으면 사건 하나에 서명 "
                       "여럿이 남는다.")
RATIONALE = (
    "선정: c1 과 제품이 겹치는 CVE 웹 규칙을 중심으로 {n}개를 골랐다(Apache 경로 조작 · Log4Shell · Confluence 둘 · "
    "Exchange 둘 · GeoServer · Pulse Connect Secure 둘, 그리고 제품과 무관한 일반 경로 조작 하나). 선정표에 c1 의 짝 서명을 "
    "적고, 같은 제품이면 c1 서명의 asset_match 를 그대로 옮겼다. 공개 규칙이 우리 서명보다 무엇을 더 · 덜 잡는지를 같은 "
    "요청에 대 보는 것이 목적이다(이슈 #54 PoC). 매치는 알려진 공격 형태로 요청했다는 시도 증거일 뿐 성공 증거가 아니므로 "
    "심각도는 R106 과 같은 medium 이다. 원본의 응답 코드 조건(예: 200 · 301)은 성공 가능성이 있는 응답만 남기려는 것이라 "
    "그대로 옮겼고, 그 조건 때문에 빠지는 요청은 리플레이에서 따로 센다. 옮기면서 좁히거나 넓힌 것은 서명마다 sigma.notes 에 있다."
)
LAB_NOTE = ("실험용 (이슈 #54 리플레이). SigmaHQ/sigma 커밋 {commit} 의 webserver 규칙 가운데 변환되는 {n}개 전부를 "
            "선정 없이 옮겼다. 운영에 쓰지 않는다(다리의 RULESETS 에 넣지 않고 detector/ 에 두지 않는다). product 는 원본 "
            "제목, vendor 는 Sigma 이고 자산 조건은 없다. 규칙 라이선스는 DRL 1.1 이다.")


class ConvertError(Exception):
    """규칙 하나를 통째로 옮기지 못한다."""


_DETECT = None


def detect_module():
    """detect.py 를 불러온다(서명 검사 · regex_gap). DB 는 쓰지 않으므로 psycopg2 가 없으면 빈 모듈로 채운다."""
    global _DETECT
    if _DETECT is None:
        try:
            import psycopg2  # noqa: F401
        except ImportError:
            fake, extras = types.ModuleType("psycopg2"), types.ModuleType("psycopg2.extras")

            def no_db(*a, **k):
                raise RuntimeError("변환기는 DB 를 쓰지 않는다")
            extras.execute_batch = no_db
            fake.extras, fake.connect = extras, no_db
            sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import detect
        _DETECT = detect
    return _DETECT


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("pyyaml 이 필요합니다 (개발 PC 전용):  python3 -m pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def git_blob_sha1(data):
    """git 이 파일 내용에 붙이는 blob 해시(git hash-object 와 같은 값)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# ----------------------------------------------------------------------
#  값 · 필드 조건
# ----------------------------------------------------------------------

def value_regex(value):
    """Sigma 값 하나를 정규식 조각으로. (조각, 물음표 와일드카드를 썼는가) 를 돌려준다.

    * 는 .* , ? 는 . 이다. \\* · \\? · \\\\ 는 그 글자이고, 그 밖의 역슬래시는 글자 역슬래시다(Sigma 규약).
    메타 문자 . ^ $ * + ? ( ) [ ] { } | \\ 앞에만 역슬래시를 붙인다. 두 엔진이 같은 글자로 읽는 이스케이프만 쓴다.
    """
    out, qmark, i = [], False, 0
    while i < len(value):
        c = value[i]
        if c == "\\" and value[i + 1:i + 2] in ("*", "?", "\\"):
            out.append("\\" + value[i + 1])
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
            qmark = True
        elif c in REGEX_META:
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    return "".join(out), qmark


def inner_dollar(rx):
    """정규식에 대괄호 밖의 이스케이프하지 않은 $ 가 있는가. 감싼 뒤 가운데에 놓이면 파이썬은 끝 줄바꿈 앞에서도,
    PostgreSQL 은 문자열 끝에서만 맞는다(서명 전체의 끝 $ 는 fullmatch 가 맞춰 주지만 가운데의 $ 는 아니다)."""
    i, in_set = 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if in_set:
            in_set = c != "]"
        elif c == "[":
            in_set = True
            i += 1 + (rx[i + 1:i + 2] == "^")
            i += rx[i:i + 1] == "]"
            continue
        elif c == "$":
            return True
        i += 1
    return False


class Lit:
    """필드 조건 하나. kind 는 url(value: ^ … $ 정규식) · method · status(value: frozenset) · bad(value: 까닭).
    text 는 원본 표기(보고용), flags 는 notes 를 만들 표시(split:<필드> · keywords · qmark · re)."""

    __slots__ = ("kind", "value", "text", "flags")

    def __init__(self, kind, value, text, flags=()):
        self.kind, self.value, self.text, self.flags = kind, value, text, frozenset(flags)


def bad(text, why):
    return ("lit", Lit("bad", why, text))


def url_lits(text, matcher, values, all_, flags, field=""):
    """url 필드 조건 → 식. 값 목록은 정규식 하나의 선택지이고 all 이면 값마다 따로 AND 다.

    우리 url 은 경로와 질의가 한 값('경로?질의')이다. 한쪽만 뜻하는 필드(cs-uri-query · cs-uri-stem)에 앵커가 붙은 조건을
    url 전체에 그대로 대면 좁아지거나 아예 맞지 않는다(질의가 '/' 로 시작하는 url 의 처음에 올 수 없다). 그래서 앵커 조건은
    url 모양에 맞춰 옮긴다. SigmaHQ 는 cs-uri-query 에 전체 URI 를 적는 일도 많아 두 관례를 모두 받는다(넓어짐만 남는다).
      질의 startswith v → url 처음 또는 ? 바로 뒤가 v      질의 같음 v → url 전체가 v(뒤에 질의 허용) 또는 ? 뒤 전체가 v
      경로 endswith v   → ? 앞(없으면 끝)이 v 로 끝남      경로 같음 v → ? 앞(없으면 전체)이 v
    질의 endswith · 경로 startswith · 포함은 url 전체에 그대로 대도 같은 뜻이다."""
    pieces, flags = [], set(flags)
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            return bad(text, f"값 {v!r} 은 문자열이 아니다")
        v = str(v)
        if not v.isascii():
            return bad(text, "비ASCII 값은 두 엔진의 대소문자 규칙이 달라 옮기지 않는다")
        if matcher == "re":
            why = detect_module().regex_gap(v) or ("값 안의 $ 는 끝 줄바꿈 앞에서 두 엔진의 뜻이 다르다"
                                                   if inner_dollar(v) else None)
            if why:
                return bad(text, f"re 값이 두 엔진에서 같게 읽히지 않는다({why})")
            pieces.append(v)
            flags.add("re")
        else:
            piece, qmark = value_regex(v)
            pieces.append(piece)
            if qmark:
                flags.add("qmark")

    def wrap(alts):
        grouped = alts[0] if len(alts) == 1 and matcher != "re" else f"({'|'.join(alts)})"
        if matcher in ("contains", "re"):
            return f"^.*{grouped}.*$"
        # 값이 그쪽 끝에서 * 로 시작(끝)하면 앵커 위치가 뜻을 바꾸지 않아 url 전체에 그대로 댄다(전과 같은 식)
        lead, trail = all(a.startswith(".*") for a in alts), all(a.endswith(".*") for a in alts)
        if field in QUERY_FIELDS and matcher != "endswith" and not lead:
            if matcher == "startswith":
                return f"^({grouped}|[^?]*\\?{grouped}).*$"
            return f"^({grouped}(\\?.*)?|[^?]*\\?{grouped})$"
        if field in STEM_FIELDS and matcher != "startswith" and not trail:
            if matcher == "endswith":
                return f"^[^?]*{grouped}(\\?.*)?$"
            return f"^{grouped}(\\?.*)?$"
        if matcher == "startswith":
            return f"^{grouped}.*$"
        if matcher == "endswith":
            return f"^.*{grouped}$"
        return f"^{grouped}$"
    if all_:
        return ("and", [("lit", Lit("url", wrap([p]), text, flags)) for p in pieces])
    return ("lit", Lit("url", wrap(pieces), text, flags))


def field_formula(key, values):
    """선택 안의 필드 조건 하나(키 'field|조건자…': 값 · 값 목록) → 식."""
    field, *mods = str(key).split("|")
    text = str(key)
    values = values if isinstance(values, list) else [values]
    if not values:
        return bad(text, "값이 없다")
    if any(v is None for v in values):
        return bad(text, "값 없음(null) 조건")
    all_ = "all" in mods
    rest = [m for m in mods if m != "all"]
    unknown = [m for m in rest if m not in MATCHERS]
    if unknown:
        return bad(text, f"조건자 {' · '.join(unknown)}")
    if len(rest) > 1:
        return bad(text, f"조건자 {' · '.join(rest)} 를 함께 쓴다")
    matcher = rest[0] if rest else None
    if field in URL_FIELDS or field == "":
        flags = {f"split:{field}"} if field in SPLIT_FIELDS else set()
        if field == "":                     # 필드 없는 키('|all' 등)는 조건자가 붙은 keywords 다. 조건자가 없으면 포함
            flags.add("keywords")
            matcher = matcher or "contains"
        return url_lits(text, matcher, values, all_, flags, field)
    if field in METHOD_FIELDS or field in STATUS_FIELDS:
        if matcher:
            return bad(text, f"{field} 의 조건자 {matcher}")
        sets = []
        for v in values:
            if field in METHOD_FIELDS:
                if not (isinstance(v, str) and METHOD_VALUE_RE.fullmatch(v)):
                    return bad(text, f"메서드 값 {v!r}")
                sets.append(frozenset([v.upper()]))
            else:
                code = v if isinstance(v, int) and not isinstance(v, bool) else (
                    int(v) if isinstance(v, str) and v.isascii() and v.isdigit() else None)
                if code is None or not 100 <= code <= 599:
                    return bad(text, f"응답 코드 값 {v!r}")
                sets.append(frozenset([code]))
        kind = "method" if field in METHOD_FIELDS else "status"
        if all_:
            return ("and", [("lit", Lit(kind, s, text)) for s in sets])
        return ("lit", Lit(kind, frozenset().union(*sets), text))
    return bad(text, f"필드 {field}")


def selection_formula(name, body):
    """검색 식별자 하나(선택 · 키워드 목록) → 식."""
    if isinstance(body, dict):
        if not body:
            return bad(name, "빈 선택")
        return ("and", [field_formula(k, v) for k, v in body.items()])
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        return ("or", [selection_formula(name, x) for x in body])
    if isinstance(body, (str, int)) and not isinstance(body, bool):
        body = [body]
    if isinstance(body, list) and body and all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in body):
        return url_lits(f"{name}(keywords)", "contains", body, False, {"keywords"})
    return bad(name, "알 수 없는 선택 모양")


# ----------------------------------------------------------------------
#  condition
# ----------------------------------------------------------------------

def name_matcher(pattern):
    return re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$")


def parse_condition(text, names):
    """condition 문자열 → 식(선택 이름은 ("sel", 이름)). 우선순위는 not > and > or 이다."""
    if "|" in text:
        raise ConvertError("집계 조건(| count() 등)은 옮기지 못한다")
    tokens = TOKEN_RE.findall(text)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(want=None):
        nonlocal pos
        tok = peek()
        if tok is None or (want is not None and tok != want):
            raise ConvertError(f"condition 을 읽지 못했다: {text!r}")
        pos += 1
        return tok

    def pick(pattern):
        if pattern == "them":
            got = [n for n in names if not n.startswith("_")]
        else:
            m = name_matcher(pattern)
            got = [n for n in names if m.match(n)]
        if not got:
            raise ConvertError(f"condition 의 {pattern!r} 에 맞는 선택이 없다")
        return got

    def or_expr():
        kids = [and_expr()]
        while peek() == "or":
            take()
            kids.append(and_expr())
        return kids[0] if len(kids) == 1 else ("or", kids)

    def and_expr():
        kids = [not_expr()]
        while peek() == "and":
            take()
            kids.append(not_expr())
        return kids[0] if len(kids) == 1 else ("and", kids)

    def not_expr():
        if peek() == "not":
            take()
            return ("not", not_expr())
        return atom()

    def atom():
        tok = take()
        if tok == "(":
            inner = or_expr()
            take(")")
            return inner
        if tok in ("1", "all") and peek() == "of":
            take()
            got = [("sel", n) for n in pick(take())]
            return ("or" if tok == "1" else "and", got)
        if tok in ("and", "or", "not", "of", ")", "them") or tok.isdigit():
            raise ConvertError(f"condition 을 읽지 못했다: {text!r}")
        if tok not in names:
            raise ConvertError(f"condition 의 {tok!r} 선택이 없다")
        return ("sel", tok)

    out = or_expr()
    if pos != len(tokens):
        raise ConvertError(f"condition 을 읽지 못했다: {text!r}")
    return out


def substitute(f, selections):
    if f[0] == "sel":
        return selections[f[1]]
    if f[0] == "not":
        return ("not", substitute(f[1], selections))
    return (f[0], [substitute(k, selections) for k in f[1]])


def nnf(f, neg=False):
    """not 을 필드 조건까지 밀어 넣는다. 잎은 ("lit", Lit, 부정 여부)."""
    if f[0] == "not":
        return nnf(f[1], not neg)
    if f[0] == "lit":
        return ("lit", f[1], neg)
    op = f[0] if not neg else ("or" if f[0] == "and" else "and")
    return (op, [nnf(k, neg) for k in f[1]])


def dnf(f):
    """부정 표준형 식 → 갈래 목록 [[(Lit, 부정 여부), …], …]. 갈래가 MAX_BRANCHES 를 넘으면 변환하지 않는다."""
    if f[0] == "lit":
        return [[(f[1], f[2])]]
    if f[0] == "or":
        out = []
        for k in f[1]:
            out += dnf(k)
            if len(out) > MAX_BRANCHES:
                raise ConvertError(f"논리합 표준형 갈래가 {MAX_BRANCHES}개를 넘는다")
        return out
    out = [[]]
    for k in f[1]:
        out = [a + b for a in out for b in dnf(k)]
        if len(out) > MAX_BRANCHES:
            raise ConvertError(f"논리합 표준형 갈래가 {MAX_BRANCHES}개를 넘는다")
    return out


# ----------------------------------------------------------------------
#  규칙 하나
# ----------------------------------------------------------------------

def branch_signature(lits):
    """갈래 하나 → (서명 조건 dict, [(순위, note)]) 또는 (None, 버린 까닭)."""
    pos, neg, methods, statuses, notes, flags, neg_flags = [], [], None, None, [], set(), set()
    for lit, negated in lits:
        if lit.kind == "bad":
            if not negated:
                return None, f"옮기지 못하는 조건 {lit.text}({lit.value})"
            notes.append((0, f"필터 조건 {lit.text}({lit.value})을 옮기지 못해 뺐다. 원본이 거르던 요청에도 맞는다"
                             "(넓어짐)."))
        elif lit.kind == "url":
            bucket = neg if negated else pos
            if lit.value not in bucket:
                bucket.append(lit.value)
            # 표시의 방향은 조건의 부호에 따라 뒤집힌다. 양의 조건을 넓히면 서명이 넓어지고, 필터(음의 조건)를 넓히면 좁아진다
            (neg_flags if negated else flags).update(lit.flags)
        elif negated:
            what = "메서드" if lit.kind == "method" else "응답 코드"
            notes.append((0, f"{what} 부정 조건 {lit.text} 을 옮기지 못해 뺐다. 원본이 거르던 요청에도 맞는다(넓어짐)."))
        elif lit.kind == "method":
            methods = lit.value if methods is None else methods & lit.value
        else:
            statuses = lit.value if statuses is None else statuses & lit.value
    if methods is not None and not methods:
        return None, "메서드 조건이 서로 어긋나 맞는 요청이 없다"
    if statuses is not None and not statuses:
        return None, "응답 코드 조건이 서로 어긋나 맞는 요청이 없다"
    if set(pos) & set(neg):
        return None, "같은 url 조건이 양 · 음으로 함께 있어 맞는 요청이 없다"
    if not pos:
        return None, "url 조건이 없어(메서드 · 응답 코드만) 너무 넓다"
    cond = {"pattern": pos[0]}
    if pos[1:]:
        cond["all_patterns"] = pos[1:]
    if neg:
        cond["not_patterns"] = neg
    if methods is not None:
        cond["methods"] = sorted(methods)
    if statuses is not None:
        cond["statuses"] = sorted(statuses)
    if "keywords" in flags:
        notes.append((1, "keywords(로그 줄 전체에서 찾는 값)를 요청 url 에만 댔다. 헤더 · 본문 · 다른 필드에 든 값은 보지 "
                         "않는다(좁아짐)."))
    if "qmark" in flags:
        notes.append((2, "값의 ? 는 Sigma 와일드카드라 아무 글자 하나로 옮겼다. 원본이 질의 문자열의 ? 를 뜻했다면 다른 "
                         "글자에도 맞는다(넓어짐)."))
    if "re" in flags:
        notes.append((3, "re 조건은 원본이 대소문자를 가리지만 엔진은 가리지 않는다(넓어짐)."))
    split = sorted(f.split(":", 1)[1] for f in flags if f.startswith("split:"))
    if split:
        notes.append((5, f"원본 필드 {' · '.join(split)} 를 요청 url(경로와 질의가 한 값) 하나에 댔다. 경로 · 질의 구분을 "
                         "잃어 한쪽 조건이 다른 쪽에서도 맞을 수 있다(넓어짐)."))
    if "keywords" in neg_flags:
        notes.append((0, "필터 keywords 를 요청 url 에서만 찾는다. 헤더 · 본문 등 다른 곳에 필터 값이 든 요청(원본이 거르던 "
                         "것)에도 맞는다(넓어짐)."))
    if "qmark" in neg_flags:
        notes.append((2, "필터 값의 ? 를 아무 글자 하나로 옮겨 원본보다 더 많이 거른다(좁아짐)."))
    if "re" in neg_flags:
        notes.append((3, "필터 re 조건을 대소문자 가리지 않고 맞춰 원본보다 더 많이 거른다(좁아짐)."))
    neg_split = sorted(f.split(":", 1)[1] for f in neg_flags if f.startswith("split:"))
    if neg_split:
        notes.append((5, f"필터 필드 {' · '.join(neg_split)} 를 요청 url 하나에 댔다. 다른 쪽에 든 값도 걸러 원본보다 "
                         "좁아질 수 있다(좁아짐)."))
    return cond, notes


def base_id(path):
    name = os.path.basename(path)
    name = name[:-4] if name.endswith(".yml") else name
    name = name[4:] if name.startswith("web_") else name
    return "sg-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def fit_id(base, suffix=""):
    """40자 안으로. 넘으면 낱말(-) 경계에서 자른다."""
    limit = ID_MAX - len(suffix)
    if len(base) > limit:
        cut = base[:limit]
        if base[limit] != "-" and "-" in cut[3:]:
            cut = cut[:cut.rindex("-")]
        base = cut.rstrip("-")
    return base + suffix


def sigma_path(path):
    """원본 저장소 안의 상대 경로(rules… 로 시작하는 조각부터). 찾지 못하면 파일 이름."""
    parts = os.path.normpath(os.path.abspath(path)).split(os.sep)
    for i, p in enumerate(parts):
        if p.startswith("rules"):
            return "/".join(parts[i:])
    return parts[-1]


def rule_meta(doc, path):
    """원본 규칙의 머리(제목 · id · 상태 · level · 작성자 · tags). 서명 sigma 객체의 꼴(detect.check_sig_sigma)에 맞아야 한다."""
    d = detect_module()
    if not isinstance(doc, dict):
        raise ConvertError("YAML 최상위가 객체가 아니다")
    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict) or logsource.get("category") != "webserver":
        raise ConvertError("logsource.category 가 webserver 가 아니다")
    meta = {k: doc.get(k) for k in ("title", "id", "status", "level", "author")}
    if not (isinstance(meta["title"], str) and meta["title"].strip()):
        raise ConvertError("title 이 없다")
    if not (isinstance(meta["id"], str) and d.SIGMA_ID_RE.fullmatch(meta["id"])):
        raise ConvertError("id 가 uuid 가 아니다")
    if meta["status"] not in d.SIGMA_STATUSES:
        raise ConvertError(f"status {meta['status']!r} 를 모른다")
    if meta["level"] not in d.SIGMA_LEVELS:
        raise ConvertError(f"level {meta['level']!r} 를 모른다")
    if not (isinstance(meta["author"], str) and meta["author"].strip()):
        meta["author"] = "(원본에 작성자 없음)"
    meta["title"], meta["author"] = " ".join(meta["title"].split()), " ".join(meta["author"].split())
    tags = doc.get("tags") or []
    cves = []
    for t in tags if isinstance(tags, list) else []:
        m = CVE_TAG_RE.fullmatch(t) if isinstance(t, str) else None
        cve = f"CVE-{m.group(1)}" if m else None
        if cve and d.SIG_CVE_RE.fullmatch(cve) and cve not in cves:
            cves.append(cve)
    meta["cves"] = cves
    meta["path"] = path
    # product · service 는 로그 출처를 한정한다(우리는 보지 않는다). definition 은 수집 요건 설명이라 뺀다
    meta["logsource_extra"] = {k: v for k, v in logsource.items() if k in ("product", "service")}
    return meta


def convert(doc, path, commit, product, vendor, asset_match=None, human_notes=(), id_base=None):
    """원본 규칙 하나 → 보고 dict {path, meta, signatures, dropped, error}. 통째로 옮기지 못하면 error 에 까닭."""
    report = {"path": path, "meta": None, "signatures": [], "dropped": [], "error": None}
    try:
        meta = rule_meta(doc, path)
        report["meta"] = meta
        det = doc.get("detection")
        if not isinstance(det, dict) or "condition" not in det:
            raise ConvertError("detection.condition 이 없다")
        names = [k for k in det if k not in NOT_SELECTIONS]
        selections = {n: selection_formula(n, det[n]) for n in names}
        conds = det["condition"] if isinstance(det["condition"], list) else [det["condition"]]
        if not all(isinstance(c, str) and c.strip() for c in conds):
            raise ConvertError("condition 이 문자열이 아니다")
        tree = substitute(("or", [parse_condition(c, names) for c in conds]), selections)
        branches = dnf(nnf(tree))
        built = []
        for i, lits in enumerate(branches, 1):
            cond, notes = branch_signature(lits)
            if cond is None:
                report["dropped"].append((i, notes))
            else:
                built.append((i, cond, notes))
        if not built:
            raise ConvertError("서명으로 옮긴 갈래가 없다 (" + " / ".join(f"갈래 {i}: {w}" for i, w in
                                                                   report["dropped"]) + ")")
    except ConvertError as e:
        report["error"] = str(e)
        return report
    base = id_base or base_id(path)
    cond_text = " / ".join(conds)
    for n, (i, cond, notes) in enumerate(built, 1):
        notes = list(notes)
        if report["dropped"]:
            why = " / ".join(f"갈래 {j}: {w}" for j, w in report["dropped"])
            notes.append((0, f"원본의 다른 갈래 {len(report['dropped'])}개는 옮기지 못해 버렸다({why}). 이 서명만으로는 "
                             "원본보다 좁다."))
        if meta["logsource_extra"]:
            ls = " · ".join(f"{k}={v}" for k, v in sorted(meta["logsource_extra"].items()))
            notes.append((0, f"원본 logsource 의 한정({ls})은 보지 않는다(넓어짐)."))
        if len(built) > 1 or report["dropped"]:
            notes.append((4, f"원본 condition '{cond_text}' 을 논리합 표준형으로 편 갈래 {len(branches)}개 가운데 "
                             f"{i}번째다."))
        if not meta["cves"]:
            notes.append((6, "원본 tags 에 CVE 가 없어 cves 를 비웠다."))
        texts = [t for _, t in sorted(notes, key=lambda x: x[0])] + list(human_notes)
        sid = fit_id(base, f"-{n}" if len(built) > 1 else "")
        sig = {"id": sid, **cond, "product": product, "vendor": vendor, "cves": list(meta["cves"])}
        if asset_match is not None:
            sig["asset_match"] = asset_match
        sig["mapping"] = "sigma"
        sig["sigma"] = {"id": meta["id"], "title": meta["title"], "path": path, "commit": commit,
                        "url": f"{BLOB_URL}{commit}/{path}", "author": meta["author"], "status": meta["status"],
                        "level": meta["level"], "license": LICENSE, "notes": texts}
        head = (f"SigmaHQ 규칙 '{meta['title']}'({meta['id']}) · 작성 {meta['author']} · {meta['status']}/"
                f"{meta['level']} · DRL 1.1 로 배포된 것을 변환했다.")
        sig["source"] = f"{head} {texts[0]}" if texts else head
        report["signatures"].append(sig)
    return report


def rules_doc(version, note, rationale, signatures, name=RULE_NAME, derived=None):
    doc = {"rule_version": version, "note": note}
    if derived:
        doc["derived_from"] = derived
    doc["aggregation"] = {"window_gap_seconds": 900, "comment": AGGREGATION_COMMENT}
    doc["rules"] = [{"id": RULE_ID, "name": name, "severity": "medium", "type": "url_signature", "enabled": True,
                     "params": {"eventids": list(EVENTIDS), "signatures": signatures}, "rationale": rationale}]
    return doc


def check_doc(doc):
    """탐지기가 이 규칙 파일을 받는지 본다(detect.url_signature_args). 받지 않으면 ValueError."""
    d = detect_module()
    for rule in doc["rules"]:
        d.url_signature_args(rule)
        for s in rule["params"]["signatures"]:
            if len(s["id"]) > ID_MAX:
                raise ValueError(f"서명 id {s['id']} 가 {ID_MAX}자를 넘는다")


def dump(doc):
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ----------------------------------------------------------------------
#  build · report · lab
# ----------------------------------------------------------------------

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def verify_sources(sigma_dir=SIGMA_DIR):
    """manifest.json 의 파일마다 git blob sha1 을 대조한다. 어긋난 파일 목록을 돌려준다."""
    manifest = load_json(os.path.join(sigma_dir, "manifest.json"))
    bad_files = []
    for item in manifest["files"]:
        p = os.path.join(sigma_dir, item["path"])
        try:
            with open(p, "rb") as f:
                ok = git_blob_sha1(f.read()) == item["blob_sha1"]
        except OSError:
            ok = False
        if not ok:
            bad_files.append(item["path"])
    return manifest, bad_files


def build(sigma_dir=SIGMA_DIR):
    """선정표와 원본으로 sg1 규칙 파일(dict)을 만든다. (규칙 파일, 규칙별 보고 목록) 을 돌려준다."""
    sel = load_json(os.path.join(sigma_dir, "selection.json"))
    manifest, bad_files = verify_sources(sigma_dir)
    if bad_files:
        raise SystemExit(f"원본이 manifest.json 의 blob sha1 과 다르다: {', '.join(bad_files)}")
    if manifest["commit"] != sel["commit"]:
        raise SystemExit("선정표와 manifest.json 의 커밋이 다르다")
    listed = {item["path"] for item in manifest["files"]}
    reports, signatures = [], []
    for entry in sel["rules"]:
        if entry["path"] not in listed:
            raise SystemExit(f"{entry['path']} 가 manifest.json 에 없다")
        doc = load_yaml(os.path.join(sigma_dir, entry["path"]))
        rep = convert(doc, entry["path"], sel["commit"], entry["product"], entry["vendor"],
                      entry.get("asset_match"), entry.get("notes", []))
        if rep["error"]:
            raise SystemExit(f"{entry['path']}: {rep['error']}")
        reports.append(rep)
        signatures += rep["signatures"]
    ids = [s["id"] for s in signatures]
    if len(set(ids)) != len(ids):
        raise SystemExit("서명 id 가 겹친다: " + ", ".join(sorted({i for i in ids if ids.count(i) > 1})))
    n = len(sel["rules"])
    doc = rules_doc("sg1", NOTE.format(commit=sel["commit"], n=n), RATIONALE.format(n=n), signatures,
                    derived={"generator": "detector/sigma_convert.py build",
                             "selection": "detector/sigma/selection.json", "source": "https://github.com/SigmaHQ/sigma",
                             "commit": sel["commit"], "license": LICENSE})
    check_doc(doc)
    return doc, reports


def print_report(reports, out=None):
    """보고 표. 규칙마다 한 줄, 그 아래 서명마다 조건과 notes."""
    w = (out or sys.stdout).write
    w(f"{'결과':<6} {'서명':>4} {'버린 갈래':>8}  원본\n")
    w("-" * 100 + "\n")
    for r in reports:
        state = "오류" if r["error"] else ("일부" if r["dropped"] else "변환")
        w(f"{state:<6} {len(r['signatures']):>4} {len(r['dropped']):>8}  {r['path']}\n")
    for r in reports:
        w("\n== " + r["path"] + "\n")
        if r["meta"]:
            m = r["meta"]
            w(f"   {m['title']} ({m['id']}) {m['status']}/{m['level']} · 작성 {m['author']}\n")
        if r["error"]:
            w(f"   변환 못 함: {r['error']}\n")
        for i, why in r["dropped"]:
            w(f"   버린 갈래 {i}: {why}\n")
        for s in r["signatures"]:
            w(f"   서명 {s['id']}\n      pattern {s['pattern']}\n")
            for p in s.get("all_patterns", []):
                w(f"      all     {p}\n")
            for p in s.get("not_patterns", []):
                w(f"      not     {p}\n")
            if "methods" in s:
                w(f"      메서드  {' · '.join(s['methods'])}\n")
            if "statuses" in s:
                w(f"      응답    {' · '.join(str(c) for c in s['statuses'])}\n")
            w(f"      cves    {' · '.join(s['cves']) or '-'}\n")
            for t in s["sigma"]["notes"]:
                w(f"      - {t}\n")


def lab(src, out, commit):
    """원본 폴더의 webserver 규칙 전부를 실험용 sgx 규칙 파일로. (규칙 파일, 보고 목록, 건너뛴 파일 수) 를 돌려준다."""
    reports, signatures, skipped = [], [], 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".yml"):
                continue
            p = os.path.join(dirpath, name)
            doc = load_yaml(p)
            if not (isinstance(doc, dict) and isinstance(doc.get("logsource"), dict)
                    and doc["logsource"].get("category") == "webserver"):
                skipped += 1
                continue
            path = os.path.relpath(p, src).replace(os.sep, "/")
            title = doc.get("title") if isinstance(doc.get("title"), str) else name
            rep = convert(doc, path, commit, " ".join(title.split()), "Sigma")
            taken = {s["id"] for s in signatures}
            for s in rep["signatures"]:
                if s["id"] in taken:        # 파일 이름이 잘려 겹치면 원본 id 앞 네 글자를 붙인다
                    s["id"] = fit_id(s["id"], "-" + doc["id"][:4])
            reports.append(rep)
            signatures += rep["signatures"]
    n = sum(1 for r in reports if r["signatures"])
    doc = rules_doc("sgx", LAB_NOTE.format(commit=commit, n=n),
                    "실험용. 선정 없이 변환되는 webserver 규칙 전부다. 리플레이에서 요청 단위 매치만 센다.", signatures,
                    name=RULE_NAME + " (실험 전체)",
                    derived={"generator": "detector/sigma_convert.py lab", "source": "https://github.com/SigmaHQ/sigma",
                             "commit": commit, "license": LICENSE})
    check_doc(doc)
    return doc, reports, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description="SigmaHQ webserver 규칙 → url_signature 서명 (이슈 #54)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="선정표 → detector/rules_sigma.json")
    b.add_argument("--check", action="store_true", help="쓰지 않고 저장된 파일과 글자가 같은지만 본다")
    r = sub.add_parser("report", help="변환 결과 · notes 를 표로")
    r.add_argument("files", nargs="+")
    r.add_argument("--commit", help="원본 커밋 (기본: 선정표의 커밋)")
    x = sub.add_parser("lab", help="원본 폴더의 webserver 규칙 전부를 실험용 sgx 로")
    x.add_argument("src")
    x.add_argument("--out", required=True)
    x.add_argument("--commit", help="원본 커밋 (기본: 선정표의 커밋)")
    args = ap.parse_args(argv)

    if args.cmd == "build":
        doc, reports = build()
        text = dump(doc)
        if args.check:
            try:
                with open(OUT, encoding="utf-8") as f:
                    same = f.read() == text
            except OSError:
                same = False
            print("같다" if same else "다르다: python3 detector/sigma_convert.py build 로 다시 만든다")
            return 0 if same else 1
        with open(OUT, "w", encoding="utf-8") as f:
            f.write(text)
        n = sum(len(r["signatures"]) for r in reports)
        print(f"{os.path.relpath(OUT)}: 원본 {len(reports)}개 → 서명 {n}개")
        return 0
    commit = args.commit or load_json(SELECTION)["commit"]
    if args.cmd == "report":
        reports = []
        for p in args.files:
            rep = convert(load_yaml(p), sigma_path(p), commit, "-", "-")
            reports.append(rep)
        print_report(reports)
        return 0
    out = os.path.abspath(args.out)
    if os.path.dirname(out) == HERE:
        sys.exit("실험 파일은 detector/ 밖에 둔다 (운영 규칙 파일과 섞이지 않게)")
    doc, reports, skipped = lab(args.src, out, commit)
    with open(out, "w", encoding="utf-8") as f:
        f.write(dump(doc))
    print_report(reports)
    ok = sum(1 for r in reports if r["signatures"])
    n = sum(len(r["signatures"]) for r in reports)
    print(f"\nwebserver 규칙 {len(reports)}개 중 {ok}개 변환(서명 {n}개), 그 밖의 범주 {skipped}개 건너뜀 → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
