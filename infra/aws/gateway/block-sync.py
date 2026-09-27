#!/usr/bin/env python3
"""
OpsLoop - 관문 차단 목록 동기화 (이슈 #47)

데이터 노드 집행기(enforcer/block_enforcer.py)가 원장 버킷에 올린 차단 목록을 1분마다 읽어 관문 nft 집합
(inet filter opsloop_block)에 반영하고, 반영 결과를 관문 상태로 올린다. 집행기가 이 상태를 읽어 DB 의
enforced_at · method · enforce_note 를 쓴다. 관문은 DB 에 닿지 않고 DB 비밀번호도 모른다.

  읽기  s3://<버킷>/block/v1/latest.json
        {"v":1,"generated_at":ISO,"entries":[{"ip":"a.b.c.d","until":ISO}],"digest":"<sha256 hex>"}
  쓰기  s3://<버킷>/hb/v1/host=<관문 인스턴스 ID>-block/latest.json
        {"v":1,"at":ISO,"mode":"fail2ban"|"nft","list_digest":..,"list_generated_at":..,"applied":n,
         "set_count":n,"rejected":[{"ip":..,"why":..}],"errors":[..],"selftest":"ok"|"fail:<사유>"|null}

한 회차
  1. 목록을 읽고 digest 를 검증한다. 못 읽거나 형식 · digest 가 틀리면 집합을 건드리지 않는다
     (fail2ban 은 bantime, nft 는 원소 timeout 으로 저절로 빠진다). 목록이 30분 넘게 오래됐으면(집행기는 10분마다
     다시 올린다) 집행기가 멈췄거나 올리지 못하는 것이다. 그사이의 해제 · 단축이 목록에 없으므로 이 목록으로 넣거나
     늘리지 않는다: 새로 넣기 · 다시 걸기 · flush 뒤 되살리기를 멈추고, 집합에 남은 것은 원소 만료로 빠지게 두며,
     until 이 지났거나 목록에 없는 것만 뺀다. 목록을 적용한 것이 아니므로 list_digest 를 비운다
  2. 항목을 다시 검사한다: IPv4 한 주소 · 금지 대역 밖 · 4096 개까지 · until 이 미래. 걸린 것은 rejected 로 돌려준다
  3. 모드별로 반영한다
     fail2ban  jail opsloop-block 의 banned 와 비교해 banip · unbanip 한다. jail bantime(24시간)이 until 보다
               길 수 있어 until 이 지난 항목은 매 회차 unbanip 한다. until 이 더 멀면 원소가 만료되기 10분 전에
               다시 걸어 끊기지 않게 한다
     nft       집합에 timeout=남은 초로 넣고 뺀다. until 이 바뀌면(연장 · 단축) 원소를 바꿔 넣는다
  4. 어느 모드든 실제 집합(nft -j list set)을 기대와 대조한다. nft -f(flush ruleset)로 비었으면 되살리고
     목록 밖 원소는 뺀다. 그래도 집합에 없는 항목은 rejected 로 돌려준다
  5. 상태를 올린다. list_digest · list_generated_at 은 대조까지 마친 목록의 값이다. 목록을 못 읽었거나,
     집합을 못 읽었거나, forward 체인에 차단 규칙이 없으면(원소가 있어도 막지 못한다) 비운다.
     set_count 는 집합을 못 읽으면 null 이다

digest
  sha256(json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)) 의 16진수.
  entries 는 파일에 적힌 순서(집행기가 ip 로 정렬해 둔다) 그대로 쓴다. 다시 정렬하지 않으므로 정렬 방식이
  문자열이든 숫자든 집행기가 올린 순서로 계산한 값과 맞는다

자가 시험 (--selftest)
  문서용 주소 192.0.2.123(RFC 5737, 금지 대역 아님, 실제 유입 없음)을 nft 에 60초 timeout 으로 넣었다 빼 보고,
  fail2ban 모드면 banip · unbanip 로 한 번 더 넣었다 뺀다(원소 timeout 이 jail bantime 인지까지 본다).
  결과("ok" · "fail:<사유>")를 상태 폴더에 남겨 이후 상태의 selftest 로 싣는다. fail2ban 이 안 되면 MODE=nft 로 바꾼다.
  다른 회차와 겹치지 않게 잠근다(겹치면 시험 주소가 목록 밖 원소로 빠진다)

설정 (/etc/default/opsloop-block-sync)
  MODE=fail2ban|nft  OPSLOOP_BUCKET=<버킷>  OPSLOOP_HOST=<관문 인스턴스 ID>  AWS_DEFAULT_REGION=ap-northeast-2
  OPSLOOP_BLOCK_STATE (기본 /var/lib/opsloop-block-sync)

사용 (root)
  set -a; . /etc/default/opsloop-block-sync; set +a
  python3 block-sync.py --dry-run      읽고 계획만 찍는다. 집합 · fail2ban · 상태를 건드리지 않는다
  python3 block-sync.py --selftest     자가 시험 뒤 한 회차
  systemctl start opsloop-block-sync.service
"""

import argparse
import ast
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

LIST_KEY = "block/v1/latest.json"
FAMILY, TABLE, SET = "inet", "filter", "opsloop_block"
JAIL = "opsloop-block"
# fail2ban/jail.d/opsloop-block.conf 의 bantime 과 같아야 한다 (자가 시험이 원소 timeout 으로 확인한다)
BANTIME = 86400
MAX_ENTRIES = 4096                # nftables.conf 의 set size 와 같다
MAX_LIST_BYTES = 4 * 1024 * 1024  # 4096 항목이면 300KB 안팎이다
REFRESH_BEFORE = 600              # fail2ban 원소가 이만큼 안 남았고 until 이 더 멀면 다시 건다
DRIFT = 120                       # nft 모드에서 남은 시간과 원소 만료가 이보다 벌어지면 바꿔 넣는다
STALE_LIST = 1800                 # 집행기는 최소 10분마다 올린다. 이보다 오래되면 빼기만 하고 넣거나 늘리지 않는다
MAX_REJECTED = 200                # 상태에 싣는 rejected 상한
SELFTEST_IP = "192.0.2.123"
SELFTEST_TIMEOUT = 60
CMD_TIMEOUT = 60
BAN_CHUNK = 200                   # fail2ban-client 한 번에 넘기는 주소 수
DEFAULT_STATE = "/var/lib/opsloop-block-sync"
HOST_RE = re.compile(r"i-[0-9a-f]{8,17}")
# nft list chain 이 찍는 차단 규칙. 카운터가 붙어 있어도 된다
DROP_RULE_RE = re.compile(r"ip saddr @opsloop_block (?:counter packets \d+ bytes \d+ )?drop\b")

# 차단 금지 대역. DB block_exempt 초기값과 같다(infra/migrations/20260927_block_enforce.sql). 집행기가 DB 로 거른
# 목록을 한 번 더 거른다. 문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)은 시험 출발지라 넣지 않는다
EXEMPT = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "15.164.37.49/32",            # 관문 EIP
    "::1/128", "fc00::/7", "fe80::/10",
))


class NftError(Exception):
    pass


class F2bError(Exception):
    pass


class F2bOutputError(F2bError):
    """fail2ban-client 는 답했지만 출력을 읽지 못했다."""


def utcnow():
    return datetime.now(timezone.utc)


def iso(t):
    return t.astimezone(timezone.utc).isoformat(timespec="seconds")


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


def first_line(s):
    for line in (s or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def canonical_digest(entries):
    canon = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


def run(argv, stdin=None, timeout=CMD_TIMEOUT):
    """(종료 코드, 표준 출력, 표준 오류). 실행 파일이 없으면 127, 시간을 넘기면 124."""
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "", f"{argv[0]} 없음"
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} 시간 초과"
    return p.returncode, p.stdout, p.stderr


# ── nft ────────────────────────────────────────────────────────

def nft_lines(op):
    """("add", ip, 초) · ("replace", ip, 초) · ("del", ip) → nft 명령 줄. ip 는 검사를 마친 IPv4 표준형뿐이다."""
    el = f"element {FAMILY} {TABLE} {SET}"
    if op[0] == "del":
        return [f"delete {el} {{ {op[1]} }}"]
    add = f"add {el} {{ {op[1]} timeout {max(1, int(op[2]))}s }}"
    return [f"delete {el} {{ {op[1]} }}", add] if op[0] == "replace" else [add]


def _v4(v):
    try:
        return str(ipaddress.IPv4Address(v)) == v
    except (ValueError, TypeError):
        return False


def parse_elems(elems):
    """nft -j 의 elem 목록. timeout 이 있으면 {"elem": {"val", "timeout", "expires"}}, 없으면 주소 문자열이다
    (nftables src/json.c set_elem_expr_json: 둘 다 밀리초를 1000 으로 나눈 초 단위 정수). IPv4 표준형만 받는다
    (여기서 받은 값을 빼기 명령에 다시 쓴다)."""
    out = {}
    for e in elems if isinstance(elems, list) else []:
        if isinstance(e, str) and _v4(e):
            out[e] = {"timeout": None, "expires": None}
        elif isinstance(e, dict) and isinstance(e.get("elem"), dict) and _v4(e["elem"].get("val")):
            inner = e["elem"]
            t, x = inner.get("timeout"), inner.get("expires")
            out[inner["val"]] = {"timeout": t if isinstance(t, (int, float)) else None,
                                 "expires": x if isinstance(x, (int, float)) else None}
    return out


class Nft:
    def __init__(self, runner=run):
        self.run = runner

    def list_set(self):
        """{주소: {"timeout": 초|None, "expires": 초|None}}. 집합이 없거나 못 읽으면 NftError."""
        rc, out, err = self.run(["nft", "-j", "list", "set", FAMILY, TABLE, SET])
        if rc != 0:
            raise NftError(first_line(err) or f"nft 종료 코드 {rc}")
        try:
            doc = json.loads(out)
        except ValueError:
            raise NftError("nft -j 출력이 JSON 이 아니다") from None
        for item in doc.get("nftables", []) if isinstance(doc, dict) else []:
            s = item.get("set") if isinstance(item, dict) else None
            if isinstance(s, dict) and s.get("name") == SET:
                return parse_elems(s.get("elem", []))
        raise NftError("nft 출력에 집합이 없다")

    def has_drop_rule(self):
        rc, out, err = self.run(["nft", "list", "chain", FAMILY, TABLE, "forward"])
        if rc != 0:
            raise NftError(first_line(err) or f"nft 종료 코드 {rc}")
        return DROP_RULE_RE.search(out) is not None

    def apply(self, ops):
        """한 묶음(원자적)으로 먼저 넣고, 실패하면 하나씩 넣는다. 없는 원소를 빼다 실패하면(만료로 막 빠진 경우)
        묶음 전체가 취소되기 때문이다. 바꿔 넣기(replace)는 빼기와 넣기를 따로 돌린다. 집합을 읽은 뒤 원소가
        만료로 빠졌으면 빼기는 실패하지만 넣기는 되어야 하기 때문이다. 실패한 [(ip, 사유)] 를 돌려준다."""
        if not ops:
            return []
        rc, _, err = self.run(["nft", "-f", "/dev/stdin"], stdin="\n".join(sum(map(nft_lines, ops), [])) + "\n")
        if rc == 0:
            return []
        failed = []
        for op in ops:
            lines = nft_lines(op)
            if op[0] == "replace":
                self.run(["nft", "-f", "/dev/stdin"], stdin=lines[0] + "\n")      # 빼기. 이미 없으면 실패해도 된다
                lines = lines[1:]
            rc, _, err = self.run(["nft", "-f", "/dev/stdin"], stdin="\n".join(lines) + "\n")
            if rc != 0:
                failed.append((op[1], first_line(err) or f"nft 종료 코드 {rc}"))
        return failed


# ── fail2ban ───────────────────────────────────────────────────

def parse_banned(out):
    """fail2ban-client get <jail> banned 출력. 1.0.2 는 파이썬 목록 표기(['1.2.3.4', ...])로 찍는다
    (beautifier 에 banned 갈래가 없어 목록을 그대로 print 한다). 공백으로 나눈 주소(get <jail> banip 형식)도 받는다."""
    out = out.strip()
    if not out:
        return set()
    try:
        v = ast.literal_eval(out)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        v = out.split()
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, (list, tuple, set)):
        raise F2bOutputError("banned 출력 형식이 틀리다")
    ips = set()
    for x in v:
        for y in (x if isinstance(x, (list, tuple)) else [x]):
            try:
                ips.add(str(ipaddress.ip_address(y)))
            except (ValueError, TypeError):
                raise F2bOutputError("banned 출력에 주소가 아닌 값이 있다") from None
    return ips


class Fail2ban:
    def __init__(self, runner=run):
        self.run = runner

    def _call(self, *args):
        rc, out, err = self.run(["fail2ban-client", *args])
        if rc != 0:
            raise F2bError(first_line(err) or first_line(out) or f"fail2ban-client 종료 코드 {rc}")
        return out

    def ping(self):
        if "pong" not in self._call("ping"):
            raise F2bError("ping 응답이 pong 이 아니다")

    def banned(self):
        # get <JAIL> banned 는 목록 객체를 그대로 찍는다(IPAddr.__repr__ 가 따옴표 붙은 주소). 그 표기를 못 읽으면
        # get <JAIL> banip(클라이언트가 공백으로 이어 찍는다)으로 한 번 더 본다
        try:
            return parse_banned(self._call("get", JAIL, "banned"))
        except F2bOutputError:
            return parse_banned(self._call("get", JAIL, "banip"))

    def ban(self, ips):
        # 1.0.2: set <JAIL> banip <IP> ... <IP>. 명령 처리 중에 actionban 을 돌리고 돌아온다
        for i in range(0, len(ips), BAN_CHUNK):
            self._call("set", JAIL, "banip", *ips[i:i + BAN_CHUNK])

    def unban(self, ips):
        # 1.0.2: set <JAIL> unbanip [--report-absent] <IP> ... <IP>. --report-absent 없이는 없는 주소를 넘어간다
        for i in range(0, len(ips), BAN_CHUNK):
            self._call("set", JAIL, "unbanip", *ips[i:i + BAN_CHUNK])


# ── 목록 ───────────────────────────────────────────────────────

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


# ── 한 회차 ────────────────────────────────────────────────────

def needs_refresh(el, rem):
    """fail2ban 모드: 원소가 곧 만료되는데 until 은 그보다 멀다."""
    exp = el.get("expires")
    return exp is not None and exp < REFRESH_BEFORE and rem > exp + 60


def plan_nft(mode, want, actual, banned, now, grow=True):
    """(nft 작업, 반영 못 한 {ip: 사유}). 목록 밖 원소 빼기 · 되살림 · 바꿔 넣기.
    grow=False(오래된 목록)면 넣거나 늘리지 않는다. 빼기와 줄이기(만료 없는 원소 · until 보다 늦게 끝나는 원소)만 한다."""
    # 빼기를 앞에 둔다. 집합이 가득(size 4096) 찼을 때 같은 묶음의 넣기가 뺀 자리를 쓴다
    # (커널은 묶음 안에서 뺀 원소 수만큼 상한을 늘려 준다. 넣기가 앞이면 묶음 전체가 실패한다)
    ops = [("del", ip) for ip in sorted(set(actual) - set(want))]
    reasons = {}
    for ip, until in want.items():
        rem = remaining(until, now)
        el = actual.get(ip)
        if el is None and not grow:
            continue
        if mode == "nft":
            if el is None:
                ops.append(("add", ip, rem))
            elif el["expires"] is None or el["expires"] - rem > DRIFT or (grow and rem - el["expires"] > DRIFT):
                ops.append(("replace", ip, rem))
        elif el is None:
            if banned is None:
                reasons[ip] = "fail2ban 응답 없음"
            elif ip in banned:
                ops.append(("add", ip, min(rem, BANTIME)))     # fail2ban 은 걸었다고 아는데 집합에 없다(flush 뒤)
            else:
                reasons[ip] = "fail2ban 반영 실패"
        elif el["expires"] is None:
            ops.append(("replace", ip, min(rem, BANTIME)))     # 만료 없는 원소는 두지 않는다
    return ops, reasons


def new_status(mode, now, selftest):
    return {"v": 1, "at": iso(now), "mode": mode, "list_digest": None, "list_generated_at": None,
            "applied": 0, "set_count": None, "rejected": [], "errors": [], "selftest": selftest}


def sync(cfg, s3, nft, f2b, now=None, selftest=None, dry_run=False):
    """한 회차. (상태, 계획 문장 목록). dry_run 이면 읽기만 한다. now 를 주면(시험) 상태 시각도 그 값이다."""
    fixed = now is not None
    now = now or utcnow()
    st = new_status(cfg["mode"], now, selftest)
    errors, plan = st["errors"], []

    try:
        actual = nft.list_set()
    except NftError as e:
        errors.append(f"nft 집합을 읽지 못함: {e}")
        return st, plan
    st["set_count"] = len(actual)

    doc, why = load_list(s3, cfg["bucket"])
    if doc is None:
        errors.append(why)
        return st, plan
    age = (now - parse_time(doc["generated_at"])).total_seconds()
    stale = age > STALE_LIST
    if stale:
        errors.append(f"목록이 오래됨 ({int(age // 60)}분) · 넣거나 늘리지 않음")
    want, rejected, dup = recheck(doc["entries"], now)
    if dup:
        errors.append(f"목록에 중복 항목 {dup}개")
    if stale:
        # 집행기가 멈췄거나 목록을 올리지 못한다. 그사이의 해제 · 단축이 이 목록에 없으므로 집합에 이미 있는 것만
        # 기대로 둔다(원소 만료로 빠진다). until 이 지났거나 목록에 없는 것은 아래에서 뺀다
        want = {ip: until for ip, until in want.items() if ip in actual}

    try:
        rule_ok = nft.has_drop_rule()
    except NftError as e:
        rule_ok = False
        errors.append(f"forward 체인을 읽지 못함: {e}")
    else:
        if not rule_ok:
            errors.append("forward 체인에 차단 규칙이 없다")

    banned = None
    if cfg["mode"] == "fail2ban":
        try:
            banned = f2b.banned()
        except F2bError as e:
            errors.append(f"fail2ban 응답 없음: {e}")
        if banned is not None:
            unban = sorted(banned - set(want))
            # 오래된 목록이면 새로 걸지도(fail2ban 이 bantime 을 새로 센다) 다시 걸지도 않는다
            ban = [] if stale else sorted(set(want) - banned)
            refresh = [] if stale else sorted(ip for ip in set(want) & banned & set(actual)
                                              if needs_refresh(actual[ip], remaining(want[ip], now)))
            plan.append(f"fail2ban unbanip {len(unban)} · banip {len(ban)} · 다시 걸기 {len(refresh)}")
            if dry_run:
                # 계획: fail2ban 이 걸고 푼 뒤의 모습으로 대조한다
                banned = (banned - set(unban)) | set(ban)
                actual = {ip: el for ip, el in actual.items() if ip not in unban}
                actual.update({ip: {"timeout": BANTIME, "expires": BANTIME} for ip in ban})
            elif unban or ban or refresh:
                try:
                    if unban or refresh:
                        f2b.unban(unban + refresh)
                    if ban or refresh:
                        f2b.ban(ban + refresh)
                except F2bError as e:
                    errors.append(f"fail2ban 반영 실패: {e}")
                # 바꾼 뒤의 모습을 다시 읽는다 (바꾼 것이 없으면 앞에서 읽은 그대로다)
                try:
                    banned = f2b.banned()
                except F2bError as e:
                    errors.append(f"fail2ban 응답 없음: {e}")
                    banned = None
                try:
                    actual = nft.list_set()
                except NftError as e:
                    errors.append(f"nft 집합을 읽지 못함: {e}")
                    st["set_count"] = None
                    return st, plan

    ops, reasons = plan_nft(cfg["mode"], want, actual, banned, now, grow=not stale)
    plan.append("nft " + " · ".join(f"{k} {sum(1 for o in ops if o[0] == k)}" for k in ("add", "replace", "del")))
    restored = sum(1 for o in ops if o[0] == "add") if cfg["mode"] == "fail2ban" else 0
    if restored and not dry_run:
        # fail2ban 은 걸었다고 아는데 집합에 없다. nft -f(flush ruleset) 뒤이거나 actionban 이 실패한 것이다
        errors.append(f"집합에서 빠진 원소 {restored}개를 nft 로 되살림")
    if dry_run:
        st["rejected"] = (rejected + [{"ip": ip, "why": w} for ip, w in reasons.items()])[:MAX_REJECTED]
        st["applied"] = len(want) - len(reasons)
        return st, plan

    failed = nft.apply(ops)
    try:
        final = nft.list_set()
    except NftError as e:
        errors.append(f"nft 집합을 읽지 못함: {e}")
        st["set_count"] = None
        return st, plan
    # 끝 상태로 판정한다. 목록 밖 원소를 빼다 실패했는데 집합에 없으면(읽은 뒤 만료로 빠졌다) 실패가 아니다
    failed = [(ip, why) for ip, why in failed if ip in want or ip in final]
    if failed:
        errors.append(f"nft 반영 실패 {len(failed)}건: {failed[0][1]}")
        for ip, _ in failed:
            reasons.setdefault(ip, "nft 반영 실패")

    st["at"] = iso(now if fixed else utcnow())      # 대조를 마친 시각
    st["set_count"] = len(final)
    missing = [ip for ip in want if ip not in final]
    rejected.extend({"ip": ip, "why": reasons.get(ip, "집합에 없음")} for ip in missing)
    extra = set(final) - set(want)
    if extra:
        errors.append(f"목록 밖 원소 {len(extra)}개가 집합에 남음")
    if len(rejected) > MAX_REJECTED:
        errors.append(f"rejected {len(rejected)}건 중 {MAX_REJECTED}건만 싣는다")
    st["rejected"] = rejected[:MAX_REJECTED]
    st["applied"] = len(want) - len(missing)
    if rule_ok and not stale:
        st["list_digest"] = doc["digest"]
        st["list_generated_at"] = doc["generated_at"]
    return st, plan


# ── 자가 시험 ──────────────────────────────────────────────────

def selftest(mode, nft, f2b):
    """"ok" 또는 "fail:<사유>". 시험 주소를 남기지 않는다."""
    ip = SELFTEST_IP
    try:
        if not nft.has_drop_rule():
            return "fail:forward 체인에 차단 규칙이 없다"
        if ip in nft.list_set():
            nft.apply([("del", ip)])                 # 지난 시험이 남긴 것
        # nft 경로. 두 모드 모두 되살림에 쓴다
        if nft.apply([("add", ip, SELFTEST_TIMEOUT)]):
            return "fail:nft 원소를 넣지 못함"
        el = nft.list_set().get(ip)
        if el is None or el["expires"] is None or not 0 < el["expires"] <= SELFTEST_TIMEOUT:
            return "fail:nft 원소가 60초 timeout 으로 보이지 않는다"
        if nft.apply([("del", ip)]) or ip in nft.list_set():
            return "fail:nft 원소를 빼지 못함"
        if mode == "nft":
            return "ok"
        # fail2ban 경로: banip → actionban(nft add element … timeout <bantime>s) → unbanip → actionunban
        f2b.ping()
        f2b.unban([ip])
        f2b.ban([ip])
        el = nft.list_set().get(ip)
        if el is None:
            return "fail:fail2ban banip 뒤 집합에 없다"
        if el["timeout"] != BANTIME:
            return f"fail:fail2ban 원소 timeout {el['timeout']} (기대 {BANTIME})"
        if ip not in f2b.banned():
            return "fail:fail2ban banned 에 없다"
        f2b.unban([ip])
        if ip in nft.list_set():
            return "fail:fail2ban unbanip 뒤 집합에 남았다"
        if ip in f2b.banned():
            return "fail:fail2ban unbanip 뒤 banned 에 남았다"
        return "ok"
    except (NftError, F2bError) as e:
        return f"fail:{str(e)[:200]}"
    finally:
        if mode == "fail2ban":
            try:
                f2b.unban([ip])
            except F2bError:
                pass
        try:
            if ip in nft.list_set():
                nft.apply([("del", ip)])
        except NftError:
            pass


# ── 실행 ───────────────────────────────────────────────────────

def config(env):
    mode = env.get("MODE", "fail2ban").strip()
    bucket = env.get("OPSLOOP_BUCKET", "").strip()
    host = env.get("OPSLOOP_HOST", "").strip()
    if mode not in ("fail2ban", "nft"):
        raise SystemExit(f"MODE 는 fail2ban 또는 nft 다: {mode!r}")
    if not bucket or not HOST_RE.fullmatch(host):
        raise SystemExit("OPSLOOP_BUCKET 과 OPSLOOP_HOST(관문 인스턴스 ID)가 필요하다")
    return {"mode": mode, "bucket": bucket, "host": host,
            "state": env.get("OPSLOOP_BLOCK_STATE", DEFAULT_STATE)}


def status_key(host):
    return f"hb/v1/host={host}-block/latest.json"


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def last_selftest(state, mode):
    """지난 자가 시험 결과. 모드가 바뀌었으면 null."""
    try:
        with open(os.path.join(state, "selftest.json"), encoding="utf-8") as f:
            d = json.load(f)
        return d["result"] if d.get("mode") == mode else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def lock(state, wait=50):
    fd = os.open(os.path.join(state, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() > deadline:
                os.close(fd)
                raise SystemExit("다른 회차가 아직 돌고 있다") from None
            time.sleep(1)


def main(argv=None, env=None, s3=None, nft=None, f2b=None):
    ap = argparse.ArgumentParser(description="OpsLoop 관문 차단 목록 동기화 (S3 목록 → nft 집합)")
    ap.add_argument("--selftest", action="store_true", help="문서용 주소로 반영 경로를 시험한 뒤 한 회차 돈다")
    ap.add_argument("--dry-run", action="store_true", help="읽고 계획만 찍는다. 아무것도 바꾸거나 올리지 않는다")
    args = ap.parse_args(argv)
    cfg = config(os.environ if env is None else env)
    os.makedirs(cfg["state"], mode=0o700, exist_ok=True)
    lock_fd = lock(cfg["state"])
    nft, f2b = nft or Nft(), f2b or Fail2ban()
    try:
        if args.selftest and not args.dry_run:
            result = selftest(cfg["mode"], nft, f2b)
            write_json(os.path.join(cfg["state"], "selftest.json"),
                       {"mode": cfg["mode"], "result": result, "at": iso(utcnow())})
            print(f"자가 시험 ({cfg['mode']}): {result}", flush=True)
        if s3 is None:
            import boto3
            from botocore.config import Config
            s3 = boto3.client("s3", config=Config(connect_timeout=10, read_timeout=20,
                                                  retries={"max_attempts": 3}))
        st, plan = sync(cfg, s3, nft, f2b, selftest=last_selftest(cfg["state"], cfg["mode"]),
                        dry_run=args.dry_run)
        for line in plan:
            print(f"  {line}", flush=True)
        summary = (f"{cfg['mode']} · 목록 {'확인' if st['list_digest'] else '미확인'} · 반영 {st['applied']} · "
                   f"집합 {st['set_count']} · 거부 {len(st['rejected'])} · 오류 {len(st['errors'])}")
        if args.dry_run:
            print(f"[계획] {summary}", flush=True)
            for e in st["errors"] + [f"{r['ip']} {r['why']}" for r in st["rejected"]]:
                print(f"  - {e}", flush=True)
            return 0
        write_json(os.path.join(cfg["state"], "status.json"), st)
        try:
            s3.put_object(Bucket=cfg["bucket"], Key=status_key(cfg["host"]),
                          Body=json.dumps(st, ensure_ascii=False).encode("utf-8"),
                          ContentType="application/json")
        except Exception as e:
            print(f"상태를 올리지 못함 ({error_code(e)}): {summary}", file=sys.stderr, flush=True)
            return 1
        print(summary, flush=True)
        for e in st["errors"]:
            print(f"  - {e}", flush=True)
        return 2 if st["errors"] else 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
