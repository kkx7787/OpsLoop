#!/usr/bin/env python3
"""
OpsLoop - 관제 대상 에이전트 로그 파서 (WBS 3.4.2 / 이슈 #11)

Alloy 가 Loki 로 보낸 원문 줄(nginx · auth · metrics)과 수집 관문 원장 줄을
events · node_metrics 행으로 바꾼다. 순수 함수만 두고 DB 는 부르지 않는다.
적재 · 워터마크 · 수신 기록은 다리(collector/pull_loki.py)가 한다. web-02(S3 경로)도 같이 쓴다.

믿는 것과 믿지 않는 것
  - 노드 이름(sensor)은 관문이 토큰으로 증명한 테넌트에서 온다. 줄 안의 값은 믿지 않는다.
  - 줄 속 호스트명이 nodes.hostname 과 다르면 적재하지 않는다(foreign_host).
    기본 VM 시절의 auth.log 줄과 호스트 위장이 여기서 걸러진다.
  - 장악된 노드는 아무 줄이나 보낼 수 있다. 어떤 줄이 와도 예외로 죽지 않고, 적재를 실패시킬 값
    (NUL · 짝 없는 서로게이트 · 범위 밖 정수 · 주소가 아닌 IP)은 비우거나 고친다.

결과
  parse(node_id, hostname, job, line, exclusions)  ("event", 행) · ("metric", 행) · ("skip", 사유)
  parse_collector(line)                            ("event", 행) · ("skip", "malformed")
  행은 dict 이고 키는 EVENT_COLUMNS · METRIC_COLUMNS 와 같다. 적재할 때 열 순서도 이 튜플을 따른다.

건너뜀 사유
  malformed     형식이 설계와 다르다 (JSON 아님 · 시각 없음 · 지표 숫자가 틀림 · 4MiB 넘는 줄)
  foreign_host  줄 속 호스트명이 이 노드가 아니다
  unmatched     auth 에서 보지 않는 줄 (pam_unix · sudo · 접속 종료 등). 원문은 Loki 에 남는다
  repeated      rsyslog 반복 축약 줄. 몇 번이었는지 알 수 없어, 과소 집계를 드러내기만 한다
  undeclared    알 수 없는 job

line_hash 는 sha1(앞뒤 공백을 뗀 원문 줄의 UTF-8) 16진수다. 기존 파서와 같은 규칙이다.
Loki 시각은 넣지 않으므로 Alloy 가 같은 줄을 다시 보내도 한 번만 들어간다.

사용 (손으로 확인할 때. 적재하지 않는다)
  python3 parser/parse_agent.py --job auth --node web-01 --host opsloop-web-01 < auth.log
  python3 parser/parse_agent.py --collector -v < /var/lib/opsloop/gate/collector-2026-09-21.jsonl
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

EVENT_COLUMNS = ("line_hash", "ts", "eventid", "session", "src_ip", "src_port", "dst_port",
                 "protocol", "username", "password", "input", "url", "shasum", "duration_ms",
                 "provenance", "message", "http_method", "http_status", "user_agent", "sensor")
METRIC_COLUMNS = ("line_hash", "node_id", "ts", "seq", "cpu_pct", "mem_used_pct", "mem_avail_mb",
                  "swap_used_pct", "disk_root_pct", "load1", "nginx_active", "sshd_active")
JOBS = ("nginx", "auth", "metrics")
SKIP_REASONS = ("malformed", "foreign_host", "unmatched", "repeated", "undeclared")

DEFAULT_EXCLUSIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exclusions.txt")
INT4 = (-2**31, 2**31 - 1)
INT8_MAX = 2**63 - 1
MAX_LINE = 4 * 1024 * 1024     # 이보다 긴 줄은 파싱하지 않는다 (메모리 보호. 정상 로그 한 줄은 수 KB 다)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# fullmatch 로만 쓴다 ($ 는 끝 줄바꿈을 허용한다). 숫자는 [0-9] 로 쓴다 (\d 는 아랍-인도 숫자 등도 받는다)
TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?"
                   r"(Z|[+-][0-9]{2}:[0-9]{2})?")
MSEC_RE = re.compile(r"([0-9]{1,11})(?:\.([0-9]{1,6}))?")          # nginx $msec  "1789977271.123"
SECONDS_RE = re.compile(r"([0-9]{1,9})(?:\.([0-9]{1,3}))?")        # nginx $request_time  "0.004"

# auth.log (Ubuntu 24.04 rsyslog 기본): "<RFC3339 µs> <호스트> <태그>: <본문>"
# 머리는 시각 · 호스트까지만 본다. sudo · CRON · (systemd) 줄도 같은 파일에 있으므로
# 태그가 sshd 가 아닌 줄은 형식 오류가 아니라 unmatched 다.
AUTH_HEAD_RE = re.compile(r"(\S+) (\S+) (.*)")
SSHD_RE = re.compile(r"(sshd|sshd-session|sshd-auth)\[([0-9]{1,10})\]: ?(.*)")
REPEATED_RE = re.compile(r"message repeated [0-9]+ times: \[")
# 잘못된 사용자의 실패는 "Invalid user" 줄로 이미 센다. 같이 세면 한 접속이 두 번 잡힌다
FAILED_INVALID = "Failed password for invalid user "
# 사용자 이름은 공격자가 정한다("x from 6.6.6.6 port 1" 도 된다). sshd 가 끝에 붙인
# 출발지를 잡도록 이름은 탐욕적으로 먹고 뒤를 고정한다. 받아들여진 로그인의 이름은 실제 계정이라 공백이 없다
AUTH_RULES = (
    ("sshd.login.failed", re.compile(r"Failed password for (.*) from (\S+) port ([0-9]+)(?: ssh2)?")),
    ("sshd.login.invalid_user", re.compile(r"Invalid user (.*) from (\S+) port ([0-9]+)")),
    ("sshd.login.success", re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port ([0-9]+)(?: ssh2)?(?:: .*)?")),
)

# 관리 원장 줄에서 events.input 으로 옮길 키. 모르는 키는 옮기지 않는다 (비밀값이 잘못 섞여도 퍼지지 않게)
ADMIN_KEYS = ("node_id", "host", "addr", "logs", "status", "expires_at")


def load_exclusions(path):
    ips = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    ips.add(line)
    return ips


def line_hash(line):
    # 짝 없는 서로게이트가 섞여 와도 죽지 않고 다른 줄과 겹치지도 않게 surrogatepass 로 바꾼다.
    # 정상 문자열에서는 기존 파서의 encode("utf-8") 와 같은 바이트다
    return hashlib.sha1(line.encode("utf-8", "surrogatepass")).hexdigest()


def to_int(v):
    """정수 열(integer)에 들어갈 값. 범위를 벗어나거나 무한대면 비운다."""
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return n if INT4[0] <= n <= INT4[1] else None


def clip(v, n=None):
    """DB 에 넣을 글자 값. parse_decoy.clip 과 같은 규칙이다.

    - NUL(\\x00) 은 PostgreSQL 글자 열에 들어가지 못해 적재 전체가 실패한다. 지운다.
    - 문자열이 아닌 값(목록 · 객체)은 JSON 글자로 바꾼다.
    - 짝 없는 서로게이트("\\ud800")는 UTF-8 로 바꿀 수 없다. 대체 문자로 바꾼다.
    - 색인 한도 · 화면을 위해 n 글자에서 자른다.
    """
    if v is None:
        return None
    if not isinstance(v, str):
        v = json.dumps(v, ensure_ascii=False)
    v = v.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    return v if n is None or len(v) <= n else v[:n]


def ip_or_none(v):
    """inet 열에 들어갈 값. 주소가 아니면 비운다 (그대로 넘기면 적재 전체가 실패한다)."""
    if not isinstance(v, str):
        return None
    if "%" in v:                     # IPv6 영역 ID(fe80::1%eth0)는 inet 열이 받지 않는다
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None
    return v


def utc_ts(raw, naive_utc=False):
    """RFC3339 시각 → UTC. 시간대가 없으면 비운다 (naive_utc 면 UTC 로 본다).

    fromisoformat 은 파이썬 판마다 받는 소수 자릿수가 달라 직접 푼다.
    """
    m = TS_RE.fullmatch(raw) if isinstance(raw, str) else None
    if not m:
        return None
    *parts, frac, off = m.groups()
    if off is None and not naive_utc:
        return None
    try:
        tz = timezone.utc
        if off not in (None, "Z"):
            delta = timedelta(hours=int(off[1:3]), minutes=int(off[4:6]))
            tz = timezone(-delta if off[0] == "-" else delta)       # 24시간 이상이면 ValueError
        t = datetime(*map(int, parts), int((frac or "0").ljust(6, "0")), tzinfo=tz)
        return t.astimezone(timezone.utc)
    except (ValueError, OverflowError):      # 13월 · 60초 · 0001년에서 음의 시간대 등
        return None


def msec_ts(raw):
    """nginx $msec("초.밀리초") → UTC. float 를 거치지 않아 마이크로초가 흔들리지 않는다."""
    m = MSEC_RE.fullmatch(raw) if isinstance(raw, str) else None
    if not m:
        return None
    return EPOCH + timedelta(seconds=int(m[1]), microseconds=int((m[2] or "0").ljust(6, "0")))


def seconds_ms(raw):
    """nginx $request_time("0.004" 초) → 밀리초 정수."""
    m = SECONDS_RE.fullmatch(raw) if isinstance(raw, str) else None
    if not m:
        return None
    return to_int(int(m[1]) * 1000 + int((m[2] or "0").ljust(3, "0")))


def json_obj(line):
    try:
        v = json.loads(line)
    except (ValueError, RecursionError):     # JSONDecodeError 와 4300자리 넘는 정수 포함
        return None
    return v if isinstance(v, dict) else None


def event(**kw):
    row = dict.fromkeys(EVENT_COLUMNS)
    row.update(kw)
    return row


def skip(reason):
    return "skip", reason


# ----------------------------------------------------------------------
#  job 별 변환
# ----------------------------------------------------------------------

def parse_nginx(node_id, hostname, line, exclusions):
    ev = json_obj(line)
    if ev is None or "host" not in ev:
        return skip("malformed")
    if ev["host"] != hostname:
        return skip("foreign_host")
    ts = msec_ts(ev.get("ts"))
    if ts is None:
        return skip("malformed")
    src_ip = ip_or_none(ev.get("src_ip"))
    return "event", event(
        line_hash=line_hash(line), ts=ts, eventid="nginx.request",
        src_ip=src_ip, src_port=to_int(ev.get("src_port")), dst_port=to_int(ev.get("dst_port")),
        protocol="http", url=clip(ev.get("uri"), 2048), duration_ms=seconds_ms(ev.get("rt")),
        provenance="fixture" if src_ip in exclusions else "real",
        http_method=clip(ev.get("method"), 16), http_status=to_int(ev.get("status")),
        user_agent=clip(ev.get("ua"), 512), sensor=node_id)


def parse_auth(node_id, hostname, line, exclusions):
    head = AUTH_HEAD_RE.fullmatch(line)
    ts = utc_ts(head[1]) if head else None
    if ts is None:                           # 전통 형식("Sep 21 ...")이나 시간대 없는 시각
        return skip("malformed")
    if head[2] != hostname:
        return skip("foreign_host")
    tag = SSHD_RE.fullmatch(head[3])
    if not tag:
        return skip("unmatched")
    pid, body = tag[2], tag[3]
    if REPEATED_RE.match(body):
        return skip("repeated")
    if body.startswith(FAILED_INVALID):
        return skip("unmatched")
    for eventid, rx in AUTH_RULES:
        m = rx.fullmatch(body)
        if m:
            break
    else:
        return skip("unmatched")
    user, ip, port = m.groups()
    src_ip = ip_or_none(ip)
    return "event", event(
        line_hash=line_hash(line), ts=ts, eventid=eventid, session=clip(f"{node_id}/sshd/{pid}", 128),
        src_ip=src_ip, src_port=to_int(port), dst_port=22, protocol="ssh",
        username=clip(user, 256), provenance="fixture" if src_ip in exclusions else "real",
        message=clip(body, 512), sensor=node_id)


def real(v, lo, hi):
    """지표 실수. 없으면 None. 숫자가 아니거나(참/거짓 · 글자 · NaN · 무한대) 범위 밖이면 ValueError."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(v)
    return float(v)


def whole(v, lo, hi):
    """지표 정수. 400.0 처럼 정수인 실수는 받는다."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(v)
    if isinstance(v, float) and not v.is_integer():
        raise ValueError(v)
    return int(v)


def flag(v):
    if v is None or isinstance(v, bool):
        return v
    raise ValueError(v)


def parse_metrics(node_id, hostname, line, exclusions):
    ev = json_obj(line)
    if ev is None or "host" not in ev:
        return skip("malformed")
    if ev["host"] != hostname:
        return skip("foreign_host")
    ts = utc_ts(ev.get("ts"))
    try:
        seq = whole(ev.get("seq"), 0, INT8_MAX)
        # real 열(float4)은 3.4e38 을 넘으면 적재 전체가 실패한다. 범위를 뜻이 있는 값으로 좁힌다
        row = {
            "line_hash": line_hash(line), "node_id": node_id, "ts": ts, "seq": seq,
            "cpu_pct": real(ev.get("cpu_pct"), 0, 100),
            "mem_used_pct": real(ev.get("mem_used_pct"), 0, 100),
            "mem_avail_mb": whole(ev.get("mem_avail_mb"), 0, INT4[1]),
            "swap_used_pct": real(ev.get("swap_used_pct"), 0, 100),
            "disk_root_pct": real(ev.get("disk_root_pct"), 0, 100),
            "load1": real(ev.get("load1"), 0, 1e6),
            "nginx_active": flag(ev.get("nginx_active")),
            "sshd_active": flag(ev.get("sshd_active")),
        }
    except ValueError:
        return skip("malformed")
    if ts is None or seq is None:            # seq 는 공백(seq_gaps) 판정에 쓰므로 반드시 있어야 한다
        return skip("malformed")
    return "metric", row


PARSERS = {"nginx": parse_nginx, "auth": parse_auth, "metrics": parse_metrics}


def parse(node_id, hostname, job, line, exclusions):
    """Loki 한 줄 → ("event", 행) · ("metric", 행) · ("skip", 사유). job 은 스트림 라벨이다."""
    fn = PARSERS.get(job) if isinstance(job, str) else None
    if fn is None:
        return skip("undeclared")
    if not isinstance(line, str):
        return skip("malformed")
    line = line.strip()
    if not line or len(line) > MAX_LINE:
        return skip("malformed")
    return fn(node_id, hostname, line, exclusions)


# ----------------------------------------------------------------------
#  수집 관문 원장 · 관리 원장
# ----------------------------------------------------------------------

def text_value(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v)


def parse_collector(line):
    """관문 원장(collector-*.jsonl) · 관리 원장(admin-*.jsonl) 한 줄 → ("event", 행) · ("skip", "malformed").

    원장은 이 노드가 직접 쓰므로 시각에 시간대가 없으면 UTC 로 본다.
    거부 · 등록 · 제한 줄:  username=node_id(알면), input="reason=… count=… fps=…"
    관리 줄(collector.admin.*): username=issued_by, input="node_id=… expires_at=…"
    """
    if not isinstance(line, str):
        return skip("malformed")
    line = line.strip()
    if not line or len(line) > MAX_LINE:
        return skip("malformed")
    ev = json_obj(line)
    if ev is None:
        return skip("malformed")
    eventid = ev.get("eventid")
    ts = utc_ts(ev.get("ts"), naive_utc=True)
    if not isinstance(eventid, str) or not eventid.startswith("collector.") or ts is None:
        return skip("malformed")
    if eventid.startswith("collector.admin."):
        username = ev.get("issued_by")
        inp = " ".join(f"{k}={text_value(ev[k])}" for k in ADMIN_KEYS if k in ev) or None
    else:
        username = ev.get("node_id")
        fps = ev.get("fps")
        fps = ",".join(str(x) for x in fps) if isinstance(fps, list) else text_value(fps)
        inp = f"reason={text_value(ev.get('reason'))} count={text_value(ev.get('count'))} fps={fps}"
    return "event", event(
        line_hash=line_hash(line), ts=ts, eventid=clip(eventid, 64),
        src_ip=ip_or_none(ev.get("src_ip")), dst_port=to_int(ev.get("dst_port")),
        username=clip(username, 256), input=clip(inp, 4096), url=clip(ev.get("path"), 2048),
        provenance="real", user_agent=clip(ev.get("ua"), 512), sensor="collector")


def main():
    ap = argparse.ArgumentParser(description="관제 대상 에이전트 로그 파서 (표준 입력을 읽어 결과만 센다. 적재하지 않음)")
    ap.add_argument("--job", choices=JOBS)
    ap.add_argument("--node", help="노드 ID (예: web-01)")
    ap.add_argument("--host", help="nodes.hostname (예: opsloop-web-01)")
    ap.add_argument("--collector", action="store_true", help="관문 · 관리 원장 줄로 읽는다")
    ap.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS)
    ap.add_argument("-v", "--verbose", action="store_true", help="줄마다 결과를 JSON 으로 찍는다")
    args = ap.parse_args()
    if not args.collector and not (args.job and args.node and args.host):
        ap.error("--collector 나 --job · --node · --host 가 필요합니다")

    exclusions = load_exclusions(args.exclusions)
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    tally = Counter()
    for raw in sys.stdin:
        if not raw.strip():
            continue
        if args.collector:
            kind, v = parse_collector(raw)
        else:
            kind, v = parse(args.node, args.host, args.job, raw, exclusions)
        tally[f"skip:{v}" if kind == "skip" else kind] += 1
        if args.verbose:
            print(json.dumps({"kind": kind, "value": v}, ensure_ascii=False, default=str))
    for k, n in sorted(tally.items()):
        print(f"  {n:>7,}  {k}", file=sys.stderr if args.verbose else sys.stdout)


if __name__ == "__main__":
    main()
