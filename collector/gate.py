#!/usr/bin/env python3
"""수집 관문 opsloop-gate (WBS 3.4.2 ~ 3.4.4, 이슈 #11).

Loki 에는 인증 계층이 없다. 그래서 Loki 는 127.0.0.1:3100 에만 붙이고, 관제 대상 에이전트(Alloy)는
이 관문(192.168.60.11:3101)으로만 보낸다. 관문은 본문을 읽기 전에 헤더만 보고 판정하고,
통과한 본문은 바이트 그대로 Loki 에 넘긴다.

push  POST /loki/api/v1/push  (Bearer 에이전트 키)
  1. 경로 · 메서드가 push 나 enroll 이 아니면 404 (사유 path)
  2. 노드 캐시가 60초보다 오래됐으면 503. 거부로 세지 않는다 (Alloy 가 다시 보낸다)
  3. Authorization 이 없으면 401 missing
  4. 키 해시가 캐시에 없으면 401 unknown (등록 토큰을 push 에 쓴 경우 포함), 폐기면 revoked, active 가 아니면 inactive
  5. 출발지가 nodes.addr 와 다르면 401 addr_mismatch
  6. 길이 없음 411 · 4MiB 초과 413 · 노드별 하루(UTC) 200MiB 초과 429. 등록 노드 자신의 문제라 R202 가 아니다
  7. X-Scope-OrgID 를 토큰이 증명한 node_id 로 덮어써(에이전트가 보낸 값은 버린다) Loki 에 넘기고,
     Loki 의 응답 코드를 그대로 돌려준다. Loki 에 닿지 않으면 503
  1 ~ 6 에서 답할 때는 본문을 읽지 않고 연결을 닫는다. 표식 문자열이 든 본문도 Loki 에 닿지 않는다.
  Expect: 100-continue 는 본문을 받기로 정한 뒤에만 답한다.

enroll  POST /opsloop/v1/enroll  (Bearer 등록 토큰, {"node_id", "agent_sha256"} 4KiB 이하)
  enroll_node(토큰 해시, node_id, 키 해시, 출발지) 한 번만 부른다. 'ok' 면 노드 캐시를 다시 읽은 뒤 200 을 준다
  (그래서 등록 직후 첫 push 가 401 을 받는 경합이 없다). 캐시를 못 읽으면 503 을 준다.
  같은 키로 다시 부르면 DB 가 'ok' 를 돌려주므로(응답 유실 재시도) 등록 도구는 그냥 다시 부르면 된다.
  그 밖의 결과는 401 {"result": 사유}, bad_key · 본문 형식 오류(enroll_body)는 400.

노드 캐시
  SELECT node_id, token_hash, status, host(addr) FROM nodes WHERE token_hash IS NOT NULL
  15초마다, SIGHUP 을 받으면 곧바로(0.5초 안) 다시 읽는다. nodes.py 가 발급 · 폐기 뒤 HUP 을 보낸다.
  관문 역할(opsloop_gate)은 nodes 네 열 읽기와 enroll_node 실행만 할 수 있다.

관문 원장  $GATE_DIR/collector-YYYY-MM-DD.jsonl (UTC 날짜, 추가만, 0640)
  거부 collector.agent.rejected · 등록 collector.agent.enrolled · 제한 collector.agent.throttled.
  거부 · 제한은 (출발지, 사유) 60초 창으로 묶는다. 창의 첫 건은 바로 쓰고, 나머지는 창이 끝날 때 한 줄로 합친다.
  임의 키를 쏟아부어도 줄 수는 분당 2 × 사유 수를 넘지 않는다.
  토큰 원문은 어디에도(원장 · 로그) 쓰지 않는다. sha256 앞 8자(지문)만 쓴다.
  다리(pull_loki.py)가 이 줄을 events 에 넣고, R202 가 인시던트로 올린다.

느린 · 악의적 클라이언트 (MemoryMax 64M 안에서 버티기 위해서)
  헤더 한 줄 8KiB · 64줄 (넘으면 431), 요청 줄과 헤더는 10초 안에 다 와야 한다(연결을 끊는다).
  소켓 시간 초과 30초, 본문은 120초 안에 다 와야 한다. 동시 연결 64개 · 출발지별 8개(넘으면 끊고 거부로 남긴다),
  동시에 받는 본문 합계 16MiB(넘으면 429 busy. Alloy 는 429 를 다시 보낸다).
  등록은 인증 전에 DB 로 가므로 더 좁힌다: 토큰 형식을 먼저 보고, 출발지별 분당 10회, 동시에 DB 로 가는 요청 2개.
  인증 전 단계의 거부(헤더 초과 · 기한 초과 · 연결 한도 · 등록의 길이 문제 · 등록 속도)는 모두 거부(R202)로 남긴다.
  하루 용량은 $GATE_DIR/usage.json 에 남겨 재시작해도 이어진다.

신호
  SIGHUP   노드 캐시를 곧바로 다시 읽는다
  SIGTERM  받기를 멈추고, 묶어 둔 원장 줄을 모두 쓴 뒤 끝낸다

환경변수
  DATABASE_URL  관문 역할 접속 (/etc/opsloop/gate.env)
  GATE_BIND     듣는 주소 (기본 192.168.60.11:3101)
  LOKI_URL      Loki (기본 http://127.0.0.1:3100)
  GATE_DIR      관문 원장 폴더 (기본 /var/lib/opsloop/gate)
"""
import argparse
import collections
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import tempfile
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUSH = "/loki/api/v1/push"
ENROLL = "/opsloop/v1/enroll"
REJECTED = "collector.agent.rejected"
ENROLLED = "collector.agent.enrolled"
THROTTLED = "collector.agent.throttled"
# enroll_node 가 돌려주는 거부 사유. 이 밖의 값은 DB 쪽 오류로 보고 503 을 준다
ENROLL_REJECT = {"enroll_unknown", "enroll_canceled", "enroll_node", "enroll_expired",
                 "addr_mismatch", "enroll_used", "bad_key"}
BAD_REQUEST = {"bad_key", "enroll_body"}      # 400 으로 답하는 사유

MAX_PUSH = 4 * 1024 * 1024
MAX_ENROLL = 4 * 1024
DAILY_QUOTA = 200 * 1024 * 1024   # 노드별 하루(UTC). Loki 에 들어간(2xx) 바이트만 센다. 재시작하면 0 부터 다시 센다
INFLIGHT_MAX = 16 * 1024 * 1024   # 동시에 메모리에 올리는 본문 합계
CACHE_EVERY, CACHE_STALE = 15, 60
WINDOW = 60
SOCK_TIMEOUT = 30
BODY_DEADLINE = 120
LOKI_TIMEOUT = 30
MAX_CONN = 64
PER_SRC_CONN = 8                  # 출발지별 동시 연결
HEADER_DEADLINE = 10              # 요청 줄 + 헤더를 다 받는 기한 (초). 요청마다 다시 잰다
ENROLL_DB = 2                     # 동시에 DB 로 가는 등록 요청. 역할 접속 한도(10) 안에서 캐시 갱신 몫을 남긴다
ENROLL_RATE = 10                  # 출발지별 분당 등록 요청
USAGE_FILE = "usage.json"
USAGE_SAVE_EVERY = 10
# 표준 라이브러리 기본값은 헤더 한 줄 64KiB × 100줄이다. 연결 하나가 인증 전에 6MB 넘게 쌓을 수 있다
http.client._MAXLINE = 8192
http.client._MAXHEADERS = 64
PRE_AUTH_ERRORS = {400: "bad_request", 414: "uri_too_long", 431: "header_too_large", 505: "bad_version"}
MAX_GROUPS = 256                  # 동시에 묶는 (출발지, 사유) 수. 넘으면 묶지 않고 바로 쓴다
MAX_FPS = 1024                    # 한 묶음에서 서로 다른 지문을 세는 상한 (distinct_fp 는 이 값에서 멈춘다)
MAX_REPLY = 64 * 1024
CHUNK = 64 * 1024
STATS_EVERY = 600

TOKENS_SQL = "SELECT node_id, token_hash, status, host(addr) FROM nodes WHERE token_hash IS NOT NULL"
ENROLL_SQL = "SELECT enroll_node(%s, %s, %s, %s::inet)"

# fullmatch 로만 쓴다. 숫자는 [0-9] 로 쓴다 (\d · isdigit 은 다른 문자 체계의 숫자도 받는다)
HEX64 = re.compile(r"[0-9a-f]{64}")
NODE_ID = re.compile(r"[\x21-\x7e]{1,128}")
ENROLL_TOKEN = re.compile(r"olE_[A-Za-z0-9_-]{43}")   # nodes.py issue 가 만드는 형식 (olE_ + token_urlsafe(32))
LENGTH = re.compile(r"[0-9]{1,15}")
HVAL = re.compile(r"[\x21-\x7e][\x20-\x7e]{0,255}")

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_UNSAFE = re.compile(r"[^\x20-\x7e]")


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


def safe(v, n=300):
    """에이전트가 정한 값(경로 · User-Agent · 오류 문구)을 원장 · 로그에 쓸 때.

    인쇄 가능한 ASCII 밖(제어 문자 · 줄바꿈 · \\x85 등)은 \\xNN 으로 바꾼다. 가짜 줄을 만들지 못하게 한다.
    """
    def esc(m):
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"
    return _UNSAFE.sub(esc, str(v))[:n]


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def utc_now():
    return datetime.now(timezone.utc)


def bearer(value):
    """Authorization 값 → 토큰. 없거나 비었으면 None. Bearer 가 아닌 형식은 값 전체를 토큰으로 본다(unknown 이 된다)."""
    if value is None or not value.strip():
        return None
    parts = value.strip().split(None, 1)
    if parts[0].lower() == "bearer":
        return parts[1].strip() if len(parts) == 2 and parts[1].strip() else None
    return value.strip()


def content_length(headers):
    """Content-Length 가 정확히 하나이고 10진수일 때만 값을 준다. 청크 전송은 받지 않는다."""
    if headers.get("Transfer-Encoding") is not None:
        return None
    vals = headers.get_all("Content-Length") or []
    if len(vals) != 1 or not LENGTH.fullmatch(vals[0].strip()):
        return None
    return int(vals[0].strip())


def norm_ip(v):
    try:
        ip = ipaddress.ip_address(v)
    except (TypeError, ValueError):
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def hval(v):
    """Loki 로 넘길 헤더 값. 인쇄 가능한 ASCII 가 아니면 넘기지 않는다."""
    return v if v is not None and HVAL.fullmatch(v) else None


def parse_enroll(body):
    """등록 본문 → (node_id, agent_sha256) 또는 거부 사유(enroll_body · bad_key)."""
    try:
        req = json.loads(bytes(body).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "enroll_body"
    if not isinstance(req, dict):
        return "enroll_body"
    node_id, agent = req.get("node_id"), req.get("agent_sha256")
    if not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id) or not isinstance(agent, str):
        return "enroll_body"
    if not HEX64.fullmatch(agent):
        return "bad_key"
    return node_id, agent


class Terminated(Exception):
    pass


class Store:
    """DB 접근. psycopg2 는 여기서만 쓴다. 호출마다 짧게 접속한다 (15초에 한 번 · 등록 때뿐이다)."""

    def __init__(self, url):
        self.url = url

    def _connect(self):
        import psycopg2
        return psycopg2.connect(self.url, connect_timeout=5, application_name="opsloop-gate",
                                options="-c statement_timeout=5000")

    def load_tokens(self):
        """[(node_id, token_hash, status, addr 글자 또는 None), ...]"""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(TOKENS_SQL)
                return cur.fetchall()
        finally:
            conn.close()

    def enroll(self, token_hash, node_id, agent_sha256, src):
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(ENROLL_SQL, (token_hash, node_id, agent_sha256, src))
                (result,) = cur.fetchone()
            conn.commit()
            return result
        finally:
            conn.close()


class Ledger:
    """관문 원장. 거부 · 제한 줄은 (종류, 출발지, 사유) 60초 창으로 묶는다."""

    def __init__(self, gate_dir, port, clock=time.monotonic, window=WINDOW):
        self.dir, self.port, self.clock, self.window = gate_dir, port, clock, window
        self.boot = secrets.token_hex(3)
        self.seq = 0
        self.groups = {}
        self.lock = threading.Lock()

    def record(self, eventid, src, path, reason, fp=None, ua="", node_id=None, group=True):
        base = {"eventid": eventid, "src_ip": src, "dst_port": self.port,
                "path": safe(path, 256), "reason": reason}
        ua = safe(ua or "", 256)
        key = (eventid, src, reason)
        with self.lock:
            now = self.clock()
            g = self.groups.get(key) if group else None
            if g is not None and now - g["start"] >= self.window:
                self._close(key, g)
                g = None
            if g is None:
                # 창의 첫 건은 바로 쓴다
                if group and len(self.groups) < MAX_GROUPS:
                    self.groups[key] = {"start": now, "n": 0, "fps": set(), "shown": [], "nodes": set()}
                self._write(base, 1, [fp] if fp else [], 1 if fp else 0, ua, node_id)
                return
            g.update(base=base, ua=ua, ts=utc_now())
            g["n"] += 1
            if fp and fp not in g["fps"] and len(g["fps"]) < MAX_FPS:
                g["fps"].add(fp)
                if len(g["shown"]) < 3:
                    g["shown"].append(fp)
            if node_id and node_id not in g["nodes"] and len(g["nodes"]) < 2:
                g["nodes"].add(node_id)

    def flush(self, force=False):
        """창이 끝난 묶음을 한 줄로 쓴다. force 면 모두 쓴다 (끝낼 때)."""
        with self.lock:
            now = self.clock()
            for key, g in list(self.groups.items()):
                if force or now - g["start"] >= self.window:
                    self._close(key, g)

    def _close(self, key, g):
        del self.groups[key]
        if g["n"]:
            node = next(iter(g["nodes"])) if len(g["nodes"]) == 1 else None
            self._write(g["base"], g["n"], g["shown"], len(g["fps"]), g["ua"], node, g["ts"])

    def _write(self, base, count, fps, distinct, ua, node_id, ts=None):
        now = utc_now()
        self.seq += 1
        rec = {"ts": (ts or now).isoformat(timespec="microseconds"), "boot": self.boot, "seq": self.seq, **base,
               "count": count, "distinct_fp": distinct, "fps": list(fps)[:3], "ua": ua}
        if node_id:
            rec["node_id"] = node_id
        data = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        path = os.path.join(self.dir, f"collector-{now:%Y-%m-%d}.jsonl")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o640)
            try:
                os.write(fd, data)       # 한 줄을 한 번에 쓴다 (O_APPEND). 다리는 줄바꿈으로 끝난 줄만 읽는다
            finally:
                os.close(fd)
        except OSError as e:
            log(f"관문 원장을 쓰지 못했다 {path}: {safe(e)}", 3)
            return
        if base["eventid"] != ENROLLED:
            kind = "거부" if base["eventid"] == REJECTED else "제한"
            log(f"{kind} {base['reason']} · {base['src_ip']} {base['path']} · {count}건 · "
                f"지문 {','.join(rec['fps']) or '-'}{' · ' + node_id if node_id else ''}", 4)


Node = collections.namedtuple("Node", "node_id status addr")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None                  # Loki 가 다른 곳으로 보내도 따라가지 않는다 (본문을 딴 곳에 넘기지 않는다)


class Gate:
    """노드 캐시 · 하루 용량 · Loki 전달. 요청 처리기와 관리 스레드가 함께 쓴다."""

    def __init__(self, store, loki_url, ledger, clock=time.monotonic, usage_path=None):
        self.store, self.ledger, self.clock = store, ledger, clock
        self.usage_path = usage_path
        self.loki = loki_url.rstrip("/") + PUSH
        # 환경의 http_proxy 를 타지 않는다
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        self.nodes = {}              # token_hash → Node. 통째로 바꿔 끼운다
        self.loaded_at = None
        self.hup = False             # 신호 처리기는 표시만 한다 (잠금을 잡지 않는다)
        self.stop = threading.Event()
        self._reload_lock = threading.Lock()
        self._lock = threading.Lock()
        self._last_try = clock()
        self._summary = None
        self._fresh = True
        self._stats_at = clock()
        self.usage = self._load_usage()   # node_id → (UTC 날짜, 넘긴 바이트)
        self._usage_dirty = False
        self._usage_saved = clock()
        self.inflight = 0
        self.stats = collections.Counter()
        self.enroll_slots = threading.BoundedSemaphore(ENROLL_DB)
        self._enroll_hits = {}           # 출발지 → 최근 60초 등록 요청 시각

    # --- 노드 캐시 ---
    def reload(self, why=""):
        """캐시를 DB 에서 다시 읽는다. 질의와 교체를 한 잠금 안에서 해 늦게 끝난 옛 질의가 새 결과를 덮지 않게 한다."""
        with self._reload_lock:
            self._last_try = self.clock()
            try:
                rows = self.store.load_tokens()
            except Exception as e:
                log(f"노드 캐시를 읽지 못했다{' (' + why + ')' if why else ''}: {type(e).__name__}: {safe(e)}", 4)
                return False
            nodes = {}
            for node_id, token_hash, status, addr in rows:
                if isinstance(token_hash, str) and token_hash:
                    nodes[token_hash] = Node(node_id, status, norm_ip(addr) if addr else None)
            self.nodes = nodes
            self.loaded_at = self.clock()
        c = collections.Counter(n.status for n in nodes.values())
        summary = tuple(sorted(c.items()))
        if why or summary != self._summary:
            others = sum(v for k, v in c.items() if k not in ("active", "revoked"))
            log(f"노드 캐시 {len(nodes)}개 (active {c['active']} · revoked {c['revoked']} · 그 밖 {others})"
                f"{' · ' + why if why else ''}")
        self._summary = summary
        return True

    def cache_fresh(self):
        return self.loaded_at is not None and self.clock() - self.loaded_at <= CACHE_STALE

    # --- 하루 용량 · 동시 본문 ---
    def quota_ok(self, node_id, n):
        day = utc_now().date()
        with self._lock:
            d, used = self.usage.get(node_id, (day, 0))
            return (used if d == day else 0) + n <= DAILY_QUOTA

    def charge(self, node_id, n):
        day = utc_now().date()
        with self._lock:
            d, used = self.usage.get(node_id, (day, 0))
            self.usage[node_id] = (day, (used if d == day else 0) + n)
            self._usage_dirty = True

    def _load_usage(self):
        """재시작해도 하루 용량이 이어지게 파일에서 읽는다. 오늘 것만 쓴다."""
        if not self.usage_path:
            return {}
        try:
            with open(self.usage_path, encoding="utf-8") as f:
                raw = json.load(f)
            today = utc_now().date()
            return {str(k): (today, int(v[1])) for k, v in raw.items()
                    if isinstance(v, list) and len(v) == 2 and v[0] == today.isoformat() and int(v[1]) >= 0}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, TypeError, AttributeError) as e:
            log(f"하루 용량 파일을 읽지 못했다. 0 부터 센다: {safe(e)}", 4)
            return {}

    def save_usage(self, force=False):
        if not self.usage_path:
            return
        now = self.clock()
        with self._lock:
            if not self._usage_dirty or (not force and now - self._usage_saved < USAGE_SAVE_EVERY):
                return
            data = {k: [d.isoformat(), used] for k, (d, used) in self.usage.items()}
            self._usage_dirty = False
            self._usage_saved = now
        d = os.path.dirname(self.usage_path) or "."
        try:
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".usage.")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.usage_path)
        except OSError as e:
            log(f"하루 용량 파일을 쓰지 못했다: {safe(e)}", 4)

    def enroll_rate_ok(self, src):
        """출발지별 분당 등록 요청 수. 인증 전에 DB 로 가는 길이라 좁힌다."""
        now = self.clock()
        with self._lock:
            q = self._enroll_hits.setdefault(src, collections.deque())
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= ENROLL_RATE:
                return False
            q.append(now)
            if len(self._enroll_hits) > 1024:
                for k in [k for k, v in self._enroll_hits.items() if not v or now - v[-1] > 60]:
                    del self._enroll_hits[k]
            return True

    def reserve(self, n):
        with self._lock:
            if self.inflight + n > INFLIGHT_MAX:
                return False
            self.inflight += n
            return True

    def release(self, n):
        with self._lock:
            self.inflight -= n

    def count(self, key, n=1):
        with self._lock:
            self.stats[key] += n

    # --- Loki ---
    def forward(self, node_id, body, ctype, cenc):
        """본문을 그대로 Loki 에 넘긴다. (응답 코드, 본문, Content-Type). 닿지 않으면 503."""
        headers = {"X-Scope-OrgID": node_id}
        if hval(ctype):
            headers["Content-Type"] = ctype
        if hval(cenc):
            headers["Content-Encoding"] = cenc
        req = urllib.request.Request(self.loki, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=LOKI_TIMEOUT) as r:
                return r.status, r.read(MAX_REPLY), r.headers.get("Content-Type")
        except urllib.error.HTTPError as e:
            try:
                data = e.read(MAX_REPLY)
            except (OSError, http.client.HTTPException):
                data = b""
            finally:
                e.close()
            if e.code >= 500:
                self.count("loki_error")
            return e.code, data, e.headers.get("Content-Type") if e.headers else None
        except (OSError, http.client.HTTPException) as e:
            self.count("loki_error")
            log(f"Loki 에 넘기지 못했다 ({node_id}): {type(e).__name__}: {safe(e)}", 4)
            return 503, b'{"result":"loki_unavailable"}', "application/json"

    # --- 관리 스레드 ---
    def tick(self):
        """0.5초마다: HUP · 15초 주기 캐시 갱신, 창이 끝난 원장 묶음 쓰기, 10분 요약."""
        now = self.clock()
        if self.hup or now - self._last_try >= CACHE_EVERY:
            why = "HUP" if self.hup else ""
            self.hup = False
            self.reload(why)
        fresh = self.cache_fresh()
        if fresh != self._fresh:
            if fresh:
                log("노드 캐시 회복. push 를 다시 받는다", 5)
            else:
                log(f"노드 캐시가 {CACHE_STALE}초 넘게 오래됐다. push 에 503 을 준다 (DB 접속 확인)", 3)
            self._fresh = fresh
        self.ledger.flush()
        self.save_usage()
        if now - self._stats_at >= STATS_EVERY:
            self._stats_at = now
            with self._lock:
                s, self.stats = self.stats, collections.Counter()
            if s:
                log(f"지난 {STATS_EVERY // 60}분: 넘김 {s['pass']}건 {s['pass_bytes']:,} B · 거부 {s['rejected']} · "
                    f"제한 {s['throttled']} · 등록 {s['enrolled']} · Loki 오류 {s['loki_error']} · "
                    f"연결 한도로 끊음 {s['refused']}")

    def housekeeping(self):
        while not self.stop.wait(0.5):
            try:
                self.tick()
            except Exception as e:
                log(f"관리 작업 오류: {type(e).__name__}: {safe(e)}", 3)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"     # Alloy 가 연결을 다시 쓴다. 응답마다 길이를 붙인다
    timeout = SOCK_TIMEOUT
    _expect = False

    def version_string(self):
        return "opsloop-gate"

    def log_request(self, code="-", size="-"):
        pass

    def log_message(self, fmt, *args):
        log(f"HTTP {self.client_address[0]}: {safe(fmt % args)}", 7)

    def handle_one_request(self):
        # 요청 줄과 헤더를 HEADER_DEADLINE 안에 다 받지 못하면 연결을 끊는다.
        # 한 바이트씩 흘려 소켓 시간 초과(30초)를 피하며 슬롯 · 메모리를 붙잡는 것을 막는다
        self.raw_requestline = b""
        self._headers_done = False
        self._hdr_timer = threading.Timer(HEADER_DEADLINE, self._header_timeout)
        self._hdr_timer.daemon = True
        self._hdr_timer.start()
        try:
            super().handle_one_request()
        finally:
            self._hdr_timer.cancel()

    def parse_request(self):
        ok = super().parse_request()
        self._headers_done = True
        self._hdr_timer.cancel()
        return ok

    def _header_timeout(self):
        if self._headers_done:
            return
        if self.raw_requestline:
            # 요청 줄은 왔는데 헤더가 끝나지 않는다 (쉬고 있는 재사용 연결이 아니다)
            self.server.gate.count("rejected")
            self.server.gate.ledger.record(REJECTED, self._src(), "-", "header_timeout")
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def send_error(self, code, message=None, explain=None):
        # 표준 라이브러리가 요청 줄 · 헤더를 해석하다 내는 오류(인증 전)도 거부로 남긴다
        reason = PRE_AUTH_ERRORS.get(code)
        if reason:
            self.server.gate.count("rejected")
            self.server.gate.ledger.record(REJECTED, self._src(), getattr(self, "path", None) or "-", reason)
        self.close_connection = True
        super().send_error(code, message, explain)

    def handle_expect_100(self):
        self._expect = True           # 100 Continue 는 본문을 받기로 정한 뒤에만 보낸다
        return True

    def __getattr__(self, name):
        # POST 밖의 메서드도 모두 같은 길로 보낸다 (404 path 로 원장에 남는다)
        if name.startswith("do_"):
            return self._route
        raise AttributeError(name)

    # --- 공통 ---
    def _src(self):
        return self.client_address[0]

    def _route(self):
        try:
            if self.command == "POST" and self.path == PUSH:
                self._push()
            elif self.command == "POST" and self.path == ENROLL:
                self._enroll()
            else:
                self._reject("path")
        except (ConnectionError, TimeoutError) as e:
            self.close_connection = True
            log(f"연결이 끊겼다 {self._src()} {safe(self.path, 80)}: {type(e).__name__}: {safe(e)}", 6)
        finally:
            self._expect = False

    def _send(self, code, obj, close=False):
        self._send_raw(code, json.dumps(obj).encode(), "application/json", close)

    def _send_raw(self, code, data, ctype, close=False):
        self.send_response(code)
        if close:
            self.send_header("Connection", "close")   # close_connection 도 함께 선다
        if code in (204, 304) or code < 200:
            self.end_headers()
            return
        data = data or b""
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data and self.command != "HEAD":
            self.wfile.write(data)

    def _reject(self, reason, fp=None, node_id=None, code=None):
        """거부. 본문을 읽지 않았으면 읽지 않은 채 연결을 닫는다."""
        gate = self.server.gate
        gate.count("rejected")
        gate.ledger.record(REJECTED, self._src(), self.path, reason, fp, self.headers.get("User-Agent"), node_id)
        if code is None:
            code = 404 if reason == "path" else 400 if reason in BAD_REQUEST else 401
        self._send(code, {"result": reason}, close=True)

    def _throttle(self, code, reason, fp, node_id=None):
        """길이 없음 · 너무 큼 · 하루 용량 · 동시 본문 초과. R202 가 아니라 제한으로만 남긴다."""
        gate = self.server.gate
        gate.count("throttled")
        gate.ledger.record(THROTTLED, self._src(), self.path, reason, fp, self.headers.get("User-Agent"), node_id)
        self._send(code, {"result": reason}, close=True)

    def _read_body(self, n):
        """Content-Length 만큼 받는다. 끊기면 ConnectionError, 늦으면 TimeoutError."""
        if self._expect:
            self._expect = False
            self.send_response_only(100)
            self.end_headers()
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        deadline = time.monotonic() + BODY_DEADLINE
        try:
            while got < n:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"본문을 {BODY_DEADLINE}초 안에 다 받지 못했다 ({got:,}/{n:,} B)")
                k = self.rfile.readinto1(view[got:got + CHUNK])
                if not k:
                    raise ConnectionError(f"본문 중간에 끊겼다 ({got:,}/{n:,} B)")
                got += k
        finally:
            view.release()
        return buf

    # --- push ---
    def _authorize(self):
        """push 의 헤더 검사 3 ~ 5. 통과하면 (노드, 지문), 거부했으면 (None, None)."""
        token = bearer(self.headers.get("Authorization"))
        if token is None:
            self._reject("missing")
            return None, None
        token_hash = sha256hex(token)
        fp = token_hash[:8]
        node = self.server.gate.nodes.get(token_hash)
        if node is None:
            reason = "unknown"
        elif node.status == "revoked":
            reason = "revoked"
        elif node.status != "active":
            reason = "inactive"
        elif node.addr is None or node.addr != norm_ip(self._src()):
            reason = "addr_mismatch"
        else:
            return node, fp
        self._reject(reason, fp, node.node_id if node else None)
        return None, None

    def _push(self):
        gate = self.server.gate
        if not gate.cache_fresh():
            # 관문 쪽 문제다. 거부로 세지 않고 Alloy 가 다시 보내게 한다
            self._send(503, {"result": "unavailable"}, close=True)
            return
        node, fp = self._authorize()
        if node is None:
            return
        n = content_length(self.headers)
        if n is None:
            return self._throttle(411, "length_required", fp, node.node_id)
        if n > MAX_PUSH:
            return self._throttle(413, "too_large", fp, node.node_id)
        if not gate.quota_ok(node.node_id, n):
            return self._throttle(429, "daily_quota", fp, node.node_id)
        if not gate.reserve(n):
            return self._throttle(429, "busy", fp, node.node_id)
        try:
            body = self._read_body(n)
            code, data, ctype = gate.forward(node.node_id, body, self.headers.get("Content-Type"),
                                             self.headers.get("Content-Encoding"))
            del body
        finally:
            gate.release(n)
        if 200 <= code < 300:
            gate.charge(node.node_id, n)
            gate.count("pass")
            gate.count("pass_bytes", n)
        self._send_raw(code, data, ctype, close=code == 503)

    # --- enroll ---
    def _enroll(self):
        gate = self.server.gate
        token = bearer(self.headers.get("Authorization"))
        if token is None:
            return self._reject("missing")
        token_hash = sha256hex(token)
        fp = token_hash[:8]
        src = self._src()
        # 여기까지는 누가 보냈는지 모른다. 길이 문제도 등록 노드의 문제가 아니라 거부(R202)로 남긴다
        if not gate.enroll_rate_ok(src):
            return self._reject("enroll_rate", fp, code=429)
        n = content_length(self.headers)
        if n is None:
            return self._reject("length_required", fp, code=411)
        if n > MAX_ENROLL:
            return self._reject("too_large", fp, code=413)
        if not ENROLL_TOKEN.fullmatch(token):
            return self._reject("enroll_unknown", fp)   # 발급 형식이 아니면 DB 에 묻지 않는다
        req = parse_enroll(self._read_body(n))
        if isinstance(req, str):
            return self._reject(req, fp)
        node_id, agent = req
        if not gate.enroll_slots.acquire(blocking=False):
            return self._reject("enroll_busy", fp, code=429)
        try:
            result = gate.store.enroll(token_hash, node_id, agent, src)
        except Exception as e:
            log(f"등록 DB 오류 {src} {node_id}: {type(e).__name__}: {safe(e)}", 3)
            gate.ledger.record(THROTTLED, src, self.path, "unavailable", fp, self.headers.get("User-Agent"), node_id)
            return self._send(503, {"result": "unavailable"}, close=True)
        finally:
            gate.enroll_slots.release()
        if result == "ok":
            known = gate.nodes.get(agent)
            if known and known.node_id == node_id and known.status == "active" and known.addr == norm_ip(src):
                # 이미 등록된 그대로다 (응답 유실 재시도). 원장에 다시 쓰지도 캐시를 다시 읽지도 않는다
                return self._send(200, {"result": "ok"})
            gate.count("enrolled")
            gate.ledger.record(ENROLLED, src, self.path, "ok", agent[:8], self.headers.get("User-Agent"),
                               node_id, group=False)
            log(f"등록 {node_id} · 출발지 {src} · 키 지문 {agent[:8]}", 5)
            if not gate.reload(f"등록 {node_id}"):
                # 등록은 끝났다. 같은 키로 다시 부르면 DB 가 ok 를 주고 캐시를 다시 읽는다
                return self._send(503, {"result": "unavailable"}, close=True)
            return self._send(200, {"result": "ok"})
        if result not in ENROLL_REJECT:
            log(f"enroll_node 가 알 수 없는 값을 돌려줬다: {safe(result)}", 3)
            return self._send(503, {"result": "unavailable"}, close=True)
        self._reject(result, fp)


class GateServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False            # 끝낼 때 느린 연결을 기다리지 않는다
    request_queue_size = 64

    def __init__(self, addr, max_conn=MAX_CONN):
        self.gate = None
        self.stopping = False         # SIGTERM 처리기는 표시만 한다
        self.slots = threading.BoundedSemaphore(max_conn)
        self.per_src = collections.Counter()
        self._src_lock = threading.Lock()
        super().__init__(addr, Handler)

    def server_bind(self):
        # HTTPServer.server_bind 는 역방향 DNS(getfqdn)를 부른다. 인터넷이 없는 곳에서 시작이 늦어지지 않게 건너뛴다
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address):
        ip = client_address[0]
        with self._src_lock:
            over = self.per_src[ip] >= PER_SRC_CONN
            if not over:
                self.per_src[ip] += 1
        if over:
            # 한 출발지가 연결을 쌓아 다른 노드의 슬롯을 빼앗지 못하게 한다. 정상 에이전트는 몇 개만 쓴다
            if self.gate:
                self.gate.count("refused")
                self.gate.ledger.record(REJECTED, ip, "-", "conn_limit")
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self._src_done(ip)
            if self.gate:
                self.gate.count("refused")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            self._src_done(ip)
            raise

    def _src_done(self, ip):
        with self._src_lock:
            self.per_src[ip] -= 1
            if self.per_src[ip] <= 0:
                del self.per_src[ip]

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
            self._src_done(client_address[0])

    def service_actions(self):
        if self.stopping:
            raise Terminated()

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        # 요청 줄을 읽다가 끊긴 연결은 흔한 일이다. 그 밖의 예외만 오류로 남긴다
        level = 7 if isinstance(e, (ConnectionError, TimeoutError)) else 3
        log(f"요청 처리 오류 {client_address[0]}: {type(e).__name__}: {safe(e)}", level)


def make_server(host, port, store, loki_url, gate_dir, clock=time.monotonic, max_conn=MAX_CONN):
    server = GateServer((host, port), max_conn)
    ledger = Ledger(gate_dir, server.server_address[1], clock)
    server.gate = Gate(store, loki_url, ledger, clock, usage_path=os.path.join(gate_dir, USAGE_FILE))
    return server, server.gate


def parse_bind(v):
    host, sep, port = v.rpartition(":")
    if not sep or not host or not LENGTH.fullmatch(port) or not 0 < int(port) < 65536:
        sys.exit(f"GATE_BIND 형식이 틀렸습니다 (주소:포트): {v}")
    return host, int(port)


def main():
    # 처리기를 걸기 전에 HUP 이 오면 기본 동작(종료)으로 죽는다. 가장 먼저 막아 둔다 (시작할 때 어차피 캐시를 읽는다)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    ap = argparse.ArgumentParser(description="OpsLoop 수집 관문 (에이전트 → Loki)")
    ap.parse_args()
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다 (/etc/opsloop/gate.env)")
    try:
        import psycopg2  # noqa: F401
    except ImportError:
        sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")
    host, port = parse_bind(os.environ.get("GATE_BIND", "192.168.60.11:3101"))
    loki_url = os.environ.get("LOKI_URL", "http://127.0.0.1:3100")
    gate_dir = os.environ.get("GATE_DIR", "/var/lib/opsloop/gate")
    if not os.path.isdir(gate_dir) or not os.access(gate_dir, os.W_OK):
        sys.exit(f"관문 원장 폴더에 쓸 수 없습니다: {gate_dir}")

    server, gate = make_server(host, port, Store(url), loki_url, gate_dir)
    signal.signal(signal.SIGHUP, lambda s, f: setattr(gate, "hup", True))
    signal.signal(signal.SIGTERM, lambda s, f: setattr(server, "stopping", True))
    gate.reload("시작")
    worker = threading.Thread(target=gate.housekeeping, name="housekeeping", daemon=True)
    worker.start()
    log(f"수집 관문 시작 {host}:{port} → Loki {loki_url} · 원장 {gate_dir} · boot {gate.ledger.boot}", 5)
    try:
        server.serve_forever(poll_interval=0.5)
    except (Terminated, KeyboardInterrupt):
        pass
    finally:
        gate.stop.set()
        worker.join(timeout=15)
        gate.ledger.flush(force=True)
        gate.save_usage(force=True)
        server.server_close()
        log("수집 관문을 멈췄다. 묶어 둔 원장 줄을 모두 썼다", 5)


if __name__ == "__main__":
    main()
