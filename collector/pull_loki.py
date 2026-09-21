#!/usr/bin/env python3
"""관제 대상 로그 다리 (WBS 3.4.2 · 3.4.4 / 이슈 #11).

opsloop-agents.service 가 opsloop-pull 사용자로 1분마다 돌린다. 등록 노드(web-01 등)의 Loki 테넌트와
수집 관문 원장을 events · node_metrics 로 옮기고, 자기 탐지(R202)와 관제 대상 규칙(R101 최소판)을 돌린다.
5분 적재기(opsloop-ingest)와 허니팟 경로는 건드리지 않는다. S3 가 막혀도 이 경로의 탐지는 계속된다.

한 회차
  1. logs 가 있는 active · revoked 노드를 읽는다.
  2. 노드마다 Loki 테넌트(X-Scope-OrgID=node_id)를 query_range {job=~".+"} 로 읽는다 (forward, 5000건씩).
     창은 [워터마크-5분, 지금-10초). 15회에 한 번은 워터마크-100분부터 본다
     (Alloy 재시도 한계 약 58분보다 길게 잡아, 늦게 도착한 묶음을 줍는다).
     5000건이 차면 마지막 시각부터 이어 읽는다. 커밋한 뒤에만 워터마크를 올린다.
     줄은 parser/parse_agent.py 로 바꾸고 INSERT ... ON CONFLICT (line_hash) DO NOTHING RETURNING 으로 신규를 센다.
     스트림 job 이 nodes.logs 에 없으면 적재하지 않고 undeclared 로만 센다.
  3. nodes.receipt[job] 에 수신 기록을 더한다 (줄 · 신규 · 건너뛴 사유별 수 · seq 공백).
     겹쳐 읽는 구간을 두 번 세지 않도록, 스트림마다 이미 센 마지막 시각과 그 시각의 줄 해시를 기억한다.
     신규가 생기면 first_loaded_at(비었을 때만) · last_loaded_at · last_seen_at 을 갱신한다.
  4. 관문 원장($GATE_DIR/collector-*.jsonl)과 관리 원장($OPSLOOP_ADMIN_DIR/admin-*.jsonl)을 파일마다
     (inode, 오프셋) 으로 이어 읽어 events 에 넣는다. 관리 원장은 관문이 쓸 수 없는 root 전용 폴더에서만 읽는다.
     쓰는 중인 마지막 줄(줄바꿈 없음)은 다음 회차에 읽는다.
  5. detect.py 를 rules_self.json(s1) · rules_node.json(n1) 으로 차례로 돈다.
  Loki 가 응답하지 않아도 4 · 5 는 한다.

관제 대상이 장악된 경우를 가정한다. 관문은 본문을 그대로 넘기므로 web-01 은 라벨 · 줄 내용을 마음대로 정한다.
그래서 믿는 것은 테넌트(관문이 토큰으로 증명한 node_id)와 job 라벨뿐이고, 어떤 줄 · 라벨이 와도 죽거나
상태 · 수신 기록이 한없이 커지지 않게 한다. 관문(opsloop-gate)도 원장 폴더의 주인이므로,
관리 원장은 root 가 쓴 파일만 읽고 관문 원장에 끼운 collector.admin.* 줄은 받지 않는다.

재생성 (DB 를 백업에서 복원한 뒤 등)
  sudo -u opsloop-pull python3 /opt/opsloop/app/collector/pull_loki.py --node web-01 --since 2026-09-21T00:00:00Z
  그 노드를 그 시각부터 다시 읽는다. line_hash 로 빠진 것만 들어가고, 두 번째 실행의 신규는 0 이다.

종료 코드
  0  정상
  1  실패 (DB 접속 · Loki 조회 · 적재 · 원장 · 탐지 중 하나라도)

경로
  $OPSLOOP_HOME/agents-state.json   노드별 워터마크 · 스트림별 센 위치 · 원장 파일별 (inode, 오프셋)
  $OPSLOOP_HOME/agents.lock         동시 실행 막기 (타이머와 손 실행)

환경변수
  DATABASE_URL    없으면 OPSLOOP_DB_ENV(기본 /etc/opsloop/collector.env)에서 읽는다 (역할 opsloop)
  LOKI_URL        기본 http://127.0.0.1:3100
  GATE_DIR        기본 /var/lib/opsloop/gate
  OPSLOOP_ADMIN_DIR 기본 /var/lib/opsloop/admin
  OPSLOOP_HOME    기본 /var/lib/opsloop
  OPSLOOP_APP     기본 /opt/opsloop/app (parser/parse_agent.py · detector/detect.py 를 여기서 찾는다)
"""
import argparse
import copy
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

APP = os.environ.get("OPSLOOP_APP", "/opt/opsloop/app")
HOME = os.environ.get("OPSLOOP_HOME", "/var/lib/opsloop")
LOKI_URL = os.environ.get("LOKI_URL", "http://127.0.0.1:3100").rstrip("/")
GATE_DIR = os.environ.get("GATE_DIR", "/var/lib/opsloop/gate")
ADMIN_DIR = os.environ.get("OPSLOOP_ADMIN_DIR", "/var/lib/opsloop/admin")
DB_ENV = os.environ.get("OPSLOOP_DB_ENV", "/etc/opsloop/collector.env")
RULESETS = ("rules_self.json", "rules_node.json")     # s1 (R202 미등록 에이전트) · n1 (R101 최소판)

NS = 10 ** 9
LAG = 10 * NS                  # 지금-10초까지만 본다 (Loki 가 막 받은 묶음이 조회에 덜 잡힐 수 있다)
OVERLAP = 5 * 60 * NS
DEEP = 100 * 60 * NS            # Alloy 재시도 한계(20회, 약 58분) + 깊은 조회 주기(15분) + 여유
DEEP_EVERY = 15
CHUNK = 6 * 3600 * NS          # 한 번에 묻는 창의 최대 길이. 오래 멈췄다 돌아와도 Loki 조회 길이 한도에 걸리지 않게 나눈다
LIMIT = 5000                   # Loki max_entries_limit_per_query 기본값
MIN_LIMIT = 5
MAX_RESP = 32 * 1024 * 1024    # 응답 한 번의 상한. 넘으면 limit 을 줄여 다시 묻는다 (줄 하나는 최대 256KB)
HTTP_TIMEOUT = 30
RUN_SECONDS = 180              # 한 회차의 Loki 읽기 시간. 넘으면 읽은 데까지 두고 다음 회차에 잇는다
DETECT_TIMEOUT = 240
MAX_LINE = 1024 * 1024         # 원장 한 줄의 상한 (관문 줄은 1KB 안팎이다)
READ = 1024 * 1024
LEDGER_BATCH = 5000
LEDGER_BYTES = 64 * 1024 * 1024
STREAM_CAP = 256               # 노드마다 기억할 스트림 수. 장악된 노드가 라벨을 흩뿌려도 상태가 커지지 않게
AT_CAP = 1000
JOB_CAP = 16                   # receipt 에 둘 job 키 수. 넘는 선언 밖 job 은 _other 로 모은다
ADMIN_UID = 0                  # 관리 원장은 nodes.py 가 root 로 쓴다

COUNTERS = ("lines", "new", "malformed", "foreign_host", "repeated", "unmatched", "undeclared", "seq_gaps")
SKIP_REASONS = ("malformed", "foreign_host", "repeated", "unmatched", "undeclared")
LEDGER_RE = re.compile(r"(collector|admin)-[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl")
NODE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
JOB_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
IDENT_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
QUERY = '{job=~".+"}'
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # Loki 는 로컬이다. 프록시 설정을 타지 않는다


def safe(v):
    """노드가 정한 값(라벨 · 줄 · 오류 문구)을 로그에 쓸 때. 줄바꿈으로 가짜 로그 줄을 만들지 못하게 한다."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(v))[:300]


def log(msg, level=6):
    prefix = f"<{level}>" if _JOURNAL else ""
    print(f"{prefix}{msg}", flush=True)


def now_ns():
    return time.time_ns()


def dt_ns(t):
    """datetime → 나노초. float 를 거치지 않아 마이크로초가 흔들리지 않는다."""
    return (t - EPOCH) // timedelta(microseconds=1) * 1000


def iso(ns):
    return datetime.fromtimestamp(ns // NS, timezone.utc).replace(microsecond=(ns % NS) // 1000) \
        .isoformat(timespec="microseconds")


def read_env(path):
    """KEY=VALUE 파일. 셸로 읽지 않는다 (값에 셸 문자가 있어도 실행되지 않는다)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def base_env():
    keep = ("PATH", "LANG", "LC_ALL", "JOURNAL_STREAM")
    env = {k: v for k, v in os.environ.items() if k in keep or k.startswith("OPSLOOP_")}
    env.setdefault("PATH", "/usr/bin:/bin")
    return env


def load_exclusions(path):
    ips = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    ips.add(line)
    except FileNotFoundError:
        pass
    return ips


# ----------------------------------------------------------------------
#  상태 파일
# ----------------------------------------------------------------------

def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    except FileNotFoundError:
        st = {}
    except ValueError:
        log(f"상태 파일 {path} 이 깨졌다. 처음부터 센다 (적재는 line_hash 로 중복 없이 된다)", 3)
        st = {}
    if not isinstance(st, dict):
        st = {}
    st.setdefault("runs", 0)
    st.setdefault("nodes", {})     # node_id → {watermark, streams: {스트림 키: [센 마지막 시각, [그 시각 줄 해시]]}}
    st.setdefault("ledgers", {})   # 원장 파일 이름 → {ino, offset}
    return st


def save_state(path, state):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".agents-state.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cleanup_temp(home):
    for name in os.listdir(home):
        if name.startswith(".agents-state."):
            try:
                os.unlink(os.path.join(home, name))
            except OSError:
                pass


# ----------------------------------------------------------------------
#  파서 (parser/parse_agent.py, 계약 7장)
# ----------------------------------------------------------------------

def load_agent():
    d = os.path.join(APP, "parser")
    if d not in sys.path:
        sys.path.insert(0, d)
    spec = importlib.util.spec_from_file_location("parse_agent", os.path.join(d, "parse_agent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ("parse", "parse_collector", "EVENT_COLUMNS", "METRIC_COLUMNS"):
        if not hasattr(mod, name):
            raise ImportError(f"parse_agent 에 {name} 이 없다")
    for cols in (mod.EVENT_COLUMNS, mod.METRIC_COLUMNS):
        if "line_hash" not in cols or not all(isinstance(c, str) and IDENT_RE.fullmatch(c) for c in cols):
            raise ImportError("parse_agent 의 열 이름이 틀렸다")
    return mod


def row_values(row, cols):
    if isinstance(row, dict):
        return tuple(row.get(c) for c in cols)
    return tuple(row)


def row_get(row, cols, name):
    return row.get(name) if isinstance(row, dict) else row[cols.index(name)]


# ----------------------------------------------------------------------
#  DB
# ----------------------------------------------------------------------

class PgStore:
    """다리가 DB 에 하는 일 전부. 시험은 같은 모양의 가짜를 쓴다."""

    def __init__(self, url):
        import psycopg2
        from psycopg2.extras import execute_values
        self._pg, self._ev = psycopg2, execute_values
        self.conn = psycopg2.connect(url, connect_timeout=10)
        self.cur = self.conn.cursor()

    def nodes(self, node=None):
        sql = ("SELECT node_id, hostname, logs, registered_at FROM nodes "
               "WHERE status IN ('active','revoked') AND cardinality(logs) > 0")
        params = ()
        if node:
            sql += " AND node_id = %s"
            params = (node,)
        self.cur.execute(sql + " ORDER BY node_id", params)
        return [(r[0], r[1], list(r[2] or ()), r[3]) for r in self.cur.fetchall()]

    def insert(self, table, cols, rows):
        """(신규 line_hash 집합, DB 가 거부한 line_hash 집합). 값 문제로 묶음이 실패하면 한 줄씩 넣어 그 줄만 뺀다.

        표가 없다 · 권한이 없다 같은 문제는 모든 줄에 같으므로 올려 보낸다 (워터마크가 오르지 않는다).
        """
        names = ", ".join(cols)
        many = f"INSERT INTO {table} ({names}) VALUES %s ON CONFLICT (line_hash) DO NOTHING RETURNING line_hash"
        one = (f"INSERT INTO {table} ({names}) VALUES ({', '.join(['%s'] * len(cols))}) "
               f"ON CONFLICT (line_hash) DO NOTHING RETURNING line_hash")
        value_errors = (self._pg.DataError, self._pg.IntegrityError, ValueError)
        self.cur.execute("SAVEPOINT ol_many")
        try:
            got = self._ev(self.cur, many, rows, page_size=1000, fetch=True)
            self.cur.execute("RELEASE SAVEPOINT ol_many")
            return {r[0] for r in got}, set()
        except value_errors:
            self.cur.execute("ROLLBACK TO SAVEPOINT ol_many")
        new, bad = set(), set()
        h = cols.index("line_hash")
        for row in rows:
            self.cur.execute("SAVEPOINT ol_one")
            try:
                self.cur.execute(one, row)
                r = self.cur.fetchone()
                self.cur.execute("RELEASE SAVEPOINT ol_one")
                if r:
                    new.add(r[0])
            except value_errors:
                self.cur.execute("ROLLBACK TO SAVEPOINT ol_one")
                bad.add(row[h])
        return new, bad

    def update_receipt(self, node_id, deltas, declared, loaded):
        self.cur.execute("SELECT receipt FROM nodes WHERE node_id = %s FOR UPDATE", (node_id,))
        r = self.cur.fetchone()
        old = r[0] if r else {}
        if isinstance(old, str):
            old = json.loads(old)
        gaps = None
        if "metrics" in deltas:
            # 늦게 온 지표가 공백을 메우면 저절로 줄어든다. seq 는 재부팅 뒤에도 이어진다 (metrics.seq)
            # numeric 으로 센다. 장악된 노드가 0 과 2^63-1 같은 번호를 넣어도 bigint 넘침으로 적재가 멈추지 않게 한다
            self.cur.execute("SELECT coalesce(least(max(seq)::numeric - min(seq) + 1 - count(DISTINCT seq), 2147483647), 0) "
                             "FROM node_metrics WHERE node_id = %s AND seq IS NOT NULL", (node_id,))
            gaps = int(self.cur.fetchone()[0])
        rec = merge_receipt(old, deltas, declared, gaps)
        self.cur.execute(
            """UPDATE nodes SET receipt = %s::jsonb,
                   first_loaded_at = CASE WHEN %s THEN coalesce(first_loaded_at, now()) ELSE first_loaded_at END,
                   last_loaded_at  = CASE WHEN %s THEN now() ELSE last_loaded_at END,
                   last_seen_at    = CASE WHEN %s THEN now() ELSE last_seen_at END
               WHERE node_id = %s""",
            (json.dumps(rec, ensure_ascii=False), loaded, loaded, loaded, node_id))

    def savepoint(self):
        self.cur.execute("SAVEPOINT ol_receipt")

    def release(self):
        self.cur.execute("RELEASE SAVEPOINT ol_receipt")

    def rollback_to(self):
        self.cur.execute("ROLLBACK TO SAVEPOINT ol_receipt")

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def connect(url):
    return PgStore(url)


def new_delta():
    d = dict.fromkeys(COUNTERS, 0)
    d["first"] = d["last"] = None
    return d


def merge_receipt(old, deltas, declared=(), seq_gaps=None):
    """receipt jsonb 에 이번 묶음의 수를 더한다. 수는 누적, first_line_at 은 처음 한 번, last_line_at 은 최댓값.

    first_line_at · last_line_at 은 Loki 항목 시각(Alloy 가 줄을 읽은 시각)이다. seq_gaps 는 DB 에서 센 현재 값이다.
    """
    rec = {k: v for k, v in old.items()} if isinstance(old, dict) else {}
    for job, d in deltas.items():
        key = job
        if key not in rec and key not in declared and len(rec) >= JOB_CAP:
            key = "_other"
        cur = rec.get(key)
        cur = dict(cur) if isinstance(cur, dict) else {}
        for k in COUNTERS:
            base = cur.get(k, 0)
            if not isinstance(base, int) or isinstance(base, bool):
                base = 0
            cur[k] = base + d.get(k, 0)
        if d.get("first") is not None and not cur.get("first_line_at"):
            cur["first_line_at"] = iso(d["first"])
        if d.get("last") is not None:
            last = iso(d["last"])
            if not isinstance(cur.get("last_line_at"), str) or last > cur["last_line_at"]:
                cur["last_line_at"] = last
        rec[key] = cur
    if seq_gaps is not None and isinstance(rec.get("metrics"), dict):
        rec["metrics"]["seq_gaps"] = seq_gaps
    return rec


# ----------------------------------------------------------------------
#  Loki
# ----------------------------------------------------------------------

class LokiError(Exception):
    pass


class TooBig(Exception):
    pass


def loki_query(node_id, start, end, limit):
    """[start, end) 의 항목을 시각 순으로. ([(시각 ns, 스트림 키, job, 줄)], 형식이 틀린 항목 수)."""
    qs = urllib.parse.urlencode({"query": QUERY, "start": str(start), "end": str(end),
                                 "direction": "forward", "limit": str(limit)})
    req = urllib.request.Request(f"{LOKI_URL}/loki/api/v1/query_range?{qs}",
                                 headers={"X-Scope-OrgID": node_id, "Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=HTTP_TIMEOUT) as r:
            body = r.read(MAX_RESP + 1)
    except urllib.error.HTTPError as e:
        try:
            detail = e.read(300).decode("utf-8", "replace")
        except OSError:
            detail = ""
        raise LokiError(f"HTTP {e.code} {safe(detail)}")
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        raise LokiError(safe(getattr(e, "reason", None) or e))
    if len(body) > MAX_RESP:
        raise TooBig()
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError):
        raise LokiError("응답이 JSON 이 아니다")
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict) or data.get("resultType") != "streams" or not isinstance(data.get("result"), list):
        raise LokiError("응답 형식이 틀렸다")
    out, bad = [], 0
    for s in data["result"]:
        labels = s.get("stream") if isinstance(s, dict) else None
        values = s.get("values") if isinstance(s, dict) else None
        if not isinstance(labels, dict) or not isinstance(values, list):
            bad += 1
            continue
        # 라벨은 노드가 정한다. 상태에는 해시만 남겨 크기를 묶는다
        skey = hashlib.sha1(json.dumps(labels, sort_keys=True).encode("utf-8", "surrogatepass")).hexdigest()[:20]
        job = labels.get("job")
        for v in values:
            if not (isinstance(v, list) and len(v) >= 2 and isinstance(v[0], str) and isinstance(v[1], str)
                    and v[0].isascii() and v[0].isdigit() and len(v[0]) <= 20):
                bad += 1
                continue
            out.append((int(v[0]), skey, job, v[1]))
    out.sort(key=lambda e: e[0])        # 안정 정렬. 스트림 안의 순서는 그대로다
    return out, bad


# ----------------------------------------------------------------------
#  노드 한 개
# ----------------------------------------------------------------------

def seen_update(streams, skey, ts, h):
    """이 줄을 처음 세는지. 스트림 안의 항목은 시각 순으로 온다(Alloy 는 묶음을 차례로 보낸다).

    센 마지막 시각보다 뒤거나, 같은 시각인데 그 시각에 센 줄이 아니면 새 줄이다.
    겹쳐 읽는 구간 · 5000건 경계에서 다시 받은 줄은 여기서 걸러져 두 번 세지 않는다.
    """
    cur = streams.get(skey)
    if cur is None or ts > cur[0]:
        streams[skey] = [ts, [h]]
        return True
    if ts == cur[0]:
        if h in cur[1]:
            return False
        if len(cur[1]) < AT_CAP:
            cur[1].append(h)
        return True
    return False


def job_key(job, declared):
    if job in declared:
        return job
    return job if isinstance(job, str) and JOB_RE.fullmatch(job) else "_invalid"


def process_page(store, agent, node, entries, streams, exclusions, warned):
    """한 쪽(최대 5000건)을 바꿔 넣고 수신 기록을 더한 뒤 커밋한다. (줄, 신규, 사유별 건너뜀) 을 돌려준다."""
    node_id, hostname, logs = node[0], node[1] or "", set(node[2])
    deltas, meta = {}, {}
    ev_rows, mt_rows = [], []
    for ts, skey, job, line in entries:
        fresh = seen_update(streams, skey, ts, hashlib.sha1(line.encode("utf-8", "surrogatepass")).hexdigest())
        key = job_key(job, logs)
        d = deltas.setdefault(key, new_delta())
        if fresh:
            d["lines"] += 1
            d["first"] = ts if d["first"] is None else min(d["first"], ts)
            d["last"] = ts if d["last"] is None else max(d["last"], ts)
        if job not in logs:
            kind, val = "skip", "undeclared"
        else:
            try:
                kind, val = agent.parse(node_id, hostname, job, line, exclusions)
            except Exception as e:            # 파서 결함 하나로 회차 전체가 멈추지 않게 한다
                if not warned.get("parse"):
                    log(f"{node_id}: 파서 예외 {type(e).__name__}: {safe(e)}. 그 줄은 malformed 로 센다", 3)
                    warned["parse"] = True
                kind, val = "skip", "malformed"
        if kind == "event":
            ev_rows.append(row_values(val, agent.EVENT_COLUMNS))
            meta.setdefault(row_get(val, agent.EVENT_COLUMNS, "line_hash"), (key, fresh))
        elif kind == "metric":
            mt_rows.append(row_values(val, agent.METRIC_COLUMNS))
            meta.setdefault(row_get(val, agent.METRIC_COLUMNS, "line_hash"), (key, fresh))
        elif fresh:
            d[val if val in SKIP_REASONS else "malformed"] += 1

    new, bad = set(), set()
    for table, cols, rows in (("events", agent.EVENT_COLUMNS, ev_rows),
                              ("node_metrics", agent.METRIC_COLUMNS, mt_rows)):
        if rows:
            n, b = store.insert(table, cols, rows)
            new |= n
            bad |= b
    for h in new:
        deltas[meta[h][0]]["new"] += 1
    for h in bad:
        key, fresh = meta[h]
        if fresh:
            deltas[key]["malformed"] += 1
    if bad and not warned.get("bad"):
        log(f"{node_id}: DB 가 받지 않은 행 {len(bad)}개 (malformed 로 센다)", 4)
        warned["bad"] = True
    touched = {k: d for k, d in deltas.items() if any(d[c] for c in COUNTERS)}
    if touched or new:
        # 수신 기록은 부가 정보다. 갱신이 실패해도 적재한 줄과 워터마크는 그대로 진행한다
        store.savepoint()
        try:
            store.update_receipt(node_id, touched, logs, bool(new))
            store.release()
        except Exception as e:
            store.rollback_to()
            log(f"{node_id}: 수신 기록을 고치지 못했다. 적재는 계속한다 ({type(e).__name__}: {safe(e)})", 3)
    store.commit()

    lines = sum(d["lines"] for d in deltas.values())
    skipped = {r: sum(d[r] for d in deltas.values()) for r in SKIP_REASONS}
    return lines, len(new), skipped


def cap_streams(streams):
    if len(streams) > STREAM_CAP:
        keep = sorted(streams.items(), key=lambda kv: kv[1][0], reverse=True)[:STREAM_CAP]
        streams.clear()
        streams.update(keep)


def pull_node(store, agent, node, nst, exclusions, now, deep, save, since=None, deadline=None):
    """한 노드의 창을 읽는다. 끝까지 읽었으면 True. Loki 오류는 LokiError 로 올린다."""
    node_id, registered = node[0], node[3]
    end = now - LAG
    wm = nst.get("watermark")
    if since is not None:
        start = since
    elif isinstance(wm, int):
        start = wm - (DEEP if deep else OVERLAP)
    elif registered is not None:
        # 처음 읽는 노드. 관문은 등록 전 전송을 받지 않으므로 등록 시각 앞 5분부터면 된다
        start = min(dt_ns(registered), end) - OVERLAP
    else:
        start = end - DEEP
    if start >= end:
        return True
    streams = nst.setdefault("streams", {})
    warned = {}
    tot_lines = tot_new = pages = 0
    tot_skip = dict.fromkeys(SKIP_REASONS, 0)
    limit = LIMIT
    complete = True

    def advance(pos):
        if pos > (nst.get("watermark") or 0):
            nst["watermark"] = pos

    cs = start
    while cs < end and complete:
        ce = min(end, cs + CHUNK)
        q = cs
        while True:
            if deadline is not None and time.monotonic() > deadline:
                log(f"{node_id}: 회차 시간 {RUN_SECONDS}초를 넘겨 {iso(q)} 까지 읽고 멈춘다. 다음 회차에 잇는다", 4)
                complete = False
                break
            try:
                entries, bad = loki_query(node_id, q, ce, limit)
            except TooBig:
                if limit <= MIN_LIMIT:
                    raise LokiError(f"{limit}건 응답도 {MAX_RESP:,} B 를 넘는다")
                limit = max(MIN_LIMIT, limit // 10)
                log(f"{node_id}: 응답이 너무 커서 한 번에 {limit}건씩 읽는다", 4)
                continue
            except LokiError as e:
                # Loki 가 5xx 를 내면(내부 gRPC 한도 등) 같은 건수로 다시 묻지 않고 줄여 본다.
                # 가장 작은 건수에서도 실패하면 이번 회차는 실패로 끝내고 다음 회차에 다시 한다 (줄을 건너뛰지 않는다)
                if str(e).startswith("HTTP 5") and limit > MIN_LIMIT:
                    limit = max(MIN_LIMIT, limit // 10)
                    log(f"{node_id}: Loki 오류({safe(e)[:80]}). 한 번에 {limit}건씩 다시 읽는다", 4)
                    continue
                raise
            if bad and not warned.get("shape"):
                log(f"{node_id}: 형식이 틀린 Loki 항목 {bad}개를 건너뛴다", 4)
                warned["shape"] = True
            work = copy.deepcopy(streams)
            lines, new, skipped = process_page(store, agent, node, entries, work, exclusions, warned)
            cap_streams(work)
            streams.clear()
            streams.update(work)            # 커밋한 뒤에만 센 위치를 옮긴다
            pages += 1
            tot_lines += lines
            tot_new += new
            for r, n in skipped.items():
                tot_skip[r] += n
            if len(entries) + bad < limit:
                advance(ce)
                save()
                break
            last = entries[-1][0] if entries else q
            if last <= q:
                # 한 나노초에 limit 건 넘게 있다. 이 API 로는 더 나눠 읽을 수 없어 1ns 건너뛴다
                log(f"{node_id}: {iso(q)} 한 시각에 {limit}건이 넘는다. 남은 줄은 건너뛴다", 3)
                last = q + 1
            q = last
            advance(q)                          # q 앞의 항목은 모두 받았다 (q 시각은 다음 쪽에서 다시 본다)
            save()
        cs = ce
    extra = " · ".join(f"{r} {n:,}" for r, n in tot_skip.items() if n)
    log(f"{node_id}: {iso(start)} ~ {iso(end)} 조회 {pages}회 · 줄 {tot_lines:,} · 신규 {tot_new:,}"
        + (f" · 건너뜀 {extra}" if extra else "") + (" · 깊은 조회" if deep and since is None else ""))
    return complete


# ----------------------------------------------------------------------
#  관문 · 관리 원장
# ----------------------------------------------------------------------

def read_ledger_file(store, agent, name, kind, led, budget, save, folder=None):
    """원장 파일 하나의 새 줄을 넣는다. ({lines, new, bad, forged}, 읽은 바이트) 또는 (None, 0)."""
    path = os.path.join(folder or (ADMIN_DIR if kind == "admin" else GATE_DIR), name)
    try:
        # 관문이 폴더 주인이다. 심볼릭 링크 · FIFO 를 심어 다른 파일을 읽히거나 멈추게 하지 못하게 한다
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        log(f"원장 {safe(name)} 을 열지 못했다 ({safe(e)})", 4)
        return None, 0
    res = dict.fromkeys(("lines", "new", "bad", "forged"), 0)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            log(f"원장 {safe(name)} 이 보통 파일이 아니다. 읽지 않는다", 3)
            return None, 0
        if kind == "admin" and st.st_uid != ADMIN_UID:
            log(f"관리 원장 {safe(name)} 의 주인이 root 가 아니다 (uid {st.st_uid}). 위조 의심으로 읽지 않는다", 3)
            return None, 0
        pos = led.get(name) if isinstance(led.get(name), dict) else {}
        off = pos.get("offset", 0) if pos.get("ino") == st.st_ino else 0
        if pos and pos.get("ino") != st.st_ino:
            log(f"원장 {safe(name)} 파일이 바뀌었다 (inode). 처음부터 다시 읽는다 (중복은 line_hash 로 걸러진다)", 4)
        if off > st.st_size:
            log(f"원장 {safe(name)} 이 줄었다 ({off:,} → {st.st_size:,} B). 처음부터 다시 읽는다", 3)
            off = 0
        start = off
        f.seek(off)
        rows = []
        mark = off

        def flush():
            nonlocal mark
            if rows:
                new, bad = store.insert("events", agent.EVENT_COLUMNS, rows)
                res["new"] += len(new)
                res["bad"] += len(bad)
                rows.clear()
            store.commit()
            if off != mark or pos.get("ino") != st.st_ino:
                led[name] = {"ino": st.st_ino, "offset": off}
                save()
                mark = off

        while off - start < budget:
            raw = f.readline(MAX_LINE + 1)
            if not raw:
                break
            if not raw.endswith(b"\n"):
                if len(raw) <= MAX_LINE:
                    break                       # 쓰는 중인 마지막 줄. 다음 회차에 읽는다
                n, ended = len(raw), False      # 너무 긴 줄. 줄바꿈까지 건너뛴다
                while True:
                    more = f.readline(READ)
                    if not more:
                        break
                    n += len(more)
                    if more.endswith(b"\n"):
                        ended = True
                        break
                if not ended:
                    break                       # 긴 줄이 아직 끝나지 않았다
                off += n
                res["bad"] += 1
                continue
            off += len(raw)
            text = raw[:-1].decode("utf-8", "replace")
            if not text.strip():
                continue
            res["lines"] += 1
            try:
                k, row = agent.parse_collector(text)
            except Exception:
                k, row = "skip", "malformed"
            if k != "event":
                res["bad"] += 1
                continue
            eid = row_get(row, agent.EVENT_COLUMNS, "eventid") or ""
            if (kind == "admin") != eid.startswith("collector.admin."):
                res["forged"] += 1              # 관문 원장에 관리 줄을 끼웠거나, 관리 원장에 관문 줄이 있다
                continue
            rows.append(row_values(row, agent.EVENT_COLUMNS))
            if len(rows) >= LEDGER_BATCH:
                flush()
        flush()
    if res["forged"]:
        log(f"원장 {safe(name)}: 제자리가 아닌 eventid {res['forged']}줄을 넣지 않았다 (위조 의심)", 3)
    return res, off - start


def read_ledgers(store, agent, state, save):
    """관문 · 관리 원장의 새 줄을 넣는다. 끝까지 문제없으면 True."""
    led = state["ledgers"]
    files = []                      # (이름, 종류, 폴더)
    ok = True
    for folder, want in ((GATE_DIR, "collector"), (ADMIN_DIR, "admin")):
        try:
            names = sorted(os.listdir(folder))
        except FileNotFoundError:
            log(f"원장 폴더 {folder} 가 없다", 4)
            continue
        except OSError as e:
            log(f"원장 폴더 {folder} 를 읽지 못했다 ({safe(e)})", 3)
            ok = False
            continue
        for name in names:
            m = LEDGER_RE.fullmatch(name)
            if not m:
                continue
            if m.group(1) != want:
                # 관문 폴더의 admin-* 는 관문이 만든 것이다 (관리 원장은 root 전용 폴더에만 있다)
                log(f"원장 {safe(name)} 이 제자리({want} 폴더)가 아니다. 위조 의심으로 읽지 않는다", 3)
                continue
            files.append((name, want, folder))
    budget = LEDGER_BYTES
    tot = dict.fromkeys(("lines", "new", "bad", "forged"), 0)
    present = set()
    for name, kind, folder in files:
        present.add(name)
        if budget <= 0:
            log("원장 읽기 한도를 넘었다. 나머지는 다음 회차에 읽는다", 4)
            break
        res, used = read_ledger_file(store, agent, name, kind, led, budget, save, folder)
        budget -= used
        if res is None:
            ok = False
            continue
        for k in tot:
            tot[k] += res[k]
    for name in list(led):
        if name not in present:
            del led[name]
    if tot["lines"]:
        log(f"원장: 줄 {tot['lines']:,} · 신규 {tot['new']:,} · 건너뜀 {tot['bad']:,} · 위조 의심 {tot['forged']:,}")
    return ok


# ----------------------------------------------------------------------
#  탐지
# ----------------------------------------------------------------------

def run_detect(env):
    ok = True
    for name in RULESETS:
        cmd = [sys.executable, os.path.join(APP, "detector", "detect.py"),
               "--rules", os.path.join(APP, "detector", name), "--run", "--quiet"]
        try:
            rc = subprocess.run(cmd, env=env, cwd=APP, timeout=DETECT_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            rc = f"{DETECT_TIMEOUT}초 초과"
        except OSError as e:
            rc = safe(e)
        if rc != 0:
            log(f"탐지 실패 {name} ({rc})", 3)
            ok = False
    return ok


# ----------------------------------------------------------------------
#  한 회차
# ----------------------------------------------------------------------

def run(node=None, since=None, ledgers_from_start=False):
    os.makedirs(HOME, exist_ok=True)
    lock = open(os.path.join(HOME, "agents.lock"), "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)        # 타이머 회차와 손 실행(--since)이 겹치지 않게 기다린다
        return _run(node, since, ledgers_from_start)
    finally:
        lock.close()


def _run(node, since, ledgers_from_start=False):
    cleanup_temp(HOME)
    state_path = os.path.join(HOME, "agents-state.json")
    state = load_state(state_path)
    state["runs"] = int(state["runs"]) + 1 if isinstance(state["runs"], int) else 1
    deep = state["runs"] % DEEP_EVERY == 0

    def save():
        save_state(state_path, state)

    env = base_env()
    url = os.environ.get("DATABASE_URL")
    if not url:
        try:
            url = read_env(DB_ENV).get("DATABASE_URL")
        except OSError as e:
            log(f"DB 접속 정보를 읽지 못했다 ({safe(e)})", 3)
    if not url:
        log("DATABASE_URL 이 없다", 3)
        return 1
    env["DATABASE_URL"] = url

    failed = False
    try:
        store = connect(url)
    except Exception as e:
        log(f"DB 에 접속하지 못했다 ({type(e).__name__}). 다음 회차에 다시 한다", 3)
        return 1

    try:
        agent = load_agent()
    except (Exception, SystemExit) as e:
        log(f"파서 parser/parse_agent.py 를 읽지 못했다 ({type(e).__name__}: {safe(e)}). 적재 없이 탐지만 한다", 3)
        agent = None
        failed = True

    if agent is not None:
        exclusions = load_exclusions(os.path.join(APP, "parser", "exclusions.txt"))
        try:
            nodes = store.nodes(node)
        except Exception as e:
            log(f"노드 목록을 읽지 못했다 ({type(e).__name__}: {safe(e)})", 3)
            store.rollback()
            nodes = []
            failed = True
        if node and not nodes:
            log(f"노드 {safe(node)} 가 없거나 active · revoked 가 아니거나 logs 가 비었다", 3)
            failed = True
        now = now_ns()
        # 타이머 회차에만 시간 한도를 둔다. 손으로 하는 재생성(--since)은 끝까지 읽는다
        # (한도에 걸리면 진행 위치가 남지 않아 다시 돌려도 같은 곳에서 멈춘다. 그동안 타이머 회차는 잠금을 기다린다)
        deadline = None if since is not None else time.monotonic() + RUN_SECONDS
        for n in nodes:
            node_id = n[0]
            if not isinstance(node_id, str) or not NODE_RE.fullmatch(node_id):
                log(f"노드 이름 {safe(node_id)} 은 테넌트로 쓸 수 없다. 건너뛴다", 3)
                failed = True
                continue
            if not n[1]:
                log(f"{node_id}: nodes.hostname 이 비었다. 모든 줄이 foreign_host 로 빠진다", 4)
            nst = state["nodes"].setdefault(node_id, {})
            try:
                if not pull_node(store, agent, n, nst, exclusions, now, deep, save,
                                 since=since, deadline=deadline):
                    failed = failed or since is not None
            except LokiError as e:
                log(f"{node_id}: Loki 조회 실패 ({safe(e)}). 이 노드는 다음 회차에 다시 읽는다", 3)
                failed = True
            except Exception as e:
                log(f"{node_id}: 적재 실패 ({type(e).__name__}: {safe(e)}). 워터마크는 그대로 둔다", 3)
                failed = True
                try:
                    store.rollback()
                except Exception:
                    pass
        if ledgers_from_start:
            # DB 를 백업에서 복원한 뒤: 원장을 처음부터 다시 넣는다. 이미 있는 줄은 line_hash 로 걸러진다
            state["ledgers"] = {}
            log("관문 · 관리 원장을 처음부터 다시 읽는다")
        try:
            if not read_ledgers(store, agent, state, save):
                failed = True
        except Exception as e:
            log(f"원장 적재 실패 ({type(e).__name__}: {safe(e)})", 3)
            failed = True
            try:
                store.rollback()
            except Exception:
                pass
    save()
    try:
        store.close()
    except Exception:
        pass

    if not run_detect(env):
        failed = True
    return 1 if failed else 0


def parse_since(v):
    t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return dt_ns(t)


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 관제 대상 로그 다리 (Loki · 관문 원장 → events, 자기 탐지)")
    ap.add_argument("--node", help="이 노드만 읽는다")
    ap.add_argument("--since", help="--node 와 함께. 그 시각(ISO 8601)부터 다시 읽는다 (재생성)")
    ap.add_argument("--ledgers-from-start", action="store_true",
                    help="관문 · 관리 원장을 처음부터 다시 읽는다 (DB 를 백업에서 복원한 뒤)")
    args = ap.parse_args()
    since = None
    if args.since:
        if not args.node:
            ap.error("--since 는 --node 와 함께 쓴다")
        try:
            since = parse_since(args.since)
        except ValueError:
            ap.error(f"시각을 읽지 못했다: {args.since}")
    if os.geteuid() == 0:
        # root 로 돌면 상태 파일이 root 소유가 되어 타이머(opsloop-pull)가 다음부터 쓰지 못한다
        sys.exit("root 로 돌리지 않는다: sudo -u opsloop-pull python3 " + os.path.abspath(__file__) + " ...")
    sys.exit(run(args.node, since, ledgers_from_start=args.ledgers_from_start))


if __name__ == "__main__":
    main()
