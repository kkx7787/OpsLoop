#!/usr/bin/env python3
"""DB 복원 훈련 도구 (이슈 #45). Mac 에서 돈다. 표준 라이브러리만 쓴다.

범위  DB 인스턴스 손실. data01 호스트와 원장(S3 · Loki · 관문 · 관리 원장)은 살아 있다고 본다.
      훈련 DB 는 data01 의 별도 컨테이너(opsloop-drill-db · 127.0.0.1:5433 · cluster_name=opsloop-drill)다.
      운영 DB(opsloop-db)는 읽기만 한다(opsloop_backup 역할 + default_transaction_read_only=on).
      운영 타이머 · 컨테이너 · 방화벽 · HAProxy 는 건드리지 않는다. 콘솔은 Mac 에 따로 띄운다(127.0.0.1 에만).
사용 (Mac, 저장소 루트)
  python3 infra/vmware/restore-drill/drill.py --list
  python3 infra/vmware/restore-drill/drill.py <회차 폴더> <단계>            드라이런. 돌릴 명령 · SQL 만 찍는다
                                                                            (ssh · docker · curl 을 하나도 부르지 않는다)
  python3 infra/vmware/restore-drill/drill.py <회차 폴더> <단계> --apply    실제로 돌린다 (앞 단계가 성공해야 한다)
  회차 폴더(예: ~/opsloop-drill/r01)에 state.json · records.jsonl · marks.jsonl 이 쌓인다(0700). 저장소 밖에 둔다.

단계 (차례대로. RTO 시각 표시는 infra/vmware/failover/mark.py 의 marks.jsonl 꼴 'rto:<단계>')
  precheck  읽기만. 시계 · 메모리 · 디스크 · 5433 비어 있음 · 이미지 · 덤프와 역할 목록 고르기 · sha256 ·
            Archive created(T_b) · 백업 간격 · 운영 기준값(읽기 전용) · 콘솔 A 이미지
  t0        rto:T0 장애 선언 · 운영 now() = T_f (DB 시계)
  up        rto:S1 백업 선택 · 훈련 DB 컨테이너(docker run, compose 아님, initdb 마운트 없음) · rto:S2
  roles     역할 목록(globals.sql)의 CREATE/ALTER ROLE · GRANT 적용 · 로그인 역할마다 훈련 전용 새 비밀번호 · rto:S3
  restore   덤프를 ssh 표준 입력으로 pg_restore --no-owner --exit-on-error · 23개 표 건수 · 목차 대조 · rto:S4
  verify    훈련 쪽 지문 → 무결성(0 이어야 함) · 구조 · 시퀀스 · 역할별 허용 · 거부 → 알림 채널 끄기 · rto:S5
  console   Mac 에 console-a 이미지 · SSH 터널 · 콘솔(127.0.0.1:18000) · /health · rto:S6
            사람이 로그인해 목록 · 상세 · 판정 1건을 확인한 뒤: console --confirm → rto:S7 (서비스 재개, 중간 지표)
  regen     data01 에서 훈련 HOME · 훈련 env 로 opsloop-ingest --full · pull_loki --since T_b−1시간 · rto:S8
  compare   따라잡기 한 회차 → T_r. [T_b−1시간, T_r−30분) 의 events · sessions · node_metrics 를 운영과 같은 문장으로 대조
            (창 끝이 T_b 뒤 15분 이상이어야 한다. 그래서 T_b + 45분 뒤에 돌린다. 이르면 멈추고 다시 돌리라고 알린다)
  done      무결성 재확인 · 지문 대조(운영) · RPO · T_b 하한 확인 → rto:S9 (RTO 끝)
  cleanup   Mac 콘솔 · 터널 · 비밀 파일 지우기 · 훈련 컨테이너 · 볼륨 · /var/lib/opsloop-drill 지우기 · 운영 이상 없음 확인
  report    docs/evidence/<T0 KST 날짜>-restore/results.json · sha256.json (비밀 문자열이 있으면 쓰지 않는다)

다시 돌리기
  단계가 ✘ 로 끝나면 원인을 고치고 그 단계를 다시 돌린다(… 는 참고라 멈추지 않는다).
  up · roles · restore 는 이미 있는 컨테이너 · 역할 · 표 때문에 다시 돌릴 수 없다. cleanup --apply 뒤 up 부터 다시 한다(T0 는 그대로).
  verify 를 다시 돌리면 훈련 쪽 지문은 그 복원 뒤 처음 뜬 것을 쓴다(첫 verify 의 알림 끄기가 훈련 DB 를 이미 바꿨다).
  console(S6 · S7)과 regen(S8)은 둘 다 verify 뒤라 어느 쪽을 먼저 해도 RTO 순서는 맞다. done 은 둘 다 끝나야 한다.
  운영 읽기는 opsloop_backup(접속 한도 2)을 쓴다. 04:30 · 16:30 백업 · 00:10 CTI 수집과 겹치지 않게 한다(precheck · regen 이 알린다).

비밀값
  훈련 DB 슈퍼유저 · 역할 비밀번호는 data01 에서 openssl 로 만들어 /var/lib/opsloop-drill/env/*.env(0600)에만 둔다.
  SQL 은 표준 입력으로만 넘긴다. 명령행 · docker inspect · sudo 기록 · 화면 · 기록 파일에 남지 않는다.
  콘솔 DSN 과 훈련용 SESSION_SECRET 은 Mac 의 ~/.config/opsloop/drill/console.env 에 두고 파일로 컨테이너에 준다(cleanup 이 지운다).
  콘솔 로그인은 사람이 한다. 이 도구는 운영자 비밀번호를 다루지 않는다.
종료 코드: 0 · 1 점검 실패 · 2 사용법 · 순서 오류 · 130 중단
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
FAILOVER = os.path.join(ROOT, "infra", "vmware", "failover")
for _p in (HERE, FAILOVER):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import common  # noqa: E402
import mark as markmod  # noqa: E402
import queries as Q  # noqa: E402

# ── 훈련 이름 (한 곳. 운영 이름과 겹치지 않는다 · 시험이 본다) ─────────────────
DRILL_DB = "opsloop-drill-db"
DRILL_VOLUME = "opsloop_drill_pgdata"
DRILL_BIND = "127.0.0.1"
DRILL_PORT = 5433
DRILL_CLUSTER = Q.DRILL_CLUSTER
DRILL_DIR = "/var/lib/opsloop-drill"
DRILL_ENV = DRILL_DIR + "/env"
DRILL_HOME = DRILL_DIR + "/home"
DRILL_MEMORY = "256m"
PG_IMAGE = "postgres:16-alpine"
TUNNEL_PORT = 15433
CONSOLE_NAME = "opsloop-drill-console"
CONSOLE_PORT = 18000
CONSOLE_URL = "http://127.0.0.1:%d" % CONSOLE_PORT
CONSOLE_IMAGE = "opsloop-api:latest"
WORKER = "opsloop-drill"
SECRET_DIR = os.path.join("~", ".config", "opsloop", "drill")
# ── 운영 이름 (읽기 명령에만 나온다) ──────────────────────────────────────
PROD_DB = "opsloop-db"
PROD_READER = "opsloop_backup"
PROD_HOME = "/var/lib/opsloop"
DATA_HOST, CONSOLE_HOST, FW_HOST = "data01", "console-a", "fw"
LOKI_NODE = "web-01"
INGEST_DEFAULTS = "/etc/default/opsloop-ingest"
INGEST_BIN = "/usr/local/bin/opsloop-ingest"
PULL_LOKI = "/opt/opsloop/app/collector/pull_loki.py"
PULL_USER = "opsloop-pull"
BOOTSTRAP_ROLE = "opsloop"
REQUIRED_ROLES = ("opsloop", "opsloop_gate", "opsloop_ingest", "opsloop_detector", "opsloop_console", "opsloop_backup")
PULL_ROLES = ("opsloop_ingest", "opsloop_detector")        # env 파일을 opsloop-pull 이 읽는다
BACKUP_DIR = os.path.join("~", "opsloop-backup")
VERIFY_ROLES_SH = os.path.join(ROOT, "infra", "vmware", "scripts", "verify-db-roles.sh")
RTO_MAX_S, RPO_TARGET_S = 7200, 43200
REGEN_BEFORE_S = 3600          # 재적재 · 대조 창의 시작 = T_b − 1시간
CUT_LAG_S = 1800               # 대조 창의 끝 = T_r − 30분 (늦게 올라오는 조각 여유)
# 대조 창이 T_b 뒤를 적어도 이만큼 덮어야 재생성을 증명한다(센서 업로더 5분 주기 3번). 창 끝이 T_b 앞이면
# 덤프에서 온 행만 견주고도 '일치' 가 된다. 그래서 compare 는 T_b + 45분(= 30분 + 15분) 뒤에 돌린다
REGEN_MIN_AFTER_TB_S = 900
INGEST_OK = (0, 11)            # opsloop-ingest: 0 정상 · 11 생존 신호 이상(적재 · 탐지는 함)
REGEN_MEM_MIN_MB = 600         # 재적재 직전 data01 가용 메모리 하한 (사전 점검과 같은 값. 훈련 DB 가 뜬 뒤에 다시 본다)
# T_b 하한 확인의 여유. Archive created 는 초 단위로 잘리고 pg_dump 가 스냅숏을 잡기 조금 전에 찍힌다.
# 그래서 T_b 직후 몇 초 안에 커밋된 행은 덤프에 들어 있으면서 시각이 T_b 보다 늦을 수 있다
BRACKET_SLACK_S = 10

DRILL_PSQL = "docker exec -i %s psql -X -U %%s -d opsloop -v ON_ERROR_STOP=1 -qAt -f -" % DRILL_DB
PROD_PSQL = ("docker exec -i -e PGOPTIONS=--default_transaction_read_only=on %s psql -X -U %s -d opsloop "
             "-v ON_ERROR_STOP=1 -qAt -f -" % (PROD_DB, PROD_READER))

STEPS = (
    ("precheck", "읽기 점검 · 덤프 · 역할 목록 고르기 · 운영 기준값"),
    ("t0", "rto:T0 장애 선언 · 운영 now() = T_f"),
    ("up", "rto:S1 백업 선택 · 훈련 DB 컨테이너 · rto:S2"),
    ("roles", "역할 · 속성 · 멤버십 · 훈련 전용 비밀번호 · rto:S3"),
    ("restore", "pg_restore · 23개 표 건수 · 목차 대조 · rto:S4"),
    ("verify", "지문 · 무결성 · 구조 · 역할별 허용 · 거부 · 알림 끄기 · rto:S5"),
    ("console", "Mac 콘솔 · 터널 · rto:S6 (--confirm: 판정 반영 확인 · rto:S7)"),
    ("regen", "opsloop-ingest --full · pull_loki --since (훈련 HOME · env) · rto:S8"),
    ("compare", "따라잡기 · 재생성 대조 (운영 읽기 전용)"),
    ("done", "무결성 재확인 · 지문 대조 · RPO · rto:S9"),
    ("cleanup", "Mac 콘솔 · 터널 · 훈련 컨테이너 · 볼륨 · 폴더 지우기 · 운영 확인"),
    ("report", "docs/evidence/<T0 KST 날짜>-restore/ results.json · sha256.json"),
)
STEP_NAMES = tuple(s for s, _ in STEPS)
PREREQ = {"precheck": (), "t0": ("precheck",), "up": ("t0",), "roles": ("up",), "restore": ("roles",),
          "verify": ("restore",), "console": ("verify",), "console-confirm": ("console",), "regen": ("verify",),
          "compare": ("regen",), "done": ("compare", "console-confirm"), "cleanup": ("precheck",),
          "report": ("t0",)}
KST = timezone(timedelta(hours=9))
# 겹치지 않게 피하는 운영 작업 창 (KST). 백업은 opsloop_backup 접속 한도 2 를 이 도구의 운영 읽기와 나눠 쓴다
BUSY = ((0, 5, 0, 15, "CTI 수집(opsloop-cti.timer)"), (4, 25, 4, 40, "04:30 백업 · 복원 시험"),
        (16, 25, 16, 40, "16:30 백업 · 복원 시험"))


def busy_window(now=None):
    """지금(KST)이 운영 작업 창 안이면 그 이름, 아니면 None."""
    t = (now or datetime.now(KST)).astimezone(KST)
    m = t.hour * 60 + t.minute
    for h1, m1, h2, m2, name in BUSY:
        if h1 * 60 + m1 <= m <= h2 * 60 + m2:
            return name
    return None


class ToolError(Exception):
    """사용법 · 순서 오류. 종료 코드 2."""


class StepFail(Exception):
    """점검 실패. 종료 코드 1."""


# ──────────────────────────────────────────────────────────────
#  작은 도우미
# ──────────────────────────────────────────────────────────────
def iso(dt):
    return dt.astimezone(timezone.utc).isoformat() if isinstance(dt, datetime) else None


def from_iso(text):
    if not text:
        return None
    return parse_pg_ts(text)


PG_TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?\s*(?:(Z|UTC)|([+-])(\d\d)(?::?(\d\d))?)?$")


def parse_pg_ts(text):
    """'2026-09-26 07:27:40.123+00' · ISO 8601 → UTC datetime. 못 읽으면 None."""
    m = PG_TS.match((text or "").strip())
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    us = int((m.group(7) or "0").ljust(6, "0"))
    dt = datetime(y, mo, d, h, mi, s, us, tzinfo=timezone.utc)
    if m.group(9):
        off = timedelta(hours=int(m.group(10)), minutes=int(m.group(11) or 0))
        dt = dt - off if m.group(9) == "+" else dt + off
    return dt


def ns_dt(ns):
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tagged(text, tag):
    """'<tag>|a|b' 줄들 → [[a, b], …]."""
    out = []
    for line in (text or "").splitlines():
        if line.startswith(tag + "|"):
            out.append(line.split("|")[1:])
    return out


def kv_lines(text):
    """'키 값…' 줄 → dict (같은 키는 마지막 값)."""
    out = {}
    for line in (text or "").splitlines():
        k, _, v = line.strip().partition(" ")
        if k:
            out[k] = v.strip()
    return out


def to_int(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


# 비밀 문자열 모양. 기록 · 화면 · 증거에 넣기 전에 가린다
SECRET_PATTERNS = (
    ("dsn", re.compile(r"(postgres(?:ql)?://[^:/@\s]+:)(?!\*\*\*@)[^@\s]+@"), r"\1***@"),
    ("password", re.compile(r"(PASSWORD\s+')(?!\*\*\*')[^']*(')", re.I), r"\1***\2"),
    ("env", re.compile(r"\b((?:SESSION_SECRET|POSTGRES_PASSWORD|OPSLOOP_CONSOLE_DB_PASSWORD|DATABASE_URL)=)(?!\*\*\*)\S+"),
     r"\1***"),
    ("webhook", re.compile(r"https://(?!notify\.invalid/)[^\s'\"|]*(?:webhook|office\.com|logic\.azure|powerautomate)"
                           r"[^\s'\"|]*", re.I), "https://***"),
)


def mask(text, extra=()):
    if not isinstance(text, str):
        return text
    for s in extra:
        if s:
            text = text.replace(s, "***")
    for _name, rx, rep in SECRET_PATTERNS:
        text = rx.sub(rep, text)
    return text


def find_secrets(text, extra=()):
    found = [name for name, rx, _ in SECRET_PATTERNS if rx.search(text)]
    found += ["알려진 비밀값" for s in extra if s and s in text]
    return found


def write_private(path, text, mode=0o600):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = "%s.tmp%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, mode)
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ──────────────────────────────────────────────────────────────
#  덤프 · 역할 목록 · 목차
# ──────────────────────────────────────────────────────────────
def parse_archive_header(data: bytes) -> dict:
    """pg_dump -Fc 머리(PGDMP). 생성 시각은 pg_dump 가 돈 곳(운영 컨테이너, TZ=UTC)의 지역 시각 필드다.
    pg_restore --list 의 'Archive created at' 과 같은 값이다. 판 1.15(PG16)부터 압축은 1바이트다."""
    if data[:5] != b"PGDMP":
        raise ValueError("PGDMP 머리가 아니다")
    vmaj, vmin, vrev = data[5], data[6], data[7]
    if (vmaj, vmin) < (1, 14):
        raise ValueError("옛 덤프 판 %d.%d" % (vmaj, vmin))
    isz, osz, fmt = data[8], data[9], data[10]
    p = 11
    if (vmaj, vmin) >= (1, 15):
        comp = data[p]
        p += 1
    else:
        comp = None

    def rint():
        nonlocal p
        sign = data[p]
        v = int.from_bytes(data[p + 1:p + 1 + isz], "little")
        p += 1 + isz
        return -v if sign else v

    if comp is None:
        comp = rint()
    sec, mi, hour, mday, mon, year, isdst = (rint() for _ in range(7))

    def rstr():
        nonlocal p
        n = rint()
        if n < 0:
            return None
        s = data[p:p + n].decode("utf-8", "replace")
        p += n
        return s

    dbname, remote, dumpver = rstr(), rstr(), rstr()
    created = datetime(year + 1900, mon + 1, mday, hour, mi, sec, tzinfo=timezone.utc)
    return {"version": "%d.%d.%d" % (vmaj, vmin, vrev), "format": fmt, "compression": comp, "int_size": isz,
            "off_size": osz, "created": created, "isdst": isdst, "dbname": dbname, "server_version": remote,
            "pg_dump_version": dumpver}


def read_header(path):
    with open(path, "rb") as f:
        return parse_archive_header(f.read(4096))


DUMP_RE = re.compile(r"^opsloop-(\d{8}-\d{4})\.dump$")


def list_backups(bdir):
    """(시각 문자열, 덤프 경로, 역할 목록 경로 또는 None) 을 이름 차례로."""
    out = []
    try:
        names = sorted(os.listdir(bdir))
    except FileNotFoundError:
        return out
    for name in names:
        m = DUMP_RE.match(name)
        if m:
            g = os.path.join(bdir, "opsloop-%s.globals.sql" % m.group(1))
            out.append((m.group(1), os.path.join(bdir, name), g if os.path.isfile(g) else None))
    return out


def pick_backup(bdir, want=None):
    items = list_backups(bdir)
    if want:
        path = os.path.abspath(os.path.expanduser(want))
        for ts, d, g in items:
            if os.path.abspath(d) == path:
                if not g:
                    raise ToolError("이 덤프에는 짝인 역할 목록(.globals.sql)이 없다: %s" % os.path.basename(d))
                return d, g
        raise ToolError("백업 폴더에 그 덤프가 없다: %s" % want)
    paired = [(ts, d, g) for ts, d, g in items if g]
    if not paired:
        raise ToolError("역할 목록(.globals.sql)과 짝인 덤프가 %s 에 없다 (backup-db.sh 새 판이 한 번 돌아야 한다)" % bdir)
    return paired[-1][1], paired[-1][2]


def backup_gaps(times):
    """덤프 생성 시각들 → 간격 최댓값 (실측 최악 RPO)."""
    ts = sorted(t for t in times if t)
    if len(ts) < 2:
        return {"count": len(ts), "max_gap_s": None, "between": None}
    gaps = [((b - a).total_seconds(), a, b) for a, b in zip(ts, ts[1:])]
    g, a, b = max(gaps, key=lambda x: x[0])
    return {"count": len(ts), "first": iso(ts[0]), "last": iso(ts[-1]), "max_gap_s": round(g, 3),
            "between": [iso(a), iso(b)]}


ROLE = r"[a-z_][a-z0-9_]{0,62}"
FLAG = r"(?:NO)?(?:SUPERUSER|INHERIT|CREATEROLE|CREATEDB|LOGIN|REPLICATION|BYPASSRLS)"
GRANT_OPT = r"(?:ADMIN OPTION|INHERIT (?:TRUE|FALSE)|SET (?:TRUE|FALSE))"
RE_CREATE = re.compile(r"^CREATE ROLE (%s);$" % ROLE)
RE_ALTER = re.compile(r"^ALTER ROLE (%s) WITH ((?:%s)(?: %s)*)(?: CONNECTION LIMIT (-?\d+))?(?: VALID UNTIL '[^']*')?;$"
                      % (ROLE, FLAG, FLAG))
RE_GRANT = re.compile(r"^GRANT (%s) TO (%s)(?: WITH (%s(?:, %s)*))?(?: GRANTED BY (%s))?;$"
                      % (ROLE, ROLE, GRANT_OPT, GRANT_OPT, ROLE))


def parse_globals(text, bootstrap=BOOTSTRAP_ROLE):
    """pg_dumpall --globals-only --no-role-passwords 출력 → 훈련 DB 에 적용할 SQL · 역할 속성.
    아는 줄만 받는다. 비밀번호가 든 줄 · 모르는 줄이 있으면 ValueError (그대로 적용하지 않는다).
    초기 슈퍼유저(bootstrap)는 컨테이너가 이미 만들었으므로 CREATE 를 빼고 ALTER 만 둔다."""
    creates, alters, grants = [], [], []
    roles, members = {}, []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("--"):
            continue
        if re.search(r"PASSWORD|SCRAM-SHA-256\$|md5[0-9a-f]{32}", line, re.I):
            raise ValueError("역할 목록 %d번째 줄에 비밀번호가 있다. 적용하지 않는다" % n)
        if re.match(r"^\\(un)?restrict [A-Za-z0-9]+$", line) or re.match(r"^SET [a-z_]+ = [^;]+;$", line):
            continue
        m = RE_CREATE.match(line)
        if m:
            name = m.group(1)
            if not name.startswith("opsloop"):
                raise ValueError("역할 목록 %d번째 줄: opsloop 역할이 아니다 (%s)" % (n, name))
            roles.setdefault(name, {})
            if name != bootstrap:
                creates.append(line)
            continue
        m = RE_ALTER.match(line)
        if m:
            name, flags = m.group(1), m.group(2).split()
            if name not in roles:
                raise ValueError("역할 목록 %d번째 줄: 만들지 않은 역할 %s" % (n, name))
            roles[name] = {"login": "LOGIN" in flags, "inherit": "INHERIT" in flags, "superuser": "SUPERUSER" in flags,
                           "connlimit": int(m.group(3)) if m.group(3) else -1}
            alters.append(line)
            continue
        m = RE_GRANT.match(line)
        if m:
            granted, member, opts = m.group(1), m.group(2), m.group(3) or ""
            if member not in roles or not (granted.startswith("pg_") or granted in roles):
                raise ValueError("역할 목록 %d번째 줄: 모르는 멤버십 %s → %s" % (n, granted, member))
            members.append({"role": granted, "member": member, "inherit": "INHERIT FALSE" not in opts})
            grants.append(line)
            continue
        raise ValueError("역할 목록 %d번째 줄을 알 수 없다: %s" % (n, line[:80]))
    missing = [r for r in REQUIRED_ROLES if r not in roles]
    if missing:
        raise ValueError("역할 목록에 없는 역할: %s" % ", ".join(missing))
    unset = [r for r, v in roles.items() if not v]
    if unset:
        raise ValueError("속성(ALTER ROLE)이 없는 역할: %s" % ", ".join(unset))
    sql = "-- q:roles_apply\n" + "\n".join(creates + alters + grants)
    return {"sql": sql, "roles": roles, "members": members}


def login_specs(roles, bootstrap=BOOTSTRAP_ROLE):
    """비밀번호를 새로 줄 로그인 역할 → (역할, env 이름, 소유자). 초기 슈퍼유저는 컨테이너 비밀번호 파일을 쓴다."""
    out = []
    for name in sorted(roles):
        if name == bootstrap or not roles[name].get("login"):
            continue
        short = name[len("opsloop_"):] if name.startswith("opsloop_") else name
        if not re.match(r"^[a-z][a-z0-9_]{0,30}$", short):
            raise ValueError("역할 이름이 이상하다: %s" % name)
        out.append((name, short, PULL_USER if name in PULL_ROLES else "self"))
    return out


TOC_TYPES = sorted(("TABLE DATA", "SEQUENCE SET", "SEQUENCE OWNED BY", "FK CONSTRAINT", "DEFAULT ACL",
                    "MATERIALIZED VIEW", "TABLE", "SEQUENCE", "FUNCTION", "TRIGGER", "VIEW", "CONSTRAINT", "INDEX",
                    "ACL", "DEFAULT", "COMMENT", "EXTENSION", "SCHEMA", "TYPE", "RULE", "POLICY", "PROCEDURE",
                    "AGGREGATE", "DATABASE", "ENCODING", "STDSTRINGS", "SEARCHPATH"), key=len, reverse=True)


def parse_toc(text):
    """pg_restore --list 출력 → 종류별 수 · 데이터가 든 표 이름 · Archive created."""
    counts, tables, created = {}, [], None
    for line in (text or "").splitlines():
        m = re.search(r"Archive created at (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\s*(\S*)", line)
        if m:
            created = {"at": m.group(1), "tz": m.group(2)}
            continue
        if line.startswith(";") or not line.strip():
            continue
        m = re.match(r"^\d+;\s+\d+\s+\d+\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(1)
        for t in TOC_TYPES:
            if rest.startswith(t + " "):
                counts[t] = counts.get(t, 0) + 1
                if t == "TABLE DATA":
                    parts = rest[len(t) + 1:].split()
                    if len(parts) >= 2 and parts[0] == "public":
                        tables.append(parts[1])
                break
        else:
            counts["기타"] = counts.get("기타", 0) + 1
    return {"counts": counts, "tables": tables, "archive_created": created}


RE_Q = re.compile(r'^\s*q\s+(opsloop_[a-z]+)\s+"(.*)"\s+(거부|허용)\s*$')
RE_P = re.compile(r'^\s*p\s+(opsloop_[a-z]+)\s+"(.*)"\s+([tf])\s*$')


def role_checks(path=VERIFY_ROLES_SH):
    """verify-db-roles.sh 의 q · p 줄 → [{idx, kind, role, stmt, expect}]. 문장은 그대로 쓴다(컨테이너만 훈련 쪽)."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = RE_Q.match(line) or RE_P.match(line)
            if m:
                out.append({"idx": len(out) + 1, "kind": "q" if RE_Q.match(line) else "p", "role": m.group(1),
                            "stmt": m.group(2), "expect": m.group(3)})
    return out


def judge_role_output(checks, outputs):
    """역할별 psql 출력(R <idx> <SQLSTATE> · P <idx> t|f) → 줄마다 결과. 42501 = 거부 · 00000 = 허용."""
    got = {}
    for text in outputs:
        for line in (text or "").splitlines():
            m = re.match(r"^R (\d+) ([0-9A-Z]{5})$", line.strip())
            if m:
                code = m.group(2)
                got[int(m.group(1))] = "허용" if code == "00000" else "거부" if code == "42501" else "오류(%s)" % code
                continue
            m = re.match(r"^P (\d+) ([tf])$", line.strip())
            if m:
                got[int(m.group(1))] = m.group(2)
    rows = []
    for c in checks:
        g = got.get(c["idx"], "결과 없음")
        rows.append({"idx": c["idx"], "role": c["role"], "stmt": c["stmt"], "expect": c["expect"], "got": g,
                     "ok": g == c["expect"]})
    return rows


# ──────────────────────────────────────────────────────────────
#  지표 · 대조
# ──────────────────────────────────────────────────────────────
def rto_marks(records):
    """marks.jsonl 기록 → {'T0': 첫 T0, 'S1'…: 마지막 표시}."""
    out = {}
    for r in records:
        m = re.match(r"^rto:(T0|S[1-9])\b", r.get("note") or "")
        if not m or not isinstance(r.get("t_local_ns"), int):
            continue
        code = m.group(1)
        if code == "T0" and code in out:
            continue
        out[code] = r
    return out


# 표시마다 먼저 있어야 하는 표시. 단계 선행 규칙(PREREQ)과 같다:
# console(S6 · S7)과 regen(S8)은 둘 다 verify(S5) 뒤라 어느 쪽이 먼저여도 되고, done(S9)은 둘 다 끝난 뒤다
RTO_PRED = {"S1": ("T0",), "S2": ("S1",), "S3": ("S2",), "S4": ("S3",), "S5": ("S4",), "S6": ("S5",),
            "S7": ("S6",), "S8": ("S5",), "S9": ("S7", "S8")}


def compute_rto(records, max_s=RTO_MAX_S):
    """RTO = S9 − T0 (Mac 시계). S7 − T0 은 서비스 재개(중간 지표).
    순서: 표시마다 RTO_PRED 의 표시보다 늦어야 한다(다시 돌린 단계는 마지막 표시)."""
    marks = rto_marks(records)
    codes = ["S%d" % i for i in range(1, 10)]
    t0 = marks.get("T0")
    if not t0:
        return {"t0": None, "steps": {}, "service_s": None, "complete_s": None, "max_s": max_s, "pass": False,
                "order_ok": None, "missing": ["T0"] + [c for c in codes if c not in marks]}
    base = t0["t_local_ns"]
    steps = {}
    for c in codes:
        r = marks.get(c)
        if not r:
            steps[c] = None
            continue
        s = round((r["t_local_ns"] - base) / 1e9, 3)
        steps[c] = {"at": iso(ns_dt(r["t_local_ns"])), "since_t0_s": s,
                    "at_remote": iso(ns_dt(r["t_remote_ns"])) if isinstance(r.get("t_remote_ns"), int) else None,
                    "offset_ms": r.get("offset_ms"), "note": r.get("note")}
    at = {c: marks[c]["t_local_ns"] for c in ["T0"] + codes if marks.get(c)}
    order_ok = all(at[c] >= at[p] for c in at if c != "T0" for p in RTO_PRED[c] if p in at)
    service = steps["S7"]["since_t0_s"] if steps.get("S7") else None
    complete = steps["S9"]["since_t0_s"] if steps.get("S9") else None
    return {"t0": iso(ns_dt(base)),
            "t0_remote": iso(ns_dt(t0["t_remote_ns"])) if isinstance(t0.get("t_remote_ns"), int) else None,
            "steps": steps, "service_s": service, "complete_s": complete, "max_s": max_s,
            "pass": complete is not None and complete <= max_s and order_ok, "order_ok": order_ok,
            "missing": [c for c in codes if not steps.get(c)]}


def compute_rpo(tb, tf, loss, drill_verdict_max, prod_verdict_max_tf, regen, gaps, target=RPO_TARGET_S):
    """RPO 세 줄. 시각은 모두 DB 시계(T_b = Archive created · T_f = 장애 선언 때 운영 now()).
    ① S3 센서  ② 관제 대상 로그(Loki · 관문 · 관리 원장)  ③ DB 에만 있는 기록(손실 = (T_b, T_f] 에 생긴 행)."""
    design = round((tf - tb).total_seconds(), 3) if tb and tf else None
    # 판정 기준 손실 = 운영의 T_f 까지 마지막 판정 − 복원 DB 의 마지막 판정 (복원 DB 에 판정이 없으면 T_b 부터)
    if prod_verdict_max_tf is None:
        verdict_loss = 0.0
    else:
        since = drill_verdict_max or tb
        verdict_loss = round(max(0.0, (prod_verdict_max_tf - since).total_seconds()), 3) if since else None
    lost = {k: v.get("until_tf") for k, v in (loss or {}).items()}
    after = {k: v.get("after_tf") for k, v in (loss or {}).items()}
    sens = (regen or {}).get("sensors") or {}
    s3 = {k: v for k, v in sens.items() if k in Q.S3_SENSORS}
    mon = {k: v for k, v in sens.items() if k not in Q.S3_SENSORS}

    def line(items, extra_ok=True):
        if not regen:
            return {"match": None, "loss_rows": None, "sensors": sorted(items)}
        miss = sum(max(0, v.get("prod", {}).get("count", 0) - v.get("drill", {}).get("count", 0)) for v in items.values())
        ok = all(v.get("same") for v in items.values()) and extra_ok
        return {"match": ok, "loss_rows": 0 if ok else miss, "sensors": sorted(items)}

    metrics_ok = (regen or {}).get("node_metrics", {}).get("same", True) if regen else True
    gap = (gaps or {}).get("max_gap_s")
    lines = {
        "s3_sensor": line(s3),
        "monitored_logs": line(mon, metrics_ok),
        "db_only": {"design_s": design, "lost_rows": lost, "after_tf_rows": after, "verdict_loss_s": verdict_loss},
    }
    # 합격은 이번 복원의 설계 RPO(T_f − T_b)와 재생성 두 줄로 본다. 보관 덤프 간격 최댓값(실측 최악)은 backup_gap_ok 로
    # 따로 적는다. 04:30 · 16:30 백업은 덤프 시각이 몇 초만 밀려도 간격이 43200 초를 넘으므로, 합격에 섞으면
    # 설계 RPO 가 목표 안이어도 'RPO 설계 … 불합격' 으로 찍힌다
    passed = (design is not None and 0 <= design <= target
              and lines["s3_sensor"]["match"] is not False and lines["monitored_logs"]["match"] is not False)
    return {"t_b": iso(tb), "t_f": iso(tf), "design_s": design, "target_s": target, "backup_gap_max_s": gap,
            "backup_gap_ok": None if gap is None else gap <= target, "lines": lines, "pass": passed}


def parse_fingerprints(text):
    """'f|표|열쇠|md5|시각' 줄 → {표: {열쇠: [md5, 시각]}}. 열쇠 안의 '|' 는 SQL 이 '/' 로 바꿨다."""
    out = {}
    for f in tagged(text, "f"):
        if len(f) < 4:
            continue
        table, key, md, ts = f[0], "|".join(f[1:-2]), f[-2], f[-1]
        out.setdefault(table, {})[key] = [md, ts]
    return out


def agg_md5(rows):
    return hashlib.md5(",".join("%s=%s" % (k, rows[k][0]) for k in sorted(rows)).encode()).hexdigest()


def diff_fingerprints(drill, prod, tf=None):
    """훈련(복원 직후) 행 지문 vs 운영(지금). 운영에만 있는 행 = T_b 뒤에 생김, 바뀐 행 = T_b 뒤에 바뀜 → 손실.
    행의 시각(생기거나 바뀐 때)으로 T_f 까지(손실)와 T_f 뒤(훈련 중 운영에서 생김)를 나눈다.
    바뀐 때를 모르는 행(시각이 T_f 이하로 남은 열)은 손실 쪽에 센다.
    추가만 되는 기록(판정 · 조치 · 감사)은 바뀐 행 · 훈련에만 있는 행이 0 이어야 한다."""
    out = {}
    for table in sorted(set(drill) | set(prod)):
        d, p = drill.get(table, {}), prod.get(table, {})
        changed = [k for k in d if k in p and p[k][0] != d[k][0]]
        drill_only = sum(1 for k in d if k not in p)
        prod_only = [k for k in p if k not in d]
        until, after = 0, 0
        for k in prod_only + changed:
            t = parse_pg_ts(p[k][1])
            if tf is not None and t is not None and t > tf:
                after += 1
            else:
                until += 1
        immutable = table in Q.IMMUTABLE
        out[table] = {"drill_rows": len(d), "prod_rows": len(p), "same": len(d) - len(changed) - drill_only,
                      "changed": len(changed), "drill_only": drill_only, "prod_only": len(prod_only),
                      "until_tf": until, "after_tf": after, "immutable": immutable,
                      "ok": (not changed and drill_only == 0) if immutable else True,
                      "drill_md5": agg_md5(d), "prod_md5": agg_md5(p)}
    return out


def parse_regen(text):
    ev = {f[0]: {"count": to_int(f[1], 0), "md5": f[2]} for f in tagged(text, "e") if len(f) >= 3}
    s = tagged(text, "s")
    m = {f[0]: {"count": to_int(f[1], 0), "md5": f[2]} for f in tagged(text, "m") if len(f) >= 3}
    i = tagged(text, "i")
    x = tagged(text, "x")
    return {"events": ev, "sessions": {"count": to_int(s[0][0], 0), "md5": s[0][1]} if s and len(s[0]) >= 2 else None,
            "node_metrics": m, "incidents": {"count": to_int(i[0][0], 0), "md5": i[0][1]} if i and len(i[0]) >= 2 else None,
            "fixture": to_int(x[0][1], 0) if x and len(x[0]) >= 2 else None}


def regen_compare(drill_text, prod_text):
    d, p = parse_regen(drill_text), parse_regen(prod_text)
    sensors = {}
    for s in sorted(set(d["events"]) | set(p["events"])):
        a, b = d["events"].get(s, {"count": 0, "md5": "-"}), p["events"].get(s, {"count": 0, "md5": "-"})
        sensors[s] = {"drill": a, "prod": b, "same": a == b}
    nm_same = d["node_metrics"] == p["node_metrics"]
    sess_same = d["sessions"] == p["sessions"]
    return {"sensors": sensors, "sessions": {"drill": d["sessions"], "prod": p["sessions"], "same": sess_same},
            "node_metrics": {"drill": d["node_metrics"], "prod": p["node_metrics"], "same": nm_same},
            "incidents_ref": {"drill": d["incidents"], "prod": p["incidents"],
                              "same": d["incidents"] == p["incidents"]},
            "fixture_rows": {"drill": d["fixture"], "prod": p["fixture"]},
            "match": all(v["same"] for v in sensors.values()) and nm_same and sess_same}


def time_v(stderr):
    """/usr/bin/time -v 의 최대 RSS(kB) · 걸린 시간(초)."""
    rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", stderr or "")
    el = re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)", stderr or "")
    secs = None
    if el:
        parts = [float(x) for x in el.group(1).split(":")]
        secs = 0.0
        for x in parts:
            secs = secs * 60 + x
    return {"max_rss_kb": int(rss.group(1)) if rss else None, "elapsed_s": round(secs, 2) if secs is not None else None}


def chrony_offset(text):
    m = re.search(r"System time\s*:\s*([\d.]+) seconds (slow|fast)", text or "")
    if not m:
        return None
    v = float(m.group(1))
    return -v if m.group(2) == "slow" else v


# ──────────────────────────────────────────────────────────────
#  실행기 · 상태
# ──────────────────────────────────────────────────────────────
class FileIn:
    """표준 입력으로 흘려 넣을 로컬 파일 (덤프)."""

    def __init__(self, path):
        self.path = path


class Result:
    def __init__(self, rc=0, out="", err="", dry=False):
        self.rc, self.out, self.err, self.dry = rc, out, err, dry


class State:
    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, "state.json")
        try:
            with open(self.path, encoding="utf-8") as f:
                self.data = json.load(f)
        except (FileNotFoundError, ValueError):
            self.data = {}

    def get(self, *keys, default=None):
        cur = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    def save(self):
        write_private(self.path, json.dumps(self.data, ensure_ascii=False, indent=1, sort_keys=True) + "\n")


def ssh_argv(host, command):
    return common.ssh_base() + [host, command]


def tag_of(text):
    m = re.search(r"(?:--|#) ([qs]:[A-Za-z0-9_]+)", text or "")
    return m.group(1) if m else None


class Ctx:
    """한 단계의 실행 환경. 드라이런이면 명령 · 스크립트 · SQL 을 찍기만 하고 아무것도 부르지 않는다."""

    def __init__(self, args, run_dir, step, state):
        self.args, self.run_dir, self.step, self.state = args, run_dir, step, state
        self.apply = bool(args.apply)
        self.secrets = []
        self.checks = []
        self._rec = common.JsonlWriter(os.path.join(run_dir, "records.jsonl")) if self.apply else None

    # ── 출력 ──
    def say(self, msg=""):
        print(mask(msg, self.secrets), flush=True)

    def show(self, head, body=None, label="원격"):
        print("  $ " + head)
        if body is not None:
            print("    <<'%s'" % label)
            for line in body.rstrip("\n").splitlines():
                print("    " + line)
            print("    %s" % label)

    # ── 실행 ──
    def run(self, name, argv, stdin=None, secret_out=False, ok=(0,), timeout=600, display=None, record=True,
            detach=False):
        """argv 를 돌린다. stdin: None · str · bytes · FileIn. ok 밖의 종료 코드면 StepFail.
        detach: 뒤로 도는 자식을 남기는 명령(ssh -f). 출력을 파이프가 아니라 임시 파일로 받는다.
        파이프로 받으면 뒤로 돈 자식이 파이프를 쥐고 있어 끝(EOF)을 기다리며 timeout 까지 멈춘다."""
        if not self.apply:
            head, body, label = display or (" ".join(shlex.quote(a) for a in argv), None, "원격")
            if isinstance(stdin, FileIn):
                head += " < " + shlex.quote(stdin.path)
            self.show(head, body if body is not None else (stdin if isinstance(stdin, str) else None),
                      label if body is not None else "표준입력")
            return Result(dry=True)
        start = time.time_ns()
        t = time.monotonic()
        fh = None
        try:
            if isinstance(stdin, FileIn):
                fh = open(stdin.path, "rb")
                p = subprocess.run(argv, stdin=fh, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                rc, out, err = p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
            elif detach:
                with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
                    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe, timeout=timeout)
                    fo.seek(0)
                    fe.seek(0)
                    rc, out, err = p.returncode, fo.read().decode("utf-8", "replace"), fe.read().decode("utf-8", "replace")
            else:
                data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
                p = subprocess.run(argv, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                rc, out, err = p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
        except FileNotFoundError:
            rc, out, err = 127, "", "%s 없음" % argv[0]
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", "%d초 초과" % timeout
        finally:
            if fh:
                fh.close()
        if record:
            self.record(name, argv, stdin, start, time.monotonic() - t, rc, out, err, secret_out, display)
        if rc not in ok:
            last = [x for x in mask(err, self.secrets).strip().splitlines() if x.strip()][-3:]
            raise StepFail("%s: 종료 코드 %d%s" % (name, rc, (" · " + " / ".join(last)) if last else ""))
        return Result(rc, out, err)

    def pipe(self, name, argv1, argv2, timeout=1800):
        """argv1 | argv2 (보내는 쪽 출력은 받는 쪽 표준 입력으로만 흐른다)."""
        if not self.apply:
            self.show(" ".join(shlex.quote(a) for a in argv1) + " | " + " ".join(shlex.quote(a) for a in argv2))
            return Result(dry=True)
        start, t = time.time_ns(), time.monotonic()
        p1 = subprocess.Popen(argv1, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            p2 = subprocess.run(argv2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            rc2, out, err2 = p2.returncode, p2.stdout.decode("utf-8", "replace"), p2.stderr.decode("utf-8", "replace")
        except FileNotFoundError:
            rc2, out, err2 = 127, "", "%s 없음" % argv2[0]
        except subprocess.TimeoutExpired:
            rc2, out, err2 = 124, "", "%d초 초과" % timeout
        finally:
            p1.stdout.close()
        if rc2 != 0 and p1.poll() is None:
            p1.kill()
        err1 = p1.stderr.read().decode("utf-8", "replace")
        rc1 = p1.wait()
        rc = rc1 or rc2
        err = err1 + err2
        self.record(name, argv1 + ["|"] + argv2, None, start, time.monotonic() - t, rc, out, err, False, None)
        if rc != 0:
            raise StepFail("%s: 종료 코드 %d · %s" % (name, rc, mask(err, self.secrets).strip()[-200:]))
        return Result(rc, out, err)

    def sh(self, name, host, script, stdin=None, ok=(0,), timeout=600):
        """원격 bash 스크립트. 스크립트는 명령행으로 가고(비밀 없음), 표준 입력은 데이터(덤프) 차지다."""
        head = "ssh %s bash -c" % host + ((" < " + shlex.quote(stdin.path)) if isinstance(stdin, FileIn) else "")
        return self.run(name, ssh_argv(host, "bash -c " + shlex.quote(script)), stdin=stdin, ok=ok, timeout=timeout,
                        display=(head, script, "원격"))

    def drill(self, name, body, role="opsloop", ok=(0,), timeout=600):
        """훈련 DB 에 SQL. 맨 앞에 cluster_name 확인 블록이 붙는다."""
        if not Q.IDENT.match(role):
            raise ToolError("역할 이름이 이상하다: %s" % role)
        cmd = DRILL_PSQL % role
        return self.run(name, ssh_argv(DATA_HOST, cmd), stdin=Q.drill_sql(body), ok=ok, timeout=timeout,
                        display=("ssh %s %s" % (DATA_HOST, cmd), Q.drill_sql(body), "훈련SQL"))

    def prod(self, name, body, timeout=600):
        """운영 DB 읽기 (opsloop_backup · default_transaction_read_only=on). 쓰기 문장이면 보내지 않는다."""
        try:
            sql = Q.prod_sql(body)
        except Q.SqlError as e:
            raise ToolError(str(e))
        return self.run(name, ssh_argv(DATA_HOST, PROD_PSQL), stdin=sql, timeout=timeout,
                        display=("ssh %s %s" % (DATA_HOST, PROD_PSQL), sql, "운영읽기"))

    def record(self, name, argv, stdin, start, seconds, rc, out, err, secret_out, display):
        if not self._rec:
            return
        cmd = argv[-1] if argv else ""
        if display and display[1] is not None:
            short = "%s [%s · sha256 %s]" % (display[0], tag_of(display[1]) or "-",
                                            hashlib.sha256(display[1].encode()).hexdigest()[:12])
        else:
            short = " ".join(shlex.quote(a) for a in argv)
        if isinstance(stdin, FileIn):
            sin = "파일 %s" % os.path.basename(stdin.path)
        elif isinstance(stdin, (str, bytes)):
            b = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
            sin = "%d 바이트 sha256 %s" % (len(b), hashlib.sha256(b).hexdigest()[:12])
        else:
            sin = None
        self._rec.write({"step": self.step, "name": name, "start": common.iso(start), "seconds": round(seconds, 3),
                         "rc": rc, "cmd": mask(short[:600], self.secrets), "stdin": sin, "kind": "cmd",
                         "stdout": ("(가림 · %d 바이트)" % len(out)) if secret_out else mask(out[-3000:], self.secrets),
                         "stderr": mask(err[-3000:], self.secrets), "remote_cmd_sha256": hashlib.sha256(
                             cmd.encode()).hexdigest()[:12]})

    def record_step(self, start, seconds, rc):
        if self._rec:
            self._rec.write({"step": self.step, "name": self.step, "start": common.iso(start),
                             "seconds": round(seconds, 3), "rc": rc, "kind": "step"})
            self._rec.close()

    # ── 시각 표시 · 점검 ──
    def mark(self, code, text):
        note = "rto:%s %s" % (code, text)
        if not self.apply:
            self.say("  표시: %s (marks.jsonl · %s 시각)" % (note, DATA_HOST))
            return
        markmod.main([self.run_dir, "note", "--host", DATA_HOST, "--text", note])

    def check(self, what, ok, value="", warn=False):
        """점검 한 줄. 드라이런이면 할 일만 적는다."""
        if not self.apply:
            self.say("  확인: %s" % what)
            return True
        self.checks.append({"what": what, "ok": bool(ok), "value": value, "warn": warn})
        sign = "✔" if ok else ("…" if warn else "✘")
        self.say("  %s %s%s" % (sign, what, (" · %s" % value) if value not in ("", None) else ""))
        return ok

    def failed(self):
        return [c for c in self.checks if not c["ok"] and not c["warn"]]

    def save(self):
        if self.apply:
            self.state.save()


# ──────────────────────────────────────────────────────────────
#  원격 스크립트 (비밀값은 원격에서만 만든다 · 표준 입력으로만 넘긴다)
# ──────────────────────────────────────────────────────────────
def fill(template, **kw):
    for k, v in kw.items():
        template = template.replace("@@%s@@" % k, str(v))
    if "@@" in template:
        raise ToolError("스크립트 자리표시가 남았다: %s" % template[template.index("@@"):][:30])
    return template


# 훈련 DB 에 SQL 을 보낼 때는 이 함수만 쓴다. 맨 앞에 cluster_name 확인 블록(queries.DRILL_HEAD)이 붙는다
SH_LIB = """set -euo pipefail
cd /
C=@@DB@@
GUARD=$(cat <<'__GUARD__'
@@HEAD@@__GUARD__
)
drill_psql() { { printf '%s\\n' "$GUARD"; cat; } | docker exec -i "$C" psql -X -U "${1:-opsloop}" -d opsloop -v ON_ERROR_STOP=1 -qAt -f -; }
"""


def sh_lib():
    return fill(SH_LIB, DB=DRILL_DB, HEAD=Q.DRILL_HEAD)


def script_precheck():
    return fill("""# s:precheck
set -uo pipefail
cd /
kv() { printf '%s %s\\n' "$1" "${2:-}"; }
chronyc -n tracking 2>/dev/null | grep -E '^(Reference ID|System time|Leap status)' | sed 's/^/chrony /'
kv mem_avail_mb "$(free -m | awk 'NR==2 {print $7}')"
kv disk_free_mb "$(df -Pm /var/lib | awk 'NR==2 {print $4}')"
kv port_listen "$(ss -ltnH 'sport = :@@PORT@@' | wc -l)"
kv image "$(docker image inspect -f '{{.Id}}' @@IMAGE@@ 2>/dev/null)"
kv prod_image "$(docker inspect -f '{{.Image}}' @@PROD_DB@@ 2>/dev/null)"
kv drill_container "$(docker ps -a --filter 'name=^@@DB@@$' --format '{{.Names}}' | wc -l)"
kv drill_volume "$(docker volume ls -q --filter 'name=^@@VOL@@$' | wc -l)"
kv drill_dir "$([ -e @@DIR@@ ] && echo 1 || echo 0)"
kv pull_user "$(id -u @@PULL@@ 2>/dev/null || echo -)"
kv ingest_bin "$([ -x @@INGEST@@ ] && echo 1 || echo 0)"
kv pull_loki "$([ -r @@LOKI@@ ] && echo 1 || echo 0)"
kv defaults_home "$(grep -c '^OPSLOOP_HOME=' @@DEFAULTS@@ 2>/dev/null)"
kv defaults_dburl "$(grep -c '^DATABASE_URL=' @@DEFAULTS@@ 2>/dev/null)"
kv sudo "$(sudo -n true 2>/dev/null && echo 1 || echo 0)"
kv time "$([ -x /usr/bin/time ] && echo 1 || echo 0)"
kv choom "$([ -x /usr/bin/choom ] && echo 1 || echo 0)"
kv docker_group "$(id -nG | tr ' ' '\\n' | grep -cx docker)"
""", PORT=DRILL_PORT, IMAGE=PG_IMAGE, PROD_DB=PROD_DB, DB=DRILL_DB, VOL=DRILL_VOLUME, DIR=DRILL_DIR, PULL=PULL_USER,
                INGEST=INGEST_BIN, LOKI=PULL_LOKI, DEFAULTS=INGEST_DEFAULTS)


def script_up():
    return "# s:up\n" + sh_lib() + fill("""D=@@DIR@@; E=@@ENV@@; H=@@HOME@@
me=$(id -un)
sudo -n install -d -m 755 -o root -g root "$D"
sudo -n install -d -m 711 -o "$me" -g "$(id -gn)" "$E"
sudo -n install -d -m 700 -o @@PULL@@ -g @@PULL@@ "$H"
umask 077
[ -s "$E/superuser.pw" ] || openssl rand -hex 24 > "$E/superuser.pw"
chmod 600 "$E/superuser.pw"
# 슈퍼유저 비밀번호는 파일로만 준다 (명령행 · docker inspect 에 남지 않는다. 시작 스크립트가 root 로 읽는다)
# compose 를 쓰지 않는다 (운영 compose 프로젝트와 섞이지 않게). initdb 폴더도 붙이지 않는다
# 메모리 한도 256m 안에서 재적재 · 재탐지를 버티게 공유 버퍼를 64MB 로 줄인다 (이미지 기본 128MB)
# data01 은 스왑이 0 이다. 호스트 메모리가 모자라면 커널이 운영 DB · Loki 보다 훈련 DB 를 먼저 죽이게 OOM 점수를 올린다
docker run -d --pull never --name "$C" --restart no --memory @@MEM@@ --oom-score-adj 1000 \\
  -p @@BIND@@:@@PORT@@:5432 -v @@VOL@@:/var/lib/postgresql/data \\
  -v "$E/superuser.pw:/run/opsloop-drill/superuser.pw:ro" \\
  -e POSTGRES_USER=opsloop -e POSTGRES_DB=opsloop -e POSTGRES_PASSWORD_FILE=/run/opsloop-drill/superuser.pw -e TZ=UTC \\
  --label opsloop.drill=1 @@IMAGE@@ -c cluster_name=@@CLUSTER@@ -c shared_buffers=64MB >/dev/null
ready=0
for i in $(seq 1 90); do
  if docker logs "$C" 2>&1 | grep -c 'init process complete' >/dev/null \\
     && docker exec "$C" pg_isready -q -h 127.0.0.1 -p 5432 -U opsloop -d opsloop </dev/null; then ready=1; break; fi
  sleep 2
done
echo "ready $ready"
if [ "$ready" != 1 ]; then docker logs --tail 20 "$C" 2>&1 | sed 's/^/log /'; exit 1; fi
echo "cluster $(docker exec "$C" psql -X -U opsloop -d opsloop -qAtc 'SHOW cluster_name' </dev/null)"
echo "bind $(docker port "$C" 5432/tcp | head -1)"
echo "memory $(docker inspect -f '{{.HostConfig.Memory}}' "$C")"
echo "oom_adj $(docker inspect -f '{{.HostConfig.OomScoreAdj}}' "$C")"
echo "image $(docker inspect -f '{{.Image}}' "$C")"
echo "env_password $(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$C" | grep -c '^POSTGRES_PASSWORD=' || true)"
echo "initdb_mounts $(docker inspect -f '{{range .Mounts}}{{println .Destination}}{{end}}' "$C" | grep -c 'docker-entrypoint-initdb' || true)"
""", DIR=DRILL_DIR, ENV=DRILL_ENV, HOME=DRILL_HOME, PULL=PULL_USER, MEM=DRILL_MEMORY, BIND=DRILL_BIND,
        PORT=DRILL_PORT, VOL=DRILL_VOLUME, IMAGE=PG_IMAGE, CLUSTER=DRILL_CLUSTER)


def _specs_words(specs):
    return " ".join("%s:%s:%s" % s for s in specs)


def script_passwords(specs):
    return "# s:passwords\n" + sh_lib() + fill("""E=@@ENV@@
me=$(id -un)
umask 077
put() { # $1 파일  $2 소유자. 표준 입력을 0600 으로 쓴다 (sudo 기록에는 경로만 남는다)
  if [ "$2" = "$me" ]; then cat > "$1.tmp"; chmod 600 "$1.tmp"; mv "$1.tmp" "$1"
  else sudo -n install -m 600 -o "$2" -g "$2" /dev/stdin "$1"; fi
}
DSN_HOST=@@BIND@@:@@PORT@@
for spec in @@SPECS@@; do
  IFS=: read -r role name owner <<< "$spec"
  [ "$owner" = self ] && owner=$me
  # 훈련 전용 새 비밀번호. 운영 비밀번호를 쓰지 않으므로 DSN 착오는 인증 실패로 끝난다
  pw=$(openssl rand -hex 24)
  printf "ALTER ROLE %s PASSWORD '%s';\\n" "$role" "$pw" | drill_psql
  printf 'DATABASE_URL=postgresql://%s:%s@%s/opsloop\\n' "$role" "$pw" "$DSN_HOST" | put "$E/$name.env" "$owner"
  pw=
  echo "env $role $name.env $owner"
done
""", ENV=DRILL_ENV, BIND=DRILL_BIND, PORT=DRILL_PORT, SPECS=_specs_words(specs))


# DSN 파일을 읽어 형식 · 대상 · cluster_name 을 본다. 비밀번호는 찍지 않는다
PY_DSN_CHECK = r'''import re, sys
import psycopg2
path = sys.argv[1]
url = None
with open(path, encoding="utf-8") as f:
    for line in f:
        if line.startswith("DATABASE_URL="):
            url = line.split("=", 1)[1].strip()
name = path.rsplit("/", 1)[-1]
if not re.fullmatch(r"postgresql://[a-z_]+:[0-9a-f]{48}@127\.0\.0\.1:@@PORT@@/opsloop", url or ""):
    print("bad", name, "형식 · 대상")
    sys.exit(1)
c = psycopg2.connect(url, connect_timeout=10)
cur = c.cursor()
cur.execute("SELECT current_user, current_setting('cluster_name')")
u, cl = cur.fetchone()
c.close()
print("ok", name, u, cl)
'''


def script_roles_check(specs):
    return fill("""# s:roles_check
set -uo pipefail
cd /
E=@@ENV@@
CHECK=$(cat <<'__PY__'
@@PY@@__PY__
)
for spec in @@SPECS@@; do
  IFS=: read -r role name owner <<< "$spec"
  if [ "$owner" = self ]; then python3 -c "$CHECK" "$E/$name.env" || echo "bad $name.env 접속"
  else sudo -n -u "$owner" python3 -c "$CHECK" "$E/$name.env" || echo "bad $name.env 접속"; fi
  echo "mode $name.env $(sudo -n stat -c '%a %U' "$E/$name.env")"
done
""", ENV=DRILL_ENV, PY=fill(PY_DSN_CHECK, PORT=DRILL_PORT), SPECS=_specs_words(specs))


def script_restore():
    return fill("""# s:restore
set -euo pipefail
C=@@DB@@
# 복원은 훈련 컨테이너에만 한다. cluster_name 이 다르면 표준 입력(덤프)을 읽지 않고 멈춘다
[ "$(docker exec "$C" psql -X -U opsloop -d opsloop -qAtc 'SHOW cluster_name' </dev/null)" = @@CLUSTER@@ ] \\
  || { echo "훈련 DB 가 아니다 (cluster_name). 복원하지 않는다" >&2; exit 3; }
docker exec -i "$C" pg_restore -U opsloop -d opsloop --no-owner --exit-on-error
echo "restore_rc 0"
""", DB=DRILL_DB, CLUSTER=DRILL_CLUSTER)


# 재적재 환경: 기본 파일 값 뒤에 훈련 값을 덮어쓴다(env 는 뒤에 적은 값이 이긴다).
# systemd-run 은 쓰지 않는다(EnvironmentFile 이 Environment 를 이겨 운영 HOME 이 붙는다).
# HOME 도 훈련 HOME 으로 둔다(opsloop-pull 의 집이 운영 /var/lib/opsloop 다).
# 손 실행은 유닛의 MemoryMax(적재 512M · 다리 256M) 밖에서 돌고 data01 은 스왑이 0 이다. 그래서 적재 · 다리 명령은
# choom -n 1000 으로 OOM 점수를 올려, 호스트 메모리가 모자라면 운영 DB · Loki 보다 이 프로세스(와 자식)를 먼저 죽게 한다
SH_PULL_ENV = """cd /
RUN=(sudo -n -u @@PULL@@ env $(cat @@DEFAULTS@@ | xargs) OPSLOOP_HOME=@@HOME@@ OPSLOOP_DB_ENV=@@ENV@@/ingest.env OPSLOOP_DETECTOR_ENV=@@ENV@@/detector.env HOME=@@HOME@@)
"""

# 훈련 env 가 실제로 이겼는지 · 두 DSN 이 훈련 DB 인지 기계적으로 본다 (opsloop-pull 로, 같은 환경으로)
PY_ENV_CHECK = r'''import os, re, sys
import psycopg2
home, env_dir = sys.argv[1], sys.argv[2]
bad, out = [], ["home " + os.environ.get("OPSLOOP_HOME", "-")]
if os.environ.get("OPSLOOP_HOME") != home or os.environ.get("HOME") != home:
    bad.append("OPSLOOP_HOME · HOME 이 훈련 HOME 이 아니다")
if "DATABASE_URL" in os.environ:
    bad.append("DATABASE_URL 이 환경에 있다 (pull_loki 가 env 파일보다 먼저 본다)")
for key in ("OPSLOOP_DB_ENV", "OPSLOOP_DETECTOR_ENV"):
    path = os.environ.get(key, "")
    if not path.startswith(env_dir + "/"):
        bad.append(key + " 이 훈련 env 가 아니다")
        continue
    url = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                url = line.split("=", 1)[1].strip()
    m = re.fullmatch(r"postgresql://([a-z_]+):[^@/]+@([0-9.]+):(\d+)/opsloop", url or "")
    if not m or m.group(2) != "@@BIND@@" or m.group(3) != "@@PORT@@":
        bad.append(key + " 대상이 @@BIND@@:@@PORT@@ 이 아니다")
        continue
    c = psycopg2.connect(url, connect_timeout=10)
    cur = c.cursor()
    cur.execute("SELECT current_user, current_setting('cluster_name')")
    u, cl = cur.fetchone()
    c.close()
    out.append("%s %s %s:%s %s" % (key, u, m.group(2), m.group(3), cl))
    if cl != "@@CLUSTER@@":
        bad.append(key + " cluster_name 이 훈련 DB 가 아니다")
print("\n".join(out))
if bad:
    print("bad " + " · ".join(bad))
    sys.exit(1)
print("ok")
'''


def _pull_env():
    return fill(SH_PULL_ENV, PULL=PULL_USER, DEFAULTS=INGEST_DEFAULTS, HOME=DRILL_HOME, ENV=DRILL_ENV)


def script_regen_check():
    return "# s:regen_check\nset -euo pipefail\n" + _pull_env() + fill("""CHECK=$(cat <<'__PY__'
@@PY@@__PY__
)
echo "mem_avail_mb $(free -m | awk 'NR==2 {print $7}')"
[ "$(sudo -n stat -c '%U' @@HOME@@)" = @@PULL@@ ] || { echo "bad 훈련 HOME 소유자"; exit 1; }
"${RUN[@]}" python3 -c "$CHECK" @@HOME@@ @@ENV@@
""", PY=fill(PY_ENV_CHECK, BIND=DRILL_BIND, PORT=DRILL_PORT, CLUSTER=DRILL_CLUSTER), HOME=DRILL_HOME,
        PULL=PULL_USER, ENV=DRILL_ENV)


def script_regen_full():
    return "# s:regen_full\nset -uo pipefail\n" + _pull_env() + fill("""# 운영 HOME(/var/lib/opsloop) · 편지함 · 워터마크는 쓰지 않는다. 빈 훈련 HOME 이라 S3 조각을 새로 받는다
"${RUN[@]}" /usr/bin/choom -n 1000 -- /usr/bin/time -v @@INGEST@@ --full
echo "rc $?"
""", INGEST=INGEST_BIN)


def script_regen_loki(since):
    if not re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$|^<[^<>'\n]+>$", since):
        raise ToolError("--since 시각 꼴이 이상하다: %s" % since)
    return "# s:regen_loki\nset -uo pipefail\n" + _pull_env() + fill("""# 관제 대상 로그(Loki)와 관문 · 관리 원장을 훈련 HOME 의 상태로 처음부터 다시 읽는다
"${RUN[@]}" /usr/bin/choom -n 1000 -- /usr/bin/time -v python3 @@LOKI@@ --node @@NODE@@ --since '@@SINCE@@' --ledgers-from-start
echo "rc $?"
""", LOKI=PULL_LOKI, NODE=LOKI_NODE, SINCE=since)


def script_catchup():
    return "# s:catchup\nset -uo pipefail\n" + _pull_env() + fill("""# 따라잡기 한 회차 (--full 없이). 끝난 시각이 T_r 이다
"${RUN[@]}" /usr/bin/choom -n 1000 -- @@INGEST@@
echo "rc_ingest $?"
"${RUN[@]}" /usr/bin/choom -n 1000 -- python3 @@LOKI@@
echo "rc_loki $?"
echo "t_r $(date -u +%s)"
""", INGEST=INGEST_BIN, LOKI=PULL_LOKI)


def script_hosts():
    return fill("""# s:hosts
set -uo pipefail
# 읽기만: 미러에 있는 센서 호스트 (훈련 HOME 은 OPSLOOP_HOSTS 의 호스트만 받는다)
for root in @@HOME@@/raw/v1 @@PROD_HOME@@/raw/v1; do
  sudo -n find "$root" -mindepth 2 -maxdepth 2 -type d -name 'host=*' 2>/dev/null | sed "s|^$root/|$root |"
done
""", HOME=DRILL_HOME, PROD_HOME=PROD_HOME)


def script_cleanup():
    return fill("""# s:cleanup
set -uo pipefail
cd /
docker rm -f @@DB@@ >/dev/null 2>&1; echo "rm_container $?"
docker volume rm @@VOL@@ >/dev/null 2>&1; echo "rm_volume $?"
sudo -n rm -rf --one-file-system @@DIR@@; echo "rm_dir $?"
echo "left_container $(docker ps -a --filter 'name=^@@DB@@$' --format '{{.Names}}' | wc -l)"
echo "left_volume $(docker volume ls -q --filter 'name=^@@VOL@@$' | wc -l)"
echo "left_dir $([ -e @@DIR@@ ] && echo 1 || echo 0)"
echo "prod_running $(docker inspect -f '{{.State.Running}}' @@PROD_DB@@ 2>/dev/null)"
systemctl show -p Id -p Result -p ExecMainStatus -p ExecMainExitTimestamp opsloop-ingest.service opsloop-agents.service \\
  | sed 's/^/unit /'
""", DB=DRILL_DB, VOL=DRILL_VOLUME, DIR=DRILL_DIR, PROD_DB=PROD_DB)


def parse_units(text):
    """'unit ' 을 붙인 systemctl show 출력 → {단위: {속성: 값}}. 단위 사이는 빈 줄이고 속성 차례는 정해져 있지 않다."""
    units, block = {}, {}
    for line in (text or "").splitlines() + ["unit "]:
        if not line.startswith("unit"):
            continue
        body = line[5:]
        if not body.strip():
            if block.get("Id"):
                units[block.pop("Id")] = block
            block = {}
            continue
        k, _, v = body.partition("=")
        block[k] = v
    return units


def console_run_argv(env_file, entry):
    """Mac 콘솔 컨테이너. 127.0.0.1 에만 게시한다. DSN · SESSION_SECRET 은 파일로 넣어 명령행 · docker inspect 에 없다.
    이미지의 원래 시작 명령(entry) 앞에서 파일을 읽어 환경으로 올린 뒤 exec 한다."""
    return (["docker", "run", "-d", "--name", CONSOLE_NAME, "--restart", "no", "--memory", "512m",
             "-p", "127.0.0.1:%d:8000" % CONSOLE_PORT,
             "-e", "TZ=UTC", "-e", "OPSLOOP_WORKER=%s" % WORKER, "-e", "OPSLOOP_CONSOLE_URL=%s" % CONSOLE_URL,
             "-e", "FORWARDED_ALLOW_IPS=127.0.0.1",
             "-v", "%s:/run/opsloop-drill/console.env:ro" % env_file, "--label", "opsloop.drill=1",
             "--entrypoint", "/bin/sh", CONSOLE_IMAGE,
             "-c", 'set -a; . /run/opsloop-drill/console.env; set +a; exec "$@"', "opsloop-drill-console"] + list(entry))


def tunnel_sock():
    return os.path.join(os.path.expanduser(SECRET_DIR), "tunnel.sock")


def tunnel_argv(op=None):
    base = common.ssh_base() + ["-S", tunnel_sock()]
    if op:
        return base + ["-O", op, DATA_HOST]
    return base + ["-o", "ExitOnForwardFailure=yes", "-f", "-N", "-M",
                   "-L", "127.0.0.1:%d:%s:%d" % (TUNNEL_PORT, DRILL_BIND, DRILL_PORT), DATA_HOST]


# ──────────────────────────────────────────────────────────────
#  단계
# ──────────────────────────────────────────────────────────────
def need(ctx, *keys, placeholder):
    v = ctx.state.get(*keys)
    if v is None:
        if ctx.apply:
            raise ToolError("상태에 %s 가 없다 (앞 단계를 먼저)" % ".".join(keys))
        return placeholder
    return v


def step_precheck(ctx):
    if ctx.apply and ctx.state.get("t0"):
        # 다시 돌리면 그 사이 생긴 새 덤프를 골라 T_b 가 T_f 보다 늦어지고(설계 RPO 음수) up 이 다른 덤프를 복원한다.
        # 운영 기준값(verify · cleanup 이 견주는 값)도 바뀐다
        raise ToolError("T0 를 표시한 뒤에는 precheck 를 다시 돌리지 않는다 (백업 선택 · 운영 기준값이 바뀐다). "
                        "새 훈련이면 새 회차 폴더를 쓴다")
    bdir = os.path.expanduser(ctx.args.backup_dir)
    try:
        dump, globs = pick_backup(bdir, ctx.args.dump)
    except ToolError:
        if ctx.apply:
            raise
        dump, globs = os.path.join(bdir, "<덤프>"), os.path.join(bdir, "<역할 목록>")
    ctx.say("  고른 백업: %s · %s" % (os.path.basename(dump), os.path.basename(globs)))
    pre = {"backup_dir": bdir}
    if ctx.apply:
        h = read_header(dump)
        with open(globs, encoding="utf-8") as f:
            gtext = f.read()
        try:
            g = parse_globals(gtext)
        except ValueError as e:
            raise StepFail("역할 목록: %s" % e)
        times = []
        for _ts, d, _g in list_backups(bdir):
            try:
                times.append(read_header(d)["created"])
            except (OSError, ValueError):
                pass
        pre["backup"] = {"file": os.path.basename(dump), "path": dump, "bytes": os.path.getsize(dump),
                         "sha256": sha256_file(dump), "globals_file": os.path.basename(globs), "globals_path": globs,
                         "globals_sha256": sha256_file(globs), "archive_created_utc": iso(h["created"]),
                         "archive_version": h["version"], "pg_dump_version": h["pg_dump_version"],
                         "server_version": h["server_version"], "dbname": h["dbname"]}
        pre["roles"] = {"roles": g["roles"], "members": g["members"]}
        pre["backup_gaps"] = backup_gaps(times)
        log_line = None
        try:
            with open(os.path.join(bdir, "backup.log"), encoding="utf-8", errors="replace") as f:
                for line in f:
                    if os.path.basename(dump) in line:
                        log_line = mask(line.strip())[:300]
        except FileNotFoundError:
            pass
        pre["backup_log"] = log_line
        ctx.check("덤프 머리 PGDMP · pg_dump 16 · db opsloop", h["pg_dump_version"].startswith("16.") and h["dbname"] == "opsloop",
                  "%s · 판 %s" % (h["pg_dump_version"], h["version"]))
        ctx.check("T_b (Archive created, data01 시계)", True, iso(h["created"]))
        ctx.check("역할 목록: 필요한 역할 %d개 · 비밀번호 없음" % len(REQUIRED_ROLES), True,
                  "역할 %d · 멤버십 %d" % (len(g["roles"]), len(g["members"])))
        ctx.check("backup.log 에 이 덤프 기록", log_line is not None, log_line or "없음", warn=True)
        ctx.check("백업 간격 최댓값 ≤ %d초" % RPO_TARGET_S,
                  (pre["backup_gaps"]["max_gap_s"] or 0) <= RPO_TARGET_S, pre["backup_gaps"]["max_gap_s"], warn=True)
    busy = busy_window()
    ctx.check("운영 작업 창 밖 (00:05~00:15 · 04:25~04:40 · 16:25~16:40 KST)", busy is None, busy or "", warn=True)
    r = ctx.run("pmset", ["pmset", "-g", "assertions"], ok=(0, 1))
    if not r.dry:
        awake = re.search(r"PreventUserIdleSystemSleep\s+1", r.out) is not None
        ctx.check("Mac 잠자기 막힘 (caffeinate -dims 를 켜 둔다)", awake, warn=True)
    r = ctx.run("mac_ports", ["lsof", "-nP", "-iTCP:%d" % TUNNEL_PORT, "-iTCP:%d" % CONSOLE_PORT, "-sTCP:LISTEN"],
                ok=(0, 1))
    if not r.dry:
        ctx.check("Mac 포트 %d · %d 비어 있음" % (TUNNEL_PORT, CONSOLE_PORT), r.rc == 1 and not r.out.strip())
    r = ctx.run("mac_docker", ["docker", "version", "--format", "{{.Server.Version}} {{.Server.Arch}}"])
    if not r.dry:
        ctx.check("Mac Docker", bool(r.out.strip()), r.out.strip())
    r = ctx.sh("data01", DATA_HOST, script_precheck())
    if not r.dry:
        kv = kv_lines(r.out)
        pre["data01"] = kv
        off = chrony_offset(r.out)
        pre["clock"] = {"data01_offset_s": off}
        ctx.check("data01 시계 (chrony)", off is not None and abs(off) < 0.5, off, warn=True)
        ctx.check("data01 가용 메모리 ≥ 600MB", to_int(kv.get("mem_avail_mb"), 0) >= 600, kv.get("mem_avail_mb"))
        ctx.check("data01 디스크 여유 ≥ 2GB", to_int(kv.get("disk_free_mb"), 0) >= 2048, kv.get("disk_free_mb"))
        ctx.check("%s:%d 비어 있음" % (DRILL_BIND, DRILL_PORT), kv.get("port_listen") == "0")
        ctx.check("이미지 %s 있음" % PG_IMAGE, kv.get("image", "").startswith("sha256:"), kv.get("image", "")[:19])
        ctx.check("운영 DB 와 같은 이미지", kv.get("image") and kv.get("image") == kv.get("prod_image"))
        ctx.check("훈련 컨테이너 · 볼륨 · 폴더 없음",
                  (kv.get("drill_container"), kv.get("drill_volume"), kv.get("drill_dir")) == ("0", "0", "0"),
                  "%s · %s · %s" % (DRILL_DB, DRILL_VOLUME, DRILL_DIR))
        ctx.check("%s 사용자 · opsloop-ingest · pull_loki.py" % PULL_USER,
                  kv.get("pull_user", "-") != "-" and kv.get("ingest_bin") == "1" and kv.get("pull_loki") == "1")
        ctx.check("%s 에 OPSLOOP_HOME 있음 · DATABASE_URL 없음" % INGEST_DEFAULTS,
                  to_int(kv.get("defaults_home"), 0) >= 1 and kv.get("defaults_dburl") == "0")
        ctx.check("sudo -n · /usr/bin/time · /usr/bin/choom · docker 그룹",
                  (kv.get("sudo"), kv.get("time"), kv.get("choom"), kv.get("docker_group")) == ("1", "1", "1", "1"))
    r = ctx.run("fw_chrony", ssh_argv(FW_HOST, "chronyc -n tracking"), ok=(0, 1))
    if not r.dry:
        pre.setdefault("clock", {})["fw_offset_s"] = chrony_offset(r.out)
    r = ctx.run("console_image", ssh_argv(CONSOLE_HOST, "docker image inspect -f '{{.Id}}' %s" % CONSOLE_IMAGE))
    if not r.dry:
        pre["console_image"] = r.out.strip()
        ctx.check("console-a 콘솔 이미지", r.out.strip().startswith("sha256:"), r.out.strip()[:19])
    r = ctx.prod("prod_baseline", "\n".join((Q.q_counts(Q.TABLES), Q.Q_CATALOG, Q.Q_BASELINE, Q.Q_PROD_STATE)))
    if not r.dry:
        p = {f[0]: f[1:] for f in tagged(r.out, "p")}
        pre["prod"] = {"counts": {f[0]: to_int(f[1]) for f in tagged(r.out, "n")},
                       "catalog": {f[0]: f[1] for f in tagged(r.out, "c")},
                       "baseline": {f[0]: to_int(f[1]) for f in tagged(r.out, "b")},
                       "state": {k: "|".join(v) for k, v in p.items()}}
        ctx.check("운영 조회가 읽기 전용", p.get("read_only") == ["on"])
        ctx.check("운영 cluster_name 이 훈련 이름이 아님", p.get("cluster_name") != [DRILL_CLUSTER],
                  "|".join(p.get("cluster_name", [])) or "(빈 값)")
        ctx.check("운영 표 %d개 건수" % len(Q.TABLES), len(pre["prod"]["counts"]) == len(Q.TABLES))
        cat = pre["prod"]["catalog"]
        ctx.check("운영 구조 (참고 FK %d · 트리거 %d · 함수 %d · 뷰 %d)" % (
            Q.EXPECT["fk"], Q.EXPECT["triggers"], Q.EXPECT["functions"], Q.EXPECT["views"]), True,
            "표 %s · FK %s" % (cat.get("tables"), cat.get("fk")))
    if ctx.apply:
        ctx.state.data["precheck"] = pre
    return 1 if ctx.failed() else 0


def step_t0(ctx):
    if ctx.apply and ctx.state.get("t0"):
        raise ToolError("T0 는 이미 표시했다 (%s). 새 훈련이면 새 회차 폴더를 쓴다" % ctx.state.get("t0", "t_f"))
    ctx.mark("T0", "장애 선언 · 복원 결정 (범위: DB 인스턴스 손실)")
    r = ctx.prod("t_f", Q.Q_T0)
    t0 = {}
    if not r.dry:
        now = tagged(r.out, "p")
        tf = parse_pg_ts(now[0][1]) if now and len(now[0]) >= 2 else None
        if not tf:
            raise StepFail("운영 now() 를 읽지 못했다")
        t0["t_f"] = iso(tf)
        ctx.say("  T_f (운영 DB 시계) %s" % t0["t_f"])
    t0["clock"] = clock_pair(ctx)
    if ctx.apply:
        ctx.state.data["t0"] = t0
    return 0


def clock_pair(ctx):
    out = {}
    for host in (DATA_HOST, FW_HOST):
        r = ctx.run("chrony_" + host, ssh_argv(host, "chronyc -n tracking"), ok=(0, 1))
        if not r.dry:
            out[host] = chrony_offset(r.out)
    return out


def step_up(ctx):
    b = ctx.state.get("precheck", "backup") or {}
    if ctx.apply:
        if sha256_file(b["path"]) != b["sha256"]:
            raise StepFail("덤프가 사전 점검 뒤에 바뀌었다: %s" % b["file"])
    ctx.mark("S1", "백업 선택 %s sha256:%s" % (b.get("file", "<덤프>"), (b.get("sha256") or "<sha256>")[:12]))
    r = ctx.sh("up", DATA_HOST, script_up(), timeout=300)
    if r.dry:
        ctx.mark("S2", "훈련 DB 준비")
        return 0
    kv = kv_lines(r.out)
    ctx.check("준비 (init 끝 · pg_isready)", kv.get("ready") == "1")
    ctx.check("cluster_name = %s" % DRILL_CLUSTER, kv.get("cluster") == DRILL_CLUSTER, kv.get("cluster"))
    ctx.check("게시 %s:%d 만" % (DRILL_BIND, DRILL_PORT), kv.get("bind") == "%s:%d" % (DRILL_BIND, DRILL_PORT),
              kv.get("bind"))
    ctx.check("메모리 한도 %s" % DRILL_MEMORY, kv.get("memory") == str(256 * 1024 * 1024), kv.get("memory"))
    ctx.check("OOM 점수 조정 1000 (호스트 메모리가 모자라면 훈련 DB 가 먼저)", kv.get("oom_adj") == "1000",
              kv.get("oom_adj"), warn=True)
    ctx.check("운영과 같은 이미지", kv.get("image") == ctx.state.get("precheck", "data01", "image"),
              (kv.get("image") or "")[:19])
    ctx.check("POSTGRES_PASSWORD 가 환경에 없음 (파일로만)", kv.get("env_password") == "0")
    ctx.check("initdb 마운트 없음", kv.get("initdb_mounts") == "0")
    ctx.state.data["up"] = kv
    if ctx.failed():
        return 1
    ctx.mark("S2", "훈련 DB 준비 · %s %s:%d" % (DRILL_DB, DRILL_BIND, DRILL_PORT))
    return 0


def step_roles(ctx):
    path = ctx.state.get("precheck", "backup", "globals_path")
    if ctx.apply:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if sha256_file(path) != ctx.state.get("precheck", "backup", "globals_sha256"):
            raise StepFail("역할 목록이 사전 점검 뒤에 바뀌었다")
        try:
            g = parse_globals(text)
        except ValueError as e:
            raise StepFail("역할 목록: %s" % e)
    else:
        g = {"sql": "-- q:roles_apply\n<역할 목록(%s)의 CREATE ROLE · ALTER ROLE … WITH … · GRANT … 줄>"
             % (os.path.basename(path) if path else "<globals.sql>"),
             "roles": {"opsloop_%s" % n: {"login": True}
                       for n in ("backup", "console", "cti", "detector", "gate", "ingest")}}
    specs = login_specs(g["roles"])
    ctx.drill("roles_apply", g["sql"])
    r = ctx.sh("passwords", DATA_HOST, script_passwords(specs))
    if not r.dry:
        ctx.check("로그인 역할 %d개 훈련 전용 비밀번호 · env 파일" % len(specs),
                  len(re.findall(r"^env ", r.out, re.M)) == len(specs))
    r = ctx.sh("roles_check", DATA_HOST, script_roles_check(specs))
    if not r.dry:
        oks = re.findall(r"^ok (\S+) (\S+) (\S+)$", r.out, re.M)
        modes = dict(re.findall(r"^mode (\S+) (.+)$", r.out, re.M))
        ctx.check("env 파일 DSN = %s:%d · 접속 · cluster_name" % (DRILL_BIND, DRILL_PORT),
                  len(oks) == len(specs) and all(c == DRILL_CLUSTER for _n, _u, c in oks), "%d/%d" % (len(oks), len(specs)))
        mode_bad = []
        for _r, short, owner in specs:
            got_mode = (modes.get("%s.env" % short) or "").split()
            if len(got_mode) != 2 or got_mode[0] != "600" or ((got_mode[1] == PULL_USER) != (owner == PULL_USER)):
                mode_bad.append("%s.env %s" % (short, " ".join(got_mode) or "없음"))
        ctx.check("env 파일 0600 · 적재 · 탐지 몫만 %s 소유" % PULL_USER, not mode_bad,
                  " · ".join(mode_bad) or " · ".join("%s %s" % kv for kv in sorted(modes.items())))
    r = ctx.drill("roles_state", Q.Q_ROLES_STATE)
    if not r.dry:
        got = {f[0]: f[1:] for f in tagged(r.out, "a") if len(f) >= 6}
        mem = {(f[0], f[1]): f[2] for f in tagged(r.out, "g") if len(f) >= 3}
        bad = []
        for name, v in g["roles"].items():
            a = got.get(name)
            if not a:
                bad.append("%s 없음" % name)
                continue
            login, inherit, limit, _su, haspw = a[0] in ("t", "true"), a[1] in ("t", "true"), to_int(a[2]), a[3], a[4]
            if login != v["login"] or inherit != v["inherit"] or limit != v["connlimit"]:
                bad.append("%s 속성" % name)
            if v["login"] and name != BOOTSTRAP_ROLE and haspw not in ("t", "true"):
                bad.append("%s 비밀번호 없음" % name)
        for m in g["members"]:
            if (m["role"], m["member"]) not in mem:
                bad.append("%s → %s 멤버십 없음" % (m["role"], m["member"]))
        console_limit = to_int((got.get("opsloop_console") or [None, None, None])[2])
        ctx.check("역할 속성(LOGIN · INHERIT · 접속 한도) · 멤버십이 역할 목록과 같음", not bad, " · ".join(bad) or
                  "역할 %d · 멤버십 %d" % (len(g["roles"]), len(g["members"])))
        ctx.check("opsloop_console 접속 한도 ≥ 30", (console_limit or 0) >= 30, console_limit)
        ctx.state.data["roles"] = {"specs": [list(s) for s in specs], "state": got,
                                   "members": ["%s>%s" % k for k in sorted(mem)]}
    if ctx.failed():
        return 1
    ctx.mark("S3", "역할 %d · 로그인 역할 비밀번호 %d (훈련 전용)" % (len(g["roles"]), len(specs)))
    return 0


def step_restore(ctx):
    dump = need(ctx, "precheck", "backup", "path", placeholder="<덤프>")
    tb = from_iso(ctx.state.get("precheck", "backup", "archive_created_utc"))
    r = ctx.sh("restore", DATA_HOST, script_restore(), stdin=FileIn(dump), timeout=3600, ok=(0, 1, 3))
    res = {}
    if not r.dry:
        res["rc"] = r.rc
        res["stderr_tail"] = mask(r.err.strip()[-600:])
        ctx.check("pg_restore --no-owner --exit-on-error 종료 0", r.rc == 0 and "restore_rc 0" in r.out, r.rc)
        if r.rc != 0:
            ctx.state.data["restore"] = res
            return 1
    r = ctx.run("toc", ssh_argv(DATA_HOST, "docker exec -i %s pg_restore --list" % DRILL_DB), stdin=FileIn(dump))
    toc = parse_toc(r.out) if not r.dry else {"tables": list(Q.TABLES), "counts": {}, "archive_created": None}
    tables = [t for t in toc["tables"] if Q.IDENT.match(t)] or list(Q.TABLES)
    r = ctx.drill("restored", "\n".join((Q.q_counts(tables), Q.Q_CATALOG, Q.Q_RESTORED)))
    if r.dry:
        ctx.mark("S4", "pg_restore rc 0 · 표 %d" % len(tables))
        return 0
    counts = {f[0]: to_int(f[1]) for f in tagged(r.out, "n")}
    cat = {f[0]: f[1] for f in tagged(r.out, "c")}
    rs = {f[0]: f[1] for f in tagged(r.out, "r")}
    tc = toc["counts"]
    prod_counts = ctx.state.get("precheck", "prod", "counts") or {}
    ac = toc.get("archive_created") or {}
    header_at = tb.strftime("%Y-%m-%d %H:%M:%S") if tb else None
    ctx.check("목차: 데이터 표 %d개 = 운영 표 목록" % len(Q.TABLES), sorted(toc["tables"]) == sorted(Q.TABLES),
              len(toc["tables"]))
    ctx.check("목차 Archive created = 덤프 머리 (T_b)", ac.get("at") == header_at and ac.get("tz") in ("UTC", ""),
              "%s %s" % (ac.get("at"), ac.get("tz")))
    ctx.check("표 %d개 건수" % len(tables), len(counts) == len(tables) and all(v is not None for v in counts.values()))
    pairs = (("tables", len(toc["tables"])), ("fk", tc.get("FK CONSTRAINT", 0)), ("sequences", tc.get("SEQUENCE", 0)))
    ctx.check("카탈로그 = 목차 (표 · FK · 시퀀스)", all(to_int(cat.get(k)) == v for k, v in pairs),
              " · ".join("%s %s/%s" % (k, cat.get(k), v) for k, v in pairs))
    fn = len([x for x in (cat.get("functions") or "").split(",") if x])
    tr = len([x for x in (cat.get("triggers") or "").split(",") if x])
    vw = len([x for x in (cat.get("views") or "").split(",") if x])
    ctx.check("카탈로그 = 목차 (함수 · 트리거 · 뷰)",
              (fn, tr, vw) == (tc.get("FUNCTION", 0), tc.get("TRIGGER", 0), tc.get("VIEW", 0)),
              "함수 %d · 트리거 %d · 뷰 %d" % (fn, tr, vw))
    over = [t for t, n in counts.items() if prod_counts.get(t) is not None and n is not None and n > prod_counts[t]]
    ctx.check("복원 건수 ≤ 사전 점검 때 운영 건수 (참고)", not over, " · ".join(over) or "모두", warn=True)
    runs_max = parse_pg_ts(rs.get("runs_max"))
    ctx.check("T_b 하한: 복원 DB 의 마지막 탐지 실행 ≤ T_b (+%d초)" % BRACKET_SLACK_S,
              runs_max is not None and tb is not None and runs_max <= tb + timedelta(seconds=BRACKET_SLACK_S),
              "%s ≤ %s" % (iso(runs_max), iso(tb)))
    res.update({"toc_counts": tc, "toc_tables": toc["tables"], "archive_created_toc": ac, "counts": counts,
                "catalog": cat, "runs_max": iso(runs_max), "verdicts_max": iso(parse_pg_ts(rs.get("verdicts_max"))),
                "verdicts_max_id": to_int(rs.get("verdicts_max_id"), 0)})
    ctx.state.data["restore"] = res
    if ctx.failed():
        return 1
    ctx.mark("S4", "pg_restore rc 0 · 표 %d · 이벤트 %s" % (len(counts), counts.get("events")))
    return 0


def step_verify(ctx):
    # 1) 훈련 쪽 지문을 먼저 뜬다 (알림 끄기 · 콘솔 · 재탐지가 훈련 DB 를 바꾸기 전). 뜨자마자 상태에 둔다.
    #    verify 를 다시 돌릴 때는 4) 알림 끄기가 이미 훈련 DB 의 notify_channels 를 바꿨으므로 다시 뜨지 않고
    #    같은 복원(steps.restore.at)의 첫 지문을 쓴다. 다시 뜨면 그 차이가 done 에서 (T_b, T_f] 손실로 잘못 셈된다
    ver = {}
    restore_at = ctx.state.get("steps", "restore", "at")
    kept = ctx.state.get("verify_fp") or {}
    if ctx.apply and kept.get("fingerprint") and kept.get("restore_at") == restore_at:
        fp = kept["fingerprint"]
        ctx.say("  훈련 쪽 지문은 이 복원 뒤 처음 뜬 것을 쓴다 (%s)" % kept.get("at"))
    else:
        r = ctx.drill("fingerprint", Q.q_fingerprint())
        fp = None if r.dry else parse_fingerprints(r.out)
        if not r.dry:
            ctx.state.data["verify_fp"] = {"restore_at": restore_at, "at": iso(datetime.now(timezone.utc)),
                                           "fingerprint": fp}
            ctx.save()
    if ctx.apply:
        ver["fingerprint"] = fp
        ctx.check("훈련 쪽 지문 (%s)" % " · ".join(n for n, *_ in Q.FINGERPRINTS), bool(fp),
                  " · ".join("%s %d" % (k, len(v)) for k, v in sorted(fp.items())))
    # 2) 무결성 · 기준값 · 구조 · 시퀀스
    r = ctx.drill("integrity", "\n".join((Q.q_zero(), Q.Q_BASELINE, Q.Q_CATALOG, Q.Q_SEQUENCES)))
    if not r.dry:
        zero = {f[0]: to_int(f[1]) for f in tagged(r.out, "z")}
        base = {f[0]: to_int(f[1]) for f in tagged(r.out, "b")}
        cat = {f[0]: f[1] for f in tagged(r.out, "c")}
        seqs = tagged(r.out, "q")
        bad_zero = ["%s=%s" % (k, v) for k, v in zero.items() if v != 0]
        ctx.check("무결성 %d개 모두 0" % len(Q.ZERO), len(zero) == len(Q.ZERO) and not bad_zero,
                  " · ".join(bad_zero) or "%d개" % len(zero))
        pbase = ctx.state.get("precheck", "prod", "baseline") or {}
        diff = ["%s 훈련 %s · 운영 %s" % (k, v, pbase.get(k)) for k, v in base.items() if pbase.get(k) != v]
        ctx.check("기준값 (판정 있는데 비resolved · 판정자 계정 없음 · 해제 차단 · 해제 감사) = 사전 점검 운영값", not diff,
                  " · ".join(diff) or " · ".join("%s %s" % kv for kv in sorted(base.items())), warn=True)
        pcat = ctx.state.get("precheck", "prod", "catalog") or {}
        cdiff = [k for k in ("tables", "fk", "triggers", "functions", "views", "sequences", "extensions")
                 if cat.get(k) != pcat.get(k)]
        ctx.check("구조 = 운영 (표 · FK · 트리거 켜짐 · 함수 · 뷰 · 시퀀스 · 확장)", not cdiff,
                  " · ".join(cdiff) or "표 %s · FK %s" % (cat.get("tables"), cat.get("fk")))
        got = {"tables": to_int(cat.get("tables")), "fk": to_int(cat.get("fk")),
               "triggers": len([x for x in (cat.get("triggers") or "").split(",") if x]),
               "functions": len([x for x in (cat.get("functions") or "").split(",") if x]),
               "views": len([x for x in (cat.get("views") or "").split(",") if x])}
        ctx.check("구조 수치 = 계약 참고값 (표 23 · FK 15 · 트리거 4 · 함수 7 · 뷰 3)", got == Q.EXPECT,
                  " · ".join("%s %s" % kv for kv in sorted(got.items())), warn=True)
        seq_bad = []
        for f in seqs:
            if len(f) < 3:
                continue
            last, mx = to_int(f[1]), to_int(f[2])
            if mx is not None and (last is None or last < mx):
                seq_bad.append(f[0])
        ctx.check("시퀀스 마지막 값 ≥ 최대 id", bool(seqs) and not seq_bad, " · ".join(seq_bad) or "%d개" % len(seqs))
        ver.update({"zero": zero, "baseline": base, "catalog": cat, "sequences": ["|".join(f) for f in seqs]})
    # 3) 역할별 허용 · 거부 (verify-db-roles.sh 의 문장 · 컨테이너만 훈련 쪽)
    checks = role_checks()
    outs = []
    for role in sorted({c["role"] for c in checks if c["kind"] == "q"}):
        rr = ctx.drill("roles_" + role, Q.q_role_checks(role, [c for c in checks if c["role"] == role and c["kind"] == "q"]),
                       role=role, ok=(0, 1, 2, 3))
        outs.append(rr.out)
    pc = [c for c in checks if c["kind"] == "p"]
    if pc:
        rr = ctx.drill("roles_privileges", Q.q_role_checks(BOOTSTRAP_ROLE, pc), ok=(0, 1, 3))
        outs.append(rr.out)
    if ctx.apply:
        rows = judge_role_output(checks, outs)
        bad = ["%s: %s → %s" % (x["role"], x["stmt"][:50], x["got"]) for x in rows if not x["ok"]]
        ctx.check("역할별 허용 · 거부 %d줄 (verify-db-roles.sh)" % len(rows), rows and not bad, " / ".join(bad[:5]) or "모두")
        ver["roles"] = {"total": len(rows), "failed": bad}
    # 4) 알림 채널 끄기 · url 무효화 (훈련 DB 에만. 지문을 뜬 뒤, 콘솔을 붙이기 전)
    r = ctx.drill("notify_off", Q.Q_NOTIFY_OFF)
    if not r.dry:
        o = tagged(r.out, "o")
        ok = bool(o) and o[0][0] == "0" and o[0][1] == "0"
        ctx.check("알림 채널 켜짐 0 · url 무효", ok, "채널 %s" % (o[0][2] if o else "?"))
        ver["notify"] = o[0] if o else None
        ctx.state.data["verify"] = ver
    if ctx.failed():
        return 1
    ctx.mark("S5", "무결성 %d · 역할 %d줄 · 알림 끔" % (len(Q.ZERO), len(checks)))
    return 0


def mac_env_path():
    return os.path.join(os.path.expanduser(SECRET_DIR), "console.env")


DSN_RE = re.compile(r"^DATABASE_URL=postgresql://opsloop_console:([0-9a-f]{48})@%s:%d/opsloop$"
                    % (re.escape(DRILL_BIND), DRILL_PORT))


def step_console(ctx):
    if ctx.args.confirm:
        return step_console_confirm(ctx)
    r = ctx.drill("notify_state", Q.Q_NOTIFY_STATE)
    if not r.dry:
        o = tagged(r.out, "o")
        if not o or o[0][0] != "0" or o[0][1] != "0":
            raise StepFail("훈련 DB 의 알림 채널이 켜져 있다. verify 를 먼저 끝낸다 (콘솔 발송기가 실제로 보낸다)")
    r = ctx.run("image_remote", ssh_argv(CONSOLE_HOST, "docker image inspect -f '{{.Id}}' %s" % CONSOLE_IMAGE))
    remote_id = r.out.strip()
    r = ctx.run("image_local", ["docker", "image", "inspect", "-f", "{{.Id}}", CONSOLE_IMAGE], ok=(0, 1))
    if r.dry or r.out.strip() != remote_id:
        ctx.pipe("image_load", ssh_argv(CONSOLE_HOST, "docker save %s" % CONSOLE_IMAGE), ["docker", "load", "-q"])
        r = ctx.run("image_local_after", ["docker", "image", "inspect", "-f", "{{.Id}}", CONSOLE_IMAGE])
    if not r.dry:
        ctx.check("콘솔 이미지 ID = console-a", r.out.strip() == remote_id and remote_id.startswith("sha256:"),
                  remote_id[:19])
    r = ctx.drill("console_base", Q.Q_CONSOLE_BASE)
    con = {}
    if not r.dry:
        v = tagged(r.out, "v")
        con["base_count"], con["base_max_id"] = (to_int(v[0][0], 0), to_int(v[0][1], 0)) if v else (0, 0)
        con["candidates"] = ["|".join(f) for f in tagged(r.out, "u")]
    # DSN 은 data01 의 0600 파일에서 파이프로만 받는다 (화면 · 기록에 남기지 않는다)
    r = ctx.run("console_dsn", ssh_argv(DATA_HOST, "cat %s/console.env" % DRILL_ENV), secret_out=True)
    env_file = mac_env_path()
    if ctx.apply:
        line = next((x.strip() for x in r.out.splitlines() if x.startswith("DATABASE_URL=")), "")
        m = DSN_RE.match(line)
        if not m:
            raise StepFail("data01 의 console.env 가 기대한 꼴이 아니다 (roles 단계를 다시)")
        pw = m.group(1)
        sess = secrets.token_hex(32)
        ctx.secrets += [pw, sess]
        text = ("DATABASE_URL=postgresql://opsloop_console:%s@host.docker.internal:%d/opsloop\nSESSION_SECRET=%s\n"
                % (pw, TUNNEL_PORT, sess))
        # 폴더 0700 · 파일 0600. Docker Desktop 파일 공유는 컨테이너 안 사용자(이미지 USER app)도 이 파일을 읽게 한다
        # (2026-09-27 이 Mac 에서 확인. 읽지 못하면 /health 가 오지 않고 컨테이너 로그에 나온다)
        os.makedirs(os.path.dirname(env_file), mode=0o700, exist_ok=True)
        os.chmod(os.path.dirname(env_file), 0o700)
        write_private(env_file, text)
        del text, pw, sess
    else:
        ctx.say("  (DSN 을 받아 %s 에 둔다: DATABASE_URL=…@host.docker.internal:%d · 새 SESSION_SECRET · 폴더 0700)"
                % (env_file, TUNNEL_PORT))
    r = ctx.run("tunnel_check", tunnel_argv("check"), ok=(0, 1, 255))
    if r.dry or r.rc != 0:
        # ssh -f 는 인증 뒤 뒤로 돌고, 뒤로 돈 마스터가 출력을 쥐고 있다. 그래서 출력은 파일로 받는다
        # (2026-09-27 이 Mac · OpenSSH 10.3 에서 확인: 파이프로 받으면 터널은 열리는데 명령이 돌아오지 않았다)
        ctx.run("tunnel", tunnel_argv(), timeout=60, detach=True)
        ctx.run("tunnel_check_after", tunnel_argv("check"))
    r = ctx.run("image_config", ["docker", "image", "inspect", "-f", "{{json .Config}}", CONSOLE_IMAGE])
    entry = ["<이미지 Entrypoint + Cmd>"]
    if not r.dry:
        cfg = json.loads(r.out or "{}")
        entry = list(cfg.get("Entrypoint") or []) + list(cfg.get("Cmd") or [])
        if not entry:
            raise StepFail("콘솔 이미지에 시작 명령이 없다")
        con["entry"] = entry
    ctx.run("console_rm_old", ["docker", "rm", "-f", CONSOLE_NAME], ok=(0, 1))
    ctx.run("console_run", console_run_argv(env_file, entry))
    code = wait_health(ctx)
    if ctx.apply:
        ctx.check("콘솔 %s/health 200" % CONSOLE_URL, code == "200", code)
        if code != "200":
            r = ctx.run("console_logs", ["docker", "logs", "--tail", "30", CONSOLE_NAME], ok=(0, 1))
            for line in mask(r.out + r.err, ctx.secrets).splitlines()[-15:]:
                ctx.say("    " + line)
            ctx.state.data["console"] = con
            return 1
        con["image_id"] = remote_id
        con["url"] = CONSOLE_URL
        ctx.state.data["console"] = con
    ctx.mark("S6", "콘솔 기동 · %s/health 200 · 이미지 %s" % (CONSOLE_URL, remote_id[:19] or "<ID>"))
    ctx.say("")
    ctx.say("  다음은 사람이 한다: 브라우저로 %s 에 복원된 계정으로 로그인 → 사건 목록 · 상세의 판정 이력 · 차단 목록 · 감사 확인 →" % CONSOLE_URL)
    ctx.say("  미판정 시험 사건 1건에 판정(undetermined · 사유 '복원 훈련')을 남긴다. 화면에 바로 반영되는지 본다.")
    for c in con.get("candidates", []):
        ctx.say("    후보 %s" % c)
    ctx.say("  확인했으면: drill.py %s console --confirm --apply  (→ rto:S7)" % ctx.run_dir)
    return 0


def wait_health(ctx, tries=45, poll=2.0):
    argv = ["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", CONSOLE_URL + "/health"]
    if not ctx.apply:
        ctx.run("health", argv)
        ctx.say("  기다림: /health 200 (최대 %d번 · %g초 간격)" % (tries, poll))
        return None
    code = None
    for _ in range(tries):
        r = ctx.run("health", argv, ok=(0, 7, 28, 52, 56))
        code = r.out.strip()
        if code == "200":
            break
        time.sleep(float(os.environ.get("OPSLOOP_DRILL_POLL", poll)))
    return code


def step_console_confirm(ctx):
    base = to_int(ctx.state.get("console", "base_max_id"), 0)
    r = ctx.drill("console_after", Q.q_console_after(base))
    if r.dry:
        ctx.mark("S7", "판정 반영")
        return 0
    rows = tagged(r.out, "w")
    resolved = [f for f in rows if len(f) >= 5 and f[4] == "resolved"]
    ctx.check("콘솔에서 남긴 판정이 훈련 DB 에 있음 (id > %d)" % base, bool(rows), "%d건" % len(rows))
    ctx.check("그 사건 status = resolved", bool(resolved), " · ".join("%s %s" % (f[1], f[4]) for f in rows[:3]))
    ctx.state.data["console_confirm"] = {"verdicts": ["|".join(f[:4]) for f in rows], "human_checked": True}
    if ctx.failed():
        return 1
    ctx.mark("S7", "판정 반영 · 서비스 재개 · 판정 %d건 · %s" % (len(rows), resolved[0][1]))
    return 0


def step_regen(ctx):
    tb = from_iso(ctx.state.get("precheck", "backup", "archive_created_utc"))
    since = (tb - timedelta(seconds=REGEN_BEFORE_S)).strftime("%Y-%m-%dT%H:%M:%SZ") if tb else "<T_b−1시간>"
    busy = busy_window()
    ctx.check("운영 작업 창 밖 (재적재는 메모리를 쓴다 · data01 스왑 0)", busy is None, busy or "", warn=True)
    r = ctx.sh("regen_check", DATA_HOST, script_regen_check(), ok=(0, 1))
    mem = None
    if not r.dry:
        # 사전 점검 뒤에 훈련 DB(최대 256m)가 떴다. 재적재 · 재탐지는 상한 없이 돌므로 지금 여유를 다시 본다
        mem = to_int(kv_lines(r.out).get("mem_avail_mb"))
        ctx.check("data01 가용 메모리 ≥ %dMB (훈련 DB 가 뜬 뒤 · 스왑 0)" % REGEN_MEM_MIN_MB, (mem or 0) >= REGEN_MEM_MIN_MB,
                  mem)
        ctx.check("재적재 환경: 훈련 HOME · 훈련 env 두 개 · %s:%d · %s" % (DRILL_BIND, DRILL_PORT, DRILL_CLUSTER),
                  r.rc == 0 and r.out.strip().endswith("ok"), mask(r.out.strip().splitlines()[-1] if r.out.strip() else ""))
        if ctx.failed():
            return 1
    reg = {"since": since, "mem_avail_mb": mem}
    r = ctx.sh("regen_full", DATA_HOST, script_regen_full(), timeout=3600)
    if not r.dry:
        rc = to_int(kv_lines(r.out).get("rc"))
        reg["full"] = dict(time_v(r.err), rc=rc)
        ctx.check("opsloop-ingest --full 종료 %s" % " · ".join(map(str, INGEST_OK)), rc in INGEST_OK,
                  "%s · 최대 RSS %s kB · %s초" % (rc, reg["full"]["max_rss_kb"], reg["full"]["elapsed_s"]))
    r = ctx.sh("regen_loki", DATA_HOST, script_regen_loki(since), timeout=3600)
    if not r.dry:
        rc = to_int(kv_lines(r.out).get("rc"))
        reg["loki"] = dict(time_v(r.err), rc=rc)
        ctx.check("pull_loki --node %s --since %s --ledgers-from-start 종료 0" % (LOKI_NODE, since), rc == 0,
                  "%s · 최대 RSS %s kB · %s초" % (rc, reg["loki"]["max_rss_kb"], reg["loki"]["elapsed_s"]))
    r = ctx.drill("regen_counts", Q.q_counts(("events", "sessions", "node_metrics", "incidents", "detector_runs")))
    if not r.dry:
        reg["counts"] = {f[0]: to_int(f[1]) for f in tagged(r.out, "n")}
        ctx.state.data["regen"] = reg
    if ctx.failed():
        return 1
    ctx.mark("S8", "재적재 · 탐지 끝 (훈련 HOME · 훈련 env)")
    return 0


def step_compare(ctx):
    tb = from_iso(ctx.state.get("precheck", "backup", "archive_created_utc"))
    r = ctx.sh("catchup", DATA_HOST, script_catchup(), timeout=1800)
    if r.dry:
        lo, cut = "<T_b−1시간>", "<T_r−30분>"
    else:
        kv = kv_lines(r.out)
        tr = to_int(kv.get("t_r"))
        if tr is None:
            raise StepFail("T_r 을 읽지 못했다")
        ctx.check("따라잡기 적재 종료 %s" % " · ".join(map(str, INGEST_OK)), to_int(kv.get("rc_ingest")) in INGEST_OK,
                  kv.get("rc_ingest"))
        ctx.check("따라잡기 pull_loki 종료 0", kv.get("rc_loki") == "0", kv.get("rc_loki"), warn=True)
        t_r = datetime.fromtimestamp(tr, tz=timezone.utc)
        lo = iso(tb - timedelta(seconds=REGEN_BEFORE_S))
        cut_dt = t_r - timedelta(seconds=CUT_LAG_S)
        cut = iso(cut_dt)
        after_tb = round((cut_dt - tb).total_seconds(), 3)
        if not ctx.check("대조 창이 T_b 뒤를 %d초 이상 덮음 (창 끝 = T_r − %d분)" % (REGEN_MIN_AFTER_TB_S, CUT_LAG_S // 60),
                         after_tb >= REGEN_MIN_AFTER_TB_S, "%s초 · 창 %s ~ %s" % (after_tb, lo, cut)):
            ctx.say("  T_b + %d분 뒤에 compare 를 다시 돌린다 (지금 견주면 덤프에서 온 행만 본다)"
                    % ((REGEN_MIN_AFTER_TB_S + CUT_LAG_S) // 60))
            ctx.state.data["compare"] = {"window": [lo, cut], "t_r": iso(t_r), "window_after_tb_s": after_tb,
                                         "match": None}
            return 1
    d = ctx.drill("regen_drill", Q.q_regen(lo, cut))
    p = ctx.prod("regen_prod", Q.q_regen(lo, cut))
    r2 = ctx.sh("hosts", DATA_HOST, script_hosts())
    if d.dry:
        return 0
    res = regen_compare(d.out, p.out)
    res.update({"window": [lo, cut], "t_r": iso(t_r), "window_after_tb_s": after_tb})
    for s, v in res["sensors"].items():
        ctx.check("events %s 건수 · 지문" % s, v["same"], "훈련 %d · 운영 %d" % (v["drill"]["count"], v["prod"]["count"]))
    ctx.check("sessions 건수 · 지문", res["sessions"]["same"],
              "훈련 %s · 운영 %s" % ((res["sessions"]["drill"] or {}).get("count"), (res["sessions"]["prod"] or {}).get("count")))
    ctx.check("node_metrics 노드별 건수 · 지문", res["node_metrics"]["same"],
              " · ".join("%s %s/%s" % (k, (res["node_metrics"]["drill"].get(k) or {}).get("count"), v["count"])
                         for k, v in sorted(res["node_metrics"]["prod"].items())))
    ctx.check("사건 키 집합 (참고 · 탐지 시점 차이로 갈릴 수 있다)", res["incidents_ref"]["same"], "", warn=True)
    # 어긋난 센서는 줄 해시로 차이 줄을 찾는다
    diffs = {}
    for s in [k for k, v in res["sensors"].items() if not v["same"]][:5]:
        a = ctx.drill("hashes_drill_" + s, Q.q_hashes(s, lo, cut))
        b = ctx.prod("hashes_prod_" + s, Q.q_hashes(s, lo, cut))
        da = {f[0]: f[1] for f in tagged(a.out, "h") if len(f) >= 2}
        db = {f[0]: f[1] for f in tagged(b.out, "h") if len(f) >= 2}
        only_prod = sorted(set(db) - set(da))
        only_drill = sorted(set(da) - set(db))
        path = os.path.join(ctx.run_dir, "regen-diff-%s.txt" % s)
        with open(path, "w", encoding="utf-8") as f:
            for h in only_prod:
                f.write("운영에만 %s %s\n" % (h, db[h]))
            for h in only_drill:
                f.write("훈련에만 %s %s\n" % (h, da[h]))
        diffs[s] = {"prod_only": len(only_prod), "drill_only": len(only_drill),
                    "sample": ["%s %s" % (h, db[h]) for h in only_prod[:5]], "file": os.path.basename(path)}
        ctx.say("    %s: 운영에만 %d · 훈련에만 %d → %s" % (s, len(only_prod), len(only_drill), path))
    res["diffs"] = diffs
    hosts = {}
    for line in r2.out.splitlines():
        root, _, rel = line.partition(" ")
        side = "drill" if root.startswith(DRILL_HOME) else "prod"
        hosts.setdefault(side, set()).add(rel)
    res["mirror_hosts"] = {"drill": sorted(hosts.get("drill", ())), "prod": sorted(hosts.get("prod", ())),
                           "prod_only": sorted(hosts.get("prod", set()) - hosts.get("drill", set()))}
    if res["mirror_hosts"]["prod_only"]:
        ctx.say("  참고: 운영 미러에만 있는 호스트 (OPSLOOP_HOSTS 밖이라 훈련 HOME 은 받지 않음): %s"
                % " · ".join(res["mirror_hosts"]["prod_only"]))
    ctx.state.data["compare"] = res
    return 1 if ctx.failed() else 0


def step_done(ctx):
    st = ctx.state
    tb = from_iso(st.get("precheck", "backup", "archive_created_utc"))
    tf = from_iso(st.get("t0", "t_f"))
    runs_max = st.get("restore", "runs_max") or "<훈련 runs_max>"
    z = ctx.drill("zero_again", Q.q_zero())
    fp = ctx.prod("fingerprint_prod", Q.q_fingerprint())
    loss = ctx.prod("loss", Q.q_loss(iso(tb) or "<T_b>", iso(tf) or "<T_f>", runs_max))  # 참고값 (로그인 · 판정 끝 시각)
    base = ctx.prod("baseline_prod", Q.Q_BASELINE)
    clock = clock_pair(ctx)
    if z.dry:
        ctx.mark("S9", "재생성 대조 · 무결성 통과 = 복구 완료")
        return 0
    zero = {f[0]: to_int(f[1]) for f in tagged(z.out, "z")}
    bad_zero = ["%s=%s" % (k, v) for k, v in zero.items() if v != 0]
    ctx.check("무결성 %d개 모두 0 (재적재 · 재탐지 뒤)" % len(Q.ZERO), len(zero) == len(Q.ZERO) and not bad_zero,
              " · ".join(bad_zero) or "%d개" % len(zero))
    diff = diff_fingerprints(st.get("verify", "fingerprint") or {}, parse_fingerprints(fp.out), tf)
    bad_fp = ["%s 바뀜 %d · 훈련에만 %d" % (k, v["changed"], v["drill_only"]) for k, v in diff.items() if not v["ok"]]
    ctx.check("지문: 판정 · 조치 · 감사는 복원 행이 운영과 같음 (운영에만 있는 행 = T_b 뒤 손실)", not bad_fp,
              " · ".join(bad_fp) or " · ".join("%s +%d" % (k, v["prod_only"]) for k, v in diff.items() if v["prod_only"])
              or "차이 없음")
    # DB 에만 있는 기록의 손실: 지문 차이(운영에만 있는 행 + 바뀐 행)를 T_f 앞뒤로 나눈 것 + 로그인 시각
    lz = {k: {"until_tf": v["until_tf"], "after_tf": v["after_tf"]} for k, v in diff.items()}
    lz.update({f[0]: {"until_tf": to_int(f[1]), "after_tf": to_int(f[2])} for f in tagged(loss.out, "l") if len(f) >= 3})
    mm = {f[0]: f[1] for f in tagged(loss.out, "m") if len(f) >= 2}
    prod_base = {f[0]: to_int(f[1]) for f in tagged(base.out, "b")}
    drill_runs = parse_pg_ts(st.get("restore", "runs_max"))
    next_run = parse_pg_ts(mm.get("runs_next"))
    bracket_ok = drill_runs is not None and tb is not None and drill_runs <= tb + timedelta(seconds=BRACKET_SLACK_S)
    ctx.check("T_b 하한: 복원 DB 마지막 탐지 실행 ≤ T_b (+%d초)" % BRACKET_SLACK_S, bracket_ok,
              "%s ≤ %s" % (iso(drill_runs), iso(tb)))
    ctx.check("T_b 상한 (참고: 운영 다음 실행 ≥ T_b)", next_run is None or tb is None or next_run >= tb,
              iso(next_run), warn=True)
    regen = st.get("compare") or {}
    ctx.check("재생성 대조 일치 (compare)", bool(regen.get("match")))
    rpo = compute_rpo(tb, tf, lz, parse_pg_ts(st.get("restore", "verdicts_max")), parse_pg_ts(mm.get("verdicts_max_tf")),
                      regen, st.get("precheck", "backup_gaps"))
    ctx.say("  RPO 설계 (T_f − T_b) %s초 (%s) · 백업 간격 최대 %s초 (%s) · 판정 손실 %s초 · (T_b, T_f] DB 전용 행 %s" % (
        rpo["design_s"], "합격" if rpo["pass"] else "불합격", rpo["backup_gap_max_s"],
        {True: "목표 안", False: "목표 초과"}.get(rpo["backup_gap_ok"], "모름"), rpo["lines"]["db_only"]["verdict_loss_s"],
        " · ".join("%s %s" % (k, v) for k, v in rpo["lines"]["db_only"]["lost_rows"].items() if v)))
    st.data["done"] = {"zero": zero, "fingerprint_diff": diff, "loss": lz, "loss_marks": mm, "prod_baseline_now": prod_base,
                       "bracket": {"drill_runs_max": iso(drill_runs), "t_b": iso(tb), "prod_next_run": iso(next_run),
                                   "lower_ok": bracket_ok},
                       "rpo": rpo, "clock_end": clock}
    if ctx.failed():
        return 1
    ctx.mark("S9", "재생성 대조 · 무결성 통과 = 복구 완료")
    rto = compute_rto(common.read_jsonl(os.path.join(ctx.run_dir, "marks.jsonl")))
    st.data["done"]["rto"] = rto
    ctx.say("  RTO (T0 → S9) %s초 · 서비스 재개 (T0 → S7) %s초 · 기준 %d초 · %s" % (
        rto["complete_s"], rto["service_s"], RTO_MAX_S, "합격" if rto["pass"] else "불합격"))
    return 0


def step_cleanup(ctx):
    ctx.run("console_rm", ["docker", "rm", "-f", CONSOLE_NAME], ok=(0, 1))
    ctx.run("tunnel_exit", tunnel_argv("exit"), ok=(0, 1, 255))
    sd = os.path.expanduser(SECRET_DIR)
    if ctx.apply:
        shutil.rmtree(sd, ignore_errors=True)
        ctx.check("Mac 비밀 폴더 지움", not os.path.exists(sd), sd)
    else:
        ctx.show("rm -rf %s" % shlex.quote(sd))
    r = ctx.sh("cleanup", DATA_HOST, script_cleanup(), timeout=300)
    p = ctx.prod("prod_after", Q.Q_PROD_STATE)
    if r.dry:
        return 0
    kv = kv_lines(r.out)
    ctx.check("훈련 컨테이너 · 볼륨 · 폴더 지움",
              (kv.get("left_container"), kv.get("left_volume"), kv.get("left_dir")) == ("0", "0", "0"),
              "%s · %s · %s" % (DRILL_DB, DRILL_VOLUME, DRILL_DIR))
    ctx.check("운영 DB 컨테이너 돌고 있음", kv.get("prod_running") == "true", kv.get("prod_running"))
    units = parse_units(r.out)
    ok_units = all(u.get("Result") == "success" for u in units.values()) and len(units) == 2
    ctx.check("운영 적재 · 다리 마지막 실행 성공", ok_units,
              " · ".join("%s %s %s" % (k, v.get("Result"), v.get("ExecMainExitTimestamp")) for k, v in units.items()))
    now = {f[0]: f[1:] for f in tagged(p.out, "p")}
    before = ctx.state.get("precheck", "prod", "state") or {}
    ctx.check("운영 알림 채널 켜짐 · 주소 그대로", "|".join(now.get("channels", [])) == before.get("channels")
              and "|".join(now.get("channels_sig", [])) == before.get("channels_sig"),
              "켜짐 %s" % "|".join(now.get("channels", [])))
    ev_now = to_int((now.get("events_max") or ["", ""])[-1])
    ev_before = to_int((before.get("events_max") or "|").split("|")[-1])
    ctx.check("운영 events 가 계속 는다", ev_now is not None and ev_before is not None and ev_now > ev_before,
              "%s → %s" % (ev_before, ev_now))
    rn, rb = parse_pg_ts("|".join(now.get("runs_max", []))), parse_pg_ts(before.get("runs_max"))
    ctx.check("운영 탐지 실행이 계속된다", rn is not None and rb is not None and rn > rb, "%s → %s" % (iso(rb), iso(rn)))
    ctx.state.data["cleanup"] = {"left": {k: kv.get(k) for k in ("left_container", "left_volume", "left_dir")},
                                 "prod_running": kv.get("prod_running"), "units": units,
                                 "prod_now": {k: "|".join(v) for k, v in now.items()},
                                 "checks": [c for c in ctx.checks]}
    return 1 if ctx.failed() else 0


# ──────────────────────────────────────────────────────────────
#  보고
# ──────────────────────────────────────────────────────────────
TOOL_FILES = ("infra/vmware/restore-drill/drill.py", "infra/vmware/restore-drill/queries.py",
              "infra/vmware/failover/mark.py", "infra/vmware/failover/common.py",
              "infra/vmware/scripts/verify-db-roles.sh", "infra/vmware/scripts/backup-db.sh")


def build_results(state, marks, records, git_head, worktree_note):
    st = state.get
    rto = compute_rto(marks)
    t0 = parse_pg_ts(rto["t0"]) if rto.get("t0") else None
    backup = dict(st("precheck", "backup") or {})
    backup.pop("path", None)
    backup.pop("globals_path", None)
    done = st("done") or {}
    diff = done.get("fingerprint_diff") or {}
    steps = [r for r in records if r.get("kind") == "step"]
    source = {}
    for rel in TOOL_FILES:
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            source[rel] = sha256_file(p)
    res = {
        "date": t0.astimezone(KST).strftime("%Y-%m-%d") if t0 else None,
        "timezone": "Asia/Seoul",
        "scope": ("DB 인스턴스 손실 복원 훈련 (이슈 #45). data01 호스트와 원장(S3 · Loki · 관문 · 관리 원장)은 유지. "
                  "훈련 DB 는 data01 의 별도 컨테이너(%s · %s:%d · cluster_name=%s), 운영 DB 는 읽기만 했다. "
                  "RTO 는 장애 선언 표시(T0)부터 재생성 대조 · 무결성 통과(S9)까지 Mac 시계로, 조회 · 판정 재개(S7)는 중간 지표다. "
                  "실제 장애를 주입하지 않아 탐지에 걸리는 시간은 빠진다. RPO 는 DB 시계(Archive created · now())로만 계산했다. "
                  "T_b 이전 행은 덤프에서 온 것이라 재생성 대조는 [T_b−1시간, T_r−30분) 의 provenance='real' 행만 본다. "
                  "시각 문자열은 UTC ISO." % (DRILL_DB, DRILL_BIND, DRILL_PORT, DRILL_CLUSTER)),
        "provenance": {"git_head": git_head, "worktree_note": worktree_note, "source_sha256": source},
        "criteria": {"rto_max_s": RTO_MAX_S, "rpo_target_s": RPO_TARGET_S, "rto_start": "T0 장애 선언",
                     "rto_end": "S9 재생성 대조 · 무결성 통과", "service_resume": "S7 조회 · 판정 재개 (중간 지표)",
                     "rpo_pass": "설계 RPO(T_f − T_b) ≤ 목표 · 재생성 대조 일치. 보관 덤프 간격 최댓값(실측 최악)은 "
                                 "rpo.backup_gap_ok 로 따로 적는다",
                     "integrity_zero": [n for n, _d, _s in Q.ZERO], "structure_reference": Q.EXPECT},
        "runs": [{
            "run": common.run_name(state.path and os.path.dirname(state.path)),
            "backup": dict(backup, gaps=st("precheck", "backup_gaps"), log=st("precheck", "backup_log"),
                           bracket=done.get("bracket")),
            "clock": {"precheck": st("precheck", "clock"), "t0": st("t0", "clock"), "end": done.get("clock_end"),
                      "marks_offset_ms": {c: (v or {}).get("offset_ms") for c, v in rto.get("steps", {}).items()}},
            "rto": rto,
            "rpo": done.get("rpo"),
            "restore": {k: st("restore", k) for k in ("rc", "toc_counts", "archive_created_toc", "counts", "catalog")},
            "roles": {"specs": [s[:2] for s in (st("roles", "specs") or [])], "members": st("roles", "members"),
                      "allow_deny": st("verify", "roles")},
            "integrity": {"zero_after_restore": st("verify", "zero"), "zero_after_regen": done.get("zero"),
                          "baseline_drill": st("verify", "baseline"), "baseline_prod_precheck": st("precheck", "prod", "baseline"),
                          "baseline_prod_end": done.get("prod_baseline_now"), "catalog": st("verify", "catalog"),
                          "sequences": st("verify", "sequences"), "notify_off": st("verify", "notify"),
                          "fingerprints": {k: {x: v[x] for x in ("drill_rows", "prod_rows", "same", "changed", "drill_only",
                                                                 "prod_only", "until_tf", "after_tf", "immutable", "ok")}
                                           for k, v in diff.items()}},
            "regen": {"run": st("regen"), "compare": st("compare")},
            "console": {"image_id": st("console", "image_id"), "url": st("console", "url"),
                        "verdicts": st("console_confirm", "verdicts"),
                        "human_checked": st("console_confirm", "human_checked")},
            "cleanup": st("cleanup"),
            "records": [{k: r.get(k) for k in ("name", "start", "seconds", "rc")} for r in steps],
        }],
        "exceptions": [
            "옛 허니팟 호스트(운영 미러에만 있는 host=, regen.compare.mirror_hosts.prod_only)는 /etc/default/opsloop-ingest 의 "
            "OPSLOOP_HOSTS 밖이라 빈 훈련 HOME 이 받지 않는다. T_b 전에 끝난 호스트면 대조 구간에 영향이 없다. "
            "'S3 센서 RPO 0' 을 빈 DB 재구축(data01 전손)까지 넓히면 틀린다.",
            "provenance='fixture' 행(원장에 없는 시험 행)은 재생성 대조에서 뺀다 (regen.compare.fixture_rows).",
            "data01 전손(Loki · 관문 원장은 Mac 사본뿐, env · 비밀값 재발급)은 이번 범위 밖이다.",
        ],
        "summary": {"rto_s": rto.get("complete_s"), "service_s": rto.get("service_s"), "rto_pass": rto.get("pass"),
                    "rpo_design_s": (done.get("rpo") or {}).get("design_s"),
                    "rpo_pass": (done.get("rpo") or {}).get("pass"),
                    "rpo_backup_gap_max_s": (done.get("rpo") or {}).get("backup_gap_max_s"),
                    "rpo_backup_gap_ok": (done.get("rpo") or {}).get("backup_gap_ok"),
                    "regen_match": (st("compare") or {}).get("match"),
                    "integrity_pass": bool(done) and all(v == 0 for v in (done.get("zero") or {"x": 1}).values())
                    and all(v["ok"] for v in diff.values()),
                    "cleanup_ok": bool(st("cleanup")) and all(c.get("ok") or c.get("warn")
                                                              for c in (st("cleanup", "checks") or [])),
                    "missing_steps": rto.get("missing")},
    }
    return res


def step_report(ctx):
    marks_path = os.path.join(ctx.run_dir, "marks.jsonl")
    rec_path = os.path.join(ctx.run_dir, "records.jsonl")
    if not ctx.apply:
        ctx.show("git -C %s rev-parse HEAD" % shlex.quote(ROOT))
        ctx.say("  docs/evidence/<T0 KST 날짜>-restore/results.json · sha256.json 을 쓴다 (비밀 문자열이 있으면 쓰지 않는다)")
        return 0
    git = ctx.run("git_head", ["git", "-C", ROOT, "rev-parse", "HEAD"], ok=(0, 128))
    st = ctx.run("git_status", ["git", "-C", ROOT, "status", "--porcelain", "--"] + list(TOOL_FILES), ok=(0, 128))
    note = "도구 파일은 git HEAD 와 같다" if not st.out.strip() else "도구 파일에 커밋 안 된 변경이 있다: " + " ".join(
        x[3:] for x in st.out.splitlines())
    marks = common.read_jsonl(marks_path)
    records = common.read_jsonl(rec_path)
    res = build_results(ctx.state, marks, records, git.out.strip() or None, note)
    files = {}
    for p in (marks_path, rec_path):
        if os.path.isfile(p):
            files[os.path.basename(p)] = sha256_file(p)
    res["runs"][0]["files"] = files
    if not res["date"]:
        raise StepFail("T0 표시가 없다")
    out_dir = os.path.expanduser(ctx.args.out) if ctx.args.out else os.path.join(
        ROOT, "docs", "evidence", "%s-restore" % res["date"])
    text = json.dumps(res, ensure_ascii=False, indent=2) + "\n"
    found = find_secrets(text, ctx.secrets)
    if found:
        raise StepFail("결과에 비밀 문자열 모양이 있다 (%s). 쓰지 않는다" % ", ".join(sorted(set(found))))
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        f.write(text)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    with open(os.path.join(out_dir, "sha256.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"results.json": sha}, indent=2) + "\n")
    s = res["summary"]
    ctx.say("  %s/results.json · sha256 %s" % (out_dir, sha[:12]))
    ctx.say("  RTO %s초 (%s) · 서비스 재개 %s초 · RPO 설계 %s초 (%s) · 백업 간격 최대 %s초 (%s) · 재생성 %s · 무결성 %s · 정리 %s" % (
        s["rto_s"], "합격" if s["rto_pass"] else "불합격", s["service_s"], s["rpo_design_s"],
        "합격" if s["rpo_pass"] else "불합격", s["rpo_backup_gap_max_s"],
        {True: "목표 안", False: "목표 초과"}.get(s["rpo_backup_gap_ok"], "모름"), "일치" if s["regen_match"] else "불일치",
        "통과" if s["integrity_pass"] else "실패", "확인" if s["cleanup_ok"] else "미확인"))
    return 0


STEP_FUNCS = {"precheck": step_precheck, "t0": step_t0, "up": step_up, "roles": step_roles, "restore": step_restore,
              "verify": step_verify, "console": step_console, "regen": step_regen, "compare": step_compare,
              "done": step_done, "cleanup": step_cleanup, "report": step_report}


# ──────────────────────────────────────────────────────────────
#  인자 · 본체
# ──────────────────────────────────────────────────────────────
def parse_args(argv):
    p = argparse.ArgumentParser(description="DB 복원 훈련 (이슈 #45). 사용법은 파일 머리 주석")
    p.add_argument("--list", action="store_true", help="단계와 하는 일을 보이고 끝낸다")
    p.add_argument("run_dir", nargs="?", help="회차 폴더 (예: ~/opsloop-drill/r01. 저장소 밖)")
    p.add_argument("step", nargs="?", choices=STEP_NAMES)
    p.add_argument("--apply", action="store_true", help="실제로 돌린다 (없으면 드라이런)")
    p.add_argument("--backup-dir", default=BACKUP_DIR, help="precheck: 백업 폴더 (기본 ~/opsloop-backup)")
    p.add_argument("--dump", default=None, help="precheck: 쓸 덤프 (기본: 역할 목록과 짝인 가장 새 덤프)")
    p.add_argument("--confirm", action="store_true", help="console: 사람이 확인한 뒤 판정 반영을 보고 rto:S7")
    p.add_argument("--out", default=None, help="report: 증거 폴더 (기본 docs/evidence/<T0 KST 날짜>-restore)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        for name, desc in STEPS:
            print("  %-9s %s" % (name, desc))
        return 0
    if not args.run_dir or not args.step:
        raise ToolError("회차 폴더와 단계가 필요하다 (--list)")
    if args.confirm and args.step != "console":
        raise ToolError("--confirm 은 console 단계에만 쓴다")
    run_dir = os.path.abspath(os.path.expanduser(args.run_dir))
    if run_dir.startswith(ROOT + os.sep):
        raise ToolError("회차 폴더는 저장소 밖에 둔다 (상태 · 기록에 운영 지문이 든다): %s" % run_dir)
    key = "console-confirm" if args.confirm else args.step
    state = State(run_dir)
    if args.apply:
        missing = [s for s in PREREQ[key] if not state.get("steps", s, "ok")]
        if missing:
            raise ToolError("앞 단계가 끝나지 않았다: %s (드라이런은 순서 없이 볼 수 있다)" % " · ".join(missing))
        os.makedirs(run_dir, mode=0o700, exist_ok=True)
        os.chmod(run_dir, 0o700)
    ctx = Ctx(args, run_dir, key, state)
    desc = dict(STEPS)[args.step]
    print("== %s · %s · %s" % (key, desc, "실제로 돌린다" if args.apply else
                                "드라이런 (명령 · SQL 만 찍는다. 원격 · docker 에 아무것도 하지 않는다)"), flush=True)
    if not args.apply and PREREQ[key]:
        print("  선행 단계: %s" % " · ".join(PREREQ[key]))
    start, t = time.time_ns(), time.monotonic()
    rc = 1
    try:
        rc = STEP_FUNCS[args.step](ctx)
    except StepFail as e:
        ctx.say("  ✘ %s" % e)
        rc = 1
    finally:
        if args.apply:
            state.data.setdefault("steps", {})[key] = {"ok": rc == 0, "rc": rc, "at": common.iso(start),
                                                      "seconds": round(time.monotonic() - t, 3)}
            state.save()
            ctx.record_step(start, time.monotonic() - t, rc)
    if args.apply:
        print("끝: %s · %s" % (key, "성공" if rc == 0 else "실패 (위 ✘ 를 본다)"))
    else:
        print("드라이런이다. 실제로 돌리려면 --apply")
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ToolError as e:
        print("오류: %s" % e, file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
