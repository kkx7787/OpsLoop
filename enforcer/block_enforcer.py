#!/usr/bin/env python3
"""차단 집행기 (이슈 #47). DB 차단 목록을 관문에 넘기고, 관문이 보고한 적용 결과를 DB 에 되쓴다.

데이터 노드에서 돈다. opsloop-enforcer.timer 가 1분마다 opsloop-enforcer 사용자로 `run` 을 돌린다.

  DB blocklist ─(opsloop_enforcer, 읽기)→ 원하는 목록 ─(S3 쓰기 사용자)→ s3://<버킷>/block/v1/latest.json
  관문 block-sync.py (1분) ─ 목록 읽기 · 재검사 · fail2ban 또는 nft 집합 → s3://<버킷>/hb/v1/host=<관문 ID>-block/latest.json
  이 집행기 ─(원장 읽기 사용자)→ 관문 보고 대조 → blocklist 의 method · enforced_at · enforce_note (이 세 열만 고친다)

하위 명령
  run [--dry-run]  한 회차. --dry-run 은 DB · 관문 보고를 읽고 할 일만 찍는다 (S3 · DB · 상태 파일을 고치지 않는다)
  list             올릴 목록 JSON 을 찍는다 (DB 만 읽는다)
  status           마지막 회차 · 관문 보고 · 집행 상태별 건수를 찍는다 (읽기만)

원하는 목록
  released_at IS NULL · expires_at > now() · IPv4 /32 · 금지 대역(block_exempt 표와 EXEMPT_NETS) 밖인 행.
  4096 개(관문 집합 크기)를 넘으면 요청이 늦은 것부터 넣고 나머지는 '관문 불일치 · 목록 상한 …' 으로 둔다.
  목록이 바뀔 때와 10분마다(생존 표시) 올린다. DB 를 못 읽으면 올리지 않는다(관문은 옛 집합을 두고 만료로 저절로 뺀다).
  digest 는 entries 를 ip 문자열 순으로 두고 json.dumps(sort_keys=True, separators=(",", ":")) 로 쓴 UTF-8 의 sha256 이다.
  until 은 expires_at 을 초 단위로 내린 UTC ISO(…Z)다.

관문 보고 대조 (행마다)
  관문 보고의 list_digest 가 이 집행기가 올린 목록이면, 그 목록이 S3 에 있던 마지막 회차로 행이 들어 있는지 가린다.
  목록이 1분마다 바뀌어도(흡수 후속 차단) 관문이 한 회차 늦게 반영한 행을 확인할 수 있다. 지금 목록과 digest 가
  같을 때만 보면 목록이 쉬지 않고 바뀌는 동안 아무 행도 확인되지 않는다.
  - 확인(보고가 5분 안 · 그 목록에 (ip, until) 이 있음 · rejected 에 없음 · 셈이 맞음): enforced_at = 처음 확인한 보고의 at,
    method = 보고의 mode, enforce_note = '관문 반영 · <digest 앞 8자> · <at>'. 같은 (ip, until, mode) 는 다시 쓰지 않는다
    (감사 이벤트가 쌓이지 않게). 관문은 목록을 적용한 뒤 실제 집합과 대조해 빠진 항목을 rejected 로 돌려주므로 행마다의 판단은
    rejected 가 맡는다. 다른 관문 오류(되살림 · 일부 반영 실패 · 목록 밖 원소)는 로그에만 남기고 그 밖의 행은 확인한다 — 한 행이
    계속 실패한다고 집합에 있는 행까지 불일치로 두면 화면 · 대시보드가 '막지 못했다'고 잘못 읽히고, 풀릴 때 행마다 새 at 으로
    다시 써 감사 이벤트가 쌓인다.
    셈이 맞지 않으면(적용 수 + 거부 수 < 목록 · 집합 원소 수 < 적용 수 · 거부 목록이 관문 상한 200 에 닿아 잘렸을 수 있음)
    어느 행이 빠졌는지 모르므로 어느 행도 확인하지 않는다.
  - rejected · 확인은 관문이 적용한 목록에 이 행의 (ip, until) 이 들어 있을 때만 이 행의 것이다. 연장 전 until 로 만든 옛 목록의
    '만료 지남' 거부나 (상태 파일을 잃은 뒤의) 모르는 목록의 거부는 이 행에 붙이지 않고 새 목록의 보고를 기다린다.
  - 불일치: 관문 보고를 5분 넘게 못 읽음 · 보고가 5분 넘게 멈춤 · 모르는 목록 5분 · 셈이 맞지 않는 보고 5분 · 올린 지 5분이 지나도
    반영 안 됨 · 관문이 거부(rejected, 바로) · 목록을 5분 넘게 못 올려 S3 에 없는 행 → enforce_note '관문 불일치 · <사유>'.
    enforced_at 은 그대로 둔다. 불일치를 거친 행은 다시 확인될 때 새 at 으로 확인한다 (그 사이 집합이 비었다 되살아났을 수 있다).
  - 목록에서 빠진 행(해제 · 만료 · 제외): 관문이 그 행이 빠진 목록을 오류 없이 적용했다고 보고하면 enforced_at 을 NULL 로
    (unenforced 감사. 관문 오류가 있는 회차는 목록 밖 원소가 남았을 수 있어 기다린다).
    해제 · 만료된 행은 만료 뒤 24시간(관문 jail bantime)이 지나면 보고 없이도 NULL 로 한다. 관문 원소는 nft 방식이면 목록의
    until 에, fail2ban 방식이면 마지막으로 건 때부터 24시간 뒤에 빠지므로 어느 쪽이든 그때는 없다. 그 전에는 관문 확인을 기다린다.
    쪽지는 그대로 둔다 (언제 반영됐는지의 기록. 화면은 해제 · 만료를 released_at · expires_at 으로 먼저 가른다).
  - 만료: 지난 2일 안에 만료된 행마다 note_block_expired(ip, expires_at) 를 한 번 부른다 (DB 쪽이 line_hash 로 멱등).
  - 제외: 만료 없음 · 금지 대역 · 대역 주소 행은 enforce_note '집행 제외 · …' (값이 같으면 쓰지 않는다).
    제외였던 행이 목록에 들어오면(만료를 새로 줬다 등) 확인될 때까지 쪽지를 비워 '집행 대기'로 둔다.
    IPv6 /128 행은 관문 집합(IPv4 만)에 넣지 않지만 계약에 맞는 쪽지가 없어 쪽지를 두지 않는다.
  쪽지 · 집행 열은 값이 바뀔 때만 쓴다. 숫자만 다른 불일치 쪽지(관문 문구의 분 · 건수)는 같은 것으로 본다.
  DB 쓰기는 읽은 값(released_at · expires_at · 집행 세 열)이 그대로일 때만 한다. 그 사이 콘솔이 고친 행은 다음 회차에 본다.

상태 파일 ($OPSLOOP_ENFORCER_HOME/state.json)
  회차 번호 · 올린 목록 · digest 별 마지막 회차 · 행이 목록에 들어온/빠진 회차 · 확인 기록 · 5분 시계 · 만료 기록.
  잃으면 목록을 다시 올리고, DB 에 남은 확인 쪽지를 이어받는다 (같은 값을 다시 쓰지 않는다).

종료 코드
  0  정상 (관문 불일치는 DB 쪽지 · 로그 경고로 드러낸다)
  1  이번 회차에 못 한 일이 있다 (DB 읽기 · 쓰기, 목록 올리기, 관문 보고 읽기)
  2  설정 오류 (버킷 · 비밀 파일 · 인자)

설정
  /etc/default/opsloop-enforcer  OPSLOOP_BUCKET · OPSLOOP_GATEWAY_ID · OPSLOOP_ENFORCER_HOME · AWS_DEFAULT_REGION (비밀 아님)
  비밀 파일 셋은 0600 root:root 다. 서비스는 systemd LoadCredential 로 읽기 전용 사본을 받는다($CREDENTIALS_DIRECTORY).
  root 로 손으로 돌리면 /etc/opsloop 의 원본을 읽는다.
    enforcer.env   DATABASE_URL (opsloop_enforcer 역할). DB 연결에만 쓴다
    s3-block.env   AWS_ACCESS_KEY_ID · AWS_SECRET_ACCESS_KEY (opsloop-block-writer, block/v1/latest.json 쓰기만)
    s3-pull.env    AWS_ACCESS_KEY_ID · AWS_SECRET_ACCESS_KEY (opsloop-archive-reader, hb/* 읽기. 적재기와 같은 키)
  비밀 파일은 셸로 읽지 않는다 (KEY=VALUE 만 읽고 실행하지 않는다). 키는 S3 클라이언트에만 넘긴다.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timedelta, timezone

LIST_KEY = "block/v1/latest.json"
STATUS_KEY = "hb/v1/host={gw}-block/latest.json"
LIST_MAX = 4096                          # 관문 nft 집합 opsloop_block 의 size
REFRESH = timedelta(minutes=10)          # 목록이 그대로여도 이 간격으로 다시 올린다 (관문이 목록이 살아 있음을 안다)
REFRESH_EARLY = timedelta(seconds=30)    # 1분 타이머가 조금 늦어도 10분을 넘기지 않게
STALE = timedelta(minutes=5)             # 관문 보고의 신선도 · 불일치로 볼 때까지 기다리는 시간
FUTURE_SLACK = timedelta(minutes=2)      # 관문 시계가 이보다 앞서면 보고를 믿지 않는다
EXPIRED_LOOKBACK = timedelta(days=2)     # 이 안에 만료된 행만 만료 기록을 남긴다 (집행기가 멈췄던 동안의 만료도 줍는다)
BAN_HOLD = timedelta(hours=24)           # 관문 jail opsloop-block 의 bantime. 만료 뒤 이만큼 지나면 어느 방식이든 빠졌다
COUNT_SLACK = timedelta(minutes=2)       # 적용 수를 셀 때 곧 만료될 항목은 빼고 센다
SEEN_KEEP = 360                          # digest 별 마지막 회차를 이만큼(6시간) 기억한다
KEEP = timedelta(days=3)                 # 빠진 행 · 만료 기록을 상태에 두는 기간
STATUS_MAX = 2 * 1024 * 1024
REJECTED_MAX = 4096
GW_REJECTED_CAP = 200                    # 관문 block-sync.py 의 MAX_REJECTED. 거부 수가 여기 닿으면 잘렸을 수 있어 확인하지 않는다
ERRORS_MAX = 100
TEXT_MAX = 160                           # 관문이 보낸 문구를 쪽지에 넣을 때의 상한
LOCK_WAIT = 30
DEFAULT_GATEWAY = "i-0ffeb29efad03546d"  # 설정 OPSLOOP_GATEWAY_ID 가 없을 때 (2026-09-27 조사)
GATEWAY_ID_RE = re.compile(r"i-[0-9a-f]{8,17}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
MODES = ("fail2ban", "nft")

# 차단 금지 대역. DB 의 block_exempt 표가 먼저고(트리거가 막는다), 이 상수는 표가 비거나 바뀌어도 남는 둘째 벽이다.
# 관문 block-sync.py 도 같은 목록으로 한 번 더 거른다. 문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)은
# 시험 출발지로 쓰므로 넣지 않는다. 15.164.37.49 는 관문 EIP 다
EXEMPT_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "15.164.37.49/32",
    "::1/128", "fc00::/7", "fe80::/10"))

NOTE_APPLIED = "관문 반영 · {d8} · {at}"
NOTE_MISMATCH = "관문 불일치 · {why}"
NOTE_NO_EXPIRY = "집행 제외 · 만료 없음"
NOTE_EXEMPT = "집행 제외 · 금지 대역"
NOTE_RANGE = "집행 제외 · 대역 주소"
APPLIED_RE = re.compile(r"관문 반영 · ([0-9a-f]{8}) · ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z)")

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SURROGATE = re.compile("[\ud800-\udfff]")


class ConfigError(Exception):
    """설정 오류 (종료 코드 2)."""


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


def clean(v, n=TEXT_MAX):
    """관문 · S3 가 준 문구를 로그 · DB 쪽지에 넣을 때. 제어 · 형식(Cf) · 줄 구분 문자를 '?' 로 바꾸고 자른다."""
    s = _SURROGATE.sub("?", _CTRL.sub("?", str(v)))
    s = "".join("?" if unicodedata.category(c) in ("Cf", "Zl", "Zp") else c for c in s)
    return s[:n]


def why(e):
    return clean(f"{type(e).__name__}: {e}", 300)


def iso(dt):
    """초 단위로 내린 UTC ISO (…Z). 목록의 until · 쪽지의 시각에 쓴다."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


def iso_full(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


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


def settings():
    """버킷 · 관문 ID · 상태 폴더 · 지역. 환경변수가 먼저고, 없으면 /etc/default/opsloop-enforcer 에서 읽는다."""
    try:
        conf = read_env(os.environ.get("OPSLOOP_ENFORCER_DEFAULTS", "/etc/default/opsloop-enforcer"))
    except OSError:
        conf = {}

    def get(k, default=None):
        return os.environ.get(k) or conf.get(k) or default
    gw = get("OPSLOOP_GATEWAY_ID", DEFAULT_GATEWAY)
    if not GATEWAY_ID_RE.fullmatch(gw):
        raise ConfigError(f"OPSLOOP_GATEWAY_ID 가 인스턴스 ID 가 아니다: {clean(gw, 40)}")
    return {"bucket": get("OPSLOOP_BUCKET"), "gateway": gw,
            "home": get("OPSLOOP_ENFORCER_HOME", "/var/lib/opsloop-enforcer"),
            "region": get("AWS_DEFAULT_REGION", "ap-northeast-2")}


SECRET_OVERRIDE = {"enforcer.env": "OPSLOOP_ENFORCER_DB_ENV", "s3-block.env": "OPSLOOP_ENFORCER_S3_BLOCK_ENV",
                   "s3-pull.env": "OPSLOOP_ENFORCER_S3_PULL_ENV"}


def secret_path(name):
    """서비스로 돌면 systemd 가 건넨 사본($CREDENTIALS_DIRECTORY), 손으로 돌리면 /etc/opsloop 의 원본."""
    over = os.environ.get(SECRET_OVERRIDE[name])
    if over:
        return over
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd and os.path.exists(os.path.join(cd, name)):
        return os.path.join(cd, name)
    return os.path.join("/etc/opsloop", name)


def db_connect():
    path = secret_path("enforcer.env")
    try:
        url = read_env(path)["DATABASE_URL"]
    except (OSError, KeyError) as e:
        raise ConfigError(f"DB 접속 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    import psycopg2
    return psycopg2.connect(url, connect_timeout=10, application_name="opsloop-enforcer")


def s3_client(cfg, name):
    """name 의 키로 만든 S3 클라이언트. 키는 이 클라이언트에만 넘기고 환경변수에 두지 않는다."""
    if not cfg["bucket"]:
        raise ConfigError("OPSLOOP_BUCKET 이 없다 (/etc/default/opsloop-enforcer)")
    path = secret_path(name)
    try:
        keys = read_env(path)
    except OSError as e:
        raise ConfigError(f"S3 키 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    if not keys.get("AWS_ACCESS_KEY_ID") or not keys.get("AWS_SECRET_ACCESS_KEY"):
        raise ConfigError(f"S3 키가 비었다 ({path})")
    # 노드의 ~/.aws 설정 · 인스턴스 메타데이터를 보지 않는다 (내부망 VM 이라 메타데이터 조회는 시간만 끈다)
    for k in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        os.environ.setdefault(k, os.devnull)
    os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
    import boto3
    from botocore.config import Config
    return boto3.client("s3", region_name=cfg["region"], aws_access_key_id=keys["AWS_ACCESS_KEY_ID"],
                        aws_secret_access_key=keys["AWS_SECRET_ACCESS_KEY"],
                        config=Config(connect_timeout=10, read_timeout=30, retries={"max_attempts": 3}))


def err_code(e):
    try:
        return str(e.response["Error"]["Code"])
    except (AttributeError, KeyError, TypeError):
        return type(e).__name__


# ── 목록 ─────────────────────────────────────────────────────────────────────

def in_exempt(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in EXEMPT_NETS if n.version == a.version)


def classify(row, now):
    """행 하나의 갈래. ('list', expires_at) · ('exclude', 쪽지) · ('expired'|'released'|'skip', None)."""
    if row["released_at"] is not None:
        return "released", None
    exp = row["expires_at"]
    if exp is not None and exp <= now:
        return "expired", None
    if row["mask"] != (32 if row["fam"] == 4 else 128):
        return "exclude", NOTE_RANGE
    if row["exempt_net"] or in_exempt(row["ip"]):
        return "exclude", NOTE_EXEMPT
    if exp is None:
        return "exclude", NOTE_NO_EXPIRY
    if row["fam"] != 4:
        # 관문 유입(EIP)은 IPv4 뿐이고 집합도 ipv4_addr 다. 계약의 쪽지 다섯에 맞는 것이 없어 쪽지를 두지 않는다
        return "skip", None
    return "list", exp


def classify_rows(rows, now):
    """행마다 kind · extra 를 달고, 올릴 항목(상한 안)을 돌려준다. 상한을 넘은 행은 kind='overcap'."""
    listed = []
    for r in rows:
        r["kind"], r["extra"] = classify(r, now)
        if r["kind"] == "list":
            listed.append(r)
    # 요청이 늦은 것부터 (같으면 주소 순). 오래된 요청보다 새 요청이 지금의 위협에 가깝다
    listed.sort(key=lambda r: (-(r["created_at"].timestamp() if r["created_at"] else 0), r["ip"]))
    for r in listed[LIST_MAX:]:
        r["kind"] = "overcap"
    return sorted(({"ip": r["ip"], "until": iso(r["extra"])} for r in listed[:LIST_MAX]), key=lambda e: e["ip"])


def canonical(entries):
    return json.dumps(sorted(entries, key=lambda e: e["ip"]), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(entries):
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def list_doc(entries, now):
    entries = sorted(entries, key=lambda e: e["ip"])
    return {"v": 1, "generated_at": iso(now), "entries": entries, "digest": digest_of(entries)}


# ── 상태 ─────────────────────────────────────────────────────────────────────

def new_state():
    return {"v": 1, "seq": 0, "published": None, "seen": {}, "entries": {}, "gone": {}, "confirmed": {},
            "status_fail_since": None, "unknown_since": None, "error_since": None, "upload_fail_since": None,
            "expired_noted": {}}


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        if not isinstance(st, dict) or st.get("v") != 1:
            raise ValueError("판이 다르다")
    except FileNotFoundError:
        return new_state()
    except (OSError, ValueError) as e:
        log(f"상태 파일을 읽지 못해 새로 시작한다 ({why(e)}). 목록을 다시 올리고 DB 의 확인 쪽지를 이어받는다", 4)
        return new_state()
    for k, v in new_state().items():
        if k not in st or (v is not None and not isinstance(st[k], type(v))):
            st[k] = v
    return st


def save_state(path, st):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def take_lock(home, wait=LOCK_WAIT, sleep=time.sleep):
    # 읽기로 연다. root 가 손으로 돌려(--dry-run · status) 만든 잠금 파일도 서비스 사용자가 열 수 있다 (flock 은 읽기로도 된다)
    try:
        os.makedirs(home, exist_ok=True)
        f = os.fdopen(os.open(os.path.join(home, "enforcer.lock"), os.O_RDONLY | os.O_CREAT, 0o644), "rb")
    except OSError as e:
        raise ConfigError(f"상태 폴더를 쓸 수 없다 ({home}: {type(e).__name__})") from None
    waited = 0
    while True:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except BlockingIOError:
            if waited >= wait:
                f.close()
                raise ConfigError(f"다른 실행이 {wait}초 넘게 끝나지 않았다") from None
            sleep(1)
            waited += 1


def since(st, key, now):
    """5분 시계. 처음이면 지금을 적고, 적힌 때부터 지난 시간을 돌려준다."""
    t = parse_ts(st.get(key)) if st.get(key) else None
    if t is None or t > now:
        st[key] = iso_full(now)
        return timedelta(0)
    return now - t


def bookkeep(st, entries, digest, now):
    """올린 목록이 S3 에 있는 회차의 기록. 행이 목록에 들어온 회차 · 빠진 회차 · digest 가 마지막으로 있던 회차.

    관문이 digest D 를 적용했다고 하면: seen[D] ≥ 들어온 회차인 행은 D 에 있고(그 뒤로 빠진 적이 없으므로),
    seen[D] ≥ 빠진 회차인 행은 D 에 없다. 같은 내용이 다시 나오면 digest 도 같으니 마지막 회차만 기억하면 된다.
    """
    seq = st["seq"]
    st["seen"][digest] = seq
    cur = {e["ip"]: e["until"] for e in entries}
    for ip, until in cur.items():
        e = st["entries"].get(ip)
        if not e or e.get("until") != until:
            st["entries"][ip] = {"until": until, "seq": seq, "at": iso_full(now)}
        st["gone"].pop(ip, None)
    for ip in [ip for ip in st["entries"] if ip not in cur]:
        st["gone"][ip] = {"seq": seq, "at": iso_full(now)}
        del st["entries"][ip]
    st["seen"] = {d: s for d, s in st["seen"].items() if isinstance(s, int) and s >= seq - SEEN_KEEP}


# ── 관문 보고 ─────────────────────────────────────────────────────────────────

def _no_const(v):
    raise ValueError(f"JSON 상수 {v}")


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10 ** 9 else None


def validate_status(d, now):
    """(보고, None) 또는 (None, 까닭). 관문이 장악돼도 이 값으로 DB 에 쓰는 것은 검증한 시각 · 방식 · 짧은 문구뿐이다."""
    if not isinstance(d, dict) or d.get("v") != 1:
        return None, "형식 틀림 (v)"
    at = parse_ts(d.get("at"))
    if at is None:
        return None, "형식 틀림 (at)"
    if at > now + FUTURE_SLACK:
        return None, "관문 시각이 앞섬"
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


def read_status(s3r, bucket, key, now):
    """(보고, 까닭). 못 읽었거나 틀렸으면 보고는 None."""
    try:
        r = s3r.get_object(Bucket=bucket, Key=key)
        body = r["Body"].read(STATUS_MAX + 1)
    except Exception as e:  # noqa: BLE001 - boto3 · 연결 오류를 모두 '읽지 못함'으로 본다
        code = err_code(e)
        return None, "없음 (관문 동기화가 아직 쓰지 않았다)" if code in ("NoSuchKey", "404") else clean(code, 60)
    if len(body) > STATUS_MAX:
        return None, "크기 초과"
    try:
        d = json.loads(body, parse_constant=_no_const)
    except (ValueError, RecursionError):
        return None, "JSON 이 아니다"
    return validate_status(d, now)


def judge(st, gw, problem, now, published):
    """관문 보고를 이번 회차의 판단으로. published 는 (digest, 항목) — 올린 목록이 S3 에 있을 때만."""
    j = {"ok": False, "verified": False, "gseq": None, "mode": None, "at": None, "d8": None, "mismatch": None,
         "rejected": {}, "problems": []}
    if gw is None:
        age = since(st, "status_fail_since", now)
        j["problems"].append(f"관문 보고를 읽지 못했다: {problem}")
        if age >= STALE:
            j["mismatch"] = f"관문 상태를 읽지 못함 ({problem})"
        return j
    st["status_fail_since"] = None
    j.update(mode=gw["mode"], at=gw["at"])
    if now - gw["at"] > STALE:
        # 쪽지가 회차마다 바뀌지 않게 지난 시간(분) 대신 마지막 보고 시각을 적는다
        st["unknown_since"] = st["error_since"] = None
        j["mismatch"] = f"관문 보고가 5분 넘게 멈춤 (마지막 {iso(gw['at'])})"
        return j
    j["rejected"] = gw["rejected"]
    dg = gw["digest"]
    j["gseq"] = st["seen"].get(dg) if dg else None
    j["d8"] = dg[:8] if dg else None
    if j["gseq"] is None:
        # list_digest 가 비면 관문이 목록을 못 읽었거나 대조를 못 마친 것이다. 관문의 첫 오류가 까닭이다
        age = since(st, "unknown_since", now)
        if dg:
            what = f"관문이 모르는 목록을 적용함 ({dg[:8]})"
        elif gw["errors"]:
            what = f"관문이 목록을 적용하지 못함 · {gw['errors'][0]}"
        else:
            what = "관문이 목록을 아직 적용하지 않음"
        j["problems"].append(what)
        if age >= STALE:
            j["mismatch"] = what
        return j
    st["unknown_since"] = None
    # 관문이 아는 목록을 적용했다. 행마다의 판단은 rejected 가 맡는다 (관문이 실제 집합과 대조해 빠진 항목을 돌려준다).
    # 셈이 맞지 않으면 어느 행이 빠졌는지 모르므로 어느 행도 확인하지 않는다. 그 밖의 관문 오류는 로그에만 남긴다
    problems = []
    if published and dg == published[0]:
        want = sum(1 for e in published[1] if (parse_ts(e["until"]) or now) > gw["at"] + COUNT_SLACK)
        if gw["applied"] + len(gw["rejected"]) < want:
            problems.append(f"적용 수 부족 ({gw['applied']}/{want})")
    if gw["set_count"] is not None and gw["set_count"] < gw["applied"]:
        problems.append(f"집합 원소 수 부족 ({gw['set_count']}/{gw['applied']})")
    if len(gw["rejected"]) >= GW_REJECTED_CAP:
        problems.append(f"거부 목록이 관문 상한에 닿음 ({len(gw['rejected'])})")
    j["problems"] += problems + gw["errors"]
    if problems:
        age = since(st, "error_since", now)
        if age >= STALE:
            j["mismatch"] = f"관문 오류 · {problems[0]}"
        return j
    st["error_since"] = None
    j["verified"] = True                  # 행마다 확인 · 거부를 판단할 수 있다
    j["ok"] = not gw["errors"]            # 목록 밖 원소까지 없는 깨끗한 회차 (집행 해제는 이때만)
    return j


# ── 행마다 할 일 ──────────────────────────────────────────────────────────────

def mismatch(reason):
    return NOTE_MISMATCH.format(why=clean(reason, TEXT_MAX))


_DIGITS = re.compile(r"[0-9]+")


def same_mismatch(a, b):
    """숫자만 다른 불일치 쪽지는 같은 것으로 본다 ('목록이 오래됨 (12분)' 처럼 관문 문구의 수가 회차마다 바뀐다)."""
    p = NOTE_MISMATCH.format(why="")
    return bool(a) and a.startswith(p) and b.startswith(p) and _DIGITS.sub("#", a) == _DIGITS.sub("#", b)


def adopt(row, until, j):
    """상태 파일을 잃었을 때 DB 에 남은 확인을 이어받는다 (같은 값을 다시 써서 감사 이벤트를 만들지 않게)."""
    m = APPLIED_RE.fullmatch(row["note"] or "")
    if not m or row["enforced_at"] is None or row["method"] != j["mode"] or m.group(2) != iso(row["enforced_at"]):
        return None
    return {"until": until, "at": iso(row["enforced_at"]), "d8": m.group(1), "mode": j["mode"]}


def want_listed(row, st, j, now):
    ip, until = row["ip"], iso(row["extra"])
    e = st["entries"].get(ip)
    published = bool(e) and e.get("until") == until
    # 관문이 적용한 목록에 이 (ip, until) 이 들어 있는가. 연장 전 until 의 옛 목록이나 모르는 목록의 거부 · 확인은 이 행의 것이 아니다
    applied = published and j["gseq"] is not None and j["gseq"] >= e["seq"]
    if applied and ip in j["rejected"]:
        if row["extra"] <= j["at"] + COUNT_SLACK:
            # 곧 만료될 행의 거부(관문 시각으로 '만료 지남')는 확인도 불일치도 아니다. 다음 회차에 만료로 빠진다
            return {}, "pending"
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch("관문 거부 · " + j["rejected"][ip])}, "reject"
    if j["verified"] and applied:
        c = st["confirmed"].get(ip)
        if not c or c.get("until") != until or c.get("mode") != j["mode"]:
            c = (adopt(row, until, j) if not c else None) or {"until": until, "at": iso(j["at"]), "d8": j["d8"],
                                                             "mode": j["mode"]}
            st["confirmed"][ip] = c
        return {"enforced_at": parse_ts(c["at"]), "method": c["mode"],
                "enforce_note": NOTE_APPLIED.format(d8=c["d8"], at=c["at"])}, "confirm"
    if j["mismatch"]:
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch(j["mismatch"])}, "mismatch"
    if not published and j.get("upload_stuck"):
        # 이 (ip, until) 이 든 목록을 5분 넘게 S3 에 올리지 못했다. 관문은 옛 목록을 적용하므로 이대로는 반영되지 않는다
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch(j["upload_stuck"])}, "mismatch"
    # 셈이 맞는 보고인데 그 목록에 이 행이 없고 올린 지 5분이 지났다. 그렇지 않은 회차(셈 불일치 · 모르는 목록 · 못 읽음)는
    # 위의 5분 시계들이 맡는다
    if j["verified"] and published and now - (parse_ts(e.get("at")) or now) >= STALE:
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch("5분 넘게 반영되지 않음")}, "mismatch"
    return {}, "pending"


def want_unenforce(row, st, j, now, current):
    """목록 밖 행의 enforced_at 을 NULL 로 할 때인가."""
    if row["enforced_at"] is None:
        return False
    ip = row["ip"]
    g = st["gone"].get(ip)
    if g is None and current:
        # 목록에 없던 집행 기록 (상태 파일을 잃었거나 다른 곳에서 썼다). 지금 올린 목록부터 센다
        g = st["gone"][ip] = {"seq": st["seq"], "at": iso_full(now)}
    if g and j["ok"] and j["gseq"] >= g["seq"]:
        return True
    # 관문 보고가 끊겨도 만료 뒤 24시간이면 관문 원소는 빠졌다 (해제도 같다. 해제는 만료를 바꾸지 않는다)
    exp = row["expires_at"]
    return row["kind"] in ("expired", "released") and exp is not None and now >= exp + BAN_HOLD


def plan(rows, st, j, now, current):
    """DB 에 쓸 것 (행마다 바꿀 열 · 읽은 값) 과 만료 기록을 부를 행."""
    updates, expired, tally = [], [], {}
    for row in rows:
        kind, ip = row["kind"], row["ip"]
        want, tag = {}, kind
        if kind == "list":
            want, tag = want_listed(row, st, j, now)
            if tag == "pending" and (row["note"] or "").startswith("집행 제외"):
                # 제외였던 행이 목록에 들어왔다 (만료가 생겼거나 금지 대역에서 빠졌다). 확인 전까지는 '집행 대기'다
                want = {"enforce_note": None}
        else:
            st["confirmed"].pop(ip, None)
            if kind == "exclude":
                want["enforce_note"] = row["extra"]
            elif kind == "overcap":
                want["enforce_note"] = mismatch(f"목록 상한 {LIST_MAX} 초과")
            if want_unenforce(row, st, j, now, current):
                want["enforced_at"] = None
                st["gone"].pop(ip, None)
                tag = f"{kind}+unenforce"
        tally[tag] = tally.get(tag, 0) + 1
        cur = {"enforced_at": row["enforced_at"], "method": row["method"], "enforce_note": row["note"]}
        change = {k: v for k, v in want.items() if cur[k] != v}
        if "enforce_note" in change and same_mismatch(cur["enforce_note"], change["enforce_note"]):
            del change["enforce_note"]
        if change:
            updates.append({"key": row["key"], "ip": ip, "set": change, "tag": tag,
                            "guard": {"released_at": row["released_at"], "expires_at": row["expires_at"], **cur}})
        if kind == "expired" and now - row["expires_at"] <= EXPIRED_LOOKBACK:
            k = f"{row['key']}|{iso_full(row['expires_at'])}"
            if k not in st["expired_noted"]:
                expired.append((row["key"], row["expires_at"], k))
    return updates, expired, tally


def prune(st, rows, now):
    fetched = {r["ip"] for r in rows}
    for ip in [ip for ip, g in st["gone"].items()
               if ip not in fetched or now - (parse_ts(g.get("at")) or now) > KEEP]:
        del st["gone"][ip]
    listed = {r["ip"] for r in rows if r["kind"] == "list"}
    for ip in [ip for ip in st["confirmed"] if ip not in listed]:
        del st["confirmed"][ip]
    for k in [k for k, t in st["expired_noted"].items() if now - (parse_ts(t) or now) > KEEP]:
        del st["expired_noted"][k]


# ── DB ───────────────────────────────────────────────────────────────────────

FETCH_SQL = """
SELECT abbrev(b.actor_ip) AS key, host(b.actor_ip) AS ip, family(b.actor_ip) AS fam, masklen(b.actor_ip) AS mask,
       b.created_at, b.expires_at, b.released_at, b.enforced_at, b.method, b.enforce_note,
       (SELECT e.cidr::text FROM block_exempt e WHERE b.actor_ip <<= e.cidr
         ORDER BY masklen(e.cidr) DESC LIMIT 1) AS exempt_net
  FROM blocklist b
 WHERE (b.released_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now() - %s::interval))
    OR b.enforced_at IS NOT NULL
 ORDER BY b.actor_ip"""
FIELDS = ("key", "ip", "fam", "mask", "created_at", "expires_at", "released_at", "enforced_at", "method", "note",
          "exempt_net")
GUARD = ("released_at", "expires_at", "enforced_at", "method", "enforce_note")


class PgStore:
    """opsloop_enforcer 역할로 읽고 쓴다. 쓰는 열은 method · enforced_at · enforce_note 셋뿐이다."""

    def __init__(self, conn):
        self.conn = conn

    def fetch(self):
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '30s'")
            cur.execute("SELECT now()")
            now = cur.fetchone()[0]
            cur.execute(FETCH_SQL, (f"{int(EXPIRED_LOOKBACK.total_seconds())} seconds",))
            rows = [dict(zip(FIELDS, r)) for r in cur.fetchall()]
        return {"now": now, "rows": rows}

    def apply(self, updates):
        """한 트랜잭션. 읽은 값이 그대로인 행만 바꾼다. 바꾼 행 수를 돌려준다."""
        n = 0
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '5s'")
            cur.execute("SET LOCAL statement_timeout = '30s'")
            for u in updates:
                cols = sorted(u["set"])
                sql = ("UPDATE blocklist SET " + ", ".join(f"{c} = %s" for c in cols)
                       + " WHERE actor_ip = %s::inet AND "
                       + " AND ".join(f"{c} IS NOT DISTINCT FROM %s" for c in GUARD))
                cur.execute(sql, [u["set"][c] for c in cols] + [u["key"]] + [u["guard"][c] for c in GUARD])
                n += cur.rowcount
        return n

    def note_expired(self, key, expires):
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '30s'")
            cur.execute("SELECT note_block_expired(%s::inet, %s)", (key, expires))


# ── 한 회차 ───────────────────────────────────────────────────────────────────

def cycle(cfg, store, s3w, s3r, st, dry_run=False):
    """한 회차. 종료 코드를 돌려준다. st 는 그 자리에서 고친다 (dry_run 이면 호출자가 버린다)."""
    rc = 0
    try:
        snap = store.fetch()
    except Exception as e:  # noqa: BLE001
        log(f"DB 를 읽지 못했다. 목록을 올리지 않는다 (관문은 옛 집합을 두고 만료로 뺀다): {why(e)}", 3)
        return 1
    now, rows = snap["now"], snap["rows"]
    entries = classify_rows(rows, now)
    doc = list_doc(entries, now)
    st["seq"] += 1
    pub = st["published"]
    last_up = parse_ts(pub.get("uploaded_at")) if pub else None
    need = not pub or pub.get("digest") != doc["digest"] or last_up is None or now - last_up >= REFRESH - REFRESH_EARLY
    if need and dry_run:
        log(f"(dry-run) 목록을 올릴 차례다: {len(entries)}개 digest {doc['digest'][:8]}")
    elif need:
        try:
            s3w.put_object(Bucket=cfg["bucket"], Key=LIST_KEY, ContentType="application/json",
                           CacheControl="no-cache", Body=json.dumps(doc, ensure_ascii=True).encode("utf-8"))
            changed = not pub or pub.get("digest") != doc["digest"]
            st["published"] = {"digest": doc["digest"], "generated_at": doc["generated_at"],
                               "uploaded_at": iso_full(now), "count": len(entries)}
            st["upload_fail_since"] = None
            log(f"목록을 올렸다: {len(entries)}개 digest {doc['digest'][:8]}" + ("" if changed else " (그대로 · 생존 표시)"))
        except Exception as e:  # noqa: BLE001
            rc = 1
            since(st, "upload_fail_since", now)
            log(f"목록을 올리지 못했다 (s3://{cfg['bucket']}/{LIST_KEY}): {why(e)}", 3)
    elif not dry_run:
        st["upload_fail_since"] = None     # S3 의 목록이 지금 목록이다 (올릴 것이 없다)
    current = bool(st["published"]) and st["published"].get("digest") == doc["digest"]
    if current:
        bookkeep(st, entries, doc["digest"], now)
    gw, problem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["gateway"]), now)
    if gw is None:
        rc = rc or 1
    j = judge(st, gw, problem, now, (doc["digest"], entries) if current else None)
    fail_at = parse_ts(st.get("upload_fail_since")) if st.get("upload_fail_since") else None
    if fail_at is not None and now - fail_at >= STALE:
        # 쪽지가 회차마다 바뀌지 않게 오류 문구 · 지난 시간을 넣지 않는다 (까닭은 로그의 '목록을 올리지 못했다')
        j["upload_stuck"] = "목록을 5분 넘게 올리지 못함"
        log(f"목록을 {fail_at.isoformat()} 부터 올리지 못했다. S3 에 없는 행은 관문 불일치로 둔다", 4)
    if j["mismatch"]:
        log(f"관문 불일치: {j['mismatch']}", 4)
    elif j["problems"] and j["verified"]:
        log("관문 오류 (행 확인은 보고대로): " + "; ".join(j["problems"])[:500], 4)
    elif j["problems"]:
        log("관문 확인 보류: " + "; ".join(j["problems"])[:500], 5)
    updates, expired, tally = plan(rows, st, j, now, current)
    summary = " · ".join(f"{k} {v}" for k, v in sorted(tally.items())) or "없음"
    if dry_run:
        for u in updates:
            log(f"(dry-run) {u['ip']} {u['tag']}: " + ", ".join(f"{k}={clean(v, 80)}" for k, v in u["set"].items()))
        for key, exp, _ in expired:
            log(f"(dry-run) 만료 기록 {clean(key, 60)} {iso(exp)}")
        log(f"(dry-run) 행 {len(rows)}: {summary}. 고칠 행 {len(updates)} · 만료 기록 {len(expired)}")
        return rc
    if updates:
        try:
            n = store.apply(updates)
            log(f"집행 기록 {n}/{len(updates)}행을 고쳤다"
                + ("" if n == len(updates) else " (나머지는 그 사이 바뀌어 다음 회차에 본다)"))
        except Exception as e:  # noqa: BLE001
            rc = 1
            log(f"집행 기록을 쓰지 못했다 (다음 회차에 다시 쓴다): {why(e)}", 3)
    for key, exp, k in expired:
        try:
            store.note_expired(key, exp)
            st["expired_noted"][k] = iso_full(now)
        except Exception as e:  # noqa: BLE001
            rc = 1
            log(f"만료 기록을 남기지 못했다 ({clean(key, 60)}): {why(e)}", 3)
    prune(st, rows, now)
    gws = f"관문 {j['mode']} {iso(j['at'])} 목록 {j['d8'] or '-'}" if gw else f"관문 보고 없음 ({problem})"
    log(f"행 {len(rows)} · 목록 {len(entries)} · {gws}: {summary}")
    return rc


# ── 명령 ─────────────────────────────────────────────────────────────────────

def cmd_run(args):
    if not args.dry_run and os.geteuid() == 0:
        # root 가 쓴 상태 파일(0600)은 서비스 사용자가 읽지 못한다
        raise ConfigError("root 로는 run --dry-run 만 한다. 한 회차는 sudo systemctl start opsloop-enforcer.service")
    cfg = settings()
    if not cfg["bucket"]:
        raise ConfigError("OPSLOOP_BUCKET 이 없다 (/etc/default/opsloop-enforcer)")
    s3w, s3r = s3_client(cfg, "s3-block.env"), s3_client(cfg, "s3-pull.env")
    lock = take_lock(cfg["home"])
    try:
        path = os.path.join(cfg["home"], "state.json")
        st = load_state(path)
        try:
            conn = db_connect()
        except ConfigError:
            raise
        except Exception as e:  # noqa: BLE001
            log(f"DB 에 붙지 못했다. 목록을 올리지 않는다: {why(e)}", 3)
            return 1
        try:
            rc = cycle(cfg, PgStore(conn), s3w, s3r, st, dry_run=args.dry_run)
        finally:
            conn.close()
        if not args.dry_run:
            save_state(path, st)
        return rc
    finally:
        lock.close()


def cmd_list(args):
    conn = db_connect()
    try:
        snap = PgStore(conn).fetch()
    finally:
        conn.close()
    doc = list_doc(classify_rows(snap["rows"], snap["now"]), snap["now"])
    # 표준 출력을 먼저 비운다. 파이프로 받으면(설치기 `list 2>&1 | tail -n 1`) 버퍼 때문에 아래 갈래 수가 JSON 앞에 온다
    print(json.dumps(doc, ensure_ascii=False, indent=1), flush=True)
    kinds = {}
    for r in snap["rows"]:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"# 행 {len(snap['rows'])}: " + " · ".join(f"{k} {v}" for k, v in sorted(kinds.items())), file=sys.stderr)
    return 0


def state_label(r):
    """화면(B4)과 같은 다섯 갈래를 사람이 읽게."""
    if r["kind"] in ("released", "expired"):
        return "해제/만료"
    note = r["note"] or ""
    if note.startswith("집행 제외"):
        return "집행 제외"
    if note.startswith("관문 불일치"):
        return "관문 불일치"
    if r["enforced_at"] is not None:
        return "집행 확인"
    return "집행 대기"


def cmd_status(args, out=print):
    cfg = settings()
    st = load_state(os.path.join(cfg["home"], "state.json"))
    pub = st.get("published") or {}
    out(f"마지막 회차 {st['seq']} · 올린 목록 {pub.get('count', '-')}개 digest {str(pub.get('digest') or '-')[:8]}"
        f" · 올린 시각 {pub.get('uploaded_at') or '-'}")
    for k in ("status_fail_since", "unknown_since", "error_since", "upload_fail_since"):
        if st.get(k):
            out(f"  5분 시계 {k}: {st[k]}")
    rc = 0
    try:
        conn = db_connect()
        try:
            snap = PgStore(conn).fetch()
        finally:
            conn.close()
        classify_rows(snap["rows"], snap["now"])
        labels = {}
        for r in snap["rows"]:
            labels[state_label(r)] = labels.get(state_label(r), 0) + 1
        out("DB (지난 2일 안의 만료 · 집행 기록이 남은 행 포함): "
            + (" · ".join(f"{k} {v}" for k, v in sorted(labels.items())) or "행 없음"))
    except ConfigError:
        raise
    except Exception as e:  # noqa: BLE001
        rc = 1
        out(f"DB 를 읽지 못했다: {why(e)}")
    try:
        s3r = s3_client(cfg, "s3-pull.env")
        gw, problem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["gateway"]), datetime.now(timezone.utc))
    except ConfigError as e:
        out(f"관문 보고를 읽을 수 없다: {e}")
        return 1
    if gw is None:
        out(f"관문 보고: 없음 ({problem})")
        return 1
    out(f"관문 보고: {iso(gw['at'])} · {gw['mode']} · 목록 {str(gw['digest'] or '-')[:8]} · 적용 {gw['applied']}"
        f" · 집합 {gw['set_count']} · 거부 {len(gw['rejected'])} · 오류 {len(gw['errors'])}"
        f" · 자가 시험 {gw['selftest'] or '-'}")
    for e in gw["errors"][:5]:
        out(f"  오류: {e}")
    return rc


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"인자 오류: {message}", file=sys.stderr)
        sys.exit(2)


def build_parser():
    p = _Parser(prog="opsloop-enforcer", description="차단 집행기 (DB 차단 목록 → 관문, 관문 보고 → DB)")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    r = sub.add_parser("run", help="한 회차 (타이머)")
    r.add_argument("--dry-run", action="store_true", help="읽기만 하고 할 일을 찍는다")
    r.set_defaults(func=cmd_run)
    sub.add_parser("list", help="올릴 목록 JSON 을 찍는다").set_defaults(func=cmd_list)
    sub.add_parser("status", help="마지막 회차 · 관문 보고 · 상태별 건수").set_defaults(func=cmd_status)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        log(f"설정 오류: {e}", 3)
        return 2


if __name__ == "__main__":
    sys.exit(main())
