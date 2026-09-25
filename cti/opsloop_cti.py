#!/usr/bin/env python3
"""CTI 수집기 (이슈 #39). 공개 취약점 정보와 자산 조사 결과를 S3 cti/ 와 DB 에 둔다.

데이터 노드에서 돈다. opsloop-cti.service 가 opsloop-cti 사용자로 하루 한 번 `fetch` 를 돌리고,
Mac 의 collect-assets.sh 가 ssh 로 `load-assets` 의 표준 입력에 자산 조사 묶음을 넘긴다.

하위 명령
  fetch [--only kev,epss,osv,nvd] [--no-nvd]
        kev → epss → osv → nvd 순서로 받는다. 출처 하나가 실패해도 나머지는 돈다.
  load-assets [--no-check]
        표준 입력의 자산 조사 묶음(opsloop-assets/1)을 검증해 원본을 S3 에 남기고 asset_inventory 를 고친 뒤,
        받은 자산만 배포판 취약점(OSV)과 대조한다. --no-check 면 대조를 건너뛴다.
  status
        출처별 마지막 성공 · 주목 CVE 조회 결과 · 자산별 수집 · 대조 시각을 사람이 읽게 찍는다 (DB 만 읽는다).

원본 보관 (모든 출처 공통)
  원본은 S3 cti/v1/source=<출처>/date=<UTC 날짜>/<sha256 앞 16자>.<json|csv.gz> 에 한 번만 쓴다(If-None-Match: *).
  같은 키가 이미 있으면(412) 키에 내용 해시가 있으니 같은 내용이다. 성공으로 본다.
  S3 에 못 쓰면 cti_snapshots 에 failed 만 남기고 그 출처의 DB 는 고치지 않는다. 쓰면 ok 행과 정규화 행을
  한 트랜잭션에서 넣는다. 그날 무엇을 보고 판단했는지 원본으로 재현할 수 있어야 하기 때문이다.
  CVE · KEV · EPSS · CVSS 는 판정값이 아니라 조사 우선순위 정보다. 탐지는 이 표를 읽지 않는다.

출처
  kev   CISA KEV JSON. cti_kev 를 목록과 같게 맞춘다 (빠진 항목은 지운다).
  epss  EPSS 전체 CSV(gzip). 원본은 gz 그대로 보관하고, cti_cve 에는 관심 CVE(KEV · 자산 · 서명 · 이미 있는 행)만
        넣는다. $OPSLOOP_CTI_HOME/epss-latest.csv.gz 에 사본을 두어, 뒤에 자산 대조로 새로 생긴 CVE 의 EPSS 를 채운다.
  osv   자산의 설치 패키지(소스 패키지 · 소스 버전)와 실행 중 커널을 OSV 의 Ubuntu 생태계로 묻고
        asset_vulnerabilities 를 자산마다 다시 계산한다. 배포판은 보안 수정을 옛 버전 번호에 덧대어 내므로
        해당 여부는 업스트림 버전이 아니라 배포판 기록의 수정 버전으로 본다. 커널은 실행 중인 이미지의 소스
        (generic 은 linux, AWS 는 linux-aws 등)로 묻는다. fetch 때는 주목 CVE 목록(watchlist.json)의 Ubuntu 기록도
        받아 cti_watch 를 목록과 같게 맞춘다 (자산에 걸리지 않은, 이미 고쳐진 CVE 도 판정 근거를 보이려고).
  nvd   초점 CVE(주목 CVE · 서명 · 서명 제품의 KEV · 자산 ∩ KEV · 자산 EPSS 상위 20)만 CVSS · 설명을 받는다.
        14일 안에 받은 것은 건너뛰고, 회차당 60개 · 요청 사이 6.5초(키 없는 한도 30초에 5회).

종료 코드
  0  정상
  1  일부 출처 실패 · DB 접속 실패 (fetch) / 일부 자산 형식 오류 · 대조 실패 · 대조 못 한 자산 (load-assets)
  2  설정 오류 (버킷 · 비밀 파일 · 인자) / 자산 묶음 적재 실패 (load-assets)

설정
  /etc/default/opsloop-cti  OPSLOOP_BUCKET · OPSLOOP_CTI_HOME · AWS_DEFAULT_REGION (비밀 아님).
                            환경변수에 없으면(sudo -u 로 부를 때) 이 파일에서 읽는다
  /etc/opsloop/cti.env      DATABASE_URL (opsloop_cti 역할). DB 연결에만 쓴다
  /etc/opsloop/s3-cti.env   AWS_ACCESS_KEY_ID · AWS_SECRET_ACCESS_KEY (cti/ 쓰기만). S3 클라이언트에만 넘긴다
  watchlist.json            주목 CVE 목록. 이 파일 옆에 둔다 (OPSLOOP_CTI_WATCHLIST 로 바꿀 수 있다)
  비밀 파일은 셸로 읽지 않는다 (KEY=VALUE 만 읽고 실행하지 않는다).
  $OPSLOOP_CTI_HOME/cti.lock  fetch 와 load-assets 가 겹치지 않게 한다 (자산 취약점을 자산마다 지우고 다시 넣는다)
"""
import argparse
import fcntl
import gzip
import hashlib
import http.client
import io
import json
import math
import os
import re
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import date, datetime, timedelta, timezone
from functools import cmp_to_key
from pathlib import Path

UA = "OpsLoop-CTI/1"          # CISA 는 User-Agent 가 없으면 403 을 준다
MIB = 1024 * 1024
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
SOURCES = ("kev", "epss", "osv", "nvd")
LIMITS = {"kev": 20 * MIB, "epss": 50 * MIB, "osv": 20 * MIB, "nvd": 5 * MIB}   # 응답 하나의 상한
HTTP_TIMEOUT = 60
RETRY_WAITS = (5, 20)          # 5xx · 시간 초과면 두 번 더 해 본다 (점점 길게 쉰다)
EPSS_TEXT_MAX = 256 * MIB      # 풀린 CSV 의 상한 (gzip 폭탄 막기. 실제는 수십 MiB 안쪽이다)
EPSS_LINE_MAX = 256            # 줄 하나의 상한. 실제 줄은 40자 안쪽이다. 줄바꿈 없는 큰 입력을 메모리에 올리기 전에 멈춘다
OSV_BATCH = 500                # querybatch 한 번의 질의 수
OSV_PAGES = 200                # 질의 하나의 쪽 수 상한 (커널 질의 하나가 3천 건을 넘는다)
OSV_DETAILS = 500              # 회차당 상세 기록 상한. 넘치면 다음 회차에 받는다
NVD_MAX = 60
NVD_GAP = 6.5
NVD_FRESH_DAYS = 14
NVD_TOP_EPSS = 20
BUNDLE_MAX = 16 * MIB
MAX_ASSETS = 20
MAX_PACKAGES = 20000
MAX_IMAGES = 200
MAX_KERNELS = 100
MAX_ERRORS = 100
WATCH_MAX = 50                 # 주목 CVE 수 상한 (회차마다 하나씩 상세 기록을 받는다)
WATCH_REASON_MAX = 200
FUTURE_SLACK = timedelta(minutes=10)   # 노드 시계가 조금 앞서도 받는다. 그보다 미래면 '늘 새것'으로 보이게 하는 위조로 본다
LOCK_WAIT = 1200
EPSS_COPY, EPSS_META = "epss-latest.csv.gz", "epss-latest.json"
CONTENT_TYPES = {"json": "application/json", "csv.gz": "application/gzip"}
ROLES = ("target", "platform", "sensor")
METHODS = ("ssh", "ssm")
UBUNTU_PRIORITIES = ("negligible", "low", "medium", "high", "critical")
# 커널 바이너리. 커널은 이 패키지들의 소스 버전이 아니라 실행 중인 커널 이미지 버전으로 따로 묻는다
KERNEL_PREFIXES = ("linux-image-", "linux-modules-", "linux-headers-", "linux-tools-", "linux-cloud-tools-")
# 커널 소스 패키지: linux · linux-aws · linux-signed-aws · linux-meta-aws · linux-hwe-6.8 · linux-azure-fde … (판 이름에
# '-' 가 여럿 들어갈 수 있어 토막을 여러 개 받는다). linux-libc-dev(사용자 공간 헤더)는 소스가 linux 라 커널로 빠진다.
# 따로 물으면 커널 기록 수천 건을 커널이 아닌 질의로 다시 끌어오고, 같은 (소스, 기록) 키로 커널 행과 겹친다
KERNEL_SOURCE_RE = re.compile(r"linux(-signed|-meta)?(-[a-z0-9.]+)*")
# 이름은 linux 로 시작하지만 커널이 아닌 소스 (사용자 공간 · 펌웨어). 이 소스의 패키지는 여느 패키지처럼 묻는다.
# linux-firmware 로 시작하는 소스(linux-firmware-raspi 등)도 펌웨어라 여기에 넣어 본다 (is_kernel_source)
NON_KERNEL_SOURCES = frozenset({"linux-base", "linux-atm", "linux-sound-base", "linux-igd", "linux-wlan-ng",
                                "linux-apfs-rw", "linux-gpib", "linux-show-player"})

CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
ASSET_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
OSV_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
PKG_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,255}")          # dpkg 패키지 이름
VER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,255}")   # dpkg 버전 (에포크 포함)
KST = timezone(timedelta(hours=9))

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")   # C0 · DEL · C1(U+0080~009F, CSI U+009B 로 터미널을 조작할 수 있다)
# 짝 없는 대리 문자(\ud800 등). JSON 의 \ud800 이스케이프로 들어올 수 있고, UTF-8 로 인코딩되지 않아
# 로그 출력 · DB 인자(psycopg2)에서 예외가 나 묶음 전체를 실패로 만든다
_SURROGATE = re.compile("[\ud800-\udfff]")
# 숨은 문자는 형식 문자(유니코드 일반 범주 Cf)다. 방향 제어(U+202A~202E · U+2066~2069) · 제로폭(U+200B~200F) · BOM(U+FEFF) ·
# 소프트 하이픈(U+00AD) · 태그 문자(U+E0001 · U+E0020~E007F) 등이다. 'nginx<U+202E>gpj.exe' 는 화면에서 뒤집혀 보이고
# 'ad<U+200B>min' 은 'admin' 과 같아 보인다. re 는 범주(\p{Cf})를 몰라 unicodedata 로 본다. 제어 문자(Cc)는 _CTRL 이 맡는다


class CtiError(Exception):
    """출처 하나를 실패로 끝낼 오류. 문구는 cti_snapshots.error 에 남는다."""


class ConfigError(Exception):
    """설정 오류 (종료 코드 2)."""


class HttpStatus(CtiError):
    """원천이 오류 상태(4xx · 재시도 뒤 5xx)를 돌려줬다. 404(기록 없음)를 다른 오류와 가르려고 상태를 담는다."""

    def __init__(self, code, url):
        super().__init__(f"HTTP {code}: {url}")
        self.code = code


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


_HIDDEN = ("Cf", "Zl", "Zp")
# 기본 무시 문자(Default_Ignorable) 가운데 Cf 가 아닌 것(한글 채움 · 결합 자소 연결 · 이형 선택자 등)과 점자 빈칸 U+2800. 아무것도 그리지 않는다
_IGNORABLE = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2800\u3164\ufe00-\ufe0f\uffa0\ufff0-\ufff8"
                        "\U000e0000-\U000e0fff]")


def _hidden(c):
    return unicodedata.category(c) in _HIDDEN or _IGNORABLE.match(c) is not None


def has_hidden(v):
    """숨은 문자(형식 문자 Cf · 줄과 문단 구분자 · 기본 무시 문자)가 있는가. ASCII 에는 없다."""
    return not v.isascii() and any(_hidden(c) for c in v)


def reveal(v, n=None):
    """숨은 문자(형식 문자 Cf · U+2028 · U+2029 · 기본 무시 문자)를 보이는 표식 ⟨U+XXXX⟩ 로 바꾼다(콘솔 revealHidden 과 같은 꼴).
    n 이 있으면 표식을 가르지 않고 n 자 안으로 자른다. 한 글자가 한 글자 이상이 되므로 앞 n 자만 보면 된다."""
    out, size = [], 0
    for c in v[:n]:
        piece = f"⟨U+{ord(c):04X}⟩" if _hidden(c) else c
        if n is not None and size + len(piece) > n:
            break
        out.append(piece)
        size += len(piece)
    return "".join(out)


def safe(v, n=300):
    """바깥에서 온 값(노드 · 원천 응답)을 로그 · 오류 문구에 쓸 때. 줄바꿈으로 가짜 로그 줄을 만들지 못하게 하고,
    짝 없는 대리 문자는 UTF-8 로 쓸 수 없어 '?' 로, 숨은 문자는 표식 ⟨U+XXXX⟩ 로 바꾼다."""
    return reveal(_SURROGATE.sub("?", _CTRL.sub("?", str(v)[:n])), n)


def why(e):
    return safe(e, 500) if isinstance(e, CtiError) else safe(f"{type(e).__name__}: {e}", 500)


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z") if dt else None


def kst(dt):
    return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M KST") if dt else "-"


_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]+))?)?)?"
                 r"(Z|[+-][0-9]{2}:?[0-9]{2})?")


def parse_ts(v):
    """ISO 8601 시각 → UTC datetime. 시간대가 없으면 UTC 로 본다(NVD). 소수 자리는 6자리까지. 못 읽으면 None."""
    if not isinstance(v, str) or len(v) > 64:
        return None
    m = _TS.fullmatch(v.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    # 달력 끝의 시각에 시간대를 더하면 UTC 로 바꿀 때 넘친다 (0001-01-01T00:00:00+09:00 → OverflowError).
    # 24시간 이상의 시간대는 timezone() 이 ValueError 를 낸다. 둘 다 '시각이 아니다'로 본다
    try:
        dt = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0),
                      int((frac or "0")[:6].ljust(6, "0")))
        if tz and tz != "Z":
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))
            return dt.replace(tzinfo=timezone(off if tz[0] == "+" else -off)).astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def iso_date(v, optional=False):
    """YYYY-MM-DD 문자열. 틀리면 ValueError (optional 이면 빈 값은 None)."""
    if optional and (v is None or v == ""):
        return None
    if not isinstance(v, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", v):
        raise ValueError(f"날짜가 아니다: {safe(v, 40)}")
    date.fromisoformat(v)
    return v


def later(a, b):
    return b if a is None or (b is not None and b > a) else a


def cve_from_id(osv_id):
    """UBUNTU-CVE-2024-6387 → CVE-2024-6387. 그 밖의 id 는 None."""
    if isinstance(osv_id, str) and osv_id.startswith("UBUNTU-CVE-"):
        cve = osv_id[len("UBUNTU-"):]
        if CVE_RE.fullmatch(cve):
            return cve
    return None


# ── dpkg 버전 비교 ─────────────────────────────────────────────────────────────
# dpkg 의 verrevcmp 를 그대로 옮긴다. 에포크(숫자) → 업스트림 → 리비전 순서로 비교하고, 각 부분은
# 숫자가 아닌 토막(문자 < 기호, '~' 는 끝보다도 앞)과 숫자 토막(앞의 0 무시)을 번갈아 비교한다.

def _order(c):
    if c == "~":
        return -1
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v):
    epoch, sep, rest = v.partition(":")
    if not sep or not epoch.isdigit():
        epoch, rest = "0", v
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return int(epoch), upstream, revision


def dpkg_compare(a, b):
    """dpkg --compare-versions 와 같은 순서. a < b 면 음수, 같으면 0, 크면 양수."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


dpkg_key = cmp_to_key(dpkg_compare)


# ── 설정 · 비밀 파일 ────────────────────────────────────────────────────────────

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
    """버킷 · 상태 폴더 · 지역. 환경변수가 먼저고, 없으면 /etc/default/opsloop-cti 에서 읽는다."""
    try:
        conf = read_env(os.environ.get("OPSLOOP_CTI_DEFAULTS", "/etc/default/opsloop-cti"))
    except OSError:
        conf = {}

    def get(k, default=None):
        return os.environ.get(k) or conf.get(k) or default
    return {"bucket": get("OPSLOOP_BUCKET"), "home": get("OPSLOOP_CTI_HOME", "/var/lib/opsloop-cti"),
            "region": get("AWS_DEFAULT_REGION", "ap-northeast-2")}


def db_connect():
    path = os.environ.get("OPSLOOP_CTI_DB_ENV", "/etc/opsloop/cti.env")
    try:
        url = read_env(path)["DATABASE_URL"]
    except (OSError, KeyError) as e:
        raise ConfigError(f"DB 접속 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    import psycopg2
    return psycopg2.connect(url, connect_timeout=10, application_name="opsloop-cti")


def cti_if_none_match(request, **_):
    # CTI 원본만 한 번 쓰기. 설치된 boto3(1.34)가 IfNoneMatch 인자를 몰라 서명 직전에 헤더를 넣는다 (sensor/upload.py 와 같다).
    # 가상 호스트 방식(/cti/v1/...)과 경로 방식(/버킷/cti/v1/...) 모두 경로에 이 문자열이 들어간다
    if "/cti/" in urllib.parse.urlparse(request.url).path:
        request.headers["If-None-Match"] = "*"


def s3_client(cfg):
    """cti/ 쓰기 전용 키로 만든 S3 클라이언트. 키는 이 클라이언트에만 넘기고 환경변수에 두지 않는다."""
    if not cfg["bucket"]:
        raise ConfigError("OPSLOOP_BUCKET 이 없다 (/etc/default/opsloop-cti)")
    path = os.environ.get("OPSLOOP_CTI_S3_ENV", "/etc/opsloop/s3-cti.env")
    try:
        keys = read_env(path)
    except OSError as e:
        raise ConfigError(f"S3 쓰기 키 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    if not keys.get("AWS_ACCESS_KEY_ID") or not keys.get("AWS_SECRET_ACCESS_KEY"):
        raise ConfigError(f"S3 쓰기 키가 비었다 ({path})")
    # 노드의 ~/.aws 설정 · 인스턴스 메타데이터를 보지 않는다 (내부망 VM 이라 메타데이터 조회는 시간만 끈다)
    for k in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        os.environ.setdefault(k, os.devnull)
    os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
    import boto3
    s3 = boto3.client("s3", region_name=cfg["region"], aws_access_key_id=keys["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=keys["AWS_SECRET_ACCESS_KEY"])
    s3.meta.events.register("before-sign.s3.PutObject", cti_if_none_match)
    return s3


def take_lock(home, wait=LOCK_WAIT, sleep=time.sleep):
    try:
        os.makedirs(home, exist_ok=True)
        f = open(os.path.join(home, "cti.lock"), "a")
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
                raise CtiError(f"다른 실행이 {wait}초 넘게 끝나지 않았다") from None
            if waited == 0:
                log("다른 실행(fetch · load-assets)이 끝나기를 기다린다", 5)
            sleep(5)
            waited += 5


# ── HTTP ───────────────────────────────────────────────────────────────────────

class Http:
    """urllib 로 받는다. User-Agent 를 붙이고, 5xx · 시간 초과는 두 번 더 해 보고, 응답이 상한을 넘으면 실패한다."""

    def __init__(self, opener=None, sleep=time.sleep, timeout=HTTP_TIMEOUT):
        self.opener = opener or urllib.request.build_opener()
        self.sleep = sleep
        self.timeout = timeout

    def fetch(self, url, limit, data=None, headers=None):
        hdrs = {"User-Agent": UA, "Accept-Encoding": "identity"}
        hdrs.update(headers or {})
        for attempt in range(len(RETRY_WAITS) + 1):
            last = attempt == len(RETRY_WAITS)
            try:
                req = urllib.request.Request(url, data=data, headers=hdrs)
                with self.opener.open(req, timeout=self.timeout) as r:
                    body = r.read(limit + 1)
            except urllib.error.HTTPError as e:
                e.close()
                if e.code < 500 or last:
                    raise HttpStatus(e.code, url) from None
                reason = f"HTTP {e.code}"
            except urllib.error.URLError as e:
                if not isinstance(e.reason, (socket.timeout, TimeoutError)):
                    raise CtiError(f"연결 실패 ({safe(e.reason, 120)}): {url}") from None
                if last:
                    raise CtiError(f"시간 초과 ({self.timeout}초): {url}") from None
                reason = "시간 초과"
            except (socket.timeout, TimeoutError):
                if last:
                    raise CtiError(f"시간 초과 ({self.timeout}초): {url}") from None
                reason = "시간 초과"
            except (OSError, http.client.HTTPException) as e:
                raise CtiError(f"받다가 끊겼다 ({type(e).__name__}): {url}") from None
            else:
                if len(body) > limit:
                    raise CtiError(f"응답이 상한 {limit // MIB} MiB 를 넘었다: {url}")
                return body
            log(f"  {reason}. {RETRY_WAITS[attempt]}초 뒤 다시 받는다: {url}", 4)
            self.sleep(RETRY_WAITS[attempt])

    def get_json(self, url, limit):
        return self._json(self.fetch(url, limit), url)

    def post_json(self, url, obj, limit):
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return self._json(self.fetch(url, limit, data=data, headers={"Content-Type": "application/json"}), url)

    @staticmethod
    def _json(body, url):
        try:
            return json.loads(body)
        except ValueError:
            raise CtiError(f"JSON 이 아니다: {url}") from None


# ── 원본 보관 · 원본 기록 ───────────────────────────────────────────────────────

def watchlist_path():
    """주목 CVE 목록 파일. 실행기 옆의 watchlist.json (설치기가 코드 폴더에 함께 둔다). 환경변수로 바꿀 수 있다."""
    return os.environ.get("OPSLOOP_CTI_WATCHLIST") or str(Path(__file__).with_name("watchlist.json"))


class Ctx:
    """한 실행의 연결들. 시험은 가짜 DB · S3 · HTTP 와 주목 CVE 목록 파일을 넣는다."""

    def __init__(self, conn, s3, bucket, home, http=None, sleep=time.sleep, now=utcnow, watchlist=None):
        self.conn, self.s3, self.bucket, self.home = conn, s3, bucket, home
        self.http = http or Http(sleep=sleep)
        self.sleep, self.now = sleep, now
        self.watchlist = watchlist or watchlist_path()


class Payload:
    """받은 원본 한 벌과 정규화할 값."""

    def __init__(self, body, ext, url, data, source_ts=None, version=None, records=None):
        self.body, self.ext, self.url, self.data = body, ext, url, data
        self.source_ts, self.version, self.records = source_ts, version, records


def s3_key(source, body, ext, fetched_at):
    sha = hashlib.sha256(body).hexdigest()
    day = fetched_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
    return f"cti/v1/source={source}/date={day}/{sha[:16]}.{ext}", sha


def put_once(s3, bucket, key, body, content_type, metadata):
    """같은 키가 이미 있으면 쓰지 않는다 (If-None-Match: *). 새로 썼으면 True, 이미 있으면 False.

    버킷 정책도 이 조건이 없는 cti/ 쓰기를 거부한다. 키에 내용 해시가 있으므로 이미 있다는 것은 같은 내용이
    이미 보관돼 있다는 뜻이다 (PUT 은 됐는데 DB 에 넣기 전에 죽은 회차를 다시 받은 경우 등).
    """
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType=content_type,
                      ChecksumAlgorithm="SHA256", Metadata=metadata)
        return True
    except Exception as e:  # botocore.exceptions.ClientError
        code = (getattr(e, "response", None) or {}).get("Error", {}).get("Code")
        if code in ("PreconditionFailed", "412"):
            return False
        raise


SNAPSHOT_INSERT = """
INSERT INTO cti_snapshots (source, fetched_at, source_url, source_ts, source_version, s3_key, sha256, bytes,
                           records, status, error)
VALUES (%(source)s, %(fetched_at)s, %(source_url)s, %(source_ts)s, %(source_version)s, %(s3_key)s, %(sha256)s,
        %(bytes)s, %(records)s, %(status)s, %(error)s)
RETURNING id"""


def insert_snapshot(cur, snap):
    row = {k: snap.get(k) for k in ("source", "fetched_at", "source_url", "source_ts", "source_version", "s3_key",
                                     "sha256", "bytes", "records", "status", "error")}
    cur.execute(SNAPSHOT_INSERT, row)
    return cur.fetchone()[0]


def select(ctx, sql, params=None):
    """읽기만 하고 트랜잭션을 바로 닫는다 (뒤따르는 긴 HTTP 동안 트랜잭션을 열어 두지 않는다)."""
    cur = ctx.conn.cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        ctx.conn.rollback()


def failed(ctx, snap, error):
    """실패 회차를 원본 기록에 남긴다 (s3_key 없음). 정규화 표는 고치지 않는다."""
    log(f"{snap['source']}: {error}", 3)
    try:
        ctx.conn.rollback()
        insert_snapshot(ctx.conn.cursor(), dict(snap, status="failed", s3_key=None, error=error[:1000]))
        ctx.conn.commit()
    except Exception as e:
        log(f"{snap['source']}: 실패 기록도 남기지 못했다: {why(e)}", 3)
        try:
            ctx.conn.rollback()
        except Exception:
            pass
    return False


def run_source(ctx, source, produce, apply, after=None):
    """출처 한 회차. 받기 · 검증(produce) → S3 원본 → DB(ok 원본 기록 + 정규화, 한 트랜잭션) → after. 성공이면 True.

    produce 가 None 을 돌려주면 할 일이 없는 것이다 (원본 기록도 남기지 않는다).
    """
    snap = {"source": source, "fetched_at": ctx.now()}
    try:
        p = produce(ctx)
    except Exception as e:
        return failed(ctx, snap, f"받기 · 검증 실패: {why(e)}")
    if p is None:
        return True
    key, sha = s3_key(source, p.body, p.ext, snap["fetched_at"])
    snap.update(source_url=p.url, source_ts=p.source_ts, source_version=p.version, records=p.records,
                sha256=sha, bytes=len(p.body))
    try:
        meta = {"source-url": p.url or "stdin", "fetched-at": iso(snap["fetched_at"]), "sha256": sha}
        new = put_once(ctx.s3, ctx.bucket, key, p.body, CONTENT_TYPES[p.ext], meta)
    except Exception as e:
        return failed(ctx, snap, f"원본 보관(S3) 실패: {why(e)}")
    try:
        cur = ctx.conn.cursor()
        snap_id = insert_snapshot(cur, dict(snap, s3_key=key, status="ok"))
        summary = apply(ctx, cur, snap_id, p.data)
        ctx.conn.commit()
    except Exception as e:
        return failed(ctx, snap, f"DB 갱신 실패: {why(e)}")
    log(f"{source}: 정상 · {summary} · 원본 {key}{'' if new else ' (이미 있음)'}")
    if after:
        after(ctx, snap_id, p)
    return True


def columns(rows):
    """행 목록 → 열별 목록 (unnest 인자). psycopg2 는 튜플을 배열이 아니라 행으로 바꾸므로 목록으로 만든다."""
    return [list(c) for c in zip(*rows)]


def read_signatures(ctx):
    """rule_versions 에 남은 모든 판의 url_signature 서명 (버전 합집합)."""
    out = []
    for _version, definition in select(ctx, "SELECT rule_version, definition FROM rule_versions ORDER BY rule_version"):
        doc = json.loads(definition) if isinstance(definition, str) else definition
        for rule in (doc or {}).get("rules") or []:
            if isinstance(rule, dict) and rule.get("type") == "url_signature":
                out.extend(s for s in (rule.get("params") or {}).get("signatures") or [] if isinstance(s, dict))
    return out


def signature_cves(sigs):
    return {c for s in sigs for c in s.get("cves") or [] if isinstance(c, str) and CVE_RE.fullmatch(c)}


# ── KEV ────────────────────────────────────────────────────────────────────────

def kev_row(v):
    if not isinstance(v, dict):
        raise ValueError("항목이 객체가 아니다")
    cve = v.get("cveID")
    if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
        raise ValueError("cveID 형식이 틀리다")
    need = [v.get(k) for k in ("vendorProject", "product", "vulnerabilityName")]
    if not all(isinstance(x, str) and x for x in need):
        raise ValueError("vendorProject · product · vulnerabilityName 이 비었다")
    desc, ransom = v.get("shortDescription"), v.get("knownRansomwareCampaignUse")
    return (cve, need[0], need[1], need[2], desc if isinstance(desc, str) else None,
            iso_date(v.get("dateAdded")), iso_date(v.get("dueDate"), optional=True),
            ransom if isinstance(ransom, str) else None)


def parse_kev(body):
    """KEV JSON → (행 목록 [cve, 공급사, 제품, 이름, 설명, 등재일, 기한, 랜섬웨어], 메타). 틀린 항목은 건너뛴다."""
    try:
        doc = json.loads(body)
    except ValueError:
        raise CtiError("KEV 가 JSON 이 아니다") from None
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        raise CtiError("KEV 에 vulnerabilities 목록이 없다")
    rows, bad = {}, 0
    for v in vulns:
        try:
            row = kev_row(v)
        except ValueError:
            bad += 1
            continue
        rows[row[0]] = row
    if not rows:
        raise CtiError("KEV 에 쓸 수 있는 항목이 없다")
    version = doc.get("catalogVersion")
    return [rows[k] for k in sorted(rows)], {
        "source_ts": parse_ts(doc.get("dateReleased")), "bad": bad,
        "version": version if isinstance(version, str) and len(version) <= 64 else None}


# 인자: 원본 기록 id, 열별 배열 8개
KEV_UPSERT = """
INSERT INTO cti_kev (cve_id, vendor_project, product, name, description, date_added, due_date, ransomware, snapshot_id)
SELECT k.cve_id, k.vendor_project, k.product, k.name, k.description, k.date_added, k.due_date, k.ransomware, %s
  FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::text[], %s::date[], %s::date[], %s::text[])
       AS k(cve_id, vendor_project, product, name, description, date_added, due_date, ransomware)
ON CONFLICT (cve_id) DO UPDATE SET
    vendor_project = EXCLUDED.vendor_project, product = EXCLUDED.product, name = EXCLUDED.name,
    description = EXCLUDED.description, date_added = EXCLUDED.date_added, due_date = EXCLUDED.due_date,
    ransomware = EXCLUDED.ransomware, snapshot_id = EXCLUDED.snapshot_id"""


def apply_kev(ctx, cur, snap_id, rows):
    cols = columns(rows)
    cur.execute(KEV_UPSERT, [snap_id] + cols)
    cur.execute("DELETE FROM cti_kev WHERE cve_id <> ALL(%s::text[])", (cols[0],))
    return f"{len(rows)}건 · 목록에서 빠진 {cur.rowcount}건 지움"


def fetch_kev(ctx):
    def produce(ctx):
        body = ctx.http.fetch(KEV_URL, LIMITS["kev"])
        rows, meta = parse_kev(body)
        if meta["bad"]:
            log(f"kev: 형식이 틀린 항목 {meta['bad']}개를 건너뛴다", 4)
        return Payload(body, "json", KEV_URL, rows, meta["source_ts"], meta["version"], len(rows))
    return run_source(ctx, "kev", produce, apply_kev)


# ── EPSS ───────────────────────────────────────────────────────────────────────

def parse_epss(body, want=None):
    """EPSS gzip CSV → (메타 {model_version, score_date}, {cve: (epss, 백분위)}, 줄 수).

    want 가 있으면 그 CVE 만 모은다 (37만 줄을 사전으로 들고 있지 않는다). 틀린 줄은 건너뛴다.
    """
    meta, rows, count, size = {"model_version": None, "score_date": None}, {}, 0, 0
    try:
        text = io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(body)), encoding="utf-8")
        first = text.readline(4096)
        if not first.startswith("#"):
            raise CtiError("EPSS 첫 줄이 #model_version:… 이 아니다")
        for part in first[1:].strip().split(","):
            k, _, v = part.partition(":")
            if k == "model_version" and len(v) <= 64:
                meta["model_version"] = v
            elif k == "score_date":
                meta["score_date"] = parse_ts(v)
        if text.readline(4096).strip() != "cve,epss,percentile":
            raise CtiError("EPSS 머리 줄이 cve,epss,percentile 이 아니다")
        while True:
            # 줄 단위로 읽되 한 줄의 길이에 상한을 둔다. 'for line in text' 는 줄 전체를 메모리에 만든 뒤에야
            # 크기를 셀 수 있어, 줄바꿈 없는 큰 입력(깨졌거나 변조된 원천)이면 상한 검사 전에 메모리가 넘친다
            line = text.readline(EPSS_LINE_MAX)
            if not line:
                break
            if len(line) >= EPSS_LINE_MAX and not line.endswith("\n"):
                raise CtiError(f"EPSS 줄 하나가 {EPSS_LINE_MAX}자를 넘는다")
            size += len(line)
            if size > EPSS_TEXT_MAX:
                raise CtiError(f"풀린 EPSS 가 {EPSS_TEXT_MAX // MIB} MiB 를 넘는다")
            parts = line.strip().split(",")
            if len(parts) != 3 or not CVE_RE.fullmatch(parts[0]):
                continue
            try:
                e, p = float(parts[1]), float(parts[2])
            except ValueError:
                continue
            if not (math.isfinite(e) and math.isfinite(p) and 0 <= e <= 1 and 0 <= p <= 1):
                continue
            count += 1
            if want is None or parts[0] in want:
                rows[parts[0]] = (e, p)
    except (OSError, EOFError, zlib.error, UnicodeDecodeError) as e:
        raise CtiError(f"EPSS gzip 을 풀지 못했다 ({type(e).__name__})") from None
    if not count:
        raise CtiError("EPSS 에 쓸 수 있는 줄이 없다")
    return meta, rows, count


# 인자: 기준일, 원본 기록 id, CVE · 점수 · 백분위 배열
EPSS_UPSERT = """
INSERT INTO cti_cve (cve_id, epss, epss_percentile, epss_date, epss_snapshot_id)
SELECT e.cve_id, e.epss, e.pct, %s::date, %s
  FROM unnest(%s::text[], %s::real[], %s::real[]) AS e(cve_id, epss, pct)
ON CONFLICT (cve_id) DO UPDATE SET
    epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile, epss_date = EXCLUDED.epss_date,
    epss_snapshot_id = EXCLUDED.epss_snapshot_id"""


def epss_upsert(cur, snap_id, score_date, rows):
    if not rows:
        return 0
    ids = sorted(rows)
    day = score_date.date().isoformat() if score_date else None
    cur.execute(EPSS_UPSERT, (day, snap_id, ids, [rows[c][0] for c in ids], [rows[c][1] for c in ids]))
    return len(ids)


def epss_interest(ctx):
    """EPSS 를 둘 CVE: KEV ∪ 자산 취약점 ∪ 주목 CVE ∪ 서명 ∪ 이미 cti_cve 에 있는 것."""
    rows = select(ctx, """SELECT cve_id FROM cti_kev
                          UNION SELECT cve_id FROM asset_vulnerabilities WHERE cve_id IS NOT NULL
                          UNION SELECT cve_id FROM cti_watch
                          UNION SELECT cve_id FROM cti_cve""")
    want = {r[0] for r in rows} | signature_cves(read_signatures(ctx))
    return {c for c in want if isinstance(c, str) and CVE_RE.fullmatch(c)}


def apply_epss(ctx, cur, snap_id, d):
    n = epss_upsert(cur, snap_id, d["meta"]["score_date"], d["rows"])
    return f"전체 {d['count']}줄 · 관심 CVE {n}건 갱신 (기준 {iso(d['meta']['score_date'])})"


def write_atomic(path, body):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, path)


def save_epss_copy(ctx, snap_id, p):
    """뒤에 자산 대조로 관심 CVE 가 늘면 이 사본에서 EPSS 를 채운다. 못 써도 이 회차는 성공이다."""
    meta = p.data["meta"]
    try:
        write_atomic(os.path.join(ctx.home, EPSS_COPY), p.body)
        write_atomic(os.path.join(ctx.home, EPSS_META), json.dumps(
            {"snapshot_id": snap_id, "score_date": iso(meta["score_date"]),
             "model_version": meta["model_version"]}).encode("utf-8"))
    except OSError as e:
        log(f"epss: 로컬 사본을 쓰지 못했다 ({type(e).__name__}). 새 자산 CVE 의 EPSS 는 다음 fetch 가 채운다", 4)


def epss_fill(ctx, cur, cves):
    """EPSS 가 아직 없는 CVE 를 로컬 사본(마지막으로 성공한 EPSS 원본)에서 채운다. 채운 수."""
    cves = sorted(c for c in cves if isinstance(c, str) and CVE_RE.fullmatch(c))
    if not cves:
        return 0
    cur.execute("SELECT cve_id FROM cti_cve WHERE cve_id = ANY(%s) AND epss IS NOT NULL", (cves,))
    missing = set(cves) - {r[0] for r in cur.fetchall()}
    if not missing:
        return 0
    try:
        with open(os.path.join(ctx.home, EPSS_META), encoding="utf-8") as f:
            meta = json.load(f)
        with open(os.path.join(ctx.home, EPSS_COPY), "rb") as f:
            body = f.read()
    except (OSError, ValueError):
        log(f"EPSS 사본이 없어 새 CVE {len(missing)}건의 EPSS 는 다음 fetch 가 채운다")
        return 0
    snap_id = meta.get("snapshot_id") if isinstance(meta, dict) else None
    if not isinstance(snap_id, int):
        return 0
    cur.execute("SELECT 1 FROM cti_snapshots WHERE id = %s AND source = 'epss' AND status = 'ok'", (snap_id,))
    if cur.fetchone() is None:
        return 0
    try:
        _, rows, _ = parse_epss(body, want=missing)
    except CtiError as e:
        log(f"EPSS 사본을 읽지 못했다 ({e}). 새 CVE 의 EPSS 는 다음 fetch 가 채운다", 4)
        return 0
    return epss_upsert(cur, snap_id, parse_ts(meta.get("score_date")), rows)


def fetch_epss(ctx):
    def produce(ctx):
        want = epss_interest(ctx)
        body = ctx.http.fetch(EPSS_URL, LIMITS["epss"])
        meta, rows, count = parse_epss(body, want)
        return Payload(body, "csv.gz", EPSS_URL, {"meta": meta, "rows": rows, "count": count},
                       meta["score_date"], meta["model_version"], count)
    return run_source(ctx, "epss", produce, apply_epss, after=save_epss_copy)


# ── OSV (배포판 취약점) ─────────────────────────────────────────────────────────

def osv_ecosystem(os_info):
    """Ubuntu 만 다룬다. XX.04 이고 XX 가 짝수면 LTS 생태계 이름이다 (Ubuntu:24.04:LTS)."""
    if not isinstance(os_info, dict) or os_info.get("id") != "ubuntu":
        return None
    v = os_info.get("version_id")
    if not isinstance(v, str) or not re.fullmatch(r"[0-9]{2}\.[0-9]{2}", v):
        return None
    return f"Ubuntu:{v}:LTS" if v.endswith(".04") and int(v[:2]) % 2 == 0 else f"Ubuntu:{v}"


def is_kernel_source(src):
    """커널 소스 패키지 이름인가 (linux · linux-aws · linux-signed-aws · linux-meta-aws …, 펌웨어 · 사용자 공간 제외)."""
    return (isinstance(src, str) and bool(KERNEL_SOURCE_RE.fullmatch(src)) and src not in NON_KERNEL_SOURCES
            and not src.startswith("linux-firmware"))


def is_kernel_package(p):
    """커널 바이너리인가. 이름(linux-image- 등)이나 소스(커널 소스)로 본다. 이것들은 질의에서 빼고 실행 중 커널로 묻는다."""
    return (p.get("name") or "").startswith(KERNEL_PREFIXES) or is_kernel_source(p.get("source"))


def _unsigned_source(src):
    """서명 · 메타 소스 → 커널 소스 (linux-signed-aws → linux-aws, linux-meta-aws → linux-aws, linux-signed → linux)."""
    for pre in ("linux-signed", "linux-meta"):
        if src == pre or src.startswith(pre + "-"):
            return "linux" + src[len(pre):]
    return src


def kernel_source(kernel, packages):
    """실행 중인 커널의 소스 패키지 이름 (OSV 에 물을 이름). 못 찾으면 'linux'.

    Ubuntu 는 판마다 커널 소스가 따로다 (generic 은 linux, AWS AMI 는 linux-aws). 실행 중인 이미지 패키지
    (kernel.running_package)의 소스를 보고 서명 · 메타 소스면 커널 소스 이름으로 바꾼다. 이미지 패키지가 목록에 없으면
    같은 커널의 모듈 패키지(linux-modules-<uname -r>)의 소스를 쓴다. 콘솔 API 의 주목 CVE 판정도 같은 규칙을 쓴다.
    """
    kernel = kernel if isinstance(kernel, dict) else {}
    by_name = {p.get("name"): p for p in packages or [] if isinstance(p, dict)}
    names = [kernel.get("running_package")]
    if isinstance(kernel.get("running"), str) and kernel["running"]:
        names.append(f"linux-modules-{kernel['running']}")
    for name in names:
        src = (by_name.get(name) or {}).get("source") if isinstance(name, str) else None
        if is_kernel_source(src):
            return _unsigned_source(src)
    return "linux"


_KERNEL_RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([a-z0-9][a-z0-9.+-]*)")


def newest_kernel(kernel):
    """실행 중인 커널과 같은 판(uname -r 의 접미사 generic · aws 등)으로 설치된 이미지 중 가장 높은 버전. 판을 모르면 None.

    판이 다른 이미지는 소스가 달라(generic 6.8.0-142 와 aws 6.8.0-1036) 버전을 견줄 수 없다.
    """
    kernel = kernel if isinstance(kernel, dict) else {}
    m = _KERNEL_RELEASE.fullmatch(kernel.get("running") or "")
    if not m:
        return None
    same = re.compile(r"linux-image-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-" + re.escape(m.group(1)))
    vers = [k.get("version") for k in kernel.get("installed") or []
            if isinstance(k, dict) and k.get("version") and same.fullmatch(k.get("package") or "")]
    return max(vers, key=dpkg_key) if vers else None


def osv_plan(os_info, kernel, packages):
    """자산 하나의 질의 계획. ({eco, queries: [(소스, 소스 버전)], kernel, running, newest}, None) 또는 (None, 대조 못 한 이유).

    커널 바이너리는 빼고 실행 중인 커널 이미지 버전을 커널 소스 이름(kernel)으로 묻는다. 같은 판으로 설치된 가장 높은
    커널이 실행 중인 것보다 새것이면 그 버전도 묻는다 (새 커널에서 사라지는 기록은 재부팅하면 해소된다).
    """
    eco = osv_ecosystem(os_info)
    if eco is None:
        return None, "지원하지 않는 배포판"
    pkgs = [p for p in packages or [] if isinstance(p, dict) and p.get("source") and p.get("source_version")]
    if not pkgs:
        return None, "패키지 목록이 없다"
    queries = sorted({(p["source"], p["source_version"]) for p in pkgs if not is_kernel_package(p)})
    kernel = kernel if isinstance(kernel, dict) else {}
    running = kernel.get("running_version") or None
    newest = None
    if running:
        top = newest_kernel(kernel)
        if top and dpkg_compare(top, running) > 0:
            newest = top
    return {"eco": eco, "queries": queries, "kernel": kernel_source(kernel, pkgs), "running": running,
            "newest": newest}, None


def osv_query(http, queries):
    """querybatch 로 (생태계, 패키지, 버전) 질의들을 묻는다. {질의: [(id, modified)]}.

    다음 쪽 토큰이 있는 질의만 page_token 을 붙여 다시 묻는다 (질의 하나당 OSV_PAGES 쪽까지).
    """
    out = {q: [] for q in queries}
    seen = {q: set() for q in queries}
    pages = dict.fromkeys(queries, 0)
    pending = [(q, None) for q in queries]
    while pending:
        nxt = []
        for i in range(0, len(pending), OSV_BATCH):
            chunk = pending[i:i + OSV_BATCH]
            body = {"queries": [dict({"package": {"name": q[1], "ecosystem": q[0]}, "version": q[2]},
                                     **({"page_token": tok} if tok else {})) for q, tok in chunk]}
            resp = http.post_json(OSV_BATCH_URL, body, LIMITS["osv"])
            results = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise CtiError("OSV querybatch 응답의 결과 수가 질의 수와 다르다")
            for (q, _tok), r in zip(chunk, results):
                r = r if isinstance(r, dict) else {}
                for v in r.get("vulns") or []:
                    oid = v.get("id") if isinstance(v, dict) else None
                    if isinstance(oid, str) and OSV_ID_RE.fullmatch(oid) and oid not in seen[q]:
                        seen[q].add(oid)
                        out[q].append((oid, parse_ts(v.get("modified"))))
                tok = r.get("next_page_token")
                if isinstance(tok, str) and tok:
                    pages[q] += 1
                    if pages[q] >= OSV_PAGES:
                        raise CtiError(f"OSV 질의 쪽 수가 상한({OSV_PAGES})을 넘었다: {q[1]} {q[2]}")
                    nxt.append((q, tok))
        pending = nxt
    return out


def osv_need_detail(ids, existing, kev):
    """상세 기록을 받을 id (KEV 에 있는 CVE 먼저, 그다음 id 순).

    ids: {id: (modified, 커널이 아닌 질의에서도 나왔는가)}, existing: {id: (modified, detailed)}.
    커널 질의에서만 나온 id 는 CVE 가 KEV 에 있을 때만 받는다 (커널 하나에 수천 건이다).
    이미 상세가 있고 modified 가 그대로면 받지 않는다. 상한에 밀려 상세 없이 넣은 id 는 다음 회차에 받는다.
    """
    need = []
    for oid, (mod, non_kernel) in ids.items():
        if not non_kernel and cve_from_id(oid) not in kev:
            continue
        old = existing.get(oid)
        if old and old[1] and not (mod is not None and (old[0] is None or mod > old[0])):
            continue
        need.append(oid)
    return sorted(need, key=lambda i: (cve_from_id(i) not in kev, i))


def osv_detail(rec):
    """상세 기록 → cti_osv 열. fixed 는 {"생태계/패키지": 수정 버전}, affected 는 모든 영향 항목 {"생태계/패키지": 수정 버전 또는 None}."""
    upstream = [u for u in rec.get("upstream") or [] if isinstance(u, str) and CVE_RE.fullmatch(u)]
    prio = vector = None
    for s in rec.get("severity") or []:
        if not isinstance(s, dict) or not isinstance(s.get("score"), str):
            continue
        if s.get("type") == "Ubuntu" and s["score"].lower() in UBUNTU_PRIORITIES:
            prio = s["score"].lower()
        elif s.get("type") == "CVSS_V3" and len(s["score"]) <= 200:
            vector = s["score"]
    details = rec.get("details") if isinstance(rec.get("details"), str) else rec.get("summary")
    fixed, affected = {}, {}
    for a in rec.get("affected") or []:
        pkg = a.get("package") if isinstance(a, dict) else None
        if not (isinstance(pkg, dict) and isinstance(pkg.get("ecosystem"), str) and isinstance(pkg.get("name"), str)):
            continue
        key = f"{pkg['ecosystem']}/{pkg['name']}"
        affected.setdefault(key, None)
        for rg in a.get("ranges") or []:
            for ev in (rg.get("events") if isinstance(rg, dict) else None) or []:
                fv = ev.get("fixed") if isinstance(ev, dict) else None
                if isinstance(fv, str) and fv and (key not in fixed or dpkg_compare(fv, fixed[key]) > 0):
                    fixed[key] = fv
    affected.update(fixed)
    return {"cve_id": upstream[0] if upstream else cve_from_id(rec.get("id")),
            "modified": parse_ts(rec.get("modified")), "ubuntu_priority": prio, "cvss_vector": vector,
            "summary": details[:500] if isinstance(details, str) and details else None, "fixed": fixed,
            "affected": affected}


def asset_vuln_rows(plan, results, info):
    """자산 하나의 asset_vulnerabilities 행 (소스 패키지, 버전, osv_id, cve_id, fix_state, fixed_version).

    커널은 실행 중인 커널 질의만 센다 (소스 패키지는 커널 소스 이름: linux · linux-aws 등). USN-… 은 공지라 세지 않는다.
    같은 소스 패키지가 두 버전으로 깔려 있으면 낮은 쪽을 남긴다. fix_state:
      reboot_pending  커널 기록이 같은 판으로 설치된 가장 높은 커널의 질의 결과에 없다. 재부팅하면 해소 (fixed_version = 그 커널)
      fix_available   배포판 기록에 이 소스 패키지의 수정 버전이 있다 (fixed_version = 그 버전)
      no_fix          상세 기록을 받았는데 수정 버전이 없다
      unknown         상세 기록을 아직 받지 않았다
    """
    eco, ksrc = plan["eco"], plan["kernel"]
    targets = [(pkg, ver, False) for pkg, ver in plan["queries"]]
    if plan["running"]:
        targets.append((ksrc, plan["running"], True))
    newest = None
    if plan["running"] and plan["newest"]:
        newest = {oid for oid, _ in results.get((eco, ksrc, plan["newest"]), [])}
    out = {}
    for pkg, ver, is_kernel in targets:
        for oid, _mod in results.get((eco, pkg, ver), []):
            if oid.startswith("USN-"):
                continue
            inf = info.get(oid) or {}
            cve = cve_from_id(oid) or (inf.get("cve_id") if CVE_RE.fullmatch(inf.get("cve_id") or "") else None)
            fixed = (inf.get("fixed") or {}).get(f"{eco}/{pkg}")
            if is_kernel and newest is not None and oid not in newest:
                state, fv = "reboot_pending", plan["newest"]
            elif isinstance(fixed, str) and fixed:
                state, fv = "fix_available", fixed
            elif inf.get("detailed"):
                state, fv = "no_fix", None
            else:
                state, fv = "unknown", None
            prev = out.get((pkg, oid))
            if prev and dpkg_compare(prev[1], ver) <= 0:
                continue
            out[(pkg, oid)] = (pkg, ver, oid, cve, state, fv)
    return [out[k] for k in sorted(out)]


def load_watchlist(path):
    """주목 CVE 목록 파일 → [(CVE, 이유)]. 형식이 틀리면 CtiError (코드와 함께 배포하는 파일이라 틀리면 드러나게 한다).

    {"note": "…", "watch": [{"cve": "CVE-2024-6387", "reason": "…"}, …]}. CVE 형식 · 이유 문자열 · 중복 없음 · 50개 이하.
    """
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise CtiError(f"주목 CVE 목록을 읽지 못했다 ({path}: {type(e).__name__})") from None
    items = doc.get("watch") if isinstance(doc, dict) else None
    if not isinstance(items, list) or len(items) > WATCH_MAX:
        raise CtiError(f"주목 CVE 목록의 watch 는 {WATCH_MAX}개 이하 목록이어야 한다 ({path})")
    out, seen = [], set()
    for i, it in enumerate(items, 1):
        cve = it.get("cve") if isinstance(it, dict) else None
        reason = it.get("reason") if isinstance(it, dict) else None
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            raise CtiError(f"주목 CVE 목록 {i}번째 항목의 cve 형식이 틀리다 ({path})")
        if (not isinstance(reason, str) or not reason.strip() or len(reason) > WATCH_REASON_MAX
                or _CTRL.search(reason) or _SURROGATE.search(reason)):
            raise CtiError(f"주목 CVE 목록 {cve} 의 reason 은 {WATCH_REASON_MAX}자 이하 문자열이어야 한다 ({path})")
        if cve in seen:
            raise CtiError(f"주목 CVE 목록에 {cve} 가 두 번 있다 ({path})")
        seen.add(cve)
        out.append((cve, reason))
    return out


def watch_records(ctx, watch, details):
    """주목 CVE 마다 Ubuntu 기록(UBUNTU-<CVE>)을 받는다. ({CVE: 기록 또는 None(404, 기록 없음)}, 실패 수).

    이 회차에 자산 대조로 이미 받은 상세는 다시 받지 않는다. 404 가 아닌 오류는 그 CVE 만 건너뛴다 (다음 회차에 다시).
    """
    got, bad = {}, 0
    for cve, _reason in watch:
        oid = "UBUNTU-" + cve
        if oid in details:
            got[cve] = details[oid]
            continue
        try:
            rec = ctx.http.get_json(OSV_VULN_URL + urllib.parse.quote(oid, safe=""), LIMITS["osv"])
            if not isinstance(rec, dict) or rec.get("id") != oid:
                raise CtiError("상세 기록의 id 가 묻은 것과 다르다")
        except HttpStatus as e:
            if e.code == 404:
                got[cve] = None
                continue
            bad += 1
            log(f"osv: 주목 CVE {cve} 의 기록을 받지 못했다 ({why(e)}). 다음 회차에 다시 받는다", 4)
            continue
        except CtiError as e:
            bad += 1
            log(f"osv: 주목 CVE {cve} 의 기록을 받지 못했다 ({why(e)}). 다음 회차에 다시 받는다", 4)
            continue
        got[cve] = rec
    return got, bad


ASSETS_FOR_CHECK = """
SELECT asset_id, os, kernel, packages FROM asset_inventory
 WHERE collected_at IS NOT NULL AND (%s::text[] IS NULL OR asset_id = ANY(%s::text[]))
 ORDER BY asset_id"""


def mark_unchecked(ctx, skipped):
    """대조하지 못한 자산에 이유를 적는다. 원천 자료가 아니라 자산 상태라 원본 기록과 따로 곧바로 커밋한다
    (대조한 자산이 하나도 없어 원본 기록을 남기지 않는 회차에도 이유는 남아야 한다)."""
    if not skipped:
        return
    cur = ctx.conn.cursor()
    for asset_id, err in sorted(skipped.items()):
        cur.execute("UPDATE asset_inventory SET check_error = %s WHERE asset_id = %s", (err, asset_id))
    ctx.conn.commit()


def osv_produce(ctx, only=None, watch=None, out=None):
    """OSV 한 회차의 원본 문서와 정규화할 값. 할 일이 없으면 None (원본 기록을 남기지 않는다).

    only: 대조할 자산 (load-assets 는 받은 자산만). watch: 주목 CVE 도 볼지 (기본은 fetch, 곧 only 가 없을 때).
    out 에 대조하지 못한 자산 {asset_id: 이유} 를 담아 준다 (load-assets 의 종료 코드).
    대조한 자산도 조회한 주목 CVE 도 없으면 None 이다. 주목 CVE 를 하나도 조회하지 못했는데 대조한 자산도 없으면 실패다.
    """
    if watch is None:
        watch = only is None
    assets = select(ctx, ASSETS_FOR_CHECK, (only, only))
    plans, skipped = {}, {}
    for asset_id, os_info, kernel, packages in assets:
        plan, err = osv_plan(os_info, kernel, packages)
        if err:
            skipped[asset_id] = err
        else:
            plans[asset_id] = plan
    if out is not None:
        out["skipped"] = dict(skipped)
    mark_unchecked(ctx, skipped)
    watchlist = load_watchlist(ctx.watchlist) if watch else None     # None: 이 회차는 주목 CVE 를 보지 않는다
    if not plans and not watchlist:
        why_none = "조사 결과가 있는 자산이 없다" if not assets else "모두 대조하지 못한다"
        log(f"osv: 대조할 자산이 없다 ({why_none}). 원본 기록을 남기지 않는다")
        return None
    queries, kernel_q = set(), set()
    for plan in plans.values():
        queries.update((plan["eco"], pkg, ver) for pkg, ver in plan["queries"])
        kq = {(plan["eco"], plan["kernel"], ver) for ver in (plan["running"], plan["newest"]) if ver}
        kernel_q |= kq
        queries |= kq
    queries = sorted(queries)
    results = osv_query(ctx.http, queries) if queries else {}
    ids = {}     # id → (modified, 커널이 아닌 질의에서도 나왔는가). USN 은 공지라 기록에 넣지 않는다
    for q, vulns in results.items():
        for oid, mod in vulns:
            if not oid.startswith("USN-"):
                m0, nk = ids.get(oid, (None, False))
                ids[oid] = (later(m0, mod), nk or q not in kernel_q)
    kev = {r[0] for r in select(ctx, "SELECT cve_id FROM cti_kev")}
    existing = {}
    if ids:
        existing = {r[0]: (r[1], r[2]) for r in
                    select(ctx, "SELECT osv_id, modified, detailed FROM cti_osv WHERE osv_id = ANY(%s)", (sorted(ids),))}
    need = osv_need_detail(ids, existing, kev)
    details, bad = {}, 0
    for oid in need[:OSV_DETAILS]:
        try:
            rec = ctx.http.get_json(OSV_VULN_URL + urllib.parse.quote(oid, safe=""), LIMITS["osv"])
            if not isinstance(rec, dict) or rec.get("id") != oid:
                raise CtiError("상세 기록의 id 가 묻은 것과 다르다")
            details[oid] = rec
        except CtiError as e:
            bad += 1
            log(f"osv: 상세 {oid} 를 받지 못했다 ({why(e)}). 다음 회차에 다시 받는다", 4)
    if len(need) > OSV_DETAILS:
        log(f"osv: 상세 {len(need) - OSV_DETAILS}건은 다음 회차에 받는다 (회차당 {OSV_DETAILS}건)")
    watched, watch_bad = watch_records(ctx, watchlist, details) if watchlist else ({}, 0)
    if watchlist and not watched and not plans:
        raise CtiError(f"주목 CVE {len(watchlist)}개의 기록을 하나도 받지 못했다 (대조한 자산도 없다)")
    doc = {"schema": "opsloop-cti-osv/1", "fetched_at": iso(ctx.now()),
           "queries": [{"package": {"name": q[1], "ecosystem": q[0]}, "version": q[2],
                        "vulns": [{"id": oid, "modified": iso(mod)} for oid, mod in results[q]]} for q in queries],
           "details": details}
    if watch:
        doc["watch"] = watched
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    found = {"UBUNTU-" + c for c, r in watched.items() if r is not None}
    data = {"plans": plans, "skipped": skipped, "results": results, "ids": ids, "details": details, "bad": bad,
            "watch": watchlist, "watched": watched, "watch_bad": watch_bad}
    return Payload(body, "json", OSV_BATCH_URL, data, records=len(set(ids) | found))


# 인자: 원본 기록 id, id · CVE · modified · 등급 · 벡터 · 요약 · 수정 버전 · 영향 항목 배열
OSV_UPSERT_DETAILED = """
INSERT INTO cti_osv (osv_id, cve_id, modified, detailed, ubuntu_priority, cvss_vector, summary, fixed, affected,
                     snapshot_id)
SELECT o.osv_id, o.cve_id, o.modified, true, o.prio, o.vector, o.summary, o.fixed, o.affected, %s
  FROM unnest(%s::text[], %s::text[], %s::timestamptz[], %s::text[], %s::text[], %s::text[], %s::jsonb[], %s::jsonb[])
       AS o(osv_id, cve_id, modified, prio, vector, summary, fixed, affected)
ON CONFLICT (osv_id) DO UPDATE SET
    cve_id = EXCLUDED.cve_id, modified = EXCLUDED.modified, detailed = true,
    ubuntu_priority = EXCLUDED.ubuntu_priority, cvss_vector = EXCLUDED.cvss_vector, summary = EXCLUDED.summary,
    fixed = EXCLUDED.fixed, affected = EXCLUDED.affected, snapshot_id = EXCLUDED.snapshot_id"""

# 상세 없이 id · modified 만 (asset_vulnerabilities 의 참조 키). 이미 있으면 그대로 둔다:
# modified 를 여기서 올리면 다음 회차가 '바뀐 기록'을 알아보지 못한다
OSV_INSERT_BARE = """
INSERT INTO cti_osv (osv_id, cve_id, modified, snapshot_id)
SELECT o.osv_id, o.cve_id, o.modified, %s
  FROM unnest(%s::text[], %s::text[], %s::timestamptz[]) AS o(osv_id, cve_id, modified)
ON CONFLICT (osv_id) DO NOTHING"""

# 인자: 자산 id, 원본 기록 id, 열별 배열 6개
ASSET_VULN_INSERT = """
INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id, cve_id, fix_state, fixed_version,
                                   snapshot_id)
SELECT %s, v.source_package, v.version, v.osv_id, v.cve_id, v.fix_state, v.fixed_version, %s
  FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::text[], %s::text[])
       AS v(source_package, version, osv_id, cve_id, fix_state, fixed_version)"""

# 주목 CVE 를 목록과 같게: 목록에 있는 것은 이유를 맞추고(새 CVE 는 조회 전 상태로 생긴다), 빠진 것은 지운다.
# 인자: CVE · 이유 배열
WATCH_UPSERT = """
INSERT INTO cti_watch (cve_id, reason)
SELECT w.cve_id, w.reason FROM unnest(%s::text[], %s::text[]) AS w(cve_id, reason)
ON CONFLICT (cve_id) DO UPDATE SET reason = EXCLUDED.reason"""

# 이번 회차에 조회한 주목 CVE 만 결과를 고친다 (오류로 건너뛴 CVE 는 옛 결과를 둔다).
# 인자: 원본 기록 id, CVE · 기록 id · 기록 있음 배열
WATCH_CHECKED = """
UPDATE cti_watch w SET osv_id = c.osv_id, record_found = c.found, checked_at = now(), snapshot_id = %s
  FROM unnest(%s::text[], %s::text[], %s::boolean[]) AS c(cve_id, osv_id, found)
 WHERE w.cve_id = c.cve_id"""


def watch_apply(cur, snap_id, watchlist, watched):
    """cti_watch 를 목록과 같게 맞추고 조회 결과를 적는다. 기록 있음 수 · 없음 수."""
    cur.execute(WATCH_UPSERT, columns(watchlist) or [[], []])
    cur.execute("DELETE FROM cti_watch WHERE cve_id <> ALL(%s::text[])", ([c for c, _ in watchlist],))
    rows = [(c, "UBUNTU-" + c if r is not None else None, r is not None) for c, r in sorted(watched.items())]
    if rows:
        cur.execute(WATCH_CHECKED, [snap_id] + columns(rows))
    found = sum(1 for r in rows if r[2])
    return found, len(rows) - found


def osv_apply(ctx, cur, snap_id, d):
    records = dict(d["details"])
    records.update({"UBUNTU-" + c: r for c, r in d["watched"].items() if r is not None})
    details = {oid: osv_detail(rec) for oid, rec in records.items()}
    if details:
        ids = sorted(details)
        cur.execute(OSV_UPSERT_DETAILED, [
            snap_id, ids, [details[i]["cve_id"] for i in ids],
            [details[i]["modified"] or d["ids"].get(i, (None,))[0] for i in ids],
            [details[i]["ubuntu_priority"] for i in ids], [details[i]["cvss_vector"] for i in ids],
            [details[i]["summary"] for i in ids], [json.dumps(details[i]["fixed"], sort_keys=True) for i in ids],
            [json.dumps(details[i]["affected"], sort_keys=True) for i in ids]])
    rest = sorted(set(d["ids"]) - set(details))
    if rest:
        cur.execute(OSV_INSERT_BARE, [snap_id, rest, [cve_from_id(i) for i in rest], [d["ids"][i][0] for i in rest]])
    info = {}
    if d["ids"]:
        cur.execute("SELECT osv_id, cve_id, detailed, fixed FROM cti_osv WHERE osv_id = ANY(%s)", (sorted(d["ids"]),))
        info = {r[0]: {"cve_id": r[1], "detailed": r[2], "fixed": r[3]} for r in cur.fetchall()}
    total, cves = 0, set()
    for asset_id, plan in sorted(d["plans"].items()):
        rows = asset_vuln_rows(plan, d["results"], info)
        cur.execute("DELETE FROM asset_vulnerabilities WHERE asset_id = %s", (asset_id,))
        if rows:
            cur.execute(ASSET_VULN_INSERT, [asset_id, snap_id] + columns(rows))
        cur.execute("UPDATE asset_inventory SET checked_at = now(), check_snapshot_id = %s, check_error = NULL"
                    " WHERE asset_id = %s", (snap_id, asset_id))
        total += len(rows)
        cves.update(r[3] for r in rows if r[3])
    watch = ""
    if d["watch"] is not None:
        found, missing = watch_apply(cur, snap_id, d["watch"], d["watched"])
        cves.update(c for c, _ in d["watch"])
        watch = (f" · 주목 CVE {len(d['watch'])}개(기록 있음 {found} · 없음 {missing}"
                 f" · 조회 실패 {d['watch_bad']})")
    filled = epss_fill(ctx, cur, cves)
    skipped = "".join(f" · {a} 대조 못 함({e})" for a, e in sorted(d["skipped"].items()))
    return (f"자산 {len(d['plans'])}개 대조 · 질의 {len(d['results'])}개 · 기록 {len(d['ids'])}개"
            f"(상세 {len(d['details'])}, 실패 {d['bad']}) · 자산 취약점 {total}건{watch} · EPSS 채움 {filled}건{skipped}")


def fetch_osv(ctx, only=None, out=None):
    """OSV 한 회차. only 가 없으면(fetch) 모든 자산과 주목 CVE 를, 있으면(load-assets) 그 자산만 대조한다."""
    return run_source(ctx, "osv", lambda c: osv_produce(c, only, out=out), osv_apply)


# ── NVD ────────────────────────────────────────────────────────────────────────

def kev_match(spec, row):
    """서명의 kev_match 가 KEV 항목(cve, 공급사, 제품, 이름, 설명)에 맞는가. 주어진 조건을 모두 만족해야 한다."""
    _cve, vendor, product, name, description = row
    if not re.search(spec["vendor"], vendor or "", re.I):
        return False
    if spec.get("product") and not re.search(spec["product"], product or "", re.I):
        return False
    if spec.get("text") and not re.search(spec["text"], f"{name or ''} {description or ''}", re.I):
        return False
    return True


def kev_matched(sigs, kev_rows):
    """서명 제품 조건(kev_match)에 맞는 KEV CVE (서명 순서 · KEV 행 순서, 중복 없이)."""
    out = []
    for s in sigs:
        spec = s.get("kev_match")
        if not isinstance(spec, dict) or not isinstance(spec.get("vendor"), str):
            continue
        try:
            for k in ("vendor", "product", "text"):
                if spec.get(k):
                    re.compile(spec[k])
        except (re.error, TypeError):
            log(f"nvd: 서명 {safe(s.get('id'), 60)} 의 kev_match 정규식이 틀려 건너뛴다", 4)
            continue
        out.extend(r[0] for r in kev_rows if r[0] not in out and kev_match(spec, r))
    return out


def focus_order(groups, recent, cap=NVD_MAX):
    """우선순위 묶음들을 차례로 이어 중복 · 최근에 받은 것을 빼고 상한까지."""
    out = []
    for g in groups:
        for c in g:
            if c not in out and c not in recent and CVE_RE.fullmatch(c or ""):
                out.append(c)
    return out[:cap]


def nvd_focus(ctx):
    """NVD 에 물을 CVE (우선순위 순): 주목 CVE → 서명 CVE → 서명 제품의 KEV → 자산 ∩ KEV → 자산 CVE 중 EPSS 상위."""
    watch = [r[0] for r in select(ctx, "SELECT cve_id FROM cti_watch ORDER BY cve_id")]
    sigs = read_signatures(ctx)
    kev_rows = select(ctx, "SELECT cve_id, vendor_project, product, name, description FROM cti_kev"
                           " ORDER BY date_added DESC, cve_id")
    asset_kev = [r[0] for r in select(ctx, """SELECT DISTINCT a.cve_id FROM asset_vulnerabilities a
                                                JOIN cti_kev k ON k.cve_id = a.cve_id ORDER BY 1""")]
    top = [r[0] for r in select(ctx, """SELECT c.cve_id FROM cti_cve c
                                         WHERE c.epss IS NOT NULL
                                           AND c.cve_id IN (SELECT cve_id FROM asset_vulnerabilities)
                                         ORDER BY c.epss DESC, c.cve_id LIMIT %s""", (NVD_TOP_EPSS,))]
    recent = {r[0] for r in select(ctx, "SELECT cve_id FROM cti_cve WHERE nvd_fetched_at > now() - %s * interval '1 day'",
                                   (NVD_FRESH_DAYS,))}
    return focus_order([watch, sorted(signature_cves(sigs)), kev_matched(sigs, kev_rows), asset_kev, top], recent)


def nvd_metric(cve):
    """CVSS 한 벌: V3.1(Primary 먼저) → V4.0 → V3.0 → V2. {score, version, vector, severity} 또는 None."""
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        found = [m for m in metrics.get(key) or [] if isinstance(m, dict) and isinstance(m.get("cvssData"), dict)]
        if not found:
            continue
        m = next((x for x in found if x.get("type") == "Primary"), found[0])
        d = m["cvssData"]
        score = d.get("baseScore")
        ok = isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10
        sev = d.get("baseSeverity") or m.get("baseSeverity")      # V2 는 baseSeverity 가 cvssData 밖에 있다
        return {"score": round(float(score), 1) if ok else None,
                "version": str(d["version"]) if d.get("version") is not None else None,
                "vector": d.get("vectorString") if isinstance(d.get("vectorString"), str) else None,
                "severity": sev if isinstance(sev, str) else None}
    return None


def parse_nvd(resp, cve_id):
    """NVD 응답 → {cvss, description, published, status}. NVD 에 없는 CVE 면 None."""
    vulns = resp.get("vulnerabilities") if isinstance(resp, dict) else None
    if not isinstance(vulns, list):
        raise CtiError("NVD 응답에 vulnerabilities 가 없다")
    cve = next((v["cve"] for v in vulns if isinstance(v, dict) and isinstance(v.get("cve"), dict)
                and v["cve"].get("id") == cve_id), None)
    if cve is None:
        return None
    desc = next((x.get("value") for x in cve.get("descriptions") or []
                 if isinstance(x, dict) and x.get("lang") == "en" and isinstance(x.get("value"), str)), None)
    status = cve.get("vulnStatus")
    return {"cvss": nvd_metric(cve), "description": desc, "published": parse_ts(cve.get("published")),
            "status": status if isinstance(status, str) else None}


# 인자: 원본 기록 id, 열별 배열 9개
NVD_UPSERT = """
INSERT INTO cti_cve (cve_id, cvss_score, cvss_version, cvss_vector, cvss_severity, description, published, nvd_status,
                     nvd_fetched_at, nvd_snapshot_id)
SELECT n.cve_id, n.score, n.version, n.vector, n.severity, n.description, n.published, n.status, n.fetched_at, %s
  FROM unnest(%s::text[], %s::numeric[], %s::text[], %s::text[], %s::text[], %s::text[], %s::timestamptz[],
              %s::text[], %s::timestamptz[])
       AS n(cve_id, score, version, vector, severity, description, published, status, fetched_at)
ON CONFLICT (cve_id) DO UPDATE SET
    cvss_score = EXCLUDED.cvss_score, cvss_version = EXCLUDED.cvss_version, cvss_vector = EXCLUDED.cvss_vector,
    cvss_severity = EXCLUDED.cvss_severity, description = EXCLUDED.description, published = EXCLUDED.published,
    nvd_status = EXCLUDED.nvd_status, nvd_fetched_at = EXCLUDED.nvd_fetched_at, nvd_snapshot_id = EXCLUDED.nvd_snapshot_id"""

# NVD 에 없는 CVE 는 받은 시각만 남긴다 (14일 동안 다시 묻지 않는다)
NVD_TOUCH = """
INSERT INTO cti_cve (cve_id, nvd_fetched_at, nvd_snapshot_id)
SELECT n.cve_id, n.fetched_at, %s FROM unnest(%s::text[], %s::timestamptz[]) AS n(cve_id, fetched_at)
ON CONFLICT (cve_id) DO UPDATE SET nvd_fetched_at = EXCLUDED.nvd_fetched_at, nvd_snapshot_id = EXCLUDED.nvd_snapshot_id"""


def nvd_apply(ctx, cur, snap_id, parsed):
    found = [(c, v, at) for c, (v, at) in sorted(parsed.items()) if v is not None]
    gone = [(c, at) for c, (v, at) in sorted(parsed.items()) if v is None]
    if found:
        cvss = [v["cvss"] or {} for _, v, _ in found]
        cur.execute(NVD_UPSERT, [
            snap_id, [c for c, _, _ in found], [x.get("score") for x in cvss], [x.get("version") for x in cvss],
            [x.get("vector") for x in cvss], [x.get("severity") for x in cvss],
            [v["description"] for _, v, _ in found], [v["published"] for _, v, _ in found],
            [v["status"] for _, v, _ in found], [at for _, _, at in found]])
    if gone:
        cur.execute(NVD_TOUCH, [snap_id] + columns(gone))
    return f"CVE {len(found)}건 갱신 · NVD 에 없음 {len(gone)}건"


def fetch_nvd(ctx):
    def produce(ctx):
        focus = nvd_focus(ctx)
        if not focus:
            log(f"nvd: 받을 CVE 가 없다 (초점 CVE 를 모두 {NVD_FRESH_DAYS}일 안에 받았다)")
            return None
        responses, parsed, bad = {}, {}, 0
        for i, cve in enumerate(focus):
            if i:
                ctx.sleep(NVD_GAP)
            try:
                resp = ctx.http.get_json(NVD_URL + cve, LIMITS["nvd"])
                parsed[cve] = (parse_nvd(resp, cve), ctx.now())
                responses[cve] = resp
            except CtiError as e:
                bad += 1
                log(f"nvd: {cve} 를 받지 못했다 ({why(e)})", 4)
        if not responses:
            raise CtiError(f"NVD 응답을 하나도 받지 못했다 ({bad}건 실패)")
        doc = {"schema": "opsloop-cti-nvd/1", "fetched_at": iso(ctx.now()), "responses": responses}
        body = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return Payload(body, "json", NVD_URL.split("?")[0], parsed, records=len(responses))
    return run_source(ctx, "nvd", produce, nvd_apply)


FETCHERS = {"kev": fetch_kev, "epss": fetch_epss, "osv": fetch_osv, "nvd": fetch_nvd}


# ── 자산 조사 묶음 ─────────────────────────────────────────────────────────────
# 허니팟(sensor) 자산의 출력은 장악된 호스트가 만든 비신뢰 데이터다. 크기 · 형 · 길이 · 글자를 모두 보고,
# 아는 키만 옮겨 담는다. 틀린 자산은 그 자산만 last_error 로 남기고 건너뛴다.

def text(v, field, limit=256, optional=False, pattern=None):
    """짧은 문자열 필드. 제어 문자 · 숨은 문자(형식 문자 Cf) · 짝 없는 대리 문자(UTF-8 로 쓸 수 없어 DB 인자에서 예외가
    난다)는 받지 않는다. 이름 · 버전 · 호스트명에는 숨은 문자가 쓰일 까닭이 없고, 판정 근거 문장에 섞여 표시를 위조한다."""
    if v is None and optional:
        return None
    if (not isinstance(v, str) or len(v) > limit or _CTRL.search(v) or _SURROGATE.search(v)
            or has_hidden(v)):
        raise ValueError(f"{field} 는 제어 문자 · 숨은 문자가 없는 {limit}자 이하 문자열이어야 한다")
    if pattern is not None and not pattern.fullmatch(v):
        raise ValueError(f"{field} 형식이 틀리다: {safe(v, 60)}")
    return v


def error_text(v, field):
    """오류 문구. 자유 문장이라 거부하지 않고 제어 문자는 빈칸, 짝 없는 대리 문자는 U+FFFD, 숨은 문자는 표식 ⟨U+XXXX⟩ 로
    바꾼다. 표식 때문에 길어져도(한 글자 최대 10자) 자르지 않는다. 무엇이 들어왔는지가 조사 근거다."""
    if not isinstance(v, str) or len(v) > 512:
        raise ValueError(f"{field} 는 512자 이하 문자열이어야 한다")
    return reveal(_SURROGATE.sub("\ufffd", _CTRL.sub(" ", v)))


def listing(v, field, cap, item=dict):
    if not isinstance(v, list) or len(v) > cap:
        raise ValueError(f"{field} 는 {cap}개 이하 목록이어야 한다")
    if not all(isinstance(x, item) for x in v):
        raise ValueError(f"{field} 항목의 형이 틀리다")
    return v


def check_probe(p, now):
    """cti/probe.py 출력 하나를 검증해 아는 키만 담아 돌려준다. 틀리면 ValueError."""
    if not isinstance(p, dict):
        raise ValueError("probe 가 객체가 아니다")
    if p.get("probe_version") != 1 or isinstance(p.get("probe_version"), bool):
        raise ValueError("probe_version 이 1 이 아니다")
    text(p.get("hostname"), "hostname", optional=True)
    collected = parse_ts(text(p.get("collected_at"), "collected_at", 64))
    if collected is None:
        raise ValueError("collected_at 이 시각이 아니다")
    if collected > now + FUTURE_SLACK:
        raise ValueError("collected_at 이 미래다")
    os_info = p.get("os")
    if os_info is not None:
        if not isinstance(os_info, dict):
            raise ValueError("os 가 객체가 아니다")
        os_info = {k: text(os_info.get(k), f"os.{k}", optional=True)
                   for k in ("id", "version_id", "codename", "pretty")}
    kernel = p.get("kernel")
    if kernel is not None:
        if not isinstance(kernel, dict):
            raise ValueError("kernel 이 객체가 아니다")
        kernel = {"running": text(kernel.get("running"), "kernel.running", optional=True),
                  "running_package": text(kernel.get("running_package"), "kernel.running_package", optional=True,
                                          pattern=PKG_RE),
                  "running_version": text(kernel.get("running_version"), "kernel.running_version", optional=True,
                                          pattern=VER_RE),
                  "installed": [{"package": text(k.get("package"), "kernel.installed.package", pattern=PKG_RE),
                                 "version": text(k.get("version"), "kernel.installed.version", pattern=VER_RE)}
                                for k in listing(kernel.get("installed") or [], "kernel.installed", MAX_KERNELS)]}
    packages = [{"name": text(x.get("name"), "packages.name", pattern=PKG_RE),
                 "version": text(x.get("version"), "packages.version", pattern=VER_RE),
                 "source": text(x.get("source"), "packages.source", pattern=PKG_RE),
                 "source_version": text(x.get("source_version"), "packages.source_version", pattern=VER_RE),
                 "arch": text(x.get("arch"), "packages.arch", optional=True)}
                for x in listing(p.get("packages", []), "packages", MAX_PACKAGES)]
    images = [{"container": text(x.get("container"), "images.container"),
               "image": text(x.get("image"), "images.image"),
               "image_id": text(x.get("image_id"), "images.image_id", optional=True)}
              for x in listing(p.get("images", []), "images", MAX_IMAGES)]
    errors = [error_text(x, "errors") for x in listing(p.get("errors", []), "errors", MAX_ERRORS, str)]
    return {"collected_at": collected, "os": os_info, "kernel": kernel, "packages": packages, "images": images,
            "errors": errors}


def check_asset(a, seen, now):
    """자산 항목 하나. kind: probe(조사 결과) · error(조사 실패) · invalid(형식 오류, 시도 기록만) · reject(버린다)."""
    if not isinstance(a, dict):
        return {"kind": "reject", "reason": "자산 항목이 객체가 아니다"}
    aid = a.get("asset_id")
    if not isinstance(aid, str) or not ASSET_RE.fullmatch(aid):
        return {"kind": "reject", "reason": f"asset_id 형식이 틀리다: {safe(aid, 70)}"}
    if aid in seen:
        return {"kind": "reject", "asset_id": aid, "reason": "asset_id 가 묶음에 두 번 있다"}
    seen.add(aid)
    if a.get("role") not in ROLES or a.get("method") not in METHODS:
        return {"kind": "reject", "asset_id": aid, "reason": "role · method 가 정해진 값이 아니다"}
    out = {"asset_id": aid, "role": a["role"], "method": a["method"], "host": None}
    try:
        out["host"] = text(a.get("host"), "host", optional=True)
        if "error" in a:
            out.update(kind="error", error=error_text(a["error"], "error"))
        else:
            out.update(kind="probe", probe=check_probe(a.get("probe"), now))
    except ValueError as e:
        out.update(kind="invalid", error=f"조사 결과 형식 오류: {safe(e, 400)}")
    except (TypeError, OverflowError, RecursionError, AttributeError, KeyError) as e:
        # 검증기가 미처 막지 못한 모양이라도 그 자산만 형식 오류로 둔다. 비신뢰 자산 하나가 묶음 전체를 깨지 않게 한다
        out.update(kind="invalid", error=f"조사 결과 형식 오류: {type(e).__name__}: {safe(e, 300)}")
    return out


def validate_bundle(body, now):
    """자산 조사 묶음(opsloop-assets/1) → (묶음, 자산 항목들). 묶음 자체가 틀리면 CtiError."""
    if len(body) > BUNDLE_MAX:
        raise CtiError(f"묶음이 {BUNDLE_MAX // MIB} MiB 를 넘는다")
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise CtiError("묶음이 JSON 이 아니다 (또는 너무 깊다)") from None
    if not isinstance(doc, dict) or doc.get("schema") != "opsloop-assets/1":
        raise CtiError("schema 가 opsloop-assets/1 이 아니다")
    assets = doc.get("assets")
    if not isinstance(assets, list) or not assets:
        raise CtiError("assets 목록이 없다")
    if len(assets) > MAX_ASSETS:
        raise CtiError(f"자산이 {MAX_ASSETS}개를 넘는다")
    seen = set()
    return doc, [check_asset(a, seen, now) for a in assets]


# 옛 조사(collected_at 이 더 이른 것)는 덮어쓰지 않는다. 묶음을 다시 보내 결과를 되돌리지 못하게 한다
ASSET_UPSERT = """
INSERT INTO asset_inventory AS a (asset_id, role, method, host, collected_at, received_at, os, kernel, packages, images,
                                  probe_errors, snapshot_id, last_attempt_at, last_error)
VALUES (%s, %s, %s, %s, %s, now(), %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, now(), NULL)
ON CONFLICT (asset_id) DO UPDATE SET
    role = EXCLUDED.role, method = EXCLUDED.method, host = EXCLUDED.host, collected_at = EXCLUDED.collected_at,
    received_at = EXCLUDED.received_at, os = EXCLUDED.os, kernel = EXCLUDED.kernel, packages = EXCLUDED.packages,
    images = EXCLUDED.images, probe_errors = EXCLUDED.probe_errors, snapshot_id = EXCLUDED.snapshot_id,
    last_attempt_at = EXCLUDED.last_attempt_at, last_error = NULL
 WHERE a.collected_at IS NULL OR a.collected_at <= EXCLUDED.collected_at"""

# 조사 실패 · 형식 오류: 시도 기록만 고치고 옛 조사 결과는 그대로 둔다. 행이 없으면 만든다
ASSET_ATTEMPT = """
INSERT INTO asset_inventory AS a (asset_id, role, method, host, last_attempt_at, last_error)
VALUES (%s, %s, %s, %s, now(), %s)
ON CONFLICT (asset_id) DO UPDATE SET last_attempt_at = EXCLUDED.last_attempt_at, last_error = EXCLUDED.last_error"""


def jsonb(v):
    return None if v is None else json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def assets_apply(ctx, cur, snap_id, entries):
    n = {"probe": 0, "error": 0, "invalid": 0, "reject": 0, "old": 0}
    for e in entries:
        n[e["kind"]] += 1
        if e["kind"] == "probe":
            p = e["probe"]
            cur.execute(ASSET_UPSERT, (e["asset_id"], e["role"], e["method"], e["host"], p["collected_at"],
                                       jsonb(p["os"]), jsonb(p["kernel"]), jsonb(p["packages"]), jsonb(p["images"]),
                                       jsonb(p["errors"]), snap_id))
            if cur.rowcount == 0:
                n["old"] += 1
                log(f"assets: {e['asset_id']} 는 이미 더 새 조사가 있어 건너뛴다", 4)
        elif e["kind"] in ("error", "invalid"):
            cur.execute(ASSET_ATTEMPT, (e["asset_id"], e["role"], e["method"], e["host"], e["error"]))
            if e["kind"] == "invalid":
                log(f"assets: {e['asset_id']} {safe(e['error'])}", 4)
        else:
            log(f"assets: 자산 항목을 버린다 ({safe(e['reason'])})", 4)
    return (f"자산 {len(entries)}개: 조사 {n['probe']} · 조사 실패 기록 {n['error']} · 형식 오류 {n['invalid']}"
            f" · 버림 {n['reject']} · 옛 조사라 건너뜀 {n['old']}")


def load_assets(ctx, body, check=True):
    """자산 조사 묶음 적재. 종료 코드를 돌려준다.

    0 정상 · 1 일부 자산 형식 오류 · 대조 실패 · 받은 자산 중 대조하지 못한 것(패키지 목록 없음 · 지원하지 않는 배포판)이
    있다 · 2 적재 실패. 대조하지 못한 자산이 있는데 0 으로 끝나면 수집 쪽(collect-assets.sh · launchd 기록)에 드러나지 않는다.
    """
    state = {}

    def produce(ctx):
        doc, entries = validate_bundle(body, ctx.now())
        state["entries"] = entries
        return Payload(body, "json", None, entries, parse_ts(doc.get("sent_at")), None, len(entries))
    if not run_source(ctx, "assets", produce, assets_apply):
        return 2
    entries = state["entries"]
    rc = 1 if any(e["kind"] in ("invalid", "reject") for e in entries) else 0
    received = sorted(e["asset_id"] for e in entries if e["kind"] == "probe")
    if check and received:
        out = {}
        if not fetch_osv(ctx, received, out=out):
            rc = 1
        for asset_id, err in sorted((out.get("skipped") or {}).items()):
            log(f"assets: {asset_id} 는 배포판 취약점과 대조하지 못했다 ({err})", 4)
            rc = 1
    return rc


# ── 상태 ───────────────────────────────────────────────────────────────────────

def status(conn, out=None):
    out = out or sys.stdout
    cur = conn.cursor()
    cur.execute("""SELECT DISTINCT ON (source) source, fetched_at, source_ts, source_version, records
                     FROM cti_snapshots WHERE status = 'ok' ORDER BY source, fetched_at DESC""")
    ok = {r[0]: r[1:] for r in cur.fetchall()}
    cur.execute("""SELECT DISTINCT ON (source) source, fetched_at, error
                     FROM cti_snapshots WHERE status = 'failed' ORDER BY source, fetched_at DESC""")
    bad = {r[0]: r[1:] for r in cur.fetchall()}
    print("== 출처 (마지막 성공)", file=out)
    for src in SOURCES + ("assets",):
        if src in ok:
            at, sts, ver, rec = ok[src]
            print(f"  {src:<6}  {kst(at)}  기준 {kst(sts)}  판 {ver or '-'}  {rec if rec is not None else '-'}건", file=out)
        else:
            print(f"  {src:<6}  성공 기록 없음", file=out)
        if src in bad and (src not in ok or bad[src][0] > ok[src][0]):
            print(f"          마지막 실패 {kst(bad[src][0])}: {safe(bad[src][1], 200)}", file=out)
    cur.execute("""SELECT a.asset_id, a.role, a.method, a.collected_at, a.last_attempt_at, a.last_error, a.checked_at,
                          a.check_error,
                          (SELECT count(*) FROM asset_vulnerabilities v WHERE v.asset_id = a.asset_id),
                          (SELECT count(*) FROM asset_vulnerabilities v JOIN cti_kev k ON k.cve_id = v.cve_id
                            WHERE v.asset_id = a.asset_id)
                     FROM asset_inventory a
                    ORDER BY array_position(ARRAY['target', 'platform', 'sensor'], a.role), a.asset_id""")
    rows = cur.fetchall()
    cur.execute("SELECT cve_id, record_found, checked_at, osv_id FROM cti_watch ORDER BY cve_id")
    watch = cur.fetchall()
    conn.rollback()
    print("== 주목 CVE (배포판 기록 조회)", file=out)
    if not watch:
        print("  없음 (fetch 가 watchlist.json 을 읽어 채운다)", file=out)
    for cve, found, at, oid in watch:
        state = {True: f"기록 있음 {oid}", False: "배포판 기록 없음", None: "조회 전"}[found]
        print(f"  {cve:<16} {state:<34} 조회 {kst(at)}", file=out)
    print("== 자산 (수집 · 대조)", file=out)
    if not rows:
        print("  자산 조사 결과가 없다 (Mac 에서 collect-assets.sh 를 돌린다)", file=out)
    for aid, role, method, coll, attempt, err, checked, cerr, nv, nk in rows:
        print(f"  {aid:<14} {role:<8} {method:<3}  수집 {kst(coll)}  대조 {kst(checked)}  취약점 {nv}건 (KEV {nk})", file=out)
        if err:
            print(f"                 마지막 시도 {kst(attempt)} 실패: {safe(err, 200)}", file=out)
        if cerr:
            print(f"                 대조 오류: {safe(cerr, 200)}", file=out)


# ── 명령 ───────────────────────────────────────────────────────────────────────

def new_http():
    return Http()


def open_ctx(cfg):
    """S3 · DB 를 연다. 설정이 틀리면 ConfigError, DB 에 못 붙으면 그 밖의 예외."""
    s3 = s3_client(cfg)
    conn = db_connect()
    return Ctx(conn, s3, cfg["bucket"], cfg["home"], new_http())


def parse_only(v):
    if not v:
        return set(SOURCES)
    got = {x.strip() for x in v.split(",") if x.strip()}
    unknown = got - set(SOURCES)
    if unknown or not got:
        raise ConfigError(f"알 수 없는 출처: {', '.join(sorted(unknown)) or '(빈 값)'} (kev · epss · osv · nvd)")
    return got


def cmd_fetch(args):
    only = parse_only(args.only)
    if args.no_nvd:
        only.discard("nvd")
    cfg = settings()
    try:
        ctx = open_ctx(cfg)
    except ConfigError:
        raise
    except Exception as e:
        log(f"DB 에 접속하지 못했다: {why(e)}", 3)
        return 1
    try:
        lock = take_lock(ctx.home)
    except CtiError as e:
        log(str(e), 3)
        ctx.conn.close()
        return 1
    results = {}
    try:
        for src in SOURCES:
            if src in only:
                results[src] = FETCHERS[src](ctx)
    finally:
        lock.close()
        ctx.conn.close()
    good = all(results.values())
    log("끝: " + " · ".join(f"{s} {'정상' if r else '실패'}" for s, r in results.items()), 6 if good else 3)
    return 0 if good else 1


def cmd_load_assets(args):
    body = sys.stdin.buffer.read(BUNDLE_MAX + 1)
    cfg = settings()
    try:
        ctx = open_ctx(cfg)
    except ConfigError:
        raise
    except Exception as e:
        log(f"DB 에 접속하지 못했다: {why(e)}", 3)
        return 2
    try:
        lock = take_lock(ctx.home)
    except CtiError as e:
        log(str(e), 3)
        ctx.conn.close()
        return 2
    try:
        return load_assets(ctx, body, check=not args.no_check)
    finally:
        lock.close()
        ctx.conn.close()


def cmd_status(args):
    try:
        conn = db_connect()
    except ConfigError:
        raise
    except Exception as e:
        log(f"DB 에 접속하지 못했다: {why(e)}", 3)
        return 1
    try:
        status(conn)
    except Exception as e:
        log(f"상태를 읽지 못했다: {why(e)} (infra/migrations/20260925_cti.sql 을 적용했는지 본다)", 3)
        return 1
    finally:
        conn.close()
    return 0


class KoreanHelp(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        # 하위 명령의 prog 를 만들 때는 prefix='' 로 부른다. 그때는 머리를 붙이지 않는다
        return super().add_usage(usage, actions, groups, "사용법: " if prefix is None else prefix)


class Parser(argparse.ArgumentParser):
    """도움말 · 오류 머리를 한국어로 찍는 인자 해석기 (하위 명령도 이 형을 쓴다)."""

    def __init__(self, *a, **kw):
        kw.setdefault("formatter_class", KoreanHelp)
        kw["add_help"] = False
        super().__init__(*a, **kw)
        self._positionals.title = "위치 인자"
        self._optionals.title = "옵션"
        self.add_argument("-h", "--help", action="help", help="이 도움말을 보이고 끝낸다")

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: 오류: {message}\n")


def build_parser():
    ap = Parser(prog="opsloop-cti",
                description="OpsLoop CTI 수집기 (이슈 #39). 공개 취약점 정보(KEV · EPSS · OSV · NVD)와 자산 조사 결과를\n"
                            "S3 cti/ (원본, 한 번만 쓰기)와 DB(정규화 행 · 원본 위치)에 둔다. 판정값이 아니라 조사 우선순위 정보다.",
                epilog="종료 코드: 0 정상 · 1 일부 출처 실패 (load-assets 는 일부 자산 형식 오류 · 대조 실패)\n"
                       "          2 설정 오류 (load-assets 는 적재 실패)")
    sub = ap.add_subparsers(title="하위 명령", dest="cmd", metavar="<명령>")
    f = sub.add_parser("fetch", help="공개 취약점 정보를 받는다 (kev → epss → osv → nvd)",
                       description="kev → epss → osv → nvd 순서로 받는다. 출처 하나가 실패해도 나머지는 돈다.\n"
                                   "원본은 S3 cti/ 에 한 번만 쓰고, 못 쓰면 그 출처의 DB 는 고치지 않는다.")
    f.add_argument("--only", metavar="출처,…", help="이 출처만 받는다 (kev · epss · osv · nvd 를 쉼표로 잇는다)")
    f.add_argument("--no-nvd", action="store_true", help="NVD 를 건너뛴다 (요청 사이 6.5초라 오래 걸린다)")
    f.set_defaults(func=cmd_fetch)
    la = sub.add_parser("load-assets", help="표준 입력의 자산 조사 묶음을 적재하고 배포판 취약점과 대조한다",
                        description="표준 입력의 자산 조사 묶음(opsloop-assets/1)을 검증해 원본을 S3 에 남기고\n"
                                    "asset_inventory 를 고친 뒤, 받은 자산만 배포판 취약점(OSV)과 대조한다.")
    la.add_argument("--no-check", action="store_true", help="적재만 하고 배포판 취약점 대조는 건너뛴다")
    la.set_defaults(func=cmd_load_assets)
    st = sub.add_parser("status", help="출처별 마지막 성공 · 주목 CVE · 자산별 수집 · 대조 시각을 보인다",
                        description="출처별 마지막 성공 · 주목 CVE 조회 결과 · 자산별 수집 · 대조 시각을 찍는다 (DB 만 읽는다).")
    st.set_defaults(func=cmd_status)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help(sys.stderr)
        return 2
    try:
        return args.func(args)
    except ConfigError as e:
        log(f"설정 오류: {e}", 3)
        return 2


if __name__ == "__main__":
    sys.exit(main())
