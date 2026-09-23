#!/usr/bin/env python3
"""데이터 노드 원장 풀러 (WBS 3.4).

센서가 S3 에 올린 원문 로그 조각을 안쪽에서 가져온다. 연결은 항상 안에서 밖으로 시작하고,
이 노드는 읽기 전용 키만 가진다.

동작
  1. 호스트마다 생존 신호(hb)를 먼저 읽는다. 업로더는 한 회차의 조각을 다 올린 뒤 hb 를 쓰므로,
     hb 보다 먼저 만들어진 조각까지가 "끝난 회차"다. 그 뒤 조각은 올라가는 중일 수 있어 다음으로 미룬다.
     (목록을 먼저 보고 hb 를 나중에 읽으면, 회전 직전 파일의 꼬리는 없고 새 파일만 있는 틈이 생긴다)
  2. 허용 호스트의 접두사(raw/v1/sensor=<s>/host=<h>/)만 목록 조회한다 (<s> 는 cowrie · decoy · gateway.
     gateway 는 관문 방화벽의 거부 기록이다). 커서를 쓰지 않으므로
     늦게 도착한 조각도 놓치지 않고, 다른 곳에 만든 키는 아예 보지 않는다.
  3. 키 규칙 · 크기(끝-시작) · 저장 등급을 검사한다. 맞지 않으면 받지 않는다.
  4. 새 조각은 받아서 SHA256 을 업로드 때 기록된 값과 대조하고, 줄바꿈으로 끝나는지 본 뒤 미러에 둔다.
     파서가 읽을 받은 편지함(inbox)에도 같은 파일을 걸어 둔다.
  5. 이미 받은 조각의 ETag 가 바뀌었으면 원장 변조 의심으로 경보하고 로컬 사본은 그대로 둔다.
  6. 파일 세대마다 0 부터 끊김 없이 이어지는지, hb 가 말한 위치까지 받았는지 본다.
     구멍이 있으면 종료 코드 10. 적재는 해도 되지만 탐지는 보류해야 한다
     (중간이 빈 데이터로 탐지하면 쪼개진 인시던트가 영구히 남는다).

센서가 장악된 경우를 가정한다. 센서는 규칙에 맞는 키로 아무 내용이나 올릴 수 있고 hb 도 마음대로 쓴다.
그래서 이 풀러는 센서가 보낸 어떤 값으로도 죽거나 메모리 · 디스크를 채우지 않아야 하고,
탐지를 막는 구멍은 운영자가 확인한 뒤 인정 목록으로 풀 수 있어야 한다.

종료 코드 (여러 개면 앞의 것)
  13  디스크 여유가 하한 아래라 받기를 멈춤 (탐지 보류)
   1  S3 일시 오류 (연결 끊김 · 시간 초과 · 5xx). 받지 못한 조각은 다음 회차에 다시 받는다 (탐지 보류)
  10  원장 구멍 (탐지 보류)
  11  생존 신호가 없거나 오래됐거나 형식이 틀림 (적재 · 탐지는 하되 실패로 드러낸다)
   0  정상

경로
  $OPSLOOP_HOME/raw/v1/...          원장 미러. S3 키와 같은 모양
  $OPSLOOP_HOME/inbox/<센서>/        아직 적재하지 않은 조각 (미러 파일의 하드 링크)
  $OPSLOOP_HOME/pull-state.json     받은 조각 목록과 이미 낸 경보

환경변수
  OPSLOOP_BUCKET     S3 버킷
  OPSLOOP_HOSTS      받을 센서 호스트 (쉼표). 목록 밖 호스트의 조각은 보지도 않는다
  OPSLOOP_GATEWAY_HOSTS  관문 방화벽 호스트 (쉼표, OPSLOOP_HOSTS 에도 있어야 한다). gateway 조각은 이 호스트만,
                     cowrie · decoy 조각은 이 밖의 호스트만 올릴 수 있다. 역할(센서 · 관문)과 버킷 정책의 host 경계가 먼저 막고, 풀러는 그 뒤의 둘째 확인으로,
                     장악된 허니팟이 관문 기록을 흉내 내거나, 생존 신호에 가짜 gateway 항목을 넣어 구멍을 만들지 못하게 한다
  OPSLOOP_HOME       작업 폴더 (기본 /var/lib/opsloop)
  OPSLOOP_GAP_ACK    운영자가 확인한 구멍 목록 (기본 /etc/opsloop/gap-ack.json).
                     ["cowrie/i-.../ino=123.g0", ...] 형식. 여기 있는 세대는 구멍 판정에서 뺀다
  OPSLOOP_RUN_BYTES  한 회차에 받을 최대 바이트 (기본 512MiB, 실패한 받기 포함). 넘으면 다음 회차로 미룬다
"""
import argparse
import base64
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

SENSORS = ("cowrie", "decoy", "gateway")   # 바꾸면 KEY_RE · coverage 의 세대 규칙도 같이 바꾼다
# fullmatch 로만 쓴다 ($ 는 끝 줄바꿈을 허용한다). 숫자는 [0-9] 로 쓴다 (\d 는 아랍-인도 숫자 등도 받는다)
KEY_RE = re.compile(
    r"raw/v1/sensor=(cowrie|decoy|gateway)/host=(i-[0-9a-f]{8,17})/"
    r"ino=([0-9]{1,20})\.g([0-9]{1,6})/([0-9]{12})-([0-9]{12})\.jsonl")
MAX_OBJ = 64 * 1024 * 1024        # 업로더는 8MiB 씩 자르고 긴 한 줄만 이를 넘는다. 64MiB 넘는 조각은 받지 않는다
HB_MAX = 1024 * 1024
HB_STALE = timedelta(minutes=15)  # 업로더 주기 5분의 세 배
RUN_BYTES = int(os.environ.get("OPSLOOP_RUN_BYTES", 512 * 1024 * 1024))
RUN_GETS = 5000                   # 한 회차의 받기 요청 수
RUN_SECONDS = 600                 # 한 회차의 받기 시간 (서비스 제한 900초 안에서 적재 · 탐지 몫을 남긴다)
# 다시 받아도 결과가 같은 오류만 영구 거부로 기록한다. 나머지(연결 · 시간 초과 · 5xx · 권한 일시 오류)는 다음 회차에 다시 받는다
PERMANENT_CODES = {"InvalidObjectState"}
MIN_FREE_BYTES = 2 * 1024 ** 3    # 미러와 PostgreSQL 이 같은 디스크를 쓴다. DB 가 멈추지 않게 여유를 남긴다
MIN_FREE_RATIO = 0.10
MAX_OFFSET = 10 ** 12
CAP = 2000                        # 상태에 남기는 거부 · 무시 · 경보 목록의 상한
SAVE_EVERY_N, SAVE_EVERY_S = 200, 30
READ = 1024 * 1024

EXIT_GAP, EXIT_STALE, EXIT_DISK = 10, 11, 13

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def safe(v):
    """센서가 정한 값(키 · ETag · 오류 문구)을 로그에 쓸 때. 줄바꿈으로 가짜 로그 줄을 만들지 못하게 한다."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(v))[:300]


def log(msg, level=6):
    prefix = f"<{level}>" if _JOURNAL else ""
    print(f"{prefix}{msg}", flush=True)


class Terminated(Exception):
    pass


def _on_term(signum, frame):
    raise Terminated()


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    except FileNotFoundError:
        st = {}
    st.setdefault("objects", {})    # 키 → {etag, sha256, size}
    st.setdefault("alerts", {})     # 키 → 이미 경보한 ETag
    st.setdefault("rejected", {})   # 키 → {etag, why}. 같은 ETag 면 다시 받지 않는다
    st.setdefault("ignored", {})    # 키 규칙 위반 키 → 이유 (한 번만 알린다)
    st.setdefault("bad_groups", [])  # 거부가 상한을 넘은 세대. 더 받지 않고 구멍으로 드러낸다
    st.setdefault("overflow", 0)    # 상한을 넘겨 기록하지 못한 거부 · 무시 수
    return st


def save_state(path, state):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pull-state.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cleanup_temp(home):
    """강제 종료로 남은 임시 파일을 치운다."""
    n = 0
    for root, _dirs, files in os.walk(home):
        for name in files:
            if name.startswith((".part.", ".pull-state.")) or (name.startswith(".") and name.endswith(".tmp")):
                try:
                    os.unlink(os.path.join(root, name))
                    n += 1
                except OSError:
                    pass
    if n:
        log(f"남은 임시 파일 {n}개를 지웠다", 5)


def disk_ok(home):
    st = os.statvfs(home)
    free = st.f_bavail * st.f_frsize
    total = st.f_blocks * st.f_frsize
    return free >= MIN_FREE_BYTES and free >= total * MIN_FREE_RATIO, free


def error_code(e):
    return getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__


def client_errors():
    try:
        from botocore.exceptions import BotoCoreError, ClientError
        return (ClientError, BotoCoreError)
    except ImportError:                 # 시험용 가짜 S3
        return (Exception,)


def _no_float(v):
    raise ValueError("정수가 아닌 숫자")


def _int(v):
    """JSON 정수(또는 ASCII 숫자 문자열)만 받는다. 실수 · 무한대 · 참거짓은 거부한다."""
    if isinstance(v, bool):
        raise ValueError("참거짓")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isascii() and v.isdigit() and len(v) <= 20:
        return int(v)
    raise ValueError("정수 아님")


def valid_hb(hb):
    """hb 를 검증해 {이름: {sensor, ino, gen, offset}} 로 돌려준다. 형식이 틀리면 None."""
    if not isinstance(hb, dict) or not isinstance(hb.get("files"), dict):
        return None
    out = {}
    for name, f in hb["files"].items():
        if not isinstance(f, dict) or f.get("sensor") not in SENSORS:
            return None
        try:
            ino, gen, off = _int(f.get("ino")), _int(f.get("gen", 0)), _int(f.get("offset", 0))
        except ValueError:
            return None
        if not (0 <= ino < 10 ** 20 and 0 <= gen <= 999999 and 0 <= off <= MAX_OFFSET):
            return None
        out[str(name)] = {"sensor": f["sensor"], "ino": str(ino), "gen": gen, "offset": off}
    return out


def read_hb(s3, bucket, host):
    """(검증된 hb files, S3 기준 쓰인 시각, 문제). 없거나 틀리면 files 는 None."""
    try:
        r = s3.get_object(Bucket=bucket, Key=f"hb/v1/host={host}/latest.json")
    except client_errors() as e:
        code = error_code(e)
        if code in ("NoSuchKey", "404", "AccessDenied", "403"):
            return None, None, f"없음 ({safe(code)})"
        raise
    body = r["Body"].read(HB_MAX + 1)
    if len(body) > HB_MAX:
        return None, None, "크기 초과"
    try:
        files = valid_hb(json.loads(body, parse_float=_no_float, parse_constant=_no_float))
    except (ValueError, RecursionError):
        files = None
    if files is None:
        return None, None, "형식이 틀림"
    return files, r["LastModified"], None


def list_raw(s3, bucket, hosts):
    for host in sorted(hosts):
        for sensor in SENSORS:
            prefix = f"raw/v1/sensor={sensor}/host={host}/"
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    yield obj


def inbox_name(host, ino, gen, start, end):
    """키의 원문 문자열로 만든다. 다시 포맷하면 서로 다른 키가 한 이름으로 모일 수 있다."""
    return f"{host}.{ino}.g{gen}.{start}-{end}.jsonl"


def group_id(sensor, host, ino, gen):
    return f"{sensor}/{host}/ino={ino}.g{gen}"


def load_ack(path):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
    except FileNotFoundError:
        return set()
    except (OSError, ValueError) as e:
        log(f"구멍 인정 목록을 읽지 못했다 ({safe(e)}). 인정 없이 판정한다", 3)
        return set()
    return {str(x) for x in v} if isinstance(v, list) else set()


def fetch(s3, bucket, key, size, home, sensor, name):
    """조각을 받아 검증한 뒤 미러와 받은 편지함에 둔다.

    (meta, 이유, 종류, 읽은 바이트) 를 돌려준다. 종류는 ok · reject(내용 문제, 다시 받아도 같다) ·
    transient(연결 · 시간 초과 · 5xx 등, 다음 회차에 다시 받는다).
    """
    def failed(e):
        code = error_code(e)
        return None, f"받기 실패 {code}", ("reject" if code in PERMANENT_CODES else "transient")

    # 편지함에 같은 이름이 이미 있는데 이 키의 미러 파일과 다른 파일이면, 다른 키가 같은 이름을 노리는 것이다
    box = os.path.join(home, "inbox", sensor)
    link = os.path.join(box, name)
    dest = os.path.join(home, key)
    if os.path.lexists(link):
        if not os.path.exists(dest) or not os.path.samefile(link, dest):
            return None, "편지함에 같은 이름의 다른 조각이 있음", "reject", 0

    try:
        r = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    except client_errors() as e:
        return (*failed(e), 0)
    want = r.get("ChecksumSHA256")
    if not want:
        return None, "업로드 체크섬 없음", "reject", 0
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    fd, part = tempfile.mkstemp(dir=os.path.dirname(dest), prefix=".part.")
    h = hashlib.sha256()
    n = 0
    last = b""
    try:
        with os.fdopen(fd, "wb") as f:
            body = r["Body"]
            while True:
                buf = body.read(READ)
                if not buf:
                    break
                n += len(buf)
                if n > size:
                    raise ValueError(f"크기 초과 {n} > {size}")
                h.update(buf)
                f.write(buf)
                last = buf[-1:]
            f.flush()
            os.fsync(f.fileno())
        got = base64.b64encode(h.digest()).decode()
        if n != size:
            raise ValueError(f"크기 불일치 {n} != {size}")
        if got != want:
            raise ValueError("SHA256 불일치")
        if last != b"\n":
            raise ValueError("줄바꿈으로 끝나지 않음")
    except ValueError as e:
        os.unlink(part)
        return None, str(e), "reject", n
    except client_errors() as e:
        os.unlink(part)
        return (*failed(e), n)
    except BaseException:
        os.unlink(part)
        raise

    os.replace(part, dest)
    fsync_dir(os.path.dirname(dest))
    os.makedirs(box, exist_ok=True)
    tmp = os.path.join(box, f".{name}.tmp")
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.link(dest, tmp)
    os.replace(tmp, link)
    fsync_dir(box)
    return {"sha256": got, "size": n}, None, "ok", n


def coverage(objects, hbs, ack=frozenset(), rejected=(), bad_groups=()):
    """파일 세대별로 0 부터 끊김 없이 이어지는지, hb 위치까지 받았는지 본다. 구멍 목록을 돌려준다.

    받지 않은 조각(rejected)의 구간도 "있어야 할 범위"로 본다. 그 구간을 다른 조각이 덮지 않으면 구멍이다.
    """
    groups = {}
    for key in objects:
        m = KEY_RE.fullmatch(key)
        if not m:
            continue
        sensor, host, ino, gen, start, end = m.groups()
        groups.setdefault((sensor, host, ino, int(gen)), []).append((int(start), int(end)))

    # hb 가 말하는 (센서, 호스트, inode, 세대) → 올린 위치
    expect = {}
    for host, files in hbs.items():
        for f in (files or {}).values():
            k = (f["sensor"], host, f["ino"], f["gen"])
            expect[k] = max(expect.get(k, 0), f["offset"])
    for key in rejected:
        m = KEY_RE.fullmatch(key)
        if m:
            sensor, host, ino, gen, _start, end = m.groups()
            k = (sensor, host, ino, int(gen))
            expect[k] = max(expect.get(k, 0), int(end))

    gaps = []
    for g, spans in groups.items():
        if group_id(*g) in ack:
            continue
        covered = 0
        for start, end in sorted(spans):
            if start > covered:
                gaps.append((g, covered, start))
            covered = max(covered, end)
        want = expect.get(g, 0)
        if covered < want:
            gaps.append((g, covered, want))
    for g, want in expect.items():
        if g not in groups and want > 0 and group_id(*g) not in ack:
            gaps.append((g, 0, want))
    seen = {group_id(*g) for g, _a, _b in gaps}
    for gid in bad_groups:
        if gid not in ack and gid not in seen:
            m = re.fullmatch(r"(cowrie|decoy|gateway)/(i-[0-9a-f]{8,17})/ino=([0-9]{1,20})\.g([0-9]{1,6})", gid)
            if m:
                gaps.append(((m[1], m[2], m[3], int(m[4])), -1, -1))   # 세대 통째로 격리
    return gaps


def role_ok(sensor, host, gateway_hosts):
    """발생원과 호스트의 짝이 맞는가. gateway 는 관문 호스트만, 나머지는 관문이 아닌 호스트만 올린다."""
    return (sensor == "gateway") == (host in gateway_hosts)


def run(s3, bucket, hosts, home, now=None, ack=frozenset(), gateway_hosts=frozenset()):
    now = now or datetime.now(timezone.utc)
    state_path = os.path.join(home, "pull-state.json")
    cleanup_temp(home)
    state = load_state(state_path)
    objects, alerts, rejected, ignored = state["objects"], state["alerts"], state["rejected"], state["ignored"]
    bad_groups = state["bad_groups"]
    overflow_before = state["overflow"]

    def remember(table, key, value, why, level):
        """상한 안에서만 기록한다. 같은 이유면 다시 알리지 않는다. 기록했으면 True."""
        if table.get(key) == value:
            return True
        if key not in table and len(table) >= CAP:
            state["overflow"] += 1
            return False
        table[key] = value
        log(f"{why}", level)
        return True

    # 1. hb 를 먼저 읽는다. 이 시각 이후 조각은 이번에 받지 않는다
    hbs, cutoff, stale = {}, {}, []
    transient = 0
    for host in sorted(hosts):
        try:
            files, when, problem = read_hb(s3, bucket, host)
        except client_errors() as e:
            files, when, problem = None, None, f"읽기 일시 오류 ({safe(error_code(e))})"
            transient += 1
        except Exception as e:                     # 한 호스트의 이상한 값이 다른 호스트를 막지 않게 한다
            files, when, problem = None, None, f"형식이 틀림 ({safe(type(e).__name__)})"
        if files:
            wrong = sorted(n for n, f in files.items() if not role_ok(f["sensor"], host, gateway_hosts))
            if wrong:
                # 이 호스트가 올릴 수 없는 발생원 항목은 빼고 본다. 두면 받지 않을 조각을 기다려 구멍이 된다
                remember(alerts, f"hb/{host}/role", ",".join(wrong)[:512],
                         f"경고: {host} 생존 신호에 이 호스트가 올릴 수 없는 발생원 항목 {len(wrong)}개. 빼고 본다", 3)
                files = {n: f for n, f in files.items() if n not in wrong}
        hbs[host], cutoff[host] = files, when
        if problem:
            log(f"경고: {host} 생존 신호 {problem}. 이 호스트 조각은 받지 않는다", 3 if "틀림" in problem or "초과" in problem else 4)
            if "일시 오류" not in problem:
                stale.append(host)
        elif now - when > HB_STALE:
            log(f"경고: {host} 생존 신호가 {int((now - when).total_seconds() // 60)}분 전. 업로더가 멈췄을 수 있다", 4)
            stale.append(host)

    got_n = got_b = read_b = gets = waiting = 0
    pending = set()                 # 이번에 못 받고 다음 회차에 받을 조각의 세대 (일시 구멍)
    disk_low = budget_hit = False
    started = time.monotonic()
    last_save, since_save = time.monotonic(), 0

    def maybe_save(force=False):
        nonlocal last_save, since_save
        if force or since_save >= SAVE_EVERY_N or time.monotonic() - last_save >= SAVE_EVERY_S:
            save_state(state_path, state)
            last_save, since_save = time.monotonic(), 0

    old = signal.signal(signal.SIGTERM, _on_term)
    try:
        for obj in list_raw(s3, bucket, hosts):
            key, size, etag = obj["Key"], obj["Size"], obj.get("ETag")

            known = objects.get(key)
            if known:
                if etag != known["etag"] and alerts.get(key) != etag:
                    remember(alerts, key, etag,
                             f"원장 변조 의심 {safe(key)}: ETag {safe(known['etag'])} → {safe(etag)}. 로컬 사본은 그대로 둔다", 2)
                continue

            m = KEY_RE.fullmatch(key)
            if not m:
                remember(ignored, key, "키 규칙 위반", f"받지 않음 {safe(key)}: 키 규칙 위반", 4)
                continue
            sensor, host, ino_s, gen_s, start_s, end_s = m.groups()
            start, end = int(start_s), int(end_s)
            gid = group_id(sensor, host, ino_s, int(gen_s))
            if host not in hosts:
                continue
            if not role_ok(sensor, host, gateway_hosts):
                remember(ignored, key, "발생원 · 호스트 불일치",
                         f"받지 않음 {safe(key)}: {sensor} 조각을 {host} 가 올렸다 (OPSLOOP_GATEWAY_HOSTS)", 3)
                continue
            if cutoff.get(host) is None or obj["LastModified"] > cutoff[host]:
                waiting += 1                    # 업로더 회차가 아직 끝나지 않았다
                continue
            prev = rejected.get(key)
            if prev and prev.get("etag") == etag:
                continue                        # 이미 거부한 그대로다. 다시 받지 않는다
            if gid in bad_groups:
                continue                        # 거부가 넘친 세대. 구멍으로 드러나 있다
            why = None
            if end <= start or size != end - start:
                why = f"크기 불일치 (구간 {end - start}, 객체 {size})"
            elif size > MAX_OBJ:
                why = f"조각이 너무 큼 ({size:,} B)"
            elif obj.get("StorageClass", "STANDARD") != "STANDARD":
                why = f"저장 등급 {obj.get('StorageClass')}"
            kind = "reject"
            if why is None:
                over = (read_b + size > RUN_BYTES and gets > 0) or gets >= RUN_GETS \
                    or time.monotonic() - started > RUN_SECONDS
                if over:
                    budget_hit = True
                    pending.add(gid)            # 이번 회차 한도. 다음 회차에 받는다
                    continue
                ok, free = disk_ok(home)
                if not ok:
                    log(f"디스크 여유 {free / 1024 ** 3:.1f}GiB 가 하한 아래라 받기를 멈춘다", 2)
                    disk_low = True
                    pending.add(gid)
                    break
                gets += 1
                meta, why, kind, nread = fetch(s3, bucket, key, size, home, sensor,
                                               inbox_name(host, ino_s, gen_s, start_s, end_s))
                read_b += nread
            if kind == "transient":
                transient += 1
                pending.add(gid)
                log(f"일시 오류 {safe(key)}: {safe(why)}. 다음 회차에 다시 받는다", 4)
                continue
            if why is not None:
                if not remember(rejected, key, {"etag": etag, "why": why}, f"받지 않음 {safe(key)}: {safe(why)}", 3):
                    # 거부 기록이 가득 찼다. 이 세대는 통째로 더 받지 않고 구멍으로 드러낸다
                    if gid not in bad_groups and len(bad_groups) < CAP:
                        bad_groups.append(gid)
                        log(f"받지 않음 {gid}: 거부가 너무 많아 세대 전체를 멈춘다 (센서 이상 의심)", 2)
                continue
            meta["etag"] = etag
            objects[key] = meta
            rejected.pop(key, None)
            got_n += 1
            got_b += size
            since_save += 1
            maybe_save()
    except Terminated:
        save_state(state_path, state)
        log("종료 신호를 받아 받은 만큼 저장하고 멈춘다", 4)
        return 1
    finally:
        signal.signal(signal.SIGTERM, old)

    maybe_save(force=True)

    gaps = coverage(objects, hbs, ack, rejected, bad_groups)
    hard = 0
    for (sensor, host, ino, gen), a, b in gaps:
        gid = group_id(sensor, host, ino, gen)
        if gid in pending:
            log(f"원장 구멍(일시) {gid}: {a:,} ~ {b:,} B 를 아직 못 받았다. 다음 회차에 받는다", 4)
        elif a < 0:
            hard += 1
            log(f"원장 구멍 {gid}: 세대 전체를 멈췄다. 확인 뒤 인정하려면 구멍 인정 목록에 이 세대를 넣는다", 3)
        else:
            hard += 1
            log(f"원장 구멍 {gid}: {a:,} ~ {b:,} B 없음 (S3 에 없거나 받지 않은 조각). "
                f"확인 뒤 인정하려면 구멍 인정 목록에 이 세대를 넣는다", 3)
    if state["overflow"] > overflow_before:
        log(f"상한을 넘겨 기록하지 못한 거부 · 무시 {state['overflow'] - overflow_before:,}건 (센서 이상 의심)", 3)
    log(f"받음 {got_n}개 {got_b:,} B · 대기 {waiting}개 · 한도로 미룸 {'있음' if budget_hit else '없음'} · "
        f"일시 오류 {transient} · 보관 {len(objects)}개 · 구멍 {hard}(일시 {len(gaps) - hard}) · 생존 신호 이상 {len(stale)}")
    if disk_low:
        return EXIT_DISK
    if transient:
        return 1
    if gaps:
        return EXIT_GAP
    if stale:
        return EXIT_STALE
    return 0


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 원장 풀러")
    ap.parse_args()
    bucket = os.environ.get("OPSLOOP_BUCKET")
    hosts = {h.strip() for h in os.environ.get("OPSLOOP_HOSTS", "").split(",") if h.strip()}
    home = os.environ.get("OPSLOOP_HOME", "/var/lib/opsloop")
    if not bucket or not hosts:
        sys.exit("OPSLOOP_BUCKET 과 OPSLOOP_HOSTS 가 필요합니다")
    ack = load_ack(os.environ.get("OPSLOOP_GAP_ACK", "/etc/opsloop/gap-ack.json"))
    gateway_hosts = frozenset(h.strip() for h in os.environ.get("OPSLOOP_GATEWAY_HOSTS", "").split(",") if h.strip())
    import boto3
    sys.exit(run(boto3.client("s3"), bucket, hosts, home, ack=ack, gateway_hosts=gateway_hosts))


if __name__ == "__main__":
    main()
