#!/usr/bin/env python3
"""데이터 노드 원장 풀러 (WBS 3.4).

센서가 S3 에 올린 원문 로그 조각을 안쪽에서 가져온다. 연결은 항상 안에서 밖으로 시작하고,
이 노드는 읽기 전용 키만 가진다.

동작
  1. 호스트마다 생존 신호(hb)를 먼저 읽는다. 업로더는 한 회차의 조각을 다 올린 뒤 hb 를 쓰므로,
     hb 보다 먼저 만들어진 조각까지가 "끝난 회차"다. 그 뒤 조각은 올라가는 중일 수 있어 다음으로 미룬다.
     (목록을 먼저 보고 hb 를 나중에 읽으면, 회전 직전 파일의 꼬리는 없고 새 파일만 있는 틈이 생긴다)
  2. raw/v1/ 를 전부 목록 조회한다. 커서를 쓰지 않으므로 늦게 도착한 조각도 놓치지 않는다.
  3. 키 규칙 · 허용 호스트 · 크기(끝-시작) 를 검사한다. 맞지 않으면 받지 않는다.
  4. 새 조각은 받아서 SHA256 을 업로드 때 기록된 값과 대조하고, 줄바꿈으로 끝나는지 본 뒤 미러에 둔다.
     파서가 읽을 받은 편지함(inbox)에도 같은 파일을 걸어 둔다.
  5. 이미 받은 조각의 ETag 가 바뀌었으면 원장 변조 의심으로 경보하고 로컬 사본은 그대로 둔다.
  6. 파일 세대마다 0 부터 끊김 없이 이어지는지, hb 가 말한 위치까지 받았는지 본다.
     구멍이 있으면 종료 코드 10. 적재는 해도 되지만 탐지는 보류해야 한다
     (중간이 빈 데이터로 탐지하면 쪼개진 인시던트가 영구히 남는다).

경로
  $OPSLOOP_HOME/raw/v1/...          원장 미러. S3 키와 같은 모양
  $OPSLOOP_HOME/inbox/<센서>/        아직 적재하지 않은 조각 (미러 파일의 하드 링크)
  $OPSLOOP_HOME/pull-state.json     받은 조각 목록과 이미 낸 경보

환경변수
  OPSLOOP_BUCKET   S3 버킷
  OPSLOOP_HOSTS    받을 센서 호스트 (쉼표). 목록 밖 호스트의 조각은 받지 않는다
  OPSLOOP_HOME     작업 폴더 (기본 /var/lib/opsloop)
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

KEY_RE = re.compile(
    r"^raw/v1/sensor=(cowrie|decoy)/host=(i-[0-9a-f]{8,17})/"
    r"ino=(\d{1,20})\.g(\d{1,6})/(\d{12})-(\d{12})\.jsonl$")
MAX_OBJ = 256 * 1024 * 1024      # 한 조각 상한. 업로더는 8MiB 씩 자르고, 긴 한 줄만 이보다 커질 수 있다
HB_STALE = timedelta(minutes=15)  # 업로더 주기 5분의 세 배
READ = 1024 * 1024

EXIT_GAP = 10

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))


def log(msg, level=6):
    prefix = f"<{level}>" if _JOURNAL else ""
    print(f"{prefix}{msg}", flush=True)


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
    except FileNotFoundError:
        st = {}
    st.setdefault("objects", {})   # 키 → {etag, sha256, size}
    st.setdefault("alerts", {})    # 키 → 이미 경보한 ETag
    st.setdefault("ignored", {})   # 키 → 받지 않은 이유 (한 번만 알린다)
    return st


def save_state(path, state):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pull-state.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def error_code(e):
    return getattr(e, "response", {}).get("Error", {}).get("Code")


def read_hb(s3, bucket, host):
    """최신 생존 신호와 그것이 쓰인 시각(S3 기준). 없으면 (None, None)."""
    try:
        r = s3.get_object(Bucket=bucket, Key=f"hb/v1/host={host}/latest.json")
    except Exception as e:
        if error_code(e) in ("NoSuchKey", "404", "AccessDenied", "403"):
            return None, None
        raise
    body = r["Body"].read(1024 * 1024)
    return json.loads(body), r["LastModified"]


def list_raw(s3, bucket):
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="raw/v1/")
    for page in pages:
        for obj in page.get("Contents", []):
            yield obj


def inbox_name(host, ino, gen, start, end):
    return f"{host}.{ino}.g{gen}.{start:012d}-{end:012d}.jsonl"


def fetch(s3, bucket, key, size, home, sensor, name):
    """조각을 받아 검증한 뒤 미러와 받은 편지함에 둔다. 검증에 실패하면 (None, 이유)."""
    r = s3.get_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")
    want = r.get("ChecksumSHA256")
    if not want:
        return None, "업로드 체크섬 없음"
    dest = os.path.join(home, key)
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
                h.update(buf)
                f.write(buf)
                n += len(buf)
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
        return None, str(e)
    except BaseException:
        os.unlink(part)
        raise
    os.replace(part, dest)
    fsync_dir(os.path.dirname(dest))

    # 파서가 읽을 곳에 같은 파일을 건다. 이미 있으면 바꿔 넣는다 (다시 받은 경우)
    box = os.path.join(home, "inbox", sensor)
    os.makedirs(box, exist_ok=True)
    link = os.path.join(box, name)
    tmp = os.path.join(box, f".{name}.tmp")
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.link(dest, tmp)
    os.replace(tmp, link)
    fsync_dir(box)
    return {"sha256": got, "size": n}, None


def coverage(objects, hbs):
    """파일 세대별로 0 부터 끊김 없이 이어지는지, hb 위치까지 받았는지 본다. 구멍 목록을 돌려준다."""
    groups = {}
    for key in objects:
        m = KEY_RE.match(key)
        if not m:
            continue
        sensor, host, ino, gen, start, end = m.groups()
        groups.setdefault((sensor, host, ino, int(gen)), []).append((int(start), int(end)))

    # hb 가 말하는 (센서, 호스트, inode, 세대) → 올린 위치
    expect = {}
    for host, hb in hbs.items():
        for f in (hb or {}).get("files", {}).values():
            k = (f.get("sensor"), host, str(f.get("ino")), int(f.get("gen", 0)))
            expect[k] = max(expect.get(k, 0), int(f.get("offset", 0)))

    gaps = []
    for g, spans in groups.items():
        covered = 0
        for start, end in sorted(spans):
            if start > covered:
                gaps.append((g, covered, start))
            covered = max(covered, end)
        want = expect.get(g, 0)
        if covered < want:
            gaps.append((g, covered, want))
    for g, want in expect.items():
        if g not in groups and want > 0:
            gaps.append((g, 0, want))
    return gaps


def run(s3, bucket, hosts, home, now=None):
    now = now or datetime.now(timezone.utc)
    state_path = os.path.join(home, "pull-state.json")
    state = load_state(state_path)
    objects, alerts, ignored = state["objects"], state["alerts"], state["ignored"]

    def ignore(key, why, level=4):
        if ignored.get(key) != why:
            log(f"받지 않음 {key}: {why}", level)
            ignored[key] = why

    # 1. hb 를 먼저 읽는다. 이 시각 이후 조각은 이번에 받지 않는다
    hbs, cutoff = {}, {}
    for host in sorted(hosts):
        hb, when = read_hb(s3, bucket, host)
        hbs[host] = hb
        cutoff[host] = when
        if when is None:
            log(f"경고: {host} 생존 신호 없음. 이 호스트 조각은 받지 않는다", 4)
        elif now - when > HB_STALE:
            log(f"경고: {host} 생존 신호가 {int((now - when).total_seconds() // 60)}분 전. 업로더가 멈췄을 수 있다", 4)

    got_n = got_b = waiting = 0
    for obj in list_raw(s3, bucket):
        key, size, etag = obj["Key"], obj["Size"], obj.get("ETag")

        known = objects.get(key)
        if known:
            if etag != known["etag"] and alerts.get(key) != etag:
                log(f"원장 변조 의심 {key}: ETag {known['etag']} → {etag}. 로컬 사본은 그대로 둔다", 2)
                alerts[key] = etag
            continue

        m = KEY_RE.match(key)
        if not m:
            ignore(key, "키 규칙 위반")
            continue
        sensor, host, ino, gen, start, end = m.groups()
        start, end = int(start), int(end)
        if host not in hosts:
            ignore(key, "허용 목록 밖 호스트")
            continue
        if end <= start or size != end - start or size > MAX_OBJ:
            ignore(key, f"크기 불일치 (구간 {end - start}, 객체 {size})", 3)
            continue
        if cutoff.get(host) is None or obj["LastModified"] > cutoff[host]:
            waiting += 1                    # 업로더 회차가 아직 끝나지 않았다
            continue

        meta, why = fetch(s3, bucket, key, size, home, sensor,
                          inbox_name(host, ino, gen, start, end))
        if meta is None:
            ignore(key, why, 3)
            continue
        meta["etag"] = etag
        objects[key] = meta
        ignored.pop(key, None)
        save_state(state_path, state)       # 받은 만큼은 바로 남긴다
        got_n += 1
        got_b += size

    save_state(state_path, state)

    gaps = coverage(objects, hbs)
    for (sensor, host, ino, gen), a, b in gaps:
        log(f"원장 구멍 {sensor} {host} ino={ino}.g{gen}: {a:,} ~ {b:,} B 없음", 3)
    log(f"받음 {got_n}개 {got_b:,} B · 대기 {waiting}개 · 보관 {len(objects)}개 · 구멍 {len(gaps)}")
    return EXIT_GAP if gaps else 0


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 원장 풀러")
    ap.parse_args()
    bucket = os.environ.get("OPSLOOP_BUCKET")
    hosts = {h.strip() for h in os.environ.get("OPSLOOP_HOSTS", "").split(",") if h.strip()}
    home = os.environ.get("OPSLOOP_HOME", "/var/lib/opsloop")
    if not bucket or not hosts:
        sys.exit("OPSLOOP_BUCKET 과 OPSLOOP_HOSTS 가 필요합니다")
    import boto3
    sys.exit(run(boto3.client("s3"), bucket, hosts, home))


if __name__ == "__main__":
    main()
