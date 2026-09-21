#!/usr/bin/env python3
"""허니팟 로그 업로더 (WBS 3.4).

센서는 원문 로그를 S3 에 올리기만 한다. 파싱 · 탐지는 내부망 데이터 노드가 가져가서 한다.
센서는 DB 주소도 비밀번호도 모른다.

동작
  - 대상 파일마다 inode 기준으로 "어디까지 올렸는지"를 기억한다.
    cowrie 는 자정에 파일 이름만 바꾸고 inode 는 유지하므로, 이름이 아니라 inode 로 기억해야
    회전 뒤에도 이어서 올린다.
  - 올린 위치 뒤의 바이트를 읽어 마지막 줄바꿈까지만 올린다. 반쪽 줄은 다음 회차로 미룬다.
  - 줄 내용은 절대 바꾸지 않는다 (인코딩 변환 · 공백 제거 · 압축 금지).
    내부의 중복 방지 기준(line_hash)이 원문 줄이기 때문이다.
  - PUT 이 성공했을 때만 위치를 옮긴다. 같은 조각이 두 번 올라가도 내부 적재는 한 번만 된다.

키 구조
  raw/v1/sensor=<cowrie|decoy>/host=<instance-id>/ino=<inode>/<시작 12자리>-<끝 12자리>.jsonl
  hb/v1/host=<instance-id>/latest.json      매 회차 덮어쓰는 생존 신호

환경변수
  OPSLOOP_BUCKET   S3 버킷
  OPSLOOP_HOST     키에 쓸 호스트 이름 (인스턴스 ID)
  OPSLOOP_STATE    상태 파일 (기본 /var/lib/opsloop-upload/state.json)
  SOURCES          "센서:글롭" 을 쉼표로 (기본 cowrie · decoy)
"""
import argparse
import glob
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_SOURCES = "cowrie:/opt/cowrie/log/cowrie.json*,decoy:/opt/decoy/log/decoy.json.*"
CHUNK = 8 * 1024 * 1024      # 한 번에 읽는 크기. 이보다 긴 한 줄은 통째로 올린다
HEAD = 256                   # inode 재사용을 가려내기 위한 파일 앞부분 크기
RUN_CAP = int(os.environ.get("OPSLOOP_RUN_CAP", 64 * 1024 * 1024))  # 파일당 한 회차 상한

# 로그 폴더에 공격자가 다른 이름의 파일이나 링크를 만들어도 올리지 않는다
NAME_RULE = {
    "cowrie": re.compile(r"^cowrie\.json(\.\d{4}-\d{2}-\d{2})?$"),
    "decoy": re.compile(r"^decoy\.json\.\d{4}-\d{2}-\d{2}$"),
}


def log(msg):
    print(f"[{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}] {msg}", flush=True)


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(path, state):
    # 임시 파일에 쓴 뒤 바꿔 넣는다. 중간에 죽어도 상태 파일이 반쪽이 되지 않는다.
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def head_digest(fh, n):
    """파일 앞 n 바이트의 해시. 같은 inode 를 다른 파일이 재사용했는지 가려내는 데 쓴다."""
    fh.seek(0)
    return hashlib.sha256(fh.read(n)).hexdigest()


def sources(spec):
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        sensor, pattern = item.split(":", 1)
        sensor = sensor.strip()
        rule = NAME_RULE.get(sensor)
        for path in sorted(glob.glob(pattern)):
            if rule and not rule.match(os.path.basename(path)):
                continue
            yield sensor, path


def open_regular(path):
    """심볼릭 링크를 따라가지 않고, 일반 파일일 때만 연다."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise ValueError("일반 파일이 아님")
    return os.fdopen(fd, "rb"), st


def put_once(s3, bucket, key, body, metadata):
    """같은 키가 이미 있으면 쓰지 않는다 (If-None-Match: *). 이미 있으면 False.

    원장은 한 번만 쓴다. 버킷 정책도 이 조건이 없는 쓰기를 거부한다.
    PUT 은 성공했는데 상태 저장 전에 죽은 경우, 다음 회차에 같은 키가 이미 있으므로
    그대로 넘어가면 된다 (키에 파일 세대가 들어가므로 다른 내용과 겹치지 않는다).
    """
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=body,
                      ContentType="application/x-ndjson",
                      ChecksumAlgorithm="SHA256", Metadata=metadata)
        return True
    except Exception as e:  # botocore.exceptions.ClientError
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        if code in ("PreconditionFailed", "412"):
            return False
        raise


def upload_file(s3, bucket, host, sensor, path, state, dry_run):
    """한 파일의 새 부분을 올린다.

    (올린 바이트 수, 실제로 연 파일의 inode, 연 시점 크기, 회차 상한에 걸려 덜 올렸는지) 를 돌려준다.
    """
    fh, st = open_regular(path)
    ino = str(st.st_ino)
    total = 0
    with fh:
        if st.st_size == 0:
            return 0, ino, 0, False
        prev = state.get(ino)
        ent = prev
        if prev is not None:
            # 기록할 때와 같은 길이로 다시 해시해 비교한다. 다르면 같은 번호를 다른 파일이 재사용한 것
            n = min(prev.get("head_len", 0), st.st_size)
            if n and head_digest(fh, n) != prev.get("head"):
                log(f"inode {ino} 재사용 감지 ({prev.get('name')} → {os.path.basename(path)}). 새 세대로 처음부터 올린다")
                ent = {"offset": 0, "gen": prev.get("gen", 0) + 1}
        if ent is None:
            ent = {"offset": 0, "gen": 0}
        offset = ent.get("offset", 0)
        if st.st_size < offset:
            # 같은 파일이 줄었다. 앞 세대와 키가 겹치지 않게 세대를 올린다
            log(f"경고: {path} 가 줄었다 ({offset} → {st.st_size}). 새 세대로 처음부터 올린다")
            offset = 0
            ent["gen"] = ent.get("gen", 0) + 1
        # 앞부분은 최대 HEAD 바이트까지 기록한다. 파일이 자라면 더 긴 앞부분으로 갱신된다
        n = min(HEAD, st.st_size)
        ent.update({"sensor": sensor, "name": os.path.basename(path),
                    "head": head_digest(fh, n), "head_len": n})
        gen = ent.get("gen", 0)

        budget = RUN_CAP
        while offset < st.st_size and budget > 0:
            fh.seek(offset)
            buf = fh.read(min(CHUNK, st.st_size - offset))
            cut = buf.rfind(b"\n")
            if cut < 0:
                if offset + len(buf) >= st.st_size:
                    break                  # 파일 끝까지 봤는데 줄바꿈이 없다 = 쓰는 중인 반쪽 줄
                # CHUNK 보다 긴 한 줄이다. 줄을 쪼개면 내부의 line_hash 가 달라지므로
                # 줄바꿈이 나올 때까지 더 읽어 통째로 올린다
                more = bytearray(buf)
                while True:
                    part = fh.read(CHUNK)
                    if not part:
                        break
                    k = part.find(b"\n")
                    if k >= 0:
                        more += part[: k + 1]
                        break
                    more += part
                if not more.endswith(b"\n"):
                    break                  # 긴 줄이 아직 쓰이는 중이다. 다음 회차로
                log(f"경고: {path} 에 {len(more):,} B 짜리 한 줄. 통째로 올린다")
                body = bytes(more)
            else:
                body = buf[: cut + 1]
            end = offset + len(body)
            key = (f"raw/v1/sensor={sensor}/host={host}/ino={ino}.g{gen}/"
                   f"{offset:012d}-{end:012d}.jsonl")
            lines = body.count(b"\n")
            if dry_run:
                log(f"[dry-run] {key}  {len(body):,} B · {lines:,} 줄")
            else:
                fresh = put_once(s3, bucket, key, body, {"lines": str(lines), "src": ent["name"]})
                log(("올림 " if fresh else "이미 있음 ") + f"{key}  {len(body):,} B · {lines:,} 줄")
            total += len(body)
            budget -= len(body)
            offset = end
            ent["offset"] = offset
            if not dry_run:
                state[ino] = ent
        capped = budget <= 0 and offset < st.st_size
        if capped:
            log(f"경고: {path} 이번 회차 상한 {RUN_CAP:,} B 도달. 나머지는 다음 회차로")
    if not dry_run:
        state[ino] = ent
    return total, ino, st.st_size, capped


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 센서 로그 업로더")
    ap.add_argument("--dry-run", action="store_true", help="올리지 않고 올릴 목록만 출력")
    args = ap.parse_args()

    if os.geteuid() == 0 and not args.dry_run:
        # root 로 돌리면 상태 파일이 root 소유가 되어 서비스가 매 회차 실패한다
        sys.exit("root 로 실행하지 마세요. systemctl start opsloop-upload.service 로 실행합니다")

    bucket = os.environ.get("OPSLOOP_BUCKET")
    host = os.environ.get("OPSLOOP_HOST")
    state_path = os.environ.get("OPSLOOP_STATE", "/var/lib/opsloop-upload/state.json")
    spec = os.environ.get("SOURCES", DEFAULT_SOURCES)
    if not bucket or not host:
        sys.exit("OPSLOOP_BUCKET 과 OPSLOOP_HOST 가 필요합니다")

    s3 = None
    if not args.dry_run:
        import boto3
        s3 = boto3.client("s3")

        def if_none_match(request, **_):
            # 원장 객체만 한 번 쓰기. 생존 신호(hb/)는 매 회차 덮어쓴다.
            # 가상 호스트 방식(/raw/v1/...)과 경로 방식(/버킷/raw/v1/...) 모두 경로에 이 문자열이 들어간다
            if "/raw/v1/" in urlparse(request.url).path:
                request.headers["If-None-Match"] = "*"
        s3.meta.events.register("before-sign.s3.PutObject", if_none_match)

    state = load_state(state_path)
    grand = 0
    files = {}
    done = {}            # 이름 → 이번 회차에 실제로 연 inode
    incomplete = []      # 이번 회차가 "끝난 회차"가 아닌 이유
    for sensor, path in sources(spec):
        try:
            n, ino, size, capped = upload_file(s3, bucket, host, sensor, path, state, args.dry_run)
        except Exception as e:           # 한 파일 실패가 나머지를 막지 않게 한다
            log(f"실패 {path}: {e}")
            incomplete.append(f"실패 {os.path.basename(path)}")
            continue
        finally:
            if not args.dry_run:
                save_state(state_path, state)   # 성공한 만큼은 바로 남긴다
        grand += n
        done[os.path.basename(path)] = ino
        if capped:
            # 덜 올린 파일이 있으면 이번 회차는 한 시점의 모습이 아니다 (회전 파일 꼬리가 밀린 채 새 파일만 올라갈 수 있다)
            incomplete.append(f"상한 {os.path.basename(path)}")
        ent = state.get(ino, {})
        files[os.path.basename(path)] = {"sensor": sensor, "ino": ino,
                                         "gen": ent.get("gen", 0), "size": size,
                                         "offset": ent.get("offset", 0)}

    # 도는 사이에 회전이 끼어들었는지 본다. 이름이 새로 생겼거나 같은 이름이 다른 파일을 가리키면
    # 이번에 올린 것이 한 시점의 모습이 아니다 (회전된 파일의 꼬리를 못 올렸을 수 있다)
    for sensor, path in sources(spec):
        name = os.path.basename(path)
        try:
            ino = str(os.stat(path, follow_symlinks=False).st_ino)
        except FileNotFoundError:
            continue
        if done.get(name) != ino and f"실패 {name}" not in incomplete:
            incomplete.append(f"회전 {name}")

    if not args.dry_run:
        if incomplete:
            # 생존 신호는 "여기까지 끝났다"는 표시다. 끝나지 않은 회차에는 쓰지 않는다.
            # 풀러는 지난 신호 이후 조각을 받지 않고 기다린다. 계속되면 풀러 쪽에서 신호 멈춤으로 드러난다
            log(f"경고: 이번 회차가 끝나지 않아 생존 신호를 쓰지 않는다 ({', '.join(incomplete)})")
        else:
            hb = {"ts": datetime.now(timezone.utc).isoformat(), "host": host, "files": files}
            s3.put_object(Bucket=bucket, Key=f"hb/v1/host={host}/latest.json",
                          Body=json.dumps(hb, ensure_ascii=False).encode(),
                          ContentType="application/json")
    log(f"완료 · 이번 회차 {grand:,} B")


if __name__ == "__main__":
    main()
