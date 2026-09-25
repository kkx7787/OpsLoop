#!/usr/bin/env bash
# ============================================================
#  자산 조사 수집 (이슈 #39). Mac 에서 돈다.
#
#  노드마다 cti/probe.py 를 돌려 설치 패키지 · 커널 · 컨테이너 이미지를 모으고, 한 묶음(JSON)으로 만들어
#  데이터 노드의 CTI 적재기(opsloop-cti load-assets)에 표준 입력으로 넘긴다. 노드에는 아무것도 설치하지 않는다.
#    VMware 노드  ssh <별칭> python3 - < probe.py (제한 시간 90초)
#    AWS 노드     SSM AWS-RunShellScript 에 probe.py 를 gzip · base64 로 실어 보내고 결과도 gzip · base64 로 받는다.
#                 SSM 표준 출력은 24,000자에서 잘린다. 거기에 닿으면 그 자산은 '출력 한도 초과' 오류로 보낸다
#  닿지 않는 노드(평소 꺼 둔 console-b 등)는 error 로 묶음에 넣는다. 적재기는 그 자산의 옛 조사 결과를 두고
#  시도 기록만 고친다. AWS 자격이 없으면 AWS 두 대는 묶음에 넣지 않는다(옛 결과가 남고 콘솔에 '정보 오래됨'으로 보인다).
#  허니팟 출력은 장악된 호스트의 비신뢰 데이터다. 여기서는 JSON 인지 · 크기 · 중첩 깊이 · UTF-8 로 쓸 수 있는지만 보고
#  (노드 하나가 묶음 전체를 깨지 못하게 그 자산에서 막는다), 형식 검증은 적재기가 한다. 묶음은 ASCII 로 쓴다.
#  노드가 정하는 글자(표준 오류 · hostname)는 제어 문자를 '?' 로 바꿔 요약 · 오류 문구에 넣는다.
#
#  사용 (저장소 루트)
#    infra/vmware/scripts/collect-assets.sh                    모아서 적재한다 (AWS 는 자격이 있을 때만)
#    infra/vmware/scripts/collect-assets.sh --dry-run          보내지 않는다. 묶음은 표준 출력, 요약은 표준 오류
#    infra/vmware/scripts/collect-assets.sh --only web-01,fw   일부 자산만
#    infra/vmware/scripts/collect-assets.sh --aws | --no-aws   AWS 두 대를 꼭 시도한다 | 건너뛴다
#  종료 코드: 0 모두 수집 · 적재 · 1 일부 자산 실패(적재는 됐다. 적재기가 일부 자산을 거른 때도) · 2 적재 실패 · 설정 오류
#  (--dry-run 은 수집 결과로만 0 · 1 을 낸다)
#
#  자동 실행: install-assets-agent.sh 가 launchd 에 올려 매일 05:10 에 돌린다. launchd 안에서는 AWS 로그인이
#  대개 만료돼 있어 AWS 두 대는 빠진다. 그 두 대는 aws login 뒤 손으로 돌린다:
#    infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws
#  필요: ~/.ssh/config.opsloop 의 별칭(web01 · fw · console-a · console-b · data01) · python3 · (AWS) aws CLI 로그인
# ============================================================
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REGION=${AWS_DEFAULT_REGION:-ap-northeast-2}
PROBE_TIMEOUT=${OPSLOOP_PROBE_TIMEOUT:-90}
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10)
LOAD_CMD='sudo -n -u opsloop-cti /usr/local/bin/opsloop-cti load-assets'
export AWS_PAGER=""   # aws CLI 가 터미널에서 less 를 띄워 멈추지 않게 한다

# 자산 표 (고정). asset_id · 역할 · 방법 · 접속(ssh 별칭, SSM 은 실행 중 인스턴스의 Name 태그)
ASSETS=(
  "web-01 target ssh web01"
  "fw platform ssh fw"
  "console-a platform ssh console-a"
  "console-b platform ssh console-b"
  "data-01 platform ssh data01"
  "gateway platform ssm opsloop-gateway"
  "honeypot-dmz sensor ssm opsloop-honeypot-dmz"
)

# 저장소에서 돌면 cti/probe.py, launchd 사본(install-assets-agent.sh 가 복사)이면 같은 폴더의 probe.py
if [ -f "$HERE/probe.py" ]; then PROBE=$HERE/probe.py; else PROBE=$HERE/../../../cti/probe.py; fi

# 파이썬 도우미 (표준 라이브러리만). macOS 에는 timeout(1)이 없어 제한 시간도 여기서 건다
#   timeout 초 명령…         넘으면 죽이고 124 로 끝난다
#   ssm-decode 접두           <접두>.ssm(get-command-invocation JSON)을 풀어 <접두>.out 에 쓴다. 실패면 <접두>.err
#   bundle 폴더 id:역할:방법…  묶음을 표준 출력에, 요약을 표준 오류에 쓴다. 실패 자산이 있으면 1
#   예상하지 못한 오류로 죽으면 셋 다 3 으로 끝난다 (잡지 못한 예외의 1 은 bundle 의 '일부 실패'와 겹친다)
IFS= read -r -d '' PY <<'EOF_PY' || true
import base64, binascii, gzip, json, os, re, subprocess, sys, zlib
from datetime import datetime, timezone

SSM_LIMIT = 24000              # get-command-invocation 표준 출력 상한(글자). 닿았으면 잘린 것이다
MAX_PROBE = 2 * 1024 * 1024    # 자산 하나의 조사 출력 상한. 일곱 대를 합쳐도 적재기 묶음 상한(16 MiB) 안이다
MAX_STDERR = 64 * 1024        # 노드 표준 오류는 앞부분만 남긴다(오류 문구에는 끝 세 줄만 쓴다)
MAX_ERROR = 500                # 적재기의 오류 문구 상한(512자) 안
MAX_DEPTH = 16                 # 조사 출력의 중첩 상한. probe.py 는 4단이다 (probe → kernel → installed → 항목)
# 노드가 정하는 글자를 터미널 · 기록에 찍기 전에 '?' 로 바꾼다 (C0 · DEL · C1). 적재기 safe() 와 같은 뜻이다
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def text(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def tail(path, n=3):
    lines = [x.strip() for x in text(path).splitlines() if x.strip()]
    return " / ".join(lines[-n:])


def clean(s):
    return CTRL.sub("?", s)


def clip(s):
    s = clean(" ".join(s.split()))
    return s if len(s) <= MAX_ERROR else s[:MAX_ERROR - 1] + "…"


def too_deep(v):
    """중첩이 MAX_DEPTH 단을 넘는가. 재귀 없이 잰다 (깊은 중첩은 다시 쓸 때 재귀 한도로 도우미를 죽인다)."""
    stack = [(v, 1)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, dict):
            x = list(x.values())
        if isinstance(x, list):
            if d > MAX_DEPTH:
                return True
            stack.extend((y, d + 1) for y in x)
    return False


def unsendable(probe):
    """묶음에 실을 수 없는 조사 출력이면 그 이유. 노드 하나의 출력이 묶음 전체를 깨지 못하게 그 자산에서 막는다."""
    if too_deep(probe):
        return "조사 출력의 중첩이 너무 깊다 (%d단 초과)" % MAX_DEPTH
    try:
        json.dumps(probe, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        # JSON 이스케이프 \ud800 · \udcff 는 json.loads 를 통과해 짝 없는 대리 문자가 된다
        return "조사 출력에 UTF-8 로 쓸 수 없는 문자가 있다 (짝 없는 대리 문자)"
    except (RecursionError, ValueError):
        return "조사 출력을 JSON 으로 다시 쓰지 못했다"
    return None


def count(v):
    return len(v) if isinstance(v, list) else 0


def cmd_timeout(sec, *cmd):
    try:
        return subprocess.run(cmd, timeout=float(sec)).returncode
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 127


def cmd_capture(sec, outpath, errpath, *cmd):
    """명령의 표준 출력 · 표준 오류를 상한까지만 파일로 받는다.

    장악된 노드(관제 대상 · 센서는 비신뢰다)가 python3 나 셸 초기화 파일을 바꿔 끝없이 흘려도 Mac 의 디스크 ·
    메모리를 먹지 못하게, 받는 도중에 자른다. 표준 출력이 MAX_PROBE 를 넘으면 명령을 끝내고 125 를 돌려준다.
    표준 오류는 MAX_STDERR 까지만 쓰고 나머지는 읽어서 버린다(파이프가 막혀 명령이 멈추지 않게).
    제한 시간을 넘으면 124, 실행하지 못하면 127. 표준 입력은 그대로 명령에 넘긴다(probe.py).
    """
    import threading
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return 127
    over = threading.Event()

    def pump(src, path, cap, flag):
        n = 0
        with open(path, "wb") as f:
            while True:
                chunk = src.read1(65536)
                if not chunk:
                    break
                if n < cap:
                    f.write(chunk[:cap - n])
                n += len(chunk)
                if flag is not None and n > cap:
                    flag.set()
                    proc.kill()
                    break
        src.close()

    workers = [threading.Thread(target=pump, args=(proc.stdout, outpath, MAX_PROBE, over), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, errpath, MAX_STDERR, None), daemon=True)]
    for w in workers:
        w.start()
    try:
        rc = proc.wait(timeout=float(sec))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        rc = 124
    for w in workers:
        w.join(5)
    return 125 if over.is_set() else rc


def cmd_ssm_decode(prefix):
    def fail(msg):
        with open(prefix + ".err", "w", encoding="utf-8", errors="replace") as f:
            f.write(msg)
        return 1
    try:
        inv = json.loads(text(prefix + ".ssm"))
    except ValueError:
        inv = None
    if not isinstance(inv, dict):
        return fail("SSM 결과를 읽지 못했다")
    # 노드가 정하는 글자다. 짝 없는 대리 문자가 와도 파일 쓰기에서 죽지 않게 바꿔 쓴다
    with open(prefix + ".stderr", "w", encoding="utf-8", errors="replace") as f:
        f.write(str(inv.get("StandardErrorContent") or ""))
    out = str(inv.get("StandardOutputContent") or "")
    if inv.get("Status") != "Success":
        return fail("SSM 명령 %s (종료 %s)" % (inv.get("Status"), inv.get("ResponseCode")))
    if len(out) >= SSM_LIMIT:
        return fail("출력 한도 초과 (SSM 표준 출력 %s자)" % format(SSM_LIMIT, ","))
    try:
        data = gzip.decompress(base64.b64decode("".join(out.split()), validate=True))
    except (binascii.Error, OSError, EOFError, zlib.error, ValueError):
        return fail("SSM 출력을 풀지 못했다 (base64 · gzip)")
    with open(prefix + ".out", "wb") as f:
        f.write(data)
    return 0


def cmd_bundle(tmp, *specs):
    assets, lines = [], []
    for spec in specs:
        aid, role, method = spec.split(":")
        p = os.path.join(tmp, aid)
        rec = {"asset_id": aid, "role": role, "method": method, "host": text(p + ".host").strip() or None}
        err = text(p + ".err").strip() if os.path.exists(p + ".err") else None
        probe = None
        if err is None:
            size = os.path.getsize(p + ".out") if os.path.exists(p + ".out") else 0
            if size > MAX_PROBE:
                err = "조사 출력이 너무 크다 (%s 바이트 · 상한 %s)" % (format(size, ","), format(MAX_PROBE, ","))
            else:
                try:
                    probe = json.loads(text(p + ".out"))
                except (ValueError, RecursionError):
                    probe = None
                if not isinstance(probe, dict) or "probe_version" not in probe:
                    err = "조사 출력이 JSON 이 아니다"
                else:
                    err = unsendable(probe)
        if err is not None:
            why = tail(p + ".stderr")
            rec["error"] = clip(err + ": " + why if why else err)
            lines.append("  %-13s 실패  %s" % (aid, rec["error"]))
        else:
            if method == "ssh" and isinstance(probe.get("hostname"), str):
                rec["host"] = probe["hostname"]
            rec["probe"] = probe
            # host 는 노드가 준 값 그대로 묶음에 싣는다(받을지는 적재기가 정한다). 요약에는 제어 문자를 바꿔 찍는다
            lines.append("  %-13s 수집  %s · 패키지 %d · 이미지 %d · 조사 오류 %d" % (
                aid, clip(str(rec["host"] or "-")), count(probe.get("packages")), count(probe.get("images")),
                count(probe.get("errors"))))
        assets.append(rec)
    # ASCII(ensure_ascii)로 쓴다. 로케일(launchd 는 LANG 이 없다)과 무관하게 같은 바이트가 나가고,
    # --dry-run 으로 터미널에 찍어도 노드가 넣은 제어 문자는 \uXXXX 로만 보인다
    body = json.dumps({"schema": "opsloop-assets/1", "collected_by": "collect-assets.sh",
                       "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "assets": assets}, separators=(",", ":")).encode("ascii")
    sys.stdout.buffer.write(body + b"\n")
    sys.stdout.flush()
    bad = sum(1 for a in assets if "error" in a)
    print("\n".join(lines), file=sys.stderr)
    print("수집 %d · 실패 %d · 묶음 %s 바이트" % (len(assets) - bad, bad, format(len(body), ",")), file=sys.stderr)
    return 1 if bad else 0


cmds = {"timeout": cmd_timeout, "capture": cmd_capture, "ssm-decode": cmd_ssm_decode, "bundle": cmd_bundle}
name = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    rc = cmds[name](*sys.argv[2:])
except Exception as e:  # 예상하지 못한 오류. 셸은 0 · 1 이 아니면 적재하지 않는다
    print("도우미 오류 (%s): %s: %s" % (name, type(e).__name__, clip(str(e))[:300]), file=sys.stderr)
    rc = 3
sys.exit(rc)
EOF_PY

helper() { python3 -c "$PY" "$@"; }

# 실패 이유를 남긴다. 세부(표준 오류 끝 세 줄)는 도우미가 <id>.stderr 에서 붙인다
fail() { printf '%s' "$2" > "$TMP/$1.err"; }

# VMware 노드: ssh 로 probe.py 를 표준 입력에 넘겨 돌린다
probe_ssh() {   # asset_id ssh별칭
  local rc=0
  # 출력은 도우미가 상한까지만 받는다 (장악된 노드가 끝없이 흘려도 Mac 의 디스크 · 메모리를 먹지 못한다)
  helper capture "$PROBE_TIMEOUT" "$TMP/$1.out" "$TMP/$1.stderr" "${SSH[@]}" "$2" python3 - < "$PROBE" || rc=$?
  case $rc in
    0) ;;
    124) fail "$1" "시간 초과 (${PROBE_TIMEOUT}초)" ;;
    125) fail "$1" "조사 출력이 너무 크다 (상한 2 MiB 를 넘어 받기를 멈췄다)" ;;
    255) fail "$1" "연결 실패" ;;
    *) fail "$1" "조사 실패 (종료 $rc)" ;;
  esac
}

# SSM 에 실을 명령. probe.py 를 gzip · base64 로 싣고, 출력도 gzip · base64 한 줄로 줄여 받는다
ssm_command() {
  printf 'echo %s | base64 -d | gunzip | python3 - | gzip -9 | base64 -w0' "$(gzip -9c < "$PROBE" | base64 | tr -d '\n')"
}

awsx() { helper timeout 120 aws --region "$REGION" "$@"; }

# AWS 노드: Name 태그로 실행 중 인스턴스를 찾아 SSM 으로 돌린다. host 는 인스턴스 ID
probe_ssm() {   # asset_id Name태그
  local id=$1 tag=$2 out cid ids=()
  if ! out=$(awsx ec2 describe-instances --filters "Name=tag:Name,Values=$tag" "Name=instance-state-name,Values=running" \
       --query 'Reservations[].Instances[].InstanceId' --output text 2> "$TMP/$id.stderr"); then
    fail "$id" "인스턴스 조회 실패"; return
  fi
  read -r -a ids <<< "$out" || true
  if [ "${#ids[@]}" -eq 0 ] || [ "${ids[0]}" = None ]; then
    fail "$id" "실행 중인 인스턴스가 없다 (Name=$tag)"; return
  elif [ "${#ids[@]}" -gt 1 ]; then
    fail "$id" "실행 중인 인스턴스가 여러 대다 (Name=$tag: ${ids[*]})"; return
  fi
  printf '%s' "${ids[0]}" > "$TMP/$id.host"
  if ! cid=$(awsx ssm send-command --instance-ids "${ids[0]}" --document-name AWS-RunShellScript --comment opsloop-assets \
       --parameters "commands=[\"$(ssm_command)\"]" --query Command.CommandId --output text 2> "$TMP/$id.stderr"); then
    fail "$id" "SSM 명령을 보내지 못했다"; return
  fi
  # 명령이 실패해도 이유는 결과에서 읽으므로 기다림(최대 100초)의 실패는 넘긴다
  awsx ssm wait command-executed --command-id "$cid" --instance-id "${ids[0]}" 2>/dev/null || true
  if ! awsx ssm get-command-invocation --command-id "$cid" --instance-id "${ids[0]}" --output json \
       > "$TMP/$id.ssm" 2> "$TMP/$id.stderr"; then
    fail "$id" "SSM 결과를 받지 못했다"; return
  fi
  helper ssm-decode "$TMP/$id" || true
}

DRY=0; ONLY=; ONLY_SET=0; AWS_MODE=auto
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) DRY=1 ;;
    --only) [ $# -ge 2 ] || { echo "--only 뒤에 자산 ID 를 쓴다" >&2; exit 2; }; ONLY=$2; ONLY_SET=1; shift ;;
    --only=*) ONLY=${1#--only=}; ONLY_SET=1 ;;
    --aws) AWS_MODE=on ;;
    --no-aws) AWS_MODE=off ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); if ($0 !~ /^=+$/) print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "모르는 옵션: $1 (--help 참고)" >&2; exit 2 ;;
  esac
  shift
done

command -v python3 >/dev/null 2>&1 || { echo "python3 이 없다" >&2; exit 2; }
[ -f "$PROBE" ] || { echo "조사 스크립트가 없다: $PROBE" >&2; exit 2; }

IDS=()
for a in "${ASSETS[@]}"; do IDS+=("${a%% *}"); done
if [ "$ONLY_SET" = 1 ]; then
  wants=()
  IFS=, read -r -a wants <<< "$ONLY" || true
  [ "${#wants[@]}" -gt 0 ] || { echo "--only 에 자산 ID 가 없다" >&2; exit 2; }
  for w in "${wants[@]}"; do
    known=0
    for i in "${IDS[@]}"; do if [ "$i" = "$w" ]; then known=1; fi; done
    [ "$known" = 1 ] || { echo "모르는 자산: '$w' (자산: ${IDS[*]})" >&2; exit 2; }
  done
fi

sel=(); need_aws=0
for a in "${ASSETS[@]}"; do
  read -r id role method conn <<< "$a"
  if [ "$ONLY_SET" = 1 ] && [[ ",$ONLY," != *",$id,"* ]]; then continue; fi
  sel+=("$a")
  if [ "$method" = ssm ]; then need_aws=1; fi
done

# AWS 두 대: --aws 면 꼭, 옵션이 없으면 자격이 있을 때만, --no-aws 면 건너뛴다
use_aws=0; aws_missing=0
if [ "$need_aws" = 1 ]; then
  if [ "$AWS_MODE" = off ]; then
    echo "AWS 노드(gateway · honeypot-dmz)는 건너뛴다 (--no-aws)" >&2
  elif command -v aws >/dev/null 2>&1 && helper timeout 30 aws --region "$REGION" sts get-caller-identity >/dev/null 2>&1; then
    use_aws=1
  else
    echo "AWS 자격이 없어 AWS 노드(gateway · honeypot-dmz)는 묶음에 넣지 않는다 (옛 결과가 남고 콘솔에 '정보 오래됨'으로 보인다)" >&2
    echo "  aws login 뒤 손으로 돌린다: infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws" >&2
    if [ "$AWS_MODE" = on ]; then aws_missing=1; fi
  fi
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/opsloop-assets.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

echo "== $(date '+%F %T %Z') 자산 조사" >&2
specs=()
for a in "${sel[@]}"; do
  read -r id role method conn <<< "$a"
  if [ "$method" = ssm ]; then
    [ "$use_aws" = 1 ] || continue
    probe_ssm "$id" "$conn"
  else
    probe_ssh "$id" "$conn"
  fi
  specs+=("$id:$role:$method")
done
[ "${#specs[@]}" -gt 0 ] || { echo "보낼 자산이 없다" >&2; exit 2; }

rc=0
helper bundle "$TMP" "${specs[@]}" > "$TMP/bundle.json" || rc=$?
case $rc in
  0|1) ;;
  *) echo "묶음을 만들지 못했다 (종료 $rc)" >&2; exit 2 ;;
esac
status=$rc
if [ "$aws_missing" = 1 ]; then status=1; fi

if [ "$DRY" = 1 ]; then
  cat "$TMP/bundle.json"
  echo "시험 실행: 적재기에 보내지 않았다" >&2
  exit "$status"
fi

# 적재기는 받은 자산의 배포판 취약점 대조(OSV)까지 하므로 제한 시간을 넉넉히(30분) 둔다.
# 적재기 종료 코드: 0 정상 · 1 일부 자산 형식 오류 · 대조 실패(적재는 됐다) · 2 적재 실패
lrc=0
helper timeout 1800 "${SSH[@]}" data01 "$LOAD_CMD" < "$TMP/bundle.json" 2> "$TMP/load.stderr" || lrc=$?
cat "$TMP/load.stderr" >&2
# sudo 가 거절해도 1 이라 적재기의 '일부 실패'와 겹친다. sudo 의 거절 문구로 가른다
if [ "$lrc" = 1 ] && grep -Eq '^sudo: .*(password is required|not allowed|not in the sudoers|unknown user|command not found)' "$TMP/load.stderr"; then
  echo "적재 실패 (data01 에서 sudo 가 거절했다: $LOAD_CMD)" >&2
  exit 2
fi
case $lrc in
  0) echo "적재: data01 opsloop-cti load-assets" >&2 ;;
  1) echo "적재는 됐다. 적재기가 일부 자산 형식 오류 · 배포판 대조 실패를 알렸다 (위 출력 참고)" >&2; status=1 ;;
  *) echo "적재 실패 (data01 opsloop-cti load-assets 종료 $lrc)" >&2; exit 2 ;;
esac
exit "$status"
