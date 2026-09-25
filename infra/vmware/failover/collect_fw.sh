#!/usr/bin/env bash
# ============================================================
#  HAProxy 백엔드 상태 수집 (이슈 #43 장애 주입 시험). Mac 에서 돈다. 방화벽에서는 읽기만 한다.
#
#  ssh fw 연결 하나 안에서 0.5초마다 `date +%s.%N` 과 통계 CSV(curl -s 'http://127.0.0.1:8404/;csv')를 읽어
#  consoles 백엔드 행(서버 둘 · BACKEND)만 <회차 폴더>/fw.csv 에 덧붙인다. 방화벽 시각과 Mac 이 받은 시각을 함께 적는다.
#    t_local,t_fw,svname,status,bck,chkfail,chkdown,lastchg,check_status,check_duration,scur
#    (통계를 읽지 못한 회차는 svname '-' · status stats_error 한 줄)
#  summarize.py 는 min(t_local − t_fw) 로 방화벽 시계를 Mac 시계에 맞춘다(fw-meta.json 의 clock_offset_ms).
#  끝나면(--duration · Ctrl-C) /var/log/haproxy.log 에서 시험 동안 붙은 부분만 fw-haproxy.log 로 가져온다(읽기).
#  시작 때 로그 크기를 적어 두고 그 뒤를 읽는다. 그 사이 로그가 돌려졌으면(자정 logrotate) 옛 파일 <로그>.1 의 그 뒤와
#  새 파일 전부를 이어 가져온다(.1 이 없거나 압축됐으면 새 파일만, 경고 줄을 남긴다).
#  원격 루프는 ssh 가 끊기면 멈추고, 끊김을 놓쳐도 --duration + 120초(0 이면 6시간) 뒤 스스로 끝난다.
#
#  사용 (저장소 루트)
#    infra/vmware/failover/collect_fw.sh ~/opsloop-failover/r01-stop-a --duration 300
#    infra/vmware/failover/collect_fw.sh <회차 폴더>              Ctrl-C 까지
#    --period 0.5 · --host fw · --log /var/log/haproxy.log · --no-log(발췌 안 함)
#  종료 코드: 0 · 1 발췌 실패(fw.csv 는 있다) · 2 수집 실패 · 설정 오류
#  필요: ~/.ssh/config.opsloop 의 fw 별칭 · python3 · (fw) curl · 통계 bind 127.0.0.1:8404
# ============================================================
set -euo pipefail
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10
     -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
HOST=fw
PERIOD=0.5
DURATION=600
LOG=/var/log/haproxy.log
FETCH_LOG=1
MAXLOG=$((64 * 1024 * 1024))

usage() { sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "오류: $*" >&2; exit 2; }

DIR=
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION=${2:?--duration 초}; shift 2 ;;
    --period) PERIOD=${2:?--period 초}; shift 2 ;;
    --host) HOST=${2:?--host 별칭}; shift 2 ;;
    --log) LOG=${2:?--log 경로}; shift 2 ;;
    --no-log) FETCH_LOG=0; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "모르는 옵션: $1" ;;
    *) [ -z "$DIR" ] || die "회차 폴더는 하나만"; DIR=$1; shift ;;
  esac
done
[ -n "$DIR" ] || { usage >&2; exit 2; }
echo "$DURATION" | grep -Eq '^[0-9]+(\.[0-9]+)?$' || die "--duration 은 0 이상의 수"
echo "$PERIOD" | grep -Eq '^[0-9]+(\.[0-9]+)?$' && awk -v p="$PERIOD" 'BEGIN { exit !(p > 0) }' \
  || die "--period 는 0 보다 큰 수"
echo "$HOST" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_.-]*$' || die "--host 가 이상하다"
echo "$LOG" | grep -Eq '^/[A-Za-z0-9_./-]+$' || die "--log 는 절대 경로 (글자 · 숫자 · _ . - /)"
mkdir -p "$DIR"
OUT="$DIR/fw.csv"
META="$DIR/fw-meta.json"
# 원격 루프의 수명 상한(초). ssh 끊김을 놓쳐도 방화벽에 남지 않게 한다
MAXS=$(awk -v d="$DURATION" 'BEGIN { if (d > 0) printf "%d", d + 120; else print 21600 }')

# 원격(방화벽) 루프. 함수 하나로 감싸 bash 가 다 읽은 뒤 돌게 한다(표준 입력으로 받는다)
#   S <방화벽 시각> <로그 크기> <로그 inode>   첫 줄 (inode 로 시험 중 로그가 돌려졌는지 안다)
#   D,<방화벽 시각>,<consoles 행 9칸>    회차마다 서버 행
#   E <방화벽 시각>                      통계를 읽지 못한 회차
IFS= read -r -d '' REMOTE <<'EOF_REMOTE' || true
main() {
  local F=$1 P=$2 MAXS=$3 start next t csv size ino
  size=$(stat -c %s "$F" 2>/dev/null || sudo -n stat -c %s "$F" 2>/dev/null || echo -1)
  ino=$(stat -c %i "$F" 2>/dev/null || sudo -n stat -c %i "$F" 2>/dev/null || echo -1)
  printf 'S %s %s %s\n' "$(date +%s.%N)" "$size" "$ino" || exit 0
  start=$(date +%s)
  next=$(date +%s.%N)
  while :; do
    [ $(( $(date +%s) - start )) -lt "$MAXS" ] || exit 0
    t=$(date +%s.%N)
    csv=$(curl -s -m 2 'http://127.0.0.1:8404/;csv' </dev/null) || csv=
    if [ -z "$csv" ]; then
      printf 'E %s\n' "$t" || exit 0
    else
      printf '%s\n' "$csv" | awk -F, -v t="$t" '
        function f(k) { return (k in c) ? $(c[k]) : "" }
        NR == 1 { sub(/^# */, ""); for (i = 1; i <= NF; i++) c[$i] = i; next }
        $1 == "consoles" {
          printf "D,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", t, f("svname"), f("status"), f("bck"), f("chkfail"),
                 f("chkdown"), f("lastchg"), f("check_status"), f("check_duration"), f("scur")
        }' || exit 0
    fi
    # 다음 회차까지 남은 시간만 잔다(밀렸으면 바로)
    set -- $(awk -v n="$next" -v p="$P" -v now="$(date +%s.%N)" \
      'BEGIN { n += p; if (n < now) n = now; printf "%.6f %.3f\n", n, n - now }')
    next=$1
    sleep "$2"
  done
}
main "$@"
EOF_REMOTE

# Mac 쪽: ssh 출력을 받아 Mac 시각을 붙여 CSV 로 쓴다. --duration · Ctrl-C 에 ssh 를 끝낸다
IFS= read -r -d '' PY <<'EOF_PY' || true
import csv, json, os, re, select, signal, subprocess, sys, time
out, meta_path, duration, host, log, period = sys.argv[1:7]
argv = sys.argv[7:]
duration = float(duration)
FIELDS = ["t_local", "t_fw", "svname", "status", "bck", "chkfail", "chkdown", "lastchg",
          "check_status", "check_duration", "scur"]
CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f,]")
TS = re.compile(r"^\d{9,11}(\.\d{1,9})?$")
new = not os.path.exists(out) or os.path.getsize(out) == 0
f = open(out, "a", newline="")
w = csv.writer(f)
if new:
    w.writerow(FIELDS)
meta = {"host": host, "log": log, "period": float(period), "t_local_start": None, "t_fw_start": None,
        "log_offset": None, "log_inode": None, "samples": 0, "stats_errors": 0, "t_local_end": None, "clock_offset_ms": None}
best = [None]
last = {}


def save_meta():
    tmp = meta_path + ".tmp"
    with open(tmp, "w") as m:
        json.dump(meta, m, ensure_ascii=False, indent=2)
    os.replace(tmp, meta_path)


def handle(line, t_local):
    if line.startswith("S "):
        parts = line.split()
        if len(parts) in (3, 4) and TS.match(parts[1]):
            meta["t_fw_start"], meta["t_local_start"] = parts[1], "%.6f" % t_local
            meta["log_offset"] = int(parts[2]) if re.match(r"^-?\d+$", parts[2]) else -1
            meta["log_inode"] = int(parts[3]) if len(parts) == 4 and re.match(r"^\d+$", parts[3]) else -1
            save_meta()
        return
    if line.startswith("E "):
        t_fw = line[2:].strip()
        if TS.match(t_fw):
            w.writerow(["%.6f" % t_local, t_fw, "-", "stats_error"] + [""] * 7)
            meta["stats_errors"] += 1
        return
    if line.startswith("D,"):
        parts = line.split(",")
        if len(parts) != 11 or not TS.match(parts[1]):
            return
        vals = [CTRL.sub("?", x)[:64] for x in parts[2:]]
        w.writerow(["%.6f" % t_local, parts[1]] + vals)
        meta["samples"] += 1
        d = t_local - float(parts[1])
        if best[0] is None or d < best[0]:
            best[0] = d
        if last.get(vals[0]) != vals[1]:
            print("  %s %s → %s" % (time.strftime("%H:%M:%S"), vals[0], vals[1]), file=sys.stderr)
            last[vals[0]] = vals[1]


def _interrupt(_signum, _frame):
    raise KeyboardInterrupt


# Ctrl-C · kill(SIGTERM) 모두 정리하고 끝낸다(백그라운드로 띄우면 SIGINT 가 무시된 채 온다)
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, _interrupt)
p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
try:
    p.stdin.write(os.environ["FW_REMOTE"].encode())
    p.stdin.close()
except (BrokenPipeError, KeyboardInterrupt):
    pass
deadline = time.monotonic() + duration if duration > 0 else None
stopped = None
fd = p.stdout.fileno()
buf = b""
code = 0
try:
    while True:
        wait = 0.5
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                stopped = "시간"
                break
            wait = min(wait, left)
        ready, _, _ = select.select([fd], [], [], wait)
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        now = time.time()
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            handle(line.decode("utf-8", "replace").strip(), now)
        f.flush()
except KeyboardInterrupt:
    stopped = "Ctrl-C"
finally:
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()
    f.close()
    meta["t_local_end"] = "%.6f" % time.time()
    if best[0] is not None:
        meta["clock_offset_ms"] = round(best[0] * 1000, 3)
    save_meta()
if meta["t_fw_start"] is None:
    print("수집 실패: %s 에서 첫 줄을 받지 못했다 (ssh 종료 %s)" % (host, p.returncode), file=sys.stderr)
    sys.exit(2)
if stopped is None:
    print("경고: %s 연결이 먼저 끝났다 (ssh 종료 %s). 그 뒤는 수집되지 않았다" % (host, p.returncode), file=sys.stderr)
print("수집: 서버 행 %d · 통계 실패 %d → %s" % (meta["samples"], meta["stats_errors"], out), file=sys.stderr)
EOF_PY

echo "HAProxy 상태 수집: $HOST · ${PERIOD}초 · $( [ "$DURATION" = 0 ] && echo 'Ctrl-C 까지' || echo "${DURATION}초" ) → $OUT" >&2
# Ctrl-C 는 수집기(python)가 받아 정리한다. 셸은 기다렸다가 발췌로 넘어간다
trap ':' INT
rc=0
FW_REMOTE=$REMOTE python3 -c "$PY" "$OUT" "$META" "$DURATION" "$HOST" "$LOG" "$PERIOD" \
  "${SSH[@]}" "$HOST" "bash -s -- '$LOG' '$PERIOD' '$MAXS'" || rc=$?
trap - INT
[ "$rc" = 0 ] || exit 2
[ "$FETCH_LOG" = 1 ] || exit 0

OFF=$(sed -n 's/.*"log_offset": *\(-\{0,1\}[0-9][0-9]*\).*/\1/p' "$META" | head -1)
INO=$(sed -n 's/.*"log_inode": *\(-\{0,1\}[0-9][0-9]*\).*/\1/p' "$META" | head -1)
INO=${INO:--1}
if [ -z "$OFF" ] || [ "$OFF" -lt 0 ]; then
  echo "경고: 시작 때 $LOG 크기를 읽지 못해 발췌하지 않는다" >&2
  exit 1
fi
# 시험 동안 붙은 부분만 읽는다. 읽기 권한이 없으면 sudo -n 으로 읽는다(읽기뿐). 둘 다 안 되면 원격 종료 3.
# 원격은 tail 의 종료 코드를 그대로 돌려주고(exec), 크기 상한은 Mac 쪽 head 가 건다(pipefail 로 ssh 실패를 본다)
EXCERPT="f='$LOG'; o=$OFF; i0=$INO
if [ -r \"\$f\" ]; then R=; elif sudo -n test -r \"\$f\" 2>/dev/null; then R='sudo -n'; else echo \"읽을 수 없다: \$f\" >&2; exit 3; fi
n=\$(\$R stat -c %s \"\$f\") || exit 3
i=\$(\$R stat -c %i \"\$f\") || exit 3
# 돌려졌는가: inode 가 바뀌었거나(시작 때 inode 를 알 때) 크기가 줄었다
if { [ \"\$i0\" -ge 0 ] && [ \"\$i\" != \"\$i0\" ]; } || [ \"\$n\" -lt \"\$o\" ]; then
  if \$R test -r \"\$f.1\" && { [ \"\$i0\" -lt 0 ] || [ \"\$(\$R stat -c %i \"\$f.1\")\" = \"\$i0\" ]; }; then
    echo '# 시험 중 로그가 돌려졌다. 옛 파일(.1)의 뒷부분과 새 파일 전부'; \$R tail -c +\$((o + 1)) \"\$f.1\" || exit 3
  else echo '# 시험 중 로그가 돌려졌다. 옛 파일(.1)을 읽지 못해 새 파일 처음부터'; fi
  o=0
fi
exec \$R tail -c +\$((o + 1)) \"\$f\""
PART="$DIR/fw-haproxy.log.part"
if "${SSH[@]}" "$HOST" "$EXCERPT" < /dev/null | head -c "$MAXLOG" > "$PART" \
   || [ "$(wc -c < "$PART" | tr -d ' ')" -ge "$MAXLOG" ]; then
  mv "$PART" "$DIR/fw-haproxy.log"
  echo "로그 발췌: $(wc -l < "$DIR/fw-haproxy.log" | tr -d ' ')줄 → $DIR/fw-haproxy.log" >&2
else
  rm -f "$PART"
  echo "경고: $HOST 의 $LOG 를 읽지 못했다 (fw.csv 는 있다)" >&2
  exit 1
fi
