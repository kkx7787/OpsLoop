#!/usr/bin/env bash
# 내부 DB 를 Mac 으로 백업한다.
# 판정 · 조치 · 차단 기록은 원문 로그에서 다시 만들 수 없고, 4대가 같은 기본 VM 의 연결 복제라
# 기본 VM 이 깨지면 함께 잃는다. 그래서 사본은 VM 밖(Mac)에 둔다.
# 관리망 ssh 로 Mac 이 안쪽에서 끌어온다. 안쪽 노드가 밖으로 쓰는 경로는 만들지 않는다.
#
# 관제 대상 로그의 원장(Loki)과 수집 관문 원장도 같은 폴더의 ledger/ 로 받는다 (LEDGER=0 이면 건너뛴다).
# 역할 · 역할 속성 · 멤버십(클러스터 전역 객체)은 pg_dump 에 들지 않으므로 같은 시각의 opsloop-<시각>.globals.sql 로 함께 받는다
#   (이슈 #45). 비밀번호는 빼고 받는다(--no-role-passwords). 새 서버에 복원할 때 역할을 이 파일대로 만든 뒤 비밀번호를 새로 준다.
# 허니팟 원장은 S3(버저닝 · 삭제 금지)에 있으므로 받지 않는다.
#
# 덤프 전 시계 확인 (이슈 #91). 덤프 머리의 Archive created(복구 지점 T_b)는 data01 시계다. Mac 잠자기 뒤 VM 시계가 뛰면
#   덤프 시각과 보관 간격이 실제와 어긋나 간격 초과가 가려진다. 그래서 받기 전에 Mac 과 data01 의 시계 차이를 잰다
#   (ssh 앞뒤 Mac 시각의 가운데와 data01 의 date 를 견준다). 잰 차이는 기록에 한 줄 남긴다.
#   2초 넘게 다르면 data01 의 chrony 가 맞출 때까지 기다린 뒤(chronyc waitsync, 5초 간격 최대 12번) 다시 잰다.
#   그래도 2초를 넘으면 실패로 끝낸다(backup-agent.sh 가 다시 돈다). chronyc 를 쓸 수 없으면 기다리지 않고 차이로만 판단한다.
#   data01 에는 쓰지 않는다(date · chronyc waitsync 는 읽기만 한다).
#
# 사용: infra/vmware/scripts/backup-db.sh [보관 폴더]      기본 ~/opsloop-backup, 최근 21개 보관
#       VERIFY=restore infra/vmware/scripts/backup-db.sh   받은 덤프를 임시 DB 에 실제로 복원해
#                                                          운영 DB 와 건수를 대조한다
# 복원 시험이 실패하면 덤프를 .unverified 로 남기고 실패로 끝난다 (보관 개수 정리도 하지 않는다).
# 자동 실행: install-backup-agent.sh 가 launchd 에 올려 매일 04:30 · 12:30 · 20:30 에 복원 시험까지 돌린다
#   (실패하면 backup-agent.sh 가 제한된 횟수로 다시 돈다).
set -euo pipefail
DEST=${1:-$HOME/opsloop-backup}
KEEP=${KEEP:-21}
# 끊긴 연결에 매달리지 않게 15초마다 살아 있는지 묻고, 4번 답이 없으면(약 1분) 끊는다
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4 data01)
TESTDB=opsloop_restore_test
CLOCK_MAX_MS=2000

# Mac 시각(밀리초). Mac 의 date 는 %N(나노초)을 안다. 모르는 판이면 초 단위로 잰다
now_ms() {
  local ns
  ns=$(date +%s%N)
  case "$ns" in
    '' | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
    *) echo $((ns / 1000000)) ;;
  esac
}

# data01 − Mac 시계 차이를 CLOCK_OFF 에, 잰 동안의 왕복을 CLOCK_RTT 에 둔다 (밀리초)
clock_measure() {
  local a b r
  a=$(now_ms)
  r=$("${SSH[@]}" 'date +%s%N') || { echo "data01 시각을 읽지 못했습니다" >&2; return 1; }
  b=$(now_ms)
  case "$r" in '' | *[!0-9]*) echo "data01 시각을 읽지 못했습니다: ${r:0:40}" >&2; return 1 ;; esac
  CLOCK_OFF=$((r / 1000000 - (a + b) / 2))
  CLOCK_RTT=$((b - a))
}

# 밀리초 → 부호 있는 초 (소수 셋째 자리)
fmt_s() {
  local v=$1 s=+
  if [ "$v" -lt 0 ]; then s=-; v=$((-v)); fi
  printf '%s%d.%03d' "$s" $((v / 1000)) $((v % 1000))
}

clock_ok() { [ "$CLOCK_OFF" -le "$CLOCK_MAX_MS" ] && [ "$CLOCK_OFF" -ge "-$CLOCK_MAX_MS" ]; }

clock_line() {  # $1 머리말. 기록에 남기는 한 줄
  local rtt
  rtt=$(fmt_s "$CLOCK_RTT")
  echo "$1 (data01 − Mac) $(fmt_s "$CLOCK_OFF")초 · 잰 왕복 ${rtt#+}초"
}

mkdir -p "$DEST"
chmod 700 "$DEST"

drop_testdb() {
  "${SSH[@]}" "sudo -n docker exec opsloop-db dropdb -U opsloop --if-exists $TESTDB" >/dev/null 2>&1
}
# 지난 실행이 중간에 끊겨 남긴 시험 DB 가 있으면 먼저 치운다. 시계 확인에서 실패로 끝나도 남기지 않게 그 앞에서 한다
drop_testdb || true

clock_measure
clock_line "시계 차이"
if ! clock_ok; then
  # 남은 보정이 0.5초 아래가 될 때까지 5초 간격 최대 12번(약 1분) 기다린다. 시간이 다 되면 그대로 다시 잰다
  sync_rc=0
  sync_out=$("${SSH[@]}" 'command -v chronyc >/dev/null 2>&1 || exit 127; chronyc waitsync 12 0.5 0 5' 2>&1) || sync_rc=$?
  if [ "$sync_rc" = 127 ]; then
    echo "시계 차이가 2초를 넘는데 data01 에서 chronyc 를 쓸 수 없습니다. 덤프하지 않습니다" >&2
    exit 1
  fi
  echo "chrony 동기 기다림 (종료 $sync_rc) $(printf '%s\n' "$sync_out" | tail -n 1)"
  clock_measure
  clock_line "시계 차이 다시 잼"
  if ! clock_ok; then
    echo "시계 차이가 2초를 넘습니다 ($(fmt_s "$CLOCK_OFF")초). 덤프하지 않습니다" >&2
    exit 1
  fi
fi

ts=$(date -u +%Y%m%d-%H%M)
part="$DEST/.opsloop-$ts.dump.part"
out="$DEST/opsloop-$ts.dump"
gpart="$DEST/.opsloop-$ts.globals.sql.part"
gout="$DEST/opsloop-$ts.globals.sql"
cleanup() {
  rm -f "$part" "$gpart"
  # 복원 시험 DB 에는 판정 · 계정까지 들어 있다. 실패해도 운영 컨테이너에 남기지 않는다
  if [ "${VERIFY:-}" = restore ] && ! drop_testdb; then
    echo "경고: 시험 DB $TESTDB 가 운영 컨테이너에 남았을 수 있다. 다음 실행 때 다시 지운다" >&2
  fi
}
trap cleanup EXIT

"${SSH[@]}" 'sudo -n docker exec opsloop-db pg_dump -U opsloop_backup -Fc opsloop' > "$part"

# 받은 파일이 온전한 덤프인지 DB 컨테이너의 pg_restore 로 목차를 읽어 본다
tables=$("${SSH[@]}" 'sudo -n docker exec -i opsloop-db pg_restore --list' < "$part" | grep -c 'TABLE DATA' || true)
[ "$tables" -gt 0 ] || { echo "덤프 목차를 읽지 못했습니다" >&2; exit 1; }

# 역할 목록. 백업 역할(pg_read_all_data)로 비밀번호 없이 받는다. 덤프에 GRANT 가 걸린 역할이 모두 있어야 한다
"${SSH[@]}" 'sudo -n docker exec opsloop-db pg_dumpall -U opsloop_backup --globals-only --no-role-passwords' > "$gpart"
roles=$(grep -c '^CREATE ROLE ' "$gpart" || true)
for r in opsloop opsloop_gate opsloop_ingest opsloop_detector opsloop_console opsloop_backup opsloop_cti opsloop_enforcer; do
  grep -qx "CREATE ROLE $r;" "$gpart" || { echo "역할 목록에 $r 이 없습니다" >&2; exit 1; }
done
! grep -qiE "PASSWORD '|SCRAM-SHA-256\\$" "$gpart" || { echo "역할 목록에 비밀번호가 들어 있습니다" >&2; exit 1; }

if [ "${VERIFY:-}" = restore ]; then
  q="select (select count(*) from events)||' '||(select count(*) from verdicts)||' '||(select count(*) from actions)||' '||(select count(*) from blocklist)"
  fail() {
    mv "$part" "$DEST/opsloop-$ts.dump.unverified"
    echo "복원 시험 실패: $1. 덤프는 opsloop-$ts.dump.unverified 로 남겼다" >&2
    exit 1
  }
  "${SSH[@]}" "sudo -n docker exec opsloop-db sh -c 'dropdb -U opsloop --if-exists $TESTDB && createdb -U opsloop $TESTDB'" || fail "임시 DB 생성"
  "${SSH[@]}" "sudo -n docker exec -i opsloop-db pg_restore -U opsloop -d $TESTDB --no-owner --exit-on-error" < "$part" || fail "pg_restore"
  got=$("${SSH[@]}" "sudo -n docker exec opsloop-db psql -U opsloop -d $TESTDB -Atc \"$q\"") || fail "복원 DB 조회"
  live=$("${SSH[@]}" "sudo -n docker exec opsloop-db psql -U opsloop -d opsloop -Atc \"$q\"") || fail "운영 DB 조회"
  echo "복원 시험 (events verdicts actions blocklist): 복원 $got · 운영 $live"
  # 덤프 뒤에 운영 쪽이 늘 수는 있어도, 복원본이 더 많거나 이벤트가 0 이면 이상하다
  read -r ge gv ga gb <<< "$got"
  read -r le lv la lb <<< "$live"
  [ "$ge" -gt 0 ] || fail "복원된 이벤트가 0"
  [ "$ge" -le "$le" ] && [ "$gv" -le "$lv" ] && [ "$ga" -le "$la" ] && [ "$gb" -le "$lb" ] || fail "복원본이 운영보다 많음"
  [ "$gv" -eq "$lv" ] && [ "$ga" -eq "$la" ] || echo "참고: 덤프 뒤에 판정 · 조치가 늘었다 (복원 $gv/$ga · 운영 $lv/$la)"
fi

mv "$part" "$out"
chmod 600 "$out"
mv "$gpart" "$gout"
chmod 600 "$gout"
echo "백업 $(du -h "$out" | cut -f1) $out · 표 $tables 개 · 역할 $roles 개 $(basename "$gout")"

# 오래된 것부터 지워 최근 KEEP 개만 남긴다 (.unverified 는 건드리지 않는다). 역할 목록도 같은 개수
# shellcheck disable=SC2012  # 이름은 이 스크립트가 만든 opsloop-<시각> 뿐이다. Mac(BSD) find 로는 시각순 정렬을 못 한다
ls -1t "$DEST"/opsloop-*.dump 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r f; do rm -f -- "$f"; done
# shellcheck disable=SC2012  # 위와 같다
ls -1t "$DEST"/opsloop-*.globals.sql 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r f; do rm -f -- "$f"; done

if [ "${LEDGER:-1}" = 1 ]; then
  # 원장은 추가만 되므로 사본 하나를 따라 맞춘다. 쓰는 중에 받은 마지막 파일은 다음 회차가 덮는다.
  # 데이터 노드에서 지운 파일은 Mac 사본에서 지우지 않는다 (--delete 없음)
  mkdir -p "$DEST/ledger"
  rsync -a --rsync-path="sudo -n rsync" \
    -e "ssh -F $HOME/.ssh/config.opsloop -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4" \
    data01:/var/lib/opsloop/loki data01:/var/lib/opsloop/gate data01:/var/lib/opsloop/admin "$DEST/ledger/"
  echo "원장 사본 $(du -sh "$DEST/ledger" | cut -f1) $DEST/ledger (loki · gate · admin)"
fi
