#!/usr/bin/env bash
# 내부 DB 를 Mac 으로 백업한다.
# 판정 · 조치 · 차단 기록은 원문 로그에서 다시 만들 수 없고, 4대가 같은 기본 VM 의 연결 복제라
# 기본 VM 이 깨지면 함께 잃는다. 그래서 사본은 VM 밖(Mac)에 둔다.
# 관리망 ssh 로 Mac 이 안쪽에서 끌어온다. 안쪽 노드가 밖으로 쓰는 경로는 만들지 않는다.
#
# 관제 대상 로그의 원장(Loki)과 수집 관문 원장도 같은 폴더의 ledger/ 로 받는다 (LEDGER=0 이면 건너뛴다).
# 허니팟 원장은 S3(버저닝 · 삭제 금지)에 있으므로 받지 않는다.
#
# 사용: infra/vmware/scripts/backup-db.sh [보관 폴더]      기본 ~/opsloop-backup, 최근 14개 보관
#       VERIFY=restore infra/vmware/scripts/backup-db.sh   받은 덤프를 임시 DB 에 실제로 복원해
#                                                          운영 DB 와 건수를 대조한다
# 복원 시험이 실패하면 덤프를 .unverified 로 남기고 실패로 끝난다 (보관 개수 정리도 하지 않는다).
# 자동 실행: install-backup-agent.sh 가 launchd 에 올려 매일 04:30 · 16:30 에 복원 시험까지 돌린다.
set -euo pipefail
DEST=${1:-$HOME/opsloop-backup}
KEEP=${KEEP:-14}
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10 data01)
TESTDB=opsloop_restore_test

mkdir -p "$DEST"
chmod 700 "$DEST"
ts=$(date -u +%Y%m%d-%H%M)
part="$DEST/.opsloop-$ts.dump.part"
out="$DEST/opsloop-$ts.dump"
drop_testdb() {
  "${SSH[@]}" "sudo -n docker exec opsloop-db dropdb -U opsloop --if-exists $TESTDB" >/dev/null 2>&1
}
cleanup() {
  rm -f "$part"
  # 복원 시험 DB 에는 판정 · 계정까지 들어 있다. 실패해도 운영 컨테이너에 남기지 않는다
  if [ "${VERIFY:-}" = restore ] && ! drop_testdb; then
    echo "경고: 시험 DB $TESTDB 가 운영 컨테이너에 남았을 수 있다. 다음 실행 때 다시 지운다" >&2
  fi
}
trap cleanup EXIT
# 지난 실행이 중간에 끊겨 남긴 시험 DB 가 있으면 먼저 치운다
drop_testdb || true

"${SSH[@]}" 'sudo -n docker exec opsloop-db pg_dump -U opsloop -Fc opsloop' > "$part"

# 받은 파일이 온전한 덤프인지 DB 컨테이너의 pg_restore 로 목차를 읽어 본다
tables=$("${SSH[@]}" 'sudo -n docker exec -i opsloop-db pg_restore --list' < "$part" | grep -c 'TABLE DATA' || true)
[ "$tables" -gt 0 ] || { echo "덤프 목차를 읽지 못했습니다" >&2; exit 1; }

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
echo "백업 $(du -h "$out" | cut -f1) $out · 표 $tables 개"

# 오래된 것부터 지워 최근 KEEP 개만 남긴다 (.unverified 는 건드리지 않는다)
ls -1t "$DEST"/opsloop-*.dump 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r f; do rm -f -- "$f"; done

if [ "${LEDGER:-1}" = 1 ]; then
  # 원장은 추가만 되므로 사본 하나를 따라 맞춘다. 쓰는 중에 받은 마지막 파일은 다음 회차가 덮는다.
  # 데이터 노드에서 지운 파일은 Mac 사본에서 지우지 않는다 (--delete 없음)
  mkdir -p "$DEST/ledger"
  rsync -a --rsync-path="sudo -n rsync" -e "ssh -F $HOME/.ssh/config.opsloop -o BatchMode=yes" \
    data01:/var/lib/opsloop/loki data01:/var/lib/opsloop/gate data01:/var/lib/opsloop/admin "$DEST/ledger/"
  echo "원장 사본 $(du -sh "$DEST/ledger" | cut -f1) $DEST/ledger (loki · gate · admin)"
fi
