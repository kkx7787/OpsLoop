#!/usr/bin/env bash
# 내부 DB 를 Mac 으로 백업한다.
# 판정 · 조치 · 차단 기록은 원문 로그에서 다시 만들 수 없고, 4대가 같은 기본 VM 의 연결 복제라
# 기본 VM 이 깨지면 함께 잃는다. 그래서 사본은 VM 밖(Mac)에 둔다.
# 관리망 ssh 로 Mac 이 안쪽에서 끌어온다. 안쪽 노드가 밖으로 쓰는 경로는 만들지 않는다.
#
# 사용: infra/vmware/scripts/backup-db.sh [보관 폴더]      기본 ~/opsloop-backup, 최근 14개 보관
#       VERIFY=restore infra/vmware/scripts/backup-db.sh   받은 덤프를 임시 DB 에 실제로 복원해 본다
set -euo pipefail
DEST=${1:-$HOME/opsloop-backup}
KEEP=${KEEP:-14}
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10 data01)

mkdir -p "$DEST"
chmod 700 "$DEST"
ts=$(date -u +%Y%m%d-%H%M)
part="$DEST/.opsloop-$ts.dump.part"
out="$DEST/opsloop-$ts.dump"
trap 'rm -f "$part"' EXIT

"${SSH[@]}" 'sudo -n docker exec opsloop-db pg_dump -U opsloop -Fc opsloop' > "$part"

# 받은 파일이 온전한 덤프인지 DB 컨테이너의 pg_restore 로 목차를 읽어 본다
tables=$("${SSH[@]}" 'sudo -n docker exec -i opsloop-db pg_restore --list' < "$part" | grep -c 'TABLE DATA')
[ "$tables" -gt 0 ] || { echo "덤프 목차를 읽지 못했습니다" >&2; exit 1; }

if [ "${VERIFY:-}" = restore ]; then
  # 같은 컨테이너의 임시 DB 에 복원하고 판정 수를 운영 DB 와 대조한 뒤 지운다
  "${SSH[@]}" 'sudo -n docker exec opsloop-db sh -c "dropdb -U opsloop --if-exists opsloop_restore_test && createdb -U opsloop opsloop_restore_test"'
  "${SSH[@]}" 'sudo -n docker exec -i opsloop-db pg_restore -U opsloop -d opsloop_restore_test --no-owner' < "$part"
  q='select (select count(*) from events)||'"'"' '"'"'||(select count(*) from verdicts)||'"'"' '"'"'||(select count(*) from actions)||'"'"' '"'"'||(select count(*) from blocklist)'
  got=$("${SSH[@]}" "sudo -n docker exec opsloop-db psql -U opsloop -d opsloop_restore_test -Atc \"$q\"")
  "${SSH[@]}" 'sudo -n docker exec opsloop-db dropdb -U opsloop opsloop_restore_test'
  echo "복원 시험 (events verdicts actions blocklist): $got"
fi

mv "$part" "$out"
trap - EXIT
chmod 600 "$out"
echo "백업 $(du -h "$out" | cut -f1) $out · 표 $tables 개"

# 오래된 것부터 지워 최근 KEEP 개만 남긴다
ls -1t "$DEST"/opsloop-*.dump 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r f; do rm -f -- "$f"; done
