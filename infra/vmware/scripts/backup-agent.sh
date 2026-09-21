#!/usr/bin/env bash
# launchd 가 하루 두 번 부르는 백업 실행기. install-backup-agent.sh 가 이 파일과 backup-db.sh 를
# ~/Library/Application Support/OpsLoop/bin 에 복사해 두고 그 사본을 부른다 (브랜치를 바꿔도 흔들리지 않는다).
# 매번 임시 DB 에 실제로 복원해 건수를 대조한다(VERIFY=restore). 실패하면 macOS 알림을 띄운다.
set -uo pipefail
export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
BIN=$(cd "$(dirname "$0")" && pwd)
DEST=${OPSLOOP_BACKUP_DIR:-$HOME/opsloop-backup}

echo "== $(date '+%F %T %Z') 백업 시작"
if VERIFY=restore bash "$BIN/backup-db.sh" "$DEST" 2>&1; then
  echo "== $(date '+%F %T %Z') 백업 성공"
else
  rc=$?
  echo "== $(date '+%F %T %Z') 백업 실패 (종료 코드 $rc)"
  osascript -e "display notification \"종료 코드 $rc · $DEST/backup.log 확인\" with title \"OpsLoop DB 백업 실패\"" >/dev/null 2>&1 || true
  exit "$rc"
fi
