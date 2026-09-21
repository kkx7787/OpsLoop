#!/usr/bin/env bash
# DB 백업(backup-db.sh)을 Mac 의 launchd 에 올린다. 매일 04:30 · 16:30, 보관 14개(7일).
# Mac 이 잠든 사이 시각이 지나면 깨어날 때 돈다. 꺼져 있던 회차는 건너뛴다(그동안 VM 도 멈춰 있다).
# 사용: infra/vmware/scripts/install-backup-agent.sh           설치 · 스크립트 갱신 (다시 실행해도 된다)
#       infra/vmware/scripts/install-backup-agent.sh --now     설치하고 한 번 바로 돌린다
#       infra/vmware/scripts/install-backup-agent.sh --remove  내린다 (보관된 덤프는 지우지 않는다)
# 기록: ~/opsloop-backup/backup.log
set -euo pipefail
LABEL=local.opsloop.backup-db
SRC=$(cd "$(dirname "$0")" && pwd)
BIN="$HOME/Library/Application Support/OpsLoop/bin"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DEST="$HOME/opsloop-backup"
DOMAIN="gui/$(id -u)"

if [ "${1:-}" = --remove ]; then
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "내림: $LABEL (덤프는 $DEST 에 그대로 있다)"
  exit 0
fi

mkdir -p "$BIN" "$DEST" "$(dirname "$PLIST")"
chmod 700 "$DEST"
install -m 700 "$SRC/backup-db.sh" "$SRC/backup-agent.sh" "$BIN/"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BIN/backup-agent.sh</string></array>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Hour</key><integer>4</integer><key>Minute</key><integer>30</integer></dict>
    <dict><key>Hour</key><integer>16</integer><key>Minute</key><integer>30</integer></dict>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>KEEP</key><string>14</string></dict>
  <key>StandardOutPath</key><string>$DEST/backup.log</string>
  <key>StandardErrorPath</key><string>$DEST/backup.log</string>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict>
</plist>
EOF
plutil -lint -s "$PLIST"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "설치: $LABEL · 매일 04:30 · 16:30 · 기록 $DEST/backup.log"

if [ "${1:-}" = --now ]; then
  launchctl kickstart "$DOMAIN/$LABEL"
  echo "한 번 바로 돌렸다. 결과는 기록 파일 끝을 본다"
fi
