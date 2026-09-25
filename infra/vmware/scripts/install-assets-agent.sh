#!/usr/bin/env bash
# 자산 조사 수집(collect-assets.sh)을 Mac 의 launchd 에 올린다 (이슈 #39). 매일 05:10 (DB 백업 04:30 뒤).
# Mac 이 잠든 사이 시각이 지나면 깨어날 때 돈다. 꺼져 있던 회차는 건너뛴다(그동안 VM 도 멈춰 있다).
# launchd 안에서는 AWS 로그인이 대개 만료돼 있어 AWS 두 대(gateway · honeypot-dmz)는 빠진다(콘솔에 '정보 오래됨').
# 그 두 대는 aws login 뒤 손으로 돌린다: infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws
# 사용: infra/vmware/scripts/install-assets-agent.sh           설치 · 스크립트 갱신 (다시 실행해도 된다)
#       infra/vmware/scripts/install-assets-agent.sh --now     설치하고 한 번 바로 돌린다
#       infra/vmware/scripts/install-assets-agent.sh --remove  내린다 (기록은 지우지 않는다)
# 기록: ~/opsloop-assets/assets.log
set -euo pipefail
LABEL=local.opsloop.assets
SRC=$(cd "$(dirname "$0")" && pwd)
PROBE="$SRC/../../../cti/probe.py"
BIN="$HOME/Library/Application Support/OpsLoop/bin"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DEST="$HOME/opsloop-assets"
DOMAIN="gui/$(id -u)"

if [ "${1:-}" = --remove ]; then
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "내림: $LABEL (기록은 $DEST 에 그대로 있다)"
  exit 0
fi

[ -f "$PROBE" ] || { echo "조사 스크립트가 없다: $PROBE (저장소 안에서 돌린다)" >&2; exit 1; }
mkdir -p "$BIN" "$DEST" "$(dirname "$PLIST")"
chmod 700 "$DEST"
install -m 700 "$SRC/collect-assets.sh" "$SRC/assets-agent.sh" "$BIN/"
# collect-assets.sh 는 같은 폴더에 probe.py 가 있으면 그것을 노드에 보낸다
install -m 600 "$PROBE" "$BIN/probe.py"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BIN/assets-agent.sh</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>5</integer><key>Minute</key><integer>10</integer></dict>
  <key>StandardOutPath</key><string>$DEST/assets.log</string>
  <key>StandardErrorPath</key><string>$DEST/assets.log</string>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
</dict>
</plist>
EOF
plutil -lint -s "$PLIST"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "설치: $LABEL · 매일 05:10 · 기록 $DEST/assets.log"
echo "  AWS 두 대(gateway · honeypot-dmz)는 aws login 뒤 손으로: infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws"

if [ "${1:-}" = --now ]; then
  launchctl kickstart "$DOMAIN/$LABEL"
  echo "한 번 바로 돌렸다. 결과는 기록 파일 끝을 본다"
fi
