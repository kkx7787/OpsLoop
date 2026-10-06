#!/usr/bin/env bash
# 자산 조사 수집(collect-assets.sh)을 Mac 의 launchd 에 올린다 (이슈 #39). 매일 05:10 (DB 백업 04:30 뒤).
# 로그인 때 · 15분마다 마지막 실행 상태를 확인한다. Mac 을 깨우거나 꺼진 VM 을 켜지는 않는다.
# AWS 인증 만료도 자산별 실패로 남긴다. 일부 실패는 4시간, 적재 실패는 15분 뒤 재시도한다.
# AWS 로그인 뒤 바로 재개하려면 python3 infra/vmware/scripts/assets-schedule.py 를 실행한다.
# 사용: infra/vmware/scripts/install-assets-agent.sh           설치 · 스크립트 갱신 (다시 실행해도 된다)
#       infra/vmware/scripts/install-assets-agent.sh --now     설치하고 실행 필요 여부를 바로 확인한다
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
install -m 700 "$SRC/collect-assets.sh" "$SRC/assets-agent.sh" "$SRC/assets-schedule.py" "$BIN/"
# collect-assets.sh 는 같은 폴더에 probe.py 가 있으면 그것을 노드에 보낸다
install -m 600 "$PROBE" "$BIN/probe.py"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BIN/assets-agent.sh</string><string>--scheduled</string></array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>900</integer>
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
echo "  로그인 시·15분마다 확인: 완전 성공은 다음 회차, 일부 실패는 4시간, 적재 실패는 15분 뒤 재시도"
echo "  AWS 인증 갱신: aws login · 바로 조사: python3 infra/vmware/scripts/assets-schedule.py"

if [ "${1:-}" = --now ]; then
  launchctl kickstart "$DOMAIN/$LABEL"
  echo "실행 필요 여부 확인을 요청했다. 결과는 기록 파일 끝을 본다"
fi
