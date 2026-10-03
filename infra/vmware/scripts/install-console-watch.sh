#!/usr/bin/env bash
# 콘솔 진입점 감시(console-watch.sh)를 Mac 의 launchd 에 올린다 (이슈 #43). 60초마다 한 회차 · 올리자마자 한 번 돈다.
# 콘솔 두 대가 다 죽으면 콘솔 안의 알림 발송기도 같이 멈추므로 그때 알릴 경로를 Mac 에 따로 둔다.
# Mac 이 잠든 동안은 돌지 않는다(VM 도 함께 멈춘다). 깨어나면 다음 간격에 다시 돈다.
# 같은 회차가 DB 백업 기록(~/opsloop-backup/backup.log)의 마지막 성공도 본다. 10시간 넘게 지나면 한 번 알린다 (이슈 #91).
# VM 을 일부러 끄거나 점검할 때는 점검 창을 둔다: ~/Library/Application\ Support/OpsLoop/bin/console-watch.sh --pause <분>
# 사용: infra/vmware/scripts/install-console-watch.sh              설치 · 스크립트 갱신 (다시 실행해도 된다)
#       infra/vmware/scripts/install-console-watch.sh --uninstall  내린다 (기록 · 설정 · 상태는 지우지 않는다. --remove 도 같다)
# 기록: ~/Library/Logs/opsloop/console-watch.log · 웹훅(선택): ~/.config/opsloop/console-watch.env (0600 · WEBHOOK_URL=https://...)
set -euo pipefail
LABEL=local.opsloop.console-watch
SRC=$(cd "$(dirname "$0")" && pwd)
BIN="$HOME/Library/Application Support/OpsLoop/bin"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/Library/Logs/opsloop"
CONF="$HOME/.config/opsloop"
DOMAIN="gui/$(id -u)"

case "${1:-}" in
  "") ;;
  --uninstall | --remove)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$PLIST" "$BIN/console-watch.sh"
    echo "내림: $LABEL (기록 $LOGDIR · 설정 $CONF 은 그대로 있다)"
    exit 0 ;;
  -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 0 ;;
  *)
    echo "모르는 옵션: $1 (--help)" >&2
    exit 2 ;;
esac

mkdir -p "$BIN" "$LOGDIR" "$CONF" "$(dirname "$PLIST")"
chmod 700 "$LOGDIR" "$CONF"
install -m 700 "$SRC/console-watch.sh" "$BIN/"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BIN/console-watch.sh</string></array>
  <key>StartInterval</key><integer>60</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$LOGDIR/console-watch.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/console-watch.log</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
EOF
plutil -lint -s "$PLIST"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
# 재설치 직후 launchd가 종료를 처리하는 동안 오류 5가 날 수 있다.
# 실패를 출력하고 최대 세 번만 시도한다. 계속 실패하면 설치 성공으로 표시하지 않는다.
bootstrap_rc=0
for attempt in 1 2 3; do
  if launchctl bootstrap "$DOMAIN" "$PLIST"; then bootstrap_rc=0; break
  else bootstrap_rc=$?; fi
  if [ "$bootstrap_rc" != 5 ] || [ "$attempt" = 3 ]; then
    echo "감시 등록 실패 (종료 $bootstrap_rc). launchctl 상태를 확인하세요: $DOMAIN/$LABEL" >&2
    exit "$bootstrap_rc"
  fi
  echo "감시 재등록 대기 ($attempt/3, 종료 5)" >&2
  sleep 1
done
echo "설치: $LABEL · 60초마다 · 기록 $LOGDIR/console-watch.log"
# 웹훅 설정이 있으면 권한 · 형식을 여기서 알려 준다 (주소는 내지 않는다)
bash "$BIN/console-watch.sh" --status | grep '^웹훅:' || true
echo "  알림 경로 시험: \"$BIN/console-watch.sh\" --test-alert"
