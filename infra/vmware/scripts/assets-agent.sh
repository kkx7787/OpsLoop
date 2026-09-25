#!/usr/bin/env bash
# launchd 가 매일 05:10 에 부르는 자산 조사 실행기 (이슈 #39). install-assets-agent.sh 가 이 파일 · collect-assets.sh ·
# probe.py 를 ~/Library/Application Support/OpsLoop/bin 에 복사해 두고 그 사본을 부른다 (브랜치를 바꿔도 흔들리지 않는다).
# AWS 두 대는 aws login 이 살아 있을 때만 모인다. launchd 안에서는 대개 만료돼 있으니 로그인 뒤 손으로 돌린다
#   (infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws).
# 종료 코드 1(일부 자산 실패 · 적재는 됐다)은 알리지 않는다. 평소 꺼 둔 console-b 때문에 매일 나오고, 자산별 실패는
# 콘솔 자산 화면에 오류 · '정보 오래됨'으로 보인다. 2(적재 실패 · 설정 오류) 이상이면 macOS 알림을 띄운다.
set -uo pipefail
export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
BIN=$(cd "$(dirname "$0")" && pwd)
LOG="$HOME/opsloop-assets/assets.log"

echo "== $(date '+%F %T %Z') 자산 수집 시작"
if bash "$BIN/collect-assets.sh" 2>&1; then
  echo "== $(date '+%F %T %Z') 자산 수집 성공"
else
  rc=$?
  if [ "$rc" = 1 ]; then
    echo "== $(date '+%F %T %Z') 자산 수집 일부 실패 (적재는 됐다. 위 요약 참고)"
  else
    echo "== $(date '+%F %T %Z') 자산 수집 실패 (종료 코드 $rc)"
    osascript -e "display notification \"종료 코드 $rc · $LOG 확인\" with title \"OpsLoop 자산 수집 실패\"" >/dev/null 2>&1 || true
  fi
  exit "$rc"
fi
