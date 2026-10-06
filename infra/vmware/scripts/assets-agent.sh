#!/usr/bin/env bash
# launchd 가 로그인 · 15분마다 확인하고 매일 05:10 기준으로 실행하는 자산 조사 실행기 (이슈 #39). install-assets-agent.sh 가 이 파일 · collect-assets.sh ·
# assets-schedule.py · probe.py 를 ~/Library/Application Support/OpsLoop/bin 에 복사해 두고 그 사본을 부른다 (브랜치를 바꿔도 흔들리지 않는다).
# AWS 두 대는 인증이 유효할 때 모인다. 만료되면 실패를 기록하며 사용자가 aws login 으로 갱신한다.
# 바로 재개하려면 python3 infra/vmware/scripts/assets-schedule.py 를 실행한다(그 외에는 다음 재시도 때 수집).
# 종료 코드 1(일부 자산 실패 · 적재는 됐다)은 알리지 않는다. 평소 꺼 둔 console-b 때문에 매일 나오고, 자산별 실패는
# 콘솔 자산 화면에 오류 · '정보 오래됨'으로 보인다. 2(적재 실패 · 설정 오류) 이상이면 macOS 알림을 띄운다.
set -euo pipefail
export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
BIN=$(cd "$(dirname "$0")" && pwd)
exec python3 "$BIN/assets-schedule.py" "$@"
