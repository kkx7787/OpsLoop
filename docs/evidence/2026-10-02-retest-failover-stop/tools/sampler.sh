#!/usr/bin/env bash
# 재시험(콘솔 이중화 정지 3회) DB 연결 표본을 10초 간격으로 계속 뜬다. Mac 에서 돈다. 운영에서는 읽기만 한다(db-sample.sh).
#   sampler.sh <표본 파일> <멈춤 파일> [최대 초, 기본 5400]
#   멈춤 파일이 생기거나 최대 초가 지나면 끝난다. 한 줄: <Mac epoch 초(ssh 앞뒤 가운데)>\t<db-sample.sh 출력 또는 오류>
set -u
OUT=${1:?표본 파일}; STOP=${2:?멈춤 파일}; MAX=${3:-5400}
HERE=$(cd "$(dirname "$0")" && pwd)
now() { python3 -c 'import time; print("%.3f" % time.time())'; }
end=$(( $(date +%s) + MAX ))
while [ ! -e "$STOP" ] && [ "$(date +%s)" -lt "$end" ]; do
  a=$(now)
  l=$(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=5 data01 'bash -s' < "$HERE/db-sample.sh" 2>&1 | tr '\n' ' ')
  b=$(now)
  printf '%s\t%s\n' "$(python3 -c "print('%.3f' % (($a + $b) / 2))")" "$l" >> "$OUT"
  sleep 10
done
