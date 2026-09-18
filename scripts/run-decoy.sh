#!/usr/bin/env bash
# OpsLoop 웹 디코이 기동 (재현용 정본)
#
#   - 8080 을 외부에 노출한다. 이번 주는 보안그룹으로, 다음 주부터는 관문 방화벽이 전달한다.
#   - 로그는 /opt/decoy/log 에 날짜별 JSON 으로 쌓인다. Cowrie 와 같은 방식이다.
#   - 읽기 전용 파일시스템으로 띄운다. 쓰기가 필요한 곳은 로그 디렉터리뿐이다.
#   - 이 컨테이너는 공격을 직접 받는다. 자원 상한을 두어 호스트를 잠식하지 못하게 한다.
set -euo pipefail

BASE=/opt/decoy
DUID=1002
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sudo mkdir -p "$BASE/log"
sudo chown -R ${DUID}:${DUID} "$BASE/log"

sudo docker build -t opsloop-decoy:latest "$REPO/decoy"

sudo docker rm -f decoy 2>/dev/null || true
sudo docker run -d --name decoy --restart always \
  -p 8080:8080 \
  -v "$BASE/log:/var/log/decoy" \
  --read-only --tmpfs /tmp:size=16m \
  --memory=256m --cpus=0.5 \
  --log-opt max-size=50m --log-opt max-file=3 \
  -e DECOY_LOG_DIR=/var/log/decoy \
  opsloop-decoy:latest

echo "[완료] 디코이 기동. 로그: $BASE/log/decoy.json.\$(date -u +%F)"
echo "       확인:  curl -s -o /dev/null -w '%{http_code}\\n' http://localhost:8080/admin"
