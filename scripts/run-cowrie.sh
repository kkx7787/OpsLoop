#!/usr/bin/env bash
# OpsLoop 허니팟 기동 (재현용 정본)
#  - 관리 접근은 SSM Session Manager 전용. 인바운드 관리 포트를 열지 않는다.
#  - CUID: 컨테이너 내부 cowrie 사용자 UID. 이미지가 바뀌면 아래 명령으로 재확인한다.
#      ps -eo uid,cmd | grep twistd
set -euo pipefail

# 새 이미지를 임의로 고르지 않는다. 검증한 다이제스트를 재구축 설정으로 지정한다.
: "${OPSLOOP_COWRIE_IMAGE:?검증한 cowrie/cowrie@sha256:<64자리> 이미지를 지정하세요}"
[[ "$OPSLOOP_COWRIE_IMAGE" =~ ^cowrie/cowrie@sha256:[a-f0-9]{64}$ ]] || {
  echo "태그 대신 검증한 Cowrie 이미지 다이제스트가 필요합니다" >&2; exit 1;
}
BASE=/opt/cowrie
CUID=999

sudo mkdir -p "$BASE"/{log,lib,etc}
sudo chown -R ${CUID}:${CUID} "$BASE"/log "$BASE"/lib

if [ ! -f "$BASE/etc/cowrie.cfg" ]; then
  echo "[중단] $BASE/etc/cowrie.cfg 가 없습니다. scripts/cowrie.cfg 를 배치하세요."
  exit 1
fi

# 다운로드 실패 때문에 기존 컨테이너부터 지우지 않는다.
sudo docker pull "$OPSLOOP_COWRIE_IMAGE"
sudo docker rm -f cowrie 2>/dev/null || true
sudo docker run -d --name cowrie --restart always \
  -p 22:2222 -p 23:2223 \
  -v "$BASE/etc/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro" \
  -v "$BASE/log:/cowrie/cowrie-git/var/log/cowrie" \
  -v "$BASE/lib:/cowrie/cowrie-git/var/lib/cowrie" \
  --memory=512m --cpus=0.5 \
  --log-opt max-size=50m --log-opt max-file=3 \
  "$OPSLOOP_COWRIE_IMAGE"

sleep 8
sudo docker ps --filter name=cowrie
sudo ls -la "$BASE/log"
