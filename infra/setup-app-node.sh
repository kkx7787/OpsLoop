#!/usr/bin/env bash
# OpsLoop 앱 노드 초기 설정 (EC2-2 에서 실행)
set -euo pipefail

echo "[1/4] Docker 설치"
if ! command -v docker &>/dev/null; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 git
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER"
  echo "  -> docker 그룹 반영을 위해 재로그인이 필요할 수 있습니다"
else
  echo "  -> 이미 설치됨"
fi

echo "[2/4] .env 생성"
ENV_FILE="$(dirname "$0")/.env"
if [ ! -f "$ENV_FILE" ]; then
  PW="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
  printf 'POSTGRES_PASSWORD=%s\n' "$PW" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "  -> 무작위 비밀번호 생성. .env 는 저장소에 커밋되지 않습니다"
else
  echo "  -> 이미 존재함 (덮어쓰지 않음)"
fi

echo "[3/4] 컨테이너 기동"
cd "$(dirname "$0")"
sudo docker compose up -d postgres

echo "[4/4] 상태 확인"
sleep 8
sudo docker compose ps
sudo docker compose exec -T postgres psql -U opsloop -d opsloop -c '\dt'