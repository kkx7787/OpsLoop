#!/usr/bin/env bash
# OpsLoop 앱 노드 초기 설정 (EC2-2 에서 실행)
# 재실행해도 안전하다.
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/5] apt 저장소를 HTTPS 로 전환"
# 아웃바운드에서 80 을 열지 않기 위해서다. 열어두면 패키지가 평문으로 오간다.
for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
  [ -f "$f" ] && sudo sed -i 's|http://|https://|g' "$f"
done

echo "[2/5] Docker 설치"
if ! command -v docker &>/dev/null; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 git
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER"
  echo "  -> docker 그룹 반영을 위해 재로그인이 필요할 수 있습니다"
else
  echo "  -> 이미 설치됨"
fi

echo "[3/5] .env 생성"
if [ ! -f .env ]; then
  PW="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
  printf 'POSTGRES_PASSWORD=%s\n' "$PW" > .env
  chmod 600 .env
  echo "  -> 무작위 비밀번호 생성. .env 는 저장소에 커밋되지 않습니다"
else
  echo "  -> 이미 존재함 (덮어쓰지 않음)"
fi

echo "[4/5] 컨테이너 기동"
sudo docker compose up -d --build

echo "[5/5] 트리거 적용 및 상태 확인"
# schema.sql 은 최초 기동 시 자동 적용되지만 notify.sql 은 나중에 추가되었다.
# 재적용해도 안전하도록 작성되어 있다.
sleep 10
sudo docker compose exec -T postgres psql -U opsloop -d opsloop -q < notify.sql
sudo docker compose ps
sudo docker compose exec -T postgres psql -U opsloop -d opsloop -c '\dt'

echo
echo "API 확인:  curl -s http://localhost:8000/health"