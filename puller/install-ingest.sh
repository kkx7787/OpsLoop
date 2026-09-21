#!/usr/bin/env bash
# 데이터 노드에 원장 가져오기 · 적재 · 탐지를 설치한다. 타이머는 켜지 않는다 (확인 후 직접 켠다).
# S3 읽기 키(/etc/opsloop/s3-pull.env)는 이 스크립트가 만들지 않는다. Mac 에서 파이프로 바로 넣는다.
#
# 사용 (Mac, 저장소 루트):
#   C=$(git rev-parse --short HEAD)
#   git archive "$C" parser detector puller \
#     | ssh -F ~/.ssh/config.opsloop data01 "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/puller/install-ingest.sh $C"
set -euo pipefail
VERSION=${1:?커밋}
SRC="$(cd "$(dirname "$0")/.." && pwd)"
BUCKET=${OPSLOOP_BUCKET:-opsloop-archive-739272173045}
HOSTS=${OPSLOOP_HOSTS:-i-058726c1a0671fe1d}
DB_HOST=192.168.60.11          # DB 는 이 주소에만 묶여 있다 (compose/data.yml)
ENV_SRC=/home/ops/opsloop/.env

echo "== 패키지"
export DEBIAN_FRONTEND=noninteractive
python3 -c 'import psycopg2' 2>/dev/null || { apt-get update -qq && apt-get install -y -qq python3-psycopg2; }
python3 -c 'import boto3' 2>/dev/null || apt-get install -y -qq python3-boto3

echo "== 사용자 · 폴더"
id opsloop-pull >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home /var/lib/opsloop opsloop-pull
install -d -o opsloop-pull -g opsloop-pull -m 750 /var/lib/opsloop
install -d -o root -g opsloop-pull -m 750 /etc/opsloop

echo "== 코드 $VERSION (root 소유. 파이프라인이 자기 코드를 바꿀 수 없다)"
rm -rf /opt/opsloop/app.new
install -d -m 755 /opt/opsloop /opt/opsloop/app.new
cp -r "$SRC/parser" "$SRC/detector" "$SRC/puller" /opt/opsloop/app.new/
# 관제 대상 수집(collector/)도 같은 앱 폴더에 있다. 받은 묶음에 있으면 함께 바꾸고, 없으면 지금 것을 옮겨 둔다
# (앱 폴더를 통째로 바꾸므로 그냥 두면 사라져 수집 관문이 뜨지 않는다)
if [ -d "$SRC/collector" ]; then
  cp -r "$SRC/collector" /opt/opsloop/app.new/
elif [ -d /opt/opsloop/app/collector ]; then
  cp -r /opt/opsloop/app/collector /opt/opsloop/app.new/
fi
find /opt/opsloop/app.new -name '__pycache__' -prune -exec rm -rf {} +
echo "$VERSION" > /opt/opsloop/app.new/VERSION
chown -R root:root /opt/opsloop/app.new
chmod -R u+rwX,go+rX,go-w /opt/opsloop/app.new
rm -rf /opt/opsloop/app.old
if [ -d /opt/opsloop/app ]; then mv /opt/opsloop/app /opt/opsloop/app.old; fi
mv /opt/opsloop/app.new /opt/opsloop/app
install -m 755 "$SRC/puller/opsloop-ingest" /usr/local/bin/opsloop-ingest
install -m 644 "$SRC/puller/opsloop-ingest.service" /etc/systemd/system/opsloop-ingest.service
install -m 644 "$SRC/puller/opsloop-ingest.timer" /etc/systemd/system/opsloop-ingest.timer
# 설정은 처음 설치할 때만 만든다. 이미 있으면 손으로 바꾼 값(센서 호스트 추가 등)을 지키려고 덮어쓰지 않는다
if [ ! -s /etc/default/opsloop-ingest ]; then
  cat > /etc/default/opsloop-ingest <<EOT
OPSLOOP_BUCKET=$BUCKET
OPSLOOP_HOSTS=$HOSTS
OPSLOOP_HOME=/var/lib/opsloop
AWS_DEFAULT_REGION=ap-northeast-2
EOT
  chmod 644 /etc/default/opsloop-ingest
fi
echo "  설정 (/etc/default/opsloop-ingest):"; sed 's/^/    /' /etc/default/opsloop-ingest
# 운영자가 확인한 원장 구멍 목록. root 만 고칠 수 있고 풀러는 읽기만 한다
if [ ! -e /etc/opsloop/gap-ack.json ]; then
  echo '[]' > /etc/opsloop/gap-ack.json
  chgrp opsloop-pull /etc/opsloop/gap-ack.json
  chmod 640 /etc/opsloop/gap-ack.json
fi
systemctl daemon-reload

echo "== DB 접속 정보"
if [ ! -s /etc/opsloop/collector.env ]; then
  # 비밀번호를 화면 · 셸 이력 · 명령행 인자에 남기지 않는다. URL 특수문자는 인코딩한다
  ( umask 027
    python3 - "$ENV_SRC" "$DB_HOST" > /etc/opsloop/collector.env <<'PY'
import sys, urllib.parse
env = {}
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
pw = urllib.parse.quote(env["POSTGRES_PASSWORD"], safe="")
print(f"DATABASE_URL=postgresql://opsloop:{pw}@{sys.argv[2]}:5432/opsloop")
PY
  )
  chgrp opsloop-pull /etc/opsloop/collector.env
  chmod 640 /etc/opsloop/collector.env
fi
sudo -u opsloop-pull sh -c 'set -a; . /etc/opsloop/collector.env; python3 -c "import os,psycopg2; psycopg2.connect(os.environ[\"DATABASE_URL\"]).close()"' \
  && echo "  DB 접속 성공" || echo "  DB 접속 실패"

echo "== S3 읽기 키"
if [ -s /etc/opsloop/s3-pull.env ]; then
  echo "  있음 (/etc/opsloop/s3-pull.env)"
else
  echo "  없음. Mac 에서 읽기 키를 넣은 뒤 타이머를 켠다"
fi
echo "설치 완료. 한 번 실행: sudo systemctl start opsloop-ingest.service; journalctl -u opsloop-ingest -n 60"
