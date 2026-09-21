#!/usr/bin/env bash
# 허니팟에 업로더를 설치한다. 타이머는 켜지 않는다 (확인 후 직접 켠다).
# 사용: sudo bash install-uploader.sh <버킷> <인스턴스 ID>
set -euo pipefail
BUCKET=${1:?버킷 이름}
HOST=${2:?인스턴스 ID}
HERE="$(cd "$(dirname "$0")" && pwd)"

id opsloop-up >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home /var/lib/opsloop-upload opsloop-up
install -d -o opsloop-up -g opsloop-up -m 700 /var/lib/opsloop-upload
install -d -m 755 /usr/local/lib/opsloop
install -m 755 "$HERE/upload.py" /usr/local/lib/opsloop/upload.py
install -m 644 "$HERE/opsloop-upload.service" /etc/systemd/system/opsloop-upload.service
install -m 644 "$HERE/opsloop-upload.timer" /etc/systemd/system/opsloop-upload.timer
cat > /etc/default/opsloop-upload <<EOT
OPSLOOP_BUCKET=$BUCKET
OPSLOOP_HOST=$HOST
AWS_DEFAULT_REGION=ap-northeast-2
OPSLOOP_STATE=/var/lib/opsloop-upload/state.json
EOT
chmod 644 /etc/default/opsloop-upload
systemctl daemon-reload

echo "== 읽기 권한 확인"
for f in /opt/cowrie/log/cowrie.json /opt/decoy/log/decoy.json.*; do
  sudo -u opsloop-up head -c1 "$f" >/dev/null 2>&1 && echo "  읽기 가능 $f" || echo "  읽기 불가 $f"
done | sort -u | head -5
echo "설치 완료. 확인: sudo -u opsloop-up env \$(cat /etc/default/opsloop-upload | xargs) python3 /usr/local/lib/opsloop/upload.py --dry-run"
