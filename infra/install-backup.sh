#!/usr/bin/env bash
# ============================================================
#  OpsLoop 데이터베이스 백업 설치 (앱 노드에서 실행)
#
#  events 와 sessions 는 원문 로그에서 재생성되므로 백업 대상이 아니다.
#  그러나 조치·판정·차단 이력은 사람이 내린 판단이라 재생성되지 않는다.
#  이것이 백업의 실질적 대상이며, 유실되면 폐루프의 근거가 함께 사라진다.
#
#  사용:  ./install-backup.sh
# ============================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-/opt/opsloop/backup}"
KEEP_DAYS="${KEEP_DAYS:-14}"
RUN_USER="${SUDO_USER:-$(id -un)}"

echo "[1/5] 보관 디렉터리 준비"
sudo install -d -m 750 -o "$RUN_USER" "$BACKUP_DIR"

echo "[2/5] 백업 스크립트 배치"
sudo tee /usr/local/bin/opsloop-backup > /dev/null <<EOF
#!/usr/bin/env bash
# 덤프를 뜨고, 읽히는지 확인하고, 오래된 것을 지운다.
# 확인하지 않은 덤프는 백업이 아니라 파일일 뿐이다.
set -euo pipefail

DIR="$BACKUP_DIR"
KEEP=$KEEP_DAYS
STAMP="\$(date -u +%Y%m%d-%H%M)"
OUT="\$DIR/opsloop-\$STAMP.dump"

cd "$REPO/infra"

# 커스텀 포맷으로 뜬다. 부분 복원과 목록 확인이 가능하다.
sudo docker compose exec -T postgres \\
  pg_dump -U opsloop -d opsloop -Fc > "\$OUT"

# 무결성 확인: 목록을 읽을 수 없으면 손상된 덤프다
if ! sudo docker compose exec -T postgres pg_restore --list < "\$OUT" > /dev/null 2>&1; then
  echo "[오류] 덤프를 읽을 수 없습니다: \$OUT" >&2
  mv "\$OUT" "\$OUT.corrupt"
  exit 1
fi

SIZE=\$(stat -c%s "\$OUT")
ROWS=\$(sudo docker compose exec -T postgres psql -U opsloop -d opsloop -tAc \\
  "SELECT (SELECT count(*) FROM incidents) || '/' || (SELECT count(*) FROM actions) || '/' || (SELECT count(*) FROM verdicts)")

logger -t opsloop-backup "ok \$OUT bytes=\$SIZE incidents/actions/verdicts=\$ROWS"
echo "백업 완료  \$OUT  (\$SIZE bytes, 인시던트/조치/판정 \$ROWS)"

# 보관 기간 경과분 정리
find "\$DIR" -name 'opsloop-*.dump' -mtime +\$KEEP -delete
EOF
sudo chmod 755 /usr/local/bin/opsloop-backup

echo "[3/5] systemd 유닛 등록"
sudo tee /etc/systemd/system/opsloop-backup.service > /dev/null <<EOF
[Unit]
Description=OpsLoop 운영 데이터 백업
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=$RUN_USER
ExecStart=/usr/local/bin/opsloop-backup
TimeoutStartSec=900
EOF

sudo tee /etc/systemd/system/opsloop-backup.timer > /dev/null <<EOF
[Unit]
Description=OpsLoop 일 1회 백업

[Timer]
OnCalendar=*-*-* 18:30:00 UTC
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "[4/5] 타이머 기동"
sudo systemctl daemon-reload
sudo systemctl enable --now opsloop-backup.timer

echo "[5/5] 첫 백업 실행"
sudo systemctl start opsloop-backup.service
sleep 5
sudo systemctl status opsloop-backup.service --no-pager -n 12 || true
ls -la "$BACKUP_DIR"

echo
echo "=============================================================="
echo " 백업 등록 완료.  매일 18:30 UTC (한국 시간 새벽 03:30)"
echo " 보관 위치 $BACKUP_DIR,  보관 기간 ${KEEP_DAYS}일"
echo
echo " 즉시 실행    sudo systemctl start opsloop-backup.service"
echo " 실행 기록    journalctl -u opsloop-backup.service -n 30"
echo
echo " ※ 같은 EBS 볼륨에 두는 것은 아직 백업이 아니다."
echo "   S3 전송은 5주차 IAM 역할 정리와 함께 붙인다."
echo "=============================================================="