#!/usr/bin/env bash
# ============================================================
#  OpsLoop 수집 자동화 설치 (수집 노드에서 실행)
#
#  파서와 탐지기를 주기 실행하는 systemd 타이머를 등록한다.
#  로그가 원장이고 DB가 파생물이므로, 이 작업이 멎어 있어도
#  데이터는 유실되지 않고 재개 시 공백 없이 채워진다.
#  다만 멎어 있는 동안 콘솔은 과거만 보여주므로 주기 실행이 필요하다.
#
#  사용:
#    ./install-collector.sh 'postgresql://opsloop:비밀번호@172.31.35.234:5432/opsloop'
# ============================================================
set -euo pipefail

DB_URL="${1:-${DATABASE_URL:-}}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INTERVAL="${INTERVAL:-10min}"
RUN_USER="${SUDO_USER:-$(id -un)}"

if [ -z "$DB_URL" ]; then
  echo "사용법: $0 'postgresql://사용자:비밀번호@호스트:5432/opsloop'"
  exit 1
fi

echo "[1/6] 접속 정보 저장"
sudo install -d -m 750 /etc/opsloop
printf 'DATABASE_URL=%s\n' "$DB_URL" | sudo tee /etc/opsloop/collector.env > /dev/null
sudo chmod 640 /etc/opsloop/collector.env
sudo chown root:"$RUN_USER" /etc/opsloop/collector.env
echo "     -> /etc/opsloop/collector.env (640, 저장소에 남지 않음)"

echo "[2/6] 연결 확인"
sudo -u "$RUN_USER" env DATABASE_URL="$DB_URL" python3 - <<'PY'
import os, sys
try:
    import psycopg2
    psycopg2.connect(os.environ["DATABASE_URL"]).close()
    print("     -> 접속 성공")
except Exception as e:
    sys.exit(f"     -> 접속 실패: {e}")
PY

echo "[3/6] 실행 스크립트 배치"
sudo tee /usr/local/bin/opsloop-collect > /dev/null <<EOF
#!/usr/bin/env bash
# 파서 → 탐지기 순차 실행. 겹쳐 도는 것을 막기 위해 잠금을 건다.
set -euo pipefail
set -a; . /etc/opsloop/collector.env; set +a
cd "$REPO"
python3 parser/parse_cowrie.py --load
python3 detector/detect.py --run
EOF
sudo chmod 755 /usr/local/bin/opsloop-collect

echo "[4/6] systemd 유닛 등록"
sudo tee /etc/systemd/system/opsloop-collect.service > /dev/null <<EOF
[Unit]
Description=OpsLoop 로그 적재 및 탐지
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$RUN_USER
# 앞선 실행이 길어졌을 때 겹쳐 도는 것을 막는다
ExecStart=/usr/bin/flock -n /tmp/opsloop-collect.lock /usr/local/bin/opsloop-collect
TimeoutStartSec=600
EOF

sudo tee /etc/systemd/system/opsloop-collect.timer > /dev/null <<EOF
[Unit]
Description=OpsLoop 수집 주기 실행

[Timer]
OnBootSec=3min
OnUnitActiveSec=$INTERVAL
# 여러 타이머가 동시에 깨어나 부하가 몰리는 것을 막는다
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "[5/6] 타이머 기동"
sudo systemctl daemon-reload
sudo systemctl enable --now opsloop-collect.timer

echo "[6/6] 첫 실행"
sudo systemctl start opsloop-collect.service
sleep 3
sudo systemctl status opsloop-collect.service --no-pager -n 12 || true

echo
echo "=============================================================="
echo " 등록 완료. 주기: $INTERVAL"
echo
echo " 다음 실행 예정   systemctl list-timers opsloop-collect.timer"
echo " 실행 기록        journalctl -u opsloop-collect.service -n 40"
echo " 즉시 한 번       sudo systemctl start opsloop-collect.service"
echo "=============================================================="