#!/usr/bin/env bash
# data01 에서 실행. 기본은 설치/측정 확인만, --enable 을 줘야 타이머를 시작한다.
set -euo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
ENABLE=0
if [ "${1:-}" = --enable ]; then ENABLE=1; shift; fi
[ "$#" = 0 ] || { echo "사용: sudo bash collector/install-data-health.sh [--enable]" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "data01 에서 sudo 로 실행하세요" >&2; exit 1; }
python3 -c 'import psycopg2'
[ -s /etc/opsloop/collector.env ] || { echo "collector 설치와 역할 분리를 먼저 완료하세요" >&2; exit 1; }
# 실제 컨테이너 마운트에서 저장소 경로를 찾는다. 볼륨 이름/경로를 추측하지 않는다.
DATA_PATHS=$(docker inspect opsloop-db opsloop-loki | python3 -c '
import json,sys,os
containers=json.load(sys.stdin)
paths={"root":"/"}
for name,key,destination in (("/opsloop-db","postgres","/var/lib/postgresql/data"),("/opsloop-loki","loki","/loki")):
    c=next(c for c in containers if c["Name"]==name)
    if not c["State"]["Running"]: raise SystemExit("데이터 서비스가 정지 상태입니다")
    mount=next(m for m in c["Mounts"] if m["Destination"]==destination)
    path=mount["Source"]
    if not os.path.isdir(path): raise SystemExit("저장소 경로를 확인할 수 없습니다")
    paths[key]=path
print(json.dumps(paths))
')
# 최소 권한 역할이 존재해야 한다. 자격 증명은 표시하지 않는다.
ROLES=$(docker exec opsloop-db psql -U opsloop -d opsloop -Atqc "SELECT count(*) FROM pg_roles WHERE rolname IN ('opsloop_ingest','opsloop_console')")
[ "$ROLES" = 2 ] || { echo "적재/콘솔 DB 역할이 없습니다" >&2; exit 1; }
docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q < "$SRC/infra/migrations/20261003_data_node_health.sql"
install -d -m 755 /opt/opsloop/app/collector /etc/opsloop
install -m 644 "$SRC/collector/data_node_health.py" /opt/opsloop/app/collector/data_node_health.py
printf '%s\n' "$DATA_PATHS" > /etc/opsloop/data-health.json
chmod 600 /etc/opsloop/data-health.json
for unit in opsloop-data-health.service opsloop-data-health.timer; do
  install -m 644 "$SRC/collector/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
python3 /opt/opsloop/app/collector/data_node_health.py --check
if [ "$ENABLE" = 1 ]; then
  systemctl start opsloop-data-health.service
  systemctl enable --now opsloop-data-health.timer
  echo '설치 및 수집 시작 완료. 타이머/카드의 최근 측정 시각을 확인하세요.'
else
  echo '설치 및 측정 확인 완료. 새 타이머는 시작하지 않았습니다. 활성화: 이 명령에 --enable 추가'
fi
