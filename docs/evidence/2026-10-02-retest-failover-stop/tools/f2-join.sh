#!/usr/bin/env bash
# 장애 전환 재측정 8 · 9단계: 콘솔 B 합류(A 의 #84 이미지) → B 판 · 이름표 · 분배 확인
set -u
source /Users/hanseongmin/opsloop-work/retest/failover-stop.env; cd /Users/hanseongmin/opsloop-repo || exit 1
SSH="ssh -F $HOME/.ssh/config.opsloop"
infra/vmware/scripts/console-join.sh --apply 2>&1 | tee "$E/pre/join.log"
echo; echo "== 합류 뒤 확인"
{
echo "== $(date '+%F %T %Z')"; for f in live.py targets.py main.py auth.py; do printf '%s  /app/%s\n' "$(git show 0d09fc7:app/$f | shasum -a 256 | cut -d' ' -f1)" "$f"; done
for h in console-a console-b; do echo "== $h"; $SSH $h 'docker image inspect -f "{{.Id}}" opsloop-api:latest; docker inspect -f "{{.State.Status}} {{.HostConfig.RestartPolicy.Name}} {{.State.StartedAt}}" opsloop-api; docker exec opsloop-api printenv OPSLOOP_WORKER; docker exec opsloop-api sha256sum /app/live.py /app/targets.py /app/main.py /app/auth.py; docker exec opsloop-api grep -c "def db_settings" /app/live.py; uname -r; docker version -f "{{.Server.Version}}"'; done
echo "== 서버 상태"; $SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ {print $4, "운영", $6, "관리", $7}'
$SSH fw 'curl -fsS "http://127.0.0.1:8404/;csv"' | cut -d, -f1,2,18 | grep '^consoles'
echo "== DB 표본 마지막 3줄"; tail -n 3 "$E/db-links.tsv"
echo "== client_addr (조회: console-b)"; $SSH console-b 'docker exec -i -w /app opsloop-api python3 -' < "$E/tools/client-addr.py"
} 2>&1 | tee "$E/pre/after-join.txt"
echo "== f2 끝 $(date '+%H:%M:%S')"
