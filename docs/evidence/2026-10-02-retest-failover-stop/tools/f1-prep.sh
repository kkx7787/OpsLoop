#!/usr/bin/env bash
# 장애 전환 재측정 1 · 2 · 3 · 6 · 7단계: 증거 폴더 · 시작 상태 · 콘솔 A 판 · DB 기준값 · 프로브 계정 · DB 연결 표본(백그라운드) · B 합류 드라이런. 모두 읽기
set -u
ENVF=/Users/hanseongmin/opsloop-work/retest/failover-stop.env
[ -f "$ENVF" ] || printf 'export E=%s\n' "/Users/hanseongmin/opsloop-repo/docs/evidence/$(date +%F)-retest-failover-stop" > "$ENVF"
source "$ENVF"; mkdir -p "$E"/{pre,raw,check,post,screens,tools}
cp -p /Users/hanseongmin/opsloop-work/retest/failover-stop/{db-sample.sh,sampler.sh,client-addr.py,db-links-summary.py,compare-stop.py} "$E/tools/"
(cd "$E/tools" && shasum -a 256 db-sample.sh sampler.sh client-addr.py db-links-summary.py compare-stop.py > SHA256SUMS)
cd /Users/hanseongmin/opsloop-repo || exit 1
h=$(date +%H%M); if { [ "$h" -ge 1445 ] && [ "$h" -lt 1640 ]; } || { [ "$h" -ge 245 ] && [ "$h" -lt 440 ]; }; then echo "!! 앞으로 100분 안에 백업 창(04:25~04:40 · 16:25~16:40)이 든다. 멈춤"; exit 1; fi
SSH="ssh -F $HOME/.ssh/config.opsloop"
{
echo "== 시각 $(date '+%F %T %Z') (백업 창과 겹치지 않음)"
echo "== 저장소"; git rev-parse HEAD 'HEAD^{tree}' '0d09fc7^{tree}'; git diff --quiet 0d09fc7 HEAD && echo "트리 = 0d09fc7"; git status --porcelain -- infra/vmware/failover infra/vmware/haproxy infra/vmware/scripts/console-join.sh; git diff --stat 907040b 0d09fc7 -- infra/vmware/failover infra/vmware/haproxy
echo "== HAProxy 설정 배포본 · 저장소"; $SSH fw 'sha256sum /etc/haproxy/haproxy.cfg; grep -nE "timeout connect|default-server|option redispatch|log-health-checks" /etc/haproxy/haproxy.cfg'; shasum -a 256 infra/vmware/haproxy/haproxy.cfg
echo "== 서버 상태 (운영 · 관리)"; $SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ {print $4, "운영", $6, "관리", $7}'
echo "== 통계"; $SSH fw 'curl -fsS "http://127.0.0.1:8404/;csv"' | cut -d, -f1,2,18 | grep '^consoles'
echo "== VM"; "/Applications/VMware Fusion.app/Contents/Library/vmrun" list
echo "== 겹치는 작업"; $SSH data01 'sudo -n docker ps -a --format "{{.Names}} {{.Status}}"' | grep -E 'drill' || echo "훈련 컨테이너 없음"
"$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --status; shasum -a 256 infra/vmware/scripts/console-watch.sh "$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh"
} 2>&1 | tee "$E/pre/state-before.txt"
{
echo "== $(date '+%F %T %Z') 저장소 0d09fc7 파일 해시"; for f in live.py targets.py main.py auth.py; do printf '%s  /app/%s\n' "$(git show 0d09fc7:app/$f | shasum -a 256 | cut -d' ' -f1)" "$f"; done
echo "== console-a"; $SSH console-a 'docker image inspect -f "{{.Id}}" opsloop-api:latest; docker inspect -f "{{.State.Status}} {{.HostConfig.RestartPolicy.Name}} {{.State.StartedAt}}" opsloop-api; docker exec opsloop-api printenv OPSLOOP_WORKER; docker exec opsloop-api sha256sum /app/live.py /app/targets.py /app/main.py /app/auth.py; docker exec opsloop-api grep -c "def db_settings" /app/live.py'
echo "== DB 쪽 5432 소켓"; $SSH data01 'pid=$(sudo -n docker inspect -f "{{.State.Pid}}" opsloop-db); sudo -n nsenter -t $pid -n ss -tnoH state established "( sport = :5432 )"' | grep -E '192\.168\.50\.1[12]:'
echo "== client_addr (조회: console-a)"; $SSH console-a 'docker exec -i -w /app opsloop-api python3 -' < "$E/tools/client-addr.py"
} 2>&1 | tee "$E/pre/a-before.txt"
$SSH data01 'sudo -n docker exec -i -e PGOPTIONS=--default_transaction_read_only=on opsloop-db psql -U opsloop_backup -d opsloop -v ON_ERROR_STOP=1 -At -F " | "' <<'SQL' 2>&1 | tee "$E/pre/db-before.txt"
SELECT 'now', now();
SELECT 'opsloop_console 한도', rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console';
SELECT 'opsloop_console 접속', coalesce(nullif(application_name, ''), '(none)'), count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = 'opsloop_console' GROUP BY 2 ORDER BY 2;
SELECT '마이그레이션 #59 · #63 · #77', (SELECT count(*) FROM information_schema.columns WHERE table_name = 'console_users' AND column_name IN ('disabled_at', 'updated_at')), (SELECT count(*) FROM pg_proc WHERE proname IN ('console_account_set', 'console_account_create', 'console_account_delete', 'console_account_password')), (SELECT count(*) FROM information_schema.columns WHERE table_name = 'blocklist' AND column_name = 'points');
SELECT '판정 · 조치 · 차단 · 활성 차단', (SELECT count(*) FROM verdicts), (SELECT count(*) FROM actions), (SELECT count(*) FROM blocklist), (SELECT count(*) FROM blocklist WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > now()));
SELECT 'failover-probe 행', count(*) FROM console_users WHERE username = 'failover-probe';
SELECT 'failover-probe', role, disabled_at IS NULL AS active, updated_at FROM console_users WHERE username = 'failover-probe';
SQL
rm -f "$E/db-links.stop"
nohup "$E/tools/sampler.sh" "$E/db-links.tsv" "$E/db-links.stop" 10800 > "$E/pre/sampler.out" 2>&1 &
echo "== DB 연결 표본 시작(백그라운드, 마무리 스크립트가 멈춘다) · 25초 뒤 확인"; sleep 25; tail -n 2 "$E/db-links.tsv"
infra/vmware/scripts/console-join.sh > "$E/pre/join-dryrun.txt" 2>&1; echo "== B 합류 드라이런: $(tail -n 1 "$E/pre/join-dryrun.txt")"
echo
grep -q "failover-probe 행 | 1" "$E/pre/db-before.txt" && grep -q "failover-probe | viewer | t" "$E/pre/db-before.txt" && echo ">>> 프로브 계정 있음 · 활성. 다음은 f2-join.sh" || echo ">>> 프로브 계정이 없거나 비활성: 콘솔 /accounts 에서 'failover-probe' 를 조회자로 추가(비밀번호는 쓰지 않을 12자 이상 아무 값) 또는 재활성한 뒤 f2-join.sh"
echo "== f1 끝 $(date '+%H:%M:%S')"
