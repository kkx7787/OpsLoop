#!/usr/bin/env bash
# 장애 전환 재측정 21 · 23 ~ 27단계(검토 반영판): 묶음 · 지난 회차 비교 → [A 살아 있음 확인] → 콘솔 B 떼기 → 끝 상태 판정 · 표본 멈춤 → 쿠키 · 점검 창 정리 → [스크린샷] → 정리 확인 · 비밀값 검사 · 해시
set -u
source /Users/hanseongmin/opsloop-work/retest/failover-stop.env; cd /Users/hanseongmin/opsloop-repo || exit 1
SSH="ssh -F $HOME/.ssh/config.opsloop"
h=$(date +%H%M); if { [ "$h" -ge 1615 ] && [ "$h" -lt 1640 ]; } || { [ "$h" -ge 415 ] && [ "$h" -lt 440 ]; }; then echo '!! 백업 창 근처. 16:40(04:40) 뒤에'; exit 1; fi
case "$(grep -E '^== [0-9-]+ [0-9:]+ KST 백업 (시작|성공|실패)' ~/opsloop-backup/backup.log | tail -n 1)" in *'백업 시작'*) echo '!! 백업이 돌고 있다. 끝난 뒤에'; exit 1 ;; esac
python3 infra/vmware/failover/summarize.py "$E/raw" --out "$E" > "$E/summary.txt" 2>&1; rc=$?; cat "$E/summary.txt"; echo "종료 코드 $rc" | tee -a "$E/summary.txt"
python3 "$E/tools/compare-stop.py" "$E/results.json" docs/evidence/2026-09-26-failover/baseline/results.json docs/evidence/2026-09-26-failover/tuned/results.json 2>&1 | tee "$E/compare-stop.txt"
a=$($SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk '$4 == "console-a" {print $6, $7}')
ar=$($SSH console-a 'docker inspect -f "{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}" opsloop-api')
if [ "$a" != "2 0" ] || [ "$ar" != "true always" ]; then echo "!! console-a 가 운영 2 · 관리 0 · running always 가 아니다 ($a · $ar). B 를 떼지 않는다. 멈춘 회차를 먼저 되살린다"; exit 1; fi
infra/vmware/scripts/console-join.sh --leave > "$E/post/leave-dryrun.txt" 2>&1
echo "== 콘솔 B 떼기"; infra/vmware/scripts/console-join.sh --leave --apply 2>&1 | tee "$E/post/leave.log"
[ "${PIPESTATUS[0]}" = 0 ] || { echo '!! 떼기 실패. console-join.sh --leave --step <실패 단계> --apply 로 마친 뒤 알려 주세요. 표본 · 쿠키 · 점검 창은 그대로 두었다'; exit 1; }
sleep 35
{
echo "== 끝 상태 $(date '+%F %T %Z')"
$SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ {print $4, "운영", $6, "관리", $7}'
$SSH fw 'curl -fsS "http://127.0.0.1:8404/;csv"' | cut -d, -f1,2,18 | grep '^consoles'
"/Applications/VMware Fusion.app/Contents/Library/vmrun" list
$SSH fw 'sha256sum /etc/haproxy/haproxy.cfg'
$SSH console-a 'docker inspect -f "{{.State.Status}} {{.HostConfig.RestartPolicy.Name}} {{.State.StartedAt}}" opsloop-api'
echo "-- client_addr (조회: console-a)"; $SSH console-a 'docker exec -i -w /app opsloop-api python3 -' < "$E/tools/client-addr.py"
echo "-- 표본 마지막 3줄"; tail -n 3 "$E/db-links.tsv"
} 2>&1 | tee "$E/post/state-after.txt"
ST="$E/post/state-after.txt"
grep -qF 'console-a 운영 2 관리 0' "$ST" && grep -qF 'console-b 운영 0 관리 1' "$ST" && grep -qF 'consoles,console-b,MAINT' "$ST" && ! grep -qF opsloop-console-b.vmx "$ST" && echo "끝 상태 기대대로 (A 2 0 · B 0 1 MAINT · B VM 꺼짐)" || echo "!! 끝 상태가 기대와 다르다 · 아래 정리는 계속하고 알려 주세요"
touch "$E/db-links.stop"; sleep 12
$SSH data01 'sudo -n docker exec -i -e PGOPTIONS=--default_transaction_read_only=on opsloop-db psql -U opsloop_backup -d opsloop -v ON_ERROR_STOP=1 -At -F " | "' <<'SQL' 2>&1 | tee "$E/post/db-after.txt"
SELECT 'now', now();
SELECT 'opsloop_console 접속', coalesce(nullif(application_name, ''), '(none)'), count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = 'opsloop_console' GROUP BY 2 ORDER BY 2;
SELECT '판정 · 조치 · 차단 · 활성 차단', (SELECT count(*) FROM verdicts), (SELECT count(*) FROM actions), (SELECT count(*) FROM blocklist), (SELECT count(*) FROM blocklist WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > now()));
SELECT 'failover-probe', role, disabled_at IS NULL AS active, updated_at FROM console_users WHERE username = 'failover-probe';
SQL
python3 "$E/tools/db-links-summary.py" "$E/raw" "$E/db-links.tsv" 2>&1 | tee "$E/db-links-summary.txt"
python3 infra/vmware/failover/probe_http.py --drop-cookie; "$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --resume
read -r -p ">>> 화면 갈무리를 docs/evidence/…/screens/ 에 넣을 거면 넣고 Enter (없으면 그냥 Enter): " _
{
echo "== 정리 확인 $(date '+%F %T %Z')"
test -e ~/.config/opsloop/probe-cookie && echo "쿠키 파일 남음" || echo "쿠키 파일 없음"
"$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --status
pgrep -fl '[p]robe_http.py|[p]robe_ws.py|[c]ollect_fw.sh|[s]ampler.sh' || echo "남은 도구 · 표본 프로세스 없음"
$SSH fw "pgrep -fa '[b]ash -s -- /var/log/haproxy.log' || echo '방화벽 수집 루프 없음'"
lsof -nP -iTCP:8404 -sTCP:LISTEN || echo "8404 터널 없음"
} 2>&1 | tee "$E/post/cleanup.txt"
cd "$E" && { grep -rlE 'opsloop_session=|[A-Za-z0-9_-]{8,}\.[0-9a-f]{32}|postgresql://[^ ]*:[^ @]*@|SESSION_SECRET=|DB_PASSWORD=|WEBHOOK_URL=' . && echo "!! 위 파일에 비밀값 모양 · 해시하지 않음"; } || { find . -type f ! -path ./SHA256SUMS ! -name db-links.stop -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS && echo "비밀값 검사 통과 · 해시 $(wc -l < SHA256SUMS)개"; }
echo "== f5b 끝 $(date '+%H:%M:%S')"
