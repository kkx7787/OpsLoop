#!/usr/bin/env bash
# 통합 재측정 5 ~ 8단계: 재접속 감시 → [사용자: 해제] → 해제 → 재접속 · 집합에서 빠짐 → 사후 확인 · verify.sh → [사용자: Teams 켜기] → 켜짐 · 늦은 발송 없음 → 흔적 정리 확인
set -u
cd /Users/hanseongmin/opsloop-repo || exit 1
E=$(ls -d docs/evidence/*-retest-integration | tail -1)
S=$(sed -n 's/^T0_EPOCH=//p' "$E/a-t0.txt"); SINCE=$(sed -n 's/^T0_UTC=//p' "$E/a-t0.txt")
SSH="ssh -F $HOME/.ssh/config.opsloop"
h=$(date +%H%M); if { [ "$h" -ge 1615 ] && [ "$h" -lt 1640 ]; } || { [ "$h" -ge 415 ] && [ "$h" -lt 440 ]; }; then echo "!! 백업 창 근처라 16:40(04:40) 뒤에 다시 실행하세요"; exit 1; fi
nohup $SSH attacker 'echo "감시 시작 $(date -u +%FT%T.%3NZ)"; end=$(( $(date +%s) + 300 )); while [ "$(date +%s)" -lt "$end" ]; do c=$(curl -s -o /dev/null --connect-timeout 1 -m 2 -w "%{http_code}" http://192.168.50.21/); if [ "$c" = 200 ]; then echo "$(date -u +%FT%T.%3NZ) 다시 열림 200"; exit 0; fi; sleep 1; done; echo "300초 안에 열리지 않음"' > "$E/e-reopen.out" 2>&1 &
W=$!
for i in $(seq 1 20); do grep -q '감시 시작' "$E/e-reopen.out" 2>/dev/null && break; sleep 1; done
cat "$E/e-reopen.out"
echo
echo ">>> 콘솔 차단 목록 화면에서 203.0.113.10 행의 '해제' → 확정 하세요 (admin)"
read -r -p ">>> 해제를 누른 뒤 Enter: " _
echo "Enter 시각 $(date '+%H:%M:%S')"
wait $W; cat "$E/e-reopen.out"
echo "== 차단 관측이 끝나기를 기다린다 (집행 기록이 빈 뒤 30초, 최대 600초)"
for i in $(seq 1 600); do grep -q '== 감사' "$E/c-probe-block.out" && break; sleep 1; done
tail -n 3 "$E/c-fw-poll.out"; tail -n 6 "$E/c-probe-block.out" | head -3 | cut -c1-300; sed -n '/== 감사/,$p' "$E/c-probe-block.out" | cut -c1-260
echo "== 사후 DB · 집행기 · 기록"
$SSH data01 'sudo -n docker exec -i -e PGOPTIONS=--default_transaction_read_only=on opsloop-db psql -X -v ON_ERROR_STOP=1 -U opsloop_backup -d opsloop -At -F " | "' > "$E/f-rule-quality.txt" 2>&1 <<SQL
SELECT now();
SELECT rule_id, rule_version, incidents, judged, threats, non_actionable, benign_positives FROM rule_quality WHERE rule_id IN ('R102', 'R105') ORDER BY 1, 2;
SELECT 'is_test_source 사건', count(*) FROM incidents WHERE is_test_source(actor_ip);
SELECT '시험 사건', incident_key, status, (SELECT verdict FROM verdicts v WHERE v.incident_key = i.incident_key ORDER BY created_at DESC, id DESC LIMIT 1) FROM incidents i WHERE actor_ip = '203.0.113.10' AND created_at >= to_timestamp($S);
SELECT host(actor_ip), points, released_at, expires_at, enforced_at, enforcement FROM blocklist WHERE actor_ip = '203.0.113.10';
SQL
cat "$E/f-rule-quality.txt" | cut -c1-250
$SSH data01 'sudo -n opsloop-enforcer status' > "$E/f-enforcer-status.txt" 2>&1
$SSH console-a "docker exec -i -w /app opsloop-api python3 -" < "$E/tools/compare77_db.py" > "$E/f-db.json"
$SSH data01 "sudo -n journalctl -u opsloop-enforcer --since @$S --no-pager -o short-iso-precise" > "$E/f-enforcer-journal.txt"
$SSH fw "sudo -n journalctl -u opsloop-block-sync --since @$S --no-pager -o short-iso-precise" > "$E/f-fw-sync-journal.txt"
cat "$E/f-enforcer-status.txt"; grep -n 'nft add 1 · replace 0 · del 0\|nft add 0 · replace 0 · del 1' "$E/f-fw-sync-journal.txt" | cut -c1-200
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("띠", d["monitor"] or "없음"); print("살아 있는 집행 대상", [(x["ip"], x["points"]) for x in d["live"]])' "$E/f-db.json"
echo "== verify.sh (해제 뒤)"
infra/vmware/scripts/verify.sh > "$E/f-verify.txt" 2>&1; grep -E "차단 전|차단 뒤" "$E/f-verify.txt"; tail -1 "$E/f-verify.txt"
echo "== Teams 켜기 전 확인"
$SSH console-a "docker exec -i -e SINCE=$SINCE -w /app opsloop-api python3 -" < "$E/tools/notify_state.py" > "$E/n4-before-on.txt"
sed -n '/지금 켜면 보낼 새 사건/,/보내지 않는 사건 범위/p' "$E/n4-before-on.txt" | cut -c1-220
echo
echo ">>> 위 세 '지금 켜면 보낼 …' 이 모두 (없음)이면, 알림 화면에서 'Teams 관제' 의 '사용' 스위치를 켜세요. (없음)이 아니면 켜지 말고 Ctrl-C 후 알려 주세요"
read -r -p ">>> 켠 뒤 Enter: " _
echo "Enter 시각 $(date '+%H:%M:%S') · 90초 뒤 켜짐 · 늦은 발송 없음 확인"
sleep 95
$SSH console-a "docker exec -i -e SINCE=$SINCE -w /app opsloop-api python3 -" < "$E/tools/notify_state.py" > "$E/n5-on.txt"
grep -E "'enabled'|console.notify|꺼져 있다" "$E/n5-on.txt" | cut -c1-220; sed -n '/범위 안 발송 이력/,/==/p' "$E/n5-on.txt" | cut -c1-200
echo "== 운영 흔적 정리 확인"
{ echo '== 콘솔 A 컨테이너 안 탐침(python3 -) 수'; $SSH console-a 'docker top opsloop-api' | grep -c 'python3 -'; echo '== fw 집합 감시 반복'; $SSH fw 'pgrep -af "[o]psloop_block" || echo 없음'; echo '== fw 집합의 203.0.113.10 원소 수'; $SSH fw 'sudo -n nft -j list set inet filter opsloop_block' | grep -c '"203.0.113.10"'; } 2>&1 | tee "$E/z-cleanup.txt"
echo "== 5 ~ 8단계 끝 $(date '+%H:%M:%S')"
