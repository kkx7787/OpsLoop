#!/usr/bin/env bash
# 통합 재측정 3 · 4단계: 차단 관측(읽기, 해제까지 계속) → [사용자: 콘솔에서 차단] → 내부 방화벽 적용 · 관문 미요청 → 차단 효과 → 거부 로그 · verify.sh → #77 대조
set -u
cd /Users/hanseongmin/opsloop-repo || exit 1
E=$(ls -d docs/evidence/*-retest-integration | tail -1)
SSH="ssh -F $HOME/.ssh/config.opsloop"
nohup $SSH console-a "docker exec -i -e ACTOR=203.0.113.10 -e TIMEOUT=3600 -w /app opsloop-api python3 -" < "$E/tools/probe_block.py" > "$E/c-probe-block.out" 2>&1 &
nohup $SSH fw 'p=x; seen=0; end=$(( $(date +%s) + 3600 )); while [ "$(date +%s)" -lt "$end" ]; do n=$(sudo -n nft -j list set inet filter opsloop_block | grep -c "\"203.0.113.10\""); if [ "$n" != "$p" ]; then echo "$(date -u +%FT%T.%3NZ) 203.0.113.10 집합 $n"; p=$n; fi; [ "$n" = 1 ] && seen=1; if [ "$seen" = 1 ] && [ "$n" = 0 ]; then break; fi; sleep 1; done' > "$E/c-fw-poll.out" 2>&1 &
for i in $(seq 1 30); do grep -q '집합 0' "$E/c-fw-poll.out" 2>/dev/null && grep -q '^T0' "$E/c-probe-block.out" 2>/dev/null && break; sleep 1; done
head -2 "$E/c-probe-block.out"; cat "$E/c-fw-poll.out"
if grep -q Traceback "$E/c-probe-block.out"; then echo "!! 차단 탐침 오류 — 차단하지 말고 알려 주세요"; exit 1; fi
echo
echo ">>> 이제 콘솔에서 차단하세요: 인시던트 → 203.0.113.10 의 R102 상세 → '차단' → 만료 '1시간' · '허니팟 관문에서도 막기' 꺼진 채 → '차단 확정'"
echo ">>> 이어서 R102 · R105 두 건을 '양성 정탐'(사유: 의도한 통합 재시험)으로 판정하세요"
read -r -p ">>> 차단 확정을 누른 뒤 Enter: " _
echo "Enter 시각 $(date '+%H:%M:%S')"
echo "== 내부 방화벽 집합에 들어가기를 기다린다 (최대 300초)"
for i in $(seq 1 300); do grep -q '집합 1' "$E/c-fw-poll.out" && break; sleep 1; done
cat "$E/c-fw-poll.out"
echo "== 내부 방화벽 보고 확인(confirmed)을 기다린다 (최대 180초)"
for i in $(seq 1 180); do grep -q 'confirmed' "$E/c-probe-block.out" && break; sleep 1; done
grep -m3 -n 'released_at": null' "$E/c-probe-block.out" | cut -c1-300
$SSH data01 'sudo -n opsloop-enforcer list' 2>/dev/null | python3 -c 'import json, sys; d = json.load(sys.stdin); print("관문 목록에 203.0.113.10", any(e["ip"] == "203.0.113.10" for e in d["entries"]), "· 내부 방화벽 목록에", any(e["ip"] == "203.0.113.10" for e in d["points"]["fw"]["entries"]))' | tee "$E/c-list-membership.txt"
echo "== 차단 효과 (공격자 → web-01 새 연결)"
$SSH attacker 'printf "%s " "$(date -u +%FT%T.%3NZ)"; curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total}s\n" http://192.168.50.21/ || echo "시간 초과 (curl 종료 $?)"' | tee "$E/c-blocked-curl.out"
echo "== 거부 로그 · verify.sh (차단 중)"
$SSH fw 'sudo -n journalctl -k --since "-10 min" --no-pager | grep fw-block-drop | grep "SRC=203.0.113.10" | tail -5' > "$E/c-fw-drop-log.txt"; wc -l < "$E/c-fw-drop-log.txt"
infra/vmware/scripts/verify.sh > "$E/c-verify-blocked.txt" 2>&1; tail -1 "$E/c-verify-blocked.txt"
echo "== #77 통합 대조"
P=d
$SSH console-a "docker exec -i -w /app opsloop-api python3 -" < "$E/tools/compare77_db.py" > "$E/$P-db.json"
$SSH data01 'sudo -n opsloop-enforcer list' > "$E/$P-enforcer-list.json" 2> "$E/$P-enforcer-list.err"
$SSH data01 'sudo -n opsloop-enforcer status' > "$E/$P-enforcer-status.txt" 2>&1
$SSH fw 'sudo -n nft -j list set inet filter opsloop_block' > "$E/$P-fw-set.json"
$SSH fw 'sudo -n cat /var/lib/opsloop-block-sync/status.json' > "$E/$P-fw-status.json"
python3 "$E/tools/compare77_local.py" "$E" $P > "$E/$P-compare.txt" 2>&1; tail -3 "$E/$P-compare.txt"
echo ">>> 지금 30초 안에 대시보드 '활성 차단 요청' 칸 · 차단 목록 화면 위 칸들 · 203.0.113.10 행의 지점 칸을 갈무리해 채팅에 올려 주세요"
echo "== 3 · 4단계 끝 $(date '+%H:%M:%S') (관측 두 개는 해제까지 계속 돈다)"
