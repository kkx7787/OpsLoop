#!/usr/bin/env bash
# 통합 재측정 2단계: 요청 → 사건 탐침(읽기 전용, 백그라운드) + 공격 요청 8경로 + 결과 · 다리 기록 · Teams 미발송 확인
set -u
cd /Users/hanseongmin/opsloop-repo || exit 1
E=$(ls -d docs/evidence/*-retest-integration | tail -1)
S=$(sed -n 's/^T0_EPOCH=//p' "$E/a-t0.txt"); SINCE=$(sed -n 's/^T0_UTC=//p' "$E/a-t0.txt")
[ -f "$E/b-probe-detect.out" ] && mv "$E/b-probe-detect.out" "$E/b-probe-detect.err1.txt"
ssh -F ~/.ssh/config.opsloop data01 'systemctl list-timers opsloop-agents.timer --no-pager' > "$E/b-timer-phase.txt"
UA=opsloop-integration-$(date +%Y%m%d); TAG=opsloop-it-$(date +%m%d)
ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -e UA=$UA -e ACTOR=203.0.113.10 -w /app opsloop-api python3 -" < "$E/tools/probe_detect.py" > "$E/b-probe-detect.out" 2>&1 &
P=$!
sleep 6
head -1 "$E/b-probe-detect.out"
if grep -q Traceback "$E/b-probe-detect.out"; then echo "!! 탐침 오류 — 공격을 보내지 않고 멈춤"; kill $P 2>/dev/null; exit 1; fi
echo "== 공격 요청"
ssh -F ~/.ssh/config.opsloop attacker "UA=$UA TAG=$TAG bash -s" <<'SH' | tee "$E/b-attack.out"
echo "사전 $(date -u +%FT%T.%3NZ) GET / → $(curl -s -o /dev/null -m 5 -w '%{http_code} %{time_total}s' http://192.168.50.21/)"
s=$(( $(date +%s) % 600 )); if [ "$s" -ge 570 ]; then echo "R102 10분 창 경계 $((600 - s))초 전이라 넘긴 뒤 보낸다"; sleep $((602 - s)); fi
for p in confluence/rest/applinks/1.0/manifest hnap1/ confluence/ "$TAG/a" "$TAG/b" "$TAG/c" "$TAG/d" "$TAG/e"; do
  printf '%s ' "$(date -u +%FT%T.%3NZ)"; curl -s -o /dev/null -m 5 -A "$UA" -w "%{http_code} /$p\n" "http://192.168.50.21/$p"
done
SH
echo "== 사건을 기다린다 (보통 1~2분, 최대 15분)"
wait $P
sed -n '/== 탐지 실행/,$p' "$E/b-probe-detect.out"
ssh -F ~/.ssh/config.opsloop data01 "sudo -n journalctl -u opsloop-agents --since @$S --no-pager -o short-iso-precise" > "$E/b-agents-journal.txt"
ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -e SINCE=$SINCE -w /app opsloop-api python3 -" < "$E/tools/notify_state.py" > "$E/n3-after-detect.txt"
grep -n -A6 '범위 안 발송 이력' "$E/n3-after-detect.txt"
echo "== 2단계 끝 $(date '+%H:%M:%S')"
