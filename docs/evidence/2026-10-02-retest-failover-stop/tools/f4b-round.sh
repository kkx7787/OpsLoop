#!/usr/bin/env bash
# 장애 전환 재측정 한 회차(14 ~ 16단계, 검토 반영판): 문턱 → 측정 300초(30초 뒤 주입 · 150초 뒤 복귀) → 복귀 확인 → 판정 · DB 연결 표본 요약
# 사용: f4b-round.sh <회차 이름> <console-a|console-b> <stop|kill>    예) f4b-round.sh v02-stop-b console-b stop
# Ctrl-C 로 멈추면 주입 뒤였을 때 대상 컨테이너를 되살리고 끝낸다
set -u
N=${1:?회차 이름}; T=${2:?대상}; SC=${3:?stop 또는 kill}
case "$SC" in stop) ACT='docker stop opsloop-api' ;; kill) ACT='docker kill opsloop-api' ;; *) echo "stop · kill 만"; exit 2 ;; esac
case "$T" in console-a) S=console-b ;; console-b) S=console-a ;; *) echo "console-a · console-b 만"; exit 2 ;; esac
case "$N" in v[0-9][0-9]-"$SC"-"${T#console-}") ;; *) echo "!! 회차 이름 $N 이 $SC · $T 와 맞지 않는다 (예: v05-kill-b console-b kill)"; exit 2 ;; esac
source /Users/hanseongmin/opsloop-work/retest/failover-stop.env; cd /Users/hanseongmin/opsloop-repo || exit 1
SSH="ssh -F $HOME/.ssh/config.opsloop"; R="$E/raw/$N"
[ -e "$R/marks.jsonl" ] && { echo "!! $N 은 이미 잰 회차다. 새 이름을 쓴다"; exit 2; }
h=$(date +%H%M); if { [ "$h" -ge 1618 ] && [ "$h" -lt 1640 ]; } || { [ "$h" -ge 418 ] && [ "$h" -lt 440 ]; }; then echo "!! 백업 창 근처. 16:40(04:40) 뒤에"; exit 1; fi
srv_ok() { [ "$($SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ && $6 == 2 && $7 == 0' | wc -l | tr -d ' ')" = 2 ]; }
caffeinate -dims -w $$ &
mkdir -p "$R"
{
echo "== $N 문턱 $(date '+%F %T %Z') · 대상 $T · $SC"
$SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ {print $4, "운영", $6, "관리", $7}'
$SSH fw 'curl -fsS "http://127.0.0.1:8404/;csv"' | cut -d, -f1,2,18 | grep '^consoles'
tail -n 1 "$E/db-links.tsv"
"$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --status | grep -E '^(상태|점검 창):'
echo "-- client_addr (조회: $S)"; $SSH "$S" 'docker exec -i -w /app opsloop-api python3 -' < "$E/tools/client-addr.py"
} 2>&1 | tee -a "$E/run.log" "$R/before.txt"
if ! test -s ~/.config/opsloop/probe-cookie || ! srv_ok; then echo "!! 문턱 미달: 쿠키 파일이 없거나 두 서버가 운영 2 · 관리 0 이 아니다. 주입하지 않았다"; exit 1; fi
INJ=0
recover() { python3 infra/vmware/failover/mark.py "$R" recover --scenario "$SC" --target "$T" && $SSH "$T" 'docker start opsloop-api'; }
trap 'echo; echo "!! 중단 $(date +%T)"; kill $P1 $P2 $P3 $P4 2>/dev/null; if [ "$INJ" = 1 ]; then echo "   $T 를 되살린다"; recover; fi; echo "   이 회차 이름($N)은 다시 쓰지 않는다"; exit 130' INT TERM
echo "== 측정 시작 $(date '+%T') (약 5분 반. 30초 뒤 $T $SC, 150초 뒤 복귀)"
infra/vmware/failover/collect_fw.sh "$R" --duration 300 > "$R/collect_fw.out" 2>&1 & P1=$!
python3 infra/vmware/failover/probe_http.py --run-dir "$R" --duration 300 > "$R/probe_http.out" 2>&1 & P2=$!
python3 infra/vmware/failover/probe_ws.py --run-dir "$R" --mode browser --conns 4 --duration 300 > "$R/probe_ws_browser.out" 2>&1 & P3=$!
python3 infra/vmware/failover/probe_ws.py --run-dir "$R" --mode net --conns 4 --duration 300 > "$R/probe_ws_net.out" 2>&1 & P4=$!
sleep 30
if srv_ok && kill -0 $P2 $P3 $P4 2>/dev/null; then
  python3 infra/vmware/failover/mark.py "$R" inject --scenario "$SC" --target "$T" && { INJ=1; $SSH "$T" "$ACT"; }
  sleep 150
  recover && INJ=0
else
  echo "!! 주입 직전 문턱 미달(서버 상태 또는 프로브 종료). 주입하지 않았다"
fi
wait $P1 $P2 $P3 $P4; trap - INT TERM
echo "회차 끝 $(date '+%T')"
[ "$($SSH "$T" 'docker inspect -f "{{.State.Running}}" opsloop-api')" = true ] && echo "$T 컨테이너 돌고 있음" || echo "!! $T 컨테이너가 돌지 않는다. 되살리기: ssh -F ~/.ssh/config.opsloop $T 'docker start opsloop-api'"
sleep 20
{
echo "== $N 뒤 $(date '+%F %T %Z')"; ls "$R"; tail -n 2 "$R"/*.out
echo "-- client_addr (조회: $S)"; $SSH "$S" 'docker exec -i -w /app opsloop-api python3 -' < "$E/tools/client-addr.py"
$SSH fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock' | awk 'NF >= 7 && $1 !~ /^#/ {print $4, "운영", $6, "관리", $7}'
"$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --status | grep -E '^(상태|점검 창):'
python3 infra/vmware/failover/summarize.py "$R" --out "$E/check/$N"
python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); [print(r["run"], "대상 연결", e["ws"]["target_conns"], "미감지", e["ws"]["undetected"], "새 콘솔", sorted({str(c.get("new_console")) for c in e["ws"]["conns"] if c.get("state") == "감지"}), "실패", e["fail"]["count"], e["fail"]["by_error"], "성공 최대 ms", e["latency"]["ok_max_ms"], "복귀 UP", e["recover"]["up_s"]) for r in d["runs"] for e in r["episodes"]]' "$E/check/$N/results.json"
python3 "$E/tools/db-links-summary.py" "$E/raw" "$E/db-links.tsv"
} 2>&1 | tee -a "$E/run.log" "$R/after.txt"
echo "== $N 끝 $(date '+%H:%M:%S')"
