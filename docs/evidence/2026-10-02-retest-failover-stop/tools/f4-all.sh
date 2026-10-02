#!/usr/bin/env bash
# 회차 3 ~ 6 을 차례로 돈다(회차 2 는 10:04 에 끝남). 한 회차라도 문턱 미달 · 중단이면 거기서 멈춘다
set -u
source /Users/hanseongmin/opsloop-work/retest/failover-stop.env
W=/Users/hanseongmin/opsloop-work/retest/failover-stop
# 회차 안의 ssh 가 표준 입력을 읽지 않도록 각 회차는 /dev/null 을 입력으로 받는다
for spec in "v03-stop-a console-a stop" "v04-kill-a console-a kill" "v05-kill-b console-b kill" "v06-kill-a console-a kill"; do
  set -- $spec
  bash "$W/f4b-round.sh" "$1" "$2" "$3" < /dev/null || { echo "!! $1 에서 멈춤"; exit 1; }
done
echo "== 회차 3 ~ 6 모두 끝 $(date '+%H:%M:%S') · 돈 회차: $(ls "$E/raw" | tr '\n' ' ')"
