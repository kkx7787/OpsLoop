#!/usr/bin/env bash
# 재현 중 다른 부하를 3초마다 적는다: 시각 · 1분 부하 평균 · CPU 사용(사용자 · 시스템 · 유휴) · CPU 상위 5개 프로세스.
# 사용: sample-load.sh <출력 파일> (끝내려면 프로세스를 죽인다)
out=$1
while :; do
  t=$(date +%H:%M:%S)
  l=$(sysctl -n vm.loadavg | awk '{print $2}')
  snap=$(top -l 2 -s 1 -n 5 -o cpu -stats command,cpu 2>/dev/null)
  cpu=$(printf '%s\n' "$snap" | grep '^CPU usage' | tail -1 | sed 's/CPU usage: //')
  procs=$(printf '%s\n' "$snap" | awk '/^COMMAND/{n++; next} n==2 && NF{c=$NF; $NF=""; sub(/ +$/, ""); printf "%s(%s) ", $0, c}')
  printf '%s\tload1=%s\t%s\t%s\n' "$t" "$l" "$cpu" "$procs" >> "$out"
  sleep 2
done
