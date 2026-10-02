#!/usr/bin/env bash
# 조사용 시험(micro.test.tsx)을 되풀이한다. 결과는 ../raw/micro-<이름>.jsonl(시험마다 한 줄), 로그는 ../raw/micro-<이름>-<회>.log.
# 사용: [BURN=<개수>] [MICRO_MODE=<확인 방법>] micro.sh <이름> <횟수>   (BURN: 도는 동안 yes > /dev/null 을 이만큼 더 띄운다)
# 돌리려면 이 폴더에 node_modules → console/node_modules 연결이 있어야 한다(조사 끝에 지운다).
set -u
C=/Users/hanseongmin/opsloop-repo/console
M=$(cd "$(dirname "$0")" && pwd)
RAW=$M/../raw
name=$1 n=$2
cd "$C" || exit 1
burn=()
if [ "${BURN:-0}" -gt 0 ]; then for _ in $(seq 1 "$BURN"); do yes > /dev/null & burn+=($!); done; fi
trap '[ ${#burn[@]} -gt 0 ] && kill "${burn[@]}" 2>/dev/null' EXIT
sleep 1
for i in $(seq -w 1 "$n"); do
  MICRO_OUT=$RAW/micro-$name.jsonl DEBUG_PRINT_LIMIT=100000 npx vitest run --config "$M/vitest.micro.config.mts" --root "$C" --dir "$M" --reporter=dot > "$RAW/micro-$name-$i.log" 2>&1
  echo "micro-$name-$i rc=$?"
done
