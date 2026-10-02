#!/usr/bin/env bash
# 404 시험 첫 실행 실패 재현 실행기. console/ 에서 vitest 를 정한 조건으로 되풀이하고 결과 JSON · 로그를 raw/ 에 남긴다.
# 사용: BUILD_OUT=<저장소 밖 폴더> [BURN=<개수>] run.sh <이름> <횟수> <방식> [vitest 인자...]
#   방식 file: router.test.tsx 만 · only: -t 로 404 시험만 · full: 전체 · full-build: 전체 + 2초 뒤 npm run build
#   BURN: 도는 동안 CPU 를 계속 쓰는 프로세스(yes > /dev/null)를 이만큼 더 띄운다(추가 부하 조건, 기본 0)
# full · full-build 는 매 회 첫 실행과 같은 파일 순서의 결과 캐시(raw/order-cache.json)를 넣고 돈다.
# 빌드 산출물은 app/static 대신 BUILD_OUT 에 낸다(검토 때 빌드도 /tmp 로 냈다).
set -u
C=/Users/hanseongmin/opsloop-repo/console
R=$(cd "$(dirname "$0")" && pwd)
RAW=$R/raw
CACHE=$C/node_modules/.vite/vitest/da39a3ee5e6b4b0d3255bfef95601890afd80709/results.json
TEST_NAME='없는 주소는 틀 안에서 404 화면'
now() { perl -MTime::HiRes=time -MPOSIX=strftime -e '$t=time; printf "%s.%03d\n", strftime("%H:%M:%S", localtime $t), ($t-int $t)*1000'; }
name=$1 n=$2 mode=$3
shift 3
cd "$C" || exit 1
for i in $(seq -w 1 "$n"); do
  tag=$name-$i
  case $mode in
    file) sel=(src/app/router.test.tsx) ;;
    only) sel=(src/app/router.test.tsx -t "$TEST_NAME") ;;
    full | full-build) sel=(); cp "$RAW/order-cache.json" "$CACHE" ;;
    *) echo "방식 모름: $mode" >&2; exit 2 ;;
  esac
  load=$(sysctl -n vm.loadavg | awk '{print $2}')
  bp= burn=()
  # macOS seq 1 0 은 1 0 을 내므로 0 이면 건너뛴다
  if [ "${BURN:-0}" -gt 0 ]; then for _ in $(seq 1 "$BURN"); do yes > /dev/null & burn+=($!); done; fi
  if [ "$mode" = full-build ]; then
    (sleep 2; s=$(now); npm run build -- --outDir "${BUILD_OUT:?}/$tag" --emptyOutDir > "$RAW/$tag.build.log" 2>&1; rc=$?
     printf '%s\t%s\t%s\n' "$s" "$(now)" "$rc" > "$RAW/$tag.build.time") &
    bp=$!
  fi
  s=$(now)
  DEBUG_PRINT_LIMIT=100000 npm test -- "${sel[@]}" "$@" --reporter=dot --reporter=json --outputFile.json="$RAW/$tag.json" > "$RAW/$tag.log" 2>&1
  rc=$?
  e=$(now)
  [ -n "$bp" ] && wait "$bp"
  [ ${#burn[@]} -gt 0 ] && kill "${burn[@]}" 2>/dev/null
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$mode" "$*" "$s" "$e" "$rc" "$load" "${BURN:-0}" >> "$RAW/runs.tsv"
  echo "$tag rc=$rc $s~$e"
done
