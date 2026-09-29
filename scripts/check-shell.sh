#!/usr/bin/env bash
# 저장소의 셸 스크립트를 shellcheck 로 정적 점검한다 (이슈 #62). 경고가 하나도 없어야 통과다.
#   대상: 추적 중인 *.sh 전부와, 첫 줄이 sh · bash shebang 인 추적 파일(cti/opsloop-cti 등).
#   기준: shellcheck 기본 수준(참고까지 센다). 의도한 모양은 그 줄 바로 위에
#     '# shellcheck disable=SCxxxx  # 이유' 로 남긴다. 남긴 목록과 이유는 infra/vmware/README.md '셸 스크립트 점검' 절.
#   읽기만 한다. 파일을 고치지 않고 원격 · VM 에 닿지 않는다.
# 사용 (저장소 안 어디서든):
#   scripts/check-shell.sh              점검 (2026-09-29 shellcheck 0.11.0 에서 경고 0)
#   scripts/check-shell.sh -f gcc       그 밖의 인자는 shellcheck 옵션으로 넘긴다 (-f gcc 는 한 줄 꼴)
#   scripts/check-shell.sh --list       대상 파일만 찍는다
# 종료 코드: 0 경고 없음 · 1 경고 있음 · 2 shellcheck 없음 · 대상 없음 · 실행 실패
# 설치: brew install shellcheck (Mac) · sudo apt-get install -y shellcheck (Ubuntu)
set -euo pipefail

case "${1:-}" in
  -h | --help)
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit 0 ;;
esac

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null) || { echo "git 저장소 안에서 돌린다" >&2; exit 2; }
cd "$ROOT"

# 대상 모으기. 이름에 공백 · 한글이 있어도 되게 NUL 로 나눈다 (Mac 의 bash 3.2 에는 mapfile 이 없다)
FILES=()
while IFS= read -r -d '' f; do
  [ -f "$f" ] && FILES+=("$f")
done < <(git ls-files -z -- '*.sh')
SHEBANG='^#![[:space:]]*[^[:space:]]*[/]((env[[:space:]]+)?(ba)?sh)([[:space:]]|$)'
while IFS= read -r -d '' f; do
  case "$f" in *.sh) continue ;; esac
  [ -f "$f" ] || continue
  first=
  IFS= read -r -n 128 first < "$f" 2>/dev/null || true
  [[ $first =~ $SHEBANG ]] && FILES+=("$f")
done < <(git ls-files -z)
[ ${#FILES[@]} -gt 0 ] || { echo "대상 셸 스크립트가 없다" >&2; exit 2; }

if [ "${1:-}" = --list ]; then
  printf '%s\n' "${FILES[@]}"
  exit 0
fi

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck 가 없다. 설치: brew install shellcheck (Mac) · sudo apt-get install -y shellcheck (Ubuntu)" >&2
  exit 2
fi
VER=$(shellcheck --version 2>/dev/null | sed -n 's/^version: //p')

rc=0
shellcheck "$@" "${FILES[@]}" || rc=$?
case $rc in
  0) echo "셸 점검: ${#FILES[@]}개 파일 · 경고 0 (shellcheck ${VER:-?})" ;;
  1) echo "셸 점검: 경고가 있다 (${#FILES[@]}개 파일 · shellcheck ${VER:-?}). 고치거나, 의도한 모양이면 그 줄 위에 이유와 함께 disable" >&2
     exit 1 ;;
  *) echo "셸 점검: shellcheck 가 실패했다 (종료 $rc)" >&2
     exit 2 ;;
esac
