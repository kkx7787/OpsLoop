#!/usr/bin/env bash
# 4.1 단위 시험: 저장소의 파이썬 시험 파일을 하나씩 돌려 파일 · 종료 코드 · 시험 수 · 결과 · 시간을 탭으로 적는다.
# 시험 DB(postgres:16-alpine)를 새로 띄우고 끝나면 지운다. 저장소는 읽기 전용으로 붙인다.
set -u
S=/private/tmp/claude-501/-Users-hanseongmin-opsloop-repo/8537c94f-6d09-4120-82fa-7b4a115be6ba/scratchpad
OUT=$S/t41/py-results.tsv
docker network create opsloop-t41 >/dev/null
docker run -d --name opsloop-t41-pg --network opsloop-t41 -e POSTGRES_PASSWORD_FILE=/pw -v "$S/t58.pw":/pw:ro postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do docker exec opsloop-t41-pg pg_isready -q && break; sleep 1; done
cd /Users/hanseongmin/opsloop-repo || exit 1
FILES=$(git ls-files | grep -E '(^|/)test_[^/]*\.py$' | tr '\n' ' ')
docker run --rm --network opsloop-t41 -v /Users/hanseongmin/opsloop-repo:/repo:ro -w /repo -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$S/t58.pw":/pw:ro -v "$S/t52-pip":/root/.cache/pip -e FILES="$FILES" python:3.12-slim bash -c '
pip install -q --root-user-action=ignore -r app/requirements.txt psycopg2-binary boto3 httpx pyyaml >/dev/null 2>&1
export OPSLOOP_TEST_DATABASE_URL="postgresql://postgres:$(cat /pw)@opsloop-t41-pg:5432/postgres"
python3 --version >&2
for f in $FILES; do
  start=$(date +%s%N)
  out=$(timeout 900 python3 "$f" 2>&1); rc=$?
  ran=$(printf "%s\n" "$out" | grep -oE "^Ran [0-9]+ tests?" | tail -1 | grep -oE "[0-9]+")
  res=$(printf "%s\n" "$out" | grep -E "^(OK|FAILED)" | tail -1)
  printf "%s\t%s\t%s\t%s\t%s\n" "$f" "$rc" "${ran:-?}" "${res:-(출력 없음)}" "$(( ($(date +%s%N) - start) / 1000000 ))"
done' > "$OUT"
docker rm -f opsloop-t41-pg >/dev/null; docker network rm opsloop-t41 >/dev/null
echo "끝: $OUT"
