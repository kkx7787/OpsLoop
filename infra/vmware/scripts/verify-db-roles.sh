#!/usr/bin/env bash
# DB 역할 분리 검증 · 격리 시험 2차 (이슈 #31).
#   데이터 노드 컨테이너 안(로컬 trust)에서 역할마다 범위 밖 문장이 거부되고 범위 안 문장은 되는지,
#   실제 접속이 어느 역할로 붙어 있는지, 관제 대상 노드에서 5432 가 막히는지 본다.
#   데이터를 바꾸지 않는다 (WHERE false · 읽기 · 권한 조회만).
# 사용 (Mac, 저장소 루트): infra/vmware/scripts/verify-db-roles.sh     종료 코드 0 = 전부 기대대로
set -uo pipefail
SSH=(ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes -o ConnectTimeout=10)
fail=0
row() { printf "  %-17s %-62s %-5s %s\n" "$@"; }
psql_as() { "${SSH[@]}" data01 "sudo -n docker exec opsloop-db psql -U $1 -d opsloop -qAtc \"$2\"" 2>&1; }
q() { # $1 역할  $2 문장  $3 기대(거부|허용)
  local out got
  out=$(psql_as "$1" "$2")
  if echo "$out" | grep -qE "permission denied|must be owner"; then got=거부
  elif echo "$out" | grep -qE "^ERROR|FATAL"; then got="오류($(echo "$out" | head -1 | cut -c8-50))"
  else got=허용; fi
  if [ "$got" = "$3" ]; then row "$1" "$2" "$3" "✔"; else row "$1" "$2" "$3" "✘ $got"; fail=1; fi
}
p() { # $1 역할  $2 has_*_privilege 식  $3 기대(t|f)  — 실행하지 않고 권한만 본다 (TRUNCATE 처럼 실행하면 안 되는 것)
  local got; got=$(psql_as opsloop "SELECT $2" | head -1)
  if [ "$got" = "$3" ]; then row "$1" "$2" "$3" "✔"; else row "$1" "$2" "$3" "✘ $got"; fail=1; fi
}

echo "== 역할별 문장 (데이터 노드 컨테이너 안)"
printf "  %-17s %-62s %-5s %s\n" 역할 문장 기대 결과
q opsloop_console  "DELETE FROM events WHERE false" 거부
q opsloop_console  "UPDATE events SET input='' WHERE false" 거부
q opsloop_console  "SELECT token_hash FROM nodes LIMIT 0" 거부
q opsloop_console  "SELECT token_hash FROM node_enrollments LIMIT 0" 거부
q opsloop_console  "UPDATE console_users SET role='admin' WHERE false" 거부
q opsloop_console  "INSERT INTO console_users SELECT * FROM console_users WHERE false" 거부
q opsloop_console  "ALTER TABLE events DISABLE TRIGGER trg_audit_append_only" 거부
q opsloop_console  "INSERT INTO incidents SELECT * FROM incidents WHERE false" 거부
p opsloop_console  "has_table_privilege('opsloop_console','actions','TRUNCATE')" f
q opsloop_console  "SELECT count(*) FROM audit_log" 허용
q opsloop_console  "SELECT count(*) FROM rule_quality" 허용
q opsloop_console  "INSERT INTO verdicts SELECT * FROM verdicts WHERE false" 허용
q opsloop_ingest   "INSERT INTO incidents SELECT * FROM incidents WHERE false" 거부
q opsloop_ingest   "SELECT token_hash FROM nodes LIMIT 0" 거부
q opsloop_ingest   "DELETE FROM events WHERE false" 거부
q opsloop_ingest   "INSERT INTO events SELECT * FROM events WHERE false" 허용
q opsloop_detector "INSERT INTO verdicts SELECT * FROM verdicts WHERE false" 거부
q opsloop_detector "INSERT INTO events SELECT * FROM events WHERE false" 거부
q opsloop_detector "UPDATE blocklist SET released_at = now() WHERE false" 거부
q opsloop_detector "INSERT INTO incidents SELECT * FROM incidents WHERE false" 허용
q opsloop_backup   "INSERT INTO events SELECT * FROM events WHERE false" 거부
q opsloop_backup   "SELECT count(*) FROM events" 허용
q opsloop_gate     "SELECT count(*) FROM events" 거부
q opsloop_gate     "SELECT count(*) FROM nodes WHERE token_hash IS NOT NULL" 허용

echo "== 지금 붙어 있는 접속 (역할 · application_name · 수)"
psql_as opsloop "SELECT usename || '  ' || app || '  ' || n FROM (SELECT usename, coalesce(nullif(application_name,''),'-') AS app, count(*) AS n FROM pg_stat_activity WHERE datname='opsloop' AND usename IS NOT NULL GROUP BY 1,2) t ORDER BY 1" 2>/dev/null | sed 's/^/  /'
if psql_as opsloop "SELECT count(*) FROM pg_stat_activity WHERE datname='opsloop' AND usename='opsloop' AND application_name NOT IN ('psql','')" | grep -qvx 0; then
  row 소유자 "opsloop 로 붙은 서비스 접속(psql 제외)" 0 "✘ 있음 — 아직 소유자로 붙는 구성요소가 있다"; fail=1
else
  row 소유자 "opsloop 로 붙은 서비스 접속(psql 제외)" 0 "✔"
fi

echo "== 네트워크: 5432 는 콘솔 · 데이터 노드만 (관제 대상 노드는 막힌다)"
net() { local got; if "${SSH[@]}" "$1" 'timeout 3 bash -c "</dev/tcp/192.168.60.11/5432" 2>/dev/null'; then got=열림; else got=막힘; fi
  if [ "$got" = "$2" ]; then row "$1" "192.168.60.11:5432" "$2" "✔"; else row "$1" "192.168.60.11:5432" "$2" "✘ $got"; fail=1; fi; }
net console-a 열림
net web01 막힘

if [ "$fail" = 0 ]; then echo "전부 기대대로"; else echo "기대와 다른 항목이 있다" >&2; exit 1; fi
