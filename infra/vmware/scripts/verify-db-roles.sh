#!/usr/bin/env bash
# DB 역할 분리 검증 · 격리 시험 2차 (이슈 #31).
#   데이터 노드 컨테이너 안(로컬 trust)에서 역할마다 범위 밖 문장이 거부되고 범위 안 문장은 되는지,
#   실제 접속이 어느 역할로 붙어 있는지, 관제 대상 노드에서 5432 가 막히는지 본다.
#   데이터를 바꾸지 않는다 (WHERE false · 읽기 · 권한 조회만).
#   CVE · KEV 연계(이슈 #39)의 수집기 역할(opsloop_cti)과 CTI 표 권한도 본다. infra/migrations/20260925_cti.sql 을
#   적용하고 cti/install-cti.sh 로 역할을 만든 뒤에 돌린다.
#   콘솔 역할의 접속 한도(이슈 #43, 30 이상)도 본다. infra/migrations/20260926_console_connlimit.sql 을 적용한 뒤에 돌린다.
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
q opsloop_detector "SELECT node_id, addr, registered_at FROM nodes LIMIT 0" 허용
q opsloop_detector "SELECT token_hash FROM nodes LIMIT 0" 거부
q opsloop_detector "INSERT INTO incidents SELECT * FROM incidents WHERE false" 허용
q opsloop_detector "UPDATE incidents SET status = status WHERE false" 거부
q opsloop_detector "UPDATE incidents SET last_ts = last_ts, evidence = evidence WHERE false" 허용
q opsloop_detector "SELECT incident_key FROM incidents WHERE false FOR UPDATE SKIP LOCKED" 허용
q opsloop_detector "INSERT INTO incident_absorbed SELECT * FROM incident_absorbed WHERE false" 허용
q opsloop_detector "UPDATE incident_absorbed SET kind = kind WHERE false" 거부
q opsloop_detector "SELECT count(*) FROM absorbed_blocks" 거부
q opsloop_console  "SELECT count(*) FROM incident_absorbed" 허용
q opsloop_console  "INSERT INTO incident_absorbed SELECT * FROM incident_absorbed WHERE false" 거부
q opsloop_console  "UPDATE absorbed_blocks SET released_at = now() WHERE false" 허용
q opsloop_console  "DELETE FROM absorbed_blocks WHERE false" 거부
# CVE · KEV 연계 (이슈 #39). 수집기는 원본 기록을 추가만 하고 CTI 표 밖은 규칙 정의 읽기뿐이다. 콘솔은 읽기만, 탐지 · 적재는 보지 못한다
#   수집기 줄은 권한 블록의 쓰기 권한을 표마다 빠짐없이 본다(받은 것은 허용, 받지 않은 것은 거부 · cti/test_cti_schema.py 가 대조한다).
#   적재 문장 INSERT … ON CONFLICT DO UPDATE 는 행이 없어도 INSERT · UPDATE 권한을 함께 본다
q opsloop_cti      "INSERT INTO cti_snapshots SELECT * FROM cti_snapshots WHERE false" 허용
q opsloop_cti      "UPDATE cti_snapshots SET error = error WHERE false" 거부
q opsloop_cti      "DELETE FROM cti_snapshots WHERE false" 거부
p opsloop_cti      "has_sequence_privilege('opsloop_cti','cti_snapshots_id_seq','USAGE')" t
q opsloop_cti      "INSERT INTO cti_kev SELECT * FROM cti_kev WHERE false ON CONFLICT (cve_id) DO UPDATE SET name = EXCLUDED.name" 허용
q opsloop_cti      "DELETE FROM cti_kev WHERE false" 허용
p opsloop_cti      "has_table_privilege('opsloop_cti','cti_kev','TRUNCATE')" f
q opsloop_cti      "INSERT INTO cti_cve SELECT * FROM cti_cve WHERE false ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss" 허용
q opsloop_cti      "DELETE FROM cti_cve WHERE false" 거부
q opsloop_cti      "INSERT INTO cti_osv SELECT * FROM cti_osv WHERE false ON CONFLICT (osv_id) DO UPDATE SET affected = EXCLUDED.affected" 허용
q opsloop_cti      "DELETE FROM cti_osv WHERE false" 거부
q opsloop_cti      "INSERT INTO cti_watch SELECT * FROM cti_watch WHERE false ON CONFLICT (cve_id) DO UPDATE SET record_found = EXCLUDED.record_found" 허용
q opsloop_cti      "DELETE FROM cti_watch WHERE false" 허용
q opsloop_cti      "INSERT INTO asset_inventory SELECT * FROM asset_inventory WHERE false ON CONFLICT (asset_id) DO UPDATE SET last_error = EXCLUDED.last_error" 허용
q opsloop_cti      "DELETE FROM asset_inventory WHERE false" 거부
q opsloop_cti      "INSERT INTO asset_vulnerabilities SELECT * FROM asset_vulnerabilities WHERE false" 허용
q opsloop_cti      "DELETE FROM asset_vulnerabilities WHERE false" 허용
q opsloop_cti      "UPDATE asset_vulnerabilities SET fix_state = fix_state WHERE false" 거부
q opsloop_cti      "SELECT rule_version, definition FROM rule_versions LIMIT 0" 허용
q opsloop_cti      "UPDATE rule_versions SET reason = reason WHERE false" 거부
q opsloop_cti      "SELECT node_id FROM nodes LIMIT 0" 거부
q opsloop_cti      "SELECT count(*) FROM events" 거부
q opsloop_cti      "SELECT count(*) FROM incidents" 거부
q opsloop_console  "SELECT 1 FROM cti_snapshots, cti_kev, cti_cve, cti_osv, cti_watch, asset_inventory, asset_vulnerabilities LIMIT 0" 허용
q opsloop_console  "INSERT INTO cti_kev SELECT * FROM cti_kev WHERE false" 거부
q opsloop_console  "UPDATE asset_inventory SET last_error = last_error WHERE false" 거부
q opsloop_console  "DELETE FROM cti_watch WHERE false" 거부
q opsloop_detector "SELECT count(*) FROM cti_kev" 거부
q opsloop_detector "SELECT count(*) FROM asset_vulnerabilities" 거부
q opsloop_ingest   "SELECT count(*) FROM cti_kev" 거부
q opsloop_backup   "SELECT 1 FROM cti_snapshots, cti_kev, cti_cve, cti_osv, cti_watch, asset_inventory, asset_vulnerabilities LIMIT 0" 허용
q opsloop_backup   "INSERT INTO events SELECT * FROM events WHERE false" 거부
q opsloop_backup   "SELECT count(*) FROM events" 허용
q opsloop_gate     "SELECT count(*) FROM events" 거부
q opsloop_gate     "SELECT count(*) FROM nodes WHERE token_hash IS NOT NULL" 허용

echo "== 접속 한도 (이슈 #43. 콘솔 한 대 = 풀 10 + LISTEN 1 → 두 대 22 + triage.py)"
#   20 이면 콘솔 B 를 켤 때 한도에 닿는다. 무제한(-1)도 기대와 다르다고 본다 (콘솔이 DB 접속을 다 써 버리지 않게 하는 울타리다)
#   올리는 곳: infra/migrations/20260926_console_connlimit.sql · db-console-role.sh · install-collector.sh (모두 30)
lim=$(psql_as opsloop "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console'" | head -1)
cur=$(psql_as opsloop "SELECT count(*) FROM pg_stat_activity WHERE usename = 'opsloop_console'" | head -1)
[[ "$cur" =~ ^[0-9]+$ ]] || cur="?"
if [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -ge 30 ]; then row opsloop_console "CONNECTION LIMIT (지금 접속 $cur)" "≥30" "✔ $lim"
else row opsloop_console "CONNECTION LIMIT (지금 접속 $cur)" "≥30" "✘ ${lim:-없음}"; fail=1; fi

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
