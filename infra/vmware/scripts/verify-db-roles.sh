#!/usr/bin/env bash
# DB 역할 분리 검증 · 격리 시험 2차 (이슈 #31).
#   데이터 노드 컨테이너 안(로컬 trust)에서 역할마다 범위 밖 문장이 거부되고 범위 안 문장은 되는지,
#   실제 접속이 어느 역할로 붙어 있는지, 관제 대상 노드에서 5432 가 막히는지 본다.
#   데이터를 바꾸지 않는다 (WHERE false · 읽기 · 권한 조회만).
#   CVE · KEV 연계(이슈 #39)의 수집기 역할(opsloop_cti)과 CTI 표 권한도 본다. infra/migrations/20260925_cti.sql 을
#   적용하고 cti/install-cti.sh 로 역할을 만든 뒤에 돌린다.
#   콘솔 역할의 접속 한도(이슈 #43, 30 이상)도 본다. infra/migrations/20260926_console_connlimit.sql 을 적용한 뒤에 돌린다.
#   차단 집행(이슈 #47)의 집행 역할(opsloop_enforcer) 권한 · 속성과 금지 대역 표(block_exempt) 권한도 본다.
#   infra/migrations/20260927_block_enforce.sql 을 적용하고 enforcer/install-enforcer.sh 로 역할을 만든 뒤에 돌린다.
#   관제 대상 상태판(이슈 #52)의 생존 신호 표(sensor_heartbeats) 권한 · 트리거와 콘솔의 노드 지표 읽기도 본다.
#   infra/migrations/20260930_status_board.sql 을 적용한 뒤에 돌린다.
#   콘솔 계정 관리(이슈 #59)의 계정 변경 함수(console_account_set) 실행 권한 · 도장 · 감사 트리거와 감사 조회 뷰 · 보호 트리거의
#   계정 조건도 본다. infra/migrations/20261001_console_accounts.sql 을 적용한 뒤에 돌린다.
#   콘솔 계정 추가 · 삭제 · 비밀번호(이슈 #63)의 세 함수(console_account_create · console_account_delete · console_account_password)
#   실행 권한도 본다. infra/migrations/20261002_console_accounts_manage.sql 을 적용한 뒤에 돌린다.
#   차단 적용 지점 선택(이슈 #77)의 요청 지점 열(points) 권한 · 좁히기 거부 트리거 · 값 제약도 본다.
#   infra/migrations/20261003_block_points_choice.sql 을 적용한 뒤에 돌린다.
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
# 차단 집행 (이슈 #47). 집행기는 차단 목록 읽기, 집행 열(method · enforced_at · enforce_note) 쓰기, 금지 대역 읽기, 만료 기록 함수뿐이다.
#   차단을 걸거나 풀거나 만료 · 주소를 바꾸지 못하고 events 를 보지 못한다(집행 열 변경의 감사는 SECURITY DEFINER 트리거가 남긴다).
#   콘솔은 금지 대역을 읽기만 하고 탐지 · 적재는 보지 못한다. 만료 기록 함수는 집행 역할만 부른다.
#   infra/test_block_enforce_db.py 가 이 줄들을 시험 DB 에서 무작위 역할로 돌려 같은 답이 나오는지 본다
q opsloop_enforcer "SELECT actor_ip, expires_at, released_at, method, enforced_at, enforce_note FROM blocklist LIMIT 0" 허용
q opsloop_enforcer "SELECT cidr, note FROM block_exempt LIMIT 0" 허용
q opsloop_enforcer "UPDATE blocklist SET method = method, enforced_at = enforced_at, enforce_note = enforce_note WHERE false" 허용
q opsloop_enforcer "UPDATE blocklist SET released_at = released_at WHERE false" 거부
q opsloop_enforcer "UPDATE blocklist SET expires_at = expires_at WHERE false" 거부
q opsloop_enforcer "UPDATE blocklist SET actor_ip = actor_ip WHERE false" 거부
q opsloop_enforcer "INSERT INTO blocklist SELECT * FROM blocklist WHERE false" 거부
q opsloop_enforcer "DELETE FROM blocklist WHERE false" 거부
q opsloop_enforcer "INSERT INTO block_exempt SELECT * FROM block_exempt WHERE false" 거부
q opsloop_enforcer "SELECT count(*) FROM events" 거부
q opsloop_enforcer "INSERT INTO events SELECT * FROM events WHERE false" 거부
q opsloop_enforcer "SELECT count(*) FROM incidents" 거부
q opsloop_enforcer "SELECT count(*) FROM absorbed_blocks" 거부
p opsloop_enforcer "has_function_privilege('opsloop_enforcer', 'note_block_expired(inet, timestamptz)', 'EXECUTE')" t
p opsloop_enforcer "has_table_privilege('opsloop_enforcer', 'blocklist', 'TRUNCATE')" f
q opsloop_console  "SELECT cidr, note FROM block_exempt LIMIT 0" 허용
q opsloop_console  "INSERT INTO block_exempt SELECT * FROM block_exempt WHERE false" 거부
q opsloop_console  "UPDATE block_exempt SET note = note WHERE false" 거부
q opsloop_console  "DELETE FROM block_exempt WHERE false" 거부
p opsloop_console  "has_function_privilege('opsloop_console', 'note_block_expired(inet, timestamptz)', 'EXECUTE')" f
#   금지 대역 검사(blocklist_guard)는 SECURITY DEFINER 다. 역할 블록만 다시 적용해 콘솔의 block_exempt 읽기가 빠져도 정상 주소 차단이 막히지 않는다
p opsloop_console  "(SELECT prosecdef FROM pg_proc WHERE proname = 'blocklist_guard')" t
q opsloop_detector "SELECT count(*) FROM block_exempt" 거부
p opsloop_detector "has_function_privilege('opsloop_detector', 'note_block_expired(inet, timestamptz)', 'EXECUTE')" f
q opsloop_ingest   "SELECT count(*) FROM block_exempt" 거부
# 집행 지점 (이슈 #51). 집행기는 지점별 결과 열(enforcement)도 쓴다. 콘솔은 시험 출발지 대역을 읽기만 하고,
#   규칙별 집계는 표 권한 없이 is_test_source(SECURITY DEFINER · PUBLIC 실행)로 한다
q opsloop_enforcer "UPDATE blocklist SET enforcement = enforcement WHERE false" 허용
q opsloop_console  "SELECT cidr, note FROM test_ranges LIMIT 0" 허용
q opsloop_console  "INSERT INTO test_ranges (cidr, note) VALUES ('192.0.2.0/24', 'x')" 거부
q opsloop_detector "SELECT is_test_source('203.0.113.10'::inet)" 허용
q opsloop_console  "SELECT is_test_source('203.0.113.10'::inet)" 허용

echo "== 관제 대상 상태판 (이슈 #52. 생존 신호 표 · 콘솔의 노드 지표 읽기)"
#   적재기는 업로더 신호, 집행기는 차단 보고 신호를 넣고 고친다(표 권한은 같고 행 종류는 트리거 sensor_heartbeats_guard 가 가른다).
#   트리거는 행이 있어야 도므로 여기서는 켜져 있는지만 본다(쓰기 시험은 infra/test_status_board_db.py). 지우는 역할은 없다.
#   콘솔은 생존 신호와 노드 지표를 읽기만 하고, 탐지는 생존 신호를 보지 못한다. infra/test_status_board_db.py 가 이 줄들을 시험 DB 에서 돌린다
q opsloop_ingest   "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false ON CONFLICT (source) DO UPDATE SET seen_at = EXCLUDED.seen_at" 허용
q opsloop_ingest   "DELETE FROM sensor_heartbeats WHERE false" 거부
p opsloop_ingest   "has_table_privilege('opsloop_ingest', 'sensor_heartbeats', 'TRUNCATE')" f
q opsloop_enforcer "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false ON CONFLICT (source) DO UPDATE SET seen_at = EXCLUDED.seen_at" 허용
q opsloop_enforcer "DELETE FROM sensor_heartbeats WHERE false" 거부
q opsloop_enforcer "SELECT count(*) FROM node_metrics" 거부
q opsloop_console  "SELECT source, kind, role, host, seen_at, checked_at, problem FROM sensor_heartbeats LIMIT 0" 허용
q opsloop_console  "SELECT node_id, ts, cpu_pct, mem_used_pct, disk_root_pct, load1 FROM node_metrics LIMIT 0" 허용
q opsloop_console  "INSERT INTO sensor_heartbeats SELECT * FROM sensor_heartbeats WHERE false" 거부
q opsloop_console  "UPDATE sensor_heartbeats SET problem = problem WHERE false" 거부
q opsloop_console  "INSERT INTO node_metrics SELECT * FROM node_metrics WHERE false" 거부
q opsloop_detector "SELECT count(*) FROM sensor_heartbeats" 거부
p opsloop_ingest   "(SELECT tgenabled = 'O' FROM pg_trigger WHERE tgname = 'sensor_heartbeats_guard')" t

echo "== 콘솔 계정 관리 (이슈 #59. 계정 변경 함수 · 도장 · 감사 트리거)"
#   콘솔은 계정 표를 직접 고치지 못한다(UPDATE 는 last_login_at 열뿐. 위 역할별 문장의 role 갱신 · INSERT 거부 줄과 같다). 관제사 ↔ 조회자
#   역할 변경 · 비활성 · 재활성은 console_account_set(SECURITY DEFINER)으로만 하고, 콘솔만 실행 권한을 받는다. 행위자가 없으면 아무것도
#   바꾸지 않고 no_actor 를 돌려주므로 실행 줄은 데이터를 바꾸지 않는다. 역할 블록을 다시 적용해도 실행 권한은 남는다.
#   감사 조회 뷰 · 추가만 되는 행 보호에 계정 감사(console.account.%)가 있어야 한다. 20260923_console_ops.sql · 20260924_notify.sql 을
#   다시 적용하면 빠지므로 20261001_console_accounts.sql 도 다시 적용한다. infra/test_console_accounts_db.py 가 이 줄들을 시험 DB 에서 돌린다
q opsloop_console  "UPDATE console_users SET disabled_at = now() WHERE false" 거부
q opsloop_console  "UPDATE console_users SET updated_at = now() WHERE false" 거부
q opsloop_console  "UPDATE console_users SET password_hash = password_hash WHERE false" 거부
q opsloop_console  "DELETE FROM console_users WHERE false" 거부
q opsloop_console  "UPDATE console_users SET last_login_at = last_login_at WHERE false" 허용
q opsloop_console  "SELECT console_account_set(NULL, NULL, NULL)" 허용
q opsloop_detector "SELECT console_account_set(NULL, NULL, NULL)" 거부
p opsloop_console  "has_function_privilege('opsloop_console', 'console_account_set(text, text, boolean)', 'EXECUTE')" t
p opsloop_detector "has_function_privilege('opsloop_detector', 'console_account_set(text, text, boolean)', 'EXECUTE')" f
p opsloop_ingest   "has_function_privilege('opsloop_ingest', 'console_account_set(text, text, boolean)', 'EXECUTE')" f
p opsloop_console  "(SELECT prosecdef FROM pg_proc WHERE proname = 'console_account_set')" t
p opsloop_console  "(SELECT count(*) = 2 FROM pg_trigger WHERE tgname IN ('console_users_stamp', 'trg_audit_console_users') AND tgenabled = 'O')" t
p opsloop_console  "(SELECT pg_get_viewdef('audit_log'::regclass) LIKE '%console.account.%')" t
p opsloop_console  "(SELECT pg_get_triggerdef(oid) LIKE '%console.account.%' FROM pg_trigger WHERE tgname = 'trg_audit_append_only')" t

echo "== 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63. 계정 추가 · 삭제 · 비밀번호 함수)"
#   관제사 · 조회자 계정 추가, 이력 없는 계정 삭제, 비밀번호 재설정은 console_account_create · console_account_delete ·
#   console_account_password(SECURITY DEFINER)로만 하고 콘솔만 실행 권한을 받는다. 콘솔 역할의 계정 표 INSERT · DELETE 는 여전히 거부다.
#   행위자가 없으면 아무것도 바꾸지 않고 no_actor 를 돌려주므로 실행 줄은 데이터를 바꾸지 않는다. 역할 블록을 다시 적용해도 실행 권한은
#   남는다. infra/test_console_accounts_manage_db.py 가 이 줄들을 시험 DB 에서 돌린다
q opsloop_console  "INSERT INTO console_users (username, password_hash, role) SELECT username, password_hash, 'viewer' FROM console_users WHERE false" 거부
q opsloop_console  "DELETE FROM console_users WHERE false" 거부
q opsloop_console  "SELECT console_account_create(NULL, NULL, NULL)" 허용
q opsloop_console  "SELECT console_account_delete(NULL)" 허용
q opsloop_console  "SELECT console_account_password(NULL, NULL)" 허용
q opsloop_detector "SELECT console_account_create(NULL, NULL, NULL)" 거부
p opsloop_console  "has_function_privilege('opsloop_console', 'console_account_create(text, text, text)', 'EXECUTE')" t
p opsloop_console  "has_function_privilege('opsloop_console', 'console_account_delete(text)', 'EXECUTE')" t
p opsloop_console  "has_function_privilege('opsloop_console', 'console_account_password(text, text)', 'EXECUTE')" t
p opsloop_detector "has_function_privilege('opsloop_detector', 'console_account_create(text, text, text)', 'EXECUTE')" f
p opsloop_detector "has_function_privilege('opsloop_detector', 'console_account_delete(text)', 'EXECUTE')" f
p opsloop_detector "has_function_privilege('opsloop_detector', 'console_account_password(text, text)', 'EXECUTE')" f
p opsloop_ingest   "has_function_privilege('opsloop_ingest', 'console_account_create(text, text, text)', 'EXECUTE')" f
p opsloop_ingest   "has_function_privilege('opsloop_ingest', 'console_account_delete(text)', 'EXECUTE')" f
p opsloop_ingest   "has_function_privilege('opsloop_ingest', 'console_account_password(text, text)', 'EXECUTE')" f
p opsloop_console  "(SELECT prosecdef FROM pg_proc WHERE proname = 'console_account_create')" t
p opsloop_console  "(SELECT prosecdef FROM pg_proc WHERE proname = 'console_account_delete')" t
p opsloop_console  "(SELECT prosecdef FROM pg_proc WHERE proname = 'console_account_password')" t

echo "== 차단 적용 지점 (이슈 #77. 요청 지점 열 · 좁히기 거부 트리거)"
#   권한은 새로 주지 않는다. 콘솔(triage 포함)은 표 INSERT · UPDATE 로 지점을 넣고 넓히고, 집행기는 읽기만 한다(열 UPDATE 목록에
#   points 가 없다). 탐지는 보지 못한다. 살아 있는 행의 지점 좁히기는 트리거(trg_blocklist_points · SECURITY DEFINER)가
#   23514 blocklist_points_narrow 로 거부한다. 트리거는 행이 있어야 돌므로 여기서는 켜져 있는지 · 거부 조건이 있는지만 본다.
#   infra/test_block_points_choice_db.py 가 이 줄들을 시험 DB 에서 돌리고 좁히기 · 넓히기를 실제 행으로 본다
q opsloop_enforcer "SELECT actor_ip, points FROM blocklist LIMIT 0" 허용
q opsloop_enforcer "UPDATE blocklist SET points = points WHERE false" 거부
p opsloop_enforcer "has_column_privilege('opsloop_enforcer', 'blocklist', 'points', 'UPDATE')" f
q opsloop_console  "INSERT INTO blocklist (actor_ip, points) SELECT actor_ip, points FROM blocklist WHERE false" 허용
q opsloop_console  "UPDATE blocklist SET points = '{gateway,fw}' WHERE false" 허용
q opsloop_console  "UPDATE absorbed_blocks SET points = '{gateway,fw}' WHERE false" 허용
q opsloop_detector "SELECT points FROM blocklist LIMIT 0" 거부
p opsloop_console  "has_function_privilege('opsloop_console', 'blocklist_points_change()', 'EXECUTE')" f
p opsloop_console  "(SELECT prosecdef AND prosrc LIKE '%blocklist_points_narrow%' FROM pg_proc WHERE proname = 'blocklist_points_change')" t
p opsloop_console  "(SELECT tgenabled = 'O' FROM pg_trigger WHERE tgname = 'trg_blocklist_points')" t
p opsloop_console  "(SELECT count(*) = 2 FROM pg_constraint WHERE conname IN ('blocklist_points_valid', 'absorbed_blocks_points_valid'))" t

echo "== 접속 한도 (이슈 #43. 콘솔 한 대 = 풀 10 + LISTEN 1 → 두 대 22 + triage.py)"
#   20 이면 콘솔 B 를 켤 때 한도에 닿는다. 무제한(-1)도 기대와 다르다고 본다 (콘솔이 DB 접속을 다 써 버리지 않게 하는 울타리다)
#   올리는 곳: infra/migrations/20260926_console_connlimit.sql · db-console-role.sh · install-collector.sh (모두 30)
lim=$(psql_as opsloop "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_console'" | head -1)
cur=$(psql_as opsloop "SELECT count(*) FROM pg_stat_activity WHERE usename = 'opsloop_console'" | head -1)
[[ "$cur" =~ ^[0-9]+$ ]] || cur="?"
if [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -ge 30 ]; then row opsloop_console "CONNECTION LIMIT (지금 접속 $cur)" "≥30" "✔ $lim"
else row opsloop_console "CONNECTION LIMIT (지금 접속 $cur)" "≥30" "✘ ${lim:-없음}"; fail=1; fi

echo "== 집행 역할 속성 (이슈 #47. enforcer/install-enforcer.sh 가 만든다)"
#   로그인 · 권한을 물려받지 않음 · 슈퍼유저 아님 · 접속 한도 2 (1분 타이머 한 번에 접속 하나. 겹쳐 돌아도 2 를 넘지 않는다)
att=$(psql_as opsloop "SELECT rolcanlogin::text || ' ' || rolinherit::text || ' ' || rolsuper::text || ' ' || rolconnlimit FROM pg_roles WHERE rolname = 'opsloop_enforcer'" | head -1)
if [ "$att" = "true false false 2" ]; then row opsloop_enforcer "LOGIN · NOINHERIT · 슈퍼유저 아님 · CONNECTION LIMIT" 2 "✔"
else row opsloop_enforcer "LOGIN · NOINHERIT · 슈퍼유저 아님 · CONNECTION LIMIT" 2 "✘ ${att:-역할 없음}"; fail=1; fi

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
