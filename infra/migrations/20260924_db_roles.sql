-- #31: 구성요소별 최소 권한 역할의 권한. 역할 생성은 collector/install-collector.sh(데이터 노드) 와
-- infra/vmware/scripts/db-console-role.sh(콘솔) 가 한다. 이 파일은 schema.sql 의 같은 블록과 동일하며 여러 번 적용해도 같다.
BEGIN;
-- 역할 분리 (이슈 #31 · 2026-09-24)
--   구성요소마다 최소 권한 역할로 붙는다. 역할은 비밀번호 때문에 여기서 만들지 않는다
--   (데이터 노드: collector/install-collector.sh, 콘솔: infra/vmware/scripts/db-console-role.sh).
--   역할이 있을 때만 권한을 주고, 먼저 모두 거둬 여러 번 적용해도 아래 권한만 남게 한다.
--   뷰(audit_log 등)를 참조하므로 이 파일의 맨 끝에 둔다.
--     opsloop_ingest    다리(pull_loki.py) · 파서(--load · --reclassify) — 원문 · 세션 · 지표 적재, 노드 수신 기록
--     opsloop_detector  탐지기(detect.py) — 규칙 실행, 인시던트 생성 · 억제, 실행 기록
--     opsloop_console   콘솔 API · triage.py — 판정 · 조치 · 차단 · 등록 토큰 · 감사 기록 · 로그인 기록
--     opsloop_backup    pg_dump — 읽기 전용
--   소유자 opsloop 는 스키마 적용 · nodes.py(관리 단말) · auth.py add(계정) 에만 쓴다.
--   토큰 해시(nodes.token_hash · node_enrollments.token_hash)는 관문과 소유자만 읽는다.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_ingest') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_ingest', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_ingest;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_ingest;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_ingest;
        GRANT SELECT, INSERT ON events TO opsloop_ingest;
        GRANT UPDATE (provenance) ON events TO opsloop_ingest;          -- parse_decoy · parse_gateway --reclassify
        GRANT SELECT, INSERT, UPDATE ON sessions TO opsloop_ingest;      -- 세션 재집계(ON CONFLICT DO UPDATE)
        GRANT SELECT, INSERT ON node_metrics TO opsloop_ingest;
        -- 수신 기록 갱신이 기존 값을 읽으므로(COALESCE · 비교) 갱신 열의 SELECT 도 준다. token_hash · agent_fp · addr 는 뺀다
        GRANT SELECT (node_id, hostname, logs, registered_at, status, receipt, first_loaded_at, last_loaded_at, last_seen_at)
              ON nodes TO opsloop_ingest;
        GRANT UPDATE (receipt, first_loaded_at, last_loaded_at, last_seen_at) ON nodes TO opsloop_ingest;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_detector') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_detector', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_detector;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_detector;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_detector;
        GRANT SELECT ON events, sessions, incidents, verdicts, actions, node_metrics, detector_runs, rule_versions,
                        rule_quality TO opsloop_detector;
        GRANT SELECT (node_id, status, logs, registered_at) ON nodes TO opsloop_detector;
        GRANT INSERT ON incidents, rule_versions, detector_runs TO opsloop_detector;
        GRANT DELETE ON incidents TO opsloop_detector;                    -- 억제: 판정 · 조치 없는 건만 코드가 고른다
        GRANT USAGE ON SEQUENCE detector_runs_id_seq TO opsloop_detector;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_console', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_console;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_console;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_console;
        GRANT SELECT ON events, incidents, verdicts, actions, blocklist, console_users, rule_versions, detector_runs,
                        rule_quality, audit_log, unjudged_incidents TO opsloop_console;
        GRANT SELECT (node_id, hostname, role, sensor, addr, logs, status, registered_at, last_seen_at,
                      first_loaded_at, last_loaded_at, agent_fp, receipt) ON nodes TO opsloop_console;
        GRANT SELECT (id, node_id, issued_by, issued_at, expires_at, used_at, used_from, canceled_at)
              ON node_enrollments TO opsloop_console;
        -- events INSERT: 로그인 기록(sensor=console)과 audit_event(). 콘솔은 events 를 고치거나 지우지 못한다
        GRANT INSERT ON events, verdicts, actions, blocklist, nodes, node_enrollments TO opsloop_console;
        GRANT UPDATE (status) ON incidents TO opsloop_console;
        GRANT UPDATE ON blocklist TO opsloop_console;                    -- 해제 · 연장 (감사 트리거가 남긴다)
        GRANT UPDATE (last_login_at) ON console_users TO opsloop_console; -- 계정 추가 · 역할 변경은 소유자(auth.py add)
        GRANT UPDATE (status) ON nodes TO opsloop_console;                -- FOR UPDATE 잠금에 필요. 대상 정보는 못 고친다
        GRANT UPDATE (canceled_at) ON node_enrollments TO opsloop_console;
        GRANT USAGE ON SEQUENCE verdicts_id_seq, actions_id_seq, node_enrollments_id_seq TO opsloop_console;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_backup') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_backup', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_backup;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_backup;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_backup;
        GRANT pg_read_all_data TO opsloop_backup WITH INHERIT TRUE;      -- pg_dump 에 필요한 읽기 전부. 역할이 NOINHERIT 여도 물려받는다
    END IF;
END
$$;
COMMIT;
