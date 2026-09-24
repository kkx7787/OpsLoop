-- 폐루프 2회차. schema.sql 의 같은 블록과 동일하며 여러 번 적용해도 같다.
--   탐지 역할(opsloop_detector)에 incidents 의 끝 시각 · 건수 · 근거 열 UPDATE 를 더한다.
--   detect.py 의 적재가 ON CONFLICT DO UPDATE 로 이어지는 사건을 키운다(판정 없는 건만).
--   nodes 의 addr 읽기를 더한다. R301 i2 가 공백을 쪼갤 관문 거부 줄을 그 노드의 등록 주소에서 온 것으로 한정한다.
--   판정된 인시던트의 끝 시각 · 건수 · 근거 갱신을 막는 트리거(trg_incidents_keep_judged)를 둔다.
--   블록이 먼저 모두 거두고 다시 주므로, 20260924_db_roles.sql 뒤에 적용하면 이 권한만 늘어난다.
BEGIN;
-- 판정된 인시던트의 끝 시각 · 건수 · 근거는 고치지 않는다. 판정자가 본 근거가 판정 기록과 함께 남아야 한다.
--   탐지 적재(detect.py ON_CONFLICT_GROW)의 WHERE 는 문장 시작 때의 스냅샷으로 판정을 본다. 콘솔 · triage 가
--   판정을 넣고 인시던트 상태를 바꾼 뒤 커밋하기를 적재가 행 잠금에서 기다렸다면, 그 판정은 WHERE 에 보이지
--   않는다. 트리거 안의 질의는 새 스냅샷을 쓰므로 여기서 다시 보고 그 행의 갱신만 건너뛴다(오류 없이 0행).
--   상태(status) 변경은 이 열들을 건드리지 않으므로 걸리지 않는다.
CREATE OR REPLACE FUNCTION incidents_keep_judged() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = OLD.incident_key) THEN
        RETURN NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER trg_incidents_keep_judged
    BEFORE UPDATE OF last_ts, signal_count, session_count, evidence ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_keep_judged();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_detector') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_detector', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_detector;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_detector;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_detector;
        GRANT SELECT ON events, sessions, incidents, verdicts, actions, node_metrics, detector_runs, rule_versions,
                        rule_quality TO opsloop_detector;
        -- addr: R301 i2 가 관문 거부 줄의 출발지를 등록 주소와 맞춘다. token_hash · agent_fp 는 여전히 뺀다
        GRANT SELECT (node_id, status, logs, registered_at, addr) ON nodes TO opsloop_detector;
        GRANT INSERT ON incidents, rule_versions, detector_runs TO opsloop_detector;
        GRANT DELETE ON incidents TO opsloop_detector;                    -- 억제: 판정 · 조치 없는 건만 코드가 고른다
        -- 이어지는 사건 갱신(ON CONFLICT DO UPDATE): 끝 시각 · 건수 · 근거만. 판정 없는 건만 문장이 고르고
        -- trg_incidents_keep_judged 가 다시 막는다. 억제 전 잠금(FOR UPDATE SKIP LOCKED)도 이 열 권한으로 된다
        GRANT UPDATE (last_ts, signal_count, session_count, evidence) ON incidents TO opsloop_detector;
        GRANT USAGE ON SEQUENCE detector_runs_id_seq TO opsloop_detector;
    END IF;
END
$$;
COMMIT;
