-- AI 판정 추천 (이슈 #120). schema.sql 의 'AI 판정 추천' 블록과 같으며 여러 번 적용해도 같다.
--   역할 블록 뒤에 적용한다. 역할 블록을 다시 적용하면 콘솔 권한이 거둬지므로 이 파일도 다시 적용한다.
--   opsloop_ai 역할은 recommend/install-recommend.sh 가 만든다.
BEGIN;
-- AI 판정 추천 (이슈 #120)
--   판정 대기 사건마다 추천 작업기(opsloop-recommend)가 LLM 에 근거를 보내 판정 후보 · 근거 세 줄 · 차단 제안을 남긴다.
--   추천은 판정이 아니다. 판정과 차단은 사람이 하고, 추천 작업기는 이 두 표에만 쓴다(판정 · 조치 · 차단 목록 권한 없음).
--   추천값은 판정 기준 §6 처럼 threat · non_actionable · undetermined 셋뿐이다(오탐 · 양성 정탐은 사람만 판정).
--   실패한 시도도 남긴다(사건별 시도 상한과 실패 사유를 보려고). 표는 추가만 된다.
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id              bigserial   PRIMARY KEY,
    incident_key    text        NOT NULL REFERENCES incidents (incident_key) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    model           text        NOT NULL CHECK (length(model) BETWEEN 1 AND 100),
    prompt_version  text        NOT NULL CHECK (length(prompt_version) BETWEEN 1 AND 40),
    status          text        NOT NULL CHECK (status IN ('ok', 'failed')),
    recommendation  text        CHECK (recommendation IN ('threat', 'non_actionable', 'undetermined')),
    needs_human     boolean,
    guard           text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(guard) <= 5),
    reasons         text[],
    block_hours     integer     CHECK (block_hours IN (0, 24)),
    seconds         real        CHECK (seconds >= 0 AND seconds < 3600),
    error           text        CHECK (length(error) <= 300),
    CONSTRAINT ai_recommendations_ok_shape CHECK (
        (status = 'ok') = (recommendation IS NOT NULL AND needs_human IS NOT NULL AND block_hours IS NOT NULL
                           AND reasons IS NOT NULL AND cardinality(reasons) = 3)),
    CONSTRAINT ai_recommendations_failed_why CHECK (status = 'ok' OR error IS NOT NULL),
    -- 위협이 아닌 추천은 차단을 제안하지 않는다(안전장치가 코드에서 먼저 0 으로 만든다)
    CONSTRAINT ai_recommendations_block_threat CHECK (block_hours IS NULL OR block_hours = 0 OR recommendation = 'threat')
);
CREATE INDEX IF NOT EXISTS idx_ai_rec_incident ON ai_recommendations (incident_key, created_at DESC);

-- 2026-10-07: 추천이 읽은 사건 근거의 지문. 옛 추천(NULL)은 근거 기준 미확인으로 표시한다.
ALTER TABLE ai_recommendations ADD COLUMN IF NOT EXISTS evidence_fingerprint text;

-- 추천 작업기의 최근 상태 한 행. AI 서버에 닿지 않는 것은 장애가 아니라 정상 상황(학교 밖)이라 알림을 보내지 않고
-- 콘솔이 '마지막 성공 시각'과 함께 보인다. last_ok_at 은 닿지 않은 회차에도 지켜진다(작업기의 UPSERT 가 그렇게 쓴다).
CREATE TABLE IF NOT EXISTS ai_status (
    singleton   boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    checked_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    reachable   boolean     NOT NULL,
    last_ok_at  timestamptz,
    model       text        CHECK (length(model) <= 100),
    pending     integer     CHECK (pending >= 0),
    error       text        CHECK (length(error) <= 300)
);

-- 관제자가 판정할 때 본 추천. 추천 일치 수(판정값 = 추천값)를 세는 근거다. 같은 사건의 추천인지는 콘솔이 확인한다.
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS recommendation_id bigint REFERENCES ai_recommendations (id);
CREATE INDEX IF NOT EXISTS idx_ver_recommendation ON verdicts (recommendation_id) WHERE recommendation_id IS NOT NULL;

REVOKE ALL ON ai_recommendations, ai_status FROM PUBLIC;
REVOKE ALL ON SEQUENCE ai_recommendations_id_seq FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_ai') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_ai', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_ai;
        -- 근거 읽기: 판정 대기 사건과 그 출발지의 이벤트. 판정 · 조치 · 차단 목록 · 계정은 읽지도 쓰지도 않는다
        GRANT SELECT ON incidents, events TO opsloop_ai;
        GRANT SELECT (incident_key) ON verdicts TO opsloop_ai;
        GRANT SELECT, INSERT ON ai_recommendations TO opsloop_ai;
        GRANT USAGE ON SEQUENCE ai_recommendations_id_seq TO opsloop_ai;
        GRANT SELECT, INSERT, UPDATE ON ai_status TO opsloop_ai;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON ai_recommendations, ai_status TO opsloop_console;
    END IF;
END
$$;
COMMIT;
