-- OpsLoop PostgreSQL 스키마 (WBS 2.4)
--
-- SQLite 판과 다른 점
--   * 타임스탬프를 timestamptz 로 둔다. 문자열 비교가 아니라 시간 연산이 가능해진다.
--   * evidence 를 jsonb 로 둔다. 증거 내부 필드로 조회·집계할 수 있다.
--   * rule_versions 테이블을 둔다. 규칙 버전이 언제 무슨 근거로 바뀌었는지 남긴다.
--     폐루프의 "조치가 탐지를 개선했다"는 이 이력이 있어야 증명된다.

CREATE TABLE IF NOT EXISTS events (
    line_hash    text PRIMARY KEY,
    ts           timestamptz NOT NULL,
    eventid      text        NOT NULL,
    session      text,
    src_ip       inet,
    src_port     integer,
    dst_port     integer,
    protocol     text,
    username     text,
    password     text,
    input        text,
    url          text,
    shasum       text,
    duration_ms  integer,
    provenance   text        NOT NULL DEFAULT 'real'
                 CHECK (provenance IN ('real', 'simulated', 'fixture')),
    message      text
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_eventid  ON events (eventid);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events (session);
CREATE INDEX IF NOT EXISTS idx_events_prov_ts  ON events (provenance, ts DESC);

CREATE TABLE IF NOT EXISTS sessions (
    session        text PRIMARY KEY,
    src_ip         inet,
    protocol       text,
    first_ts       timestamptz,
    last_ts        timestamptz,
    duration_ms    integer,
    login_attempts integer NOT NULL DEFAULT 0,
    login_success  boolean NOT NULL DEFAULT false,
    command_count  integer NOT NULL DEFAULT 0,
    downloads      integer NOT NULL DEFAULT 0,
    provenance     text    NOT NULL DEFAULT 'real'
);
CREATE INDEX IF NOT EXISTS idx_sessions_first_ts ON sessions (first_ts DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip   ON sessions (src_ip);

-- 규칙 버전 이력. 임계치를 왜 바꿨는지가 남아야 개선을 주장할 수 있다.
CREATE TABLE IF NOT EXISTS rule_versions (
    rule_version text PRIMARY KEY,
    definition   jsonb       NOT NULL,
    reason       text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_key  text PRIMARY KEY,
    rule_id       text        NOT NULL,
    rule_version  text        NOT NULL,
    rule_name     text,
    severity      text        NOT NULL
                  CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    actor_ip      inet,
    first_ts      timestamptz NOT NULL,
    last_ts       timestamptz NOT NULL,
    signal_count  integer     NOT NULL,
    session_count integer,
    evidence      jsonb,
    status        text        NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inc_rule    ON incidents (rule_id, rule_version);
CREATE INDEX IF NOT EXISTS idx_inc_ts      ON incidents (first_ts DESC);
CREATE INDEX IF NOT EXISTS idx_inc_actor   ON incidents (actor_ip);
CREATE INDEX IF NOT EXISTS idx_inc_status  ON incidents (status, severity);

-- 조치 기록. 폐루프의 입력.
CREATE TABLE IF NOT EXISTS actions (
    id           bigserial PRIMARY KEY,
    incident_key text        NOT NULL REFERENCES incidents (incident_key) ON DELETE CASCADE,
    action       text        NOT NULL
                 CHECK (action IN ('block_ip', 'unblock_ip', 'acknowledge',
                                   'suppress_rule', 'escalate', 'note')),
    operator     text,
    note         text,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_act_incident ON actions (incident_key);
CREATE INDEX IF NOT EXISTS idx_act_created  ON actions (created_at DESC);

-- 판정 기록. 오탐률과 비조치율은 서로 다른 지표이며 둘 다 여기서 나온다.
--   threat          : 실제 위협      -> 탐지도 옳고 조치도 필요
--   non_actionable  : 무시 가능      -> 탐지는 옳으나 조치할 것이 없음
--   false_positive  : 오탐          -> 탐지가 틀림
-- 오탐률   = false_positive / 전체
-- 비조치율 = (non_actionable + false_positive) / 전체
CREATE TABLE IF NOT EXISTS verdicts (
    id             bigserial PRIMARY KEY,
    incident_key   text        NOT NULL REFERENCES incidents (incident_key) ON DELETE CASCADE,
    verdict        text        NOT NULL
                   CHECK (verdict IN ('threat', 'non_actionable', 'false_positive')),
    reason         text,
    observed_value double precision,
    operator       text,
    -- 도구가 제안한 판정. 사람이 뒤집었는지를 알 수 있어야 판정 기준 자체를
    -- 평가할 수 있다. 뒤집힌 비율이 높으면 기준 문서를 고쳐야 한다는 뜻이다.
    proposed       text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
-- 기존 데이터베이스에도 적용한다. 멱등이다.
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS proposed text;
CREATE INDEX IF NOT EXISTS idx_ver_incident ON verdicts (incident_key);
CREATE INDEX IF NOT EXISTS idx_ver_verdict  ON verdicts (verdict);

-- 차단 목록. 조치의 결과가 실제 상태로 남는 곳.
CREATE TABLE IF NOT EXISTS blocklist (
    actor_ip     inet PRIMARY KEY,
    reason       text,
    incident_key text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    released_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_block_active ON blocklist (released_at) WHERE released_at IS NULL;

-- 규칙 버전별 판정 집계. 리플레이 평가의 출력 지점.
CREATE OR REPLACE VIEW rule_quality AS
SELECT
    i.rule_id,
    i.rule_version,
    count(*)                                                        AS incidents,
    count(v.id)                                                     AS judged,
    count(*) FILTER (WHERE v.verdict = 'threat')                    AS threats,
    count(*) FILTER (WHERE v.verdict = 'non_actionable')            AS non_actionable,
    count(*) FILTER (WHERE v.verdict = 'false_positive')            AS false_positives,
    round(100.0 * count(*) FILTER (WHERE v.verdict = 'false_positive')
          / NULLIF(count(v.id), 0), 1)                              AS false_positive_rate,
    round(100.0 * count(*) FILTER (WHERE v.verdict IN ('non_actionable', 'false_positive'))
          / NULLIF(count(v.id), 0), 1)                              AS non_action_rate
FROM incidents i
LEFT JOIN verdicts v ON v.incident_key = i.incident_key
GROUP BY i.rule_id, i.rule_version;
