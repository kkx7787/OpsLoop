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

-- 웹 계층 로그 소스(디코이 · 관제 콘솔)를 위한 확장 (2026-09-18)
--   Cowrie 는 SSH 로그를, 디코이와 콘솔은 HTTP 로그를 남긴다. 같은 표에 담되
--   웹에만 있는 필드를 열로 추가한다. 기존 행은 전부 비어 있어도 무방하다.
--   sensor 를 두는 이유는 집계를 섞지 않기 위해서다. 정상이 없는 환경(디코이)과
--   정상이 있는 환경(콘솔)의 수치를 한 덩어리로 평균 내면 둘 다 의미를 잃는다.
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_method text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_status integer;
ALTER TABLE events ADD COLUMN IF NOT EXISTS user_agent  text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS sensor      text NOT NULL DEFAULT 'cowrie';
CREATE INDEX IF NOT EXISTS idx_events_sensor_ts ON events (sensor, ts DESC);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sensor text NOT NULL DEFAULT 'cowrie';

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
                   CHECK (verdict IN ('threat', 'non_actionable', 'false_positive',
                                      'benign_positive', 'undetermined')),
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

-- 판정값 확장 (2026-09-18)
--   benign_positive : 규칙이 겨냥한 것을 정확히 잡았고 악의도 없다. 조사 기관의
--                     스캐너가 여기 해당한다. 오탐으로 세면 규칙 정확도가 실제보다
--                     낮게 집계되어 멀쩡한 규칙을 고치게 된다.
--   undetermined    : 근거가 부족하다. 억지 판정은 없는 판정보다 나쁘므로 값으로
--                     남기되 지표에서는 제외한다.
ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS decision_seconds integer;
ALTER TABLE verdicts DROP CONSTRAINT IF EXISTS verdicts_verdict_check;
ALTER TABLE verdicts ADD CONSTRAINT verdicts_verdict_check
      CHECK (verdict IN ('threat', 'non_actionable', 'false_positive',
                         'benign_positive', 'undetermined'));
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

-- 차단의 집행 정보 (2026-09-18)
--   요청과 실제 차단은 다르다. 규칙을 넣었다고 트래픽이 막힌다는 보장이 없으므로
--   집행 결과를 따로 남기고 화면에서도 요청과 구분해 보여준다.
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS method       text;
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS requested_by text;
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS enforced_at  timestamptz;
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS enforce_note text;

-- 수집 노드 등록
--   에이전트는 설치 후 발급받은 토큰으로 자신을 등록한다. 등록되지 않은
--   에이전트가 붙으면 그 자체가 알림 대상이므로 목록이 있어야 한다.
--   토큰은 원문을 저장하지 않는다. 저장하면 DB 가 곧 자격증명 보관소가 된다.
CREATE TABLE IF NOT EXISTS nodes (
    node_id       text PRIMARY KEY,
    hostname      text,
    role          text,
    sensor        text,
    token_hash    text,
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz,
    status        text NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'stale', 'revoked'))
);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes (last_seen_at DESC);

-- 미판정 대기 목록
--   대시보드의 첫 화면이 쓰는 값이다. 판정이 사람의 일인 이상 밀린 시간이
--   곧 위험이므로, 건수가 아니라 경과 시간을 기준으로 정렬한다.
CREATE OR REPLACE VIEW unjudged_incidents AS
SELECT
    i.incident_key,
    i.rule_id,
    i.rule_version,
    i.rule_name,
    i.severity,
    i.actor_ip,
    i.first_ts,
    i.last_ts,
    i.signal_count,
    i.status,
    extract(epoch FROM (now() - i.first_ts))::bigint AS pending_seconds
FROM incidents i
LEFT JOIN verdicts v ON v.incident_key = i.incident_key
WHERE v.id IS NULL;

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
    -- 미결은 판정이 아니므로 분모에서 뺀다. 양성 정탐은 정확한 탐지이므로
    -- 분모에는 남기고 분자에서만 뺀다. 둘을 같이 취급하면 규칙의 정확도가
    -- 실제와 달라진다.
    round(100.0 * count(*) FILTER (WHERE v.verdict = 'false_positive')
          / NULLIF(count(v.id) FILTER (WHERE v.verdict <> 'undetermined'), 0), 1)
                                                                    AS false_positive_rate,
    round(100.0 * count(*) FILTER (WHERE v.verdict IN ('non_actionable', 'false_positive',
                                                       'benign_positive'))
          / NULLIF(count(v.id) FILTER (WHERE v.verdict <> 'undetermined'), 0), 1)
                                                                    AS non_action_rate,
    -- 새 열은 뒤에 붙인다. 뷰는 기존 열의 이름과 순서를 바꾸면 교체되지 않는다.
    count(*) FILTER (WHERE v.verdict = 'benign_positive')           AS benign_positives,
    count(*) FILTER (WHERE v.verdict = 'undetermined')              AS undetermined,
    count(v.id) FILTER (WHERE v.verdict <> 'undetermined')          AS judged_effective
FROM incidents i
LEFT JOIN verdicts v ON v.incident_key = i.incident_key
GROUP BY i.rule_id, i.rule_version;
