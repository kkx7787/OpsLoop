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
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sensor text NOT NULL DEFAULT 'cowrie';

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
                  CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved', 'suppressed')),
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_inc_rule    ON incidents (rule_id, rule_version);
CREATE INDEX IF NOT EXISTS idx_inc_ts      ON incidents (first_ts DESC);
CREATE INDEX IF NOT EXISTS idx_inc_actor   ON incidents (actor_ip);
CREATE INDEX IF NOT EXISTS idx_inc_status  ON incidents (status, severity);
-- 조치중 상태 추가 (2026-09-18). 차단은 종결이 아니며, 종결은 판정이 기록될 때만 일어난다.
ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_status_check
      CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved', 'suppressed'));

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

-- 콘솔 사용자
--   판정과 조치가 계정에 귀속되어야 이력이 근거가 된다. 되돌리는 행위와
--   기준을 바꾸는 행위를 분리하기 위해 역할을 셋으로 나눈다.
--   가입 화면은 두지 않는다. 계정은 명령줄로만 만든다.
CREATE TABLE IF NOT EXISTS console_users (
    username      text PRIMARY KEY,
    password_hash text        NOT NULL,
    role          text        NOT NULL DEFAULT 'operator'
                  CHECK (role IN ('viewer', 'operator', 'admin')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

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

-- 관제 대상 수집 (이슈 #11 · 2026-09-21)
--   에이전트는 수집 관문(opsloop-gate)을 거쳐 Loki 에 쓰고, 다리(opsloop-agents)가 events ·
--   node_metrics 로 옮긴다. 노드는 발급(pending) → 자기 등록(active) → 폐기(revoked) 순으로 간다.
--   등록 토큰과 에이전트 키는 둘 다 원문을 두지 않고 sha256 16진수만 둔다.
--   registered_at 은 발급 시각이 아니라 자기 등록이 끝난 시각이다. 발급만 된 노드는 비어 있다.
--   receipt 는 다리가 로그(job)마다 남기는 수신 기록이다 (first_line_at · lines · malformed …).
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS addr            inet;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS logs            text[] NOT NULL DEFAULT '{}';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS agent_fp        text;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS first_loaded_at timestamptz;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_loaded_at  timestamptz;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS receipt         jsonb  NOT NULL DEFAULT '{}';
ALTER TABLE nodes ALTER COLUMN registered_at DROP NOT NULL;
ALTER TABLE nodes ALTER COLUMN registered_at DROP DEFAULT;
-- 행을 넣었다고 수집이 허용되면 안 된다. 활성화는 enroll_node 만 한다
ALTER TABLE nodes ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE nodes DROP CONSTRAINT IF EXISTS nodes_status_check;
ALTER TABLE nodes ADD CONSTRAINT nodes_status_check
      CHECK (status IN ('pending', 'active', 'stale', 'revoked'));
-- 키 하나가 두 노드를 증명하면 관문이 테넌트를 정할 수 없다
CREATE UNIQUE INDEX IF NOT EXISTS uq_nodes_token_hash ON nodes (token_hash) WHERE token_hash IS NOT NULL;

-- 등록 토큰 발급 이력. 1회용이며 만료 · 취소 · 사용 시각과 사용한 출발지가 남는다
CREATE TABLE IF NOT EXISTS node_enrollments (
    id          bigserial PRIMARY KEY,
    node_id     text        NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    token_hash  text        NOT NULL UNIQUE,
    issued_by   text,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_from   inet,
    canceled_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_enroll_node ON node_enrollments (node_id, issued_at DESC);

-- 노드 지표 (metrics.py 1분). 줄 해시가 키라서 다시 적재해도 한 번만 들어간다
CREATE TABLE IF NOT EXISTS node_metrics (
    line_hash     text PRIMARY KEY,
    node_id       text        NOT NULL,
    ts            timestamptz NOT NULL,
    seq           bigint,
    cpu_pct       real,
    mem_used_pct  real,
    mem_avail_mb  integer,
    swap_used_pct real,
    disk_root_pct real,
    load1         real,
    nginx_active  boolean,
    sshd_active   boolean
);
CREATE INDEX IF NOT EXISTS idx_node_metrics_node_ts ON node_metrics (node_id, ts DESC);

-- 탐지 실행 기록. "적재 뒤에 탐지가 돌았는가"를 DB 가 답한다 (첫 수신 확인 4단계)
CREATE TABLE IF NOT EXISTS detector_runs (
    id           bigserial PRIMARY KEY,
    rule_version text        NOT NULL,
    since        timestamptz,
    until        timestamptz,
    started_at   timestamptz NOT NULL,
    finished_at  timestamptz NOT NULL,
    incidents    integer
);
CREATE INDEX IF NOT EXISTS idx_detector_runs_started ON detector_runs (started_at DESC);

-- 자기 등록. 관문은 sha256(등록 토큰), node_id, sha256(에이전트 키), 출발지를 넘기기만 한다.
--   SECURITY DEFINER 라 소유자 권한으로 돈다. search_path 를 고정해 호출자가 만든 같은 이름의
--   표 · 함수로 바꿔치지 못하게 하고, PUBLIC 실행 권한은 회수한다.
--   잠금 순서는 nodes → node_enrollments 다. nodes.py(issue · cancel · revoke)도 같은 순서로
--   잠가서 동시에 돌아도 교착이 생기지 않는다.
--   결과: ok · bad_key · enroll_unknown · enroll_canceled · enroll_node · enroll_expired ·
--         addr_mismatch · enroll_used
CREATE OR REPLACE FUNCTION enroll_node(p_token_hash text, p_node_id text,
                                       p_agent_sha256 text, p_from inet)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_node text;
    nd     nodes%ROWTYPE;
    en     node_enrollments%ROWTYPE;
BEGIN
    -- 형식이 틀린 키 해시로는 아무것도 보지 않는다
    IF p_agent_sha256 IS NULL OR p_agent_sha256 !~ '^[0-9a-f]{64}$' THEN
        RETURN 'bad_key';
    END IF;

    SELECT node_id INTO v_node FROM node_enrollments WHERE token_hash = p_token_hash;
    IF NOT FOUND THEN
        RETURN 'enroll_unknown';
    END IF;
    SELECT * INTO nd FROM nodes WHERE node_id = v_node FOR UPDATE;
    SELECT * INTO en FROM node_enrollments WHERE token_hash = p_token_hash FOR UPDATE;
    IF NOT FOUND OR nd.node_id IS NULL THEN
        RETURN 'enroll_unknown';        -- 그 사이 노드가 지워졌다
    END IF;

    IF en.canceled_at IS NOT NULL THEN
        RETURN 'enroll_canceled';
    END IF;
    IF en.node_id IS DISTINCT FROM p_node_id THEN
        RETURN 'enroll_node';
    END IF;
    IF en.expires_at <= now() THEN
        RETURN 'enroll_expired';
    END IF;
    IF p_from IS NULL OR nd.addr IS NULL OR host(p_from) <> host(nd.addr) THEN
        RETURN 'addr_mismatch';
    END IF;
    IF en.used_at IS NOT NULL THEN
        -- 응답이 중간에 사라져 같은 키로 다시 온 경우다. 바꿀 것이 없으므로 ok 만 돌려준다.
        -- 그 사이 폐기된 노드는 이 길로 되살리지 않는다
        IF host(en.used_from) = host(p_from) AND nd.token_hash = p_agent_sha256
           AND nd.status = 'active' THEN
            RETURN 'ok';
        END IF;
        RETURN 'enroll_used';
    END IF;

    -- 쓸 수 없는 키: 등록 토큰(원문이 관리자 쪽에 있다), 다른 노드의 키, 이 노드에서 폐기된 키
    IF EXISTS (SELECT 1 FROM node_enrollments WHERE token_hash = p_agent_sha256)
       OR EXISTS (SELECT 1 FROM nodes WHERE token_hash = p_agent_sha256 AND node_id <> nd.node_id)
       OR (nd.status = 'revoked' AND nd.token_hash = p_agent_sha256) THEN
        RETURN 'bad_key';
    END IF;

    BEGIN
        UPDATE nodes
           SET token_hash = p_agent_sha256, agent_fp = left(p_agent_sha256, 8),
               status = 'active', registered_at = now()
         WHERE node_id = nd.node_id;
    EXCEPTION WHEN unique_violation THEN
        RETURN 'bad_key';               -- 같은 키를 동시에 다른 노드에 등록하려 했다
    END;
    UPDATE node_enrollments SET used_at = now(), used_from = p_from WHERE id = en.id;
    -- 살아 있는 등록 토큰을 남기지 않는다. 같은 노드의 나머지 미사용 토큰은 취소한다
    UPDATE node_enrollments SET canceled_at = now()
     WHERE node_id = nd.node_id AND id <> en.id AND used_at IS NULL AND canceled_at IS NULL;
    RETURN 'ok';
END;
$$;
REVOKE ALL ON FUNCTION enroll_node(text, text, text, inet) FROM PUBLIC;

-- 첫 수신 확인. nodes.py check, Ansible 마지막 작업, 나중의 S-13 이 같은 판정을 쓴다.
--   네 단계를 차례로 보고, 앞 단계가 통과하지 못하면 뒤 단계는 ok = NULL, detail = '대기' 다.
--     1 등록      status=active, 키 해시 있음, 등록 토큰이 만료 전에 쓰였고 그 출발지가 addr
--     2 첫 로그   선언한 로그마다 receipt[로그].first_line_at 있음 (다리가 Loki 에서 실제 줄을 본 시각)
--     3 형식 변환 nonce 가 든 nginx.request(204) · sshd.login.success · node_metrics 가 하나 이상이고
--                 receipt 의 모든 로그에서 malformed · repeated 가 0. foreign_host 는 건수만 보인다
--     4 규칙 적용 첫 적재 뒤에 시작한 detector_runs 가 있고, 그 규칙 버전에 이 노드의 eventid 와 맞는
--                 활성 규칙이 있음 (eventid 같음 · eventid_like · eventids 포함,
--                 params.sensors 가 있으면 노드 포함). 맞는 규칙을 '버전:ID' 로 보인다
CREATE OR REPLACE FUNCTION node_first_receipt(p_node text, p_nonce text)
RETURNS TABLE (step int, name text, ok boolean, detail text)
LANGUAGE plpgsql
STABLE
SET search_path = public, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    names    text[]    := ARRAY['등록', '첫 로그', '형식 변환', '규칙 적용'];
    oks      boolean[] := ARRAY[NULL, NULL, NULL, NULL]::boolean[];
    dets     text[]    := ARRAY['대기', '대기', '대기', '대기'];
    nd       nodes%ROWTYPE;
    en       node_enrollments%ROWTYPE;
    rc       jsonb;
    bad      text[];
    v_text   text;
    v_fh     text;
    n_probe  bigint := 0;
    n_login  bigint;
    n_metric bigint;
    v_evs    text[];
    v_runs   text;
BEGIN
    <<checks>>
    BEGIN
        -- 1 등록
        SELECT * INTO nd FROM nodes WHERE node_id = p_node;
        IF NOT FOUND THEN
            oks[1] := false;
            dets[1] := '노드 없음 (nodes.py issue 로 발급부터)';
            EXIT checks;
        END IF;
        bad := '{}';
        IF nd.status <> 'active' THEN
            bad := array_append(bad, format('status=%s', nd.status));
        END IF;
        IF nd.token_hash IS NULL THEN
            bad := array_append(bad, '에이전트 키 해시 없음');
        END IF;
        SELECT * INTO en FROM node_enrollments
         WHERE node_id = p_node AND used_at IS NOT NULL
         ORDER BY used_at DESC LIMIT 1;
        IF NOT FOUND THEN
            SELECT format('쓴 등록 토큰 없음 (발급 %s · 만료 %s · 취소 %s)', count(*),
                          count(*) FILTER (WHERE canceled_at IS NULL AND expires_at <= now()),
                          count(*) FILTER (WHERE canceled_at IS NOT NULL))
              INTO v_text
              FROM node_enrollments WHERE node_id = p_node;
            bad := array_append(bad, v_text);
        ELSE
            IF en.used_at > en.expires_at THEN
                bad := array_append(bad, '만료 뒤에 쓰인 등록 토큰');
            END IF;
            IF en.used_from IS NULL OR nd.addr IS NULL OR host(en.used_from) <> host(nd.addr) THEN
                bad := array_append(bad, format('등록 출발지 %s ≠ addr %s',
                                                coalesce(host(en.used_from), '-'),
                                                coalesce(host(nd.addr), '-')));
            END IF;
        END IF;
        IF cardinality(bad) > 0 THEN
            oks[1] := false;
            dets[1] := array_to_string(bad, ' · ');
            EXIT checks;
        END IF;
        oks[1] := true;
        dets[1] := format('키 %s · %s 에서 %s 등록', nd.agent_fp, host(en.used_from),
                          to_char(en.used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS"Z"'));

        -- 2 첫 로그
        rc := CASE WHEN jsonb_typeof(nd.receipt) = 'object' THEN nd.receipt ELSE '{}'::jsonb END;
        IF cardinality(nd.logs) = 0 THEN
            oks[2] := false;
            dets[2] := '선언한 로그 없음 (nodes.py issue --logs)';
            EXIT checks;
        END IF;
        SELECT string_agg(u.l, ', ' ORDER BY u.o) INTO v_text
          FROM unnest(nd.logs) WITH ORDINALITY AS u(l, o)
         WHERE (rc -> u.l ->> 'first_line_at') IS NULL;
        IF v_text IS NOT NULL THEN
            oks[2] := false;
            dets[2] := format('아직 줄이 없는 로그: %s', v_text);
            EXIT checks;
        END IF;
        oks[2] := true;
        SELECT string_agg(format('%s %s', u.l, rc -> u.l ->> 'first_line_at'), ' · ' ORDER BY u.o)
          INTO v_text
          FROM unnest(nd.logs) WITH ORDINALITY AS u(l, o);
        dets[2] := v_text;

        -- 3 형식 변환
        bad := '{}';
        IF coalesce(p_nonce, '') = '' THEN
            bad := array_append(bad, 'nonce 없음');
        ELSE
            -- nonce 는 글자 그대로 비교한다 (LIKE 의 % · _ · \ 를 무력화)
            SELECT count(*) INTO n_probe
              FROM events
             WHERE sensor = p_node AND eventid = 'nginx.request' AND http_status = 204
               AND url LIKE '%/opsloop-first-receipt/'
                            || replace(replace(replace(p_nonce, '\', '\\'), '%', '\%'), '_', '\_');
            IF n_probe = 0 THEN
                bad := array_append(bad, 'nonce 요청(204) 없음');
            END IF;
        END IF;
        SELECT count(*) INTO n_login FROM events WHERE sensor = p_node AND eventid = 'sshd.login.success';
        IF n_login = 0 THEN
            bad := array_append(bad, 'SSH 로그인 성공 줄 없음');
        END IF;
        SELECT count(*) INTO n_metric FROM node_metrics WHERE node_id = p_node;
        IF n_metric = 0 THEN
            bad := array_append(bad, '지표 행 없음');
        END IF;
        SELECT string_agg(format('%s %s=%s', k.k, j.key, j.value -> k.k), ', ' ORDER BY k.k, j.key)
          INTO v_text
          FROM jsonb_each(rc) AS j, unnest(ARRAY['malformed', 'repeated']) AS k(k)
         WHERE jsonb_typeof(j.value) = 'object'
           AND (j.value -> k.k) IS NOT NULL AND (j.value -> k.k) <> '0'::jsonb;
        IF v_text IS NOT NULL THEN
            bad := array_append(bad, v_text);
        END IF;
        SELECT string_agg(format('%s=%s', j.key, j.value -> 'foreign_host'), ', ' ORDER BY j.key)
          INTO v_fh
          FROM jsonb_each(rc) AS j
         WHERE jsonb_typeof(j.value) = 'object'
           AND (j.value -> 'foreign_host') IS NOT NULL AND (j.value -> 'foreign_host') <> '0'::jsonb;
        IF cardinality(bad) > 0 THEN
            oks[3] := false;
            dets[3] := array_to_string(bad, ' · ') || coalesce(' · foreign_host ' || v_fh, '');
            EXIT checks;
        END IF;
        oks[3] := true;
        dets[3] := format('nonce 요청 %s · SSH 로그인 %s · 지표 %s행', n_probe, n_login, n_metric)
                   || coalesce(' · foreign_host ' || v_fh, '');

        -- 4 규칙 적용
        IF nd.first_loaded_at IS NULL THEN
            oks[4] := false;
            dets[4] := '첫 적재 시각 없음 (다리 opsloop-agents 확인)';
            EXIT checks;
        END IF;
        SELECT string_agg(format('%s %s회', r.rule_version, r.n), ', ' ORDER BY r.rule_version)
          INTO v_runs
          FROM (SELECT rule_version, count(*) AS n FROM detector_runs
                 WHERE started_at > nd.first_loaded_at GROUP BY rule_version) AS r;
        IF v_runs IS NULL THEN
            oks[4] := false;
            dets[4] := format('첫 적재(%s) 뒤 탐지 실행 없음',
                              to_char(nd.first_loaded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS"Z"'));
            EXIT checks;
        END IF;
        SELECT array_agg(DISTINCT eventid ORDER BY eventid) INTO v_evs FROM events WHERE sensor = p_node;
        SELECT string_agg(DISTINCT format('%s:%s', rv.rule_version, x.rule ->> 'id'), ', ')
          INTO v_text
          FROM rule_versions AS rv
         CROSS JOIN LATERAL jsonb_array_elements(
                   CASE WHEN jsonb_typeof(rv.definition -> 'rules') = 'array'
                        THEN rv.definition -> 'rules' ELSE '[]'::jsonb END) AS x(rule)
         WHERE rv.rule_version IN (SELECT rule_version FROM detector_runs
                                    WHERE started_at > nd.first_loaded_at)
           AND jsonb_typeof(x.rule) = 'object'
           AND (x.rule -> 'enabled') IS DISTINCT FROM 'false'::jsonb
           AND (NOT coalesce((x.rule -> 'params') ? 'sensors', false)
                OR coalesce((x.rule -> 'params' -> 'sensors') ? p_node, false))
           AND EXISTS (SELECT 1 FROM unnest(v_evs) AS e(eventid)
                        WHERE e.eventid = (x.rule -> 'params' ->> 'eventid')
                           OR e.eventid LIKE (x.rule -> 'params' ->> 'eventid_like')
                           OR coalesce((x.rule -> 'params' -> 'eventids') ? e.eventid, false));
        IF v_text IS NULL THEN
            oks[4] := false;
            dets[4] := format('이 노드를 보는 규칙 없음 (노드 eventid: %s · 첫 적재 뒤 실행: %s)',
                              coalesce(array_to_string(v_evs[1:10], ', '), '-'), v_runs);
            EXIT checks;
        END IF;
        oks[4] := true;
        dets[4] := v_text;
    END checks;

    FOR i IN 1..4 LOOP
        step := i;
        name := names[i];
        ok := oks[i];
        detail := dets[i];
        RETURN NEXT;
    END LOOP;
END;
$$;

-- 관문 역할(opsloop_gate)의 권한은 nodes 네 열 읽기와 enroll_node 실행뿐이다.
--   역할은 비밀번호 때문에 여기서 만들지 않는다. 운영자가 만든 뒤 이 파일을 다시 적용한다.
--   먼저 표 권한을 모두 거둬, 여러 번 적용해도 위 두 권한만 남게 한다.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_gate') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_gate', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_gate;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_gate;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_gate;
        GRANT SELECT (node_id, token_hash, status, addr) ON nodes TO opsloop_gate;
        GRANT EXECUTE ON FUNCTION enroll_node(text, text, text, inet) TO opsloop_gate;
    END IF;
END
$$;
