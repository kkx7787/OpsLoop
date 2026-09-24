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
LEFT JOIN LATERAL (
    SELECT id, verdict FROM verdicts WHERE incident_key = i.incident_key
    ORDER BY created_at DESC, id DESC LIMIT 1
) v ON true
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

-- 규칙군 확장 (이슈 #14 · 2026-09-22)
--   w1(웹 · 인증) · a1(차단 목록 감사) · i1(노드 수신 끊김)이 쓰는 열 · 함수 · 트리거다. 여러 번 적용해도 결과가 같다.
--   허니팟 v1 · v2 의 입력과 적재 문장은 바뀌지 않는다. 새 열은 비어 있거나 기본값을 받는다.
--   이 블록을 먼저 적용하고 코드를 깐다. 새 탐지기의 대상 적재(a1 · i1)와 R301, 콘솔 · triage 는 새 열을 읽고 쓴다.

-- IP 가 아닌 대상 (user:<이름> · node:<id>). 탐지기가 신호의 detail._target 을 여기 넣고 actor_ip 는 비운다.
--   콘솔은 actor_ip 가 있을 때만 차단 목록에 넣으므로, 이런 인시던트로는 콘솔 · 인프라 주소를 막을 수 없다
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS target text;
CREATE INDEX IF NOT EXISTS idx_inc_target ON incidents (target) WHERE target IS NOT NULL;

-- 다리가 지표를 넣은 시각 (R301 노드 수신 끊김). ts 는 노드가 만든 시각이라, 밀린 줄을 나중에 한꺼번에 받으면
--   ts 에는 공백이 없어도 그동안 관제는 아무것도 받지 못했다. 다리의 INSERT 열 목록은 그대로 두고 기본값으로 채운다.
--   기존 행은 넣은 시각을 모르므로 ts 로 채운다. DO 블록 하나(한 트랜잭션)로 묶어, 열을 더한 뒤 기본값을 걸기 전에
--   다리가 넣은 행이 비어 NOT NULL 이 실패하는 일이 없게 한다. 두 번째부터는 채울 행이 없다
DO $$
BEGIN
    ALTER TABLE node_metrics ADD COLUMN IF NOT EXISTS loaded_at timestamptz;
    UPDATE node_metrics SET loaded_at = ts WHERE loaded_at IS NULL;
    ALTER TABLE node_metrics ALTER COLUMN loaded_at SET DEFAULT now();
    ALTER TABLE node_metrics ALTER COLUMN loaded_at SET NOT NULL;
END
$$;
CREATE INDEX IF NOT EXISTS idx_node_metrics_node_loaded ON node_metrics (node_id, loaded_at);

-- 차단 목록 감사 (a1 R201 차단 대량 해제의 입력)
--   차단의 해제 · 만료 변경을 DB 트리거가 events 에 남긴다 (sensor = 'audit'). 콘솔을 거치지 않은 psql 직접 변경도 남는다.
--   누가 했는지는 앱이 트랜잭션 안에서 set_config('opsloop.actor', <사용자>, true) 로 넘긴다 (app/main.py add_action).
--   넘기지 않았으면 'db:<DB 역할>' 이다. triage.py 도 판정자를 넘긴다. triage 의 차단은 만료가 없으므로(영구)
--   살아 있는 콘솔 차단에 다시 걸면 extended 가 남는다.
--     console.block.released   살아 있는 차단을 풀거나 지웠다          R201 이 센다
--     console.block.shortened  살아 있는 차단의 만료를 앞당겼다        R201 이 센다
--     console.block.extended   살아 있는 차단의 만료를 늦췄다
--   만료는 어디서도 집행하지 않고 활성은 released_at IS NULL 로만 정한다. 그래서 살아 있는 차단을 푸는 것은
--   만료가 지났든 아니든 해제(released)다. 만료가 지났는지는 input 의 past_expiry 로만 남긴다. 호출자가 넣은
--   해제 시각(미래 · 과거)으로 분류가 갈리지 않는다. 만료를 집행하는 작업(3.9)이 생기면 그 해제를 따로 가른다.
--   살아 있는 차단의 주소(actor_ip)를 바꾸는 것도 원래 주소의 해제로 남긴다 (how=readdress).
--   이미 풀린 차단을 다시 풀거나 풀린 차단을 새로 거는 것은 남기지 않는다.
--   sensor 를 console 로 두지 않는다. v1 · v2 R005(기준선)는 sensors 가 없으면 cowrie · decoy · console 을 세므로
--   console 로 두면 허니팟 규칙의 입력이 바뀐다. audit 는 탐지기의 BASELINE_SENSORS 밖이다.
--   계정(console_users) 감사는 아직 두지 않는다.
--
--   잔여 위험 (T-8): 콘솔 · 다리 · 탐지기는 최소 권한 역할(이슈 #31 블록)로 붙어 트리거를 끄거나 TRUNCATE 할 수 없다.
--   소유자 opsloop(슈퍼유저)로 붙는 것은 스키마 적용 · nodes.py · auth.py add 뿐이라, 우회는 데이터 노드 root 의 의도적 행위로 좁혀진다.
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS released_by text;

CREATE OR REPLACE FUNCTION audit_event(p_eventid text, p_input text) RETURNS void
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_ts    timestamptz := clock_timestamp();
    -- set_config(…, true) 가 끝난 연결에서는 NULL 이 아니라 '' 가 돌아온다
    v_actor text := coalesce(nullif(current_setting('opsloop.actor', true), ''), 'db:' || session_user);
BEGIN
    INSERT INTO events (line_hash, ts, eventid, src_ip, username, input, provenance, sensor)
    VALUES (encode(sha256(convert_to(concat_ws('|', 'audit', p_eventid, v_ts::text,
                                               txid_current()::text, v_actor, p_input), 'UTF8')), 'hex'),
            v_ts, p_eventid, inet_client_addr(), left(v_actor, 128),
            left(format('by=%s %s', v_actor, p_input), 1024), 'real', 'audit')
    ON CONFLICT (line_hash) DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION audit_blocklist() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.released_at IS NULL THEN          -- 살아 있는 차단을 지우는 것도 해제다
            PERFORM audit_event('console.block.released',
                                format('ip=%s incident=%s how=delete past_expiry=%s', host(OLD.actor_ip),
                                       coalesce(OLD.incident_key, '-'),
                                       CASE WHEN OLD.expires_at <= now() THEN 'yes' ELSE 'no' END));
        END IF;
        RETURN NULL;
    END IF;
    IF OLD.released_at IS NULL AND NEW.actor_ip IS DISTINCT FROM OLD.actor_ip THEN
        -- 주소를 바꾸면 원래 주소의 차단이 풀린다. 해제 · 만료 변경이 함께 있어도 이 한 줄로 남긴다
        PERFORM audit_event('console.block.released',
                            format('ip=%s incident=%s how=readdress to=%s', host(OLD.actor_ip),
                                   coalesce(OLD.incident_key, '-'), host(NEW.actor_ip)));
    ELSIF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL THEN
        SELECT verdict INTO v FROM verdicts WHERE incident_key = NEW.incident_key
         ORDER BY created_at DESC LIMIT 1;
        PERFORM audit_event('console.block.released',
            format('ip=%s incident=%s verdict=%s past_expiry=%s', host(NEW.actor_ip),
                   coalesce(NEW.incident_key, '-'), coalesce(v, 'none'),
                   CASE WHEN OLD.expires_at <= now() THEN 'yes' ELSE 'no' END));
    ELSIF OLD.released_at IS NULL AND NEW.released_at IS NULL
          AND NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        PERFORM audit_event(
            CASE WHEN NEW.expires_at IS NOT NULL AND (OLD.expires_at IS NULL OR NEW.expires_at < OLD.expires_at)
                 THEN 'console.block.shortened' ELSE 'console.block.extended' END,
            format('ip=%s from=%s to=%s', host(NEW.actor_ip), coalesce(OLD.expires_at::text, 'none'),
                   coalesce(NEW.expires_at::text, 'none')));
    END IF;
    RETURN NULL;
END;
$$;

-- CREATE OR REPLACE TRIGGER 로 바꾼다 (PostgreSQL 14+). DROP 뒤 CREATE 는 그 사이의 해제를 놓친다
CREATE OR REPLACE TRIGGER trg_audit_blocklist
    AFTER UPDATE OF released_at, expires_at, actor_ip OR DELETE ON blocklist
    FOR EACH ROW EXECUTE FUNCTION audit_blocklist();

-- 감사 기록 조회 (S-14). 차단 변경 · 콘솔에서 발급·취소한 노드 토큰 · 알림 채널 변경의 메타데이터만 담는다
CREATE OR REPLACE VIEW audit_log AS
SELECT ts, eventid, username AS actor, host(src_ip) AS db_client, input AS detail
  FROM events
 WHERE sensor = 'audit' AND (eventid LIKE 'console.block.%' OR eventid LIKE 'console.node.token.%'
                             OR eventid LIKE 'console.notify.%');

-- 차단 변경 · 등록 토큰 · 알림 채널 감사 행은 추가만 된다. 적재기 · 다리는 INSERT … DO NOTHING 만 하고,
--   parse_decoy.py 의 출처 재분류는 decoy 행만 고치므로 걸리지 않는다
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '감사 이벤트는 고치거나 지울 수 없다 (%)', OLD.eventid;
END;
$$;
CREATE OR REPLACE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW WHEN (OLD.sensor = 'audit' AND (OLD.eventid LIKE 'console.block.%' OR OLD.eventid LIKE 'console.node.token.%'
                                                 OR OLD.eventid LIKE 'console.notify.%'))
    EXECUTE FUNCTION audit_append_only();

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

-- 알림 (이슈 #33)
--   콘솔이 Microsoft Teams(Workflows 웹훅 · Adaptive Card) 와 일반 웹훅(JSON) 으로 사건을 알린다.
--   등급은 즉시(immediate) 와 일일 요약(daily 09:00 KST), 사건 종류는 incident.created · pending.overdue · node.silent 다.
--   url 은 비밀값이다. 콘솔은 응답 · 감사 · 이력 · 로그 어디에도 원문을 넣지 않고 호스트와 끝 4자만 보인다.
--   메시지 틀은 문자 치환만 한다 ({event_label} {count} {severity_counts} {rule_id} {rule_name} {severity} {who}
--   {elapsed} {first_ts} {incident_key} {link}). 형식 지정자는 받지 않는다.
CREATE TABLE IF NOT EXISTS notify_channels (
    id              bigserial PRIMARY KEY,
    name            text        NOT NULL UNIQUE,
    kind            text        NOT NULL CHECK (kind IN ('teams', 'webhook')),
    url             text        NOT NULL,
    grade           text        NOT NULL CHECK (grade IN ('immediate', 'daily')),
    events          text[]      NOT NULL DEFAULT '{incident.created,pending.overdue,node.silent}',
    min_severity    text        NOT NULL DEFAULT 'low' CHECK (min_severity IN ('critical', 'high', 'medium', 'low')),
    batch_seconds   integer     NOT NULL DEFAULT 300 CHECK (batch_seconds BETWEEN 0 AND 86400),
    template_header text        NOT NULL DEFAULT '[OpsLoop] {event_label} {count}건',
    template_item   text        NOT NULL DEFAULT '{rule_id} {rule_name} · {severity} · {who} · {elapsed}',
    enabled         boolean     NOT NULL DEFAULT true,
    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
-- 알림 기준 시각. 만들 때 · 다시 켤 때 · 등급이나 사건 종류 · 최소 심각도로 범위를 넓힐 때 now() 가 된다.
--   발송기는 이 시각 뒤에 생긴 사건 · 목표를 넘긴 미판정만 넣어, 켜는 순간 밀린 알림이 쏟아지지 않게 한다.
ALTER TABLE notify_channels ADD COLUMN IF NOT EXISTS enabled_at timestamptz NOT NULL DEFAULT now();

-- 발송 이력. (채널, 사건 종류, 대상) 이 같으면 한 번만 넣는다. 대상은 incident_key · 'node:<id>@<침묵 시작 ISO>' ·
--   'YYYY-MM-DD'(일일 요약) · 'test:<uuid>'(시험 발송) 이다. payload 는 요약만 담고 원문 로그를 넣지 않는다.
--   보내기는 status='queued' AND next_attempt_at <= now() 인 행을 FOR UPDATE SKIP LOCKED 로 집는다.
--   실패하면 attempts 를 올리고 1 · 5 · 15분 뒤 다시 보내며, 넘기면 failed 다. error 는 예외 이름 · 응답 코드만이다.
CREATE TABLE IF NOT EXISTS notify_deliveries (
    id              bigserial PRIMARY KEY,
    channel_id      bigint      NOT NULL REFERENCES notify_channels (id) ON DELETE CASCADE,
    event           text        NOT NULL
                    CHECK (event IN ('incident.created', 'pending.overdue', 'node.silent', 'daily.summary', 'test')),
    subject_key     text        NOT NULL,
    payload         jsonb       NOT NULL,
    status          text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sending', 'sent', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claimed_at      timestamptz,
    claimed_by      text,
    response_code   integer,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    UNIQUE (channel_id, event, subject_key)
);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_due     ON notify_deliveries (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_channel ON notify_deliveries (channel_id, created_at DESC);

-- 콘솔 역할(opsloop_console)이 있으면 알림 표의 읽기 · 쓰기와 시퀀스 사용을 준다. 역할은 여기서 만들지 않는다.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT, INSERT, UPDATE ON notify_channels, notify_deliveries TO opsloop_console;
        GRANT USAGE ON SEQUENCE notify_channels_id_seq, notify_deliveries_id_seq TO opsloop_console;
    END IF;
END
$$;
