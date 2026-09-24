-- 규칙 v3 (폐루프 2회차) 운영 전환. schema.sql 의 '같은 페이로드 흡수 기록' 블록과 동일하며 여러 번 적용해도 같다.
--   20260925_round2.sql 뒤에 적용한다. round2(또는 schema.sql 역할 블록)를 다시 적용하면 모든 표의 권한을 먼저
--   거두므로 이 파일도 다시 적용한다.
BEGIN;
-- 같은 페이로드 흡수 기록 (규칙 v3)
--   detect.py 가 같은 페이로드 흡수로 지운 인시던트(kind = absorbed)와, 가린 것이 흡수된 인시던트뿐이라 억제로 지운
--   같은 출발지의 낮은 알림(kind = suppressed, via_key = 가린 흡수 인시던트)을 첫 사건(first_key) 아래 남긴다.
--   차단 근거(출발지 · 첫 시각 · 세션 · 키)는 이 표다. 상한 없이 모두 남는다.
--   incidents.evidence 와 따로 둔다. 판정된 첫 사건의 근거는 굳지만(trg_incidents_keep_judged) 이 표에는 판정 뒤의
--   흡수도 붙는다. 탐지는 지우는 문장에서 지운 행을 그대로 여기에 넣으므로, 지운 인시던트는 모두 여기 있다.
--   탐지 역할은 넣기만 한다(고치거나 지우지 않는다). 첫 사건을 참조 키로 걸지 않는다. 첫 사건이 지워져도 근거는 남는다.
--   rule_version · actor_ip 색인: 기준선 이탈 v3 가 지운 인시던트의 출발지도 제외 행위자로 센다.
--   규칙 v3 를 쓰기 전에 적용한다(infra/migrations/20260925_v3_absorbed.sql 이 이 블록과 같다). 역할 블록이 모든 표의
--   권한을 먼저 거두므로 권한은 여기서 다시 준다. 역할 블록 뒤에 있어야 한다.
CREATE TABLE IF NOT EXISTS incident_absorbed (
    first_key     text        NOT NULL,
    member_key    text        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('absorbed', 'suppressed')),
    via_key       text,
    rule_id       text        NOT NULL,
    rule_version  text        NOT NULL,
    actor_ip      inet,
    first_ts      timestamptz NOT NULL,
    last_ts       timestamptz NOT NULL,
    signal_count  integer     NOT NULL,
    sessions      text[]      NOT NULL DEFAULT '{}',
    payloads      text[]      NOT NULL DEFAULT '{}',
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (first_key, member_key),
    CHECK ((kind = 'suppressed') = (via_key IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS incident_absorbed_member ON incident_absorbed (member_key);
CREATE INDEX IF NOT EXISTS incident_absorbed_actor ON incident_absorbed (rule_version, actor_ip);

-- 흡수 후속 차단 약속 (규칙 v3)
--   첫 사건을 차단하며 흡수 출발지 함께 차단을 고르면 콘솔 · triage 가 여기에 만료와 함께 남긴다. 흡수는 첫 사건이
--   판정 · 차단된 뒤에도 24시간 창 끝까지 붙으므로, 콘솔이 주기적으로 약속이 살아 있는 첫 사건의 새 흡수 출발지를
--   같은 만료로 차단 목록에 올린다(app/absorbed.py AbsorbedFollower). 함께 해제하면 거둔다(released_at).
--   탐지 역할은 이 표를 보지 못한다(차단 목록 권한이 없는 것과 같다).
CREATE TABLE IF NOT EXISTS absorbed_blocks (
    first_key     text        PRIMARY KEY,
    expires_at    timestamptz NOT NULL,
    requested_by  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    released_at   timestamptz,
    released_by   text
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_detector') THEN
        GRANT SELECT, INSERT ON incident_absorbed TO opsloop_detector;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        -- 콘솔 상세의 흡수 목록과 흡수 출발지 함께 차단 · 해제(app/main.py · triage.py). 차단 목록 쓰기는 역할 블록의
        -- blocklist INSERT · UPDATE 로 된다. 표를 고치거나 지우지 못한다
        GRANT SELECT ON incident_absorbed TO opsloop_console;
        -- 후속 차단 약속: 함께 차단 · 해제(add_action · triage record)와 후속 차단 루프. 지우지 못한다
        GRANT SELECT, INSERT, UPDATE ON absorbed_blocks TO opsloop_console;
    END IF;
END
$$;
COMMIT;
