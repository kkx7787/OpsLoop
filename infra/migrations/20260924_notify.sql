-- 알림 채널 · 발송 이력 (이슈 #33). schema.sql 의 "알림" 절과 같은 내용이며 여러 번 적용해도 결과가 같다.
--   기존 표 · 함수(events · audit_append_only)는 schema.sql 을 전제로 한다.
BEGIN;
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

-- 감사 조회 뷰와 변경 방지 트리거에 알림 채널 감사 행(console.notify.%)을 더한다
CREATE OR REPLACE VIEW audit_log AS
SELECT ts, eventid, username AS actor, host(src_ip) AS db_client, input AS detail
  FROM events
 WHERE sensor = 'audit' AND (eventid LIKE 'console.block.%' OR eventid LIKE 'console.node.token.%'
                             OR eventid LIKE 'console.notify.%');

CREATE OR REPLACE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW WHEN (OLD.sensor = 'audit' AND (OLD.eventid LIKE 'console.block.%' OR OLD.eventid LIKE 'console.node.token.%'
                                                 OR OLD.eventid LIKE 'console.notify.%'))
    EXECUTE FUNCTION audit_append_only();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT, INSERT, UPDATE ON notify_channels, notify_deliveries TO opsloop_console;
        GRANT USAGE ON SEQUENCE notify_channels_id_seq, notify_deliveries_id_seq TO opsloop_console;
    END IF;
END
$$;
COMMIT;
