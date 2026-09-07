-- 인시던트가 생기면 DB 가 알린다 (WBS 3.x)
--
-- 콘솔 실시간 갱신을 위해 별도 메시지 브로커(Redis 등)를 두는 대신
-- PostgreSQL 의 LISTEN/NOTIFY 를 쓴다. 운영할 구성요소가 하나 줄고,
-- 알림과 데이터가 같은 트랜잭션 안에서 처리되어 유실 구간이 없다.
--
-- 제약: NOTIFY 페이로드는 8000 바이트를 넘을 수 없다. 그래서 인시던트
-- 전체가 아니라 식별자와 요약만 보낸다. 상세는 콘솔이 REST 로 가져간다.

CREATE OR REPLACE FUNCTION notify_incident() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('opsloop_incident', json_build_object(
        'incident_key', NEW.incident_key,
        'rule_id',      NEW.rule_id,
        'rule_name',    NEW.rule_name,
        'severity',     NEW.severity,
        'actor_ip',     host(NEW.actor_ip),
        'first_ts',     NEW.first_ts,
        'last_ts',      NEW.last_ts,
        'signal_count', NEW.signal_count,
        'status',       NEW.status
    )::text);
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notify_incident ON incidents;
CREATE TRIGGER trg_notify_incident
    AFTER INSERT ON incidents
    FOR EACH ROW EXECUTE FUNCTION notify_incident();