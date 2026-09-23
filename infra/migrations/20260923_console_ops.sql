-- #27: 최신 판정 집계 · 토큰 발급/취소 감사. 기존 함수와 표는 schema.sql을 전제로 한다.
BEGIN;
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

CREATE OR REPLACE VIEW audit_log AS
SELECT ts, eventid, username AS actor, host(src_ip) AS db_client, input AS detail
  FROM events
 WHERE sensor = 'audit' AND (eventid LIKE 'console.block.%' OR eventid LIKE 'console.node.token.%');

CREATE OR REPLACE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW WHEN (OLD.sensor = 'audit' AND (OLD.eventid LIKE 'console.block.%' OR OLD.eventid LIKE 'console.node.token.%'))
    EXECUTE FUNCTION audit_append_only();
COMMIT;
