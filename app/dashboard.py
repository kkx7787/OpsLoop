"""대시보드 집계. 기존 /api/stats/summary 응답을 보완한다.

미판정은 상태가 아니라 판정 기록의 부재로 센다. 재판정은 마지막 한 건만 사용한다.
대량 원문 로그를 브라우저에 가져오지 않고 DB에서 집계한다.
"""

PENDING = """
WITH pending AS (
    SELECT i.*, greatest(0, extract(epoch FROM ($1::timestamptz - first_ts)))::float8 AS age,
        CASE WHEN rule_id ~ '^R2[0-9]{2}([^0-9]|$)' THEN 3600
             WHEN severity = 'critical' THEN 3600 WHEN severity = 'high' THEN 14400
             WHEN severity = 'medium' THEN 43200 ELSE 86400 END AS target_seconds
    FROM incidents i
    WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)
)
"""

PENDING_COUNTS = PENDING + """
SELECT count(*) AS total, coalesce(max(age), 0) AS oldest_seconds,
    count(*) FILTER (WHERE age >= target_seconds) AS overdue,
    count(*) FILTER (WHERE age >= target_seconds * 2.0 / 3 AND age < target_seconds) AS warning,
    count(*) FILTER (WHERE age < 3600) AS age_0,
    count(*) FILTER (WHERE age >= 3600 AND age < 14400) AS age_1,
    count(*) FILTER (WHERE age >= 14400 AND age < 43200) AS age_2,
    count(*) FILTER (WHERE age >= 43200 AND age < 86400) AS age_3,
    count(*) FILTER (WHERE age >= 86400) AS age_4
FROM pending
"""

OLDEST_PENDING = PENDING + """
SELECT incident_key, rule_id, rule_name, severity, host(actor_ip) AS actor_ip, target,
       first_ts, age AS pending_seconds, target_seconds, age >= target_seconds AS overdue
FROM pending ORDER BY first_ts, incident_key LIMIT 8
"""

RULE_RATES = """
WITH latest AS (
    SELECT DISTINCT ON (incident_key) incident_key, verdict
    FROM verdicts ORDER BY incident_key, created_at DESC, id DESC
)
SELECT i.rule_id, i.rule_version, count(*) AS incidents,
    count(v.verdict) FILTER (WHERE v.verdict <> 'undetermined') AS judged_effective,
    count(*) FILTER (WHERE v.verdict IN ('non_actionable', 'false_positive', 'benign_positive')) AS non_action,
    round(100.0 * count(*) FILTER (WHERE v.verdict IN ('non_actionable', 'false_positive', 'benign_positive'))
          / nullif(count(v.verdict) FILTER (WHERE v.verdict <> 'undetermined'), 0), 1) AS non_action_rate
FROM incidents i LEFT JOIN latest v USING (incident_key)
GROUP BY i.rule_id, i.rule_version ORDER BY i.rule_id, i.rule_version
"""


async def dashboard_metrics(connection, as_of):
    counts = dict(await connection.fetchrow(PENDING_COUNTS, as_of))
    buckets = [counts.pop(f"age_{index}") for index in range(5)]
    oldest = await connection.fetch(OLDEST_PENDING, as_of)
    rates = await connection.fetch(RULE_RATES)
    return {
        "as_of": as_of.isoformat(),
        "pending": counts | {"age_distribution": buckets},
        "oldest_pending": [dict(row) | {"first_ts": row["first_ts"].isoformat()} for row in oldest],
        "rule_quality": [dict(row) for row in rates],
    }
