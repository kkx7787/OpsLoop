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

# 미판정 전체(먼저 처리할 사건, targets.queue_of). 장비로 앞 · 뒤를 가른 뒤 자르므로 LIMIT 을 두지 않는다
PENDING_ROWS = PENDING + """
SELECT incident_key, rule_id, rule_version, rule_name, severity, host(actor_ip) AS actor_ip, target, first_ts,
       age AS pending_seconds, target_seconds, age >= target_seconds AS overdue
FROM pending ORDER BY first_ts, incident_key"""

# 미결(판단 유보): 사건의 최신 판정이 사람이 남긴 undetermined 다. 시스템 기록(operator 'system:…', v3 전환 일괄 처리)은
#   사람의 판단이 아니라 빼고 기록은 그대로 둔다(보고서 backlog.undetermined 는 시스템 기록을 포함한 수다, reports.UNDETERMINED_SQL).
#   {v} 는 최신 판정 한 행(verdict · operator)의 별칭이다. 판정이 없으면(NULL) 거짓이다(참 · 거짓만 낸다).
#   대시보드 수 · 사건 목록 undetermined 필터(main.incident_page) · 대상 카드 수(targets.INCIDENTS_SQL)가 같은 식을 쓴다
HUMAN_UNDETERMINED = ("({v}.verdict IS NOT DISTINCT FROM 'undetermined'"
                      " AND coalesce({v}.operator, '') NOT LIKE 'system:%')")

# 미결 사건 수(사건 단위: 같은 사건 여러 번 미결 → 1건, 미결 뒤 재판정 → 제외). 미판정 수처럼 시험 출발지를 빼지 않는다
UNDETERMINED_COUNT = f"""
SELECT count(*) FROM (SELECT DISTINCT ON (incident_key) verdict, operator FROM verdicts
                      ORDER BY incident_key, created_at DESC, id DESC) v
WHERE {HUMAN_UNDETERMINED.format(v="v")}"""

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
WHERE NOT is_test_source(i.actor_ip)   -- 시험 출발지 제외 (이슈 #51, rule_quality 뷰와 같다)
GROUP BY i.rule_id, i.rule_version ORDER BY i.rule_id, i.rule_version
"""


async def dashboard_metrics(connection, as_of):
    counts = dict(await connection.fetchrow(PENDING_COUNTS, as_of))
    buckets = [counts.pop(f"age_{index}") for index in range(5)]
    counts["undetermined"] = await connection.fetchval(UNDETERMINED_COUNT)
    oldest = await connection.fetch(OLDEST_PENDING, as_of)
    rates = await connection.fetch(RULE_RATES)
    return {
        "as_of": as_of.isoformat(),
        "pending": counts | {"age_distribution": buckets},
        "oldest_pending": [dict(row) | {"first_ts": row["first_ts"].isoformat()} for row in oldest],
        "rule_quality": [dict(row) for row in rates],
    }
