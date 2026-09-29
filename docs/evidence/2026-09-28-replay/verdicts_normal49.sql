-- 이슈 #49 B2 — 정상 구간(2026-09-27 08:30 ~ 16:30 UTC)에서 뜬 사건을 정의서 5절 판정값(false_positive)으로 판정한다. 실험 DB(opsloop-lab49)에서만.
-- 시나리오 id 는 사건 first_ts 의 표식 행(message '[정상 시나리오 <id>] …')에서 읽는다. 콘솔과 같이 판정이 곧 종결이라 status 를 resolved 로 둔다.
\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE n49_fp AS
SELECT i.incident_key, s.sid, (i.evidence->>'observed_count_max')::float AS observed
FROM incidents i
JOIN LATERAL (SELECT substring(e.message from 10 for 3) AS sid FROM events e
              WHERE e.ts = i.first_ts AND e.src_ip = i.actor_ip AND e.message ~ '^\[정상 시나리오 [A-Z][0-9]{2}\] ' LIMIT 1) s ON true
WHERE i.rule_version IN ('w2', 'w2-c3', 'w2-c8')
  AND i.first_ts >= '2026-09-27 08:30:00+00' AND i.first_ts < '2026-09-27 16:30:00+00'
  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key);
INSERT INTO verdicts (incident_key, verdict, reason, observed_value, operator)
SELECT incident_key, 'false_positive',
       '[정상 시나리오 ' || sid || '] 사전 정의 정상 시나리오가 규칙에 걸림 → 오탐 (정상 트래픽 정의서 5절)', observed, 'lab:normal49'
FROM n49_fp ORDER BY incident_key;
UPDATE incidents SET status = 'resolved' WHERE incident_key IN (SELECT incident_key FROM n49_fp);
SELECT 'verdicts_inserted', count(*) FROM n49_fp;
COMMIT;
