\echo == 1. 판정 건수 (날짜 · 판정자 · 판정값)
SELECT created_at::date AS d, operator, verdict, count(*), count(decision_seconds) AS with_seconds FROM verdicts GROUP BY 1,2,3 ORDER BY 1,2,3;
\echo == 2. 판정 소요 시간 (decision_seconds 있는 것만) · 심각도별
SELECT i.severity, count(*) AS n, round(percentile_cont(0.5) WITHIN GROUP (ORDER BY v.decision_seconds)::numeric,1) AS p50, round(percentile_cont(0.9) WITHIN GROUP (ORDER BY v.decision_seconds)::numeric,1) AS p90, max(v.decision_seconds) AS max, round(avg(v.decision_seconds)::numeric,1) AS avg
FROM verdicts v JOIN incidents i USING (incident_key) WHERE v.decision_seconds IS NOT NULL GROUP BY 1 ORDER BY 1;
\echo == 3. 판정 소요 시간 · 판정값별
SELECT v.verdict, count(*) AS n, round(percentile_cont(0.5) WITHIN GROUP (ORDER BY v.decision_seconds)::numeric,1) AS p50, round(percentile_cont(0.9) WITHIN GROUP (ORDER BY v.decision_seconds)::numeric,1) AS p90, max(v.decision_seconds)
FROM verdicts v WHERE v.decision_seconds IS NOT NULL GROUP BY 1 ORDER BY 1;
\echo == 4. 사건 생성 → 첫 판정까지 (시간) · 심각도별 · 목표 구간 비율
WITH fv AS (SELECT incident_key, min(created_at) AS first_v FROM verdicts GROUP BY 1)
SELECT i.severity, count(*) AS judged,
  round(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM fv.first_v - i.created_at)/3600)::numeric,1) AS p50_h,
  round(percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM fv.first_v - i.created_at)/3600)::numeric,1) AS p90_h,
  round(100.0*count(*) FILTER (WHERE fv.first_v - i.created_at <= interval '1 hour')/count(*),1) AS within_1h,
  round(100.0*count(*) FILTER (WHERE fv.first_v - i.created_at <= interval '4 hours')/count(*),1) AS within_4h,
  round(100.0*count(*) FILTER (WHERE fv.first_v - i.created_at <= interval '24 hours')/count(*),1) AS within_24h
FROM incidents i JOIN fv USING (incident_key) GROUP BY 1 ORDER BY 1;
\echo == 5. 미판정 잔량 추이 (날짜 끝 기준 · 판정 없음 · 판단 유보 누적)
WITH d AS (SELECT generate_series(date '2026-09-04', current_date, interval '1 day')::date AS d),
fv AS (SELECT incident_key, min(created_at) AS first_v FROM verdicts GROUP BY 1)
SELECT d.d,
  (SELECT count(*) FROM incidents i WHERE i.created_at < d.d + 1) AS created_cum,
  (SELECT count(*) FROM incidents i LEFT JOIN fv USING (incident_key) WHERE i.created_at < d.d + 1 AND (fv.first_v IS NULL OR fv.first_v >= d.d + 1)) AS no_verdict,
  (SELECT count(*) FROM (SELECT DISTINCT ON (incident_key) incident_key, verdict FROM verdicts WHERE created_at < d.d + 1 ORDER BY incident_key, id DESC) x WHERE verdict = 'undetermined') AS undetermined_latest
FROM d ORDER BY 1;
\echo == 6. 판단 유보(undetermined) 최신 판정 · 규칙 버전별
SELECT i.rule_version, i.rule_id, count(*) FROM (SELECT DISTINCT ON (incident_key) incident_key, verdict FROM verdicts ORDER BY incident_key, id DESC) x JOIN incidents i USING (incident_key) WHERE x.verdict='undetermined' GROUP BY 1,2 ORDER BY 1,2;
\echo == 7. rule_quality 현재
SELECT * FROM rule_quality ORDER BY 1,2;
\echo == 8. 판정 목표 시간 관련 표 · 열
SELECT table_name, column_name FROM information_schema.columns WHERE column_name ~ 'target|deadline|due' ORDER BY 1,2;
\echo == 9. 새 차단 집행 상태
SELECT count(*) FILTER (WHERE enforced_at IS NOT NULL) AS enforced, count(*) AS total, min(enforced_at)::time(0), max(enforce_note) FROM blocklist WHERE requested_by='triage:han' AND created_at > now() - interval '30 minutes';
