-- R107(sg1) 사건과, 같은 출발지 · 겹치는 구간(첫 시각 ~ 끝 시각이 서로 걸침)의 c1 사건(R105 · R106)
SELECT 'r107_incidents', count(*) FROM incidents WHERE rule_version = 'sg1';
SELECT 'r107_by_signature', s, count(*) FROM incidents i, jsonb_array_elements_text(i.evidence -> 'signatures') s
 WHERE i.rule_version = 'sg1' GROUP BY s ORDER BY s;
SELECT 'overlap', i.incident_key, c.incident_key FROM incidents i JOIN incidents c
  ON c.rule_version = 'c1' AND c.actor_ip = i.actor_ip AND c.first_ts <= i.last_ts AND c.last_ts >= i.first_ts
 WHERE i.rule_version = 'sg1' ORDER BY 2, 3;
SELECT 'same_source_any_time', count(DISTINCT c.incident_key) FROM incidents i JOIN incidents c
  ON c.rule_version = 'c1' AND c.actor_ip = i.actor_ip WHERE i.rule_version = 'sg1';
SELECT 'c1_incidents', rule_id, host(actor_ip), first_ts, last_ts, signal_count, evidence -> 'signatures' FROM incidents WHERE rule_version = 'c1' ORDER BY first_ts;
SELECT 'runs', id, rule_version, since, until, incidents FROM detector_runs WHERE id > 29971 ORDER BY id;
SELECT 'rule_versions', string_agg(rule_version, ',' ORDER BY rule_version) FROM rule_versions;
