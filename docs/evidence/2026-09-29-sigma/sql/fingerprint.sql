-- 복원 지문. 사건 키 md5 는 incident_key 를 바이트 순서로 줄바꿈 이어 붙인 것의 md5 다
SELECT 'events', count(*) FROM events
UNION ALL SELECT 'events_real', count(*) FROM events WHERE provenance = 'real'
UNION ALL SELECT 'incidents', count(*) FROM incidents
UNION ALL SELECT 'verdicts', count(*) FROM verdicts
UNION ALL SELECT 'actions', count(*) FROM actions
UNION ALL SELECT 'blocklist', count(*) FROM blocklist
UNION ALL SELECT 'sessions', count(*) FROM sessions
UNION ALL SELECT 'detector_runs', count(*) FROM detector_runs
UNION ALL SELECT 'nginx_request_real', count(*) FROM events WHERE provenance='real' AND eventid='nginx.request'
UNION ALL SELECT 'decoy_request_real', count(*) FROM events WHERE provenance='real' AND eventid='decoy.request';
SELECT 'events_min_ts', min(ts), 'events_max_ts', max(ts) FROM events;
SELECT 'incident_key_md5', md5(string_agg(incident_key, E'\n' ORDER BY incident_key COLLATE "C")) FROM incidents;
SELECT 'by_version', rule_version, count(*) FROM incidents GROUP BY 2 ORDER BY 2;
SELECT 'c1_incidents', rule_id, count(*) FROM incidents WHERE rule_version='c1' GROUP BY 2 ORDER BY 2;
SELECT 'rule_versions', string_agg(rule_version, ',' ORDER BY rule_version) FROM rule_versions;
SELECT 'unjudged', count(*) FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key);
