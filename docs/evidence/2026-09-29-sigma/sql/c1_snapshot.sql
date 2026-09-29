-- c1 사건 행(키 · 끝 시각 · 건수 · 세션 수 · 근거 md5)과 전체 사건 키 md5
SELECT incident_key, last_ts, signal_count, session_count, md5(evidence::text), severity FROM incidents WHERE rule_version = 'c1' ORDER BY incident_key COLLATE "C";
SELECT 'all_keys', count(*), md5(string_agg(incident_key, E'\n' ORDER BY incident_key COLLATE "C")) FROM incidents;
SELECT 'non_sg_keys', count(*), md5(string_agg(incident_key, E'\n' ORDER BY incident_key COLLATE "C")) FROM incidents WHERE rule_version NOT IN ('sg1');
SELECT 'detector_runs', count(*), max(id) FROM detector_runs;
