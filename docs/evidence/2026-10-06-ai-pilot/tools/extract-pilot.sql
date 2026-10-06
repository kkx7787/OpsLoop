-- AI 판정 추천 조정용 20건 추출 (읽기 전용). 사람 판정(han, ubuntu)만, 시험 출발지 제외.
-- 같은 페이로드 중복은 규칙이 흡수하지 않던 v1, v2 사건에만 계산한다(v3 는 규칙이 흡수한다).
-- 정답이 새지 않게 판정 뒤에 생기는 정보(지금 차단 상태, 그 뒤 사건)는 넣지 않는다.
-- label 과 proposed 는 채점용이며 실행 스크립트가 지시문에 넣지 않는다.
WITH last AS (
  SELECT DISTINCT ON (incident_key) incident_key, verdict, operator, proposed
  FROM verdicts ORDER BY incident_key, created_at DESC, id DESC
), pool AS (
  SELECT i.incident_key, i.rule_id, i.rule_name, i.severity, i.rule_version, i.actor_ip, i.first_ts, i.last_ts,
         i.signal_count, i.session_count, i.evidence, l.verdict, l.proposed,
         ARRAY(SELECT jsonb_array_elements_text(coalesce(i.evidence -> 'sessions', '[]'::jsonb))) AS sess,
         row_number() OVER (PARTITION BY i.rule_id, l.verdict ORDER BY md5(i.incident_key || ':pilot-1006')) AS rn
  FROM incidents i JOIN last l USING (incident_key)
  WHERE l.operator IN ('han', 'ubuntu') AND NOT is_test_source(i.actor_ip)
), quota(rule_id, verdict, n) AS (VALUES
  ('R001', 'threat', 2), ('R002', 'threat', 3), ('R003', 'threat', 2), ('R004', 'threat', 2), ('R006', 'threat', 1),
  ('R001', 'non_actionable', 2), ('R003', 'non_actionable', 2), ('R005', 'non_actionable', 2), ('R105', 'non_actionable', 1),
  ('R102', 'false_positive', 1), ('R202', 'benign_positive', 1), ('R301', 'false_positive', 1)
), pick AS (
  SELECT p.* FROM pool p JOIN quota q ON q.rule_id = p.rule_id AND q.verdict = p.verdict AND p.rn <= q.n
)
SELECT json_build_object(
  'key', k.incident_key, 'label', k.verdict, 'proposed', k.proposed,
  'case', json_build_object(
    'rule_id', k.rule_id, 'rule_name', k.rule_name, 'severity', k.severity, 'rule_version', k.rule_version,
    'source_ip', host(k.actor_ip), 'first_ts', k.first_ts, 'last_ts', k.last_ts,
    'signal_count', k.signal_count, 'session_count', k.session_count,
    'rule_evidence', CASE WHEN length(k.evidence::text) > 3000 THEN to_jsonb(left(k.evidence::text, 3000) || ' (잘림)') ELSE k.evidence END,
    'event_counts', (SELECT json_object_agg(eventid, c) FROM (
        SELECT e.eventid, count(*) c FROM events e
        WHERE e.src_ip = k.actor_ip AND (e.session = ANY(k.sess) OR e.ts BETWEEN k.first_ts AND k.last_ts) GROUP BY 1) x),
    -- 비밀번호 원문은 넣지 않는다. 타인의 실제 자격증명일 수 있어 콘솔도 화면에 내지 않는다(app/main.py raw). 모델이 근거 문장에 옮겨
    -- 적으면 콘솔 AI 추천 칸으로 새어 나간다(평가 p2 에서 140건 중 51건). 판정에는 계정 · 성공 여부 · 횟수면 된다
    'logins', (SELECT json_agg(json_build_object('user', username, 'result', eventid, 'count', c)) FROM (
        SELECT username, eventid, count(*) c FROM events e
        WHERE e.src_ip = k.actor_ip AND (e.session = ANY(k.sess) OR e.ts BETWEEN k.first_ts AND k.last_ts)
          AND eventid IN ('cowrie.login.failed', 'cowrie.login.success')
        GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 6) x),
    'commands', (SELECT json_agg(json_build_object('input', left(input, 300), 'count', c)) FROM (
        SELECT input, count(*) c FROM events e
        WHERE e.src_ip = k.actor_ip AND (e.session = ANY(k.sess) OR e.ts BETWEEN k.first_ts AND k.last_ts)
          AND eventid = 'cowrie.command.input' AND input IS NOT NULL
        GROUP BY 1 ORDER BY 2 DESC LIMIT 10) x),
    'files', (SELECT json_agg(json_build_object('event', f.eventid, 'sha256', left(f.shasum, 16), 'url', f.url,
          'same_payload_other_source_within_24h_before',
          CASE WHEN k.rule_version IN ('v1', 'v2') THEN (SELECT min(e2.ts) FROM events e2 WHERE e2.shasum = f.shasum AND e2.src_ip <> k.actor_ip
             AND e2.eventid LIKE 'cowrie.session.file_%' AND e2.ts < f.ts AND e2.ts >= f.ts - interval '24 hours'
             AND f.shasum NOT LIKE 'e3b0c442%') END)) FROM (
        SELECT eventid, shasum, url, ts FROM events e
        WHERE e.src_ip = k.actor_ip AND (e.session = ANY(k.sess) OR e.ts BETWEEN k.first_ts AND k.last_ts)
          AND eventid LIKE 'cowrie.session.file_%' ORDER BY ts LIMIT 5) f),
    'web_requests', (SELECT json_agg(json_build_object('sensor', sensor, 'method', http_method, 'url', left(url, 200),
          'status', http_status, 'user_agent', left(user_agent, 120), 'count', c)) FROM (
        SELECT sensor, http_method, url, http_status, user_agent, count(*) c FROM events e
        WHERE e.src_ip = k.actor_ip AND e.sensor NOT IN ('cowrie', 'gateway')
          AND (e.session = ANY(k.sess) OR e.ts BETWEEN k.first_ts AND k.last_ts)
        GROUP BY 1, 2, 3, 4, 5 ORDER BY 6 DESC LIMIT 8) x),
    'same_source_overlap_higher', (SELECT CASE WHEN i2.incident_key <> k.incident_key THEN i2.rule_id END
        FROM incidents i2 WHERE i2.actor_ip = k.actor_ip AND i2.rule_version = k.rule_version
          AND i2.first_ts <= k.last_ts + interval '15 minutes' AND i2.last_ts >= k.first_ts - interval '15 minutes'
        ORDER BY CASE i2.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, i2.first_ts
        LIMIT 1),
    'earlier_incidents_same_source', (SELECT json_object_agg(rule_id, c) FROM (
        SELECT rule_id, count(*) c FROM incidents i3
        WHERE i3.actor_ip = k.actor_ip AND i3.first_ts < k.first_ts GROUP BY 1) x)
  ))
FROM pick k ORDER BY k.verdict = 'threat' DESC, k.rule_id, k.incident_key;
