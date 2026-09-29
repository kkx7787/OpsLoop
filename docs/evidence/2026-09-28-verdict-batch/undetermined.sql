SET statement_timeout = '240s';
WITH nv AS (
  SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity, i.actor_ip, i.first_ts, i.last_ts,
         i.signal_count, i.session_count, i.status, i.target,
         CASE WHEN jsonb_typeof(i.evidence->'sessions') = 'array'
              THEN ARRAY(SELECT jsonb_array_elements_text(i.evidence->'sessions')) ELSE ARRAY[]::text[] END AS sessions
  FROM incidents i
  WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)
),
ev AS (
  SELECT n.incident_key, e.eventid, e.input, e.username, e.password, e.shasum, e.url, e.http_status, e.http_method
  FROM nv n JOIN events e ON e.src_ip = n.actor_ip
   AND (e.session = ANY(n.sessions) OR e.ts BETWEEN n.first_ts AND n.last_ts)
),
cnt AS (SELECT incident_key, jsonb_object_agg(eventid, c) AS counts
        FROM (SELECT incident_key, eventid, count(*) c FROM ev GROUP BY 1,2) s GROUP BY 1),
cmds AS (SELECT incident_key, jsonb_agg(jsonb_build_array(input, c) ORDER BY c DESC) AS commands
         FROM (SELECT incident_key, input, count(*) c, row_number() OVER (PARTITION BY incident_key ORDER BY count(*) DESC) rn
               FROM ev WHERE eventid = 'cowrie.command.input' AND input IS NOT NULL GROUP BY 1,2) s WHERE rn <= 6 GROUP BY 1),
creds AS (SELECT incident_key, jsonb_agg(jsonb_build_array(username, password, c) ORDER BY c DESC) AS creds
          FROM (SELECT incident_key, username, password, count(*) c, row_number() OVER (PARTITION BY incident_key ORDER BY count(*) DESC) rn
                FROM ev WHERE eventid IN ('cowrie.login.failed','cowrie.login.success') GROUP BY 1,2,3) s WHERE rn <= 6 GROUP BY 1),
files AS (SELECT incident_key, jsonb_agg(jsonb_build_array(eventid, shasum, url)) AS files
          FROM (SELECT incident_key, eventid, shasum, url, row_number() OVER (PARTITION BY incident_key) rn
                FROM ev WHERE eventid LIKE 'cowrie.session.file_%') s WHERE rn <= 5 GROUP BY 1),
web AS (SELECT incident_key, jsonb_agg(jsonb_build_array(http_method, url, http_status, c) ORDER BY c DESC) AS web
        FROM (SELECT incident_key, http_method, url, http_status, count(*) c, row_number() OVER (PARTITION BY incident_key ORDER BY count(*) DESC) rn
              FROM ev WHERE eventid IN ('nginx.request','decoy.request') GROUP BY 1,2,3,4) s WHERE rn <= 8 GROUP BY 1),
also AS (SELECT n.incident_key, jsonb_agg(jsonb_build_array(o.rule_id, o.severity, o.c) ORDER BY o.rule_id) AS also
         FROM nv n JOIN LATERAL (SELECT rule_id, severity, count(*) c FROM incidents WHERE actor_ip = n.actor_ip GROUP BY 1,2) o ON true
         GROUP BY 1),
cov AS (SELECT n.incident_key,
          (SELECT o.incident_key FROM incidents o
            WHERE o.actor_ip = n.actor_ip AND o.rule_version = n.rule_version
              AND o.first_ts <= n.last_ts + interval '15 minutes' AND o.last_ts >= n.first_ts - interval '15 minutes'
            ORDER BY CASE o.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, o.first_ts
            LIMIT 1) AS rep
        FROM nv n),
repv AS (SELECT c.incident_key, c.rep,
           (SELECT v.verdict FROM verdicts v WHERE v.incident_key = c.rep ORDER BY v.id DESC LIMIT 1) AS rep_verdict
         FROM cov c),
blk AS (SELECT n.incident_key,
               bool_or(b.released_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now())) AS live,
               max(b.released_by) AS released_by
        FROM nv n JOIN blocklist b ON b.actor_ip = n.actor_ip GROUP BY 1),
ab AS (SELECT first_key, count(*) total, count(DISTINCT actor_ip) sources FROM incident_absorbed GROUP BY 1)
SELECT jsonb_build_object(
  'key', n.incident_key, 'rule', n.rule_id, 'ver', n.rule_version, 'name', n.rule_name, 'sev', n.severity,
  'ip', host(n.actor_ip), 'first', n.first_ts, 'last', n.last_ts, 'signals', n.signal_count, 'sessions', n.session_count,
  'status', n.status, 'target', n.target,
  'counts', COALESCE(cnt.counts, '{}'::jsonb), 'commands', COALESCE(cmds.commands, '[]'::jsonb),
  'creds', COALESCE(creds.creds, '[]'::jsonb), 'files', COALESCE(files.files, '[]'::jsonb), 'web', COALESCE(web.web, '[]'::jsonb),
  'also', COALESCE(also.also, '[]'::jsonb), 'rep', repv.rep, 'rep_verdict', repv.rep_verdict,
  'blocked', COALESCE(blk.live, false), 'released_by', blk.released_by,
  'absorbed_total', COALESCE(ab.total, 0), 'absorbed_sources', COALESCE(ab.sources, 0))
FROM nv n LEFT JOIN cnt USING (incident_key) LEFT JOIN cmds USING (incident_key) LEFT JOIN creds USING (incident_key)
 LEFT JOIN files USING (incident_key) LEFT JOIN web USING (incident_key) LEFT JOIN also USING (incident_key)
 LEFT JOIN repv USING (incident_key) LEFT JOIN blk USING (incident_key) LEFT JOIN ab ON ab.first_key = n.incident_key
ORDER BY CASE n.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, n.rule_id, n.first_ts;
