SELECT '남은 미판정' AS k, count(*)::text, string_agg(DISTINCT rule_id || ' ' || rule_version, ', ') FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key);
SELECT host(actor_ip), requested_by, expires_at::timestamp(0), enforced_at IS NOT NULL, coalesce(enforce_note, '-') FROM blocklist WHERE created_at > now() - interval '15 minutes' ORDER BY actor_ip;
SELECT status, count(*) FROM incidents WHERE incident_key IN (SELECT incident_key FROM verdicts WHERE reason LIKE '[판정안 일괄 검토]%') GROUP BY 1;
SELECT count(*) FROM events WHERE eventid LIKE 'console.block.%' AND ts > now() - interval '15 minutes';
