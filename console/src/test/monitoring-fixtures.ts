import type { BlockEntry, Summary } from '@/api/monitoring'

export const AS_OF = '2026-09-23T08:00:00Z'
export const MONITORING_SUMMARY: Summary = {
  as_of: AS_OF,
  pending: { total: 12, overdue: 3, warning: 2, oldest_seconds: 22_320, age_distribution: [4, 5, 3, 0, 0] },
  oldest_pending: [{ incident_key: 'R003|v2|192.0.2.8', rule_id: 'R003', rule_name: '악성코드 투하', severity: 'critical', actor_ip: '192.0.2.8', target: null, first_ts: '2026-09-23T01:48:00Z', pending_seconds: 22_320, target_seconds: 3600, overdue: true }],
  rule_quality: [
    { rule_id: 'R001', rule_version: 'v2', incidents: 20, judged_effective: 10, non_action: 3, non_action_rate: 30 },
    { rule_id: 'R201', rule_version: 'v2', incidents: 2, judged_effective: 0, non_action: 0, non_action_rate: null },
  ],
  blocked_ips: 2, latest_event: AS_OF,
}

export function blockEntry(extra: Partial<BlockEntry> = {}): BlockEntry {
  return { actor_ip: '192.0.2.8', reason: '반복 인증 시도', incident_key: 'R001|v2|192.0.2.8', created_at: AS_OF, expires_at: '2026-09-24T08:00:00Z', released_at: null, method: null, requested_by: 'operator', enforced_at: null, enforce_note: null, released_by: null, checked_at: AS_OF, ...extra }
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
