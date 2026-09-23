import type { AuditEntry, NodeEntry, RulesResult } from '@/api/operations'
export const RULES: RulesResult = {
  as_of: '2026-09-23T08:00:00Z', since: null, until: null,
  rows: [{ rule_id: 'R001', rule_version: 'v2', incidents: 4, judged: 3, judged_effective: 2, threats: 1, non_actionable: 1, false_positives: 0, benign_positives: 0, undetermined: 1, non_action_rate: 50, false_positive_rate: 0 }],
  versions: ['v1','v2'].map(version => ({ version, created_at: '2026-09-08T00:00:00Z', reason: '중복 경보 조건 조정', rules: [{ id: 'R001', name: 'SSH 무차별 대입', enabled: true, severity: 'medium', rationale: '반복 인증 실패', change: null }] })),
  runs: [{ id: 1, rule_version: 'v2', since: null, until: null, started_at: '2026-09-23T08:00:00Z', finished_at: '2026-09-23T08:00:01Z', incidents: 0 }],
}
export function nodeEntry(overrides: Partial<NodeEntry> = {}): NodeEntry { return { node_id: 'web-01', hostname: 'opsloop-web-01', addr: '192.0.2.21', logs: ['nginx','auth'], status: 'active', reception: 'normal', registered_at: '2026-09-21T08:00:00Z', last_seen_at: '2026-09-23T08:00:00Z', first_loaded_at: '2026-09-21T08:00:00Z', last_loaded_at: '2026-09-23T08:00:00Z', enrollment_expires_at: null, checked_at: '2026-09-23T08:00:00Z', ...overrides } }
export function auditEntry(i=0): AuditEntry { return { ts: '2026-09-23T08:00:00Z', actor: 'admin', target: `web-${i}`, eventid: 'console.node.token.issued', db_client: '192.0.2.11', detail: `by=admin node=web-${i} enrollment=${i}` } }
