import type { BlocksSection, CtiSection, OpsSection, OverviewSection, PeriodReport, RulesSection, TargetsSection } from '@/api/reports'

/** 기간 보고서 표본(app/reports.py 응답 모양). 출력 시각 2026-09-29 17:00 KST, 최근 7일 */
export const REPORT_AS_OF = '2026-09-29T08:00:00Z'

export const OVERVIEW_SECTION: OverviewSection = {
  available: true, basis: 'mixed', notes: ['사건 수 · 상위 출발지: 발생 시각이 기간 안인 사건', '잔량 · 목표 초과: 출력 시각 기준. 목표 시간은 발생 시각부터 잰다'],
  incidents: { total: 120, by_severity: { critical: 3, high: 20, medium: 60, low: 37 }, by_origin: { R0xx: 90, R1xx: 25, R2xx: 5, R3xx: 0, other: 0 }, test_source: 4 },
  verdicts: { total: 80, by_verdict: { threat: 10, non_actionable: 50, false_positive: 5, benign_positive: 3, undetermined: 12 }, test_source: 1 },
  backlog: { unjudged: 40, undetermined: 12, overdue: 7, warning: 2, oldest_seconds: 93_600 },
  wait: { incidents: 90, judged: 68, p50_seconds: 5_400, p90_seconds: 86_400 },
  decision: { n: 0, p50_seconds: null, p90_seconds: null },
  daily: [{ date: '2026-09-22', created: 10, judged: 4 }, { date: '2026-09-23', created: 20, judged: 16 }],
  top_sources: { total: 41, items: [{ ip: '198.51.100.7', incidents: 30, severity: 'critical', last_ts: '2026-09-29T07:00:00Z' }, { ip: '198.51.100.9', incidents: 12, severity: 'medium', last_ts: null }] },
}

export const RULES_SECTION: RulesSection = {
  available: true, basis: 'period', notes: ['시험 출발지의 사건 · 흡수는 뺀다'],
  rows: [
    { rule_id: 'R001', rule_version: 'v3', incidents: 40, judged: 30, judged_effective: 28, threats: 2, non_actionable: 20, false_positives: 4, benign_positives: 2, undetermined: 2, non_action_rate: 92.9, false_positive_rate: 14.3 },
    { rule_id: 'R003', rule_version: 'v3', incidents: 5, judged: 5, judged_effective: 5, threats: 5, non_actionable: 0, false_positives: 0, benign_positives: 0, undetermined: 0, non_action_rate: 0, false_positive_rate: 0 },
  ],
  absorbed: { absorbed: 12, suppressed: 3, rules: [{ rule_id: 'R001', rule_version: 'v3', absorbed: 12, suppressed: 3 }] },
  versions: [{ rule_version: 'v3', created_at: '2026-09-24T01:00:00Z', reason: '키 심기를 R006 으로 분리', rules: ['R001', 'R003', 'R006'] }],
}

export const BLOCKS_SECTION: BlocksSection = {
  available: true, basis: 'mixed', notes: ['감사 이벤트: 종류별 수(행위자 · 내용은 싣지 않는다)'],
  actions: { block_ip: 9, unblock_ip: 1 },
  requests: { total: 9, console: 6, triage: 3, system: 0, unknown: 0 },
  audit: [{ eventid: 'console.block.created', count: 8 }, { eventid: 'console.block.extended', count: 1 }],
  enforcement: { created: 9, enforced: 8, p50_seconds: 42, max_seconds: 310 },
  states: { total: 5, enforced: 3, pending: 1, excluded: 1, mismatch: 0 },
}

export const TARGETS_SECTION: TargetsSection = {
  available: true, basis: 'mixed', notes: ['대상별 수집 · 대응: 출력 시각의 상태판 값'],
  targets: [
    { id: 'aws-sensor', label: 'AWS 센서', collection: { state: 'ok', reason: '생존 신호 2분 전' }, response: { point_label: '수집 관문', applied: 3, failed: 0, unverified: 1, exempt: 0, stalled: null } },
    { id: 'console', label: '관제 콘솔', collection: { state: 'unknown', reason: '생존 신호 없음' }, response: { point_label: null, applied: null, failed: null, unverified: null, exempt: 0, stalled: null } },
  ],
  sensors: [{ sensor: 'cowrie', events: 91_000 }, { sensor: 'decoy', events: 1_200 }],
  detector: { runs: 2_016, max_gap_seconds: 900 },
  web: { samples: 10_000, cpu_pct: 88.4, mem_used_pct: 61, disk_root_pct: null, max_gap_seconds: 120 },
}

export const CTI_SECTION: CtiSection = {
  available: true, basis: 'mixed', notes: ['자산별 취약점 · 주목 CVE: 출력 시각의 대조 결과'],
  assets: [{ asset_id: 'web-01', role: 'target', vuln_total: 14, vuln_kev: 1, vuln_fix_available: 6, vuln_reboot_pending: 1, collected_at: '2026-09-29T00:00:00Z', stale: false }],
  watch: { total: 3, affected: 1, unknown: 1, not_affected: 1, affected_cves: ['CVE-2024-6387'] },
  kev_added: { total: 4, ours: [{ cve_id: 'CVE-2026-0001', name: 'OpenSSH 예시 취약점', date_added: '2026-09-25', assets: ['web-01'] }] },
  freshness: {
    kev: { fetched_at: '2026-09-29T00:00:00Z', source_ts: null, stale: false }, epss: { fetched_at: '2026-09-29T00:00:00Z', source_ts: null, stale: false },
    osv: { fetched_at: '2026-09-27T00:00:00Z', source_ts: null, stale: true }, nvd: { fetched_at: null, source_ts: null, stale: false },
    assets: { oldest_collected_at: '2026-09-29T00:00:00Z', stale_assets: [] },
  },
}

export const OPS_SECTION: OpsSection = {
  available: true, basis: 'period', notes: ['알림 발송: 시험 발송은 뺀다'],
  audit: [{ eventid: 'console.notify.channel.changed', count: 2 }],
  login_failed: 9,
  notify: { total: 32, failed: 2, p50_seconds: 3, rows: [{ event: 'incident.created', status: 'sent', count: 30 }, { event: 'pending.overdue', status: 'failed', count: 2 }] },
}

export function periodReport(overrides: Partial<PeriodReport> = {}): PeriodReport {
  return {
    as_of: REPORT_AS_OF, since: '2026-09-22T08:00:00Z', until: REPORT_AS_OF, period: '7d', tz: 'Asia/Seoul', generated_by: 'tester',
    sections: { overview: OVERVIEW_SECTION, rules: RULES_SECTION, blocks: BLOCKS_SECTION, targets: TARGETS_SECTION, cti: CTI_SECTION, ops: OPS_SECTION },
    ...overrides,
  }
}
