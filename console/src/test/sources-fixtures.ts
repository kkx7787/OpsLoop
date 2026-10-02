import type { Fingerprint, FingerprintsResult, SourceDetail, SourceSummary, SourcesResult } from '@/api/sources'
import { COWRIE } from './targets-fixtures'

/** 출발지 분석(S-09) 표본. 서버 계약은 app/sources.py */
export const SOURCES_AS_OF = '2026-09-29T03:00:00Z'
export const HASSH = 'b5752e36ba6c5979a575e43178908adf'

export function sourceSummary(extra: Partial<SourceSummary> = {}): SourceSummary {
  return {
    ip: '198.51.100.23',
    incidents: 4,
    unjudged: 1,
    severity: 'critical',
    rules: ['R001', 'R003'],
    targets: ['aws-sensor'],
    first_ts: '2026-09-27T01:00:00Z',
    last_ts: '2026-09-29T02:40:00Z',
    // 마지막 사건 뒤에도 이벤트가 이어졌다(차단 뒤에도 두드린 경우)
    last_seen: '2026-09-29T02:55:00Z',
    verdicts: { threat: 2, non_actionable: 1, false_positive: 0, benign_positive: 0, undetermined: 0 },
    test_source: false,
    exempt: false,
    block: null,
    ...extra,
  }
}

export function sourcesResult(items: SourceSummary[], extra: Partial<SourcesResult> = {}): SourcesResult {
  return { as_of: SOURCES_AS_OF, total: items.length, limit: 25, offset: 0, checkers: { gateway_stale: false, fw_stale: false }, items, ...extra }
}

/** 살아 있는 두 지점 차단(관문 적용 확인 · 내부 방화벽 대기). 요청한 지점이 모두 확인이 아니라 종합 상태는 집행 대기다(#77) */
export const LIVE_BLOCK: NonNullable<SourceSummary['block']> = {
  reason: '위협 판정 차단',
  method: 'nft',
  created_at: '2026-09-29T02:00:00Z',
  expires_at: '2026-09-30T02:00:00Z',
  released_at: null,
  enforced_at: '2026-09-29T02:01:00Z',
  enforce_note: '관문 반영 · 2026-09-29T02:01:00Z',
  requested_by: 'han',
  enforcement: {
    gateway: { state: 'confirmed', since: '2026-09-29T02:01:00Z', mode: 'nft', note: null },
    fw: { state: 'pending', since: '2026-09-29T02:00:30Z', mode: null, note: null },
  },
  points: ['gateway', 'fw'],
}

export function sourceDetail(extra: Partial<SourceDetail> = {}): SourceDetail {
  const summary = sourceSummary({ block: LIVE_BLOCK })
  return {
    as_of: SOURCES_AS_OF,
    ip: summary.ip,
    summary,
    last_seen: summary.last_seen,
    checkers: { gateway_stale: false, fw_stale: false },
    // 장비는 사건 목록과 같은 계산이다. R001 은 규칙 범위(Cowrie), R003 은 근거 발생원으로 확인한 Cowrie
    incidents: [
      { incident_key: 'R001|v3|198.51.100.23|2026-09-27T01:00:00+00:00', rule_id: 'R001', rule_version: 'v3', rule_name: 'SSH 무차별 대입', severity: 'medium', status: 'resolved', first_ts: '2026-09-27T01:00:00Z', last_ts: '2026-09-27T01:20:00Z', target: null, verdict: 'threat', devices: [COWRIE], device_state: 'rule_scope', device_fallback: [] },
      { incident_key: 'R003|v3|198.51.100.23|2026-09-29T02:30:00+00:00', rule_id: 'R003', rule_version: 'v3', rule_name: '악성코드 투하', severity: 'critical', status: 'open', first_ts: '2026-09-29T02:30:00Z', last_ts: '2026-09-29T02:40:00Z', target: null, verdict: null, devices: [{ ...COWRIE, basis: 'confirmed' }], device_state: 'confirmed', device_fallback: [] },
    ],
    incidents_total: 2,
    event_kinds: [
      { sensor: 'cowrie', eventid: 'cowrie.login.failed', count: 120, first_ts: '2026-09-27T01:00:00Z', last_ts: '2026-09-29T02:55:00Z' },
      { sensor: 'decoy', eventid: 'decoy.http.request', count: 8, first_ts: '2026-09-28T04:00:00Z', last_ts: '2026-09-28T04:05:00Z' },
    ],
    fingerprints: {
      hassh: [{ value: HASSH, count: 42 }],
      ssh_version: [{ value: 'SSH-2.0-Go', count: 42 }],
      user_agent: [],
    },
    actions: [
      { incident_key: 'R003|v3|198.51.100.23|2026-09-29T02:30:00+00:00', action: 'block_ip', operator: 'han', note: '위협 판정 차단', created_at: '2026-09-29T02:00:00Z' },
    ],
    block: LIVE_BLOCK,
    exempt: null,
    exempt_flag: summary.exempt,
    absorbed: 3,
    ...extra,
  }
}

export function fingerprint(extra: Partial<Fingerprint> = {}): Fingerprint {
  return { value: HASSH, sources: 12, connections: 340, incident_sources: 9, first_ts: '2026-09-20T00:00:00Z', last_ts: '2026-09-29T02:35:00Z', ...extra }
}

export function fingerprintsResult(items: Fingerprint[], extra: Partial<FingerprintsResult> = {}): FingerprintsResult {
  return { as_of: SOURCES_AS_OF, kind: 'hassh', total: items.length, limit: 25, offset: 0, items, ...extra }
}
