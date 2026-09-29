import type { Target, TargetsResult } from '@/api/targets'

/**
 * 관제 대상 상태판(#52) 픽스처. 기준 시각은 TARGETS_AS_OF(2026-09-28 19:00 KST).
 * 기본값은 대상 네 곳이 모두 정상이고, 차단 · 취약점 수치가 0 이 아닌 경우와 0 인 경우가 섞여 있다
 */

export const TARGETS_AS_OF = '2026-09-28T10:00:00Z'
export const LATEST_KEY = 'R105|c1|203.0.113.7|2026-09-28T09:40:00+00:00'

/** 기준 시각에서 분 단위로 앞선 ISO 시각 */
export function minutesAgo(minutes: number): string {
  return new Date(Date.parse(TARGETS_AS_OF) - minutes * 60_000).toISOString()
}

export function awsSensor(extra: Partial<Target> = {}): Target {
  return {
    id: 'aws-sensor',
    label: 'AWS 센서',
    role: 'Cowrie 허니팟 · 웹 디코이 · AWS 관문 (DMZ)',
    collection: {
      state: 'ok',
      reason: '업로더 생존 신호 3분 전 · 최근 1시간 로그 있음',
      signal: { label: '업로더 생존 신호', seen_at: minutesAgo(3), checked_at: minutesAgo(1), stale_after_seconds: 900, problem: null },
      logs: [
        { key: 'cowrie', label: 'Cowrie', last_at: minutesAgo(2) },
        { key: 'decoy', label: '웹 디코이', last_at: minutesAgo(90) },
        { key: 'gateway', label: 'AWS 관문 기록', last_at: null },
      ],
      extra: [],
    },
    security: {
      incidents_1h: 4,
      high_1h: 1,
      pending: 12,
      parts: [
        { key: 'cowrie', label: 'Cowrie', incidents_1h: 3, pending: 10 },
        { key: 'decoy', label: '웹 디코이', incidents_1h: 1, pending: 2 },
        { key: 'gateway', label: 'AWS 관문', incidents_1h: 0, pending: 0 },
      ],
      latest: { incident_key: LATEST_KEY, rule_id: 'R105', rule_name: '제품 식별 탐색', severity: 'high', actor_ip: '203.0.113.7', target: null, last_ts: minutesAgo(20), judged: false },
    },
    system: { state: 'not_collected', metrics: null },
    response: { point: 'gateway', point_label: 'AWS 관문', applied: 2, unverified: 1, exempt: 3, report: { seen_at: minutesAgo(2), checked_at: minutesAgo(1), problem: null } },
    vulns: {
      available: true,
      assets: [
        { asset_id: 'honeypot-dmz', vuln_total: 12, vuln_kev: 1, collected_at: minutesAgo(180), checked_at: minutesAgo(170), stale: false, missing: false },
        { asset_id: 'gateway', vuln_total: 0, vuln_kev: 0, collected_at: null, checked_at: null, stale: true, missing: true },
      ],
    },
    ...extra,
  }
}

export function web01(extra: Partial<Target> = {}): Target {
  return {
    id: 'web-01',
    label: 'web-01',
    role: '실서비스 웹 서버 (온프레미스)',
    collection: {
      state: 'quiet',
      reason: '노드 수신 1분 전 · 최근 1시간 로그 없음(요청 없음)',
      signal: { label: '노드 수신', seen_at: minutesAgo(1), checked_at: null, stale_after_seconds: 600, problem: null },
      logs: [{ key: 'web-01', label: 'web-01 로그', last_at: minutesAgo(200) }],
      extra: [{ label: '마지막 적재', at: minutesAgo(1), note: null }],
    },
    security: { incidents_1h: 0, high_1h: 0, pending: 0, parts: [], latest: null },
    system: { state: 'ok', metrics: { ts: minutesAgo(1), cpu_pct: 12.4, mem_used_pct: 41.6, disk_root_pct: 63, load1: 0.42 } },
    response: { point: 'fw', point_label: '내부 방화벽', applied: 0, unverified: 0, exempt: 0, report: { seen_at: null, checked_at: minutesAgo(1), problem: '보고 파일 없음' } },
    vulns: { available: true, assets: [{ asset_id: 'web-01', vuln_total: 30, vuln_kev: 0, collected_at: minutesAgo(60 * 50), checked_at: minutesAgo(60 * 50), stale: true, missing: false }] },
    ...extra,
  }
}

export function consoleTarget(extra: Partial<Target> = {}): Target {
  return {
    id: 'console',
    label: '관제 콘솔',
    role: '콘솔 A · B (HAProxy 뒤)',
    collection: {
      state: 'unknown',
      reason: '생존 신호 없음 · 현재 콘솔은 실시간 연결로 표시',
      signal: null,
      logs: [{ key: 'console', label: '마지막 로그인 기록', last_at: minutesAgo(12) }],
      extra: [],
    },
    security: { incidents_1h: 1, high_1h: 0, pending: 1, parts: [], latest: { incident_key: 'R201|v2|user:root|x', rule_id: 'R201', rule_name: '콘솔 로그인 실패', severity: 'low', actor_ip: null, target: 'user:root', last_ts: minutesAgo(12), judged: true } },
    system: { state: 'not_collected', metrics: null },
    response: { point: null, point_label: null, applied: null, unverified: null, exempt: 0, report: null },
    vulns: {
      available: true,
      assets: [
        { asset_id: 'console-a', vuln_total: 5, vuln_kev: 0, collected_at: minutesAgo(120), checked_at: minutesAgo(110), stale: false, missing: false },
        { asset_id: 'console-b', vuln_total: 0, vuln_kev: 0, collected_at: minutesAgo(120), checked_at: null, stale: false, missing: false },
      ],
    },
    ...extra,
  }
}

export function dataNode(extra: Partial<Target> = {}): Target {
  return {
    id: 'data-node',
    label: '데이터 노드',
    role: 'DB · 적재 · 탐지 · 집행 (온프레미스)',
    collection: {
      state: 'no_signal',
      reason: '마지막 탐지 실행 20분 전 · 15분 넘게 실행 없음',
      signal: { label: '마지막 탐지 실행', seen_at: minutesAgo(20), checked_at: null, stale_after_seconds: 900, problem: null },
      logs: [],
      extra: [
        { label: '적재기 확인', at: minutesAgo(1), note: null },
        { label: '집행기 확인', at: null, note: null },
      ],
    },
    security: { incidents_1h: 0, high_1h: 0, pending: 0, parts: [], latest: null },
    system: { state: 'not_collected', metrics: null },
    response: { point: null, point_label: null, applied: null, unverified: null, exempt: 0, report: null },
    vulns: { available: true, assets: [{ asset_id: 'data-01', vuln_total: 8, vuln_kev: 2, collected_at: minutesAgo(30), checked_at: minutesAgo(25), stale: false, missing: false }] },
    ...extra,
  }
}

/**
 * 등록 노드 카드(#64). web-01 카드와 같은 틀이다: 노드 수신 판정 · 집행 지점 없음(미확인) · 지표 미수집 ·
 * 같은 이름의 자산 없음(서버 vulns_block 은 빈 목록을 준다).
 * 이름은 hostname(opsloop-<id>), 역할은 '등록 노드', 로그 이름은 '<이름> 로그'(targets.py 와 같다)
 */
export function nodeTarget(id = 'web-02', extra: Partial<Target> = {}): Target {
  return {
    id,
    kind: 'node',
    label: `opsloop-${id}`,
    role: '등록 노드',
    collection: {
      state: 'ok',
      reason: '노드 수신 2분 전 · 최근 1시간 로그 있음',
      signal: { label: '노드 수신', seen_at: minutesAgo(2), checked_at: null, stale_after_seconds: 600, problem: null },
      logs: [{ key: id, label: `opsloop-${id} 로그`, last_at: minutesAgo(3) }],
      extra: [{ label: '마지막 적재', at: minutesAgo(2), note: null }],
    },
    security: {
      incidents_1h: 2,
      high_1h: 1,
      pending: 3,
      parts: [],
      latest: { incident_key: `R101|v3|198.51.100.9|${id}`, rule_id: 'R101', rule_name: 'SSH 무차별 대입', severity: 'high', actor_ip: '198.51.100.9', target: null, last_ts: minutesAgo(5), judged: false },
    },
    system: { state: 'not_collected', metrics: null },
    response: { point: null, point_label: null, applied: null, failed: null, unverified: null, exempt: 0, report: null, stalled: null },
    vulns: { available: true, assets: [] },
    ...extra,
  }
}

export function targetsResult(extra: Partial<TargetsResult> = {}): TargetsResult {
  return {
    as_of: TARGETS_AS_OF,
    window_seconds: 3600,
    heartbeats_available: true,
    metrics_available: true,
    targets: [awsSensor(), web01(), consoleTarget(), dataNode()],
    unmapped: { incidents_1h: 0, pending: 0 },
    ...extra,
  }
}
