import type { ControlHealth, MonitorItem } from '@/api/health'
import type { BlockEntry, PointCounts, Summary } from '@/api/monitoring'

export const AS_OF = '2026-09-23T08:00:00Z'
/** 요약. 기본값에는 지점별 차단(blocks_by_point)이 없다(이전 서버). 지점별은 BLOCKS_BY_POINT 를 넣는다 */
export const MONITORING_SUMMARY: Summary = {
  as_of: AS_OF,
  pending: { total: 12, overdue: 3, warning: 2, oldest_seconds: 22_320, age_distribution: [4, 5, 3, 0, 0], undetermined: 0 },
  oldest_pending: [{ incident_key: 'R003|v2|192.0.2.8', rule_id: 'R003', rule_name: '악성코드 투하', severity: 'critical', actor_ip: '192.0.2.8', target: null, first_ts: '2026-09-23T01:48:00Z', pending_seconds: 22_320, target_seconds: 3600, overdue: true }],
  rule_quality: [
    { rule_id: 'R001', rule_version: 'v2', incidents: 20, judged_effective: 10, non_action: 3, non_action_rate: 30 },
    { rule_id: 'R201', rule_version: 'v2', incidents: 2, judged_effective: 0, non_action: 0, non_action_rate: null },
  ],
  blocked_ips: 2, blocks: { enforced: 1, pending: 1, excluded: 0, mismatch: 0 }, latest_event: AS_OF,
}

/** 지점별 차단(#72). 요청 16건 · 집행 제외 13건이면 지점마다 합이 3 이다. 내부 방화벽은 집행기 확인이 멈춰 적용 · 실패를 미확인에 합쳤다 */
export const BLOCKS_BY_POINT: PointCounts[] = [
  { point: 'gateway', label: 'AWS 관문', applied: 2, failed: 0, unverified: 1, stalled: null },
  { point: 'fw', label: '내부 방화벽', applied: 0, failed: 0, unverified: 3, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' },
]

export function blockEntry(extra: Partial<BlockEntry> = {}): BlockEntry {
  return { actor_ip: '192.0.2.8', reason: '반복 인증 시도', incident_key: 'R001|v2|192.0.2.8', created_at: AS_OF, expires_at: '2026-09-24T08:00:00Z', released_at: null, method: null, requested_by: 'operator', enforced_at: null, enforce_note: null, released_by: null, checked_at: AS_OF, ...extra }
}

/** 관제 이상 항목 하나(#72). 모든 칸이 있고 해당 없는 칸은 null 이다(서버 monitor_items) */
export function monitorItem(extra: Partial<MonitorItem> & Pick<MonitorItem, 'key' | 'label'>): MonitorItem {
  return { level: 'alert', reason: null, at: null, count: null, ...extra }
}

/**
 * 관제 이상 항목(#72 · #82): 멈춤 · 센서 · 관문 기록 수신 · 탐지 경로 · 적용 실패 · 지점 불일치 · 관문 불일치 · 지점 보고 · 노드 수신(전부 · 일부) ·
 * 웹 로그 적재 · 자원 지표와 모름
 */
export const MONITOR = {
  loader: monitorItem({ key: 'loader', label: '적재기', reason: '적재기 확인 중단 · 마지막 45분 전', at: '2026-09-23T07:15:00Z' }),
  enforcerFw: monitorItem({ key: 'enforcer:fw', label: '내부 방화벽 집행기', reason: '집행기 확인 중단 · 마지막 확인 12분 전' }),
  /** 까닭은 카드 까닭 그대로다(관문 업로더가 있으면 끝에 관문 기록 신호 시각) */
  sensor: monitorItem({ key: 'sensor', label: 'AWS 센서 수신', reason: '업로더 생존 신호 40분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음 · 관문 기록 신호 40분 전', at: '2026-09-23T07:20:00Z' }),
  gatewayUploader: monitorItem({ key: 'gateway_uploader', label: 'AWS 관문 기록 수신', reason: '관문 기록 신호 40분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음', at: '2026-09-23T07:20:00Z' }),
  detectBridge: monitorItem({ key: 'detect:bridge', label: '노드 · 관제 탐지(1분)', reason: 'w2 마지막 실행 16분 전', at: '2026-09-23T07:44:00Z' }),
  /** 기대 버전(수집 설정)에 기록이 없다. 마지막 실행 시각이 없다 */
  detectBridgeMissing: monitorItem({ key: 'detect:bridge', label: '노드 · 관제 탐지(1분)', reason: 'c1 · sg1 24시간 넘게 실행 없음' }),
  failedGateway: monitorItem({ key: 'block_failed:gateway', label: 'AWS 관문 적용 실패', count: 2 }),
  pointStaleFw: monitorItem({ key: 'point_stale:fw', label: '내부 방화벽 불일치', count: 2 }),
  mismatch: monitorItem({ key: 'gateway_mismatch', label: '관문 불일치', count: 1 }),
  reportFw: monitorItem({ key: 'report:fw', label: '내부 방화벽 보고', reason: '마지막 보고 20분 전' }),
  nodesSilent: monitorItem({ key: 'nodes_silent', label: '노드 수신', reason: '노드 2대 수신 끊김', count: 2 }),
  nodesSilentSome: monitorItem({ key: 'nodes_silent', label: '노드 수신', reason: 'node-b 수신 끊김 · 마지막 수신 12분 전', count: 1 }),
  parse: monitorItem({ key: 'parse:web-01', label: 'web-01 웹 로그 적재', reason: '로그는 도착하는데 적재되지 않음 · 마지막 도착 3분 전' }),
  /** 카드 시스템 구역에는 까닭 글이 없어 서버가 마지막 지표 시각으로 적는다 */
  metrics: monitorItem({ key: 'metrics:node-e', label: 'node-e 자원 지표', reason: '마지막 지표 25분 전', at: '2026-09-23T07:35:00Z' }),
  heartbeats: monitorItem({ key: 'heartbeats', level: 'unknown', label: '생존 신호', reason: '생존 신호 표를 읽을 수 없음' }),
  nodes: monitorItem({ key: 'nodes', level: 'unknown', label: '노드 수신', reason: '노드 표를 읽을 수 없음' }),
} as const

/** 관제 상태 응답. 기본값은 이상 없음(items 빈 목록 · 두 탐지 경로 정상) */
export function controlHealth(extra: Partial<ControlHealth> = {}): ControlHealth {
  return {
    as_of: AS_OF,
    items: [],
    detect_paths: [
      { key: 'honeypot', label: '허니팟 탐지(5분)', last_at: '2026-09-23T07:57:00Z', stale: false, reason: null, versions: [{ rule_version: 'v3', last_at: '2026-09-23T07:57:00Z', stale: false }] },
      { key: 'bridge', label: '노드 · 관제 탐지(1분)', last_at: '2026-09-23T07:59:00Z', stale: false, reason: null, versions: [{ rule_version: 'w2', last_at: '2026-09-23T07:59:00Z', stale: false }] },
    ],
    ...extra,
  }
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
