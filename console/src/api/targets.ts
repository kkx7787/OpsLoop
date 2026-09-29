import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { ApiError, isApiError } from './errors'
import type { IncidentBase } from './incidents'
import type { PendingIncident } from './monitoring'
import { monitoringKeys } from './monitoring-keys'

/**
 * 관제 대상 상태판(이슈 #52). 서버 계약은 app/targets.py.
 *  GET /api/dashboard/targets → TargetsResult (고정 대상 네 곳 · 등록 노드(#64)의 수집 · 보안 · 시스템 · 대응 · 취약점 요약)
 * 수치는 대상별이다. 한 사건이 여러 대상에 붙을 수 있어 카드 합은 전체 사건 수가 아니다.
 * 생존 신호가 없는 대상은 서버가 '미확인'(unknown)으로 답한다. 화면은 로그 시각만으로 정상 · 장애 색을 입히지 않는다.
 * 화면은 대상을 세 무리로 나눠 그린다(#72): 보호 대상(web-01 · 등록 노드) · 관측 센서(aws-sensor) · 관제 시스템(console · data-node).
 * 먼저 처리할 사건(queue)은 이 경로에만 있다(보고서의 같은 계산에는 없다).
 */

/** 코드에 정한 고정 대상(app/targets.py TARGETS). 카드 순서도 이 순서다 */
export const TARGET_IDS = ['aws-sensor', 'web-01', 'console', 'data-node'] as const
export type FixedTargetId = (typeof TARGET_IDS)[number]
/** 대상 id. 고정 네 값이거나 등록 노드의 node_id(#64, 고정 값과 겹치지 않는다) */
export type TargetId = string

/** fixed 고정 대상 · node 수집 노드 표(nodes)에 등록한 노드(#64). 이전 서버는 싣지 않는다 */
export const TARGET_KINDS = ['fixed', 'node'] as const
export type TargetKind = (typeof TARGET_KINDS)[number]

/** 무리(#72). 보호 대상은 web-01 과 등록 노드(kind node) 전부다. 서버 TARGETS 순서 · TARGET_IDS 는 바꾸지 않는다 */
export const PROTECTED_IDS = ['web-01'] as const
export const PROTECTED_KIND: TargetKind = 'node'
export const SENSOR_IDS = ['aws-sensor'] as const
export const SYSTEM_IDS = ['console', 'data-node'] as const

export function isFixedTargetId(id: string): id is FixedTargetId {
  return (TARGET_IDS as readonly string[]).includes(id)
}

/** 대상 종류. kind 가 없거나 모르는 값이면 id 로 가른다(고정 네 값이 아니면 등록 노드) */
export function targetKind(target: Pick<Target, 'id' | 'kind'>): TargetKind {
  if (target.kind === 'fixed' || target.kind === 'node') return target.kind
  return isFixedTargetId(target.id) ? 'fixed' : 'node'
}

/** 수집 상태. ok 정상 · quiet 요청 없음(신호는 있고 로그만 없다) · no_signal 수신 없음 · unknown 생존 상태 미확인 */
export const COLLECTION_STATES = ['ok', 'quiet', 'no_signal', 'unknown'] as const
export type CollectionState = (typeof COLLECTION_STATES)[number]

/** 자원 지표 상태. 지표를 보내는 노드(web-01 · 등록 노드 가운데 node_metrics 에 있는 것)만 수집한다 */
export const SYSTEM_STATES = ['ok', 'stale', 'not_collected', 'no_privilege', 'no_data'] as const
export type SystemState = (typeof SYSTEM_STATES)[number]

export type EnforcePoint = 'gateway' | 'fw'

/** 생존 신호 하나(업로더 · 노드 수신 · 탐지 실행). seen_at 은 신호 자체의 시각, checked_at 은 기록한 쪽이 마지막으로 본 시각 */
export interface TargetSignal {
  label: string
  seen_at: string | null
  checked_at: string | null
  stale_after_seconds: number
  /** 읽기 문제(없음 · 형식이 틀림 · 일시 오류 …). 정상이면 null */
  problem: string | null
}

export interface TargetLog {
  key: string
  label: string
  last_at: string | null
}

export interface TargetExtra {
  label: string
  at: string | null
  note: string | null
}

export interface TargetCollection {
  state: CollectionState
  /** 상태를 정한 까닭 한 문장 */
  reason: string
  /** 생존 신호. 없는 대상(콘솔)은 null */
  signal: TargetSignal | null
  logs: TargetLog[]
  extra: TargetExtra[]
  /** 데이터 노드만: 멈춘 확인(적재기 · 집행기 지점 하나라도). state 는 그대로라 화면이 '주의' 로 보인다. 이전 서버에는 없다 */
  stopped?: Array<'loader' | 'enforcer'>
}

/** 발생원(Cowrie · 웹 디코이 · AWS 관문) 하나의 수치. AWS 센서만 있다 */
export interface TargetPart {
  key: string
  label: string
  incidents_1h: number
  pending: number
}

/** 최근 중요 탐지 한 줄: 24시간 안 critical · high 중 최신, 없으면 24시간 안 아무 사건 최신 */
export interface TargetLatest {
  incident_key: string
  rule_id: string
  rule_name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  actor_ip: string | null
  target: string | null
  last_ts: string
  judged: boolean
}

export interface TargetSecurity {
  /** 최근 1시간(window_seconds) 안에 시작한 이 대상 사건 */
  incidents_1h: number
  /** 그중 critical · high */
  high_1h: number
  /** 판정 기록 없는 이 대상 사건 전체(기간 무관) */
  pending: number
  parts: TargetPart[]
  latest: TargetLatest | null
}

export interface TargetMetrics {
  ts: string
  cpu_pct: number | null
  mem_used_pct: number | null
  disk_root_pct: number | null
  load1: number | null
}

export interface TargetSystem {
  state: SystemState
  metrics: TargetMetrics | null
}

/** 그 지점의 차단 보고 신호(block:<point>) */
export interface TargetReport {
  seen_at: string | null
  checked_at: string | null
  problem: string | null
}

export interface TargetResponse {
  /** 이 대상 앞의 집행 지점. 콘솔 · 데이터 노드 · 등록 노드는 null(적용 결과를 수집하지 않는다) */
  point: EnforcePoint | null
  point_label: string | null
  /** 그 지점이 적용을 확인한 살아 있는 차단 수 */
  applied: number | null
  /** 그 지점이 거부했다고 보고한 살아 있는 차단 수(알려진 미적용). 이전 서버에는 없다 */
  failed?: number | null
  /** 그 지점에서 적용을 확인하지 못한 살아 있는 차단 수(대기 · 확인 지연 · 기록 없음) */
  unverified: number | null
  /** 이 대상 사건의 출발지 중 차단 금지 대역(정책상 차단 제외) 주소 수 */
  exempt: number
  report: TargetReport | null
  /** 집행기 확인이 멈췄거나 기록이 없어 적용 확인을 믿지 않을 때의 까닭. 그때 서버는 적용 · 실패를 미확인에 합친다. 이전 서버에는 없다 */
  stalled?: string | null
}

export interface TargetAssetVulns {
  asset_id: string
  vuln_total: number
  vuln_kev: number
  /** 수정 상태별 수(#72). missing 이면 0. 이전 서버에는 없다 */
  vuln_fix_available?: number
  vuln_reboot_pending?: number
  vuln_fix_unknown?: number
  collected_at: string | null
  checked_at: string | null
  stale: boolean
  /** 자산 표에 없다. 수는 0 이지만 '없음'으로 읽지 않는다 */
  missing: boolean
}

export interface TargetVulns {
  /** CTI 표가 없으면 false, assets 는 빈 목록 */
  available: boolean
  assets: TargetAssetVulns[]
}

export interface Target {
  id: TargetId
  /** 고정 대상 · 등록 노드. 이전 서버에는 없다(targetKind 로 읽는다) */
  kind?: TargetKind
  /** 등록 노드는 hostname(없으면 node_id)이라 비신뢰 문자열로 그린다 */
  label: string
  role: string
  collection: TargetCollection
  security: TargetSecurity
  system: TargetSystem
  response: TargetResponse
  vulns: TargetVulns
}

export interface TargetsResult {
  /** DB now() */
  as_of: string
  /** '최근 1시간' 창(초) */
  window_seconds: number
  /** sensor_heartbeats 표가 있고 읽을 수 있다 */
  heartbeats_available: boolean
  /** node_metrics 를 읽을 수 있다 */
  metrics_available: boolean
  /** 순서 고정: aws-sensor, web-01, console, data-node, 그 뒤 등록 노드(node_id 순) */
  targets: Target[]
  /** 장비를 확인하지 못한 사건(화면 글자는 '장비 미확인'). 숨기지 않는다 */
  unmapped: { incidents_1h: number; pending: number }
  /** 먼저 처리할 사건(#72). 이전 서버에는 없다(화면은 요약의 oldest_pending 으로 대신한다) */
  queue?: TargetsQueue
}

/**
 * 먼저 처리할 사건 한 줄. 요약 oldest_pending 과 같은 칸에 묶음 · 관련 장비를 더했다(rule_version 은 없다).
 * lane front: 보호 대상 · 관제 시스템 · 장비 미확인, back: AWS 센서(허니팟 · 디코이)뿐
 */
export type QueueItem = PendingIncident & Pick<IncidentBase, 'devices' | 'device_state' | 'device_fallback'> & { lane: 'front' | 'back' }

/** 미판정 전체의 수와 앞 묶음부터 채운 최대 8건. 순서는 서버가 정한다(묶음 → 첫 시각 → 키) */
export interface TargetsQueue {
  total: number
  front: number
  back: number
  /** 그중 장비 미확인 */
  unconfirmed: number
  overdue: number
  items: QueueItem[]
}

export const TARGETS_PATH = '/api/dashboard/targets'

/** 상태판 API 가 없는 서버(404)의 안내. 화면은 이 글로 '배포 전'을 알린다 */
export const TARGETS_NOT_DEPLOYED = '관제 대상 상태판 API 가 없습니다. 콘솔 API 배포 전일 수 있습니다.'

export function isTargetsNotDeployed(error: unknown): boolean {
  return isApiError(error) && error.status === 404
}

export async function fetchTargets(signal?: AbortSignal): Promise<TargetsResult> {
  let data: TargetsResult
  try {
    data = await api.get<TargetsResult>(TARGETS_PATH, { signal })
  } catch (error) {
    // 이 경로를 모르는 이전 서버다. '찾을 수 없음' 대신 배포 전으로 읽히게 한다
    if (isApiError(error) && error.status === 404) throw new ApiError({ status: 404, detail: TARGETS_NOT_DEPLOYED, body: error.body, cause: error })
    throw error
  }
  // 모양이 다른 응답을 빈 카드로 꾸미지 않는다
  if (!data || typeof data !== 'object' || !Array.isArray(data.targets) || !data.unmapped || typeof data.as_of !== 'string') {
    throw new ApiError({ status: 0, kind: 'parse', detail: '서버의 관제 대상 응답을 해석할 수 없습니다. 콘솔 API 배포를 확인해 주세요.' })
  }
  return data
}

/** 요약(useSummary)과 같이 10초 동안은 다시 묻지 않고 30초마다 재조회한다. 사건 · 판정 · 조치 통보도 무효화한다(live.ts) */
export function useTargets() {
  return useQuery({ queryKey: monitoringKeys.targets, queryFn: ({ signal }) => fetchTargets(signal), staleTime: 10_000, refetchInterval: 30_000 })
}
