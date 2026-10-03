import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { deviceLogsHref, STATUS_PATH, statusHref } from '@/components/molecules/device-format'
import { api } from './client'
import { ApiError } from './errors'
import { monitoringKeys } from './monitoring-keys'
import { FRESHNESS_TICK_MS, STALE_MS } from '@/lib/freshness'
import { useNow } from '@/lib/useNow'

/**
 * 관제 이상(#72 · #82). 서버 계약은 app/targets.py monitor_view.
 *  GET /api/dashboard/monitor → ControlHealth (적재기 · 집행기 확인, 센서 · 관문 기록 수신, 탐지 경로, 지점별 적용 실패 · 불일치 · 보고 · 확인 지연,
 *  노드 수신 · 노드별 웹 로그 적재 · 자원 지표)
 * items 는 이상(alert)과 모름(unknown)만 싣는다. 비면 이상이 없다는 뜻이다.
 * 대시보드 띠와 사이드바 요약이 같은 조회 · 같은 판정(controlHealthView)을 쓴다. 조회가 실패하면 이전 항목을 보이지 않는다(Q14).
 */

export type MonitorLevel = 'alert' | 'unknown'

/**
 * 관제 이상 한 항목. key 는 heartbeats · loader · enforcer:<지점> · sensor · gateway_uploader · detect:<경로> · block_failed:<지점> ·
 * point_stale:<지점> · gateway_mismatch · report:<지점> · point_delayed:<지점>(#84, 5분 넘은 확인 전) · nodes_silent · nodes ·
 * parse:<node_id> · metrics:<node_id>.
 * 해당 없는 칸은 null 이다(at 은 멈춘 확인 · 신호 · 탐지의 마지막 시각, count 는 적용 실패 · 불일치 · 확인 지연 · 끊긴 노드 수)
 */
export interface MonitorItem {
  key: string
  level: MonitorLevel
  label: string
  reason: string | null
  at: string | null
  count: number | null
}

export interface DetectPathVersion {
  rule_version: string | null
  last_at: string | null
  stale: boolean
}

/**
 * 탐지 경로. honeypot(5분 풀러, 경로 최댓값으로 가른다) · bridge(1분 다리, 돌아야 할 버전(수집 설정 RULESETS)마다 가른다).
 * 기록이 없는 기대 버전은 last_at 이 null 인 멈춤이고, 기대 밖 옛 버전 기록은 보지 않는다(#82)
 */
export interface DetectPath {
  key: 'honeypot' | 'bridge'
  label: string
  last_at: string | null
  stale: boolean
  /** 멈췄을 때의 글(관제 이상 항목과 같다). 멈춤이 아니면 null */
  reason?: string | null
  versions: DetectPathVersion[]
}

export interface ControlHealth {
  /** DB now() */
  as_of: string
  items: MonitorItem[]
  detect_paths: DetectPath[]
}

export const HEALTH_PATH = '/api/dashboard/monitor'

export async function fetchControlHealth(signal?: AbortSignal): Promise<ControlHealth> {
  const data = await api.get<ControlHealth>(HEALTH_PATH, { signal })
  // 모양이 다른 응답을 '이상 없음' 으로 꾸미지 않는다
  if (!data || typeof data !== 'object' || !Array.isArray(data.items)) {
    throw new ApiError({ status: 0, kind: 'parse', detail: '서버의 관제 상태 응답을 해석할 수 없습니다. 콘솔 API 배포를 확인해 주세요.' })
  }
  return { ...data, detect_paths: Array.isArray(data.detect_paths) ? data.detect_paths : [] }
}

/** 요약 · 상태판과 같이 10초 동안은 다시 묻지 않고 30초마다 재조회한다. enabled 는 로그인을 확인한 뒤에만 켜려고 둔다 */
export function useControlHealth(enabled = true) {
  return useQuery({ queryKey: monitoringKeys.health, queryFn: ({ signal }) => fetchControlHealth(signal), staleTime: 10_000, refetchInterval: 30_000, enabled })
}

/** 이상(alert)과 모름(unknown). 모르는 level 은 모름으로 두고(숨기지 않는다), 항목이 아닌 값은 뺀다. 각각 서버 순서다 */
export function opsAnomalies(health: Pick<ControlHealth, 'items'> | undefined): { alerts: MonitorItem[]; unknowns: MonitorItem[] } {
  const alerts: MonitorItem[] = []
  const unknowns: MonitorItem[] = []
  for (const item of Array.isArray(health?.items) ? health.items : []) {
    if (typeof item !== 'object' || item === null || typeof item.key !== 'string') continue
    if (item.level === 'alert') alerts.push(item)
    else unknowns.push(item)
  }
  return { alerts, unknowns }
}

/** 띠 · 사이드바가 그릴 상태: 받는 중 · 확인 불가 · 받음(이상 · 모름) */
export type ControlHealthView = { state: 'pending' } | { state: 'error' } | { state: 'stale' } | { state: 'ok'; alerts: MonitorItem[]; unknowns: MonitorItem[] }

/** controlHealthView 가 보는 조회 결과 칸(useControlHealth 결과를 그대로 넘긴다). 시각 두 칸은 없으면 0 으로 본다 */
export type ControlHealthQuery = Pick<UseQueryResult<ControlHealth>, 'data' | 'isError'> &
  Partial<Pick<UseQueryResult<ControlHealth>, 'errorUpdatedAt' | 'dataUpdatedAt'>>

/**
 * 조회 결과를 상태로 바꾼다. 실패(isError)를 받은 값(data)보다 먼저 본다: 갱신이 실패하면 react-query 는 이전 data 를 남긴 채
 * isError 를 켜는데, 이때 이전 항목 대신 '관제 상태 확인 불가' 만 보인다(Q14). 5xx 는 재시도가 끝난 뒤에 실패가 된다.
 * 한 번도 받지 못한 채 다시 조회하는 동안은 react-query 가 pending 으로 되돌리고 error 를 비우므로, 마지막으로 끝난 조회가
 * 실패였는지(errorUpdatedAt > dataUpdatedAt)도 본다. 재조회마다 '조회 전' 으로 깜빡이지 않는다
 */
export function controlHealthView(query: ControlHealthQuery, now = Date.now()): ControlHealthView {
  if (query.isError || (query.errorUpdatedAt ?? 0) > (query.dataUpdatedAt ?? 0)) return { state: 'error' }
  if (!query.data) return { state: 'pending' }
  if (query.dataUpdatedAt && now - query.dataUpdatedAt > STALE_MS) return { state: 'stale' }
  return { state: 'ok', ...opsAnomalies(query.data) }
}

/** 요청이 멈추거나 탭에서 돌아와도 오래된 정상 결과를 계속 초록으로 보이지 않는다. */
export function useControlHealthView(query: ControlHealthQuery): ControlHealthView {
  return controlHealthView(query, useNow(FRESHNESS_TICK_MS))
}

/** 항목 이름 뒤에 붙일 글: 까닭이 있으면 까닭, 없으면 건수 */
export function monitorItemText(item: Pick<MonitorItem, 'reason' | 'count'>): string | null {
  if (item.reason) return item.reason
  if (typeof item.count === 'number' && Number.isFinite(item.count)) return `${item.count.toLocaleString('ko-KR')}건`
  return null
}

/**
 * 항목을 누르면 갈 곳(#84). 차단 집행 쪽(집행기 · 적용 실패 · 불일치 · 지점 보고 · 확인 지연)은 차단 목록, 노드 수신 · 자원 지표는 수집 · 관제 상태의
 * 등록 노드 표, 센서 · 관문 기록 수신은 그 화면의 허니팟 센서 줄(펼침), 탐지 경로 · 적재기 · 생존 신호는 데이터 노드 줄(펼침),
 * 웹 로그 적재는 그 장비의 최근 로그. 모르는 키는 링크가 없다
 */
export function monitorItemHref(key: string): string | null {
  if (['enforcer:', 'block_failed:', 'point_stale:', 'report:', 'point_delayed:'].some((p) => key.startsWith(p)) || key === 'gateway_mismatch') return '/blocklist'
  if (key === 'nodes_silent' || key === 'nodes' || key.startsWith('metrics:')) return STATUS_PATH
  if (key === 'sensor' || key === 'gateway_uploader') return statusHref('aws-sensor')
  if (key.startsWith('detect:') || key === 'loader' || key === 'heartbeats' || key === 'data_resources' || key.startsWith('data_disk:')) return statusHref('data-node')
  if (key.startsWith('parse:') && key.length > 'parse:'.length) return deviceLogsHref(key.slice('parse:'.length))
  return null
}
