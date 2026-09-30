import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { ApiError } from './errors'
import type { ActorBlock } from './incidents'
import { monitoringKeys } from './monitoring-keys'

export interface PendingIncident {
  incident_key: string
  rule_id: string
  rule_name: string
  severity: string
  actor_ip: string | null
  target: string | null
  first_ts: string
  pending_seconds: number
  target_seconds: number
  overdue: boolean
}

export interface Summary {
  as_of: string
  pending: { total: number; overdue: number; warning: number; oldest_seconds: number; age_distribution: number[] }
  oldest_pending: PendingIncident[]
  rule_quality: Array<{ rule_id: string; rule_version: string; incidents: number; judged_effective: number; non_action: number; non_action_rate: number | null }>
  /** 살아 있는(만료 · 해제 전) 차단 요청 수. 실제로 막은 수가 아니다 */
  blocked_ips: number
  /**
   * 살아 있는 차단 요청의 집행 상태(이슈 #47, 화면 blockState 와 같은 순서). 관문이 실제로 반영한 것은 enforced 뿐이다.
   * 이전 서버는 생략한다
   */
  blocks?: BlockCounts
  /**
   * 집행 지점별 적용 결과(#72, 관문 · 내부 방화벽 순). 카드 대응(response_block)과 같은 정의라 집행기 확인이 멈추면(stalled)
   * 적용 · 실패를 미확인에 합친다. 지점별 합은 blocked_ips − blocks.excluded 다. 이전 서버는 생략한다
   */
  blocks_by_point?: PointCounts[]
  /**
   * 첫 사건을 위협으로 판정한 뒤에 같은 페이로드로 흡수됐는데 차단이 없는 출발지(규칙 v3). 흡수는 알림이 없어
   * 여기서만 드러난다. 흡수 기록 표가 없는 서버는 생략한다. first_key 는 그런 첫 사건 하나(바로 가기)
   */
  absorbed_unblocked?: { sources: number; incidents: number; first_key: string | null }
  latest_event: string | null
}

export interface BlockCounts {
  enforced: number
  pending: number
  excluded: number
  mismatch: number
}

/**
 * 한 집행 지점의 살아 있는 차단(만료 없음 · 집행 제외 뺌). stalled 는 집행기 확인이 멈춘 까닭 글, 정상이면 null.
 * unreadable 이면 멈춤이 아니라 생존 신호 표를 읽을 수 없어 합친 것이다(확인 불가, #82). 이전 서버에는 없다
 */
export interface PointCounts {
  point: 'gateway' | 'fw'
  label: string
  applied: number
  failed: number
  unverified: number
  stalled: string | null
  unreadable?: boolean
}

export interface BlockEntry extends ActorBlock {
  actor_ip: string
  incident_key: string | null
  requested_by: string | null
  enforce_note: string | null
  released_by: string | null
  checked_at: string
}

export async function fetchSummary(signal?: AbortSignal): Promise<Summary> {
  const data = await api.get<Summary>('/api/stats/summary', { signal })
  // 옛 서버의 응답을 0건으로 꾸미지 않는다. API를 함께 배포해야 한다.
  if (!data.pending || !Array.isArray(data.oldest_pending) || !Array.isArray(data.rule_quality)) {
    throw new ApiError({ status: 0, kind: 'parse', detail: '서버의 대시보드 응답이 이전 버전입니다. 콘솔 API 배포를 확인해 주세요.' })
  }
  return data
}

export function fetchBlocklist(signal?: AbortSignal): Promise<BlockEntry[]> {
  return api.get<BlockEntry[]>('/api/blocklist', { signal, query: { active_only: false } })
}

/** 시간 목표·차단 만료와 누락된 통보도 따라잡는다. 숨겨진 탭에서는 주기 조회를 멈춘다. */
const REFRESH = { staleTime: 10_000, refetchInterval: 30_000 } as const
export function useSummary() {
  return useQuery({ queryKey: monitoringKeys.summary, queryFn: ({ signal }) => fetchSummary(signal), ...REFRESH })
}
export function useBlocklist() {
  return useQuery({ queryKey: monitoringKeys.blocklist, queryFn: ({ signal }) => fetchBlocklist(signal), ...REFRESH })
}
