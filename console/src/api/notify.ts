import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import type { Severity } from '@/lib/domain'

/**
 * 알림 채널 · 발송 이력(S-12). 서버 계약은 app/notify.py.
 * 채널 주소(웹훅 URL)는 비밀값이다. 서버는 호스트와 끝 4자만 돌려주고, 화면은 원문을 Query 캐시에 두지 않는다
 * (만들기 · 바꾸기는 훅이 아니라 함수로 호출하고 응답에도 원문이 없다).
 */

export const NOTIFY_KINDS = ['teams', 'webhook'] as const
export type NotifyKind = (typeof NOTIFY_KINDS)[number]
export const KIND_LABEL: Record<NotifyKind, string> = { teams: 'Teams', webhook: '웹훅' }

export const NOTIFY_GRADES = ['immediate', 'daily'] as const
export type NotifyGrade = (typeof NOTIFY_GRADES)[number]
export const GRADE_LABEL: Record<NotifyGrade, string> = { immediate: '즉시', daily: '일일 요약' }

export const NOTIFY_EVENTS = ['incident.created', 'pending.overdue', 'node.silent'] as const
export type NotifyEvent = (typeof NOTIFY_EVENTS)[number]
/** 서버 notifier.EVENT_LABELS 와 같은 말이다. 메시지의 {event_label} 에 그대로 들어가므로 화면과 어긋나지 않게 한다 */
export const EVENT_LABEL: Record<NotifyEvent, string> = {
  'incident.created': '새 인시던트',
  'pending.overdue': '판정 지연',
  'node.silent': '노드 수신 끊김',
}

/** 이력에는 채널 사건 종류 외에 일일 요약 · 시험 발송이 더 있다 */
export const DELIVERY_EVENT_LABEL: Record<string, string> = { ...EVENT_LABEL, 'daily.summary': '일일 요약', test: '시험 발송' }

export const DELIVERY_STATUSES = ['queued', 'sending', 'sent', 'failed'] as const
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number]
export const DELIVERY_STATUS_LABEL: Record<DeliveryStatus, string> = { queued: '대기', sending: '보내는 중', sent: '성공', failed: '실패' }

/** 서버 기본 틀과 같다(infra/schema.sql notify_channels). '기본값으로' 단추가 되돌리는 값 */
export const DEFAULT_TEMPLATE_HEADER = '[OpsLoop] {event_label} {count}건'
export const DEFAULT_TEMPLATE_ITEM = '{rule_id} {rule_name} · {severity} · {who} · {elapsed}'
export const TEMPLATE_MAX = 300
export const BATCH_MAX = 86_400

export interface LastDelivery {
  status: DeliveryStatus
  sent_at: string | null
  response_code: number | null
  /** 실패 원인(예외 이름 · 'HTTP 404' 등). 주소 · 응답 본문은 없다 */
  error: string | null
  /** 보낸 시각, 없으면 집은 시각 · 만든 시각. 실패 · 대기도 언제였는지 보인다 */
  at: string | null
}

export interface NotifyChannel {
  id: number
  name: string
  kind: NotifyKind
  grade: NotifyGrade
  events: NotifyEvent[]
  min_severity: Severity
  batch_seconds: number
  template_header: string
  template_item: string
  enabled: boolean
  /** 주소 끝 4자 · 호스트. 원문은 오지 않는다 */
  url_tail: string
  url_host: string
  created_at: string
  updated_at: string
  updated_by: string | null
  last_delivery: LastDelivery | null
}

/** 만들기 · 바꾸기 본문. 바꿀 때 url 을 빼면(또는 빈 문자열이면) 서버가 기존 주소를 유지한다 */
export interface ChannelInput {
  name: string
  kind: NotifyKind
  url?: string
  grade: NotifyGrade
  events: NotifyEvent[]
  min_severity: Severity
  batch_seconds: number
  template_header: string
  template_item: string
  enabled: boolean
}

export interface TestResult {
  status: DeliveryStatus
  response_code: number | null
  error: string | null
}

export interface Delivery {
  id: number
  channel_id: number
  channel_name: string
  event: string
  subject_key: string
  status: DeliveryStatus
  attempts: number
  response_code: number | null
  error: string | null
  created_at: string
  sent_at: string | null
  next_attempt_at: string | null
}

export interface DeliveryFilters {
  channel_id?: number
  status?: DeliveryStatus
  limit: number
  offset: number
}

export interface DeliveriesResult {
  rows: Delivery[]
  total: number
  limit: number
  offset: number
}

export const notifyKeys = {
  all: ['notify'] as const,
  channels: () => [...notifyKeys.all, 'channels'] as const,
  deliveries: (filters: DeliveryFilters) => [...notifyKeys.all, 'deliveries', filters] as const,
}

const REFRESH = { staleTime: 10_000, refetchInterval: 30_000 } as const

/** 채널 목록. admin 이 아니면 부르지 않는다(서버도 403). */
export function useChannels(enabled = true) {
  return useQuery({
    queryKey: notifyKeys.channels(),
    queryFn: ({ signal }) => api.get<NotifyChannel[]>('/api/notify/channels', { signal }),
    enabled,
    ...REFRESH,
  })
}

/** 발송 이력. 비어 있는 조건은 쿼리 문자열에 넣지 않는다(client.buildUrl 이 undefined 를 뺀다). 조건 · 쪽을 바꾸는 동안 이전 결과를 유지한다. */
export function useDeliveries(filters: DeliveryFilters, enabled = true) {
  return useQuery({
    queryKey: notifyKeys.deliveries(filters),
    placeholderData: keepPreviousData,
    queryFn: ({ signal }) =>
      api.get<DeliveriesResult>('/api/notify/deliveries', {
        signal,
        query: { channel_id: filters.channel_id, status: filters.status, limit: filters.limit, offset: filters.offset },
      }),
    enabled,
    ...REFRESH,
  })
}

/** 주소가 본문에 들어가므로 Mutation 캐시를 거치지 않는다. 응답에는 주소 원문이 없다. */
export function createChannel(input: ChannelInput) {
  return api.post<NotifyChannel>('/api/notify/channels', input)
}

export function updateChannel(id: number, input: ChannelInput) {
  return api.put<NotifyChannel>(`/api/notify/channels/${id}`, input)
}

/** 동기 시험 발송(서버 시간 초과 10초). 이력에 event='test' 로 남는다. */
export function testChannel(id: number) {
  return api.post<TestResult>(`/api/notify/channels/${id}/test`, undefined, { timeoutMs: 20_000 })
}
