/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useId } from 'react'
import { DELIVERY_EVENT_LABEL, DELIVERY_STATUSES, DELIVERY_STATUS_LABEL, type DeliveriesResult, type DeliveryFilters, type DeliveryStatus, type NotifyChannel } from '@/api/notify'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Select } from '@/components/atoms/Select'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { revealHidden } from '@/lib/untrusted'
import { DeliveryStatusBadge } from './ChannelTable'
import { deliveryProblem } from './problem'

const HEAD = ['만든 시각 (KST)', '채널', '종류', '대상', '상태', '시도', '응답 · 원인', '보낸 시각 · 다음 시도 (KST)']
const cell = 'px-4 py-3 align-top'

interface Props {
  channels: NotifyChannel[]
  filters: DeliveryFilters
  onFilters: (filters: DeliveryFilters) => void
  /** 조회 결과. 없으면 첫 조회 중이거나 실패다 */
  data: DeliveriesResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  onRetry: () => void
}

/** 발송 이력 표(표시만). 조회 · 조건 상태는 페이지가 갖는다. 채널 · 상태 조건을 바꾸면 1쪽부터 다시 본다. */
export function DeliveryTable({ channels, filters, onFilters, data, pending, fetching, error, onRetry }: Props) {
  const id = useId()
  const set = (next: Partial<DeliveryFilters>) => onFilters({ ...filters, ...next, offset: 0 })
  return (
    <Card padding="none" className="min-w-0">
      <CardHeader title="발송 이력" aside={<>
        <label htmlFor={`${id}-channel`}>채널</label>
        <Select id={`${id}-channel`} fieldSize="sm" className="h-7 w-auto" value={filters.channel_id ?? ''} onChange={(e) => set({ channel_id: e.target.value ? Number(e.target.value) : undefined })}>
          <option value="">전체</option>{channels.map((c) => <option key={c.id} value={c.id}>{revealHidden(c.name)}</option>)}
        </Select>
        <label htmlFor={`${id}-status`}>상태</label>
        <Select id={`${id}-status`} fieldSize="sm" className="h-7 w-auto" value={filters.status ?? ''} onChange={(e) => set({ status: (e.target.value || undefined) as DeliveryStatus | undefined })}>
          <option value="">전체</option>{DELIVERY_STATUSES.map((s) => <option key={s} value={s}>{DELIVERY_STATUS_LABEL[s]}</option>)}
        </Select>
        {data && <span>{data.total.toLocaleString()}건</span>}
      </>} />
      {pending ? <LoadingState className="m-4" /> : !data ? <ApiErrorState error={error} onRetry={onRetry} className="m-4" /> : <>
        <div className="overflow-x-auto" role="region" aria-label="발송 이력 표" tabIndex={0}>
          <table className="w-full min-w-[880px] text-left text-sm">
            <thead className="border-b border-line text-xs text-ink-muted"><tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{data.rows.map((r) => {
              const problem = deliveryProblem(r.error, r.response_code)
              return <tr key={r.id}>
                <td className={`${cell} whitespace-nowrap`}><Time value={r.created_at} format="short" /></td>
                <td className={cell}><UntrustedText value={r.channel_name} max={120} /></td>
                <td className={`${cell} whitespace-nowrap`}>{DELIVERY_EVENT_LABEL[r.event] ?? r.event}</td>
                <td className={`${cell} max-w-xs break-all font-mono text-xs`}><UntrustedText value={r.subject_key} /></td>
                <td className={cell}><DeliveryStatusBadge status={r.status} /></td>
                <td className={`${cell} tabular-nums`}>{r.attempts}</td>
                <td className={`${cell} max-w-64 text-xs`}>{problem ? <span className="break-keep text-danger"><UntrustedText value={problem} /></span> : r.response_code ?? '—'}</td>
                <td className={`${cell} text-xs whitespace-nowrap`}>{r.status === 'sent' ? <Time value={r.sent_at} format="short" /> : r.status === 'queued' ? <>다음 <Time value={r.next_attempt_at} format="short" /></> : '—'}</td>
              </tr>
            })}</tbody>
          </table>
        </div>
        {!data.rows.length && <p className="p-4 text-sm text-ink-muted">조건에 맞는 발송 이력이 없습니다.</p>}
        <IncidentPagination label="발송 이력 페이지" page={Math.floor(filters.offset / filters.limit) + 1} pageSize={filters.limit} total={data.total} busy={fetching} onPage={(page) => onFilters({ ...filters, offset: (page - 1) * filters.limit })} onPageSize={(limit) => onFilters({ ...filters, limit, offset: 0 })} />
        <p className="m-0 border-t border-line px-4 py-3 text-xs text-ink-muted">실패하면 1 · 5 · 15분 뒤 다시 보내고 3회를 넘기면 실패로 남습니다. 채널을 중지하면 대기 중인 알림은 보내지 않음으로 닫힙니다. 이력에는 메시지 요약만 있고 채널 주소 · 응답 본문은 기록하지 않습니다.</p>
      </>}
    </Card>
  )
}
