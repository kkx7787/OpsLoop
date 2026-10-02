/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useId } from 'react'
import { DELIVERY_EVENT_LABEL, DELIVERY_STATUSES, DELIVERY_STATUS_LABEL, type DeliveriesResult, type DeliveryFilters, type DeliveryStatus, type NotifyChannel } from '@/api/notify'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Select } from '@/components/atoms/Select'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { InfoTip } from '@/components/molecules/InfoTip'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { revealHidden } from '@/lib/untrusted'
import { DeliveryStatusBadge } from './ChannelTable'
import { deliveryProblemParts } from './problem'
import { DeliverySubject } from './DeliverySubject'

const HEAD = ['만든 시각 (KST)', '채널 · 종류', '대상', '발송 결과', '보낸 시각 · 다음 시도 (KST)']
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

/**
 * 발송 이력 표(표시만). 조회 · 조건 상태는 페이지가 갖는다. 채널 · 상태 조건을 바꾸면 1쪽부터 다시 본다.
 * 재시도 · 기록 범위는 카드 머리 ⓘ 에, 실패 행의 조치는 원인 옆 ⓘ 에 접는다(행마다 긴 조치문이 되풀이되지 않게).
 */
export function DeliveryTable({ channels, filters, onFilters, data, pending, fetching, error, onRetry }: Props) {
  const id = useId()
  const set = (next: Partial<DeliveryFilters>) => onFilters({ ...filters, ...next, offset: 0 })
  return (
    <Card padding="none" className="min-w-0">
      <InfoTip label="발송 이력" render={({ button, panel }) => <>
      <CardHeader title="발송 이력" className="[&>div]:max-w-full" aside={<div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 whitespace-nowrap"><label htmlFor={`${id}-channel`}>채널</label>
        <Select id={`${id}-channel`} fieldSize="sm" className="h-7 w-auto" value={filters.channel_id ?? ''} onChange={(e) => set({ channel_id: e.target.value ? Number(e.target.value) : undefined })}>
          <option value="">전체</option>{channels.map((c) => <option key={c.id} value={c.id}>{revealHidden(c.name)}</option>)}
        </Select>
        </div><div className="flex items-center gap-2 whitespace-nowrap"><label htmlFor={`${id}-status`}>상태</label>
        <Select id={`${id}-status`} fieldSize="sm" className="h-7 w-auto" value={filters.status ?? ''} onChange={(e) => set({ status: (e.target.value || undefined) as DeliveryStatus | undefined })}>
          <option value="">전체</option>{DELIVERY_STATUSES.map((s) => <option key={s} value={s}>{DELIVERY_STATUS_LABEL[s]}</option>)}
        </Select>
        </div>{data && <span className="whitespace-nowrap">{data.total.toLocaleString()}건</span>}{button}
      </div>} />
      {panel}
      </>}>실패하면 1 · 5 · 15분 뒤 다시 보내고 3회를 넘기면 실패로 남습니다. 이력에는 메시지 요약만 있고 채널 주소 · 응답 본문은 기록하지 않습니다.</InfoTip>
      {pending ? <LoadingState className="m-4" /> : !data ? <ApiErrorState error={error} onRetry={onRetry} className="m-4" /> : <>
        <div key={JSON.stringify(filters)} className="overflow-auto md:max-h-[420px]" role="region" aria-label="발송 이력 표" tabIndex={0}>
          <table className="responsive-table w-full table-fixed text-left text-sm">
            <thead className="sticky top-0 bg-surface border-b border-line text-xs text-ink-muted"><tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{data.rows.map((r) => {
              const problem = deliveryProblemParts(r.error, r.response_code)
              return <tr key={r.id}>
                <td className={`${cell} whitespace-nowrap`}><Time value={r.created_at} format="short" /></td>
                <td data-label="채널 · 종류" className={cell}><UntrustedText value={r.channel_name} max={120} /><div className="mt-1 text-xs text-ink-muted">{DELIVERY_EVENT_LABEL[r.event] ?? r.event}</div></td>
                <td data-label="대상" className={`${cell} max-w-xs break-words`}><DeliverySubject delivery={r} /></td>
                <td data-label="발송 결과" className={cell}><DeliveryStatusBadge status={r.status} /><div className="mt-1 text-xs text-ink-muted">시도 {r.attempts}회 · {r.response_code ?? '응답 없음'}</div>{problem.cause && <div className="mt-1 text-xs text-danger"><UntrustedText value={problem.cause} />{problem.action && <> <InfoTip label="실패 조치">{problem.action}</InfoTip></>}</div>}</td>
                <td data-label="보낸 시각 · 다음 시도" className={`${cell} text-xs`}>{r.status === 'sent' ? <Time value={r.sent_at} format="short" /> : r.status === 'queued' ? <>다음 <Time value={r.next_attempt_at} format="short" /></> : '—'}</td>
              </tr>
            })}</tbody>
          </table>
        </div>
        {!data.rows.length && <p className="p-4 text-sm text-ink-muted">조건에 맞는 발송 이력이 없습니다.</p>}
        <IncidentPagination label="발송 이력 페이지" page={Math.floor(filters.offset / filters.limit) + 1} pageSize={filters.limit} total={data.total} busy={fetching} onPage={(page) => onFilters({ ...filters, offset: (page - 1) * filters.limit })} onPageSize={(limit) => onFilters({ ...filters, limit, offset: 0 })} />
      </>}
    </Card>
  )
}
