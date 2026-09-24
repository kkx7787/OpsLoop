/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { DELIVERY_STATUS_LABEL, EVENT_LABEL, GRADE_LABEL, KIND_LABEL, type DeliveryStatus, type NotifyChannel } from '@/api/notify'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { SeverityBadge } from '@/components/atoms/SeverityBadge'
import { Switch } from '@/components/atoms/Switch'
import { Time } from '@/components/atoms/Time'
import type { Tone } from '@/components/atoms/tones'
import { formatDuration } from '@/lib/time'
import { deliveryProblem } from './problem'

const STATUS_TONE: Record<DeliveryStatus, Tone> = { queued: 'neutral', sending: 'info', sent: 'success', failed: 'danger' }
export function DeliveryStatusBadge({ status }: { status: DeliveryStatus }) {
  return <Badge tone={STATUS_TONE[status] ?? 'neutral'}>{DELIVERY_STATUS_LABEL[status] ?? status}</Badge>
}

const HEAD = ['이름', '종류', '등급', '사건 종류', '최소 심각도', '묶음', '사용', '주소', '마지막 발송', '동작']
const cell = 'px-4 py-3 align-top'

interface Props {
  channels: NotifyChannel[]
  /** 지금 처리 중인 채널(토글 · 시험 발송). 하나라도 있으면 모든 행의 토글 · 시험 발송을 막는다 */
  busyId: number | null
  onEdit: (channel: NotifyChannel) => void
  onToggle: (channel: NotifyChannel) => void
  onTest: (channel: NotifyChannel) => void
}

/** 채널 표. 주소는 호스트와 끝 4자만 보인다(원문은 서버가 주지 않는다). 일일 요약은 사건 종류 · 심각도로 거르지 않는다. */
export function ChannelTable({ channels, busyId, onEdit, onToggle, onTest }: Props) {
  const anyBusy = busyId !== null
  return (
    <Card padding="none" className="min-w-0">
      <CardHeader title="알림 채널" aside={`${channels.length}개`} />
      <div className="overflow-x-auto" role="region" aria-label="알림 채널 표" tabIndex={0}>
        <table className="w-full min-w-[960px] text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{channels.map((c) => {
            const busy = busyId === c.id
            const daily = c.grade === 'daily'
            const last = c.last_delivery
            const problem = last && last.status !== 'sent' ? deliveryProblem(last.error, last.response_code) : ''
            return <tr key={c.id} className={c.enabled ? undefined : 'text-ink-muted'}>
              <th scope="row" className={`${cell} font-normal`}><div className="font-semibold">{c.name}</div><div className="text-xs text-ink-muted">{c.updated_by || '미기록'} · <Time value={c.updated_at} format="short" /></div></th>
              <td className={cell}><Badge tone={c.kind === 'teams' ? 'violet' : 'neutral'}>{KIND_LABEL[c.kind] ?? c.kind}</Badge></td>
              <td className={`${cell} whitespace-nowrap`}>{GRADE_LABEL[c.grade] ?? c.grade}</td>
              <td className={`${cell} text-xs`}>{daily ? '—' : c.events.map((e) => EVENT_LABEL[e] ?? e).join(' · ') || '—'}</td>
              <td className={cell}>{daily ? '—' : <SeverityBadge severity={c.min_severity} />}</td>
              <td className={`${cell} whitespace-nowrap tabular-nums`}>{daily ? '09:00 KST' : c.batch_seconds > 0 ? formatDuration(c.batch_seconds * 1000) : '바로'}</td>
              <td className={cell}><Switch aria-label={`${c.name} 사용`} label={c.enabled ? '사용' : '중지'} checked={c.enabled} disabled={anyBusy} onChange={() => onToggle(c)} /></td>
              <td className={`${cell} font-mono text-xs`}><div>{c.url_host || '—'}</div><div className="text-ink-muted">…{c.url_tail}</div></td>
              <td className={`${cell} text-xs`}>{last ? <>
                <div className="whitespace-nowrap"><DeliveryStatusBadge status={last.status} /> <Time value={last.at ?? last.sent_at} format="short" />{last.status === 'sent' && last.response_code !== null && <span className="text-ink-muted"> · {last.response_code}</span>}</div>
                {problem && <div className="mt-1 max-w-56 break-keep text-danger">{problem}</div>}
              </> : '없음'}</td>
              <td className={`${cell} whitespace-nowrap`}>
                <Button size="sm" className="mr-1.5" aria-label={`${c.name} 수정`} disabled={busy} onClick={() => onEdit(c)}>수정</Button>
                <Button size="sm" aria-label={`${c.name} 시험 발송`} loading={busy} disabled={anyBusy && !busy} onClick={() => onTest(c)}>시험 발송</Button>
              </td>
            </tr>
          })}</tbody>
        </table>
      </div>
      {!channels.length && <p className="p-4 text-sm text-ink-muted">등록된 채널이 없습니다. '채널 추가'로 Teams 또는 웹훅 채널을 만들어 주세요.</p>}
    </Card>
  )
}
