/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { DELIVERY_STATUS_LABEL, EVENT_LABEL, GRADE_LABEL, KIND_LABEL, type DeliveryStatus, type NotifyChannel } from '@/api/notify'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { SeverityBadge } from '@/components/atoms/SeverityBadge'
import { Switch } from '@/components/atoms/Switch'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import type { Tone } from '@/components/atoms/tones'
import { InfoTip } from '@/components/molecules/InfoTip'
import { formatDuration } from '@/lib/time'
import { revealHidden } from '@/lib/untrusted'
import { deliveryProblemParts } from './problem'

const STATUS_TONE: Record<DeliveryStatus, Tone> = { queued: 'neutral', sending: 'info', sent: 'success', failed: 'danger' }
export function DeliveryStatusBadge({ status }: { status: DeliveryStatus }) {
  return <Badge tone={STATUS_TONE[status] ?? 'neutral'}>{DELIVERY_STATUS_LABEL[status] ?? status}</Badge>
}

const HEAD = ['채널', '통보 정책', '사용', '마지막 발송', '동작']
const cell = 'px-4 py-3 align-top'

interface Props {
  channels: NotifyChannel[]
  /** 지금 처리 중인 채널(토글 · 시험 발송). 하나라도 있으면 모든 행의 토글 · 시험 발송을 막는다 */
  busyId: number | null
  onEdit: (channel: NotifyChannel) => void
  onToggle: (channel: NotifyChannel) => void
  onTest: (channel: NotifyChannel) => void
}

/**
 * 채널 표. 주소는 호스트와 끝 4자만 보인다(원문은 서버가 주지 않는다). 일일 요약은 사건 종류 · 심각도로 거르지 않는다.
 * 통보 정책 기준은 카드 머리 ⓘ 에 둔다(좁은 화면은 표 머리를 숨겨 열 머리 ⓘ 가 보이지 않는다). 마지막 발송 실패는 원인만 칸에, 조치는 ⓘ 로 접는다.
 */
export function ChannelTable({ channels, busyId, onEdit, onToggle, onTest }: Props) {
  const anyBusy = busyId !== null
  return (
    <Card padding="none" className="min-w-0">
      <InfoTip label="통보 정책" panelClassName="mx-4 my-2" render={({ button, panel }) => <>
        <CardHeader title="알림 채널" aside={<>{`${channels.length}개`}{button}</>} />
        {panel}
      </>}>즉시 등급은 같은 종류의 첫 사건부터 묶음 시간 동안 모아 한 메시지로 보내고, 일일 요약은 매일 09:00 KST 에 미판정 현황을 보냅니다.</InfoTip>
      <div className="overflow-x-auto" role="region" aria-label="알림 채널 표" tabIndex={0}>
        <table className="responsive-table w-full table-fixed text-left text-sm">
          <colgroup><col className="w-[25%]" /><col className="w-[23%]" /><col className="w-[12%]" /><col className="w-[23%]" /><col className="w-[17%]" /></colgroup>
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{channels.map((c) => {
            const busy = busyId === c.id
            const daily = c.grade === 'daily'
            const last = c.last_delivery
            const problem = last && last.status !== 'sent' ? deliveryProblemParts(last.error, last.response_code) : null
            return <tr key={c.id} data-channel-id={c.id} className={c.enabled ? undefined : 'text-ink-muted'}>
              <th scope="row" className={`${cell} font-normal`}>
                <div className="font-semibold break-words"><UntrustedText value={c.name} max={120} /></div>
                <div className="mt-1 text-xs text-ink-muted">{KIND_LABEL[c.kind] ?? c.kind}</div>
                <details className="mt-2 text-xs text-ink-muted"><summary className="cursor-pointer">연결 정보</summary>
                  <div className="mt-2 break-all font-mono"><UntrustedText value={c.url_host} fallback="—" /><div>…{c.url_tail}</div></div>
                  <div className="mt-1"><UntrustedText value={c.updated_by} max={64} fallback="미기록" /> · <Time value={c.updated_at} format="short" /></div>
                </details>
              </th>
              <td data-label="통보 정책" className={cell}>
                <div className="font-medium">{GRADE_LABEL[c.grade] ?? c.grade}</div>
                <div className="mt-1 text-xs text-ink-muted">{daily ? '09:00 KST' : c.batch_seconds > 0 ? `${formatDuration(c.batch_seconds * 1000)} 묶음` : '바로'}</div>
                {!daily && <div className="mt-2 text-xs"><SeverityBadge severity={c.min_severity} /> 이상<div className="mt-1 text-ink-muted">{c.events.map((e) => EVENT_LABEL[e] ?? e).join(' · ') || '—'}</div></div>}
              </td>
              <td data-label="사용" className={cell}><Switch aria-label={`${revealHidden(c.name)} 사용`} label={c.enabled ? '사용' : '중지'} checked={c.enabled} disabled={anyBusy} onChange={() => onToggle(c)} /></td>
              <td data-label="마지막 발송" className={`${cell} text-xs`}>{last ? <>
                <div className="flex flex-wrap items-center gap-1.5"><DeliveryStatusBadge status={last.status} /> <Time value={last.at ?? last.sent_at} format="short" />{last.status === 'sent' && last.response_code !== null && <span className="text-ink-muted"> · {last.response_code}</span>}</div>
                {problem?.cause && <div className="mt-1 max-w-56 break-keep text-danger"><UntrustedText value={problem.cause} />{problem.action && <> <InfoTip label="실패 조치">{problem.action}</InfoTip></>}</div>}
              </> : '없음'}</td>
              <td data-label="동작" className={cell}><div className="flex flex-wrap gap-1.5">
                <Button size="sm" data-edit-channel aria-label={`${revealHidden(c.name)} 수정`} disabled={busy} onClick={() => onEdit(c)}>수정</Button>
                <Button size="sm" aria-label={`${revealHidden(c.name)} 시험 발송`} loading={busy} disabled={anyBusy && !busy} onClick={() => onTest(c)}>시험 발송</Button>
              </div></td>
            </tr>
          })}</tbody>
        </table>
      </div>
      {!channels.length && <p className="p-4 text-sm text-ink-muted">등록된 채널이 없습니다. '채널 추가'로 만들어 주세요.</p>}
    </Card>
  )
}
