import { useId } from 'react'
import { Link } from 'react-router'
import type { PendingIncident } from '@/api/monitoring'
import type { QueueItem, TargetsQueue } from '@/api/targets'
import { cn } from '@/lib/cn'
import { sensorOf } from '@/lib/domain'
import { formatDuration } from '@/lib/time'
import { revealHidden } from '@/lib/untrusted'
import { Card } from '../../atoms/Card'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { UntrustedText } from '../../atoms/UntrustedText'
import { DeviceBadges } from '../../molecules/DeviceBadges'
import { InfoTip } from '../../molecules/InfoTip'
import { incidentHref } from '../incidents/model'

export interface PendingQueueProps {
  /** 상태판의 먼저 처리할 사건(#72). 있으면 이것을 그린다(요약 조회와 관계없이) */
  queue?: TargetsQueue
  /** 이전 서버 · 상태판 조회 실패일 때 요약의 오래된 미판정. 발생원은 규칙 번호 분류(sensorOf)로 적는다 */
  oldest?: readonly PendingIncident[]
  className?: string
}

const QUEUE_NOTE = '보호 대상 · 관제 시스템 · 장비 미확인 사건을 먼저, 허니팟 · 디코이 사건을 뒤에 두고 각각 오래된 순입니다. 최대 8건 · 전체 규칙 버전.'
const OLDEST_NOTE = '오래된 순입니다. 최대 8건 · 전체 규칙 버전.'
const BACK_TITLE = '허니팟 · 디코이'

type Row = PendingIncident & Partial<Pick<QueueItem, 'devices' | 'device_state' | 'device_fallback' | 'lane'>>

/**
 * 먼저 처리할 사건(#72). 앞 묶음(보호 대상 · 관제 시스템 · 장비 미확인) 뒤에 '허니팟 · 디코이' 묶음을 둔다. 순서는 서버가 준 대로다.
 * 한 줄 = 경과 · 목표 | 규칙 번호 + 이름 / 출발지 또는 대상 · 관련 장비 | 심각도. 줄 전체가 상세 링크라 안에 단추를 두지 않는다(#41).
 * 제목 옆 수는 미판정 전체의 묶음별 수다(목록은 최대 8건이라 뒤 묶음이 목록에 없을 수 있다).
 * queue 가 없으면(이전 서버 · 상태판 실패) 요약의 오래된 미판정을 지금 모양(발생원)으로 그린다.
 */
export function PendingQueue({ queue, oldest, className }: PendingQueueProps) {
  const backId = useId()
  const items: Row[] = queue ? queue.items : [...(oldest ?? [])]
  const front = queue ? items.filter((item) => item.lane !== 'back') : items
  const back = queue ? items.filter((item) => item.lane === 'back') : []
  const count = (n: number) => n.toLocaleString('ko-KR')
  return (
    <Card padding="none" className={cn('min-w-0', className)} data-queue={queue ? 'lanes' : 'oldest'}>
      <InfoTip
        label="먼저 처리할 사건"
        render={({ button, panel }) => (
          <div className="rounded-t-card border-b border-line bg-canvas/60 px-4 py-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-1">
                <h2 className="m-0 text-md font-semibold tracking-heading">먼저 처리할 사건</h2>
                {button}
                {queue && (
                  <span className="text-xs tabular-nums text-ink-muted" data-queue-counts="">
                    앞 {count(queue.front)} · {BACK_TITLE} {count(queue.back)}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs text-ink-muted">
                <Link to="/incidents?judged=false">미판정 전체 보기 →</Link>
              </div>
            </div>
            {panel}
          </div>
        )}
      >
        {queue ? QUEUE_NOTE : OLDEST_NOTE}
      </InfoTip>
      {items.length ? (
        <>
          {front.length > 0 && (
            <ol className="m-0 list-none divide-y divide-line p-0" data-lane="front">
              {front.map((item) => (
                <QueueRow key={item.incident_key} item={item} />
              ))}
            </ol>
          )}
          {back.length > 0 && (
            <>
              <h3 id={backId} className={cn('m-0 bg-canvas/60 px-4 py-1.5 text-xs font-medium text-ink-muted', front.length > 0 && 'border-t border-line')}>
                {BACK_TITLE}
              </h3>
              <ol aria-labelledby={backId} className="m-0 list-none divide-y divide-line border-t border-line p-0" data-lane="back">
                {back.map((item) => (
                  <QueueRow key={item.incident_key} item={item} />
                ))}
              </ol>
            </>
          )}
          {queue && back.length === 0 && queue.back > 0 && (
            <p className="m-0 border-t border-line px-4 py-2 text-xs tabular-nums text-ink-muted" data-queue-back="">
              {BACK_TITLE} {count(queue.back)}건
            </p>
          )}
        </>
      ) : (
        <p className="m-0 px-4 py-8 text-ink-muted">미판정 사건이 없습니다. 최근 수집 시각도 함께 확인해 주세요.</p>
      )}
    </Card>
  )
}

/** 한 줄. 출발지 · 대상 · 규칙 이름은 비신뢰라 한 줄로 자르고 전체는 말풍선으로 본다 */
function QueueRow({ item }: { item: Row }) {
  const source = item.actor_ip ?? item.target
  return (
    <li>
      <Link
        to={incidentHref(item.incident_key)}
        className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-3 hover:bg-canvas sm:grid-cols-[110px_minmax(0,1fr)_auto]"
      >
        <div className={cn('text-sm font-semibold tabular-nums', item.overdue ? 'text-warning' : 'text-ink')}>
          {formatDuration(item.pending_seconds * 1000, 'compact')}
          <div className="text-xs font-normal">{item.overdue ? '목표 초과' : `목표 ${formatDuration(item.target_seconds * 1000)}`}</div>
        </div>
        <div className="col-span-2 row-start-2 min-w-0 sm:col-span-1 sm:row-auto">
          <div className="break-words text-sm text-ink" title={revealHidden(item.rule_name)}>
            <span className="mr-2 font-mono text-primary">{item.rule_id}</span>
            <UntrustedText value={item.rule_name} clip />
          </div>
          <div className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-1 gap-y-0.5 text-xs text-ink-muted">
            <span className="max-w-full truncate font-mono" title={revealHidden(source ?? '') || undefined}>
              <UntrustedText value={source} fallback="대상 없음" clip />
            </span>
            {item.devices ? (
              <>
                <span className="shrink-0">·</span>
                <DeviceBadges source={item} mode="compact" className="flex-wrap" />
              </>
            ) : (
              <span className="shrink-0">· {sensorOf(item.rule_id)}</span>
            )}
          </div>
        </div>
        <SeverityBadge severity={item.severity} className="col-start-2 row-start-1 justify-self-end sm:col-start-3" />
      </Link>
    </li>
  )
}
