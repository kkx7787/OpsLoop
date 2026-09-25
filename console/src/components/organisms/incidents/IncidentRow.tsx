import type { ComponentProps, MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import type { Incident } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { sensorOf } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { ElapsedTime } from './ElapsedTime'
import { IncidentStatusLabel } from './IncidentStatusLabel'
import { incidentHref, isPending, ROW_GRID, sourceOf } from './model'

export interface IncidentRowProps extends Omit<ComponentProps<'div'>, 'children'> {
  incident: Incident
  /** 발생부터 지난 초. 서버가 준 pending_seconds 에 목록을 받은 뒤 흐른 시간을 더한 값 */
  elapsedSeconds: number
  /** aria-rowindex. 머리 행이 1 이므로 본문은 2 부터 */
  rowIndex?: number
}

/**
 * 목록 한 행(데스크톱). 행 어디를 눌러도 상세로 간다.
 * 키보드 초점은 규칙 링크에 있다. 링크를 눌렀을 때는 링크가 이미 이동했으므로(defaultPrevented) 두 번 가지 않고,
 * 보조키(새 탭)와 글자 드래그는 누름으로 보지 않는다.
 */
export function IncidentRow({ incident, elapsedSeconds, rowIndex, className, onClick, ...rest }: IncidentRowProps) {
  const navigate = useNavigate()
  const href = incidentHref(incident.incident_key)
  const pending = isPending(incident)

  function handleClick(event: MouseEvent<HTMLDivElement>) {
    onClick?.(event)
    if (event.defaultPrevented) return
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    if (window.getSelection()?.toString()) return
    void navigate(href)
  }

  return (
    // 키보드 · 낭독기의 진입점은 안쪽 규칙 링크다(행마다 초점 하나). 행의 onClick 은 마우스 편의라 키 처리기를 두지 않는다
    // oxlint-disable-next-line jsx-a11y/click-events-have-key-events
    <div
      role="row"
      aria-rowindex={rowIndex}
      data-incident-key={incident.incident_key}
      onClick={handleClick}
      className={cn(ROW_GRID, 'min-h-[52px] cursor-pointer border-l-2 border-transparent px-3 py-1.5 text-sm shadow-hairline hover:bg-primary-soft/60', pending && 'border-l-primary/25', className)}
      {...rest}
    >
      <div role="cell">
        <ElapsedTime
          seconds={elapsedSeconds}
          severity={incident.severity}
          ruleId={incident.rule_id}
          since={incident.first_ts}
          pending={pending}
        />
      </div>
      <div role="cell">
        <SeverityBadge severity={incident.severity} />
      </div>
      <div role="cell" className="flex min-w-0 flex-col gap-0.5">
        <div className="flex min-w-0 items-baseline gap-2">
          <Link to={href} className="shrink-0 font-mono text-xs font-medium text-primary">
            {incident.rule_id}
          </Link>
          <span className="truncate font-medium text-ink" title={revealHidden(incident.rule_name)}>
            <UntrustedText value={incident.rule_name} clip />
          </span>
        </div>
        <span className="text-xs text-ink-muted tabular-nums">{incident.signal_count} 신호 · {incident.session_count} 세션</span>
      </div>
      <div role="cell" className="flex min-w-0 flex-col gap-0.5">
        <span className="truncate font-mono" title={revealHidden(sourceOf(incident))}>
          <UntrustedText value={sourceOf(incident)} clip />
        </span>
        {incident.actor_ip && incident.target && (
          <span className="truncate text-xs text-ink-muted" title={revealHidden(incident.target)}>
            대상 <UntrustedText value={incident.target} clip />
          </span>
        )}
        <span className="text-xs text-ink-muted">{sensorOf(incident.rule_id)}</span>
      </div>
      <div role="cell">
        <IncidentStatusLabel status={incident.status} />
      </div>
      <div role="cell">
        {incident.verdict ? <VerdictBadge verdict={incident.verdict} /> : <span className="text-xs font-medium text-primary">미판정</span>}
      </div>
    </div>
  )
}
