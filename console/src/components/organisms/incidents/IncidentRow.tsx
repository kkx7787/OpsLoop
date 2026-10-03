import type { ComponentProps, MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import type { CtiBadge as CtiBadgeValue } from '@/api/cti'
import type { Incident } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { useReturnTo } from '@/lib/returnTo'
import { sensorOf } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { CtiBadge } from '../../molecules/CtiBadge'
import { DeviceBadges } from '../../molecules/DeviceBadges'
import { ElapsedTime } from './ElapsedTime'
import { IncidentStatusLabel } from './IncidentStatusLabel'
import { incidentHref, isPending, ROW_GRID, sourceOf } from './model'

export interface IncidentRowProps extends Omit<ComponentProps<'div'>, 'children'> {
  incident: Incident
  /** 발생부터 지난 초. 서버가 준 pending_seconds 에 목록을 받은 뒤 흐른 시간을 더한 값 */
  elapsedSeconds: number
  /** aria-rowindex. 머리 행이 1 이므로 본문은 2 부터 */
  rowIndex?: number
  /** CVE 배지(#52). 서명 규칙 사건이고 배지 조회가 성공했을 때만 준다 */
  cti?: CtiBadgeValue
}

/**
 * 목록 한 행(데스크톱). 행 어디를 눌러도 상세로 간다.
 * 키보드 초점은 규칙 링크에 있다. 링크를 눌렀을 때는 링크가 이미 이동했으므로(defaultPrevented) 두 번 가지 않고,
 * 보조키(새 탭)와 글자 드래그는 누름으로 보지 않는다.
 */
export function IncidentRow({ incident, elapsedSeconds, rowIndex, cti, className, onClick, ...rest }: IncidentRowProps) {
  const navigate = useNavigate()
  const origin = useReturnTo()
  const href = incidentHref(incident.incident_key)
  const pending = isPending(incident)

  function handleClick(event: MouseEvent<HTMLDivElement>) {
    onClick?.(event)
    if (event.defaultPrevented) return
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    if (window.getSelection()?.toString()) return
    void navigate(href, { state: { returnTo: origin.href } })
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
        {/* 배지는 이름 옆에 두되, 이름이 6자 남짓(basis-24)보다 좁아지면 다음 줄로 내린다 */}
        <div className={cn('flex min-w-0 items-baseline gap-x-2', cti && 'flex-wrap gap-y-0.5')}>
          <Link to={href} state={{ returnTo: origin.href }} className="shrink-0 font-mono text-xs font-medium text-primary">
            {incident.rule_id}
          </Link>
          <span className={cn('truncate font-medium text-ink', cti && 'min-w-0 grow basis-24')} title={revealHidden(incident.rule_name)}>
            <UntrustedText value={incident.rule_name} clip />
          </span>
          {cti && <CtiBadge badge={cti} className="shrink-0" />}
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
        {/* 관련 장비(#72). 이전 서버(devices 없음)는 규칙 번호 분류(발생원)를 그대로 보인다 */}
        {incident.devices ? (
          <DeviceBadges source={incident} mode="compact" className="flex-wrap" />
        ) : (
          <span className="text-xs text-ink-muted">{sensorOf(incident.rule_id)}</span>
        )}
      </div>
      <div role="cell">
        <IncidentStatusLabel status={incident.status} />
        <div className="mt-1 text-xs text-ink-muted">담당 <UntrustedText value={incident.assigned_to} fallback="미배정" />{incident.assigned_to && incident.assignee_available === false && <span className="text-warning"> · 변경 필요</span>}</div>
      </div>
      <div role="cell">
        {incident.verdict ? <VerdictBadge verdict={incident.verdict} /> : <span className="text-xs font-medium text-primary">미판정</span>}
      </div>
    </div>
  )
}
