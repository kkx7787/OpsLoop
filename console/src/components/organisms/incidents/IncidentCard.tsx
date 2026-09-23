import type { ComponentProps } from 'react'
import { Link } from 'react-router'
import type { Incident } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { IncidentStatusLabel } from './IncidentStatusLabel'
import { ElapsedTime } from './ElapsedTime'
import { incidentHref, isPending, sourceOf } from './model'

export interface IncidentCardProps extends Omit<ComponentProps<'li'>, 'children'> {
  incident: Incident
  /** 발생부터 지난 초 */
  elapsedSeconds: number
}

/** 모바일 카드: 경과·심각도·규칙·출발지와 판정·처리 상태. 카드 전체가 링크다. */
export function IncidentCard({ incident, elapsedSeconds, className, ...rest }: IncidentCardProps) {
  return (
    <li data-incident-key={incident.incident_key} className={cn('list-none', className)} {...rest}>
      <Link
        to={incidentHref(incident.incident_key)}
        className="flex flex-col gap-1.5 bg-surface px-3 py-3 text-ink hover:bg-primary-soft/50 hover:text-ink"
      >
        <div className="flex items-center justify-between gap-3">
          <ElapsedTime
            seconds={elapsedSeconds}
            severity={incident.severity}
            ruleId={incident.rule_id}
            since={incident.first_ts}
            pending={isPending(incident)}
            format="long"
            className="text-sm font-medium"
          />
          <SeverityBadge severity={incident.severity} />
        </div>
        <div className="flex min-w-0 items-baseline gap-1.5 text-sm">
          <span className="shrink-0 font-mono font-medium">{incident.rule_id}</span>
          <span className="truncate text-ink-muted">{incident.rule_name}</span>
        </div>
        <div className="truncate font-mono text-sm text-ink-muted">{sourceOf(incident)}</div>
        {incident.actor_ip && incident.target && <div className="truncate text-xs text-ink-muted">대상 {incident.target}</div>}
        <div className="flex items-center justify-between gap-2 border-t border-black/5 pt-2 text-xs">
          <IncidentStatusLabel status={incident.status} />
          {incident.verdict ? <VerdictBadge verdict={incident.verdict} /> : <span className="font-medium text-primary">미판정</span>}
        </div>
      </Link>
    </li>
  )
}
