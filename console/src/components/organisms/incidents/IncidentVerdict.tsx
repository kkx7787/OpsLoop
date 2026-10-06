import type { Incident } from '@/api/incidents'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'

/** 판정값과 그 기록의 작성자를 함께 보인다. 미판정에는 과거 담당자를 섞지 않는다. */
export function IncidentVerdict({ incident }: { incident: Incident }) {
  if (!incident.verdict) return <span className="text-xs font-medium text-primary">미판정</span>
  return <div className="flex min-w-0 flex-col items-start gap-1">
    <VerdictBadge verdict={incident.verdict} />
    {incident.verdict_operator && <span className="max-w-full break-all text-xs text-ink-muted">판정 <UntrustedText value={incident.verdict_operator} max={64} /></span>}
    {incident.verdict_at && <span className="text-xs text-ink-muted"><Time value={incident.verdict_at} format="short" /></span>}
  </div>
}
