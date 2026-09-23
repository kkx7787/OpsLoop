import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { INCIDENT_STATUS_LABEL, type IncidentStatus } from '@/lib/domain'
import { StatusDot } from '../../atoms/StatusDot'
import { isIncidentStatus, STATUS_SIGNAL } from './model'

export interface IncidentStatusLabelProps extends Omit<ComponentProps<'span'>, 'children'> {
  /** 서버 값(open …). 모르는 값은 회색 점과 값 그대로 */
  status: IncidentStatus | (string & {})
}

/** 사건 상태: 점 + 글(신규 · 확인 · 조치중 · 종결 · 억제). 점만 두지 않는다. */
export function IncidentStatusLabel({ status, className, ...rest }: IncidentStatusLabelProps) {
  const known = isIncidentStatus(status)
  return (
    <span data-status={status} className={cn('inline-flex items-center gap-1.5 whitespace-nowrap', className)} {...rest}>
      <StatusDot signal={known ? STATUS_SIGNAL[status] : 'idle'} />
      {known ? INCIDENT_STATUS_LABEL[status] : status}
    </span>
  )
}
