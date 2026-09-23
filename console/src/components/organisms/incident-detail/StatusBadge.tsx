import { INCIDENT_STATUS_LABEL, INCIDENT_STATUSES, type IncidentStatus } from '@/lib/domain'
import { Badge, type BadgeProps } from '../../atoms/Badge'
import { STATUS_TONE } from './format'

export interface StatusBadgeProps extends Omit<BadgeProps, 'tone' | 'children'> {
  /** 서버 값(open …). 모르는 값은 회색으로 그대로 보인다 */
  status: IncidentStatus | (string & {})
}

function isStatus(value: string): value is IncidentStatus {
  return (INCIDENT_STATUSES as readonly string[]).includes(value)
}

/** 사건 상태. 표기는 신규 · 확인 · 조치중 · 종결 · 억제(화면 설계 15장) */
export function StatusBadge({ status, ...rest }: StatusBadgeProps) {
  const known = isStatus(status)
  return (
    <Badge data-status={status} tone={known ? STATUS_TONE[status] : 'neutral'} {...rest}>
      {known ? INCIDENT_STATUS_LABEL[status] : status}
    </Badge>
  )
}
