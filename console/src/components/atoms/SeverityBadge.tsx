import { cn } from '@/lib/cn'
import { isSeverity, type Severity } from '@/lib/domain'
import { Badge, type BadgeProps } from './Badge'
import { SEVERITY_CLASS } from './tones'

export interface SeverityBadgeProps extends Omit<BadgeProps, 'tone' | 'children'> {
  /** 서버 값 그대로. 모르는 값은 회색으로 그대로 보인다. */
  severity: Severity | (string & {})
}

/** 심각도. 표기는 서버 값(critical · high · medium · low)을 그대로 쓴다(와이어프레임). */
export function SeverityBadge({ severity, className, ...rest }: SeverityBadgeProps) {
  return (
    <Badge
      data-severity={severity}
      className={cn(isSeverity(severity) && SEVERITY_CLASS[severity], className)}
      {...rest}
    >
      {severity}
    </Badge>
  )
}
