import { cn } from '@/lib/cn'
import { isVerdict, VERDICT_LABEL, type Verdict } from '@/lib/domain'
import { Badge, type BadgeProps } from './Badge'
import { VERDICT_CLASS } from './tones'

export interface VerdictBadgeProps extends Omit<BadgeProps, 'tone' | 'children'> {
  /** 서버 값(threat …). 모르는 값은 회색으로 그대로 보인다. */
  verdict: Verdict | (string & {})
}

/** 판정값. 화면 표기는 실제 위협 · 무시 가능 · 오탐 · 양성 정탐 · 미결(화면 설계 6.1). */
export function VerdictBadge({ verdict, className, ...rest }: VerdictBadgeProps) {
  const known = isVerdict(verdict)
  return (
    <Badge data-verdict={verdict} className={cn(known && VERDICT_CLASS[verdict], className)} {...rest}>
      {known ? VERDICT_LABEL[verdict] : verdict}
    </Badge>
  )
}
