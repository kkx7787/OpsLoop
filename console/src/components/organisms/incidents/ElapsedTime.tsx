import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { elapsedTone, verdictTargetSeconds, type ElapsedTone, type Severity } from '@/lib/domain'
import { formatDuration, formatKst, type TimeInput } from '@/lib/time'

export interface ElapsedTimeProps extends Omit<ComponentProps<'span'>, 'children'> {
  /** 발생(first_ts)부터 지난 초 */
  seconds: number
  severity: Severity | (string & {})
  /** 콘솔 발생 건(R2xx)은 심각도와 관계없이 critical 목표를 따른다 */
  ruleId?: string | null
  /** 발생 시각. 마우스를 올리면 KST 로 보인다 */
  since?: TimeInput | null
  /** 판정을 기다리는 건만 목표 대비 색을 준다. 판정된 건은 회색 */
  pending?: boolean
  /** compact '6h 12m'(목록의 좁은 칸) · long '6시간 12분'(카드 · 상세) */
  format?: 'compact' | 'long'
}

/** ok → warn(목표의 2/3 경과, 주황) → over(목표 초과, 빨강). 화면 설계 3장 · 4장 */
const TONE_CLASS: Record<ElapsedTone, string> = {
  ok: 'text-ink',
  warn: 'text-orange font-semibold',
  over: 'text-danger font-semibold',
}

/** 색만으로 뜻을 전하지 않도록 화면 낭독기에는 글로 알린다 */
const TONE_TEXT: Record<ElapsedTone, string | null> = {
  ok: null,
  warn: '목표 임박',
  over: '목표 초과',
}

/** 미판정 경과 시간. 심각도별 판정 목표 대비 색을 준다. */
export function ElapsedTime({
  seconds,
  severity,
  ruleId,
  since,
  pending = true,
  format = 'compact',
  className,
  title,
  ...rest
}: ElapsedTimeProps) {
  const safe = Number.isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0
  const tone: ElapsedTone = pending ? elapsedTone(severity, safe, ruleId) : 'ok'
  const target = verdictTargetSeconds(severity, ruleId)
  const hint = [
    since ? `발생 ${formatKst(since)} KST` : null,
    `경과 ${formatDuration(safe * 1000)}`,
    pending ? `판정 목표 ${formatDuration(target * 1000)}` : null,
  ]
    .filter(Boolean)
    .join(' · ')
  const note = pending ? TONE_TEXT[tone] : null

  return (
    <span
      data-tone={pending ? tone : undefined}
      title={title ?? hint}
      // sr-only의 절대 위치가 목록 스크롤 영역 밖 문서 높이를 늘리지 않도록 기준을 둔다.
      className={cn('relative whitespace-nowrap tabular-nums', pending ? TONE_CLASS[tone] : 'text-ink-muted', className)}
      {...rest}
    >
      {formatDuration(safe * 1000, format)}
      {note && <span className="sr-only"> ({note})</span>}
    </span>
  )
}
