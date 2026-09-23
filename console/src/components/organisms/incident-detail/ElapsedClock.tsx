import { cn } from '@/lib/cn'
import { elapsedTone, verdictTargetSeconds, type ElapsedTone } from '@/lib/domain'
import { formatDuration, secondsSince, toDate } from '@/lib/time'
import { useNow } from '@/lib/useNow'

export interface ElapsedClockProps {
  severity: string
  ruleId: string
  /** 발생 시각. 시계는 여기서부터 세고 교대할 때 초기화하지 않는다 */
  firstTs: string
  /** 판정된 시각. 있으면 시계를 멈추고 판정까지 걸린 시간을 보인다 */
  judgedAt?: string | null
  className?: string
}

const TONE_CLASS: Record<ElapsedTone, string> = {
  ok: 'text-ink',
  warn: 'text-warning',
  over: 'text-warning',
}

const TONE_LABEL: Record<ElapsedTone, string> = {
  ok: '이내',
  warn: '임박',
  over: '초과',
}

/**
 * 경과 시간과 판정 목표(화면 설계 3장 표). 목표 임박과 초과는 시간 경고색으로 표시한다.
 * 콘솔 발생 건은 심각도와 관계없이 critical 목표를 따른다(verdictTargetSeconds).
 */
export function ElapsedClock({ severity, ruleId, firstTs, judgedAt, className }: ElapsedClockProps) {
  const judged = toDate(judgedAt)
  const tick = useNow(judged ? 0 : 1000)
  const seconds = secondsSince(firstTs, judged ? judged.getTime() : tick)
  const target = verdictTargetSeconds(severity, ruleId)
  const tone = elapsedTone(severity, seconds, ruleId)
  return (
    <div className={cn('flex flex-col items-start gap-0.5 md:items-end', className)} data-elapsed-tone={tone}>
      <span className={cn('text-base font-medium tracking-heading tabular-nums', TONE_CLASS[tone])}>
        {judged ? '판정까지 ' : '경과 '}
        {formatDuration(seconds * 1000)}
      </span>
      <span className="text-xs text-ink-muted">
        판정 목표 {formatDuration(target * 1000)} · <span className={cn(tone !== 'ok' && 'font-medium', TONE_CLASS[tone])}>{TONE_LABEL[tone]}</span>
      </span>
    </div>
  )
}
