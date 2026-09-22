import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { formatKst, formatRelative, toDate, type TimeFormat, type TimeInput } from '@/lib/time'

export interface TimeProps extends Omit<ComponentProps<'time'>, 'children' | 'dateTime'> {
  value: TimeInput | null | undefined
  /** relative 는 '3분 전'. 마우스를 올리면 KST 전체 시각을 보인다. */
  format?: TimeFormat | 'relative'
  /** 뒤에 ' KST' 를 붙인다(상단바 시계처럼 시간대를 밝힐 때) */
  zone?: boolean
  /** relative 의 기준 시각(ms). 시험 · 일괄 갱신용 */
  now?: number
}

/** KST 시각. 값이 없거나 해석할 수 없으면 '—'. */
export function Time({ value, format = 'datetime', zone = false, now, className, title, ...rest }: TimeProps) {
  const date = toDate(value)
  if (!date) return <span className={cn('text-ink-muted', className)}>—</span>

  const full = `${formatKst(date, 'datetime')} KST`
  const text = format === 'relative' ? formatRelative(date, now) : formatKst(date, format) + (zone ? ' KST' : '')
  return (
    <time
      dateTime={date.toISOString()}
      title={title ?? (text === full ? undefined : full)}
      className={cn('tabular-nums', className)}
      {...rest}
    >
      {text}
    </time>
  )
}
