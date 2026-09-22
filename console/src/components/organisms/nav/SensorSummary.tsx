import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { StatusDot, type Signal } from '../../atoms/StatusDot'

export interface SensorSummaryProps extends Omit<ComponentProps<'span'>, 'children'> {
  /** 수신 중인 센서 수. 아직 모르면(실시간 갱신 3.6.5 전) 비워 둔다. */
  received?: number
  total?: number
  /** 모바일 상단바용 짧은 표기('센서 3/3') */
  compact?: boolean
}

/** 센서 수신 요약 자리(와이어프레임 '센서 3/3 수신 중'). 값이 없으면 '확인 전'으로 보인다. */
export function SensorSummary({ received, total, compact = false, className, ...rest }: SensorSummaryProps) {
  const known = received !== undefined && total !== undefined
  const signal: Signal = !known ? 'idle' : received >= total ? 'ok' : received === 0 ? 'bad' : 'warn'
  const text = !known
    ? compact
      ? '센서 —'
      : '센서 수신 · 확인 전'
    : compact
      ? `센서 ${received}/${total}`
      : `센서 ${received}/${total} 수신 중`
  return (
    <span data-signal={signal} className={cn('inline-flex items-center gap-2 text-xs text-ink-muted', className)} {...rest}>
      <StatusDot signal={signal} />
      {text}
    </span>
  )
}
