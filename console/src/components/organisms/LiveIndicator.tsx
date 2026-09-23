import type { ComponentProps } from 'react'
import type { LiveState, LiveStatus } from '@/api/live'
import { cn } from '@/lib/cn'
import { StatusDot, type Signal } from '../atoms/StatusDot'

export interface LiveIndicatorProps extends Omit<ComponentProps<'span'>, 'children'> {
  /** useLiveUpdates 가 돌려주는 연결 상태 */
  live: LiveState
}

/** 연결 상태별 점 색과 글. 끊김은 눈에 띄어야 하고 이어져 있으면 조용해야 한다 */
const VIEW: Record<LiveStatus, { signal: Signal; label: string }> = {
  connecting: { signal: 'idle', label: '실시간 연결 중' },
  connected: { signal: 'ok', label: '실시간 수신 중' },
  reconnecting: { signal: 'warn', label: '실시간 끊김 · 다시 연결 중' },
  closed: { signal: 'bad', label: '실시간 끊김 · 다시 로그인 필요' },
}

/**
 * 실시간 통보(WS /ws) 연결 표시. 상단바 오른쪽에 점 하나와 짧은 글로 둔다.
 * 글은 md 이상에서 보이고 그 아래서는 읽기 전용(sr-only)으로 남겨, 색만으로 뜻을 전하지 않는다.
 */
export function LiveIndicator({ live, className, ...rest }: LiveIndicatorProps) {
  const { signal, label } = VIEW[live.status]
  return (
    <span data-live={live.status} title={label} className={cn('inline-flex items-center gap-1.5', className)} {...rest}>
      <StatusDot signal={signal} />
      <span className="sr-only md:not-sr-only">{label}</span>
    </span>
  )
}
