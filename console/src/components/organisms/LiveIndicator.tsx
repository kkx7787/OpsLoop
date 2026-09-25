import type { ComponentProps } from 'react'
import { consoleLabel, type LiveState, type LiveStatus } from '@/api/live'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../atoms/Badge'
import { StatusDot, type Signal } from '../atoms/StatusDot'
import { UntrustedText } from '../atoms/UntrustedText'

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
 * 옆에 통보를 보내는 콘솔(hello 의 console)을 '콘솔 A' · '콘솔 B' 로 붙인다. 정해 둔 이름이 아니면 원문을 비신뢰 문자열로 그린다.
 * 끊기면 마지막 콘솔을 흐리게 남긴다(다시 이어지면 새 연결의 hello 로 바뀐다 · 이중화 전환이 눈에 보인다).
 */
export function LiveIndicator({ live, className, ...rest }: LiveIndicatorProps) {
  const { signal, label } = VIEW[live.status]
  const name = live.console
  const stale = live.status !== 'connected'
  const known = name === undefined ? null : consoleLabel(name)
  const shownName = name === undefined ? undefined : (known ?? revealHidden(name))
  const title = shownName === undefined ? label : `${label} · ${stale ? '마지막 연결 ' : ''}${shownName}`
  return (
    <span data-live={live.status} title={title} className={cn('inline-flex min-w-0 items-center gap-1.5', className)} {...rest}>
      <StatusDot signal={signal} />
      <span className="sr-only md:not-sr-only">{label}</span>
      {name !== undefined && (
        <span data-console={known ?? ''} data-stale={stale || undefined} className={cn('sr-only md:not-sr-only md:inline-flex md:min-w-0', stale && 'opacity-45')}>
          {stale && <span className="sr-only">마지막 연결 </span>}
          <Badge tone="neutral" className="inline-block max-w-40 truncate align-middle">
            {known ?? <UntrustedText value={name} max={64} clip />}
          </Badge>
        </span>
      )}
    </span>
  )
}
