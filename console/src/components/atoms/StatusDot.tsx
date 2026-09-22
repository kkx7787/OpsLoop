import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

export type Signal = 'ok' | 'bad' | 'warn' | 'idle' | 'info'

const SIGNAL: Record<Signal, string> = {
  ok: 'bg-signal-ok',
  bad: 'bg-signal-bad',
  warn: 'bg-signal-warn',
  idle: 'bg-signal-idle',
  info: 'bg-primary',
}

export interface StatusDotProps extends Omit<ComponentProps<'span'>, 'children'> {
  signal: Signal
  /** 옆에 글이 없을 때만 준다. 없으면 장식으로 숨긴다. */
  label?: string
}

/** 수신 · 연결 상태 점(7~8px). 색만으로 뜻을 전하지 않도록 옆에 글을 둔다. */
export function StatusDot({ signal, label, className, ...rest }: StatusDotProps) {
  return (
    <span
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      data-signal={signal}
      className={cn('inline-block size-2 shrink-0 rounded-full', SIGNAL[signal], className)}
      {...rest}
    />
  )
}
