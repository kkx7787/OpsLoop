import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

export interface SpinnerProps extends Omit<ComponentProps<'span'>, 'children'> {
  size?: 'sm' | 'md' | 'lg'
  /** 화면 낭독기가 읽을 말. 버튼 안처럼 주변 글이 이미 설명하면 decorative 로 숨긴다. */
  label?: string
  decorative?: boolean
}

const SIZE = { sm: 'size-3.5', md: 'size-5', lg: 'size-8' } as const

export function Spinner({ size = 'md', label = '불러오는 중', decorative = false, className, ...rest }: SpinnerProps) {
  return (
    <span
      role={decorative ? undefined : 'status'}
      aria-hidden={decorative || undefined}
      className={cn('inline-flex shrink-0 text-current', className)}
      {...rest}
    >
      <svg className={cn(SIZE[size], 'animate-spin')} viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
        <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
        <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {!decorative && <span className="sr-only">{label}</span>}
    </span>
  )
}
