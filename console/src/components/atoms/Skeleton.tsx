import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

/** 불러오는 동안 자리를 잡는 회색 막대(와이어프레임 States: 12px · 6px 모서리) */
export function Skeleton({ className, ...rest }: ComponentProps<'span'>) {
  return (
    <span
      aria-hidden="true"
      className={cn('block h-3 rounded-md bg-skeleton motion-safe:animate-pulse', className)}
      {...rest}
    />
  )
}
