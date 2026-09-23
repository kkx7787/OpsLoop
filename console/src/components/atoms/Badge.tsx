import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { SOFT_TONE, type Tone } from './tones'

export interface BadgeProps extends ComponentProps<'span'> {
  tone?: Tone
}

/** 상태 표지. 색만으로 뜻을 전하지 않도록 항상 글자를 넣는다. */
export function Badge({ tone = 'neutral', className, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-sm px-1.5 py-0.5 text-xs leading-4 font-medium',
        SOFT_TONE[tone],
        className,
      )}
      {...rest}
    />
  )
}
