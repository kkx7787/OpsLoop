import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

export interface DividerProps extends ComponentProps<'hr'> {
  orientation?: 'horizontal' | 'vertical'
}

/** 0.5px 느낌의 옅은 구분선 */
export function Divider({ orientation = 'horizontal', className, ...rest }: DividerProps) {
  const vertical = orientation === 'vertical'
  return (
    <hr
      aria-orientation={vertical ? 'vertical' : undefined}
      className={cn('m-0 shrink-0 border-0 bg-black/8', vertical ? 'w-px self-stretch' : 'h-px w-full', className)}
      {...rest}
    />
  )
}
