import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

/** 단축키 표시 */
export function Kbd({ className, ...rest }: ComponentProps<'kbd'>) {
  return (
    <kbd
      className={cn(
        'inline-flex h-5 min-w-5 items-center justify-center rounded-md bg-surface px-1.5 font-mono text-2xs text-muted shadow-control',
        className,
      )}
      {...rest}
    />
  )
}
