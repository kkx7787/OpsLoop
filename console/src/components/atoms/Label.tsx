import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

export interface LabelProps extends ComponentProps<'label'> {
  /** 필수 표시(*). 화면 낭독기에는 "필수"로 읽힌다. */
  required?: boolean
}

export function Label({ required = false, className, children, ...rest }: LabelProps) {
  return (
    <label className={cn('text-sm font-medium text-ink', className)} {...rest}>
      {children}
      {required && (
        <span className="ml-0.5 text-danger">
          <span aria-hidden="true">*</span>
          <span className="sr-only">필수</span>
        </span>
      )}
    </label>
  )
}
