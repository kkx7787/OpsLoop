import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { fieldClasses } from './field-styles'

export type TextareaProps = ComponentProps<'textarea'>

/** 판정 근거 같은 여러 줄 입력 */
export function Textarea({ className, rows = 3, ...rest }: TextareaProps) {
  return <textarea rows={rows} className={fieldClasses('md', cn('h-auto resize-y py-2', className))} {...rest} />
}
