import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'
import { fieldClasses, type FieldSize } from './field-styles'

export interface SelectProps extends ComponentProps<'select'> {
  fieldSize?: FieldSize
}

/** 네이티브 select. 목록 모양은 브라우저에 맡기고 겉모양만 맞춘다. */
export function Select({ fieldSize = 'md', className, ...rest }: SelectProps) {
  return <select className={fieldClasses(fieldSize, cn('cursor-pointer pr-8', className))} {...rest} />
}
