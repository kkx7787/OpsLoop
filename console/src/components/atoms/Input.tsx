import type { ComponentProps } from 'react'
import { fieldClasses, type FieldSize } from './field-styles'

export interface InputProps extends ComponentProps<'input'> {
  /** sm 32px(필터 · 검색) · md 36px(양식). 네이티브 size 속성과 헷갈리지 않게 이름을 달리한다. */
  fieldSize?: FieldSize
}

export function Input({ fieldSize = 'md', className, type = 'text', ...rest }: InputProps) {
  return <input type={type} className={fieldClasses(fieldSize, className)} {...rest} />
}
