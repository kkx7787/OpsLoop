import { useId, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { Label } from '../atoms/Label'

/** FormField 가 입력 요소에 넘기는 연결 속성 */
export interface FieldControlProps {
  id: string
  'aria-invalid'?: true
  'aria-describedby'?: string
  required?: boolean
}

export interface FormFieldProps {
  label: ReactNode
  /** 오류 문장. 있으면 입력이 aria-invalid 가 되고 문장이 설명으로 연결된다. */
  error?: ReactNode
  /** 도움말 */
  hint?: ReactNode
  required?: boolean
  /** 입력 요소 id 를 정해야 할 때만 준다. 없으면 useId. */
  id?: string
  className?: string
  /** 입력 요소를 그리는 함수. 받은 속성을 그대로 펼친다: {(f) => <Input {...f} />} */
  children: (control: FieldControlProps) => ReactNode
}

/** 라벨 · 입력 · 도움말 · 오류를 한 묶음으로 잇는다(htmlFor · aria-describedby · aria-invalid). */
export function FormField({ label, error, hint, required = false, id, className, children }: FormFieldProps) {
  const autoId = useId()
  const controlId = id ?? autoId
  const hintId = `${controlId}-hint`
  const errorId = `${controlId}-error`
  const hasError = error !== undefined && error !== null && error !== false && error !== ''
  const describedBy = [hint ? hintId : null, hasError ? errorId : null].filter(Boolean).join(' ')

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <Label htmlFor={controlId} required={required}>
        {label}
      </Label>
      {children({
        id: controlId,
        'aria-invalid': hasError ? true : undefined,
        'aria-describedby': describedBy || undefined,
        required: required || undefined,
      })}
      {hint && (
        <p id={hintId} className="m-0 text-xs text-ink-muted">
          {hint}
        </p>
      )}
      {hasError && (
        <p id={errorId} className="m-0 text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  )
}
