import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface SwitchProps extends Omit<ComponentProps<'input'>, 'type' | 'children'> {
  label: ReactNode
}

/** 켜고 끄는 단추(와이어프레임 "문제만 보기"). 속은 체크박스라 양식 · 키보드가 그대로 동작한다. */
export function Switch({ label, className, disabled, checked, ...rest }: SwitchProps) {
  return (
    <label className={cn('inline-flex cursor-pointer items-center gap-1.5 text-sm', disabled && 'cursor-not-allowed opacity-50', className)}>
      <span className="relative inline-flex h-[22px] w-[38px] shrink-0">
        <input
          type="checkbox"
          role="switch"
          checked={checked}
          aria-checked={checked}
          disabled={disabled}
          className="peer absolute inset-0 m-0 cursor-[inherit] appearance-none rounded-full opacity-0"
          {...rest}
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 rounded-full bg-skeleton transition-colors peer-checked:bg-primary peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-primary"
        />
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-0.5 left-0.5 size-[18px] rounded-full bg-white shadow-[0_1px_3px_rgb(0_0_0/0.2)] transition-transform peer-checked:translate-x-4"
        />
      </span>
      {label}
    </label>
  )
}
