import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface SegmentOption<V extends string> {
  value: V
  label: ReactNode
  disabled?: boolean
}

export interface SegmentedControlProps<V extends string> {
  options: readonly SegmentOption<V>[]
  value: V
  onChange: (value: V) => void
  /** 묶음의 이름(정렬 · 묶음 기준) */
  'aria-label': string
  className?: string
}

/** 하나만 고르는 단추 묶음(와이어프레임 "전체 · 발생원 · 세그먼트 · 규칙", "경과순 · 심각도순 · 최신순") */
export function SegmentedControl<V extends string>({
  options,
  value,
  onChange,
  'aria-label': ariaLabel,
  className,
}: SegmentedControlProps<V>) {
  return (
    <div role="group" aria-label={ariaLabel} className={cn('inline-flex flex-wrap items-center gap-0.5 text-xs', className)}>
      {options.map((opt) => {
        const selected = opt.value === value
        return (
          <button
            key={opt.value}
            type="button"
            aria-pressed={selected}
            disabled={opt.disabled}
            onClick={() => onChange(opt.value)}
            className={cn(
              'cursor-pointer rounded-control px-2.5 py-1 whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-50',
              selected ? 'bg-primary-soft font-semibold text-primary' : 'text-muted hover:text-ink',
            )}
          >
            {opt.label}
          </button>
        )
      })}
    </div>
  )
}
