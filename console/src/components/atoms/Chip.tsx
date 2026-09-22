import type { ComponentProps } from 'react'
import { cn } from '@/lib/cn'

export interface ChipProps extends ComponentProps<'span'> {
  /** 있으면 × 단추를 붙인다(적용 중인 조건 빼기) */
  onRemove?: () => void
  /** × 단추의 이름(화면 낭독기용). 조건이 여럿이면 무엇을 빼는지 넣는다. 예: '판정 = 미판정 조건 빼기' */
  removeLabel?: string
}

/** 적용 중인 조건(와이어프레임 .chip) */
export function Chip({ onRemove, removeLabel = '조건 빼기', className, children, ...rest }: ChipProps) {
  return (
    <span
      className={cn(
        'inline-flex h-7 items-center gap-1.5 rounded-full bg-primary-soft px-3 text-xs font-medium text-primary',
        onRemove && 'pr-1',
        className,
      )}
      {...rest}
    >
      {children}
      {onRemove && (
        <button
          type="button"
          aria-label={removeLabel}
          onClick={onRemove}
          className="inline-flex size-5 cursor-pointer items-center justify-center rounded-full hover:bg-primary/10"
        >
          <svg viewBox="0 0 12 12" className="size-2.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
            <path d="M3 3l6 6M9 3l-6 6" />
          </svg>
        </button>
      )}
    </span>
  )
}
