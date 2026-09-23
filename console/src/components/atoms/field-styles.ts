import { cn } from '@/lib/cn'

export type FieldSize = 'sm' | 'md'

/** 입력 · 선택 · 여러 줄 입력이 같이 쓰는 모양(작은 모서리 · 명확한 입력 경계) */
export function fieldClasses(size: FieldSize = 'md', className?: string): string {
  return cn(
    'w-full min-w-0 rounded-control border-0 bg-surface px-3 text-sm text-ink shadow-field outline-none',
    'placeholder:text-ink-muted',
    'focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-primary',
    'aria-invalid:shadow-[0_0_0_1px_var(--color-danger)] aria-invalid:focus-visible:outline-danger',
    'disabled:cursor-not-allowed disabled:bg-canvas disabled:text-ink-muted',
    size === 'sm' ? 'h-8' : 'h-9',
    className,
  )
}
