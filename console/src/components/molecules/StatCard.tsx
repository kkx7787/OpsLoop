import { useId, type ComponentProps, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { Skeleton } from '../atoms/Skeleton'

export interface StatCardProps extends Omit<ComponentProps<'div'>, 'title'> {
  label: ReactNode
  value: ReactNode
  /** 수치 아래 한 줄(기준 · 비교) */
  caption?: ReactNode
  /** 맨 아래 이동 링크("목록 보기 ›"). 라우터 Link 를 넣는다. */
  action?: ReactNode
  /** danger: 목표 위반처럼 먼저 봐야 하는 수치(붉은 타일) */
  tone?: 'default' | 'danger'
  loading?: boolean
}

/** 대시보드 수치 타일(와이어프레임 Main 윗줄 네 칸) */
export function StatCard({ label, value, caption, action, tone = 'default', loading = false, className, ...rest }: StatCardProps) {
  const labelId = useId()
  const danger = tone === 'danger'
  return (
    <div
      role="group"
      aria-labelledby={labelId}
      aria-busy={loading || undefined}
      className={cn(
        'flex flex-col gap-1 px-4.5 py-4',
        danger ? 'rounded-tile bg-danger-soft text-danger' : 'rounded-card bg-surface shadow-card',
        className,
      )}
      {...rest}
    >
      <span id={labelId} className={cn(danger ? 'text-sm' : 'text-xs text-ink-muted')}>
        {label}
      </span>
      {loading ? (
        <Skeleton className="my-1 h-8 w-28" />
      ) : (
        <span className="text-4xl font-semibold tracking-display tabular-nums">{value}</span>
      )}
      {caption && <span className={cn('text-xs', !danger && 'text-ink-muted')}>{caption}</span>}
      {action && <span className={cn('mt-1.5 text-xs font-medium', danger && '[&_a]:text-danger')}>{action}</span>}
    </div>
  )
}
