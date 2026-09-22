import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface CardProps extends ComponentProps<'div'> {
  /** 안쪽 여백. 머리 · 표를 넣는 카드는 none 으로 두고 CardHeader 를 쓴다. */
  padding?: 'none' | 'sm' | 'md' | 'lg'
}

const PADDING = {
  none: '',
  sm: 'px-4 py-3.5',
  md: 'p-4',
  lg: 'p-5',
} as const

/** 흰 카드(와이어프레임 .card): 18px 모서리 · 0.5px 테두리 그림자 */
export function Card({ padding = 'md', className, ...rest }: CardProps) {
  return <div className={cn('rounded-card bg-surface shadow-card', PADDING[padding], className)} {...rest} />
}

export interface CardHeaderProps extends Omit<ComponentProps<'div'>, 'title'> {
  title: ReactNode
  /** 오른쪽 보조 정보(기준 · 링크) */
  aside?: ReactNode
  titleAs?: 'h2' | 'h3' | 'h4'
}

/** 카드 머리: 제목 15px · 아래 0.5px 선 */
export function CardHeader({ title, aside, titleAs: Heading = 'h2', className, ...rest }: CardHeaderProps) {
  return (
    <div className={cn('flex items-center justify-between gap-3 px-4 py-3 shadow-hairline', className)} {...rest}>
      <Heading className="m-0 text-md font-semibold tracking-heading">{title}</Heading>
      {aside !== undefined && <div className="flex items-center gap-3 text-xs text-ink-muted">{aside}</div>}
    </div>
  )
}
