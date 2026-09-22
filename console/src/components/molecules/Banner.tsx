import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { SOFT_TONE } from '../atoms/tones'

export type BannerTone = 'info' | 'success' | 'warning' | 'danger'

export interface BannerProps extends Omit<ComponentProps<'div'>, 'title'> {
  tone?: BannerTone
  /** 굵게 시작하는 첫 마디("데이터 연결이 끊겼습니다") */
  title?: ReactNode
  /** 오른쪽 동작 */
  action?: ReactNode
}

/**
 * 화면 위 띠(와이어프레임 Error · Detail · Incidents). 연결 끊김 · 알림 발송 실패 · 순환 규칙 안내에 쓴다.
 * danger 는 role="alert" 로 바로 읽히고, 나머지는 role="status" 로 조용히 알린다.
 */
export function Banner({ tone = 'info', title, action, className, children, ...rest }: BannerProps) {
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'status'}
      className={cn('flex items-center gap-3 rounded-panel px-4 py-3 text-sm', SOFT_TONE[tone], className)}
      {...rest}
    >
      <p className="m-0 min-w-0 flex-1">
        {title && <strong className="font-semibold">{title}</strong>}
        {title && children ? ' · ' : null}
        {children}
      </p>
      {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
    </div>
  )
}
