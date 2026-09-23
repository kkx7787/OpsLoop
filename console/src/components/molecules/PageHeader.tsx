import { Fragment, type ComponentProps, type ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface PageHeaderProps extends Omit<ComponentProps<'header'>, 'title'> {
  /** 경로(관제 › 인시던트 › …). 링크는 부르는 쪽이 라우터 Link 로 넣는다. 마지막 칸이 현재 위치다. */
  breadcrumbs?: readonly ReactNode[]
  title: ReactNode
  /** 제목 옆 표지(심각도 · 규칙 버전 배지) */
  badges?: ReactNode
  /** 제목 아래 한 줄 설명 */
  description?: ReactNode
  /** 오른쪽 부가 정보 · 동작(경과 시간 · 담당 · 단추) */
  aside?: ReactNode
}

/** 페이지 머리: 경로 · 제목(24px) · 표지 · 한 줄 설명 · 오른쪽 부가 정보 */
export function PageHeader({ breadcrumbs, title, badges, description, aside, className, ...rest }: PageHeaderProps) {
  return (
    <header className={cn('flex flex-col gap-2', className)} {...rest}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <nav aria-label="현재 위치">
          <ol className="m-0 flex list-none flex-wrap items-center gap-1.5 p-0 text-sm text-ink-muted">
            {breadcrumbs.map((crumb, i) => {
              const last = i === breadcrumbs.length - 1
              return (
                <Fragment key={i}>
                  <li aria-current={last ? 'page' : undefined} className={cn(last && 'text-ink')}>
                    {crumb}
                  </li>
                  {!last && (
                    <li aria-hidden="true" className="text-ink-muted">
                      ›
                    </li>
                  )}
                </Fragment>
              )
            })}
          </ol>
        </nav>
      )}
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div className="flex min-w-0 flex-col gap-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="m-0 text-xl font-semibold tracking-tight md:text-[24px] md:leading-8">{title}</h1>
            {badges}
          </div>
          {description && <p className="m-0 text-sm text-ink-muted">{description}</p>}
        </div>
        {aside && <div className="flex shrink-0 flex-wrap items-center gap-3 text-sm md:justify-end">{aside}</div>}
      </div>
    </header>
  )
}
