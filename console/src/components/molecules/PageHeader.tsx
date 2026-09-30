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
  /**
   * 화면 기준 시각 + 새로고침(PageRefresh, #79). 모든 폭에서 제목 줄 오른쪽 끝에 둔다.
   * 넓은 화면은 aside 뒤(맨 오른쪽), 좁은 화면은 aside 가 설명 아래로 내려가도 이것은 제목 줄에 남는다
   */
  status?: ReactNode
}

/** 페이지 머리: 경로 · 제목(24px) · 표지 · 한 줄 설명 · 오른쪽 부가 정보 · 기준 시각 */
export function PageHeader({ breadcrumbs, title, badges, description, aside, status, className, ...rest }: PageHeaderProps) {
  const heading = (
    <div className="flex min-w-0 flex-wrap items-center gap-2.5">
      <h1 className="m-0 text-xl font-semibold tracking-tight md:text-[24px] md:leading-8">{title}</h1>
      {badges}
    </div>
  )
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
      {status ? (
        // 좁은 폭: [제목 | 기준 시각] / 설명 / aside, 넓은 폭: [제목 | aside | 기준 시각] / 설명.
        // DOM(Tab) 순서는 제목 → 설명 → aside → 기준 시각이라 넓은 폭에서 보이는 순서와 같다(좁은 폭은 기준 시각 단추가 aside 뒤)
        <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 md:grid-cols-[minmax(0,1fr)_auto_auto]">
          <div className="col-start-1 row-start-1 min-w-0">{heading}</div>
          {description && <p className="col-span-2 m-0 text-sm text-ink-muted md:col-span-1 md:col-start-1 md:row-start-2">{description}</p>}
          {aside && (
            <div className="col-span-2 mt-1.5 flex flex-wrap items-center gap-3 text-sm md:col-span-1 md:col-start-2 md:row-start-1 md:mt-0 md:justify-end">
              {aside}
            </div>
          )}
          <div className="col-start-2 row-start-1 flex justify-end md:col-start-3" data-page-status="">
            {status}
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div className="flex min-w-0 flex-col gap-1.5">
            {heading}
            {description && <p className="m-0 text-sm text-ink-muted">{description}</p>}
          </div>
          {aside && <div className="flex shrink-0 flex-wrap items-center gap-3 text-sm md:justify-end">{aside}</div>}
        </div>
      )}
    </header>
  )
}
