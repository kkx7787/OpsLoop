import { Fragment, type ComponentProps, type ReactNode, type Ref } from 'react'
import { cn } from '@/lib/cn'
import { Button } from '../atoms/Button'
import { IconMenu, IconRefresh } from '../atoms/icons'

export interface TopBarProps extends ComponentProps<'header'> {
  /** 경로 표시(관제 › 대시보드). 마지막이 현재 위치. 없으면 제품명을 보인다. */
  breadcrumbs?: readonly ReactNode[]
  /** 갱신 주기 안내('30초마다 갱신'). 새로고침 단추 앞에 둔다 */
  status?: ReactNode
  /** 새로고침. 주지 않으면 단추가 없다(대시보드 · 장비 로그는 화면 머리의 기준 시각 옆에 둔다, #79) */
  onRefresh?: () => void
  refreshing?: boolean
  /** 모바일 서랍 열기. 주면 메뉴 단추가 생긴다(데스크톱에서는 숨긴다). */
  onOpenMenu?: () => void
  menuOpen?: boolean
  /** 서랍을 닫은 뒤 초점을 돌려줄 메뉴 단추 */
  menuButtonRef?: Ref<HTMLButtonElement>
  /** 관제 이상 요약(모바일 상단바 오른쪽 · Mobile.dc.html). AppLayout 이 짧은 표기로 넣는다 */
  ops?: ReactNode
  /** 실시간 통보 연결 표시(LiveIndicator). AppLayout 이 넣는다. */
  live?: ReactNode
}

/**
 * 상단바 48px. 데스크톱(Main.dc.html)은 경로 표시 · 실시간 연결 표시 · 갱신 안내 · 새로고침,
 * 모바일(Mobile.dc.html)은 메뉴 단추 · 제품명 · 연결 점 · 관제 이상 요약. 사용자 · 로그아웃은 메뉴 아래(SideNav · MobileNav)에 있다.
 * 현재 시계는 두지 않는다(#79). 운영자에게 필요한 것은 지금 몇 시인지가 아니라 화면 숫자가 언제 것인지라,
 * 화면마다 조회 기준 시각 하나를 본문(PageHeader · 카드 머리)에 둔다.
 */
export function TopBar({
  breadcrumbs = [],
  status,
  onRefresh,
  refreshing = false,
  onOpenMenu,
  menuOpen = false,
  menuButtonRef,
  ops,
  live,
  className,
  ...rest
}: TopBarProps) {
  return (
    <header
      className={cn(
        'sticky top-0 z-20 flex h-12 shrink-0 items-center justify-between gap-3 bg-surface px-4 shadow-hairline',
        'md:px-6',
        className,
      )}
      {...rest}
    >
      <div className="flex min-w-0 flex-1 items-center gap-2">
        {onOpenMenu && (
          <Button
            ref={menuButtonRef}
            size="icon"
            aria-label="메뉴 열기"
            aria-haspopup="dialog"
            aria-expanded={menuOpen}
            onClick={onOpenMenu}
            className="shadow-none md:hidden"
          >
            <IconMenu size={18} />
          </Button>
        )}
        <span className="text-[16px] font-semibold md:hidden">OpsLoop</span>
        {breadcrumbs.length > 0 ? (
          <nav aria-label="현재 위치" className="hidden min-w-0 md:block">
            <ol className="m-0 flex min-w-0 list-none items-center gap-1.5 p-0 text-sm text-ink-muted">
              {breadcrumbs.map((crumb, i) => {
                const last = i === breadcrumbs.length - 1
                return (
                  <Fragment key={i}>
                    <li aria-current={last ? 'page' : undefined} className="min-w-0 truncate">
                      {crumb}
                    </li>
                    {!last && <li aria-hidden="true">›</li>}
                  </Fragment>
                )
              })}
            </ol>
          </nav>
        ) : (
          <span className="hidden text-sm text-ink-muted md:block">OpsLoop</span>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2 text-xs text-ink-muted md:gap-3.5">
        {live !== undefined && live}
        {ops !== undefined && <span className="md:hidden">{ops}</span>}
        {status !== undefined && <span className="hidden md:inline">{status}</span>}
        {onRefresh && (
          <Button
            size="icon"
            aria-label="새로고침"
            onClick={onRefresh}
            disabled={refreshing}
            disabledReason="새로고침 중"
            className="text-ink"
          >
            <IconRefresh size={14} className={cn(refreshing && 'animate-spin')} />
          </Button>
        )}
      </div>
    </header>
  )
}
