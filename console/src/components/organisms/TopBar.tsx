import { Fragment, type ComponentProps, type ReactNode, type Ref } from 'react'
import { cn } from '@/lib/cn'
import { useNow } from '@/lib/useNow'
import { Button } from '../atoms/Button'
import { IconMenu, IconRefresh } from '../atoms/icons'
import { Time } from '../atoms/Time'

export interface TopBarProps extends ComponentProps<'header'> {
  /** 경로 표시(관제 › 대시보드). 마지막이 현재 위치. 없으면 제품명을 보인다. */
  breadcrumbs?: readonly ReactNode[]
  /** 시계 기준 시각(ms). 주지 않으면 1초마다 지금 시각을 보인다. */
  now?: number
  /** 갱신 주기 안내('30초마다 갱신'). 대시보드(3.6.4)가 넣는다. */
  status?: ReactNode
  onRefresh?: () => void
  refreshing?: boolean
  /** 모바일 서랍 열기. 주면 메뉴 단추가 생긴다(데스크톱에서는 숨긴다). */
  onOpenMenu?: () => void
  menuOpen?: boolean
  /** 서랍을 닫은 뒤 초점을 돌려줄 메뉴 단추 */
  menuButtonRef?: Ref<HTMLButtonElement>
  /** 센서 수신 요약(모바일 상단바 오른쪽 · Mobile.dc.html) */
  sensor?: ReactNode
  /** 실시간 통보 연결 표시(LiveIndicator). AppLayout 이 넣는다. */
  live?: ReactNode
}

/**
 * 상단바 52px. 데스크톱(Main.dc.html)은 경로 표시 · 실시간 연결 표시 · KST 시계 · 갱신 안내 · 새로고침,
 * 모바일(Mobile.dc.html)은 메뉴 단추 · 제품명 · 연결 점 · 센서 요약. 사용자 · 로그아웃은 메뉴 아래(SideNav · MobileNav)에 있다.
 */
export function TopBar({
  breadcrumbs = [],
  now,
  status,
  onRefresh,
  refreshing = false,
  onOpenMenu,
  menuOpen = false,
  menuButtonRef,
  sensor,
  live,
  className,
  ...rest
}: TopBarProps) {
  const tick = useNow(now === undefined ? 1000 : 0)
  const shown = now ?? tick
  return (
    <header
      className={cn(
        'sticky top-0 z-20 flex h-[52px] shrink-0 items-center justify-between gap-3 bg-surface px-4 shadow-hairline',
        'md:bg-canvas/85 md:px-10 md:backdrop-blur',
        className,
      )}
      {...rest}
    >
      <div className="flex min-w-0 items-center gap-2">
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
            <ol className="m-0 flex list-none flex-wrap items-center gap-1.5 p-0 text-sm text-ink-muted">
              {breadcrumbs.map((crumb, i) => {
                const last = i === breadcrumbs.length - 1
                return (
                  <Fragment key={i}>
                    <li aria-current={last ? 'page' : undefined} className="truncate">
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
      <div className="flex shrink-0 items-center gap-3.5 text-xs text-ink-muted">
        {live !== undefined && live}
        {sensor !== undefined && <span className="md:hidden">{sensor}</span>}
        <Time value={shown} zone className="hidden font-mono md:inline" />
        {status !== undefined && <span className="hidden md:inline">{status}</span>}
        {onRefresh && (
          <Button
            size="icon"
            aria-label="새로고침"
            onClick={onRefresh}
            disabled={refreshing}
            disabledReason="새로고침 중"
            className="hidden text-ink md:inline-flex"
          >
            <IconRefresh size={14} className={cn(refreshing && 'animate-spin')} />
          </Button>
        )}
      </div>
    </header>
  )
}
