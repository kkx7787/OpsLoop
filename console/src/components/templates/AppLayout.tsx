import { useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type ReactNode } from 'react'
import { Outlet, useLocation, useMatches } from 'react-router'
import { loginHref } from '@/api/client'
import { isApiError } from '@/api/errors'
import { useLiveUpdates } from '@/api/live'
import { useMe, type Me } from '@/auth/useMe'
import { Button } from '../atoms/Button'
import { buttonClasses } from '../atoms/button-styles'
import { LiveIndicator } from '../organisms/LiveIndicator'
import { MobileNav } from '../organisms/MobileNav'
import type { NavGroup } from '../organisms/nav/nav-items'
import { SensorSummary, type SensorSummaryProps } from '../organisms/nav/SensorSummary'
import { SideNav } from '../organisms/SideNav'
import { ErrorState } from '../organisms/states/ErrorState'
import { LoadingState } from '../organisms/states/LoadingState'
import { SessionExpiredState } from '../organisms/states/SessionExpiredState'
import { TopBar } from '../organisms/TopBar'
import { breadcrumbsFor } from './breadcrumbs'

export interface AppLayoutProps {
  groups: readonly NavGroup[]
  /** 본문. 없으면 라우터의 <Outlet /> */
  children?: ReactNode
  /** 센서 수신 요약 값. 실시간 갱신(3.6.5)이 넣는다. */
  sensor?: Pick<SensorSummaryProps, 'received' | 'total'>
}

/** /api/me 응답이 쓸 만한지. 비어 있으면 로그인 안 된 것으로 본다. */
function isMe(data: unknown): data is Me {
  if (!data || typeof data !== 'object') return false
  const { username, role } = data as Partial<Me>
  return typeof username === 'string' && username !== '' && typeof role === 'string'
}

/**
 * 화면 틀: 사이드바(데스크톱) + 상단바 + 본문, 모바일은 서랍(Main · Mobile.dc.html).
 * 처음에 GET /api/me 로 사용자와 역할을 받는다. 401 이면 API 클라이언트가 /login?next= 로 보내고,
 * 이동이 막힌 경우 본문에 세션 만료 화면이 남는다. 받는 동안 관리 묶음은 막아 둔다.
 * 실시간 통보(WS /ws)는 여기서 한 번 잇고, 연결 상태는 상단바의 점(LiveIndicator)으로 보인다.
 */
export function AppLayout({ groups, children, sensor }: AppLayoutProps) {
  const me = useMe()
  const live = useLiveUpdates()
  const location = useLocation()
  const matches = useMatches()
  const queryClient = useQueryClient()
  const [refreshing, setRefreshing] = useState(false)
  // 서랍을 연 시점의 location.key 를 적어 둔다. 이동하면 key 가 바뀌므로 효과 없이 닫힌 것이 된다.
  // (pathname 으로 적으면 같은 경로로 돌아왔을 때 다시 열린다)
  const [menuOpenKey, setMenuOpenKey] = useState<string | null>(null)
  const menuButtonRef = useRef<HTMLButtonElement>(null)

  const menuOpen = menuOpenKey === location.key
  const user = isMe(me.data) ? me.data : null
  const crumbs = breadcrumbsFor(groups, location.pathname, matches)

  function closeMenu() {
    setMenuOpenKey(null)
    menuButtonRef.current?.focus()
  }

  async function refresh() {
    setRefreshing(true)
    try {
      await queryClient.invalidateQueries()
    } finally {
      setRefreshing(false)
    }
  }

  let body: ReactNode
  if (me.isPending) {
    body = <LoadingState size="page" titleAs="h1" title="로그인 정보를 확인하는 중입니다" lines={2} />
  } else if (me.isError) {
    body = <MeError error={me.error} onRetry={() => void me.refetch()} retrying={me.isFetching} />
  } else if (!user) {
    body = (
      <SessionExpiredState
        size="page"
        titleAs="h1"
        description="서버가 로그인 정보를 주지 않았습니다. 다시 로그인해 주세요."
      />
    )
  } else {
    body = children ?? <Outlet />
  }

  return (
    <div className="flex min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-surface focus:px-3 focus:py-2 focus:shadow-card"
      >
        본문으로 건너뛰기
      </a>
      <SideNav
        groups={groups}
        userRole={user?.role}
        user={user}
        sensor={<SensorSummary {...sensor} />}
        className="sticky top-0 hidden h-screen overflow-y-auto md:flex"
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          breadcrumbs={crumbs}
          onRefresh={refresh}
          refreshing={refreshing}
          onOpenMenu={() => setMenuOpenKey(location.key)}
          menuOpen={menuOpen}
          menuButtonRef={menuButtonRef}
          sensor={<SensorSummary {...sensor} compact />}
          live={<LiveIndicator live={live} />}
        />
        <main id="main" className="flex flex-1 flex-col gap-3 p-4 md:gap-[18px] md:px-10 md:py-8">
          {body}
        </main>
      </div>
      <MobileNav
        open={menuOpen}
        onClose={closeMenu}
        groups={groups}
        userRole={user?.role}
        user={user}
        sensor={<SensorSummary {...sensor} />}
      />
    </div>
  )
}

interface MeErrorProps {
  error: unknown
  onRetry: () => void
  retrying: boolean
}

/** /api/me 실패. 401 은 로그인으로(이미 이동 중), 404 는 서버 불일치, 그 밖은 오류와 다시 시도. */
function MeError({ error, onRetry, retrying }: MeErrorProps) {
  if (isApiError(error) && error.status === 401) {
    return <SessionExpiredState size="page" titleAs="h1" />
  }
  if (isApiError(error) && error.status === 404) {
    return (
      <ErrorState
        size="page"
        titleAs="h1"
        eyebrow="공통 · 서버 불일치"
        title="콘솔 서버가 로그인 정보를 주지 않습니다"
        description="서버에 /api/me 가 없습니다(app/web.py 이전 버전). 콘솔 서버 배포를 확인해 주세요."
        actions={
          <>
            <a href={loginHref()} className={buttonClasses({ variant: 'primary', size: 'lg' })}>
              로그인
            </a>
            <Button size="lg" onClick={onRetry} loading={retrying}>
              다시 시도
            </Button>
          </>
        }
      />
    )
  }
  return (
    <ErrorState
      size="page"
      titleAs="h1"
      title="로그인 정보를 확인하지 못했습니다"
      error={error}
      onRetry={onRetry}
      retrying={retrying}
    />
  )
}
