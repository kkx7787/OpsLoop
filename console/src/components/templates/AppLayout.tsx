import { useMemo, useRef, useState, type ReactNode } from 'react'
import { Outlet, useLocation, useMatches } from 'react-router'
import { loginHref } from '@/api/client'
import { isApiError } from '@/api/errors'
import { useControlHealthView, useControlHealth } from '@/api/health'
import { useLiveUpdates } from '@/api/live'
import { LiveContext } from '@/api/live-context'
import { useNewIncidentToasts } from '@/api/new-incidents'
import { PageRefreshContext, useRefreshAll, type PageRefreshSlot } from '@/api/page-refresh'
import { parseMe, useMe } from '@/auth/useMe'
import { useTabBadge } from '@/lib/useTabBadge'
import { Button } from '../atoms/Button'
import { buttonClasses } from '../atoms/button-styles'
import { LiveIndicator } from '../organisms/LiveIndicator'
import { MobileNav } from '../organisms/MobileNav'
import type { NavGroup } from '../organisms/nav/nav-items'
import { OpsSummary } from '../organisms/nav/OpsSummary'
import { NewIncidentToasts } from '../organisms/NewIncidentToasts'
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
}

/**
 * 화면 틀: 사이드바(데스크톱) + 상단바 + 본문, 모바일은 서랍(Main · Mobile.dc.html).
 * 처음에 GET /api/me 로 사용자와 역할을 받는다. 401 이면 API 클라이언트가 /login?next= 로 보내고,
 * 이동이 막힌 경우 본문에 세션 만료 화면이 남는다. 받는 동안 관리 묶음은 막아 둔다.
 * 실시간 통보(WS /ws)는 여기서 한 번 잇고, 연결 상태와 붙은 콘솔은 상단바의 점(LiveIndicator)으로 보인다.
 * 세션이 끝나 웹소켓이 1008 로 닫히면 /api/me 를 다시 물어 401 → 로그인으로 간다.
 * 로그인을 확인한 뒤에만 관제 이상(GET /api/dashboard/monitor)을 받아 사이드바 · 상단바 · 서랍에 같은 요약을 보인다(대시보드 띠와 같은 판정).
 * 새 사건 통보는 보호 대상 장비가 확인된 사건만 본문 오른쪽 아래 알림으로 띄우고, 탭이 숨은 동안 띄운 수를 탭 제목 앞에 붙인다.
 * 인쇄(보고서 #58)에는 틀(건너뛰기 링크 · 사이드바 · 상단바)을 빼고 본문만 여백 없이 찍는다(print:hidden · print:p-0).
 * 상단바 새로고침은 화면이 머리에 기준 시각 + 새로고침(PageRefresh)을 둔 동안 숨는다(대시보드 · 장비 로그, #79). 동작은 같다(useRefreshAll).
 */
export function AppLayout({ groups, children }: AppLayoutProps) {
  const me = useMe()
  // 비어 있거나 모양이 틀리면 로그인 안 된 것으로 본다. console(#43)은 선택이라 없거나 틀려도 견딘다
  const user = parseMe(me.data)
  const health = useControlHealth(user !== null)
  const ops = useControlHealthView(health)
  const addUnseen = useTabBadge()
  const toasts = useNewIncidentToasts(user !== null, { onShown: addUnseen })
  const live = useLiveUpdates({ onMessage: toasts.onLiveMessage })
  const location = useLocation()
  const matches = useMatches()
  const { refresh, refreshing } = useRefreshAll()
  // 화면 머리에 새로고침을 둔 부품 수(PageRefresh). 0 보다 크면 상단바 단추를 숨긴다
  const [pageRefreshes, setPageRefreshes] = useState(0)
  const pageRefresh = useMemo<PageRefreshSlot>(
    () => ({
      claim: () => {
        setPageRefreshes((n) => n + 1)
        return () => setPageRefreshes((n) => n - 1)
      },
    }),
    [],
  )
  // 서랍을 연 시점의 location.key 를 적어 둔다. 이동하면 key 가 바뀌므로 효과 없이 닫힌 것이 된다.
  // (pathname 으로 적으면 같은 경로로 돌아왔을 때 다시 열린다)
  const [menuOpenKey, setMenuOpenKey] = useState<string | null>(null)
  const menuButtonRef = useRef<HTMLButtonElement>(null)

  const menuOpen = menuOpenKey === location.key
  const crumbs = breadcrumbsFor(groups, location.pathname, matches)

  function closeMenu() {
    setMenuOpenKey(null)
    menuButtonRef.current?.focus()
  }

  // 실시간 재접속 · resync 때 /api/me 를 다시 묻는다. 콘솔 전환 중이라 다시 묻기가 5xx · 네트워크로 실패해도
  // 이미 받은 사용자가 있으면 본문을 지우지 않는다. 401(세션 끝)만 곧바로 로그인 안내로 바꾼다.
  const unauthorized = isApiError(me.error) && me.error.status === 401
  let body: ReactNode
  if (me.isPending) {
    body = <LoadingState size="page" titleAs="h1" title="로그인 정보를 확인하는 중입니다" lines={2} />
  } else if (me.isError && (unauthorized || !user)) {
    body = <MeError error={me.error} onRetry={() => void me.refetch()} retrying={me.isFetching} />
  } else if (!user) {
    body = (
      <SessionExpiredState
        size="page"
        titleAs="h1"
        description="서버가 로그인 정보를 주지 않았습니다."
      />
    )
  } else {
    body = children ?? <Outlet />
  }

  return (
    <div className="flex min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-surface focus:px-3 focus:py-2 focus:shadow-card print:hidden"
      >
        본문으로 건너뛰기
      </a>
      <SideNav
        groups={groups}
        userRole={user?.role}
        user={user}
        ops={<OpsSummary view={ops} />}
        className="sticky top-0 hidden h-screen overflow-y-auto md:flex print:hidden"
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          className="print:hidden"
          breadcrumbs={crumbs}
          onRefresh={pageRefreshes > 0 ? undefined : () => void refresh()}
          refreshing={refreshing}
          onOpenMenu={() => setMenuOpenKey(location.key)}
          menuOpen={menuOpen}
          menuButtonRef={menuButtonRef}
          ops={<OpsSummary view={ops} compact />}
          live={<LiveIndicator live={live} />}
        />
        {/* tabIndex -1: 건너뛰기 링크 · 마지막 알림을 키보드로 닫을 때 초점을 받는다 */}
        <main id="main" tabIndex={-1} className="flex flex-1 flex-col gap-3 p-4 outline-none md:px-6 md:py-4 print:p-0">
          <LiveContext.Provider value={live}>
            <PageRefreshContext.Provider value={pageRefresh}>{body}</PageRefreshContext.Provider>
          </LiveContext.Provider>
        </main>
        <NewIncidentToasts toasts={toasts.toasts} onDismiss={toasts.dismiss} />
      </div>
      <MobileNav
        open={menuOpen}
        onClose={closeMenu}
        groups={groups}
        userRole={user?.role}
        user={user}
        ops={<OpsSummary view={ops} onClick={closeMenu} />}
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
        eyebrow="서버 불일치"
        title="콘솔 서버가 로그인 정보를 주지 않습니다"
        description="콘솔 서버 버전이 화면과 맞지 않습니다. 배포를 확인해 주세요."
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
