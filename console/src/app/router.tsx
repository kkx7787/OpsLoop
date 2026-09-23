import { createBrowserRouter, type RouteObject } from 'react-router'
import type { RouteHandle } from '@/components/templates/breadcrumbs'
import { AppLayout } from '@/components/templates/AppLayout'
import { IncidentDetailPage } from '@/pages/incident-detail'
import { IncidentsPage } from '@/pages/incidents'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { PlaceholderPage } from '@/pages/PlaceholderPage'
import { RootError, RouteError } from '@/pages/RouteError'
import { NAV_GROUPS } from './nav'
import { SCREENS } from './screens'

/** 상세 경로는 짧게 표시한다. 전체 사건 키는 상세 머리글에서 펼쳐 본다. */
const incidentHandle: RouteHandle = { crumb: () => '사건 상세' }

/**
 * 경로표(화면 설계 1장). 틀(AppLayout) 아래에 화면들이 놓이고, 화면의 오류는 틀 안에서 보인다.
 * 개발 서버에서만 /dev/components 에 공통 컴포넌트 모음이 붙는다(운영 번들에는 들어가지 않는다).
 */
export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppLayout groups={NAV_GROUPS} />,
    errorElement: <RootError />,
    children: [
      {
        errorElement: <RouteError />,
        children: [
          { index: true, element: <PlaceholderPage screen={SCREENS.dashboard} /> },
          { path: 'incidents', element: <IncidentsPage /> },
          { path: 'incidents/:key', element: <IncidentDetailPage />, handle: incidentHandle },
          { path: 'blocklist', element: <PlaceholderPage screen={SCREENS.blocklist} /> },
          { path: 'rules', element: <PlaceholderPage screen={SCREENS.rules} /> },
          { path: 'sources', element: <PlaceholderPage screen={SCREENS.sources} /> },
          { path: 'reports', element: <PlaceholderPage screen={SCREENS.reports} /> },
          { path: 'nodes', element: <PlaceholderPage screen={SCREENS.nodes} /> },
          { path: 'alerts', element: <PlaceholderPage screen={SCREENS.alerts} /> },
          { path: 'audit', element: <PlaceholderPage screen={SCREENS.audit} /> },
          { path: 'accounts', element: <PlaceholderPage screen={SCREENS.accounts} /> },
          ...(import.meta.env.DEV
            ? [
                {
                  path: 'dev/components',
                  lazy: async () => {
                    const { ComponentCatalog } = await import('./ComponentCatalog')
                    return { Component: ComponentCatalog }
                  },
                },
              ]
            : []),
          { path: '*', element: <NotFoundPage /> },
        ],
      },
    ],
  },
]

/** 브라우저 주소를 쓰는 라우터. 시험은 routes 로 메모리 라우터를 만든다. */
export function createAppRouter() {
  return createBrowserRouter(routes)
}
