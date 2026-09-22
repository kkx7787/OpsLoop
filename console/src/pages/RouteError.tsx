import { isRouteErrorResponse, Link, useLocation, useRouteError } from 'react-router'
import { buttonClasses } from '@/components/atoms/button-styles'
import { ErrorState } from '@/components/organisms/states/ErrorState'
import { NotFoundState } from '@/components/organisms/states/NotFoundState'

/** 페이지가 그리다 실패했을 때(틀 안). 라우터의 404 응답은 없는 주소 화면으로 보인다. */
export function RouteError() {
  const error = useRouteError()
  const { pathname, search } = useLocation()
  const home = (
    <Link to="/" className={buttonClasses({ variant: 'primary', size: 'lg' })}>
      대시보드로
    </Link>
  )
  if (isRouteErrorResponse(error) && error.status === 404) {
    return <NotFoundState size="page" titleAs="h1" path={`${pathname}${search}`} actions={home} />
  }
  return (
    <ErrorState
      size="page"
      titleAs="h1"
      eyebrow="오류 · 화면"
      title="화면을 그리지 못했습니다"
      error={error}
      actions={home}
      footnote="같은 일이 반복되면 브라우저를 새로고침하고, 그래도 안 되면 관리자에게 알려 주세요."
    />
  )
}

/** 틀(AppLayout) 자체가 실패했을 때. 라우터 밖으로 나가는 일반 링크만 둔다. */
export function RootError() {
  const error = useRouteError()
  return (
    <main className="mx-auto flex max-w-[720px] flex-col p-4 md:px-10 md:py-8">
      <ErrorState
        size="page"
        titleAs="h1"
        eyebrow="오류 · 화면"
        title="화면을 그리지 못했습니다"
        error={error}
        actions={
          <a href="/" className={buttonClasses({ variant: 'primary', size: 'lg' })}>
            대시보드로
          </a>
        }
      />
    </main>
  )
}
