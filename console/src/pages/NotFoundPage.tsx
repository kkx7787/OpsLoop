import { Link, useLocation } from 'react-router'
import { buttonClasses } from '@/components/atoms/button-styles'
import { NotFoundState } from '@/components/organisms/states/NotFoundState'

/** 메뉴에 없는 주소(경로 '*'). 틀 안에서 그려지므로 메뉴로 바로 옮겨 갈 수 있다. */
export function NotFoundPage() {
  const { pathname, search } = useLocation()
  return (
    <NotFoundState
      size="page"
      titleAs="h1"
      path={`${pathname}${search}`}
      actions={
        <Link to="/" className={buttonClasses({ size: 'lg' })}>
          대시보드로
        </Link>
      }
    />
  )
}
