import { Link } from 'react-router'
import { can, PERMISSIONS } from '@/auth/roles'
import { useMe } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { buttonClasses } from '@/components/atoms/button-styles'
import { PageHeader } from '@/components/molecules/PageHeader'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import type { Screen } from '@/app/screens'
import { PendingCard } from './PendingCard'

export interface PlaceholderPageProps {
  screen: Screen
}

/**
 * 화면 자리: 페이지 머리(제목 · 설계 번호 · 한 줄 설명)와 구현 예정 카드.
 * 권한이 필요한 화면(관리 묶음)은 역할을 안 뒤 권한 밖이면 403 안내를 보인다. 서버도 같은 규칙으로 403 을 준다.
 */
export function PlaceholderPage({ screen }: PlaceholderPageProps) {
  const { data: me } = useMe()
  const action = screen.action
  const forbidden = action !== undefined && me !== undefined && !can(me.role, action)
  return (
    <div className="flex flex-col gap-[18px]">
      <PageHeader title={screen.title} badges={<Badge tone="info">{screen.code}</Badge>} description={screen.description} />
      {forbidden ? (
        <ForbiddenState
          size="page"
          title={`이 화면은 ${PERMISSIONS[action].join(' · ')} 만 볼 수 있습니다`}
          requiredRoles={PERMISSIONS[action]}
          currentRole={me.role}
          actions={
            <Link to="/" className={buttonClasses({ size: 'lg' })}>
              대시보드로
            </Link>
          }
        />
      ) : (
        <PendingCard wbs={screen.wbs} code={screen.code} />
      )}
    </div>
  )
}
