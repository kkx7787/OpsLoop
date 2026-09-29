import type { ComponentProps, ReactNode } from 'react'
import type { Me } from '@/auth/useMe'
import { cn } from '@/lib/cn'
import { Brand } from './nav/Brand'
import { NavMenu } from './nav/NavMenu'
import type { NavGroup } from './nav/nav-items'
import { OpsSummary } from './nav/OpsSummary'
import { UserPanel } from './nav/UserPanel'

export interface SideNavProps extends ComponentProps<'aside'> {
  groups: readonly NavGroup[]
  /** 지금 사용자의 역할. 관리 묶음의 흐림 여부를 정한다. */
  userRole?: string | null
  user?: Me | null
  /** 관제 이상 요약(OpsSummary). 없으면 조회 전 자리 */
  ops?: ReactNode
}

/** 데스크톱 사이드바 208px(Main.dc.html): 제품 표지 · 메뉴 묶음 · 아래에 관제 이상 요약과 사용자 · 로그아웃 */
export function SideNav({ groups, userRole, user, ops, className, ...rest }: SideNavProps) {
  return (
    <aside
      aria-label="사이드바"
      className={cn('flex w-[208px] shrink-0 flex-col bg-sidebar px-3 shadow-sidebar', className)}
      {...rest}
    >
      <Brand />
      <NavMenu groups={groups} userRole={userRole} />
      <div className="mt-auto flex flex-col gap-3 px-1.5 pt-3 pb-4 shadow-hairline-up">
        {ops ?? <OpsSummary view={{ state: 'pending' }} />}
        <UserPanel user={user} />
      </div>
    </aside>
  )
}
