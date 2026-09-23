import { useId } from 'react'
import { NavLink } from 'react-router'
import { permission } from '@/auth/roles'
import { cn } from '@/lib/cn'
import { Gated } from '../../molecules/Gated'
import type { NavGroup } from './nav-items'

export interface NavMenuProps {
  groups: readonly NavGroup[]
  /** 지금 사용자의 역할. 모르면(불러오는 중) 권한이 필요한 항목은 막아 둔다. */
  userRole?: string | null
  /** 항목을 눌렀을 때(모바일 서랍 닫기) */
  onNavigate?: () => void
  className?: string
}

// 기본 메뉴는 중립색, 현재 위치만 주 색상과 왼쪽 선으로 구별한다.
const LINK =
  'flex items-center gap-2.5 rounded-control border-l-2 border-transparent px-2 py-1.5 text-sm text-ink transition-colors ' +
  'hover:bg-black/4 hover:text-ink [&>svg]:shrink-0 [&>svg]:text-ink-muted'
// 색과 형태를 함께 써 현재 위치를 알린다.
const LINK_ON = 'border-l-primary bg-primary-soft font-semibold text-primary hover:bg-primary-soft hover:text-primary [&>svg]:text-primary'

/**
 * 메뉴 묶음(와이어프레임 .side). 사이드바와 모바일 서랍이 같이 쓴다.
 * 현재 위치는 NavLink 가 aria-current="page" 로 표시한다. 권한 밖 항목은 Gated 로 흐리게 두고 숨기지 않는다.
 */
export function NavMenu({ groups, userRole, onNavigate, className }: NavMenuProps) {
  const id = useId()
  return (
    <nav aria-label="주 메뉴" className={cn('flex flex-col', className)}>
      {groups.map((group, g) => {
        const gates = group.items.map((item) => (item.action ? permission(userRole, item.action) : undefined))
        // 묶음의 모든 항목이 막히면 묶음 이름도 같이 흐리게 둔다(관리 묶음)
        const dimmed = gates.length > 0 && gates.every((gate) => gate !== undefined && !gate.allowed)
        const labelId = `${id}-${g}`
        return (
          <div key={group.label} role="group" aria-labelledby={labelId} className="flex flex-col">
            <span
              id={labelId}
              className={cn('px-2.5 pt-4 pb-1 text-2xs font-semibold text-ink-muted', dimmed && 'opacity-45')}
            >
              {group.label}
            </span>
            {group.items.map((item, i) => {
              const Icon = item.icon
              const link = (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  onClick={onNavigate}
                  className={({ isActive }) => cn(LINK, isActive && LINK_ON)}
                >
                  <Icon />
                  {item.label}
                </NavLink>
              )
              const gate = gates[i]
              if (gate === undefined || gate.allowed) return link
              return (
                <Gated key={item.to} allowed={false} reason={gate.reason} className="flex w-full gap-0">
                  {link}
                </Gated>
              )
            })}
          </div>
        )
      })}
    </nav>
  )
}
