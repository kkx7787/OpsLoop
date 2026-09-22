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

// 와이어프레임 .side a: 14px · 7px 10px · 모서리 8px · 아이콘은 주 색상
const LINK =
  'flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-base text-ink transition-colors ' +
  'hover:bg-black/4 hover:text-ink [&>svg]:shrink-0 [&>svg]:text-primary'
// .side a.on: 연한 파랑 바탕 · 주 색상 글자 · 600
const LINK_ON = 'bg-primary-soft font-semibold text-primary hover:bg-primary-soft hover:text-primary'

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
              className={cn('px-2.5 pt-[18px] pb-1.5 text-2xs font-semibold text-ink-muted', dimmed && 'opacity-45')}
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
