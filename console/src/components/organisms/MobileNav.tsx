import { useEffect, useRef, type ReactNode } from 'react'
import type { Me } from '@/auth/useMe'
import { Button } from '../atoms/Button'
import { IconClose } from '../atoms/icons'
import { Brand } from './nav/Brand'
import { NavMenu } from './nav/NavMenu'
import type { NavGroup } from './nav/nav-items'
import { SensorSummary } from './nav/SensorSummary'
import { UserPanel } from './nav/UserPanel'

export interface MobileNavProps {
  open: boolean
  /** 닫기: Escape · 바깥 누름 · 닫기 단추 · 메뉴 항목 누름 */
  onClose: () => void
  groups: readonly NavGroup[]
  userRole?: string | null
  user?: Me | null
  sensor?: ReactNode
}

/**
 * 모바일 서랍. 왼쪽에서 280px 로 열리고 뒤는 어둡게 덮는다. 데스크톱(md 이상)에서는 그리지 않는다.
 * 열리면 닫기 단추에 초점을 두고 본문 스크롤을 멈춘다. 초점 되돌리기는 부르는 쪽(AppLayout)이 한다.
 */
export function MobileNav({ open, onClose, groups, userRole, user, sensor }: MobileNavProps) {
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    closeRef.current?.focus()
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [open])

  // 열린 채 데스크톱 폭(md)이 되면 닫는다. CSS 로만 숨기면 스크롤 잠금과 Escape 리스너가 남는다
  useEffect(() => {
    if (!open || typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia('(min-width: 768px)')
    if (mq.matches) {
      onClose()
      return
    }
    function onChange(event: MediaQueryListEvent) {
      if (event.matches) onClose()
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [open, onClose])

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-40 md:hidden">
      <button
        type="button"
        tabIndex={-1}
        aria-label="바깥을 눌러 메뉴 닫기"
        onClick={onClose}
        className="absolute inset-0 h-full w-full cursor-default border-0 bg-black/30 p-0"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="메뉴"
        className="absolute inset-y-0 left-0 flex w-[280px] max-w-[85vw] flex-col overflow-y-auto bg-sidebar px-3 shadow-card"
      >
        <div className="flex items-center justify-between">
          <Brand onClick={onClose} />
          <Button ref={closeRef} size="icon" aria-label="메뉴 닫기" onClick={onClose}>
            <IconClose size={16} />
          </Button>
        </div>
        <NavMenu groups={groups} userRole={userRole} onNavigate={onClose} />
        <div className="mt-auto flex flex-col gap-3.5 px-1.5 pt-4 pb-5 shadow-hairline-up">
          {sensor ?? <SensorSummary />}
          <UserPanel user={user} />
        </div>
      </div>
    </div>
  )
}
