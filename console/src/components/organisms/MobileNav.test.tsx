import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NAV_GROUPS } from '@/app/nav'
import { MobileNav } from './MobileNav'

function renderNav(open: boolean, onClose = vi.fn<() => void>()) {
  render(
    <MemoryRouter initialEntries={['/']}>
      <MobileNav open={open} onClose={onClose} groups={NAV_GROUPS} userRole="admin" user={{ username: 'root', role: 'admin' }} />
    </MemoryRouter>,
  )
  return onClose
}

describe('MobileNav', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('닫혀 있으면 아무것도 그리지 않는다', () => {
    renderNav(false)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('열리면 대화상자로 메뉴 · 사용자 · 로그아웃을 보이고 닫기 단추에 초점을 둔다', () => {
    renderNav(true)
    const dialog = screen.getByRole('dialog', { name: '메뉴' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(within(dialog).getByRole('navigation', { name: '주 메뉴' })).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: '대시보드' })).toHaveAttribute('aria-current', 'page')
    expect(within(dialog).getByText('root')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '로그아웃' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: '메뉴 닫기' })).toHaveFocus()
    expect(document.body.style.overflow).toBe('hidden')
  })

  it('Escape · 바깥 누름 · 닫기 단추 · 메뉴 항목 누름으로 닫는다', () => {
    const onClose = renderNav(true)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: '바깥을 눌러 메뉴 닫기' }))
    expect(onClose).toHaveBeenCalledTimes(2)
    fireEvent.click(screen.getByRole('button', { name: '메뉴 닫기' }))
    expect(onClose).toHaveBeenCalledTimes(3)
    fireEvent.click(screen.getByRole('link', { name: '인시던트' }))
    expect(onClose).toHaveBeenCalledTimes(4)
    fireEvent.click(screen.getByRole('link', { name: 'OpsLoop' }))      // 제품 표지도 이동이다
    expect(onClose).toHaveBeenCalledTimes(5)
  })

  it('열린 채 데스크톱 폭이 되면 닫는다', () => {
    const listeners: Array<(event: { matches: boolean }) => void> = []
    const mq = {
      matches: false,
      addEventListener: (_type: string, fn: (event: { matches: boolean }) => void) => listeners.push(fn),
      removeEventListener: () => {},
    }
    vi.stubGlobal('matchMedia', vi.fn(() => mq))
    const onClose = renderNav(true)
    expect(onClose).not.toHaveBeenCalled()
    listeners.forEach((fn) => fn({ matches: true }))
    expect(onClose).toHaveBeenCalledTimes(1)

    mq.matches = true                                                   // 이미 데스크톱 폭이면 열자마자 닫는다
    const again = renderNav(true)
    expect(again).toHaveBeenCalledTimes(1)
  })
})
