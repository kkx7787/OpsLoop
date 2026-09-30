import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { TopBar } from './TopBar'

describe('TopBar', () => {
  it('경로 표시(마지막이 현재 위치) · 갱신 안내 · 새로고침. 현재 시계는 없다(#79)', () => {
    const onRefresh = vi.fn<() => void>()
    const { container } = render(<TopBar breadcrumbs={['관제', '대시보드']} status="30초마다 갱신" onRefresh={onRefresh} />)
    const nav = screen.getByRole('navigation', { name: '현재 위치' })
    expect(nav).toHaveTextContent('관제›대시보드')
    expect(within(nav).getByText('대시보드')).toHaveAttribute('aria-current', 'page')
    expect(within(nav).getByText('관제')).not.toHaveAttribute('aria-current')
    expect(container.querySelector('time')).toBeNull()
    expect(container).not.toHaveTextContent(/KST|\d\d:\d\d:\d\d/)
    // 갱신 안내는 새로고침 바로 앞이다
    const refresh = screen.getByRole('button', { name: '새로고침' })
    expect(screen.getByText('30초마다 갱신').nextElementSibling).toBe(refresh)
    fireEvent.click(refresh)
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('onRefresh 가 없으면 새로고침 단추가 없다(화면 머리에 둔 화면)', () => {
    render(<TopBar breadcrumbs={['관제', '대시보드']} />)
    expect(screen.queryByRole('button', { name: '새로고침' })).toBeNull()
  })

  it('새로고침 중에는 단추를 잠그되 초점은 남긴다', () => {
    const onRefresh = vi.fn<() => void>()
    render(<TopBar onRefresh={onRefresh} refreshing />)
    const button = screen.getByRole('button', { name: '새로고침' })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    expect(button).not.toBeDisabled()                 // 네이티브 disabled 는 키보드 초점을 잃는다
    fireEvent.click(button)
    expect(onRefresh).not.toHaveBeenCalled()
  })

  it('메뉴 단추는 열림 상태를 알리고 서랍을 연다', () => {
    const onOpenMenu = vi.fn<() => void>()
    render(<TopBar onOpenMenu={onOpenMenu} menuOpen={false} ops={<span>이상 2</span>} />)
    const button = screen.getByRole('button', { name: '메뉴 열기' })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(button).toHaveAttribute('aria-haspopup', 'dialog')
    fireEvent.click(button)
    expect(onOpenMenu).toHaveBeenCalledTimes(1)
    expect(screen.getByText('이상 2')).toBeInTheDocument()
  })

  it('경로가 없으면(없는 주소) 제품명을 보이고 메뉴 단추는 없다', () => {
    render(<TopBar />)
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.getAllByText('OpsLoop').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: '메뉴 열기' })).toBeNull()
  })
})
