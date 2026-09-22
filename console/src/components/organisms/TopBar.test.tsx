import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { TopBar } from './TopBar'

const NOW = Date.parse('2026-09-18T06:20:04Z')

describe('TopBar', () => {
  it('경로 표시(마지막이 현재 위치) · KST 시계 · 갱신 안내 · 새로고침', () => {
    const onRefresh = vi.fn<() => void>()
    render(<TopBar breadcrumbs={['관제', '대시보드']} now={NOW} status="30초마다 갱신" onRefresh={onRefresh} />)
    const nav = screen.getByRole('navigation', { name: '현재 위치' })
    expect(nav).toHaveTextContent('관제›대시보드')
    expect(within(nav).getByText('대시보드')).toHaveAttribute('aria-current', 'page')
    expect(within(nav).getByText('관제')).not.toHaveAttribute('aria-current')
    expect(screen.getByText('2026-09-18 15:20:04 KST')).toBeInTheDocument()
    expect(screen.getByText('30초마다 갱신')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }))
    expect(onRefresh).toHaveBeenCalledTimes(1)
  })

  it('새로고침 중에는 단추를 잠그되 초점은 남긴다', () => {
    const onRefresh = vi.fn<() => void>()
    render(<TopBar now={NOW} onRefresh={onRefresh} refreshing />)
    const button = screen.getByRole('button', { name: '새로고침' })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    expect(button).not.toBeDisabled()                 // 네이티브 disabled 는 키보드 초점을 잃는다
    fireEvent.click(button)
    expect(onRefresh).not.toHaveBeenCalled()
  })

  it('메뉴 단추는 열림 상태를 알리고 서랍을 연다', () => {
    const onOpenMenu = vi.fn<() => void>()
    render(<TopBar now={NOW} onOpenMenu={onOpenMenu} menuOpen={false} sensor={<span>센서 3/3</span>} />)
    const button = screen.getByRole('button', { name: '메뉴 열기' })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(button).toHaveAttribute('aria-haspopup', 'dialog')
    fireEvent.click(button)
    expect(onOpenMenu).toHaveBeenCalledTimes(1)
    expect(screen.getByText('센서 3/3')).toBeInTheDocument()
  })

  it('경로가 없으면(없는 주소) 제품명을 보이고 메뉴 단추는 없다', () => {
    render(<TopBar now={NOW} />)
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(screen.getAllByText('OpsLoop').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: '메뉴 열기' })).toBeNull()
  })
})
