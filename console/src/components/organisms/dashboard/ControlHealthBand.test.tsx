import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import type { ControlHealth } from '@/api/health'
import { MONITOR, controlHealth } from '@/test/monitoring-fixtures'
import { ControlHealthBand } from './ControlHealthBand'

function renderBand(health: { data: ControlHealth | undefined; isError: boolean }) {
  const result = render(
    <MemoryRouter>
      <ControlHealthBand health={health} />
    </MemoryRouter>,
  )
  const rerender = (next: { data: ControlHealth | undefined; isError: boolean }) =>
    result.rerender(
      <MemoryRouter>
        <ControlHealthBand health={next} />
      </MemoryRouter>,
    )
  return { ...result, rerender }
}

describe('ControlHealthBand(#72)', () => {
  it('받는 중 · 이상 없음이면 보이는 띠가 없고, 비어 있는 status 자리만 미리 있다', () => {
    for (const health of [{ data: undefined, isError: false }, { data: controlHealth(), isError: false }]) {
      const { container, unmount } = renderBand(health)
      expect(screen.queryByRole('region', { name: '관제 이상' })).toBeNull()
      expect(container).toHaveTextContent(/^$/)
      expect(screen.getByRole('status')).toBeEmptyDOMElement()
      expect(screen.getByRole('status').parentElement).toHaveClass('sr-only')
      unmount()
    }
  })

  it('실패로 바뀌면 미리 있던 status 자리에 글만 들어간다(새로 끼운 status 는 낭독되지 않을 수 있다)', () => {
    const { rerender } = renderBand({ data: undefined, isError: false })
    const status = screen.getByRole('status')
    rerender({ data: undefined, isError: true })
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(within(band).getByRole('status')).toBe(status)
    expect(status).toHaveTextContent('관제 상태 확인 불가')
    expect(band).not.toHaveClass('sr-only')
    rerender({ data: controlHealth({ items: [MONITOR.loader] }), isError: false })
    expect(status).toBeInTheDocument()
    expect(status).toBeEmptyDOMElement()
  })

  it('실패면 받은 항목이 있어도 관제 상태 확인 불가 한 줄만(role status)이다', () => {
    const { container } = renderBand({ data: controlHealth({ items: [MONITOR.loader, MONITOR.enforcerFw] }), isError: true })
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(within(band).getByRole('status')).toHaveTextContent('관제 상태 확인 불가')
    expect(band).toHaveTextContent(/^관제 상태 확인 불가$/)
    expect(container.querySelectorAll('[data-monitor-item]')).toHaveLength(0)
    expect(within(band).queryByRole('link')).toBeNull()
  })

  it('항목 줄에는 role status · alert 를 두지 않는다(주기 조회마다 다시 읽히지 않게)', () => {
    renderBand({ data: controlHealth({ items: [MONITOR.loader, MONITOR.failedGateway, MONITOR.nodes] }), isError: false })
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(within(band).queryByRole('status')).toBeNull()
    expect(within(band).queryByRole('alert')).toBeNull()
    expect(within(band).getAllByRole('listitem')).toHaveLength(3)
    // 넓으면 한 줄로 잇고 좁으면 한 열로 쌓는다
    expect(within(band).getByRole('list')).toHaveClass('flex-col', 'md:flex-row', 'md:flex-wrap')
  })
})
