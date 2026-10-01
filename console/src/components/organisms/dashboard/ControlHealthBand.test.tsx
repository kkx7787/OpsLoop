import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { loginHref } from '@/api/client'
import type { ControlHealth } from '@/api/health'
import type { LiveStatus } from '@/api/live'
import { MONITOR, controlHealth } from '@/test/monitoring-fixtures'
import { ControlHealthBand } from './ControlHealthBand'

type Health = { data: ControlHealth | undefined; isError: boolean }

function renderBand(health: Health, live?: LiveStatus) {
  const result = render(
    <MemoryRouter>
      <ControlHealthBand health={health} live={live} />
    </MemoryRouter>,
  )
  const rerender = (next: Health, nextLive?: LiveStatus) =>
    result.rerender(
      <MemoryRouter>
        <ControlHealthBand health={next} live={nextLive} />
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
      expect(screen.getByRole('status').closest('section')).toHaveClass('sr-only')
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

describe('ControlHealthBand · 실시간 끊김 항목(#84)', () => {
  const ok = { data: controlHealth(), isError: false }

  it.each<[LiveStatus | undefined]>([[undefined], ['connecting'], ['connected']])('실시간 %s 이면 띠가 없다', (live) => {
    const { container } = renderBand(ok, live)
    expect(screen.queryByRole('region', { name: '관제 이상' })).toBeNull()
    expect(container).toHaveTextContent(/^$/)
  })

  it('다시 연결 중이고 이상이 없으면 띠 하나에 실시간 항목 하나(링크 없음)이고, 늘 있던 낭독 칸에 글만 들어간다', () => {
    const { rerender } = renderBand(ok, 'connected')
    const status = screen.getByRole('status')
    rerender(ok, 'reconnecting')
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(band).toHaveAttribute('data-control-health', 'alert')
    const items = [...band.querySelectorAll<HTMLElement>('[data-monitor-item]')]
    expect(items.map((li) => [li.dataset.monitorItem, li.textContent])).toEqual([['live', '실시간 연결 · 끊김 · 다시 연결 중']])
    expect(within(band).queryByRole('link')).toBeNull()
    // 낭독 칸은 하나뿐이고(띠 밖 첫 section) 새로 끼우지 않는다. 항목 띠에는 역할이 없다
    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(screen.getByRole('status')).toBe(status)
    expect(status).toHaveTextContent(/^실시간 연결 끊김 · 다시 연결 중$/)
    expect(within(band).queryByRole('status')).toBeNull()
    // 기준 ⓘ 는 공통 끊김 띠의 원문(주기 조회)을 그대로 싣고, 실시간 끊김만이라 단추 이름도 그 항목이다(확인 불가 띠와 같다)
    expect(within(band).getByRole('button', { name: '실시간 연결 끊김 설명' })).toHaveAccessibleDescription('현재 화면은 30초마다 별도로 조회합니다.')
    expect(within(band).queryByRole('button', { name: '관제 이상 기준 설명' })).toBeNull()
    rerender(ok, 'connected')
    expect(screen.queryByRole('region', { name: '관제 이상' })).toBeNull()
    expect(status).toBeEmptyDOMElement()
  })

  it('서버 항목이 있으면 한 띠 안에 서버 항목 뒤 끝 항목이고, ⓘ 는 멈춤 기준 뒤에 주기 조회를 붙인다', () => {
    renderBand({ data: controlHealth({ items: [MONITOR.loader] }), isError: false }, 'reconnecting')
    expect(screen.getAllByRole('region', { name: '관제 이상' })).toHaveLength(1)
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect([...band.querySelectorAll<HTMLElement>('[data-monitor-item]')].map((li) => li.dataset.monitorItem)).toEqual(['loader', 'live'])
    expect(within(band).getByRole('button', { name: '관제 이상 기준 설명' })).toHaveAccessibleDescription(
      '적재기 30분 · 집행기 10분 · 센서 15분 · 탐지 15분 · 노드 10분 넘게 확인이 없으면 멈춤입니다. 현재 화면은 30초마다 별도로 조회합니다.')
  })

  it('모름만 있어도 실시간 끊김이 있으면 주의색 띠이고, 관제 상태를 처음 받는 중이어도 실시간 항목만으로 띠를 그린다', () => {
    const { unmount } = renderBand({ data: controlHealth({ items: [MONITOR.heartbeats] }), isError: false }, 'reconnecting')
    expect(screen.getByRole('region', { name: '관제 이상' })).toHaveClass('bg-warning-soft')
    unmount()
    renderBand({ data: undefined, isError: false }, 'reconnecting')
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect([...band.querySelectorAll<HTMLElement>('[data-monitor-item]')].map((li) => li.dataset.monitorItem)).toEqual(['live'])
  })

  it('세션 종료(1008)면 다시 로그인 링크가 있고 주기 조회 ⓘ 는 붙이지 않는다(공통 끊김 띠와 같다)', () => {
    const { unmount } = renderBand(ok, 'closed')
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(band.querySelector('[data-monitor-item="live"]')).toHaveTextContent(/^실시간 연결 · 종료 · 다시 로그인$/)
    expect(within(band).getByRole('link', { name: '다시 로그인' })).toHaveAttribute('href', loginHref())
    expect(within(band).queryByRole('button')).toBeNull()
    expect(screen.getByRole('status')).toHaveTextContent('실시간 연결 종료 · 다시 로그인 필요')
    unmount()
    renderBand({ data: controlHealth({ items: [MONITOR.loader] }), isError: false }, 'closed')
    expect(within(screen.getByRole('region', { name: '관제 이상' })).getByRole('button', { name: '관제 이상 기준 설명' })).toHaveAccessibleDescription(
      '적재기 30분 · 집행기 10분 · 센서 15분 · 탐지 15분 · 노드 10분 넘게 확인이 없으면 멈춤입니다.')
  })

  it('관제 상태 확인 불가와 함께면 같은 한 줄 뒤에 붙인다(띠 하나 · 낭독 칸 하나)', () => {
    const { rerender } = renderBand({ data: undefined, isError: true })
    const status = screen.getByRole('status')
    rerender({ data: undefined, isError: true }, 'reconnecting')
    expect(screen.getAllByRole('region', { name: '관제 이상' })).toHaveLength(1)
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(within(band).getByRole('status')).toBe(status)
    expect(status).toHaveTextContent(/^관제 상태 확인 불가 · 실시간 연결 끊김$/)
    expect(band.querySelectorAll('[data-monitor-item]')).toHaveLength(0)
    expect(within(band).getByRole('button', { name: '실시간 연결 끊김 설명' })).toHaveAccessibleDescription('현재 화면은 30초마다 별도로 조회합니다.')
    rerender({ data: undefined, isError: true }, 'closed')
    expect(status).toHaveTextContent(/^관제 상태 확인 불가 · 실시간 연결 종료$/)
    expect(within(band).getByRole('link', { name: '다시 로그인' })).toHaveAttribute('href', loginHref())
    expect(within(band).queryByRole('button')).toBeNull()
  })
})
