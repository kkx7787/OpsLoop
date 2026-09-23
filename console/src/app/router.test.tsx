import { screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderRoutes, stubMe } from '@/test/render'
import { routes } from './router'
import { MONITORING_SUMMARY } from '@/test/monitoring-fixtures'

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** /api/me 에 더해 목록 화면이 부르는 /api/incidents(0건) · /api/rules/quality(빈 배열)에 답한다 */
function stubIncidents(me: unknown) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(raw, 'http://localhost')
    if (url.pathname === '/api/stats/summary') return json(MONITORING_SUMMARY, 200)
    if (url.pathname === '/api/blocklist') return json([], 200)
    if (url.pathname === '/api/me') return json(me, 200)
    if (url.pathname === '/api/incidents') return json({ total: 0, limit: 50, offset: 0, items: [] }, 200)
    if (url.pathname === '/api/rules/quality') return json([], 200)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

describe('경로표', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('없는 주소는 틀 안에서 404 화면: 주소 표시 · 대시보드 링크', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/nowhere?x=1')
    expect(await screen.findByRole('heading', { level: 1, name: '페이지를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByText('/nowhere?x=1')).toBeInTheDocument()
    expect(within(screen.getByRole('main')).getByRole('link', { name: '대시보드로' })).toHaveAttribute('href', '/')
    // 메뉴는 그대로 있어 바로 옮겨 갈 수 있다
    expect(screen.getByRole('navigation', { name: '주 메뉴' })).toBeInTheDocument()
  })

  it.each([['/', '미판정 현황'], ['/blocklist', '차단 목록']])('%s는 구현 화면이다', async (path, title) => {
    stubIncidents({ username: 'han', role: 'operator' })
    renderRoutes(routes, path)
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.queryByText('구현 예정')).toBeNull()
  })

  it.each([
    ['/rules', '규칙과 리플레이', 'S-07'],
    ['/sources', '출발지 분석', 'S-09'],
    ['/reports', '보고서', 'S-11'],
    ['/nodes', '수집 노드', 'S-08 · S-13'],
  ])('%s → %s (%s)', async (path, title, code) => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, path)
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.getByText(code)).toBeInTheDocument()
    expect(screen.getByText('구현 예정')).toBeInTheDocument()
  })

  it('/incidents 는 목록 화면: 제목 · 조건 막대 · 0건 안내(자리 카드가 아니다)', async () => {
    const fetch = stubIncidents({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/incidents')
    expect(await screen.findByRole('heading', { level: 1, name: '인시던트' })).toBeInTheDocument()
    expect(await screen.findByText('인시던트가 없습니다')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page')
    expect(screen.queryByText('구현 예정')).toBeNull()
    expect(fetch.mock.calls.some(([input]) => String(input).startsWith('/api/incidents?'))).toBe(true)
  })

  it('인시던트 상세는 화면 이름을 상단바 경로 표시에 보이고, 없는 사건이면 목록으로 돌아가는 길을 둔다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/incidents/R003%7Cv2%7C1.2.3.4')
    expect(await screen.findByRole('heading', { level: 1, name: '인시던트를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: '현재 위치' })).toHaveTextContent('관제›인시던트›사건 상세')
    expect(screen.getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', '/incidents')
  })

  it('관리 화면은 admin 이 아니면 403 안내(숨기지 않고 이유를 보인다)', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/audit')
    expect(await screen.findByRole('heading', { level: 1, name: '감사 기록' })).toBeInTheDocument()
    const main = screen.getByRole('main')
    expect(await within(main).findByRole('heading', { name: '이 화면은 admin 만 볼 수 있습니다' })).toBeInTheDocument()
    expect(within(main).getByText(/현재 역할 operator/)).toBeInTheDocument()
    expect(screen.queryByText('구현 예정')).toBeNull()
  })

  it('admin 은 관리 화면 자리를 본다', async () => {
    stubMe({ username: 'root', role: 'admin' })
    renderRoutes(routes, '/accounts')
    expect(await screen.findByRole('heading', { level: 1, name: '계정' })).toBeInTheDocument()
    expect(await screen.findByText('구현 예정')).toBeInTheDocument()
    expect(screen.getByText('WBS 3.6.8')).toBeInTheDocument()
  })
})
