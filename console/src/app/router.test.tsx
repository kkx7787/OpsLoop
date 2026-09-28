import { screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderRoutes, stubMe } from '@/test/render'
import { routes } from './router'
import { MONITORING_SUMMARY } from '@/test/monitoring-fixtures'

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** /api/me 에 더해 목록 화면이 부르는 /api/incidents(0건) · /api/rules/quality(빈 배열) · /api/sources(0곳) · /api/accounts(한 명)에 답한다 */
function stubIncidents(me: unknown) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(raw, 'http://localhost')
    if (url.pathname === '/api/stats/summary') return json(MONITORING_SUMMARY, 200)
    if (url.pathname === '/api/blocklist') return json([], 200)
    if (url.pathname === '/api/me') return json(me, 200)
    if (url.pathname === '/api/incidents') return json({ total: 0, limit: 50, offset: 0, items: [] }, 200)
    if (url.pathname === '/api/nodes') return json({ as_of: '', rows: [] }, 200)
    if (url.pathname === '/api/assets') return json({ as_of: '', available: false }, 200)
    if (url.pathname === '/api/sources') return json({ as_of: '2026-09-29T00:00:00+00:00', total: 0, limit: 50, offset: 0, checkers: { gateway_stale: false, fw_stale: false }, items: [] }, 200)
    if (url.pathname === '/api/rules/quality') return json(url.searchParams.has('details') ? { rows: [], versions: [], runs: [] } : [], 200)
    if (url.pathname === '/api/accounts') return json({ accounts: [{ username: 'root', role: 'admin', active: true, disabled_at: null, created_at: '2026-09-20T00:00:00Z', last_login_at: null, updated_at: null, locked: 'self' }] }, 200)
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

  it.each([['/', '관제 현황'], ['/blocklist', '차단 목록'], ['/rules', '규칙 · 리플레이'], ['/nodes', '수집 노드'], ['/inventory', '자산 · 취약점'], ['/sources', '출발지 분석'], ['/reports', '보고서']])('%s는 구현 화면이다', async (path, title) => {
    stubIncidents({ username: 'han', role: 'operator' })
    renderRoutes(routes, path)
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.queryByText('구현 예정')).toBeNull()
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

  it('/inventory 는 수집 묶음의 자산 · 취약점 메뉴가 현재 위치다', async () => {
    stubIncidents({ username: 'han', role: 'viewer' })
    renderRoutes(routes, '/inventory?asset=web-01')
    expect(await screen.findByRole('heading', { level: 1, name: '자산 · 취약점' })).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: '주 메뉴' })).getByRole('link', { name: '자산 · 취약점' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('navigation', { name: '현재 위치' })).toHaveTextContent('수집›자산 · 취약점')
  })

  it.each([['/audit', '감사 기록'], ['/accounts', '계정']])('관리 화면 %s 는 admin 이 아니면 403 안내(숨기지 않고 이유를 보인다)', async (path, title) => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, path)
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    const main = screen.getByRole('main')
    expect(await within(main).findByRole('heading', { name: '이 화면은 admin 만 볼 수 있습니다' })).toBeInTheDocument()
    expect(within(main).getByText(/현재 역할 operator/)).toBeInTheDocument()
    expect(screen.queryByText('구현 예정')).toBeNull()
  })

  it('admin 은 계정 화면을 본다: 계정 표 · 명령줄 안내(자리 카드가 아니다)', async () => {
    const fetch = stubIncidents({ username: 'root', role: 'admin' })
    renderRoutes(routes, '/accounts')
    expect(await screen.findByRole('heading', { level: 1, name: '계정' })).toBeInTheDocument()
    expect(await screen.findByRole('region', { name: '계정 표' })).toHaveTextContent('본인 계정')
    expect(screen.getByRole('heading', { name: '명령줄에서 하는 일' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '계정' })).toHaveAttribute('aria-current', 'page')
    expect(screen.queryByText('구현 예정')).toBeNull()
    expect(screen.queryByText('WBS 3.6.8')).toBeNull()
    expect(fetch.mock.calls.some(([input]) => String(input) === '/api/accounts')).toBe(true)
  })
})
