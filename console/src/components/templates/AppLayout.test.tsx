import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NAV_GROUPS } from '@/app/nav'
import { noRetryClient, renderRoutes, stubHanging, stubMe } from '@/test/render'
import { AppLayout } from './AppLayout'
import { breadcrumbsFor, type RouteHandle } from './breadcrumbs'

const detailHandle: RouteHandle = { crumb: (params) => params.key ?? '' }

/** 서버 없이 여닫을 수 있는 가짜 WebSocket. 마지막으로 만든 것을 last 에 둔다 */
class FakeSocket extends EventTarget {
  static last: FakeSocket | undefined
  readonly url: string
  constructor(url: string) {
    super()
    this.url = url
    FakeSocket.last = this
  }
  close() {}
}

function layoutRoutes(): RouteObject[] {
  return [
    {
      path: '/',
      element: <AppLayout groups={NAV_GROUPS} sensor={{ received: 3, total: 3 }} />,
      children: [
        { index: true, element: <p>대시보드 본문</p> },
        { path: 'incidents', element: <p>인시던트 본문</p> },
        { path: 'incidents/:key', element: <p>상세 본문</p>, handle: detailHandle },
      ],
    },
  ]
}

describe('breadcrumbsFor', () => {
  it('묶음 › 항목 › handle.crumb', () => {
    expect(breadcrumbsFor(NAV_GROUPS, '/')).toEqual(['관제', '대시보드'])
    expect(breadcrumbsFor(NAV_GROUPS, '/incidents/R003', [{ handle: detailHandle, params: { key: 'R003' } }])).toEqual([
      '관제',
      '인시던트',
      'R003',
    ])
    expect(breadcrumbsFor(NAV_GROUPS, '/nowhere')).toEqual([])
  })
})

describe('AppLayout', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('사이드바 · 상단바 · 본문을 그리고 /api/me 로 사용자 · 역할을 채운다', async () => {
    const fetch = stubMe({ username: 'han', role: 'operator' })
    renderRoutes(layoutRoutes(), '/incidents/R003%7Cv2')

    expect(await screen.findByText('상세 본문')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledWith('/api/me', expect.objectContaining({ method: 'GET', credentials: 'same-origin' }))

    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    expect(within(sidebar).getByText('han')).toBeInTheDocument()
    expect(within(sidebar).getByText('operator')).toBeInTheDocument()
    expect(within(sidebar).getByText('센서 3/3 수신 중')).toBeInTheDocument()
    expect(within(sidebar).getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page')
    expect(sidebar.querySelectorAll('[data-gated="denied"]')).toHaveLength(3)

    expect(screen.getByRole('navigation', { name: '현재 위치' })).toHaveTextContent('관제›인시던트›R003|v2')
    expect(screen.getByRole('main')).toContainElement(screen.getByText('상세 본문'))
    expect(screen.getByRole('link', { name: '본문으로 건너뛰기' })).toHaveAttribute('href', '#main')
  })

  it('불러오는 동안은 본문 대신 확인 중 상태를 보이고 관리 묶음은 막혀 있다', () => {
    stubHanging()
    renderRoutes(layoutRoutes(), '/')
    expect(screen.getByRole('status')).toHaveAccessibleName('로그인 정보를 확인하는 중입니다')
    expect(screen.queryByText('대시보드 본문')).toBeNull()
    expect(screen.getByText('확인 중')).toBeInTheDocument()
  })

  it('/api/me 가 401 이면 /login?next=<지금 경로> 로 보내고, 남는 본문은 세션 만료 화면이다', async () => {
    const assign = vi.fn<(url: string | URL) => void>()
    vi.stubGlobal('location', { assign, pathname: '/incidents', search: '?q=4.4.66.84', href: 'http://localhost/incidents?q=4.4.66.84' })
    stubMe({ detail: '인증이 필요합니다' }, 401)
    renderRoutes(layoutRoutes(), '/incidents')

    expect(await screen.findByRole('heading', { level: 1, name: '다시 로그인해 주세요' })).toBeInTheDocument()
    expect(assign).toHaveBeenCalledTimes(1)
    expect(assign).toHaveBeenCalledWith('/login?next=%2Fincidents%3Fq%3D4.4.66.84')
    expect(screen.getByRole('link', { name: '로그인' })).toHaveAttribute('href', '/login?next=%2Fincidents%3Fq%3D4.4.66.84')
    expect(screen.queryByText('인시던트 본문')).toBeNull()
  })

  it('/api/me 가 사용자 정보를 주지 않으면(빈 응답) 세션 만료 화면으로 로그인을 안내한다', async () => {
    stubMe({})
    renderRoutes(layoutRoutes(), '/')
    expect(await screen.findByRole('heading', { level: 1, name: '다시 로그인해 주세요' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '로그인' })).toHaveAttribute('href', expect.stringMatching(/^\/login/))
    expect(screen.queryByText('대시보드 본문')).toBeNull()
  })

  it('/api/me 가 없으면(404) 서버 불일치를 알리고 로그인 · 다시 시도를 둔다', async () => {
    stubMe({ detail: 'Not Found' }, 404)
    renderRoutes(layoutRoutes(), '/')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('콘솔 서버가 로그인 정보를 주지 않습니다')
    expect(alert).toHaveTextContent('/api/me')
    expect(within(alert).getByRole('link', { name: '로그인' })).toHaveAttribute('href', expect.stringMatching(/^\/login/))
    expect(within(alert).getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
  })

  it('5xx 면 오류 화면과 다시 시도. 다시 시도가 /api/me 를 다시 부른다', async () => {
    const fetch = stubMe({ detail: '데이터베이스에 연결할 수 없습니다' }, 503)
    renderRoutes(layoutRoutes(), '/', noRetryClient())
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('로그인 정보를 확인하지 못했습니다')
    const calls = fetch.mock.calls.length
    fireEvent.click(within(alert).getByRole('button', { name: '다시 시도' }))
    await waitFor(() => expect(fetch.mock.calls.length).toBeGreaterThan(calls))
  })

  it('모바일 메뉴 단추로 서랍을 열고, 항목을 누르면 이동하며 닫힌다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    const { router } = renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')

    fireEvent.click(screen.getByRole('button', { name: '메뉴 열기' }))
    const dialog = screen.getByRole('dialog', { name: '메뉴' })
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveAttribute('aria-expanded', 'true')

    fireEvent.click(within(dialog).getByRole('link', { name: '인시던트' }))
    expect(await screen.findByText('인시던트 본문')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/incidents')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveFocus()

    // 서랍이 닫힌 뒤 처음 경로로 돌아와도 저절로 열리지 않는다
    await router.navigate('/')
    await screen.findByText('대시보드 본문')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('실시간 연결 상태를 상단바에 점과 글로 보인다: 이어지면 수신 중, 끊기면 다시 연결 중', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')

    const banner = screen.getByRole('banner')
    expect(FakeSocket.last?.url).toMatch(/^ws:\/\/.+\/ws$/)
    expect(within(banner).getByText('실시간 연결 중')).toBeInTheDocument()

    act(() => FakeSocket.last?.dispatchEvent(new Event('open')))
    expect(within(banner).getByText('실시간 수신 중')).toBeInTheDocument()

    act(() => FakeSocket.last?.dispatchEvent(Object.assign(new Event('close'), { code: 1006 })))
    expect(within(banner).getByText('실시간 끊김 · 다시 연결 중')).toBeInTheDocument()
  })

  it('Escape 로 닫아도 초점이 메뉴 단추로 돌아온다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')
    fireEvent.click(screen.getByRole('button', { name: '메뉴 열기' }))
    expect(screen.getByRole('dialog', { name: '메뉴' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveFocus()
  })
})
