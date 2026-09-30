import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { monitoringKeys } from '@/api/monitoring-keys'
import { NAV_GROUPS } from '@/app/nav'
import { expectInertDom, HOSTILE } from '@/test/hostile-fixtures'
import { controlHealth, json, MONITOR, monitorItem } from '@/test/monitoring-fixtures'
import { noRetryClient, renderRoutes, stubHanging, stubMe } from '@/test/render'
import { PageHeader } from '../molecules/PageHeader'
import { PageRefresh } from '../organisms/PageRefresh'
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
      element: <AppLayout groups={NAV_GROUPS} />,
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
    // 관제 상태 조회는 이 가짜 서버에 없다(404) → 확인 불가
    expect(await within(sidebar).findByRole('link', { name: '관제 상태 확인 불가' })).toHaveAttribute('href', '/')
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

  it('/api/me 의 console(#43)은 선택이다: 있어도 · 없어도 · 문자열이 아니어도 사용자와 본문을 그린다', async () => {
    for (const name of ['opsloop-console-a', undefined, 42, null, { name: 'b' }]) {
      stubMe({ username: 'han', role: 'operator', console: name })
      const { unmount } = renderRoutes(layoutRoutes(), '/')
      expect(await screen.findByText('대시보드 본문')).toBeInTheDocument()
      const sidebar = screen.getByRole('complementary', { name: '사이드바' })
      expect(within(sidebar).getByText('han')).toBeInTheDocument()
      expect(within(sidebar).getByText('operator')).toBeInTheDocument()
      unmount()
      vi.unstubAllGlobals()
    }
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
    expect(alert).toHaveTextContent('콘솔 서버 버전이 화면과 맞지 않습니다. 배포를 확인해 주세요.')
    // 소스 파일 이름 · '공통' 분류는 보이지 않는다
    expect(alert).not.toHaveTextContent(/app\/web\.py|공통/)
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

  it('실시간 연결 상태를 상단바에 점과 글로 보인다: 이어지면 통보 연결, 끊기면 다시 연결 중', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')

    const banner = screen.getByRole('banner')
    expect(FakeSocket.last?.url).toMatch(/^ws:\/\/.+\/ws$/)
    expect(within(banner).getByText('실시간 연결 중')).toBeInTheDocument()

    act(() => FakeSocket.last?.dispatchEvent(new Event('open')))
    expect(within(banner).getByText('실시간 통보 연결')).toBeInTheDocument()

    act(() => FakeSocket.last?.dispatchEvent(Object.assign(new Event('close'), { code: 1006 })))
    expect(within(banner).getByText('실시간 끊김 · 다시 연결 중')).toBeInTheDocument()
  })

  it('상단바에 현재 시계가 없다. 화면이 머리에 기준 시각 + 새로고침을 두면 상단바 새로고침은 숨고, 떠나면 돌아온다(#79)', async () => {
    stubMe({ username: 'han', role: 'operator' })
    const routes: RouteObject[] = [
      {
        path: '/',
        element: <AppLayout groups={NAV_GROUPS} />,
        children: [
          { index: true, element: <p>대시보드 본문</p> },
          {
            path: 'incidents',
            element: <PageHeader title="장비 로그" status={<PageRefresh parts={[{ dataUpdatedAt: Date.now(), errorUpdatedAt: 0, isError: false, asOf: '2026-09-30T05:00:05Z' }]} />} />,
          },
        ],
      },
    ]
    const { router } = renderRoutes(routes, '/')
    await screen.findByText('대시보드 본문')
    const banner = screen.getByRole('banner')
    expect(banner.querySelector('time')).toBeNull()
    expect(banner).not.toHaveTextContent(/KST|\d\d:\d\d:\d\d/)
    expect(within(banner).getByRole('button', { name: '새로고침' })).toBeInTheDocument()

    await router.navigate('/incidents')
    await screen.findByRole('heading', { level: 1, name: '장비 로그' })
    // 새로고침은 화면 머리의 기준 시각 옆 하나뿐이다
    expect(within(banner).queryByRole('button', { name: '새로고침' })).toBeNull()
    expect(screen.getAllByRole('button', { name: '새로고침' })).toHaveLength(1)
    expect(within(screen.getByRole('main')).getByRole('button', { name: '새로고침' })).toBeInTheDocument()
    expect(screen.getByRole('main')).toHaveTextContent('기준 14:00:05')

    await router.navigate('/')
    await screen.findByText('대시보드 본문')
    expect(within(banner).getByRole('button', { name: '새로고침' })).toBeInTheDocument()
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

/** /api/me 는 로그인 성공, /api/dashboard/monitor 는 monitor() 가 정한 응답, 그 밖은 404 */
function stubLayout(monitor: () => Response | Promise<Response>) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.startsWith('/api/me')) return json({ username: 'han', role: 'operator' })
    if (url.startsWith('/api/dashboard/monitor')) return monitor()
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

const monitorCalls = (fetch: { mock: { calls: unknown[][] } }) => fetch.mock.calls.filter(([input]) => String(input).startsWith('/api/dashboard/monitor')).length

describe('AppLayout · 관제 이상 요약(#72)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('/api/me 성공 뒤에만 /api/dashboard/monitor 를 부른다(받는 중 · 401 에는 부르지 않는다)', async () => {
    stubHanging()
    const { unmount } = renderRoutes(layoutRoutes(), '/')
    const hanging = vi.mocked(globalThis.fetch)
    await waitFor(() => expect(hanging).toHaveBeenCalled())
    expect(monitorCalls(hanging)).toBe(0)
    // 받는 동안 사이드바는 조회 전 자리다
    expect(within(screen.getByRole('complementary', { name: '사이드바' })).getByRole('link', { name: '관제 상태 조회 전' })).toBeInTheDocument()
    unmount()
    vi.unstubAllGlobals()

    vi.stubGlobal('location', { assign: vi.fn<(url: string | URL) => void>(), pathname: '/', search: '', href: 'http://localhost/' })
    const denied = stubMe({ detail: '인증이 필요합니다' }, 401)
    const second = renderRoutes(layoutRoutes(), '/')
    expect(await screen.findByRole('heading', { level: 1, name: '다시 로그인해 주세요' })).toBeInTheDocument()
    expect(monitorCalls(denied)).toBe(0)
    second.unmount()
    vi.unstubAllGlobals()

    const fetch = stubLayout(() => json(controlHealth()))
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')
    await waitFor(() => expect(monitorCalls(fetch)).toBe(1))
    expect(fetch).toHaveBeenCalledWith('/api/dashboard/monitor', expect.objectContaining({ method: 'GET', credentials: 'same-origin' }))
  })

  it('404 면 사이드바 · 상단바가 관제 상태 확인 불가다', async () => {
    stubLayout(() => json({ detail: 'Not Found' }, 404))
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')
    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    const link = await within(sidebar).findByRole('link', { name: '관제 상태 확인 불가' })
    expect(link).toHaveAttribute('data-signal', 'warn')
    expect(within(screen.getByRole('banner')).getByRole('link', { name: '확인 불가' })).toHaveAttribute('href', '/')
    // 본문 상태 화면과 섞이지 않는다(역할 없음)
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('이상이 있으면 관제 이상 n 과 말풍선 이름, 모름만 있으면 일부 미확인, 없으면 이상 없음. 서랍도 같은 글이다', async () => {
    let body = controlHealth({ items: [MONITOR.loader, MONITOR.mismatch, MONITOR.nodes] })
    stubLayout(() => json(body))
    const client = noRetryClient()
    renderRoutes(layoutRoutes(), '/', client)
    await screen.findByText('대시보드 본문')
    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    const link = await within(sidebar).findByRole('link', { name: '관제 이상 2' })
    expect(link).toHaveAttribute('title', '적재기 · 관문 불일치')
    expect(within(screen.getByRole('banner')).getByRole('link', { name: '이상 2' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '메뉴 열기' }))
    expect(within(screen.getByRole('dialog', { name: '메뉴' })).getByRole('link', { name: '관제 이상 2' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })

    body = controlHealth({ items: [MONITOR.heartbeats] })
    await act(() => client.refetchQueries({ queryKey: monitoringKeys.health }))
    expect(await within(sidebar).findByRole('link', { name: '관제 상태 일부 미확인' })).toBeInTheDocument()

    body = controlHealth()
    await act(() => client.refetchQueries({ queryKey: monitoringKeys.health }))
    expect(await within(sidebar).findByRole('link', { name: '관제 이상 없음' })).toBeInTheDocument()
    expect(within(screen.getByRole('banner')).getByRole('link', { name: '이상 없음' })).toBeInTheDocument()
  })

  it('이상 2건을 받은 뒤 다음 조회가 503 이면(재시도 없음) 이전 항목을 지우고 확인 불가만 남는다', async () => {
    let status = 200
    stubLayout(() => (status === 200 ? json(controlHealth({ items: [MONITOR.loader, MONITOR.mismatch] })) : json({ detail: '콘솔 서버를 잠시 쓸 수 없습니다' }, status)))
    const client = noRetryClient()
    renderRoutes(layoutRoutes(), '/', client)
    await screen.findByText('대시보드 본문')
    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    expect(await within(sidebar).findByRole('link', { name: '관제 이상 2' })).toBeInTheDocument()

    status = 503
    await act(() => client.refetchQueries({ queryKey: monitoringKeys.health }))
    expect(await within(sidebar).findByRole('link', { name: '관제 상태 확인 불가' })).not.toHaveAttribute('title')
    expect(screen.queryByText('관제 이상 2')).toBeNull()
    expect(within(screen.getByRole('banner')).getByRole('link', { name: '확인 불가' })).toBeInTheDocument()
    expect(screen.queryByText('이상 2')).toBeNull()

    // 다시 받으면 돌아온다
    status = 200
    await act(() => client.refetchQueries({ queryKey: monitoringKeys.health }))
    expect(await within(sidebar).findByRole('link', { name: '관제 이상 2' })).toBeInTheDocument()
  })

  it('한 번도 받지 못한 채 다시 조회하는 동안에도 사이드바 · 상단바는 확인 불가다(조회 전으로 바뀌지 않는다)', async () => {
    let calls = 0
    let hold: ((response: Response) => void) | undefined
    stubLayout(() => (++calls === 1 ? json({ detail: 'DB unavailable' }, 503) : new Promise<Response>((resolve) => { hold = resolve })))
    const client = noRetryClient()
    renderRoutes(layoutRoutes(), '/', client)
    await screen.findByText('대시보드 본문')
    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    expect(await within(sidebar).findByRole('link', { name: '관제 상태 확인 불가' })).toBeInTheDocument()
    act(() => void client.refetchQueries({ queryKey: monitoringKeys.health }))
    await waitFor(() => expect(calls).toBe(2))
    expect(within(sidebar).getByRole('link', { name: '관제 상태 확인 불가' })).toBeInTheDocument()
    expect(within(screen.getByRole('banner')).getByRole('link', { name: '확인 불가' })).toBeInTheDocument()
    expect(screen.queryByText('관제 상태 조회 전')).toBeNull()
    act(() => hold?.(json(controlHealth())))
    expect(await within(sidebar).findByRole('link', { name: '관제 이상 없음' })).toBeInTheDocument()
  })

  it('서랍의 관제 요약을 누르면 대시보드로 가며 서랍이 닫히고 초점이 메뉴 단추로 돌아온다', async () => {
    stubLayout(() => json(controlHealth({ items: [MONITOR.loader] })))
    const { router } = renderRoutes(layoutRoutes(), '/incidents')
    await screen.findByText('인시던트 본문')
    fireEvent.click(screen.getByRole('button', { name: '메뉴 열기' }))
    fireEvent.click(await within(screen.getByRole('dialog', { name: '메뉴' })).findByRole('link', { name: '관제 이상 1' }))
    expect(await screen.findByText('대시보드 본문')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByRole('button', { name: '메뉴 열기' })).toHaveFocus()
  })

  it('악성 항목 이름도 말풍선에 글자로만 들어간다', async () => {
    stubLayout(() => json(controlHealth({ items: [monitorItem({ key: 'loader', label: `${HOSTILE.rlo} ${HOSTILE.img} ${HOSTILE.decoy}` })] })))
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')
    const sidebar = screen.getByRole('complementary', { name: '사이드바' })
    const link = await within(sidebar).findByRole('link', { name: '관제 이상 1' })
    expectInertDom(sidebar)
    expect(link.getAttribute('title')).toContain('admin⟨U+202E⟩gnp.exe')
  })
})
