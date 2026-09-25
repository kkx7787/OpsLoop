import { act, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NAV_GROUPS } from '@/app/nav'
import { noRetryClient, renderRoutes, stubMe } from '@/test/render'
import { AppLayout } from './AppLayout'

/**
 * 화면 틀과 실시간 통보(#43): 붙은 콘솔 표시 · 세션이 끝난 탭의 1008 → 로그인.
 * API 클라이언트는 401 이동을 한 번만 하므로(모듈 안 상태) 다른 401 시험과 파일을 나눈다.
 */

/** 서버 없이 여닫을 수 있는 가짜 WebSocket. 만든 순서대로 instances 에 남는다 */
class FakeSocket extends EventTarget {
  static instances: FakeSocket[] = []
  readonly url: string
  constructor(url: string) {
    super()
    this.url = url
    FakeSocket.instances.push(this)
  }
  close() {}
  static last(): FakeSocket {
    return FakeSocket.instances[FakeSocket.instances.length - 1]
  }
}

const open = () => act(() => void FakeSocket.last().dispatchEvent(new Event('open')))
const hello = (name: unknown) =>
  act(() => void FakeSocket.last().dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ type: 'hello', data: { channel: 'opsloop_incident', console: name } }) })))
const drop = (code: number) => act(() => void FakeSocket.last().dispatchEvent(Object.assign(new Event('close'), { code })))

function layoutRoutes(): RouteObject[] {
  return [
    {
      path: '/',
      element: <AppLayout groups={NAV_GROUPS} />,
      children: [
        { index: true, element: <p>대시보드 본문</p> },
        { path: 'incidents', element: <p>인시던트 본문</p> },
      ],
    },
  ]
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

describe('AppLayout · 실시간 통보(#43)', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    FakeSocket.instances = []
  })

  it('hello 의 콘솔을 상단바에 콘솔 A 로 보이고, 끊기면 흐리게 남기며, 콘솔 B 로 이어지면 바뀐다', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    stubMe({ username: 'han', role: 'operator', console: 'opsloop-console-b' })
    renderRoutes(layoutRoutes(), '/')
    await screen.findByText('대시보드 본문')
    const banner = screen.getByRole('banner')
    const tag = () => banner.querySelector('[data-console]')

    open()
    expect(tag()).toBeNull()
    hello('opsloop-console-a')
    expect(within(banner).getByText('실시간 수신 중')).toBeInTheDocument()
    expect(tag()).toHaveTextContent('콘솔 A')
    expect(tag()).not.toHaveAttribute('data-stale')

    vi.useFakeTimers()
    drop(1006)
    expect(within(banner).getByText('실시간 끊김 · 다시 연결 중')).toBeInTheDocument()
    expect(tag()).toHaveTextContent('콘솔 A')
    expect(tag()).toHaveAttribute('data-stale', 'true')

    act(() => void vi.advanceTimersByTime(1_000))
    expect(FakeSocket.instances).toHaveLength(2)
    open()
    expect(tag()).toBeNull()
    hello('opsloop-console-b')
    expect(within(banner).getByText('실시간 수신 중')).toBeInTheDocument()
    expect(tag()).toHaveTextContent('콘솔 B')
    expect(tag()).not.toHaveAttribute('data-stale')
  })

  it('세션이 끝난 탭: 웹소켓이 받은 뒤 1008 로 닫히면 다시 잇지 않고 /api/me 를 다시 물어 401 이면 로그인으로 보낸다', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    const assign = vi.fn<(url: string | URL) => void>()
    vi.stubGlobal('location', {
      assign,
      pathname: '/incidents',
      search: '',
      href: 'http://localhost/incidents',
      protocol: 'http:',
      host: 'localhost',
    })
    let sessionAlive = true
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.startsWith('/api/me')) return sessionAlive ? json({ username: 'han', role: 'operator' }, 200) : json({ detail: '인증이 필요합니다' }, 401)
      return json({ detail: '없는 경로' }, 404)
    })
    vi.stubGlobal('fetch', fetch)
    const meCalls = () => fetch.mock.calls.filter(([input]) => String(input).startsWith('/api/me')).length

    renderRoutes(layoutRoutes(), '/incidents')
    await screen.findByText('인시던트 본문')
    expect(meCalls()).toBe(1)
    expect(FakeSocket.last().url).toBe('ws://localhost/ws')

    // 세션이 끝났다. 서버는 연결을 받은 뒤(open) 1008 로 닫는다
    sessionAlive = false
    open()
    drop(1008)

    const banner = screen.getByRole('banner')
    expect(within(banner).getByText('실시간 끊김 · 다시 로그인 필요')).toBeInTheDocument()
    await waitFor(() => expect(assign).toHaveBeenCalledTimes(1))
    expect(assign).toHaveBeenCalledWith('/login?next=%2Fincidents')
    expect(meCalls()).toBe(2)
    expect(await screen.findByRole('heading', { level: 1, name: '다시 로그인해 주세요' })).toBeInTheDocument()
    expect(screen.queryByText('인시던트 본문')).toBeNull()
    // 다시 잇지 않는다(403 · 1006 재연결 되풀이가 없다)
    expect(FakeSocket.instances).toHaveLength(1)
  })

  it('재접속 때 /api/me 다시 묻기가 5xx 로 실패해도(콘솔 전환 중) 본문을 지우지 않는다', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    let meStatus = 200
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.startsWith('/api/me')) return meStatus === 200 ? json({ username: 'han', role: 'operator' }, 200) : json({ detail: '콘솔이 응답하지 않습니다' }, meStatus)
      return json({ detail: '없는 경로' }, 404)
    })
    vi.stubGlobal('fetch', fetch)
    const meCalls = () => fetch.mock.calls.filter(([input]) => String(input).startsWith('/api/me')).length

    const client = noRetryClient()
    renderRoutes(layoutRoutes(), '/', client)
    await screen.findByText('대시보드 본문')
    open()

    vi.useFakeTimers()
    drop(1006)
    meStatus = 503
    act(() => void vi.advanceTimersByTime(1_000))
    open()
    vi.useRealTimers()

    await waitFor(() => expect(client.getQueryState(['me'])?.status).toBe('error'))
    expect(meCalls()).toBe(2)
    expect(within(screen.getByRole('complementary', { name: '사이드바' })).getByText('han')).toBeInTheDocument()
    expect(screen.getByText('대시보드 본문')).toBeInTheDocument()
    expect(screen.queryByText('로그인 정보를 확인하지 못했습니다')).toBeNull()
    expect(screen.queryByRole('heading', { name: '다시 로그인해 주세요' })).toBeNull()
  })
})
