import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Incident } from '@/api/incidents'
import { NAV_GROUPS } from '@/app/nav'
import { controlHealth } from '@/test/monitoring-fixtures'
import { noRetryClient, renderRoutes, stubMe } from '@/test/render'
import { DECOY, device } from '@/test/targets-fixtures'
import { AppLayout } from './AppLayout'

/**
 * 화면 틀과 실시간 통보(#43): 붙은 콘솔 표시 · 세션이 끝난 탭의 1008 → 로그인 · 새 사건 알림과 탭 제목(#72).
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
const send = (payload: unknown) => act(() => void FakeSocket.last().dispatchEvent(new MessageEvent('message', { data: JSON.stringify(payload) })))

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
    expect(within(banner).getByText('실시간 통보 연결')).toBeInTheDocument()
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
    expect(within(banner).getByText('실시간 통보 연결')).toBeInTheDocument()
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

  it('incident.created 로 보호 대상 확인 사건 알림과 탭 제목 수가 생긴다. 재접속 · resync 뒤 중복이 없고, 대체 추정만 있는 사건은 뜨지 않는다', async () => {
    vi.stubGlobal('WebSocket', FakeSocket)
    document.title = 'OpsLoop 관제'
    const incident = (key: string, extra: Partial<Incident>): Incident => ({
      incident_key: key,
      rule_id: 'R102',
      rule_version: 'w2',
      rule_name: '웹 경로 탐색',
      severity: 'high',
      actor_ip: '198.51.100.20',
      target: null,
      first_ts: '2026-09-30T00:00:00+00:00',
      last_ts: '2026-09-30T00:01:00+00:00',
      signal_count: 4,
      session_count: 0,
      status: 'open',
      created_at: '2026-09-30T00:01:05+00:00',
      verdict: null,
      pending_seconds: 60,
      ...extra,
    })
    const web = incident('R102|w2|198.51.100.20|2026-09-30T00:00:00+00:00', { devices: [DECOY, device()], device_state: 'confirmed', device_fallback: [] })
    const guess = incident('R005|v3|-|2026-09-30T00:00:00+00:00', {
      rule_id: 'R005',
      actor_ip: null,
      devices: [],
      device_state: 'unconfirmed',
      device_fallback: [device({ id: 'aws-sensor', part: 'cowrie', label: 'Cowrie', group: 'sensor', logs: ['SSH 세션'], basis: 'fallback' })],
    })
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/me') return json({ username: 'han', role: 'operator' }, 200)
      if (url.pathname === '/api/dashboard/monitor') return json(controlHealth(), 200)
      if (url.pathname === '/api/incidents') return json({ total: 2, limit: 50, offset: 0, items: [web, guess] }, 200)
      return json({ detail: '없는 경로' }, 404)
    })
    vi.stubGlobal('fetch', fetch)
    const listCalls = () => fetch.mock.calls.filter(([input]) => String(input).startsWith('/api/incidents?')).length
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' })

    try {
      const { unmount } = renderRoutes(layoutRoutes(), '/', noRetryClient())
      await screen.findByText('대시보드 본문')
      expect(screen.queryByRole('region', { name: '새 사건 알림' })).toBeNull()
      open()

      vi.useFakeTimers()
      send({ type: 'incident.created', data: { incident_key: web.incident_key, rule_name: '통보 글' } })
      send({ type: 'incident.created', data: { incident_key: guess.incident_key } })
      await act(() => vi.advanceTimersByTimeAsync(2_000))
      vi.useRealTimers()

      const region = await screen.findByRole('region', { name: '새 사건 알림' })
      expect(listCalls()).toBe(1)
      const cards = within(region).getAllByRole('listitem')
      expect(cards).toHaveLength(1)
      expect(cards[0]).toHaveTextContent('웹 경로 탐색')
      expect(cards[0]).not.toHaveTextContent('통보 글')
      expect(cards[0].querySelector('[data-device="web-01"]')).not.toBeNull()
      expect(region).not.toHaveTextContent('R005')
      expect(document.title).toBe('(1) OpsLoop 관제')

      // resync · 재접속 뒤 같은 키가 다시 와도 새로 확인하거나 띄우지 않는다
      vi.useFakeTimers()
      send({ type: 'resync' })
      drop(1006)
      act(() => void vi.advanceTimersByTime(1_000))
      open()
      send({ type: 'incident.created', data: { incident_key: web.incident_key } })
      send({ type: 'incident.created', data: { incident_key: guess.incident_key } })
      await act(() => vi.advanceTimersByTimeAsync(10_000))
      vi.useRealTimers()
      expect(listCalls()).toBe(1)
      expect(within(screen.getByRole('region', { name: '새 사건 알림' })).getAllByRole('listitem')).toHaveLength(1)
      expect(document.title).toBe('(1) OpsLoop 관제')

      // 다시 보이면 탭 제목 수는 0 이다
      Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
      act(() => void document.dispatchEvent(new Event('visibilitychange')))
      expect(document.title).toBe('OpsLoop 관제')

      // 닫기
      fireEvent.click(within(screen.getByRole('region', { name: '새 사건 알림' })).getByRole('button', { name: '알림 닫기' }))
      expect(screen.queryByRole('region', { name: '새 사건 알림' })).toBeNull()
      unmount()
      expect(document.title).toBe('OpsLoop 관제')
    } finally {
      Reflect.deleteProperty(document, 'visibilityState')
      document.title = ''
    }
  })
})
