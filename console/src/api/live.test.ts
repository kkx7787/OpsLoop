import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { incidentKeys, ruleKeys } from './incidents'
import { applyLiveMessage, backoffMs, connectLive, parseLiveMessage, useLiveUpdates, wsUrl, type LiveSocket, type LiveState } from './live'

/** 서버 없이 여닫을 수 있는 가짜 WebSocket. 만들어진 순서대로 instances 에 남는다 */
class FakeSocket extends EventTarget implements LiveSocket {
  static instances: FakeSocket[] = []
  closed: number[] = []
  readonly url: string

  constructor(url: string) {
    super()
    this.url = url
    FakeSocket.instances.push(this)
  }

  open() {
    this.dispatchEvent(new Event('open'))
  }

  message(payload: unknown) {
    this.dispatchEvent(new MessageEvent('message', { data: typeof payload === 'string' ? payload : JSON.stringify(payload) }))
  }

  drop(code = 1006) {
    this.dispatchEvent(Object.assign(new Event('close'), { code }))
  }

  close(code = 1000) {
    this.closed.push(code)
  }

  static last(): FakeSocket {
    return FakeSocket.instances[FakeSocket.instances.length - 1]
  }
}

const factory = (url: string) => new FakeSocket(url)

describe('wsUrl · backoffMs · parseLiveMessage', () => {
  it('같은 출처의 /ws, https 는 wss', () => {
    expect(wsUrl({ protocol: 'http:', host: 'localhost:5173' })).toBe('ws://localhost:5173/ws')
    expect(wsUrl({ protocol: 'https:', host: 'console.example' })).toBe('wss://console.example/ws')
  })

  it('1초에서 두 배씩 늘다가 30초에서 멈춘다', () => {
    expect([0, 1, 2, 3, 4, 5, 9].map((n) => backoffMs(n))).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000])
    expect(backoffMs(-1)).toBe(1_000)
  })

  it('type 이 문자열인 JSON 객체만 통보로 본다', () => {
    expect(parseLiveMessage('{"type":"hello","data":{"channel":"opsloop_incident"}}')).toEqual({ type: 'hello', data: { channel: 'opsloop_incident' } })
    expect(parseLiveMessage('{"type":"x"}')).toEqual({ type: 'x', data: undefined })
    expect(parseLiveMessage('{"data":{}}')).toBeNull()
    expect(parseLiveMessage('not json')).toBeNull()
    expect(parseLiveMessage(new Blob())).toBeNull()
  })
})

describe('applyLiveMessage', () => {
  const KEY = 'R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00'

  it('incident.created 는 목록만 무효화한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'incident.created', data: { incident_key: KEY, severity: 'critical' } })
    expect(invalidate).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
  })

  it('verdict.created 는 그 사건의 상세 · 목록 · 규칙 품질을 무효화한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'verdict.created', data: { incident_key: KEY, verdict: 'threat' } })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.detail(KEY) })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ruleKeys.quality() })
  })

  it('action.created 는 상세 · 목록을 무효화한다. 키가 없으면 목록만', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'action.created', data: { incident_key: KEY, action: 'block_ip' } })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.detail(KEY) })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ruleKeys.quality() })

    invalidate.mockClear()
    applyLiveMessage(client, { type: 'action.created' })
    expect(invalidate).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
  })

  it('hello 와 모르는 종류는 아무것도 하지 않는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'hello', data: { channel: 'opsloop_incident' } })
    applyLiveMessage(client, { type: 'whatever' })
    expect(invalidate).not.toHaveBeenCalled()
  })
})

describe('connectLive', () => {
  beforeEach(() => {
    FakeSocket.instances = []
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('열리면 connected, 통보가 오면 무효화한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })

    expect(FakeSocket.instances).toHaveLength(1)
    expect(FakeSocket.last().url).toBe('ws://t/ws')
    expect(states).toEqual([{ status: 'connecting', retries: 0 }])

    FakeSocket.last().open()
    expect(states.at(-1)).toEqual({ status: 'connected', retries: 0 })

    FakeSocket.last().message({ type: 'hello', data: {} })
    expect(invalidate).not.toHaveBeenCalled()
    FakeSocket.last().message({ type: 'incident.created', data: { incident_key: 'k' } })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    FakeSocket.last().message('깨진 JSON')
    expect(invalidate).toHaveBeenCalledTimes(1)

    stop()
  })

  it('끊기면 지수 백오프로 다시 잇고, 이어지면 횟수가 0 으로 돌아간다', () => {
    const client = noRetryClient()
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().open()

    FakeSocket.last().drop()
    expect(states.at(-1)).toEqual({ status: 'reconnecting', retries: 0 })
    expect(FakeSocket.instances).toHaveLength(1)

    vi.advanceTimersByTime(999)
    expect(FakeSocket.instances).toHaveLength(1)
    vi.advanceTimersByTime(1)
    expect(FakeSocket.instances).toHaveLength(2)

    // 두 번째도 실패: 2초 뒤에 세 번째
    FakeSocket.last().drop()
    expect(states.at(-1)).toEqual({ status: 'reconnecting', retries: 1 })
    vi.advanceTimersByTime(2_000)
    expect(FakeSocket.instances).toHaveLength(3)

    // 세 번째도 실패: 4초
    FakeSocket.last().drop()
    vi.advanceTimersByTime(4_000)
    expect(FakeSocket.instances).toHaveLength(4)

    FakeSocket.last().open()
    expect(states.at(-1)).toEqual({ status: 'connected', retries: 0 })

    // 다시 끊기면 1초부터 시작한다
    FakeSocket.last().drop()
    vi.advanceTimersByTime(1_000)
    expect(FakeSocket.instances).toHaveLength(5)
    stop()
  })

  it('대기는 30초를 넘지 않는다', () => {
    const client = noRetryClient()
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory })
    for (let i = 0; i < 6; i += 1) {
      FakeSocket.last().drop()
      vi.advanceTimersByTime(30_000)
    }
    const before = FakeSocket.instances.length
    FakeSocket.last().drop()
    vi.advanceTimersByTime(29_999)
    expect(FakeSocket.instances).toHaveLength(before)
    vi.advanceTimersByTime(1)
    expect(FakeSocket.instances).toHaveLength(before + 1)
    stop()
  })

  it('서버가 세션 없음(1008)으로 닫으면 다시 잇지 않는다', () => {
    const client = noRetryClient()
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().drop(1008)
    expect(states.at(-1)).toEqual({ status: 'closed', retries: 0 })
    vi.advanceTimersByTime(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
    stop()
  })

  it('멈추면 소켓을 닫고 타이머를 지우며, 늦게 온 close 로 다시 잇지 않는다', () => {
    const client = noRetryClient()
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    const first = FakeSocket.last()
    first.open()

    stop()
    expect(first.closed).toEqual([1000])
    const count = states.length
    first.drop()
    vi.advanceTimersByTime(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
    expect(states).toHaveLength(count)
  })

  it('기다리는 중에 멈추면 다시 잇지 않는다', () => {
    const client = noRetryClient()
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory })
    FakeSocket.last().drop()
    stop()
    vi.advanceTimersByTime(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
  })
})

describe('useLiveUpdates', () => {
  beforeEach(() => {
    FakeSocket.instances = []
  })

  it('한 번 잇고 상태를 돌려주며, 내려가면 닫는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
    const { result, rerender, unmount } = renderHook(() => useLiveUpdates({ url: 'ws://t/ws', socket: factory }), { wrapper })

    expect(result.current).toEqual({ status: 'connecting', retries: 0 })
    expect(FakeSocket.instances).toHaveLength(1)

    act(() => FakeSocket.last().open())
    expect(result.current).toEqual({ status: 'connected', retries: 0 })

    rerender()
    expect(FakeSocket.instances).toHaveLength(1)

    act(() => FakeSocket.last().message({ type: 'verdict.created', data: { incident_key: 'k' } }))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.detail('k') })

    unmount()
    expect(FakeSocket.last().closed).toEqual([1000])
  })
})
