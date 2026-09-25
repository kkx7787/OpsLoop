import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { ctiKeys } from './cti'
import { incidentKeys, ruleKeys } from './incidents'
import { nodeKey, auditKey } from './operations'
import { monitoringKeys } from './monitoring-keys'
import {
  applyLiveMessage,
  backoffMs,
  connectLive,
  consoleLabel,
  helloConsole,
  parseLiveMessage,
  RESYNC_KEYS,
  useLiveUpdates,
  wsUrl,
  type LiveSocket,
  type LiveState,
} from './live'

/** 재접속 · resync 때 다시 받는 쿼리 전부. /api/me 는 세션이 끝났으면 로그인으로 보내려고 넣는다 */
const ALL_KEYS = [incidentKeys.all, ruleKeys.all, monitoringKeys.summary, monitoringKeys.blocklist, nodeKey, auditKey, ctiKeys.all, ['me']]

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

  it('incident.created 는 목록과 요약을 무효화한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'incident.created', data: { incident_key: KEY, severity: 'critical' } })
    expect(invalidate).toHaveBeenCalledTimes(2)
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

  it('action.created 는 상세 · 목록 · 요약 · 차단을 무효화한다. 키가 없으면 상세는 제외한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'action.created', data: { incident_key: KEY, action: 'block_ip' } })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.detail(KEY) })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ruleKeys.quality() })

    invalidate.mockClear()
    applyLiveMessage(client, { type: 'action.created' })
    expect(invalidate).toHaveBeenCalledTimes(4)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
  })

  it('hello 와 모르는 종류는 아무것도 하지 않는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'hello', data: { channel: 'opsloop_incident', console: 'opsloop-console-a' } })
    applyLiveMessage(client, { type: 'whatever' })
    expect(invalidate).not.toHaveBeenCalled()
  })

  it('resync 는 재접속 때와 같이 사건 · 규칙 · 지표 · 차단 · 노드 · 감사 · CVE 연계 · /api/me 를 전부 다시 조회한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'resync' })
    expect(RESYNC_KEYS).toEqual(ALL_KEYS)
    expect(invalidate).toHaveBeenCalledTimes(ALL_KEYS.length)
    for (const queryKey of ALL_KEYS) expect(invalidate).toHaveBeenCalledWith({ queryKey })
  })

  it('키가 빠진 판정 통보(서버가 8000 바이트를 넘겨 뺐다)는 목록만 다시 받는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    applyLiveMessage(client, { type: 'verdict.created', data: { id: 7 } })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    const keys = invalidate.mock.calls.map(([arg]) => arg?.queryKey)
    expect(keys.some((k) => Array.isArray(k) && k[1] === incidentKeys.details()[1])).toBe(false)
  })
})

describe('consoleLabel · helloConsole', () => {
  it('opsloop-console-a · b 만 콘솔 A · B 로 바꾸고 그 밖은 null(원문을 그린다)', () => {
    expect(consoleLabel('opsloop-console-a')).toBe('콘솔 A')
    expect(consoleLabel('opsloop-console-b')).toBe('콘솔 B')
    for (const other of ['opsloop-console-c', 'OPSLOOP-CONSOLE-A', 'console-a', ' opsloop-console-a', 'opsloop-console-a\u202e', '3f2a9c1b7d4e', '']) {
      expect(consoleLabel(other)).toBeNull()
    }
  })

  it('hello 의 data.console 이 비지 않은 문자열일 때만 이름으로 본다', () => {
    expect(helloConsole({ type: 'hello', data: { channel: 'c', console: 'opsloop-console-b' } })).toBe('opsloop-console-b')
    expect(helloConsole({ type: 'hello', data: { channel: 'c' } })).toBeUndefined()
    expect(helloConsole({ type: 'hello', data: { console: '' } })).toBeUndefined()
    expect(helloConsole({ type: 'hello', data: { console: 42 } })).toBeUndefined()
    expect(helloConsole({ type: 'hello', data: { console: { name: 'a' } } })).toBeUndefined()
    expect(helloConsole({ type: 'hello' })).toBeUndefined()
    expect(helloConsole({ type: 'incident.created', data: { console: 'opsloop-console-a' } })).toBeUndefined()
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
    expect(invalidate).toHaveBeenCalledTimes(2)

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

  it('재접속하면 끊긴 동안의 사건·판정·차단 · CVE 연계와 /api/me 를 다시 조회한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory })
    FakeSocket.last().open()
    expect(invalidate).not.toHaveBeenCalled()
    FakeSocket.last().drop()
    vi.advanceTimersByTime(1_000)
    FakeSocket.last().open()
    expect(invalidate).toHaveBeenCalledTimes(ALL_KEYS.length)
    for (const queryKey of ALL_KEYS) expect(invalidate).toHaveBeenCalledWith({ queryKey })
    stop()
  })

  it('서버가 resync 를 보내면(DB 통보 연결이 다시 붙음) 연결은 그대로 두고 전부 다시 조회한다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().open()
    FakeSocket.last().message({ type: 'hello', data: { channel: 'opsloop_incident', console: 'opsloop-console-a' } })
    const count = states.length
    FakeSocket.last().message({ type: 'resync' })
    expect(invalidate).toHaveBeenCalledTimes(ALL_KEYS.length)
    for (const queryKey of ALL_KEYS) expect(invalidate).toHaveBeenCalledWith({ queryKey })
    expect(states).toHaveLength(count)
    expect(FakeSocket.instances).toHaveLength(1)
    expect(FakeSocket.last().closed).toEqual([])
    stop()
  })

  it('hello 의 콘솔 이름을 상태에 싣고, 끊기면 남겨 두며, 다시 열리면 지웠다가 새 hello 로 바꾼다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().open()
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0 })

    FakeSocket.last().message({ type: 'hello', data: { channel: 'opsloop_incident', console: 'opsloop-console-a' } })
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0, console: 'opsloop-console-a' })
    expect(invalidate).not.toHaveBeenCalled()

    // 콘솔 A 가 죽었다: 다시 연결하는 동안 마지막 이름을 남긴다(화면은 흐리게)
    FakeSocket.last().drop()
    expect(states.at(-1)).toStrictEqual({ status: 'reconnecting', retries: 0, console: 'opsloop-console-a' })

    // 콘솔 B 로 이어졌다: 열리면 이름을 비우고, hello 로 채운다
    vi.advanceTimersByTime(1_000)
    FakeSocket.last().open()
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0 })
    FakeSocket.last().message({ type: 'hello', data: { channel: 'opsloop_incident', console: 'opsloop-console-b' } })
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0, console: 'opsloop-console-b' })

    // 이름이 문자열이 아니면 없는 것으로 본다(옛 서버 · 틀린 값)
    FakeSocket.last().message({ type: 'hello', data: { channel: 'opsloop_incident', console: 7 } })
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0 })
    stop()
  })

  it('옛 소켓이 늦게 보낸 hello 는 새 연결의 콘솔 이름을 덮지 않는다', () => {
    const client = noRetryClient()
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    const first = FakeSocket.last()
    first.open()
    first.drop()
    vi.advanceTimersByTime(1_000)
    FakeSocket.last().open()
    FakeSocket.last().message({ type: 'hello', data: { console: 'opsloop-console-b' } })
    first.message({ type: 'hello', data: { console: 'opsloop-console-a' } })
    expect(states.at(-1)).toStrictEqual({ status: 'connected', retries: 0, console: 'opsloop-console-b' })
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

  it('서버가 세션 없음(1008)으로 닫으면 다시 잇지 않고 /api/me 를 다시 묻는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().drop(1008)
    expect(states.at(-1)).toEqual({ status: 'closed', retries: 0 })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['me'] })
    vi.advanceTimersByTime(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
    stop()
  })

  it('서버가 연결을 받은 뒤 1008 로 닫아도(#43 이후의 서버) 다시 잇지 않고 /api/me 를 다시 묻는다', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().open()
    expect(states.at(-1)).toEqual({ status: 'connected', retries: 0 })
    FakeSocket.last().drop(1008)
    expect(states.map((s) => s.status)).toEqual(['connecting', 'connected', 'closed'])
    expect(invalidate).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['me'] })
    vi.advanceTimersByTime(60_000)
    expect(FakeSocket.instances).toHaveLength(1)
    stop()
  })

  it('세션이 끝난 탭: 끊겼다 다시 이으려는데 받아 준 뒤 1008 이 오면 거기서 멈춘다(재연결을 되풀이하지 않는다)', () => {
    const client = noRetryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const states: LiveState[] = []
    const stop = connectLive(client, { url: 'ws://t/ws', socket: factory, onState: (s) => states.push(s) })
    FakeSocket.last().open()
    FakeSocket.last().message({ type: 'hello', data: { console: 'opsloop-console-a' } })
    FakeSocket.last().drop()
    vi.advanceTimersByTime(1_000)
    FakeSocket.last().open()
    // 다시 열리면 전부 다시 조회한다. RESYNC_KEYS 의 끝이 ['me'] 라 마지막 호출만 보면 1008 의 다시 묻기와 가려지지 않는다
    expect(invalidate).toHaveBeenCalledTimes(ALL_KEYS.length)
    FakeSocket.last().drop(1008)
    expect(states.at(-1)).toStrictEqual({ status: 'closed', retries: 0 })
    // 1008 이 /api/me 를 한 번 더 묻는다
    expect(invalidate).toHaveBeenCalledTimes(ALL_KEYS.length + 1)
    expect(invalidate).toHaveBeenLastCalledWith({ queryKey: ['me'] })
    vi.advanceTimersByTime(120_000)
    expect(FakeSocket.instances).toHaveLength(2)
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
