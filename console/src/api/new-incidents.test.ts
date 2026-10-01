import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { COWRIE, DECOY, device } from '@/test/targets-fixtures'
import { ApiError } from './errors'
import { incidentKeys, type Incident, type IncidentBase, type IncidentDevice, type IncidentPage } from './incidents'
import type { LiveMessage } from './live'
import {
  createNewIncidentWatcher,
  GROUP_MS,
  incidentKeyOf,
  KEY_MAX,
  MAX_TOASTS,
  SEEN_LIMIT,
  toastHref,
  useNewIncidentToasts,
  type NewIncidentToast,
  type WatcherDeps,
} from './new-incidents'

// ---------------------------------------------------------------- 표본

const WEB01 = device()
const WEB01_SCOPE = device({ basis: 'rule_scope' })
const WEB01_FALLBACK = device({ basis: 'fallback' })
const WEB02 = device({ id: 'web-02', label: 'web02.lab', logs: ['SSH 인증'] })

function incident(key: string, extra: Partial<Incident> = {}): Incident {
  return {
    incident_key: key,
    rule_id: 'R101',
    rule_version: 'w2',
    rule_name: 'SSH 무차별 대입',
    severity: 'medium',
    actor_ip: '198.51.100.7',
    target: null,
    first_ts: '2026-09-30T00:00:00+00:00',
    last_ts: '2026-09-30T00:01:00+00:00',
    signal_count: 5,
    session_count: 0,
    status: 'open',
    created_at: '2026-09-30T00:01:05+00:00',
    verdict: null,
    pending_seconds: 60,
    devices: [WEB01],
    device_state: 'confirmed',
    device_fallback: [],
    ...extra,
  }
}

const created = (key: unknown, data: Record<string, unknown> = {}): LiveMessage => ({ type: 'incident.created', data: { incident_key: key, ...data } })

/** 비동기 확인(목록 → 상세 → 띄우기)이 끝나도록 마이크로태스크를 비운다 */
async function flush() {
  for (let i = 0; i < 20; i += 1) await Promise.resolve()
}

async function tick(ms: number) {
  await vi.advanceTimersByTimeAsync(ms)
  await flush()
}

function http(status: number): ApiError {
  return new ApiError({ status, detail: `HTTP ${status}` })
}

interface Setup {
  list?: Incident[] | (() => Promise<Pick<IncidentPage, 'items'>>)
  detail?: (key: string) => Promise<IncidentBase>
  seen?: Map<string, true>
}

function setup({ list = [], detail, seen }: Setup = {}) {
  const changes: NewIncidentToast[][] = []
  const shown: number[] = []
  const fetchList = vi.fn<WatcherDeps['fetchList']>(async () => (typeof list === 'function' ? list() : { items: list }))
  const fetchDetail = vi.fn<WatcherDeps['fetchDetail']>(async (key) => {
    if (!detail) throw http(404)
    return detail(key)
  })
  const watcher = createNewIncidentWatcher({ fetchList, fetchDetail, onChange: (t) => changes.push(t), onShown: (n) => shown.push(n), seen })
  const toasts = () => changes.at(-1) ?? []
  return { watcher, fetchList, fetchDetail, changes, shown, toasts }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(Date.parse('2026-09-30T00:02:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------- 받기

describe('incidentKeyOf', () => {
  it('incident.created 의 1~1024자 문자열 키만 받는다', () => {
    expect(incidentKeyOf(created('k'))).toBe('k')
    expect(incidentKeyOf(created('x'.repeat(KEY_MAX)))).toBe('x'.repeat(KEY_MAX))
    for (const bad of ['', 'x'.repeat(KEY_MAX + 1), 42, null, undefined, { key: 'k' }, ['k']]) {
      expect(incidentKeyOf(created(bad))).toBeNull()
    }
    expect(incidentKeyOf({ type: 'verdict.created', data: { incident_key: 'k' } })).toBeNull()
    expect(incidentKeyOf({ type: 'resync' })).toBeNull()
    expect(incidentKeyOf({ type: 'incident.created' })).toBeNull()
  })
})

// ---------------------------------------------------------------- 거르기

describe('보호 대상 확인만 띄운다', () => {
  it('확인된 보호 대상(web-01 · 등록 노드)만 뜨고, 규칙 범위 · 대체 추정 · 센서만 · devices 없음은 띄우지 않고 본 것으로 둔다', async () => {
    const items = [
      incident('web', { devices: [DECOY, WEB01], actor_ip: '198.51.100.1' }),
      incident('node', { rule_id: 'R301', actor_ip: null, target: 'node:web-02', devices: [WEB02] }),
      incident('scope', { actor_ip: '198.51.100.3', devices: [WEB01_SCOPE], device_state: 'rule_scope' }),
      incident('scope+decoy', { actor_ip: '198.51.100.4', devices: [WEB01_SCOPE, DECOY], device_state: 'confirmed' }),
      incident('fallback', { actor_ip: '198.51.100.5', devices: [], device_state: 'unconfirmed', device_fallback: [WEB01_FALLBACK] }),
      incident('fallback-in-devices', { actor_ip: '198.51.100.6', devices: [WEB01_FALLBACK] }),
      incident('sensor', { rule_id: 'R002', actor_ip: '198.51.100.7', devices: [COWRIE, DECOY] }),
      incident('old', { actor_ip: '198.51.100.8', devices: undefined, device_state: undefined, device_fallback: undefined }),
    ]
    const { watcher, fetchList, fetchDetail, toasts, shown } = setup({ list: items })
    for (const item of items) watcher.receive(created(item.incident_key))
    await tick(2_000)

    expect(fetchList).toHaveBeenCalledTimes(1)
    expect(fetchDetail).not.toHaveBeenCalled()
    expect(toasts().map((t) => t.id)).toEqual(['node', 'web'])
    expect(shown).toEqual([2])

    // 띄우지 않은 것도 본 것이다: 다시 와도 확인하지 않는다
    for (const item of items) watcher.receive(created(item.incident_key))
    await tick(10_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------- 모으기 · 확인

describe('모으기 · 확인', () => {
  it('마지막 통보 2초 뒤에 한 번 확인한다(여러 키도 목록 조회 한 번)', async () => {
    const { watcher, fetchList } = setup({ list: [incident('a'), incident('b')] })
    watcher.receive(created('a'))
    await tick(1_500)
    watcher.receive(created('b'))
    await tick(1_999)
    expect(fetchList).not.toHaveBeenCalled()
    await tick(1)
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it('통보가 계속 와도 첫 통보 5초 안에는 확인한다', async () => {
    const { watcher, fetchList } = setup()
    for (let i = 0; i < 4; i += 1) {
      if (i > 0) await tick(1_500)
      watcher.receive(created(`k${i}`))
    }
    // 0 · 1.5 · 3 · 4.5 초에 받음 → 마지막 뒤 2초(6.5초)가 아니라 5초에 확인
    expect(fetchList).toHaveBeenCalledTimes(0)
    await tick(499)
    expect(fetchList).toHaveBeenCalledTimes(0)
    await tick(1)
    expect(fetchList).toHaveBeenCalledTimes(1)
  })

  it('목록은 최근순 한 번, 목록에 없는 키는 3건까지 상세로 받는다. 목록 밖 5건이면 두 회차에 걸쳐 모두 확인한다', async () => {
    const keys = ['k1', 'k2', 'k3', 'k4', 'k5']
    const { watcher, fetchList, fetchDetail, toasts, shown } = setup({ list: [], detail: async (key) => incident(key) })
    for (const key of keys) watcher.receive(created(key))

    await tick(2_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
    expect(fetchDetail.mock.calls.map(([key]) => key)).toEqual(['k1', 'k2', 'k3'])
    // 같은 규칙 · 출발지라 한 장에 묶인다
    expect(toasts()).toHaveLength(1)
    expect(toasts()[0].keys).toEqual(['k1', 'k2', 'k3'])

    // 넘긴 두 건은 다음 회차(2초 뒤)에 확인한다
    await tick(1_999)
    expect(fetchList).toHaveBeenCalledTimes(1)
    await tick(1)
    expect(fetchList).toHaveBeenCalledTimes(2)
    expect(fetchDetail.mock.calls.map(([key]) => key)).toEqual(['k1', 'k2', 'k3', 'k4', 'k5'])
    expect(toasts()[0].keys).toEqual(keys)
    expect(shown).toEqual([3, 2])

    // 다 확인했으니 더 묻지 않는다
    await tick(30_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
  })

  it('상한을 넘은 키는 두 회차까지만 본다(그 뒤 본 것)', async () => {
    const keys = Array.from({ length: 8 }, (_, i) => `k${i}`)
    const { watcher, fetchList, fetchDetail } = setup({ list: [], detail: async (key) => incident(key) })
    for (const key of keys) watcher.receive(created(key))
    await tick(2_000)
    await tick(2_000)
    await tick(30_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
    // 회차마다 3건: 여섯 건만 확인하고 나머지 둘은 두 회차를 넘겨 본 것이 된다
    expect(fetchDetail.mock.calls.map(([key]) => key)).toEqual(['k0', 'k1', 'k2', 'k3', 'k4', 'k5'])
    watcher.receive(created('k6'))
    watcher.receive(created('k7'))
    await tick(30_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
  })

  it('상세 5xx 는 다음 회차에 다시 보고, 두 번 실패하면 띄우지 않고 본 것으로 둔다. 404 는 바로 본 것이다', async () => {
    const { watcher, fetchList, fetchDetail, changes } = setup({
      list: [],
      detail: async (key) => {
        throw http(key === 'gone' ? 404 : 503)
      },
    })
    watcher.receive(created('busy'))
    watcher.receive(created('gone'))
    await tick(2_000)
    expect(fetchDetail.mock.calls.map(([key]) => key)).toEqual(['busy', 'gone'])
    await tick(2_000)
    expect(fetchDetail.mock.calls.map(([key]) => key)).toEqual(['busy', 'gone', 'busy'])
    await tick(30_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
    expect(changes).toEqual([])

    watcher.receive(created('busy'))
    await tick(30_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
  })

  it('목록이 5xx 면 키를 다음 회차로 넘기고, 다음 회차에 받으면 띄운다', async () => {
    let fail = true
    const { watcher, fetchList, fetchDetail, toasts } = setup({
      list: async () => {
        if (fail) throw http(502)
        return { items: [incident('a')] }
      },
    })
    watcher.receive(created('a'))
    await tick(2_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
    expect(fetchDetail).not.toHaveBeenCalled()
    expect(toasts()).toEqual([])

    fail = false
    await tick(2_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
    expect(toasts().map((t) => t.id)).toEqual(['a'])
  })

  it('확인 중에 온 통보는 끝난 뒤 다음 회차로 확인한다(겹쳐 묻지 않는다)', async () => {
    let release: (() => void) | undefined
    const { watcher, fetchList, toasts } = setup({
      list: () =>
        new Promise((resolve) => {
          release = () => resolve({ items: [incident('a'), incident('b', { actor_ip: '198.51.100.99' })] })
        }),
    })
    watcher.receive(created('a'))
    await tick(2_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
    watcher.receive(created('b'))
    await tick(5_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
    release?.()
    await flush()
    expect(toasts().map((t) => t.id)).toEqual(['a'])
    await tick(2_000)
    expect(fetchList).toHaveBeenCalledTimes(2)
    release?.()
    await flush()
    expect(toasts().map((t) => t.id)).toEqual(['b', 'a'])
  })
})

// ---------------------------------------------------------------- 묶기

describe('묶기', () => {
  it('같은 규칙 · 출발지는 묶음을 연 때부터 60초 동안 한 장에 붙어 건수 · 장비 합집합(보호 대상 먼저)이 되고, 60초 뒤에는 새 장이다', async () => {
    const items: Record<string, Incident> = {
      k1: incident('k1', { devices: [DECOY, WEB01] }),
      k2: incident('k2', { severity: 'critical', devices: [WEB01, device({ id: 'aws-sensor', part: 'gateway', label: '허니팟 관문', group: 'sensor', logs: ['관문 기록'] }), DECOY] }),
      k3: incident('k3', { devices: [WEB02] }),
    }
    const { watcher, toasts, shown } = setup({ list: async () => ({ items: Object.values(items) }) })
    watcher.receive(created('k1'))
    await tick(2_000)
    const opened = toasts()[0]
    expect(opened).toMatchObject({ id: 'k1', keys: ['k1'], version: 0, severity: 'medium' })
    expect(toastHref(opened)).toBe(`/incidents/${encodeURIComponent('k1')}`)

    await tick(10_000)
    watcher.receive(created('k2'))
    await tick(2_000)
    expect(toasts()).toHaveLength(1)
    const merged = toasts()[0]
    expect(merged).toMatchObject({ id: 'k1', keys: ['k1', 'k2'], version: 1, severity: 'critical' })
    expect(merged.devices.map((d: IncidentDevice) => `${d.id}|${d.part ?? ''}`)).toEqual(['web-01|', 'aws-sensor|decoy', 'aws-sensor|gateway'])
    expect(toastHref(merged)).toBe('/incidents?rule_id=R101&actor_ip=198.51.100.7')

    // 묶음을 연 때(2초)부터 60초가 지나면 같은 묶음이라도 새 장이다
    await tick(GROUP_MS - 14_000)
    watcher.receive(created('k3'))
    await tick(2_000)
    expect(toasts().map((t) => t.id)).toEqual(['k3', 'k1'])
    expect(toasts()[1].keys).toEqual(['k1', 'k2'])
    expect(shown).toEqual([1, 1, 1])
  })

  it('출발지가 없는 묶음(대상 사건)은 마지막 사건 상세로 잇는다', async () => {
    const node = (key: string) => incident(key, { rule_id: 'R301', actor_ip: null, target: 'node:web-01' })
    const { watcher, toasts } = setup({ list: [node('n1'), node('n2')] })
    watcher.receive(created('n1'))
    watcher.receive(created('n2'))
    await tick(2_000)
    expect(toasts()).toHaveLength(1)
    expect(toasts()[0].group).toBe('R301|node:web-01')
    expect(toastHref(toasts()[0])).toBe(`/incidents/${encodeURIComponent('n2')}`)
  })

  it(`한꺼번에 ${MAX_TOASTS}장까지 두고(새 것 먼저), 넘으면 가장 오래된 장을 뺀다. 닫으면 목록에서 빠진다`, async () => {
    const items = ['a', 'b', 'c', 'd'].map((key, i) => incident(key, { actor_ip: `198.51.100.${i + 10}` }))
    const { watcher, toasts, changes } = setup({ list: items })
    for (const item of items) watcher.receive(created(item.incident_key))
    await tick(2_000)
    expect(toasts().map((t) => t.id)).toEqual(['d', 'c', 'b'])

    const count = changes.length
    watcher.dismiss('c')
    expect(toasts().map((t) => t.id)).toEqual(['d', 'b'])
    watcher.dismiss('nope')
    expect(changes).toHaveLength(count + 1)
  })

  it('통보 data 의 rule_name · severity 는 쓰지 않고 REST 값을 쓴다', async () => {
    const { watcher, toasts } = setup({ list: [incident('a')] })
    watcher.receive(created('a', { rule_name: '통보 글', severity: 'critical', actor_ip: '203.0.113.1' }))
    await tick(2_000)
    expect(toasts()[0]).toMatchObject({ rule_name: 'SSH 무차별 대입', severity: 'medium', actor_ip: '198.51.100.7' })
  })
})

// ---------------------------------------------------------------- 중복

describe('중복 방지', () => {
  it('같은 키 · resync · 재접속 뒤에도 다시 띄우지 않고, resync · hello 만으로는 확인하지 않는다', async () => {
    const seen = new Map<string, true>()
    const first = setup({ list: [incident('a')], seen })
    first.watcher.receive({ type: 'resync' })
    first.watcher.receive({ type: 'hello', data: { console: 'opsloop-console-a' } })
    await tick(10_000)
    expect(first.fetchList).not.toHaveBeenCalled()

    first.watcher.receive(created('a'))
    first.watcher.receive(created('a'))
    await tick(2_000)
    expect(first.fetchList).toHaveBeenCalledTimes(1)
    expect(first.toasts()[0].keys).toEqual(['a'])

    first.watcher.receive({ type: 'resync' })
    first.watcher.receive(created('a'))
    await tick(10_000)
    expect(first.fetchList).toHaveBeenCalledTimes(1)

    // 감시기를 다시 만들어도(훅 재실행) 본 키 Map 이 남아 있다
    first.watcher.stop()
    const second = setup({ list: [incident('a')], seen })
    second.watcher.receive(created('a'))
    await tick(10_000)
    expect(second.fetchList).not.toHaveBeenCalled()
  })

  it(`본 키는 ${SEEN_LIMIT}개까지 두고 오래된 것부터 지운다`, async () => {
    const seen = new Map<string, true>()
    const { watcher } = setup({ list: [], seen })
    for (let i = 0; i <= SEEN_LIMIT; i += 1) watcher.receive(created(`old-${i}`))
    await tick(2_000)
    await tick(2_000)
    expect(seen.size).toBe(SEEN_LIMIT)
    expect(seen.has('old-0')).toBe(false)
    expect(seen.has(`old-${SEEN_LIMIT}`)).toBe(true)
  })

  it('멈추면 기다리던 확인을 하지 않고, 늦게 온 응답도 띄우지 않는다', async () => {
    let release: (() => void) | undefined
    const { watcher, fetchList, changes } = setup({
      list: () =>
        new Promise((resolve) => {
          release = () => resolve({ items: [incident('a'), incident('b')] })
        }),
    })
    watcher.receive(created('a'))
    await tick(2_000)
    watcher.stop()
    release?.()
    await flush()
    expect(changes).toEqual([])
    watcher.receive(created('b'))
    await tick(10_000)
    expect(fetchList).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------- 훅

describe('useNewIncidentToasts', () => {
  function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('목록(최근순 50건)은 캐시에 넣지 않고, 목록 밖 사건만 상세 캐시 키로 받는다. 로그인 전(enabled=false)에는 받지 않는다', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/incidents') return json({ total: 1, limit: 50, offset: 0, items: [incident('in-list')] })
      if (url.pathname === `/api/incidents/${encodeURIComponent('out|1')}`) return json(incident('out|1', { actor_ip: '203.0.113.9' }))
      return json({ detail: '없는 경로' }, 404)
    })
    vi.stubGlobal('fetch', fetch)
    const client = noRetryClient()
    const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
    const onShown = vi.fn<(n: number) => void>()
    const { result, rerender } = renderHook(({ enabled }) => useNewIncidentToasts(enabled, { onShown }), { wrapper, initialProps: { enabled: false } })

    act(() => result.current.onLiveMessage(created('in-list')))
    await act(() => tick(10_000))
    expect(fetch).not.toHaveBeenCalled()

    rerender({ enabled: true })
    act(() => {
      result.current.onLiveMessage(created('in-list'))
      result.current.onLiveMessage(created('out|1'))
    })
    await act(() => tick(2_000))
    const urls = fetch.mock.calls.map(([input]) => String(input))
    expect(urls).toEqual(['/api/incidents?sort=recent&limit=50&offset=0', `/api/incidents/${encodeURIComponent('out|1')}`])
    expect(result.current.toasts.map((t) => t.id)).toEqual(['out|1', 'in-list'])
    expect(onShown).toHaveBeenCalledWith(2)
    expect(client.getQueryData(incidentKeys.detail('out|1'))).toMatchObject({ incident_key: 'out|1' })
    expect(client.getQueryCache().findAll({ queryKey: incidentKeys.lists() })).toEqual([])

    act(() => result.current.dismiss('in-list'))
    expect(result.current.toasts.map((t) => t.id)).toEqual(['out|1'])

    // 꺼지면(로그아웃) 알림을 비운다
    rerender({ enabled: false })
    expect(result.current.toasts).toEqual([])
  })
})
