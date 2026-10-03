import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { MONITOR, controlHealth, json } from '@/test/monitoring-fixtures'
import { isApiError } from './errors'
import { controlHealthView, fetchControlHealth, HEALTH_PATH, monitorItemHref, monitorItemText, opsAnomalies, useControlHealth } from './health'
import { monitoringKeys } from './monitoring-keys'

function stubFetch(route: (url: string) => Response | undefined) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    return route(url) ?? json({ detail: 'Not Found' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function wrapper(client = noRetryClient()) {
  return { client, wrapper: ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children) }
}

describe('관제 상태 API(#72)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('GET /api/dashboard/monitor 를 받아 그대로 돌려준다', async () => {
    const body = controlHealth({ items: [MONITOR.loader] })
    const fetch = stubFetch((url) => (url === '/api/dashboard/monitor' ? json(body) : undefined))
    expect(HEALTH_PATH).toBe('/api/dashboard/monitor')
    expect(await fetchControlHealth()).toEqual(body)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('items 가 목록이 아니면 이상 없음으로 꾸미지 않고 해석 오류로 던진다', async () => {
    for (const body of [{ as_of: '', detect_paths: [] }, { items: null }, [], null]) {
      stubFetch(() => json(body))
      const error = await fetchControlHealth().catch((e: unknown) => e)
      expect(isApiError(error) && error.kind).toBe('parse')
    }
  })

  it('detect_paths 가 없으면 빈 목록으로 채운다', async () => {
    stubFetch(() => json({ as_of: 'x', items: [] }))
    expect((await fetchControlHealth()).detect_paths).toEqual([])
  })

  it('404(이전 서버) · 5xx 는 그대로 넘긴다(띠 · 사이드바는 확인 불가)', async () => {
    stubFetch(() => undefined)
    expect(await fetchControlHealth().catch((e: unknown) => isApiError(e) && e.status)).toBe(404)
    stubFetch(() => json({ detail: 'DB unavailable' }, 503))
    expect(await fetchControlHealth().catch((e: unknown) => isApiError(e) && e.status)).toBe(503)
  })

  it('useControlHealth 는 대시보드 · 관제 이상 키로 받고, enabled=false 면 묻지 않는다', async () => {
    const fetch = stubFetch((url) => (url === HEALTH_PATH ? json(controlHealth()) : undefined))
    const off = wrapper()
    const idle = renderHook(() => useControlHealth(false), { wrapper: off.wrapper })
    expect(idle.result.current.isPending).toBe(true)
    expect(controlHealthView(idle.result.current)).toEqual({ state: 'pending' })
    expect(fetch).not.toHaveBeenCalled()

    const on = wrapper()
    const { result } = renderHook(() => useControlHealth(), { wrapper: on.wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(monitoringKeys.health).toEqual(['dashboard', 'monitor'])
    expect(on.client.getQueryData(monitoringKeys.health)).toEqual(controlHealth())
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('한 번도 받지 못한 채 다시 조회하는 동안에도 확인 불가다(react-query 가 pending 으로 되돌려도 조회 전으로 바뀌지 않는다)', async () => {
    let calls = 0
    let hold: ((response: Response) => void) | undefined
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async () => {
      calls += 1
      if (calls === 1) return json({ detail: 'DB unavailable' }, 503)
      return new Promise<Response>((resolve) => { hold = resolve })
    }))
    const { result } = renderHook(() => useControlHealth(), { wrapper: wrapper().wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    act(() => void result.current.refetch())          // 30초 재조회 · 창 초점 · 재접속 resync 와 같은 다시 조회
    await waitFor(() => expect(result.current.fetchStatus).toBe('fetching'))
    expect([result.current.isError, result.current.data]).toEqual([false, undefined])
    expect(controlHealthView(result.current)).toEqual({ state: 'error' })
    act(() => hold?.(json(controlHealth({ items: [MONITOR.loader] }))))
    await waitFor(() => expect(controlHealthView(result.current)).toEqual({ state: 'ok', alerts: [MONITOR.loader], unknowns: [] }))
  })
})

describe('관제 이상 판정(#72)', () => {
  it('opsAnomalies: 이상 · 모름을 서버 순서로 나누고, 모르는 level 은 모름 · 항목이 아닌 값은 뺀다', () => {
    const odd = { ...MONITOR.nodes, key: 'future', level: 'warn' as never }
    const items = [MONITOR.heartbeats, MONITOR.loader, null as never, odd, MONITOR.mismatch, { level: 'alert' } as never]
    const { alerts, unknowns } = opsAnomalies(controlHealth({ items }))
    expect(alerts.map((i) => i.key)).toEqual(['loader', 'gateway_mismatch'])
    expect(unknowns.map((i) => i.key)).toEqual(['heartbeats', 'future'])
    expect(opsAnomalies(undefined)).toEqual({ alerts: [], unknowns: [] })
    expect(opsAnomalies(controlHealth())).toEqual({ alerts: [], unknowns: [] })
  })

  it('controlHealthView: 실패를 받은 값보다 먼저 본다(이전 항목이 있어도 확인 불가)', () => {
    const data = controlHealth({ items: [MONITOR.loader, MONITOR.nodes] })
    expect(controlHealthView({ data: undefined, isError: false })).toEqual({ state: 'pending' })
    expect(controlHealthView({ data: undefined, isError: true })).toEqual({ state: 'error' })
    expect(controlHealthView({ data, isError: true })).toEqual({ state: 'error' })
    expect(controlHealthView({ data, isError: false })).toEqual({ state: 'ok', alerts: [MONITOR.loader], unknowns: [MONITOR.nodes] })
    expect(controlHealthView({ data: controlHealth(), isError: false })).toEqual({ state: 'ok', alerts: [], unknowns: [] })
    // 마지막으로 끝난 조회가 실패면(다시 조회 중이라 isError 가 꺼져도) 확인 불가, 그 뒤 받으면 받은 값
    expect(controlHealthView({ data: undefined, isError: false, errorUpdatedAt: 5, dataUpdatedAt: 0 })).toEqual({ state: 'error' })
    expect(controlHealthView({ data, isError: false, errorUpdatedAt: 5, dataUpdatedAt: 9 }, 10)).toEqual({ state: 'ok', alerts: [MONITOR.loader], unknowns: [MONITOR.nodes] })
  })

  it('정상 응답도 마지막 수신 후 90초를 넘으면 갱신 지연이고 새 성공 뒤에만 정상이다', () => {
    const data = controlHealth()
    expect(controlHealthView({ data, isError: false, dataUpdatedAt: 1000 }, 91000).state).toBe('ok')
    expect(controlHealthView({ data, isError: false, dataUpdatedAt: 1000 }, 91001).state).toBe('stale')
    expect(controlHealthView({ data, isError: false, dataUpdatedAt: 92000, errorUpdatedAt: 91500 }, 92000).state).toBe('ok')
    expect(controlHealthView({ data, isError: true, dataUpdatedAt: 1000 }, 92000).state).toBe('error')
  })

  it('항목 글은 까닭, 없으면 건수', () => {
    expect(monitorItemText(MONITOR.loader)).toBe('적재기 확인 중단 · 마지막 45분 전')
    expect(monitorItemText(MONITOR.failedGateway)).toBe('2건')
    expect(monitorItemText(MONITOR.pointStaleFw)).toBe('2건')
    expect(monitorItemText({ reason: null, count: 1234 })).toBe('1,234건')
    expect(monitorItemText(MONITOR.nodesSilent)).toBe('노드 2대 수신 끊김')
    // 일부만 끊겨도 까닭(대수 · 이름)이 건수보다 먼저다
    expect(monitorItemText(MONITOR.nodesSilentSome)).toBe('node-b 수신 끊김 · 마지막 수신 12분 전')
    expect(monitorItemText({ reason: null, count: null })).toBeNull()
  })

  it.each<[string, string | null]>([
    // 차단 집행 쪽 → 차단 목록
    ['enforcer:gateway', '/blocklist'], ['enforcer:fw', '/blocklist'], ['block_failed:fw', '/blocklist'], ['gateway_mismatch', '/blocklist'],
    ['point_stale:fw', '/blocklist'], ['point_stale:gateway', '/blocklist'], ['report:fw', '/blocklist'], ['report:gateway', '/blocklist'],
    ['point_delayed:gateway', '/blocklist'], ['point_delayed:fw', '/blocklist'],
    // 노드 수신 · 자원 지표 → 수집 · 관제 상태의 등록 노드 표
    ['nodes_silent', '/nodes'], ['nodes', '/nodes'], ['metrics:web-01', '/nodes'], ['metrics:node-e', '/nodes'],
    // 센서 · 관문 기록 수신 → 그 화면의 허니팟 센서 줄, 탐지 경로 · 적재기 · 생존 신호 → 데이터 노드 줄(펼침, #84)
    ['sensor', '/nodes?open=aws-sensor'], ['gateway_uploader', '/nodes?open=aws-sensor'],
    ['detect:honeypot', '/nodes?open=data-node'], ['detect:bridge', '/nodes?open=data-node'], ['loader', '/nodes?open=data-node'], ['heartbeats', '/nodes?open=data-node'],
    // 웹 로그 적재 → 그 장비의 최근 로그(id 는 주소 조각으로 감싼다)
    ['parse:web-01', '/devices/web-01/logs'], ['parse:node a/1', '/devices/node%20a%2F1/logs'], ['parse:', null],
    // 모르는 키
    ['other', null], ['nodes_silent_x', null], ['reports', null],
  ])('링크: %s → %s', (key, href) => {
    expect(monitorItemHref(key)).toBe(href)
  })
})

it('데이터 자원·디스크 경고는 데이터 노드 상세를 펼친다(#109)', () => {
  expect(monitorItemHref('data_resources')).toBe('/nodes?open=data-node')
  expect(monitorItemHref('data_disk:0')).toBe('/nodes?open=data-node')
})
