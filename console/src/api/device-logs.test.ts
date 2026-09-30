import { QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { logsResult, webLine } from '@/test/device-logs-fixtures'
import { noRetryClient } from '@/test/render'
import {
  DEVICE_LOGS_INTERVAL,
  DEVICE_LOGS_LIMIT,
  DEVICE_NOT_FOUND,
  deviceLogsKey,
  deviceLogsPath,
  deviceLogsQuery,
  deviceLogsQueryOptions,
  fetchDeviceLogs,
  isDeviceNotFound,
  isFinalError,
  isHttpStatus,
  isLogsNotDeployed,
  LOGS_NOT_DEPLOYED,
  useDeviceLogs,
} from './device-logs'
import { ApiError, isApiError } from './errors'
import { shouldRetry } from './queryClient'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function stubFetch(route: (url: string) => Response | undefined) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    return route(url) ?? json({ detail: 'Not Found' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

const urls = (fetch: ReturnType<typeof stubFetch>) => fetch.mock.calls.map(([input]) => String(input))

async function caught(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  )
  if (!isApiError(error)) throw new Error('ApiError 가 아님')
  return error
}

describe('장비 최근 로그 API(#73)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('경로는 장비 id 를 부호화하고, 쿼리는 종류 · 출발지 · 응답 코드 · limit 100 이다', async () => {
    expect(deviceLogsPath('web-01')).toBe('/api/devices/web-01/logs')
    expect(deviceLogsPath('a b/c')).toBe('/api/devices/a%20b%2Fc/logs')
    const fetch = stubFetch((url) => (url.startsWith('/api/devices/web-02/logs?') ? json(logsResult()) : undefined))
    await fetchDeviceLogs('web-02', { kind: 'ssh', src_ip: ' 203.0.113.7 ', status: 404 })
    await fetchDeviceLogs('web-02', {})
    expect(urls(fetch)).toEqual(['/api/devices/web-02/logs?kind=ssh&src_ip=203.0.113.7&status=404&limit=100', '/api/devices/web-02/logs?limit=100'])
    expect(DEVICE_LOGS_LIMIT).toBe(100)
  })

  it('모르는 종류 · 100..599 밖 응답 코드 · 빈 출발지는 보내지 않는다(서버의 영어 검증 문장이 뜨지 않게)', () => {
    expect(deviceLogsQuery({ kind: 'all' as never, src_ip: '  ', status: 600 })).toEqual({ limit: 100 })
    expect(deviceLogsQuery({ status: 99 })).toEqual({ limit: 100 })
    expect(deviceLogsQuery({ status: 404.5 })).toEqual({ limit: 100 })
    expect(deviceLogsQuery({ kind: 'web', status: 100 })).toEqual({ kind: 'web', status: 100, limit: 100 })
    expect([99, 100, 599, 600, Number.NaN, '200'].map(isHttpStatus)).toEqual([false, true, true, false, false, false])
  })

  it('404 두 가지: 서버 문장이면 보호 대상이 아닌 장비, 기본 Not Found 면 배포 전 안내로 바꾼다', async () => {
    stubFetch((url) => (url.startsWith('/api/devices/aws-sensor/') ? json({ detail: DEVICE_NOT_FOUND }, 404) : undefined))
    const missing = await caught(fetchDeviceLogs('aws-sensor', {}))
    expect(missing.status).toBe(404)
    expect(missing.detail).toBe('보호 대상 장비를 찾을 수 없습니다')
    expect(isDeviceNotFound(missing)).toBe(true)
    expect(isLogsNotDeployed(missing)).toBe(false)

    const old = await caught(fetchDeviceLogs('web-01', {}))
    expect(old.status).toBe(404)
    expect(old.detail).toBe(LOGS_NOT_DEPLOYED)
    expect(LOGS_NOT_DEPLOYED).toBe('장비 로그 API 가 없습니다. 콘솔 API 배포 전일 수 있습니다.')
    expect(isLogsNotDeployed(old)).toBe(true)
    expect(isDeviceNotFound(old)).toBe(false)
    expect(isDeviceNotFound(new ApiError({ status: 500, detail: DEVICE_NOT_FOUND }))).toBe(false)
  })

  it('422 는 서버 문장 그대로 넘긴다', async () => {
    stubFetch(() => json({ detail: 'src_ip 는 IP 주소여야 합니다' }, 422))
    const error = await caught(fetchDeviceLogs('web-01', { src_ip: 'nope' }))
    expect([error.status, error.detail]).toEqual([422, 'src_ip 는 IP 주소여야 합니다'])
  })

  it.each([
    ['목록이 배열이 아님', { ...logsResult(), items: null }],
    ['줄에 id 가 없음', { ...logsResult(), items: [{ ...webLine(1), id: undefined }] }],
    ['줄 시각이 글자가 아님', { ...logsResult(), items: [{ ...webLine(1), ts: 1 }] }],
    ['시각 칸이 없음', { ...logsResult(), times: undefined }],
    ['탐지 칸이 없음', { ...logsResult(), times: { ...logsResult().times, detect: null } }],
    ['앞선 시각 수가 없음', { ...logsResult(), future: undefined }],
    ['장비가 없음', { ...logsResult(), device: null }],
    ['장비 이름이 글자가 아님', { ...logsResult(), device: { id: 'web-01', label: null, kind: 'fixed' } }],
    ['조회 창이 없음', { ...logsResult(), window_days: undefined }],
    ['배열', []],
  ])('모양이 틀린 응답(%s)은 빈 목록으로 꾸미지 않고 해석 오류다', async (_name, body) => {
    stubFetch(() => json(body))
    const error = await caught(fetchDeviceLogs('web-01', {}))
    expect(error.kind).toBe('parse')
    expect(error.detail).toContain('장비 로그 응답을 해석할 수 없습니다')
  })

  it('조회 설정: 5초 주기 · 숨은 탭에서 멈춤 · 초점 조회 · 4초 신선 · 재시도 규칙. placeholderData 는 쓰지 않는다', () => {
    const q = (error: unknown = null) => ({ state: { error } })
    const on = deviceLogsQueryOptions('web-01', { kind: 'web' }, false)
    expect(on.queryKey).toEqual(['device-logs', 'web-01', { kind: 'web', src_ip: null, status: null }])
    expect(on.queryKey).toEqual(deviceLogsKey('web-01', { kind: 'web' }))
    expect(on.refetchInterval(q())).toBe(5_000)
    expect(DEVICE_LOGS_INTERVAL).toBe(5_000)
    expect(on.refetchIntervalInBackground).toBe(false)
    expect(on.refetchOnWindowFocus(q())).toBe(true)
    expect(on.staleTime).toBe(4_000)
    expect(on.retry).toBe(shouldRetry)
    expect(on).not.toHaveProperty('placeholderData')
    // 오프라인이어도 멈추지 않고 보내 실패가 갱신 실패로 보이게 한다. 재연결 조회는 초점 조회와 같은 규칙이다
    expect(on.networkMode).toBe('always')
    expect(on.refetchOnReconnect(q())).toBe(true)

    // 일시정지면 주기 · 초점 조회를 모두 끈다
    const off = deviceLogsQueryOptions('web-01', {}, true)
    expect(off.refetchInterval(q())).toBe(false)
    expect(off.refetchOnWindowFocus(q())).toBe(false)
    expect(off.refetchOnReconnect(q())).toBe(false)
    expect(off.refetchIntervalInBackground).toBe(false)
  })

  it('마지막 조회가 4xx 면 주기 · 초점 조회를 멈추고, 5xx · 네트워크 · 해석 오류는 계속 받는다', () => {
    const on = deviceLogsQueryOptions('web-01', {}, false)
    const q = (error: unknown) => ({ state: { error } })
    for (const status of [401, 403, 404, 422]) {
      const error = new ApiError({ status, detail: 'x' })
      expect(isFinalError(error)).toBe(true)
      expect(on.refetchInterval(q(error))).toBe(false)
      expect(on.refetchOnWindowFocus(q(error))).toBe(false)
      expect(on.refetchOnReconnect(q(error))).toBe(false)
    }
    for (const error of [new ApiError({ status: 503, detail: 'x' }), new ApiError({ status: 0, kind: 'network', detail: 'x' }), new ApiError({ status: 0, kind: 'parse', detail: 'x' }), new Error('x')]) {
      expect(isFinalError(error)).toBe(false)
      expect(on.refetchInterval(q(error))).toBe(5_000)
      expect(on.refetchOnReconnect(q(error))).toBe(true)
    }
  })

  it('useDeviceLogs 는 조건마다 따로 받는다', async () => {
    const fetch = stubFetch((url) => (url.startsWith('/api/devices/web-01/logs?') ? json(logsResult()) : undefined))
    const client = noRetryClient()
    const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
    const { result, rerender } = renderHook(({ kind }: { kind?: 'web' | 'ssh' }) => useDeviceLogs('web-01', { kind }, true), { wrapper, initialProps: {} })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    rerender({ kind: 'ssh' })
    await waitFor(() => expect(urls(fetch)).toEqual(['/api/devices/web-01/logs?limit=100', '/api/devices/web-01/logs?kind=ssh&limit=100']))
  })
})
