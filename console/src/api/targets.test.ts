import { QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { targetsResult } from '@/test/targets-fixtures'
import { isApiError } from './errors'
import { monitoringKeys } from './monitoring-keys'
import { fetchTargets, isTargetsNotDeployed, TARGETS_NOT_DEPLOYED, TARGETS_PATH, useTargets } from './targets'

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

describe('관제 대상 상태판 API(#52)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('GET /api/dashboard/targets 를 받아 그대로 돌려준다', async () => {
    const fetch = stubFetch((url) => (url === '/api/dashboard/targets' ? json(targetsResult()) : undefined))
    const data = await fetchTargets()
    expect(TARGETS_PATH).toBe('/api/dashboard/targets')
    expect(data.targets.map((t) => t.id)).toEqual(['aws-sensor', 'web-01', 'console', 'data-node'])
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('404(이전 서버)는 찾을 수 없음이 아니라 콘솔 API 배포 전으로 읽힌다', async () => {
    stubFetch(() => undefined)
    const error = await fetchTargets().catch((e: unknown) => e)
    expect(isApiError(error) && error.status).toBe(404)
    expect(isApiError(error) && error.detail).toBe(TARGETS_NOT_DEPLOYED)
    expect(TARGETS_NOT_DEPLOYED).toContain('콘솔 API 배포 전')
    expect(isTargetsNotDeployed(error)).toBe(true)
  })

  it('그 밖의 오류는 그대로 넘긴다', async () => {
    stubFetch(() => json({ detail: 'DB unavailable' }, 503))
    const error = await fetchTargets().catch((e: unknown) => e)
    expect(isApiError(error) && error.status).toBe(503)
    expect(isTargetsNotDeployed(error)).toBe(false)
  })

  it('모양이 다른 응답(요약 등)을 빈 카드로 꾸미지 않고 해석 오류로 던진다', async () => {
    stubFetch(() => json({ pending: {}, oldest_pending: [] }))
    const error = await fetchTargets().catch((e: unknown) => e)
    expect(isApiError(error) && error.kind).toBe('parse')
  })

  it('useTargets 는 대시보드 · 대상 키로 한 번 받는다', async () => {
    const fetch = stubFetch((url) => (url === TARGETS_PATH ? json(targetsResult()) : undefined))
    const client = noRetryClient()
    const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
    const { result } = renderHook(() => useTargets(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(monitoringKeys.targets).toEqual(['dashboard', 'targets'])
    expect(client.getQueryData(monitoringKeys.targets)).toEqual(targetsResult())
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
