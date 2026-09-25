import { QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import { assetDetailResult, assetsResult, CTI_KEY, incidentCti, watchResult } from '@/test/cti-fixtures'
import { assetPath, ctiKeys, incidentCtiPath, lastVulnOffset, useAsset, useAssets, useIncidentCti, useWatch, WATCH_PATH, type VulnFilter } from './cti'
import { incidentKeys } from './incidents'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** 주소별 응답을 정한 fetch. 약속을 돌려주면 그 응답이 올 때까지 기다린다(응답하지 않는 서버 흉내) */
function stubFetch(route: (url: string) => Response | Promise<Response> | undefined) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    return route(url) ?? json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function calledUrls(fetch: ReturnType<typeof stubFetch>): string[] {
  return fetch.mock.calls.map(([input]) => (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url))
}

function withClient() {
  const client = noRetryClient()
  const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
  return { client, wrapper }
}

describe('CVE 연계 경로 · 쿼리 키', () => {
  it('사건 키는 상세 경로와 같은 방식으로 부호화하고 /cti 를 붙인다', () => {
    expect(incidentCtiPath('R105|c1|192.0.2.1|x')).toBe('/api/incidents/R105%7Cc1%7C192.0.2.1%7Cx/cti')
    expect(incidentCtiPath('a/b+c')).toBe(`/api/incidents/${encodeURIComponent('a/b+c')}/cti`)
  })

  it('자산 경로 조각도 부호화한다', () => {
    expect(assetPath('web-01')).toBe('/api/assets/web-01')
    expect(assetPath('a b/c')).toBe('/api/assets/a%20b%2Fc')
  })

  it('CTI 키는 사건 상세 키 밑에 있지 않고 cti 한 접두로 묶인다', () => {
    expect(ctiKeys.incident(CTI_KEY)).toEqual(['cti', 'incident', CTI_KEY])
    expect(ctiKeys.incident(CTI_KEY).slice(0, incidentKeys.details().length)).not.toEqual(incidentKeys.details())
    expect(ctiKeys.asset('fw', 'kev', 50).slice(0, 2)).toEqual(ctiKeys.assets())
    expect(ctiKeys.assets().slice(0, 1)).toEqual(ctiKeys.all)
  })

  it('주목 CVE 키는 cti 접두 밑이지만 자산 키 밑에 있지 않다(자산 상세의 이전 결과 유지와 섞이지 않는다)', () => {
    expect(ctiKeys.watch()).toEqual(['cti', 'watch'])
    expect(ctiKeys.watch().slice(0, ctiKeys.assets().length)).not.toEqual(ctiKeys.assets())
    expect(WATCH_PATH).toBe('/api/cti/watch')
  })

  it('마지막 쪽 offset 은 총수와 한 쪽 크기로 정하고 0건이면 첫 쪽이다', () => {
    expect(lastVulnOffset(120)).toBe(100)
    expect(lastVulnOffset(100)).toBe(50)
    expect(lastVulnOffset(60, 50)).toBe(50)
    expect(lastVulnOffset(30, 50)).toBe(0)
    expect(lastVulnOffset(1, 50)).toBe(0)
    expect(lastVulnOffset(0, 50)).toBe(0)
    expect(lastVulnOffset(10, 0)).toBe(0)
  })
})

describe('useIncidentCti', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('부호화한 경로로 한 번 받는다', async () => {
    const fetch = stubFetch((url) => (url === `/api/incidents/${encodeURIComponent(CTI_KEY)}/cti` ? json(incidentCti()) : undefined))
    const { wrapper } = withClient()
    const { result } = renderHook(() => useIncidentCti(CTI_KEY), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.applicable).toBe(true)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('키가 비어 있으면 묻지 않는다', () => {
    const fetch = stubFetch(() => undefined)
    const { wrapper } = withClient()
    const { result } = renderHook(() => useIncidentCti(''), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('useAssets · useAsset', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('자산 목록을 받는다', async () => {
    stubFetch((url) => (url === '/api/assets' ? json(assetsResult()) : undefined))
    const { wrapper } = withClient()
    const { result } = renderHook(() => useAssets(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.rows).toHaveLength(3)
  })

  it('자산이 비어 있으면 상세를 묻지 않는다', () => {
    const fetch = stubFetch(() => undefined)
    const { wrapper } = withClient()
    const { result } = renderHook(() => useAsset('', 'all', 0), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('거르기 · 쪽 · 한 쪽 크기를 질의로 보내고, 거르기를 바꾸는 동안 같은 자산의 이전 결과를 유지한다', async () => {
    let release: () => void = () => undefined
    const fetch = stubFetch((url) => (url.startsWith('/api/assets/fw?') ? json(assetDetailResult()) : undefined))
    const { wrapper } = withClient()
    const { result, rerender } = renderHook(({ id, filter, offset }: { id: string; filter: VulnFilter; offset: number }) => useAsset(id, filter, offset), {
      wrapper,
      initialProps: { id: 'fw', filter: 'all', offset: 0 },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(calledUrls(fetch)).toEqual(['/api/assets/fw?filter=all&limit=50&offset=0'])

    // 다음 응답을 붙잡아 두고 거르기를 바꾼다: 이전 결과가 자리표시로 남는다
    fetch.mockImplementationOnce(() => new Promise<Response>((resolve) => { release = () => resolve(json(assetDetailResult())) }))
    rerender({ id: 'fw', filter: 'kev', offset: 0 })
    expect(result.current.isPlaceholderData).toBe(true)
    expect(result.current.data?.asset?.asset_id).toBe('fw')
    await act(async () => release())
    await waitFor(() => expect(result.current.isPlaceholderData).toBe(false))
    expect(calledUrls(fetch).at(-1)).toBe('/api/assets/fw?filter=kev&limit=50&offset=0')
  })

  it('다른 자산으로 옮기면 이전 자산의 결과를 자리표시로 쓰지 않는다', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/assets/fw?')) return json(assetDetailResult())
      if (url.startsWith('/api/assets/web-01?')) return new Promise<Response>(() => undefined)
      return undefined
    })
    const { wrapper } = withClient()
    const { result, rerender } = renderHook(({ id }: { id: string }) => useAsset(id, 'all', 0), { wrapper, initialProps: { id: 'fw' } })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    rerender({ id: 'web-01' })
    expect(result.current.data).toBeUndefined()
    expect(result.current.isPending).toBe(true)
  })
})

describe('useWatch', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('/api/cti/watch 를 한 번 받는다', async () => {
    const fetch = stubFetch((url) => (url === '/api/cti/watch' ? json(watchResult()) : undefined))
    const { wrapper } = withClient()
    const { result } = renderHook(() => useWatch(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.rows.map((r) => r.cve_id)).toEqual(['CVE-2026-53266', 'CVE-2024-6387', 'CVE-2021-3156'])
    expect(calledUrls(fetch)).toEqual(['/api/cti/watch'])
  })

  it('cti 전체 무효화(웹소켓 재접속)에 함께 다시 받는다', async () => {
    const fetch = stubFetch((url) => (url === '/api/cti/watch' ? json(watchResult()) : undefined))
    const { client, wrapper } = withClient()
    const { result } = renderHook(() => useWatch(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    await act(async () => { await client.invalidateQueries({ queryKey: ctiKeys.all }) })
    expect(fetch).toHaveBeenCalledTimes(2)
  })
})

