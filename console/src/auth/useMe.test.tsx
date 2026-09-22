import { QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queryClient'
import { useMe, usePermission } from './useMe'

function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={createQueryClient()}>{children}</QueryClientProvider>
}

function stubMe(body: unknown) {
  const fetch = vi.fn<typeof globalThis.fetch>(async () => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }))
  vi.stubGlobal('fetch', fetch)
  return fetch
}

describe('useMe', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GET /api/me 로 사용자와 역할을 받는다', async () => {
    const fetch = stubMe({ username: 'han', role: 'operator' })
    const { result } = renderHook(() => useMe(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual({ username: 'han', role: 'operator' })
    expect(fetch).toHaveBeenCalledWith('/api/me', expect.objectContaining({ method: 'GET', credentials: 'same-origin' }))
  })

  it('usePermission: 받기 전에는 막고, 받은 뒤 역할로 판단한다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    const { result } = renderHook(() => ({ verdict: usePermission('incident.verdict'), release: usePermission('block.release') }), {
      wrapper,
    })
    expect(result.current.verdict.allowed).toBe(false)
    await waitFor(() => expect(result.current.verdict.allowed).toBe(true))
    expect(result.current.release).toEqual({
      allowed: false,
      reason: '이 동작(차단 해제)은 admin 만 할 수 있습니다 · 현재 역할 operator',
    })
  })
})
