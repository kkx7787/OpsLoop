import { QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createQueryClient } from '@/api/queryClient'
import { parseMe, useMe, usePermission } from './useMe'

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

describe('parseMe', () => {
  it('사용자 이름 · 역할이 있으면 받은 객체를 그대로 쓴다(console 은 있어도 없어도 된다)', () => {
    const old = { username: 'han', role: 'operator' }
    expect(parseMe(old)).toBe(old)
    const withConsole = { username: 'han', role: 'admin', console: 'opsloop-console-b' }
    expect(parseMe(withConsole)).toBe(withConsole)
  })

  it('console 이 문자열이 아니면 빼고 나머지는 쓴다', () => {
    for (const bad of [42, null, true, { name: 'a' }, ['opsloop-console-a']]) {
      const me = parseMe({ username: 'han', role: 'viewer', console: bad })
      expect(me).toEqual({ username: 'han', role: 'viewer' })
      expect(me).not.toHaveProperty('console')
    }
  })

  it('비었거나 모양이 틀리면 null(로그인 안 된 것으로 본다)', () => {
    for (const bad of [undefined, null, '', 'han', 42, {}, { username: '', role: 'viewer' }, { username: 'han' }, { username: 'han', role: 3 }, { role: 'admin', console: 'opsloop-console-a' }]) {
      expect(parseMe(bad)).toBeNull()
    }
  })
})
