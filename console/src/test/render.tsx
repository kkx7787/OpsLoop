import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { createMemoryRouter, RouterProvider, type RouteObject } from 'react-router'
import { vi } from 'vitest'
import { createQueryClient } from '@/api/queryClient'

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** /api/me 의 응답을 정한 fetch 를 전역에 끼운다. 그 밖의 주소는 404 JSON. 끝나면 vi.unstubAllGlobals(). */
export function stubMe(body: unknown, status = 200) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.startsWith('/api/me')) return jsonResponse(body, status)
    return jsonResponse({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

/** 답하지 않는 fetch(불러오는 중 화면을 보려고) */
export function stubHanging() {
  vi.stubGlobal(
    'fetch',
    vi.fn<typeof globalThis.fetch>(() => new Promise<Response>(() => undefined)),
  )
}

/** 재시도 없는 클라이언트. 5xx 를 바로 오류 화면으로 보고 싶을 때(재시도 지연 1초 · 2초를 기다리지 않는다). */
export function noRetryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
}

/** 경로표를 메모리 라우터로 그린다. TanStack Query 는 시험마다 새 클라이언트(기본은 운영 규칙과 같은 재시도). */
export function renderRoutes(routes: RouteObject[], path: string, client: QueryClient = createQueryClient()) {
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  const result = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return { router, ...result }
}
