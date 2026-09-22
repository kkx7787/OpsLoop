import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { buildUrl, createClient, DEFAULT_TIMEOUT_MS, loginHref } from './client'
import { ApiError } from './errors'

type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** 응답하지 않다가 신호가 끊기면 그 이유로 실패하는 fetch */
const hanging: FetchFn = (_input, init) =>
  new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(init.signal?.reason ?? new DOMException('aborted', 'AbortError')))
  })

describe('createClient', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/')
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('같은 출처 쿠키 · JSON 머리글로 보내고 본문을 풀어 돌려준다', async () => {
    const fetch = vi.fn<FetchFn>(async () => json({ username: 'han', role: 'operator' }))
    const client = createClient({ fetch })

    await expect(client.get('/api/me')).resolves.toEqual({ username: 'han', role: 'operator' })

    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe('/api/me')
    expect(init?.method).toBe('GET')
    expect(init?.credentials).toBe('same-origin')
    expect(init?.headers).toMatchObject({ Accept: 'application/json' })
    expect(init?.body).toBeUndefined()
  })

  it('POST 본문은 JSON 으로 싣고 쿼리는 이어 붙인다', async () => {
    const fetch = vi.fn<FetchFn>(async () => json({ id: 1 }, 201))
    const client = createClient({ fetch })

    await client.post('/api/incidents/R003%7Cv2/verdict', { verdict: 'threat' }, { query: { dry: true, tag: ['a', 'b'], skip: undefined } })

    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe('/api/incidents/R003%7Cv2/verdict?dry=true&tag=a&tag=b')
    expect(init?.method).toBe('POST')
    expect(init?.body).toBe('{"verdict":"threat"}')
    expect(init?.headers).toMatchObject({ 'Content-Type': 'application/json', Accept: 'application/json' })
  })

  it('본문 없는 204 는 undefined', async () => {
    const client = createClient({ fetch: async () => new Response(null, { status: 204 }) })
    await expect(client.del('/api/x')).resolves.toBeUndefined()
  })

  it('2xx 가 아니면 ApiError(status · detail · body) 로 던진다', async () => {
    const body = { detail: '인시던트를 찾을 수 없습니다' }
    const client = createClient({ fetch: async () => json(body, 404) })

    const error = await client.get('/api/incidents/none').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 404, kind: 'http', detail: '인시던트를 찾을 수 없습니다', body })
  })

  it('FastAPI 검증 오류(detail 배열)는 msg 를 이어 붙인다', async () => {
    const client = createClient({
      fetch: async () => json({ detail: [{ loc: ['body', 'verdict'], msg: '허용되지 않는 값' }, { msg: '필수' }] }, 422),
    })
    await expect(client.post('/api/x', {})).rejects.toMatchObject({ status: 422, detail: '허용되지 않는 값 · 필수' })
  })

  it('JSON 이 아닌 오류 응답은 상태 코드로 설명을 만든다', async () => {
    const client = createClient({ fetch: async () => new Response('Bad Gateway', { status: 502 }) })
    await expect(client.get('/api/x')).rejects.toMatchObject({ status: 502, detail: '콘솔 서버가 응답하지 않습니다', body: 'Bad Gateway' })
  })

  it('2xx 인데 HTML 이면 parse 오류로 멈춘다', async () => {
    const client = createClient({
      fetch: async () => new Response('<!doctype html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    })
    await expect(client.get('/api/x')).rejects.toMatchObject({ status: 200, kind: 'parse' })
  })

  it('403 은 이동하지 않고 ApiError 로 넘긴다', async () => {
    const onUnauthorized = vi.fn<(href: string) => void>()
    const client = createClient({ fetch: async () => json({ detail: '권한이 없습니다 (operator)' }, 403), onUnauthorized })
    await expect(client.post('/api/x', {})).rejects.toMatchObject({ status: 403, detail: '권한이 없습니다 (operator)' })
    expect(onUnauthorized).not.toHaveBeenCalled()
  })

  it('401 이면 지금 경로를 next 로 붙여 로그인으로 한 번만 보낸다', async () => {
    window.history.replaceState(null, '', '/incidents?q=4.4.66.84')
    const onUnauthorized = vi.fn<(href: string) => void>()
    const client = createClient({ fetch: async () => json({ detail: '인증이 필요합니다' }, 401), onUnauthorized })

    const results = await Promise.allSettled([client.get('/api/a'), client.get('/api/b'), client.get('/api/c')])

    for (const r of results) {
      expect(r.status).toBe('rejected')
      expect((r as PromiseRejectedResult).reason).toMatchObject({ status: 401 })
    }
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    expect(onUnauthorized).toHaveBeenCalledWith('/login?next=%2Fincidents%3Fq%3D4.4.66.84')
  })

  it('서버가 /login 으로 돌려보낸 응답도 401 로 본다', async () => {
    const onUnauthorized = vi.fn<(href: string) => void>()
    const res = new Response('<form action="/login">', { status: 200, headers: { 'content-type': 'text/html' } })
    Object.defineProperty(res, 'redirected', { value: true })
    Object.defineProperty(res, 'url', { value: 'http://localhost:3000/login' })
    const client = createClient({ fetch: async () => res, onUnauthorized })

    await expect(client.get('/api/x')).rejects.toMatchObject({ status: 401, kind: 'http' })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it('정한 시간 안에 답이 없으면 멈추고 timeout 오류를 던진다(기본 15초)', async () => {
    vi.useFakeTimers()
    const client = createClient({ fetch: hanging })

    const pending = client.get('/api/slow').catch((e: unknown) => e)
    await vi.advanceTimersByTimeAsync(DEFAULT_TIMEOUT_MS - 1)
    let settled = false
    void pending.then(() => (settled = true))
    await Promise.resolve()
    expect(settled).toBe(false)

    await vi.advanceTimersByTimeAsync(1)
    const error = await pending
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 0, kind: 'timeout', detail: '응답이 15초 안에 오지 않아 요청을 멈췄습니다' })
  })

  it('요청마다 시간 초과를 바꿀 수 있다', async () => {
    vi.useFakeTimers()
    const client = createClient({ fetch: hanging })
    const pending = client.get('/api/slow', { timeoutMs: 3_000 }).catch((e: unknown) => e)
    await vi.advanceTimersByTimeAsync(3_000)
    await expect(pending).resolves.toMatchObject({ kind: 'timeout', detail: '응답이 3초 안에 오지 않아 요청을 멈췄습니다' })
  })

  it('호출자가 취소하면(TanStack Query) ApiError 가 아닌 취소 이유를 그대로 넘긴다', async () => {
    const client = createClient({ fetch: hanging })
    const caller = new AbortController()
    const pending = client.get('/api/slow', { signal: caller.signal }).catch((e: unknown) => e)

    caller.abort()
    const error = await pending
    expect(error).not.toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ name: 'AbortError' })
  })

  it('이미 취소된 신호로는 보내지 않는다', async () => {
    const fetch = vi.fn<FetchFn>(hanging)
    const client = createClient({ fetch })
    const caller = new AbortController()
    caller.abort()
    await expect(client.get('/api/x', { signal: caller.signal })).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('끝난 요청은 시간 초과 타이머와 취소 연결을 남기지 않는다', async () => {
    vi.useFakeTimers()
    const client = createClient({ fetch: async () => json({ ok: true }) })
    const caller = new AbortController()
    const remove = vi.spyOn(caller.signal, 'removeEventListener')

    await client.get('/api/x', { signal: caller.signal })
    expect(vi.getTimerCount()).toBe(0)
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function))
  })

  it('서버에 닿지 못하면 network 오류', async () => {
    const client = createClient({
      fetch: async () => {
        throw new TypeError('Failed to fetch')
      },
    })
    await expect(client.get('/api/x')).rejects.toMatchObject({ status: 0, kind: 'network', detail: '서버에 연결할 수 없습니다' })
  })
})

describe('loginHref · buildUrl', () => {
  it('루트는 next 를 붙이지 않는다', () => {
    expect(loginHref({ pathname: '/', search: '' })).toBe('/login')
    expect(loginHref({ pathname: '/audit', search: '' })).toBe('/login?next=%2Faudit')
  })

  it('이미 쿼리가 있는 경로에는 & 로 잇는다', () => {
    expect(buildUrl('', '/api/x?a=1', { b: 2 })).toBe('/api/x?a=1&b=2')
    expect(buildUrl('/base', '/api/x', { none: null })).toBe('/base/api/x')
  })
})
