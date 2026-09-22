import { ApiError, detailFrom } from './errors'

/**
 * API 공통 인스턴스. fetch 하나로 만든다(axios 는 쓰지 않는다: 같은 브라우저 통신 경로라 속도 차이가 없고 번들이 준다).
 *  - 같은 출처 쿠키 세션(credentials 'same-origin')
 *  - 시간 초과(기본 15초)와 호출자 취소(TanStack Query 의 signal)를 한 AbortController 로 합친다
 *  - 2xx 가 아니면 ApiError 하나로 던진다
 *  - 401 은 세션 만료로 보고 로그인 화면으로 한 번만 보낸다. 403 은 ApiError 로 넘겨 화면이 ForbiddenState 를 그린다
 */

export const DEFAULT_TIMEOUT_MS = 15_000

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'
export type QueryValue = string | number | boolean | null | undefined
export type QueryParams = Record<string, QueryValue | readonly QueryValue[]>

export interface RequestOptions {
  /** 호출자 취소 신호. TanStack Query 의 queryFn({ signal }) 을 그대로 넘긴다. */
  signal?: AbortSignal
  /** 이 요청만의 시간 초과(ms) */
  timeoutMs?: number
  headers?: Record<string, string>
  /** 쿼리 문자열. undefined · null 은 빼고, 배열은 같은 이름으로 여러 번 붙인다. */
  query?: QueryParams
}

export interface ClientOptions {
  /** 경로 앞에 붙는 주소. 같은 출처로 서빙하므로 기본은 '' */
  baseUrl?: string
  timeoutMs?: number
  /** 시험에서 바꿔 끼우는 fetch */
  fetch?: typeof fetch
  /** 401 을 받았을 때 한 번 부른다. 기본은 /login?next=<현재 경로> 로 이동. */
  onUnauthorized?: (loginHref: string) => void
}

export interface ApiClient {
  request<T>(method: HttpMethod, path: string, options?: RequestOptions & { body?: unknown }): Promise<T>
  get<T>(path: string, options?: RequestOptions): Promise<T>
  post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T>
  put<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T>
  del<T>(path: string, options?: RequestOptions): Promise<T>
}

/** 로그인 뒤 돌아올 곳을 붙인 로그인 주소. 서버는 같은 출처의 상대 경로만 받는다. */
export function loginHref(location: Pick<Location, 'pathname' | 'search'> = window.location): string {
  const next = `${location.pathname}${location.search}`
  return next && next !== '/' ? `/login?next=${encodeURIComponent(next)}` : '/login'
}

export function buildUrl(baseUrl: string, path: string, query?: QueryParams): string {
  let url = `${baseUrl}${path}`
  if (query) {
    const params = new URLSearchParams()
    for (const [key, raw] of Object.entries(query)) {
      const values: readonly QueryValue[] = Array.isArray(raw) ? raw : [raw as QueryValue]
      for (const v of values) if (v !== undefined && v !== null) params.append(key, String(v))
    }
    const qs = params.toString()
    if (qs) url += (url.includes('?') ? '&' : '?') + qs
  }
  return url
}

function isRawBody(body: unknown): body is BodyInit {
  return (
    body instanceof FormData ||
    body instanceof URLSearchParams ||
    body instanceof Blob ||
    body instanceof ArrayBuffer ||
    typeof body === 'string'
  )
}

/** 서버가 세션 없는 요청을 /login 으로 돌려보낸 경우(화면 경로 규칙)도 401 로 본다. */
function redirectedToLogin(res: Response): boolean {
  if (!res.redirected || !res.url) return false
  try {
    return new URL(res.url).pathname === '/login'
  } catch {
    return false
  }
}

async function readBody(res: Response): Promise<unknown> {
  if (res.status === 204 || res.status === 205) return undefined
  const text = await res.text()
  if (!text) return undefined
  const type = res.headers.get('content-type') ?? ''
  if (type.includes('json')) {
    try {
      return JSON.parse(text)
    } catch (cause) {
      throw new ApiError({ status: res.status, kind: 'parse', detail: '응답을 해석할 수 없습니다', body: text, cause })
    }
  }
  if (res.ok && type.includes('text/html')) {
    // API 가 화면(HTML)을 받으면 파싱에서 엉뚱한 곳이 깨진다. 여기서 멈춘다.
    throw new ApiError({ status: res.status, kind: 'parse', detail: '서버가 JSON 대신 HTML 을 돌려줬습니다', body: text })
  }
  return text
}

export function createClient(options: ClientOptions = {}): ApiClient {
  const baseUrl = options.baseUrl ?? ''
  const defaultTimeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const doFetch = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init))
  const onUnauthorized = options.onUnauthorized ?? ((href: string) => window.location.assign(href))

  // 동시에 나간 요청 여러 개가 401 을 받아도 이동은 한 번만 한다.
  // 기본 동작은 페이지를 새로 여는 이동이라 로그인 뒤에는 이 값도 새로 시작한다.
  let sentToLogin = false
  function handleUnauthorized() {
    if (sentToLogin) return
    sentToLogin = true
    onUnauthorized(loginHref())
  }

  async function request<T>(
    method: HttpMethod,
    path: string,
    { body, signal, timeoutMs = defaultTimeout, headers, query }: RequestOptions & { body?: unknown } = {},
  ): Promise<T> {
    if (signal?.aborted) throw signal.reason

    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, timeoutMs)
    const forwardAbort = () => controller.abort(signal?.reason)
    signal?.addEventListener('abort', forwardAbort, { once: true })

    const init: RequestInit = {
      method,
      credentials: 'same-origin',
      headers: { Accept: 'application/json', ...headers },
      signal: controller.signal,
    }
    if (body !== undefined) {
      if (isRawBody(body)) {
        init.body = body
      } else {
        init.body = JSON.stringify(body)
        init.headers = { 'Content-Type': 'application/json', ...init.headers }
      }
    }

    try {
      let res: Response
      let toLogin = false
      let payload: unknown
      try {
        res = await doFetch(buildUrl(baseUrl, path, query), init)
        toLogin = redirectedToLogin(res)
        payload = toLogin ? undefined : await readBody(res)
      } catch (err) {
        if (err instanceof ApiError) throw err
        if (timedOut) {
          throw new ApiError({
            status: 0,
            kind: 'timeout',
            detail: `응답이 ${Math.round(timeoutMs / 1000)}초 안에 오지 않아 요청을 멈췄습니다`,
            cause: err,
          })
        }
        // 호출자가 취소한 요청은 그대로 넘긴다. TanStack Query 가 취소로 처리한다.
        if (signal?.aborted) throw err
        throw new ApiError({ status: 0, kind: 'network', detail: '서버에 연결할 수 없습니다', cause: err })
      }

      if (res.ok && !toLogin) return payload as T

      const status = toLogin ? 401 : res.status
      const error = new ApiError({ status, detail: detailFrom(payload, status), body: payload })
      if (status === 401) handleUnauthorized()
      throw error
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', forwardAbort)
    }
  }

  return {
    request,
    get: (path, opts) => request('GET', path, opts),
    post: (path, body, opts) => request('POST', path, { ...opts, body }),
    put: (path, body, opts) => request('PUT', path, { ...opts, body }),
    del: (path, opts) => request('DELETE', path, opts),
  }
}

/** 화면 전체가 쓰는 인스턴스 하나 */
export const api = createClient()
