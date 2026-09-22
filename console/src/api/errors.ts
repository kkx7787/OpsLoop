/**
 * API 오류를 한 모양으로 모은다. 화면은 status · kind 만 보고 어떤 상태 화면을 그릴지 정한다.
 *  http     서버가 답했지만 2xx 가 아니다(status 에 코드)
 *  network  서버에 닿지 못했다(status 0)
 *  timeout  정한 시간 안에 답이 없어 요청을 멈췄다(status 0)
 *  parse    2xx 지만 본문을 해석할 수 없다(JSON 대신 HTML 등)
 */
export type ApiErrorKind = 'http' | 'network' | 'timeout' | 'parse'

export interface ApiErrorInit {
  status: number
  detail: string
  body?: unknown
  kind?: ApiErrorKind
  cause?: unknown
}

export class ApiError extends Error {
  readonly status: number
  readonly detail: string
  readonly body: unknown
  readonly kind: ApiErrorKind

  constructor({ status, detail, body, kind = 'http', cause }: ApiErrorInit) {
    super(detail, cause === undefined ? undefined : { cause })
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
    this.body = body
    this.kind = kind
  }

  /** 다시 보내면 나아질 수 있는 오류: 5xx 와 네트워크 오류. 시간 초과는 넣지 않는다(queryClient.ts). */
  get retryable(): boolean {
    return this.kind === 'network' || (this.kind === 'http' && this.status >= 500)
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}

const STATUS_DETAIL: Record<number, string> = {
  400: '요청이 올바르지 않습니다',
  401: '로그인이 필요합니다',
  403: '권한이 없습니다',
  404: '찾을 수 없습니다',
  409: '다른 변경과 충돌했습니다',
  413: '요청이 너무 큽니다',
  422: '입력값을 확인해 주세요',
  429: '요청이 많습니다. 잠시 뒤 다시 시도해 주세요',
  502: '콘솔 서버가 응답하지 않습니다',
  503: '콘솔 서버를 잠시 쓸 수 없습니다',
  504: '콘솔 서버의 응답이 늦습니다',
}

/**
 * 응답 본문에서 사람이 읽을 설명을 꺼낸다.
 * FastAPI 는 {"detail": "문장"} 또는 검증 오류 {"detail": [{"loc": [...], "msg": "..."}]} 를 준다.
 */
export function detailFrom(body: unknown, status: number): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (typeof detail === 'string' && detail.trim()) return detail
    if (Array.isArray(detail)) {
      const msgs = detail
        .map((d) => (d && typeof d === 'object' && 'msg' in d ? String((d as { msg: unknown }).msg) : ''))
        .filter(Boolean)
      if (msgs.length) return msgs.join(' · ')
    }
  }
  return STATUS_DETAIL[status] ?? (status >= 500 ? '서버 오류가 발생했습니다' : `요청이 실패했습니다 (HTTP ${status})`)
}

/** 상태 화면 설명에 쓰는 한 줄. ApiError 가 아니면 일반 문장. */
export function describeError(error: unknown): string {
  if (isApiError(error)) {
    return error.kind === 'http' ? `${error.detail} (HTTP ${error.status})` : error.detail
  }
  if (error instanceof Error && error.message) return error.message
  return '알 수 없는 오류가 발생했습니다'
}
