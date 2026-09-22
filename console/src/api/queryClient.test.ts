import { describe, expect, it } from 'vitest'
import { ApiError } from './errors'
import { createQueryClient, MAX_RETRIES, shouldRetry } from './queryClient'

const http = (status: number) => new ApiError({ status, detail: '' })

describe('shouldRetry', () => {
  it('5xx 와 네트워크 오류만 두 번까지 다시 보낸다', () => {
    expect(MAX_RETRIES).toBe(2)
    expect(shouldRetry(0, http(503))).toBe(true)
    expect(shouldRetry(1, http(500))).toBe(true)
    expect(shouldRetry(2, http(503))).toBe(false)
    expect(shouldRetry(0, new ApiError({ status: 0, kind: 'network', detail: '' }))).toBe(true)
  })

  it('401 · 403 · 404 와 그 밖의 4xx 는 다시 보내지 않는다', () => {
    for (const status of [400, 401, 403, 404, 409, 422, 429]) expect(shouldRetry(0, http(status))).toBe(false)
  })

  it('시간 초과 · 해석 실패 · ApiError 가 아닌 오류도 다시 보내지 않는다', () => {
    expect(shouldRetry(0, new ApiError({ status: 0, kind: 'timeout', detail: '' }))).toBe(false)
    expect(shouldRetry(0, new ApiError({ status: 200, kind: 'parse', detail: '' }))).toBe(false)
    expect(shouldRetry(0, new Error('x'))).toBe(false)
  })

  it('기본 설정: 조회는 shouldRetry, 변경은 재시도 없음', () => {
    const client = createQueryClient()
    expect(client.getDefaultOptions().queries?.retry).toBe(shouldRetry)
    expect(client.getDefaultOptions().mutations?.retry).toBe(false)
  })
})
