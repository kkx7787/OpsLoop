import { QueryClient } from '@tanstack/react-query'
import { isApiError } from './errors'

export const MAX_RETRIES = 2

/**
 * 조회 재시도 규칙: 5xx · 네트워크 오류만 두 번 더 보낸다.
 * 401 · 403 · 404 같은 4xx 는 다시 보내도 같은 답이므로 바로 상태 화면으로 넘긴다.
 * 시간 초과도 다시 보내지 않는다. 15초씩 세 번이면 45초 넘게 로딩만 보이기 때문이다.
 */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  return failureCount < MAX_RETRIES && isApiError(error) && error.retryable
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: shouldRetry },
      // 판정 · 조치는 두 번 들어가면 안 되므로 자동 재시도하지 않는다.
      mutations: { retry: false },
    },
  })
}

export const queryClient = createQueryClient()
