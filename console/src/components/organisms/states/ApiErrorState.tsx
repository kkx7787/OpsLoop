import { isApiError } from '@/api/errors'
import { ErrorState } from './ErrorState'
import { ForbiddenState } from './ForbiddenState'
import { NotFoundState } from './NotFoundState'
import { SessionExpiredState } from './SessionExpiredState'
import type { StateViewProps } from './StateView'

export interface ApiErrorStateProps extends Pick<StateViewProps, 'size' | 'className' | 'titleAs'> {
  error: unknown
  onRetry?: () => void
  retrying?: boolean
}

/**
 * 조회 오류를 알맞은 상태 화면으로 나눈다. 페이지는 useQuery 의 error 를 그대로 넘긴다.
 *   401 → 세션 만료 · 403 → 권한 밖 · 404 → 없음 · 그 밖(5xx · 네트워크 · 시간 초과) → 오류
 */
export function ApiErrorState({ error, onRetry, retrying, ...view }: ApiErrorStateProps) {
  if (isApiError(error)) {
    if (error.status === 401) return <SessionExpiredState {...view} />
    if (error.status === 403) return <ForbiddenState detail={error.detail} {...view} />
    if (error.status === 404) return <NotFoundState title="찾을 수 없습니다" description={error.detail} {...view} />
  }
  return <ErrorState error={error} onRetry={onRetry} retrying={retrying} {...view} />
}
