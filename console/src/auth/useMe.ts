import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { permission, type Action, type Permission, type Role } from './roles'

/** GET /api/me 의 응답 */
export interface Me {
  username: string
  role: Role
}

export const meQueryKey = ['me'] as const

export function fetchMe(signal?: AbortSignal): Promise<Me> {
  return api.get<Me>('/api/me', { signal })
}

/**
 * 로그인한 사용자. 세션은 쿠키가 들고 있고 12시간 동안 바뀌지 않으므로 자주 다시 묻지 않는다.
 * 세션이 끝나면 API 클라이언트가 401 을 받아 로그인으로 보낸다.
 */
export function useMe() {
  return useQuery({
    queryKey: meQueryKey,
    queryFn: ({ signal }) => fetchMe(signal),
    staleTime: 5 * 60_000,
  })
}

/** 지금 사용자가 이 동작을 할 수 있는지와 막힌 이유. 불러오는 동안은 막아 둔다. */
export function usePermission(action: Action): Permission {
  const { data } = useMe()
  return permission(data?.role, action)
}
