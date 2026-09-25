import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { permission, type Action, type Permission, type Role } from './roles'

/** GET /api/me 의 응답 */
export interface Me {
  username: string
  role: Role
  /**
   * 이 요청을 받은 콘솔 이름(#43 · 서버 OPSLOOP_WORKER). 옛 서버는 주지 않는다.
   * REST 요청은 콘솔 두 대에 번갈아 가므로 요청마다 다를 수 있다. 상단바의 콘솔 표시는 웹소켓 hello 의 값을 쓴다.
   */
  console?: string
}

/**
 * /api/me 응답이 쓸 만한지 보고 Me 로 고른다. 사용자 이름이 비었거나 역할이 문자열이 아니면 null(로그인 안 된 것으로 본다).
 * console 은 선택이다. 없거나 문자열이 아니면 없는 것으로 보고 빼며, 나머지는 그대로 쓴다.
 */
export function parseMe(data: unknown): Me | null {
  if (!data || typeof data !== 'object') return null
  const { username, role, console: name } = data as Record<string, unknown>
  if (typeof username !== 'string' || username === '' || typeof role !== 'string') return null
  // 모양이 맞으면 받은 객체를 그대로 돌려준다(렌더마다 새 객체를 만들지 않는다)
  if (name === undefined || typeof name === 'string') return data as Me
  const copy = { ...(data as Me) }
  delete copy.console
  return copy
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
