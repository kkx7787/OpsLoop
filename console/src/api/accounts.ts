import { useQuery, type QueryClient } from '@tanstack/react-query'
import { api } from './client'
import { auditKey } from './operations'
import type { Role } from '@/auth/roles'

/**
 * 콘솔 계정(S-15 · #59). 서버 계약은 app/accounts.py(모두 admin 만).
 * 화면은 관제사 ↔ 조회자 역할 변경과 비활성 · 재활성만 한다. 관리자 계정 · 관리자 부여 · 계정 추가 · 비밀번호는 명령줄(app/auth.py)이다.
 * 서버는 비밀번호 해시를 주지 않는다. 변경은 DB 함수(console_account_set)가 한 번 더 가르고 감사에 한 줄 남긴다.
 */

/** 화면에서 줄 수 있는 역할. admin 으로 올리기는 서버가 409(명령줄 전용)로 거부한다 */
export const ASSIGNABLE_ROLES = ['viewer', 'operator'] as const
export type AssignableRole = (typeof ASSIGNABLE_ROLES)[number]

/** 버튼 대신 까닭을 보이는 행. admin = 관리자 계정(명령줄에서만 변경) · self = 지금 로그인한 본인 */
export type AccountLock = 'admin' | 'self'

export interface Account {
  username: string
  role: Role
  active: boolean
  /** 비활성한 시각. 활성이면 null */
  disabled_at: string | null
  created_at: string
  last_login_at: string | null
  /** 역할 · 활성 · 비밀번호가 마지막으로 바뀐 시각. 이보다 먼저 받은 쿠키는 무효다. 서버는 늘 채운다(바뀐 적 없으면 추가 시각) */
  updated_at: string | null
  locked: AccountLock | null
}

export interface AccountsResult {
  accounts: Account[]
}

/** 변경 응답. unchanged = 이미 그 값이라 바꾼 것이 없다(감사 행도 없다) */
export interface AccountChange {
  result: 'ok' | 'unchanged'
  account: Account
}

export const accountKeys = {
  all: ['accounts'] as const,
}

const REFRESH = { staleTime: 10_000, refetchInterval: 30_000 } as const

/** 계정 목록(아이디 순). admin 이 아니면 부르지 않는다(서버도 403). */
export function useAccounts(enabled: boolean) {
  return useQuery({
    queryKey: accountKeys.all,
    queryFn: ({ signal }) => api.get<AccountsResult>('/api/accounts', { signal }),
    enabled,
    ...REFRESH,
  })
}

/**
 * 쓰기는 훅이 아니라 함수로 부른다(두 번 들어가지 않게 화면이 막는다). 성공이든 실패든 끝나면 목록과 감사 기록을 다시 받는다.
 * 실패(404 · 409)는 다른 콘솔 · 명령줄에서 먼저 바뀐 경우라 최신 목록을 보여야 한다.
 */
async function change(client: QueryClient, path: string, body: object): Promise<AccountChange> {
  try {
    return await api.post<AccountChange>(path, body)
  } finally {
    await Promise.all([client.invalidateQueries({ queryKey: accountKeys.all }), client.invalidateQueries({ queryKey: auditKey })])
  }
}

/** 관제사 ↔ 조회자. 그 계정의 열린 세션은 무효가 되어 다시 로그인해야 한다 */
export function setAccountRole(client: QueryClient, username: string, role: AssignableRole) {
  return change(client, '/api/accounts/role', { username, role })
}

/** 비활성 · 재활성. 비활성하면 열린 세션이 끊기고(실시간 연결은 30초 안), 재활성해도 옛 세션은 되살아나지 않는다 */
export function setAccountActive(client: QueryClient, username: string, active: boolean) {
  return change(client, '/api/accounts/active', { username, active })
}
