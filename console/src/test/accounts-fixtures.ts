import type { Account } from '@/api/accounts'

/** 계정 한 줄. 기본은 활성 관제사 · 잠금 없음 */
export function account(overrides: Partial<Account> = {}): Account {
  return {
    username: 'han', role: 'operator', active: true, disabled_at: null, created_at: '2026-09-20T00:00:00Z',
    last_login_at: '2026-09-28T23:10:00Z', updated_at: null, locked: null, ...overrides,
  }
}

/** 아이디 순(서버와 같다). 로그인한 사람은 root 다 */
export const ACCOUNTS: Account[] = [
  account(),
  account({ username: 'kim', role: 'viewer', active: false, disabled_at: '2026-09-28T01:00:00Z', updated_at: '2026-09-28T01:00:00Z', last_login_at: null }),
  account({ username: 'ops-admin', role: 'admin', locked: 'admin' }),
  account({ username: 'root', role: 'admin', locked: 'self' }),
]
