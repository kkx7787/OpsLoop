/**
 * 역할과 권한(화면 설계 15장 권한표). 서버가 같은 규칙으로 다시 검사한다(app/main.py require_role).
 * 화면의 검사는 누를 수 없는 버튼을 미리 흐리게 보이려는 것이지 보안 경계가 아니다.
 */

export const ROLES = ['viewer', 'operator', 'admin'] as const
export type Role = (typeof ROLES)[number]

export const ROLE_LABEL: Record<Role, string> = {
  viewer: '조회자',
  operator: '관제사',
  admin: '관리자',
}

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value)
}

/** 권한을 따지는 동작과 화면 표기 */
export const ACTION_LABEL = {
  'incident.verdict': '판정',
  'block.request': '차단 요청',
  'block.release': '차단 해제',
  'block.extend': '차단 연장',
  'rule.suppress': '규칙 억제',
  'rule.approve': '규칙 승인',
  'notify.manage': '알림 설정',
  'node.token': '노드 토큰 발급',
  'console.distribution': '콘솔 분배',
  'account.manage': '계정 관리',
  'audit.read': '감사 기록 열람',
} as const

export type Action = keyof typeof ACTION_LABEL

const OPERATORS: readonly Role[] = ['operator', 'admin']
const ADMINS: readonly Role[] = ['admin']

/**
 * 권한표. 되돌리는 행위(차단 해제 · 연장)와 기준을 바꾸는 행위(규칙 억제 · 승인)는 admin 만 한다.
 *
 * | 역할     | 판정 · 차단 요청 | 차단 해제 · 연장 · 규칙 억제 · 승인 | 알림 · 노드 토큰 · 콘솔 분배 · 계정 | 감사 기록 열람 |
 * | viewer   | 불가             | 불가                                | 불가                                | 불가           |
 * | operator | 가능             | 불가                                | 불가                                | 불가           |
 * | admin    | 가능             | 가능                                | 가능                                | 가능           |
 */
export const PERMISSIONS: Record<Action, readonly Role[]> = {
  'incident.verdict': OPERATORS,
  'block.request': OPERATORS,
  'block.release': ADMINS,
  'block.extend': ADMINS,
  'rule.suppress': ADMINS,
  'rule.approve': ADMINS,
  'notify.manage': ADMINS,
  'node.token': ADMINS,
  'console.distribution': ADMINS,
  'account.manage': ADMINS,
  'audit.read': ADMINS,
}

/** 모르는 역할 · 로그인 전(undefined)은 아무것도 할 수 없다. */
export function can(role: string | null | undefined, action: Action): boolean {
  return isRole(role) && PERMISSIONS[action].includes(role)
}

export interface Permission {
  allowed: boolean
  /** 막힌 이유. 허용이면 빈 문자열. Gated · Button 의 disabledReason 에 그대로 넘긴다. */
  reason: string
}

/** 허용 여부와, 막혔다면 그 이유(와이어프레임 States: "이 동작은 admin 만 할 수 있습니다"). */
export function permission(role: string | null | undefined, action: Action): Permission {
  if (can(role, action)) return { allowed: true, reason: '' }
  const who = PERMISSIONS[action].join(' · ')
  const label = ACTION_LABEL[action]
  if (!role) return { allowed: false, reason: `권한을 확인하는 중입니다 (${label})` }
  return { allowed: false, reason: `이 동작(${label})은 ${who} 만 할 수 있습니다 · 현재 역할 ${role}` }
}
