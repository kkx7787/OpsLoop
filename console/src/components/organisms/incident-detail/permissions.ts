import { isRole, type Permission } from '@/auth/roles'

/**
 * 확인(acknowledge) 조치의 권한. 권한표(auth/roles.ts)에 따로 없는 동작이라 서버(add_action: operator · admin)와 같게 여기서 정한다.
 * 이유 문장은 permission() 과 같은 모양이라 Button 의 disabledReason 에 그대로 넘긴다.
 */
export function ackPermission(role: string | null | undefined): Permission {
  if (isRole(role) && role !== 'viewer') return { allowed: true, reason: '' }
  if (!role) return { allowed: false, reason: '권한을 확인하는 중입니다 (확인)' }
  return { allowed: false, reason: `이 동작(확인)은 operator · admin 만 할 수 있습니다 · 현재 역할 ${role}` }
}
