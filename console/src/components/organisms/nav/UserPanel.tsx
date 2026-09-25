import { isRole, ROLE_LABEL } from '@/auth/roles'
import type { Me } from '@/auth/useMe'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { IconAccounts } from '../../atoms/icons'
import { UntrustedText } from '../../atoms/UntrustedText'

export interface LogoutFormProps {
  className?: string
}

/**
 * 로그아웃은 서버가 처리한다(POST /logout → 쿠키 삭제 → /login). 화면 이동이 아니라 폼 제출이다.
 * 브라우저가 같은 출처 POST 에 Origin 을 붙이므로 서버의 출처 확인을 통과한다.
 */
export function LogoutForm({ className }: LogoutFormProps) {
  return (
    <form method="post" action="/logout" className={cn('m-0', className)}>
      <button
        type="submit"
        className="cursor-pointer rounded-sm border-0 bg-transparent p-0 text-xs text-primary hover:text-primary-strong"
      >
        로그아웃
      </button>
    </form>
  )
}

export interface UserPanelProps {
  /** 로그인한 사용자. 아직 모르면(불러오는 중) 자리만 보인다. */
  user?: Me | null
  className?: string
}

/** 사이드바 · 서랍 아래의 사용자 칸: 계정 아이콘 · 아이디 · 역할 · 로그아웃(와이어프레임 Main.dc.html) */
export function UserPanel({ user, className }: UserPanelProps) {
  const roleTitle = user && isRole(user.role) ? ROLE_LABEL[user.role] : undefined
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <span
        aria-hidden="true"
        className="flex shrink-0 items-center justify-center text-ink-muted"
      >
        <IconAccounts size={18} />
      </span>
      <span className="flex min-w-0 flex-col text-sm">
        <span className="truncate font-medium" title={user ? revealHidden(user.username) : undefined}>
          <UntrustedText value={user?.username} clip fallback="확인 중" />
        </span>
        <span className="text-xs text-ink-muted" title={roleTitle}>
          {user?.role ?? '—'}
        </span>
      </span>
      <LogoutForm className="ml-auto shrink-0 whitespace-nowrap" />
    </div>
  )
}
