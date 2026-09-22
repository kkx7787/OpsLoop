import type { MouseEvent, ReactNode } from 'react'
import { cn } from '@/lib/cn'

export interface GatedProps {
  /** 할 수 있는가. auth 의 permission() · usePermission() 결과를 그대로 펼쳐 넣을 수 있다. */
  allowed: boolean
  /** 막힌 이유("이 동작(차단 해제)은 admin 만 할 수 있습니다 · 현재 역할 operator") */
  reason?: string
  /** 이유를 글로 함께 보인다. 기본은 마우스 오버(title) · 화면 낭독기 설명으로만 알린다. */
  showReason?: boolean
  className?: string
  children: ReactNode
}

/**
 * 권한 밖의 동작을 숨기지 않고 흐리게 보인다(화면 설계 15장). 무엇이 있는지는 알되 누를 수 없다.
 * 안쪽은 inert 로 초점 · 누름을 막는다. inert 는 화면 낭독기에서도 빠지므로 이유 문장이 그 자리를 대신한다
 * (이유에 동작 이름이 들어 있다). 마우스로는 title 로 이유를 본다.
 * 단추 하나만 막을 때는 Button 의 disabledReason 이 낫다. 초점이 남아 키보드로도 이유를 읽을 수 있다.
 * 화면의 검사는 보안 경계가 아니다. 서버가 같은 규칙으로 403 을 준다.
 */
export function Gated({ allowed, reason = '권한이 없습니다', showReason = false, className, children }: GatedProps) {
  if (allowed) return <>{children}</>

  // inert 를 모르는 환경에서도 안쪽 onClick 이 불리지 않게 잡는 단계에서 끊는다.
  function stop(event: MouseEvent) {
    event.preventDefault()
    event.stopPropagation()
  }

  return (
    <div
      title={reason}
      data-gated="denied"
      onClickCapture={stop}
      className={cn('inline-flex max-w-full cursor-not-allowed flex-col gap-1', className)}
    >
      <div inert className="pointer-events-none opacity-45 select-none">
        {children}
      </div>
      <span className={cn(showReason ? 'text-xs text-ink-muted' : 'sr-only')}>
        {reason}
      </span>
    </div>
  )
}
