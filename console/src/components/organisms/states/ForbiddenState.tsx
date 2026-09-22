import type { ReactNode } from 'react'
import { Button } from '../../atoms/Button'
import { IconLock } from '../../atoms/icons'
import { StateView, type StateViewProps } from './StateView'

export interface ForbiddenStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 할 수 있는 역할(예: 'admin' · ['operator', 'admin']) */
  requiredRoles?: string | readonly string[]
  currentRole?: string
  /** 서버가 준 설명(403 detail) */
  detail?: string
  /** 돌아가기. 없으면 브라우저 뒤로 가기 */
  onBack?: () => void
}

/** 권한 밖(403). 권한 밖의 단추는 흐리게 보이고, 직접 요청하면 이 안내가 뜬다(States.dc.html). */
export function ForbiddenState({
  title,
  requiredRoles,
  currentRole,
  detail,
  onBack,
  eyebrow = '공통 · 403',
  description,
  actions,
  icon,
  ...rest
}: ForbiddenStateProps) {
  const roles = typeof requiredRoles === 'string' ? [requiredRoles] : requiredRoles
  const heading = title ?? (roles?.length ? `이 동작은 ${roles.join(' · ')} 만 할 수 있습니다` : '이 화면을 볼 권한이 없습니다')
  const body = description ?? (
    <>
      {currentRole && <>현재 역할 {currentRole}. </>}
      {detail && <>{detail}. </>}
      권한이 필요하면 관리자에게 요청하세요.
    </>
  )
  return (
    <StateView
      tone="danger"
      eyebrow={eyebrow}
      title={heading}
      description={body}
      icon={icon ?? <IconLock size={28} />}
      actions={
        actions ?? (
          <Button size="sm" onClick={onBack ?? (() => window.history.back())}>
            돌아가기
          </Button>
        )
      }
      {...rest}
    />
  )
}
