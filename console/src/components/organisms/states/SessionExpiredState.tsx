import type { ReactNode } from 'react'
import { loginHref } from '@/api/client'
import { buttonClasses } from '../../atoms/button-styles'
import { IconClock } from '../../atoms/icons'
import { StateView, type StateViewProps } from './StateView'

export interface SessionExpiredStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 로그인 주소. 기본은 지금 경로를 next 로 붙인 /login */
  href?: string
}

/**
 * 세션 만료(401). 보통은 API 클라이언트가 바로 로그인으로 보내므로 잠깐 보이거나,
 * 이동이 막힌 경우에 남는다. 로그인 화면은 서버가 그리므로 라우터가 아닌 일반 링크로 간다.
 */
export function SessionExpiredState({
  title = '다시 로그인해 주세요',
  href,
  eyebrow = '공통 · 세션 만료',
  description = '세션이 끝났습니다(로그인 후 12시간). 다시 로그인하면 이어서 볼 수 있습니다.',
  actions,
  icon,
  ...rest
}: SessionExpiredStateProps) {
  const size = rest.size ?? 'compact'
  return (
    <StateView
      tone="warning"
      eyebrow={eyebrow}
      title={title}
      description={description}
      icon={icon ?? <IconClock size={28} />}
      actions={
        actions ?? (
          <a href={href ?? loginHref()} className={buttonClasses({ variant: 'primary', size: size === 'page' ? 'lg' : 'sm' })}>
            로그인
          </a>
        )
      }
      {...rest}
    />
  )
}
