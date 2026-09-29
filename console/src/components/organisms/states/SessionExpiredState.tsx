import type { ReactNode } from 'react'
import { loginHref } from '@/api/client'
import { buttonClasses } from '../../atoms/button-styles'
import { IconClock } from '../../atoms/icons'
import { InfoTip } from '../../molecules/InfoTip'
import { StateView, type StateViewProps } from './StateView'

export interface SessionExpiredStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 로그인 주소. 기본은 지금 경로를 next 로 붙인 /login */
  href?: string
}

/**
 * 세션 만료(401). 보통은 API 클라이언트가 바로 로그인으로 보내므로 잠깐 보이거나,
 * 이동이 막힌 경우에 남는다. 로그인 화면은 서버가 그리므로 라우터가 아닌 일반 링크로 간다.
 * 세션이 끝나는 기준(12시간 · 계정 변경, app/auth.py SESSION_HOURS)은 ⓘ 로 접는다.
 */
export function SessionExpiredState({
  title = '다시 로그인해 주세요',
  href,
  eyebrow = '세션 만료',
  description = <>세션이 끝났습니다. <InfoTip label="세션 만료">로그인 후 12시간이 지나거나 계정의 역할 · 활성 · 비밀번호가 바뀌면 세션이 끝납니다.</InfoTip></>,
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
