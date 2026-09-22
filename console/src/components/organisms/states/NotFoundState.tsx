import type { ReactNode } from 'react'
import { buttonClasses } from '../../atoms/button-styles'
import { IconCompass } from '../../atoms/icons'
import { StateView, type StateViewProps } from './StateView'

export interface NotFoundStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 찾지 못한 주소 · 키 */
  path?: string
  /** 돌아갈 곳. 기본은 대시보드 */
  homeHref?: string
}

/**
 * 없는 주소(404) · 없는 인시던트. 기본 링크는 일반 <a> 다(라우터 밖에서도 그려지게).
 * 라우터 안에서는 actions 에 Link 를 넣는다.
 */
export function NotFoundState({
  title = '페이지를 찾을 수 없습니다',
  path,
  homeHref = '/',
  eyebrow = '404',
  description,
  actions,
  icon,
  ...rest
}: NotFoundStateProps) {
  const size = rest.size ?? 'compact'
  return (
    <StateView
      tone="warning"
      eyebrow={eyebrow}
      title={title}
      description={
        description ?? (
          <>
            주소가 바뀌었거나 없는 화면입니다.
            {path && (
              <>
                {' '}
                <code className="font-mono text-xs break-all text-ink">{path}</code>
              </>
            )}
          </>
        )
      }
      icon={icon ?? <IconCompass size={28} />}
      actions={
        actions ?? (
          <a href={homeHref} className={buttonClasses({ size: size === 'page' ? 'lg' : 'sm' })}>
            대시보드로
          </a>
        )
      }
      {...rest}
    />
  )
}
