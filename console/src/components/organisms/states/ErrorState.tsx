import type { ReactNode } from 'react'
import { describeError } from '@/api/errors'
import { Button } from '../../atoms/Button'
import { IconAlert } from '../../atoms/icons'
import { StateView, type StateViewProps } from './StateView'

export interface ErrorStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 받은 오류. 설명을 따로 주지 않으면 여기서 한 줄을 만든다. */
  error?: unknown
  /** 다시 시도. 주면 단추가 생긴다(TanStack Query 의 refetch). */
  onRetry?: () => void
  /** 다시 시도하는 중 */
  retrying?: boolean
}

/** 불러오기 실패(5xx · 네트워크 · 시간 초과). 연결 끊김(S-10) 전용 화면은 3.6.x 에서 이 틀로 만든다. */
export function ErrorState({
  title = '데이터를 불러오지 못했습니다',
  error,
  onRetry,
  retrying = false,
  eyebrow = '오류',
  description,
  actions,
  icon,
  ...rest
}: ErrorStateProps) {
  const size = rest.size ?? 'compact'
  return (
    <StateView
      role="alert"
      tone="danger"
      eyebrow={eyebrow}
      title={title}
      description={description ?? (error !== undefined ? describeError(error) : undefined)}
      icon={icon ?? <IconAlert size={28} />}
      actions={
        actions ??
        (onRetry && (
          <Button variant="primary" size={size === 'page' ? 'lg' : 'sm'} loading={retrying} onClick={onRetry}>
            다시 시도
          </Button>
        ))
      }
      {...rest}
    />
  )
}
