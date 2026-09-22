import type { ReactNode } from 'react'
import { Skeleton } from '../../atoms/Skeleton'
import { StateView, type StateViewProps } from './StateView'

export interface LoadingStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
  /** 회색 막대 수 */
  lines?: number
}

/**
 * 불러오는 중. 목록은 이전 결과를 유지한 채 다시 조회하는 것이 기본이라(States.dc.html)
 * 이 화면은 처음 불러올 때만 쓴다.
 */
export function LoadingState({ title = '불러오는 중입니다', lines = 3, description, ...rest }: LoadingStateProps) {
  return (
    <StateView role="status" aria-live="polite" aria-busy="true" title={title} description={description} {...rest}>
      <div className="flex w-full flex-col gap-2.5 py-1">
        {Array.from({ length: lines }, (_, i) => (
          <Skeleton key={i} className={i === lines - 1 ? 'w-2/3' : 'w-full'} />
        ))}
      </div>
    </StateView>
  )
}
