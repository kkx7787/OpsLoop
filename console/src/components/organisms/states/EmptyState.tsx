import type { ReactNode } from 'react'
import { IconInbox } from '../../atoms/icons'
import { StateView, type StateViewProps } from './StateView'

export interface EmptyStateProps extends Omit<StateViewProps, 'title' | 'tone'> {
  title?: ReactNode
}

/**
 * 결과 0건. 0건은 좋은 소식이기 전에 수집부터 의심한다(States.dc.html).
 * 설명에 조건 수 · 마지막 수신 시각을, 동작에 "조건 초기화 · 수집 노드 보기"를 넣는다.
 */
export function EmptyState({ title = '표시할 항목이 없습니다', icon, ...rest }: EmptyStateProps) {
  return <StateView tone="info" title={title} icon={icon ?? <IconInbox size={28} />} {...rest} />
}
