import { useId, type ComponentProps, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { Card, CardHeader } from '../../atoms/Card'

export interface DetailSectionProps extends Omit<ComponentProps<'div'>, 'title'> {
  /** 구역 번호(① … ⑤). 장식이라 낭독기에는 읽히지 않는다 */
  number: string
  title: ReactNode
  /** 머리 오른쪽 보조 정보(행 수 · 기준) */
  aside?: ReactNode
  /** 본문 여백. 표를 넣는 구역은 none */
  padding?: 'none' | 'md'
}

/** 상세 화면(S-04)의 구역 카드 하나. 제목이 구역의 이름이 되어 낭독기가 구역 단위로 옮겨 다닐 수 있다 */
export function DetailSection({ number, title, aside, padding = 'md', className, children, ...rest }: DetailSectionProps) {
  const titleId = useId()
  return (
    <Card padding="none" role="region" aria-labelledby={titleId} className={cn('flex min-w-0 flex-col', className)} {...rest}>
      <CardHeader
        title={
          <span id={titleId} className="inline-flex items-center gap-2">
            <span aria-hidden="true" className="text-ink-muted">
              {number}
            </span>
            {title}
          </span>
        }
        aside={aside}
      />
      <div className={cn('flex min-w-0 flex-col gap-3', padding === 'md' && 'p-4')}>{children}</div>
    </Card>
  )
}
