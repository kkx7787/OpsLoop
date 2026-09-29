import { useId } from 'react'
import type { CtiBadge } from '@/api/cti'
import type { Target, TargetsResult } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { groupTargets } from './target-format'
import { TargetSummaryList } from './TargetSummaryList'

export interface SupportTargetsProps {
  /** GET /api/dashboard/targets 응답. 없으면(조회 전 · 실패) 아무것도 그리지 않는다. 오류는 보호 대상 자리만 보인다 */
  data: TargetsResult | undefined
  /** 마지막 성공 조회 시각(ms). as_of 가 없을 때 상대 시각의 기준 */
  updatedAt: number
  /** 페이지가 한 번 받은 최근 사건 CVE 배지 */
  badges?: Readonly<Record<string, CtiBadge>>
  className?: string
}

/**
 * 관측 센서(AWS 센서) · 관제 시스템(콘솔 · 데이터 노드)(#72). 보호 대상 아래에 두고 모든 폭에서 한 줄씩 접어 둔다.
 * 머리 배지(데이터 노드 확인 멈춤은 '주의') · 경고 배지(적용 실패 · 집행기 · 적재기 멈춤) · 미판정만 보이고, 누르면 카드를 펼친다.
 * 넓으면(md 이상) 두 무리를 나란히, 좁으면 쌓는다.
 */
export function SupportTargets({ data, updatedAt, badges, className }: SupportTargetsProps) {
  if (!data) return null
  const groups = groupTargets(data.targets)
  const asOf = toDate(data.as_of)?.getTime() ?? updatedAt
  if (!groups.sensors.length && !groups.system.length) return null
  return (
    <div className={cn('grid items-start gap-4 md:grid-cols-2', className)}>
      <Group title="관측 센서" targets={groups.sensors} asOf={asOf} badges={badges} />
      <Group title="관제 시스템" targets={groups.system} asOf={asOf} badges={badges} />
    </div>
  )
}

function Group({ title, targets, asOf, badges }: { title: string; targets: Target[]; asOf: number; badges: SupportTargetsProps['badges'] }) {
  const titleId = useId()
  if (!targets.length) return null
  return (
    <section aria-labelledby={titleId} className="flex min-w-0 flex-col gap-2">
      <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
        {title}
      </h2>
      <TargetSummaryList title={title} targets={targets} asOf={asOf} badges={badges} />
    </section>
  )
}
