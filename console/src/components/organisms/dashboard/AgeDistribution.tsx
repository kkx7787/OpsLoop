import type { Summary } from '@/api/monitoring'
import { cn } from '@/lib/cn'
import { Card, CardHeader } from '../../atoms/Card'

const AGE_LABELS = ['1시간 미만', '1–4시간', '4–12시간', '12–24시간', '24시간 이상']

export interface AgeDistributionProps {
  /** 요약의 미판정 수 · 경과 분포(다섯 구간) */
  pending: Summary['pending']
  className?: string
}

/** 미판정 경과 시간 분포. 구간마다 건수와 전체 대비 막대(비율 글은 만들지 않는다) */
export function AgeDistribution({ pending, className }: AgeDistributionProps) {
  return (
    <Card padding="none" className={cn(className)}>
      <CardHeader title="미판정 경과 시간" />
      <ul className="m-0 flex list-none flex-col gap-4 p-4">
        {AGE_LABELS.map((label, index) => {
          const count = pending.age_distribution[index] ?? 0
          const percent = pending.total ? (count / pending.total) * 100 : 0
          return (
            <li key={label}>
              <div className="mb-1.5 flex justify-between gap-2 text-xs">
                <span>{label}</span>
                <span className="tabular-nums">{count.toLocaleString()}건</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-sm bg-line" aria-hidden="true">
                <div className="h-full bg-primary" style={{ width: `${percent}%` }} />
              </div>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
