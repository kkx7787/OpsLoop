import type { ReactNode } from 'react'
import type { CtiFreshness, SourceFreshness } from '@/api/cti'
import { cn } from '@/lib/cn'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'

export interface CtiFreshnessFactsProps {
  freshness: CtiFreshness
  className?: string
}

/**
 * 공개 정보 신선도: KEV · EPSS · 배포판 대조(OSV) · NVD 의 마지막 수집 시각과 원천 기준 시각, 가장 오래된 자산 수집 시각.
 * 오래됨은 서버가 정한다(STALE_HOURS). NVD 는 초점 CVE 만 받으므로 오래됨으로 보이지 않는다.
 */
export function CtiFreshnessFacts({ freshness, className }: CtiFreshnessFactsProps) {
  const { assets } = freshness
  return (
    <dl className={cn('m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-5', className)}>
      <SourceFact label="KEV 수집" source={freshness.kev} />
      <SourceFact label="EPSS 수집" source={freshness.epss} />
      <SourceFact label="배포판 대조" source={freshness.osv} />
      <SourceFact label="NVD 수집" source={freshness.nvd} />
      <Fact
        label="자산 수집 (가장 오래된)"
        value={<Stamp value={assets.oldest_collected_at} stale={assets.stale_assets.length > 0} />}
        note={assets.stale_assets.length > 0 ? `오래됨 · ${assets.stale_assets.join(' · ')}` : undefined}
      />
    </dl>
  )
}

function SourceFact({ label, source }: { label: string; source: SourceFreshness }) {
  return (
    <Fact
      label={label}
      value={<Stamp value={source.fetched_at} stale={source.stale} />}
      note={source.source_ts ? <>원천 기준 <Time value={source.source_ts} format="minute" /></> : undefined}
    />
  )
}

/** 받은 시각(KST, 분까지)과 오래됨 표지. 받은 적이 없으면 그렇게 적는다 */
function Stamp({ value, stale }: { value: string | null; stale: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {value ? <Time value={value} format="minute" /> : <span className="text-ink-muted">받은 적 없음</span>}
      {stale && <Badge tone="warning">오래됨</Badge>}
    </span>
  )
}

function Fact({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-medium break-words tabular-nums">
        {value}
        {note && <span className="block text-2xs font-normal text-ink-muted">{note}</span>}
      </dd>
    </div>
  )
}
