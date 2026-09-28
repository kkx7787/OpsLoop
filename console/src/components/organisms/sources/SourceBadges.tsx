import { VERDICTS } from '@/lib/domain'
import type { VerdictCounts } from '@/api/sources'
import { Badge } from '../../atoms/Badge'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { targetLabel } from './model'

/**
 * 주소 옆 표지: 시험 대역 · 차단 금지 대역. 금지 대역 표를 읽을 수 없으면(exempt null) '금지 대역 확인 불가'.
 * 금지 대역은 사설 · 예약 · 인프라 주소라 차단하지 않는다(관리망 주소가 R101 등으로 목록에 들어온다)
 */
export function SourceMarks({ testSource, exempt }: { testSource: boolean | undefined; exempt: boolean | null | undefined }) {
  if (!testSource && exempt === false) return null
  return (
    <span className="inline-flex flex-wrap gap-1">
      {testSource && <Badge tone="violet">시험 대역</Badge>}
      {exempt === true && <Badge>차단 금지 대역</Badge>}
      {exempt === null && <Badge tone="warning" title="차단 금지 대역 표를 읽을 수 없습니다">금지 대역 확인 불가</Badge>}
    </span>
  )
}

/** 최신 판정 분포. 0건인 판정값은 빼고, 판정이 하나도 없으면 '판정 없음' */
export function VerdictMix({ verdicts }: { verdicts: VerdictCounts }) {
  const shown = VERDICTS.filter((verdict) => (verdicts[verdict] ?? 0) > 0)
  if (!shown.length) return <span className="text-xs text-ink-muted">판정 없음</span>
  return (
    <ul className="m-0 flex list-none flex-wrap gap-1 p-0" aria-label="판정 분포">
      {shown.map((verdict) => (
        <li key={verdict} className="inline-flex items-center gap-1 text-xs tabular-nums">
          <VerdictBadge verdict={verdict} />
          {verdicts[verdict]}
        </li>
      ))}
    </ul>
  )
}

/** 노린 대상 이름. 모르는 값은 원문을 글자로만 */
export function TargetNames({ targets }: { targets: readonly string[] }) {
  if (!targets.length) return <span className="text-ink-muted">—</span>
  return (
    <span className="break-words">
      {targets.map((id, i) => (
        <span key={`${i}-${id}`}>
          {i > 0 && ' · '}
          {targetLabel(id) ?? <UntrustedText value={id} max={64} />}
        </span>
      ))}
    </span>
  )
}
