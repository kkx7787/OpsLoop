import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { POINT_STATE_LABEL, POINT_STATE_TONE, type PointRow } from './format'

/**
 * 집행 지점별 결과 목록(이슈 #51). 지점 · 상태 · 그 상태가 된 시각 · 방식, 실패 · 확인 지연이면 까닭.
 * 방식 · 까닭은 지점이 보낸 값이라 글자로만 그린다. 지점이 없으면 아무것도 그리지 않는다(이전 서버 · 집행기)
 */
export function EnforcePointList({ points, className, compact = false }: { points: PointRow[]; className?: string; compact?: boolean }) {
  if (!points.length) return null
  return (
    <ul className={['m-0 flex list-none flex-col gap-1 p-0 text-xs', className].filter(Boolean).join(' ')} aria-label="집행 지점별 결과">
      {points.map(({ key, label, point }) => (
        <li key={key} data-enforce-point={key} data-point-state={point.state} className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <span className="text-ink-muted">{label}</span>
          <Badge tone={POINT_STATE_TONE[point.state]}>{POINT_STATE_LABEL[point.state]}</Badge>
          {!compact && point.since && <Time value={point.since} format="short" />}
          {!compact && point.mode && <span className="text-ink-muted">· <UntrustedText value={point.mode} max={16} /></span>}
          {point.note && (point.state === 'failed' || point.state === 'stale') && <span className="basis-full break-words text-ink-muted"><UntrustedText value={point.note} max={160} /></span>}
        </li>
      ))}
    </ul>
  )
}
