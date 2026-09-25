import type { IncidentDetail } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { VERDICT_LABEL } from '@/lib/domain'
import { formatDuration } from '@/lib/time'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { mergeHistory } from './format'
import { TABLE } from './table-styles'

export interface HistoryListProps {
  detail: Pick<IncidentDetail, 'verdicts' | 'actions'>
  className?: string
}

/** 판정 · 조치 이력. 시각(KST) · 종류 · 값 · 행위자 · 사유/메모. 최근 것이 위 */
export function HistoryList({ detail, className }: HistoryListProps) {
  const entries = mergeHistory(detail)
  if (entries.length === 0) {
    return <p className={cn('m-0 text-xs text-ink-muted', className)}>아직 판정 · 조치 기록이 없습니다.</p>
  }
  return (
    <div className={cn(TABLE.wrap, className)}>
      <table className={TABLE.table} aria-label="판정 · 조치 이력">
        <thead>
          <tr>
            <th scope="col" className={TABLE.th}>
              시각 (KST)
            </th>
            <th scope="col" className={TABLE.th}>
              종류
            </th>
            <th scope="col" className={TABLE.th}>
              값
            </th>
            <th scope="col" className={TABLE.th}>
              행위자
            </th>
            <th scope="col" className={`${TABLE.th} w-full`}>
              사유 · 메모
            </th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={`${entry.kind}-${entry.id}`} data-history-kind={entry.kind}>
              <td className={`${TABLE.td} ${TABLE.mono}`}>
                <Time value={entry.created_at} format="datetime" />
              </td>
              <td className={TABLE.td}>{entry.kind === 'verdict' ? '판정' : '조치'}</td>
              <td className={`${TABLE.td} whitespace-nowrap`}>
                {entry.verdict ? <VerdictBadge verdict={entry.verdict} /> : <Badge tone="info">{entry.label}</Badge>}
                {entry.observed_value !== null && entry.observed_value !== undefined && (
                  <span className="ml-1.5 text-ink-muted tabular-nums">관측 {entry.observed_value}</span>
                )}
                {entry.verdict && (
                  <div className="mt-1 text-xs text-ink-muted">
                    {entry.proposed
                      ? `제안 ${VERDICT_LABEL[entry.proposed]} · ${entry.proposed === entry.verdict ? '제안 수락' : '제안 뒤집힘'}`
                      : '제안 기록 없음'}
                    {entry.decision_seconds != null && ` · 소요 ${formatDuration(entry.decision_seconds * 1000)}`}
                  </div>
                )}
              </td>
              <td className={`${TABLE.td} whitespace-nowrap`}>
                <UntrustedText value={entry.operator} max={64} />
              </td>
              <td className={`${TABLE.td} break-words`}>
                <UntrustedText value={entry.note} fallback={<span className="text-ink-muted">—</span>} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
