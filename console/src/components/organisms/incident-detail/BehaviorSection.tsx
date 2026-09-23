import type { BehaviorRow } from '@/api/incidents'
import { Time } from '../../atoms/Time'
import { DetailSection } from './DetailSection'
import { MAX_ROWS, summarizeBehavior } from './format'
import { TABLE } from './table-styles'

export interface BehaviorSectionProps {
  rows: BehaviorRow[]
  /** 출발지. 없으면(대상만 있는 건) 행위를 모을 수 없다 */
  actorIp: string | null
  className?: string
}

/**
 * ② 규칙이 보지 않은 증거: 같은 구간(앞 5분 · 뒤 30분) 같은 출발지가 실제로 한 일.
 * 로그인 성공 · 명령 · 파일 · 경유 · 요청. 규칙이 본 것만으로 판정하면 규칙의 시야를 그대로 물려받는다(판정 기준 5장).
 */
export function BehaviorSection({ rows, actorIp, className }: BehaviorSectionProps) {
  const shown = rows.slice(0, MAX_ROWS)
  return (
    <DetailSection
      number="②"
      title="규칙이 보지 않은 증거"
      aside={<span>구간 앞 5분 · 뒤 30분 · {rows.length}행</span>}
      padding={shown.length > 0 ? 'none' : 'md'}
      className={className}
    >
      {actorIp === null ? (
        <p className="m-0 text-xs text-ink-muted">출발지가 없는 사건이라 같은 출발지의 행위를 모을 수 없습니다.</p>
      ) : shown.length === 0 ? (
        <p className="m-0 text-xs text-ink-muted">
          이 구간에서 추가 행위 기록을 찾지 못했습니다. 수집 누락이나 관측 범위 밖의 행위가 없는지는 별도로 확인하세요.
        </p>
      ) : (
        <>
          <div className={`${TABLE.wrap} max-h-[420px]`}>
            <table className={TABLE.table} aria-label="같은 출발지의 실제 행위">
              <thead>
                <tr>
                  <th scope="col" className={TABLE.th}>
                    시각 (KST)
                  </th>
                  <th scope="col" className={TABLE.th}>
                    센서
                  </th>
                  <th scope="col" className={TABLE.th}>
                    이벤트
                  </th>
                  <th scope="col" className={`${TABLE.th} w-full`}>
                    요약
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((row, i) => (
                  <tr key={`${row.ts}-${row.eventid}-${i}`}>
                    <td className={`${TABLE.td} ${TABLE.mono}`}>
                      <Time value={row.ts} format="datetime" />
                    </td>
                    <td className={`${TABLE.td} whitespace-nowrap`}>{row.sensor}</td>
                    <td className={`${TABLE.td} ${TABLE.mono}`}>{row.eventid}</td>
                    <td className={`${TABLE.td} font-mono break-all`}>{summarizeBehavior(row)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length > MAX_ROWS && (
            <p className="m-0 px-4 py-2 text-xs text-ink-muted">처음 {MAX_ROWS}행만 보입니다 (전체 {rows.length}행).</p>
          )}
        </>
      )}
    </DetailSection>
  )
}
