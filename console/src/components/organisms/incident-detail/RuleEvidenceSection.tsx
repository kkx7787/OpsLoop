import type { ReactNode } from 'react'
import type { IncidentDetail } from '@/api/incidents'
import { Banner } from '../../molecules/Banner'
import { Time } from '../../atoms/Time'
import { DetailSection } from './DetailSection'
import { formatValue, isSampleObject, sampleColumns } from './format'
import { TABLE } from './table-styles'

export interface RuleEvidenceSectionProps {
  detail: IncidentDetail
  className?: string
}

/** 표본 목록에서 한 번에 보이는 세션 수. 그 뒤는 개수만 보인다 */
const SESSIONS_SHOWN = 20

/**
 * ① 규칙이 본 것: 관측값 · 임계치와 비교된 값 · 신호 수 · 세션 수 · 규칙이 남긴 표본.
 * 순환 규칙(R002 · R003 · R004)은 판정 근거와 규칙 조건이 겹친다는 사실을 먼저 보인다(화면 설계 5장).
 */
export function RuleEvidenceSection({ detail, className }: RuleEvidenceSectionProps) {
  const evidence = detail.evidence
  const samples = evidence?.sample ?? []
  const sessions = evidence?.sessions ?? []
  const columns = sampleColumns(samples)
  const objectSamples = samples.filter(isSampleObject)
  const otherSamples = samples.filter((s) => !isSampleObject(s))

  return (
    <DetailSection number="①" title="규칙이 본 것" aside={<span>규칙 {detail.rule_id} {detail.rule_version}</span>} className={className}>
      {detail.circular && (
        <Banner tone="warning" title="순환 규칙">
          {detail.circular}. 이 규칙에서는 정탐률이 품질 지표가 되지 못하고 중복률을 본다.
        </Banner>
      )}

      <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-4">
        <Fact label="신호 수" value={`${detail.signal_count}건`} />
        <Fact label="세션 수" value={`${detail.session_count}개`} />
        <Fact
          label="관측값"
          value={
            evidence?.observed_count_max !== undefined
              ? `최대 ${evidence.observed_count_max}건`
              : evidence?.observed_sigma_max !== undefined
                ? `최대 ${evidence.observed_sigma_max}σ`
                : '—'
          }
        />
        <Fact
          label="구간"
          value={
            <>
              <Time value={detail.first_ts} format="time" /> ~ <Time value={detail.last_ts} format="time" />
            </>
          }
        />
      </dl>

      {samples.length === 0 && sessions.length === 0 ? (
        <p className="m-0 text-xs text-ink-muted">규칙이 남긴 표본이 없습니다.</p>
      ) : (
        <>
          {objectSamples.length > 0 && (
            <div className={TABLE.wrap}>
              <table className={TABLE.table} aria-label="규칙이 남긴 표본">
                <thead>
                  <tr>
                    {columns.map((col) => (
                      <th key={col} scope="col" className={TABLE.th}>
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {objectSamples.map((sample, i) => (
                    <tr key={i}>
                      {columns.map((col) => (
                        <td key={col} className={`${TABLE.td} font-mono break-all`}>
                          {formatValue(sample[col], col)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {otherSamples.length > 0 && (
            <ul className="m-0 flex list-none flex-col gap-1 p-0 font-mono text-xs">
              {otherSamples.map((sample, i) => (
                <li key={i} className="break-all">
                  {formatValue(sample)}
                </li>
              ))}
            </ul>
          )}
          {sessions.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-xs text-ink-muted">세션 {sessions.length}개</span>
              <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0">
                {sessions.slice(0, SESSIONS_SHOWN).map((session) => (
                  <li key={session} className="rounded-md bg-muted-soft px-2 py-0.5 font-mono text-2xs text-muted">
                    {session}
                  </li>
                ))}
                {sessions.length > SESSIONS_SHOWN && (
                  <li className="px-1 py-0.5 text-2xs text-ink-muted">+{sessions.length - SESSIONS_SHOWN}개</li>
                )}
              </ul>
            </div>
          )}
        </>
      )}
    </DetailSection>
  )
}

interface FactProps {
  label: string
  value: ReactNode
}

function Fact({ label, value }: FactProps) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="m-0 font-medium tabular-nums">{value}</dd>
    </div>
  )
}
