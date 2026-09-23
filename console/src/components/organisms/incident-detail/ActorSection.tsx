import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { ActorInfo, RelatedIncident } from '@/api/incidents'
import { Badge } from '../../atoms/Badge'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { DetailSection } from './DetailSection'
import { BLOCK_STATE_LABEL, BLOCK_STATE_TONE, blockState, incidentHref } from './format'
import { StatusBadge } from './StatusBadge'
import { TABLE } from './table-styles'

export interface ActorSectionProps {
  actor: ActorInfo
  related: RelatedIncident[]
  actorIp: string | null
  className?: string
}

/**
 * ③ 행위자 이력: 최초 · 최근 관측, 누적 이벤트, 관측된 센서, 다른 규칙 탐지, 차단 이력, 같은 출발지의 다른 사건.
 * 허니팟 · 디코이 접속 이력은 결정적 근거다. 그 자산에 접근한 출발지가 정상 사용자일 가능성은 사실상 없다(화면 설계 5장).
 */
export function ActorSection({ actor, related, actorIp, className }: ActorSectionProps) {
  const { history, rules, blocked } = actor
  const state = blocked ? blockState(blocked) : null
  return (
    <DetailSection number="③" title="행위자 이력" aside={actorIp && <span className="font-mono">{actorIp}</span>} className={className}>
      {actorIp === null ? (
        <p className="m-0 text-xs text-ink-muted">출발지가 없는 사건입니다. 대상(계정 · 노드) 기준의 이력은 아직 모으지 않습니다.</p>
      ) : (
        <>
          <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-4">
            <Fact label="최초 관측" value={<Time value={history?.first_seen} format="datetime" />} />
            <Fact label="최근 관측" value={<Time value={history?.last_seen} format="datetime" />} />
            <Fact label="누적 이벤트" value={history ? `${history.events}건` : '—'} />
            <Fact label="세션" value={history ? `${history.sessions}개` : '—'} />
          </dl>

          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-ink-muted">관측된 센서 · 허니팟 · 디코이 접속 이력은 결정적 근거다</span>
            {history?.sensors && history.sensors.length > 0 ? (
              <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0" aria-label="관측된 센서">
                {history.sensors.map((sensor) => (
                  <li key={sensor}>
                    <Badge tone="violet">{sensor}</Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-xs text-ink-muted">기록 없음</span>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-ink-muted">다른 규칙 탐지</span>
            {rules.length > 0 ? (
              <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0" aria-label="규칙별 사건 수">
                {rules.map((hit) => (
                  <li key={hit.rule_id}>
                    <Badge>
                      <span className="font-mono">{hit.rule_id}</span> {hit.incidents}건
                    </Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <span className="text-xs text-ink-muted">없음</span>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-ink-muted">차단 이력</span>
            {blocked && state ? (
              <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3" data-block-state={state}>
                <Fact label="상태" value={<Badge tone={BLOCK_STATE_TONE[state]}>{BLOCK_STATE_LABEL[state]}</Badge>} />
                <Fact label="사유" value={blocked.reason ?? '—'} />
                <Fact label="방식" value={blocked.method ?? '—'} />
                <Fact label="요청" value={<Time value={blocked.created_at} format="datetime" />} />
                <Fact label="집행" value={blocked.enforced_at ? <Time value={blocked.enforced_at} format="datetime" /> : '아직 집행 전'} />
                <Fact
                  label={blocked.released_at ? '해제' : '만료'}
                  value={blocked.released_at ? <Time value={blocked.released_at} format="datetime" /> : blocked.expires_at ? <Time value={blocked.expires_at} format="datetime" /> : '만료 없음'}
                />
              </dl>
            ) : (
              <span className="text-xs text-ink-muted">차단한 적 없음</span>
            )}
          </div>
        </>
      )}

      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-ink-muted">같은 출발지의 다른 사건 · 최근 {related.length}건</span>
        {related.length === 0 ? (
          <span className="text-xs text-ink-muted">없음</span>
        ) : (
          <div className={TABLE.wrap}>
            <table className={TABLE.table} aria-label="같은 출발지의 다른 사건">
              <thead>
                <tr>
                  <th scope="col" className={TABLE.th}>
                    규칙
                  </th>
                  <th scope="col" className={TABLE.th}>
                    심각도
                  </th>
                  <th scope="col" className={TABLE.th}>
                    발생 (KST)
                  </th>
                  <th scope="col" className={TABLE.th}>
                    신호
                  </th>
                  <th scope="col" className={TABLE.th}>
                    상태
                  </th>
                </tr>
              </thead>
              <tbody>
                {related.map((r) => (
                  <tr key={r.incident_key}>
                    <td className={TABLE.td}>
                      <Link to={incidentHref(r.incident_key)} className="font-mono font-medium" title={r.incident_key}>
                        {r.rule_id}
                      </Link>
                    </td>
                    <td className={TABLE.td}>
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className={`${TABLE.td} ${TABLE.mono}`}>
                      <Time value={r.first_ts} format="datetime" />
                    </td>
                    <td className={`${TABLE.td} ${TABLE.mono}`}>{r.signal_count}</td>
                    <td className={TABLE.td}>
                      <StatusBadge status={r.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </DetailSection>
  )
}

interface FactProps {
  label: string
  value: ReactNode
}

function Fact({ label, value }: FactProps) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-medium break-words tabular-nums">{value}</dd>
    </div>
  )
}
