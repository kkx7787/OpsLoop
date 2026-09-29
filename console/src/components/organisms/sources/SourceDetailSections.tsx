import { useId, type ReactNode } from 'react'
import { Link } from 'react-router'
import { FINGERPRINT_KINDS, FINGERPRINT_LABEL, type SourceDetail } from '@/api/sources'
import { actionLabel } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { InfoTip } from '../../molecules/InfoTip'
import { DetailSection } from '../incident-detail/DetailSection'
import { incidentHref } from '../incident-detail/format'
import { StatusBadge } from '../incident-detail/StatusBadge'
import { TABLE } from '../incident-detail/table-styles'
import { SourceBlockDetail } from './SourceBlock'
import { TargetNames, VerdictMix } from './SourceBadges'
import { fingerprintHref, incidentsOfHref, SAME_TOOL_NOTE, SAME_TOOL_REASON, sourceExempt } from './model'

/**
 * 출발지 상세(S-09)의 구역들. 모양은 사건 상세의 구역(DetailSection · TABLE)을 따른다.
 * 좁은 화면에서는 표가 responsive-table 로 행마다 쌓인다.
 */

interface SectionProps {
  detail: SourceDetail
  className?: string
}

const ABSORBED_TIP = '같은 페이로드 흡수로 지워진 사건 기록 수입니다. 흡수된 사건은 사건 수에 들지 않습니다.'

/** 흡수 기록 항목. 표를 읽을 수 없으면 0 이 아니라 확인 불가 */
function AbsorbedFact({ absorbed }: { absorbed: number | null }) {
  return (
    <Fact
      label="흡수 기록"
      tip={ABSORBED_TIP}
      value={absorbed === null ? <span className="text-warning">확인 불가</span> : `${absorbed.toLocaleString('ko-KR')}건`}
    />
  )
}

/**
 * ① 요약: 사건 · 미판정 · 최고 심각도 · 첫/마지막 사건 · 마지막 관측 · 규칙 · 대상 · 흡수 기록 · 판정 분포.
 * 마지막 관측은 수집 이벤트 기준이라 사건 없는 출발지도 보인다(사건 뒤에도 이어졌는지 본다). 계산 기준은 항목 이름 옆 ⓘ
 */
export function SourceSummarySection({ detail, className }: SectionProps) {
  const { summary } = detail
  return (
    <DetailSection number="①" title="요약" aside={<>기준 <Time value={detail.as_of} format="datetime" /></>} className={className}>
      {summary ? (
        <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-4">
          <Fact label="사건" value={`${summary.incidents.toLocaleString('ko-KR')}건 · 미판정 ${summary.unjudged.toLocaleString('ko-KR')}`} />
          <Fact label="최고 심각도" value={<SeverityBadge severity={summary.severity} />} />
          <Fact label="첫 사건" value={<Time value={summary.first_ts} format="datetime" />} />
          <Fact label="마지막 사건" value={<Time value={summary.last_ts} format="datetime" />} />
          <Fact label="마지막 관측" value={<Time value={detail.last_seen} format="datetime" />} />
          <Fact label="규칙" value={<span className="font-mono text-xs">{summary.rules.join(' · ') || '—'}</span>} />
          <Fact label="노린 대상" value={<TargetNames targets={summary.targets} />} />
          <AbsorbedFact absorbed={detail.absorbed} />
          <Fact label="판정 분포" tip="사건마다 마지막 판정입니다." value={<VerdictMix verdicts={summary.verdicts} />} wide />
        </dl>
      ) : (
        <>
          <p className="m-0 text-sm text-ink-muted">사건 없음 · 수집 이벤트만 있습니다</p>
          <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-4">
            <Fact label="마지막 관측" value={<Time value={detail.last_seen} format="datetime" />} />
            <AbsorbedFact absorbed={detail.absorbed} />
          </dl>
        </>
      )}
    </DetailSection>
  )
}

/** ② 사건 흐름: 첫 시각 순. 규칙을 누르면 사건 상세 */
export function SourceIncidentsSection({ detail, className }: SectionProps) {
  const { incidents, incidents_total: total } = detail
  return (
    <DetailSection number="②" title="사건 흐름" padding="none" aside={`첫 시각 순 · ${total.toLocaleString('ko-KR')}건`} className={className}>
      {incidents.length === 0 ? (
        <p className="m-0 p-4 text-sm text-ink-muted">사건이 없습니다.</p>
      ) : (
        <div className={`${TABLE.wrap} max-h-[420px]`}>
          <table className={`${TABLE.table} responsive-table`} aria-label="사건 흐름">
            <thead>
              <tr>
                {['규칙', '심각도', '상태', '판정', '대상', '첫 시각 (KST)', '마지막 (KST)'].map((label) => (
                  <th key={label} scope="col" className={TABLE.th}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {incidents.map((row) => (
                <tr key={row.incident_key}>
                  <td className={TABLE.td}>
                    <Link to={incidentHref(row.incident_key)} className="font-mono font-medium" title={revealHidden(row.incident_key)}>{row.rule_id}</Link>
                    <span className="ml-1 font-mono text-xs text-ink-muted"><UntrustedText value={row.rule_version} max={16} clip /></span>
                    <span className="ml-1.5 text-ink-muted"><UntrustedText value={row.rule_name} max={64} clip /></span>
                  </td>
                  <td data-label="심각도" className={TABLE.td}><SeverityBadge severity={row.severity} /></td>
                  <td data-label="상태" className={TABLE.td}><StatusBadge status={row.status} /></td>
                  <td data-label="판정" className={TABLE.td}>{row.verdict ? <VerdictBadge verdict={row.verdict} /> : <span className="text-warning">미판정</span>}</td>
                  <td data-label="대상" className={TABLE.td}><UntrustedText value={row.target} max={64} fallback="—" /></td>
                  <td data-label="첫 시각 (KST)" className={`${TABLE.td} ${TABLE.mono}`}><Time value={row.first_ts} format="datetime" /></td>
                  <td data-label="마지막 (KST)" className={`${TABLE.td} ${TABLE.mono}`}><Time value={row.last_ts} format="datetime" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {total > incidents.length && (
        <p className="m-0 border-t border-line px-4 py-2 text-xs text-ink-muted">
          앞 {incidents.length.toLocaleString('ko-KR')}건만 보입니다 · 전체 {total.toLocaleString('ko-KR')}건은 <Link to={incidentsOfHref(detail.ip)}>사건 목록</Link>에서 봅니다
        </p>
      )}
    </DetailSection>
  )
}

/** ③ 이벤트 종류: 발생원 · 이벤트별 수(실제 수집만). 발생원 · 이벤트 이름도 로그에서 온 글자라 글자로만 그린다 */
export function SourceEventsSection({ detail, className }: SectionProps) {
  const rows = detail.event_kinds
  return (
    <DetailSection number="③" title="이벤트 종류" padding="none" aside="수 많은 순 · 최대 50종" className={className}>
      {rows.length === 0 ? (
        <p className="m-0 p-4 text-sm text-ink-muted">수집 이벤트가 없습니다.</p>
      ) : (
        <div className={`${TABLE.wrap} max-h-[360px]`}>
          <table className={`${TABLE.table} responsive-table`} aria-label="이벤트 종류">
            <thead>
              <tr>
                {['발생원 · 이벤트', '수', '처음 (KST)', '마지막 (KST)'].map((label) => (
                  <th key={label} scope="col" className={TABLE.th}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={`${i}:${row.sensor}:${row.eventid}`}>
                  <td className={TABLE.td}>
                    <span className="text-ink-muted"><UntrustedText value={row.sensor} max={64} /></span>{' · '}
                    <span className="font-mono"><UntrustedText value={row.eventid} max={64} /></span>
                  </td>
                  <td data-label="수" className={`${TABLE.td} ${TABLE.mono}`}>{row.count.toLocaleString('ko-KR')}</td>
                  <td data-label="처음 (KST)" className={`${TABLE.td} ${TABLE.mono}`}><Time value={row.first_ts} format="short" /></td>
                  <td data-label="마지막 (KST)" className={`${TABLE.td} ${TABLE.mono}`}><Time value={row.last_ts} format="short" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DetailSection>
  )
}

/**
 * ④ 도구 지문: 종류마다 많이 쓴 값. 값은 공격자가 보낸 글자다. 같은 지문을 쓴 다른 출발지로 이어 간다.
 * 같은 지문 주의는 머리 오른쪽 ⓘ 에 둔다(본문 한 줄은 지문 조건 목록의 띠 한 곳). 제목 안에 두면 구역 이름에 섞인다
 */
export function SourceFingerprintsSection({ detail, className }: SectionProps) {
  return (
    <InfoTip label="도구 지문" render={({ button, panel }) => (
      <DetailSection number="④" title="도구 지문" aside={<span className="inline-flex items-center gap-1.5">종류마다 최대 10개 {button}</span>} className={className}>
        {panel}
        <FingerprintKinds detail={detail} />
      </DetailSection>
    )}>
      {SAME_TOOL_NOTE}. {SAME_TOOL_REASON}
    </InfoTip>
  )
}

function FingerprintKinds({ detail }: { detail: SourceDetail }) {
  return (
    <>
      {FINGERPRINT_KINDS.map((kind) => {
        const rows = detail.fingerprints[kind] ?? []
        return (
          <div key={kind} className="flex flex-col gap-1.5">
            <span className="text-xs font-medium text-ink-muted">{FINGERPRINT_LABEL[kind]}</span>
            {rows.length === 0 ? (
              <span className="text-xs text-ink-muted">기록 없음</span>
            ) : (
              <ul className="m-0 flex list-none flex-col gap-1.5 p-0" aria-label={`${FINGERPRINT_LABEL[kind]} 지문`}>
                {rows.map((row, i) => (
                  <li key={`${i}:${row.value}`} className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm">
                    <span className="min-w-0 font-mono text-xs break-all"><UntrustedText value={row.value} max={160} /></span>
                    <span className="text-xs text-ink-muted tabular-nums">{row.count.toLocaleString('ko-KR')}회</span>
                    <Link to={fingerprintHref(kind, row.value)} className="text-xs">같은 지문 출발지</Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )
      })}
    </>
  )
}

/** ⑤ 차단 상태: 지금 차단 목록 행 · 지점별 결과 · 금지 대역 */
export function SourceBlockSection({ detail, className }: SectionProps) {
  return (
    <DetailSection number="⑤" title="차단 상태" className={className}>
      <SourceBlockDetail
        block={detail.block}
        checkers={detail.checkers}
        now={Date.parse(detail.as_of)}
        exempt={sourceExempt(detail)}
        exemptRange={detail.exempt}
      />
    </DetailSection>
  )
}

/** ⑥ 조치 이력: 이 주소 사건들의 차단 · 해제 요청(최근 50건). 누가 풀고 걸었는지는 사건의 조치 이력과 같다 */
export function SourceActionsSection({ detail, className }: SectionProps) {
  const rows = detail.actions
  return (
    <DetailSection number="⑥" title="조치 이력" padding="none" aside="차단 · 해제 · 최근 50건" className={className}>
      {rows.length === 0 ? (
        <p className="m-0 p-4 text-sm text-ink-muted">차단 · 해제 조치가 없습니다.</p>
      ) : (
        <div className={`${TABLE.wrap} max-h-[360px]`}>
          <table className={`${TABLE.table} responsive-table`} aria-label="조치 이력">
            <thead>
              <tr>
                {['시각 (KST)', '조치', '요청자', '메모', '사건'].map((label) => (
                  <th key={label} scope="col" className={TABLE.th}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={`${i}:${row.incident_key}:${row.created_at}`}>
                  <td className={`${TABLE.td} ${TABLE.mono}`}><Time value={row.created_at} format="short" /></td>
                  <td data-label="조치" className={TABLE.td}><UntrustedText value={actionLabel(row.action)} max={32} /></td>
                  <td data-label="요청자" className={TABLE.td}><UntrustedText value={row.operator} max={64} fallback="미기록" /></td>
                  <td data-label="메모" className={TABLE.td}><UntrustedText value={row.note} max={160} fallback="—" /></td>
                  <td data-label="사건" className={TABLE.td}>
                    <Link to={incidentHref(row.incident_key)} className="font-mono" title={revealHidden(row.incident_key)}>{row.incident_key.split('|')[0]}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DetailSection>
  )
}

/** 요약 항목 하나. tip(계산 기준)이 있으면 이름 옆 ⓘ 로 두고 값이 그 설명을 읽는다 */
function Fact({ label, value, wide, tip }: { label: string; value: ReactNode; wide?: boolean; tip?: ReactNode }) {
  const id = useId()
  return (
    <div className={wide ? 'col-span-2 flex min-w-0 flex-col gap-0.5 sm:col-span-4' : 'flex min-w-0 flex-col gap-0.5'}>
      <dt className="text-xs text-ink-muted">
        {label}
        {tip && <>{' '}<InfoTip label={label} id={id}>{tip}</InfoTip></>}
      </dt>
      <dd className="m-0 min-w-0 font-medium break-words tabular-nums" aria-describedby={tip ? id : undefined}>{value}</dd>
    </div>
  )
}
