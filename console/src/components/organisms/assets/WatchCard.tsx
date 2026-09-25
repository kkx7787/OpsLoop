/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { Fragment, useId, useState, type ReactNode } from 'react'
import { APPLICABILITY_LABEL, ROLE_LABEL, type WatchResult, type WatchRow } from '@/api/cti'
import { describeError, isApiError } from '@/api/errors'
import { Badge } from '@/components/atoms/Badge'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { Banner } from '@/components/molecules/Banner'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { APPLICABILITY_TONE, cvssTone, formatCvss, formatPercentile, formatProbability, ransomwareLabel, staleSources, ubuntuPriorityLabel, ubuntuPriorityTone } from './cti-format'

const HEAD = ['CVE', '주목 이유', 'KEV', 'EPSS (백분위)', '판정', '자산별 판정']
const ASSET_HEAD = ['자산', '판정', '패키지', '설치 버전', '배포판 수정판', '이유']
const cell = 'px-4 py-3 align-top'
const subCell = 'px-2.5 py-1.5 align-top shadow-hairline'

export interface WatchCardProps {
  /** GET /api/cti/watch 응답. 없으면 첫 조회 중이거나 실패다 */
  data: WatchResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  onRetry: () => void
}

/**
 * 주목 CVE(#39): 널리 알려진 CVE 몇 개를 정해 두고(cti/watchlist.json) 자산마다 설치 버전을 배포판 수정판과 견준 결과(표시만).
 * 자산 취약점 표는 '걸린 것'만 담으므로, 이미 고쳐진 CVE 도 '비해당'이라는 대조 결과로 보이려고 따로 둔다.
 * 판정(해당 · 비해당 · 미확인)과 이유는 서버가 정하고 화면은 옮겨 적기만 한다. 행을 펼치면 자산마다 패키지 · 설치 · 수정판을 보인다.
 * 404 는 이 기능을 모르는 이전 서버로 보고 안내 한 줄만, 그 밖의 오류는 카드 안에서 다시 시도할 수 있게 보인다.
 */
export function WatchCard({ data, pending, fetching, error, onRetry }: WatchCardProps) {
  const rows = data?.available ? data.rows : []
  const affected = rows.filter((r) => r.summary === 'affected').length
  return (
    <Card padding="none" className="min-w-0" role="region" aria-label="주목 CVE">
      <CardHeader
        title="주목 CVE"
        aside={data?.available ? <span>{rows.length}건 · 해당 {affected}건 · <Time value={data.as_of} format="time" zone /> 기준</span> : undefined}
      />
      {pending ? <LoadingState className="m-4" /> : !data ? (
        isApiError(error) && error.status === 404
          ? <p className="m-0 p-4 text-sm text-ink-muted">주목 CVE 정보가 없습니다. 콘솔 API 가 이 기능 이전 판일 수 있습니다.</p>
          : <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} titleAs="h3" className="m-4" />
      ) : !data.available ? (
        <p className="m-0 p-4 text-sm text-ink-muted">주목 CVE 표가 아직 없습니다. 서버에 CTI 마이그레이션을 적용하고 수집기를 한 번 돌리면 보입니다.</p>
      ) : <WatchBody data={data} error={error} />}
    </Card>
  )
}

function WatchBody({ data, error }: { data: WatchResult; error: unknown }) {
  const stale = staleSources(data.freshness)
  return <>
    <div className="flex flex-col gap-3 p-4">
      <p className="m-0 text-xs leading-5 text-ink-muted">
        널리 알려진 CVE 를 정해 두고 자산마다 설치 버전을 배포판(Ubuntu) 수정판과 견줍니다. 조사 · 조치 우선순위 참고용이며 판정 근거가 아닙니다.
      </p>
      {error ? <Banner tone="danger" title="다시 받지 못했습니다">{describeError(error)} · 이전 결과를 보입니다</Banner> : null}
      {stale.length > 0 && <Banner tone="warning">공개 정보가 오래돼 이 표의 비해당도 비해당으로 읽지 않습니다. 오래된 출처: {stale.join(' · ')}</Banner>}
    </div>
    {data.rows.length === 0
      ? <p className="m-0 border-t border-line p-4 text-sm text-ink-muted">주목 CVE 목록이 비어 있습니다. 수집기의 목록(cti/watchlist.json)을 확인합니다.</p>
      : <WatchTable rows={data.rows} />}
  </>
}

/** 주목 CVE 표. 정렬은 서버가 한다(해당 먼저 → KEV → EPSS 높은 순 → CVE). 펼친 행은 이 카드 안에서만 기억한다 */
function WatchTable({ rows }: { rows: WatchRow[] }) {
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set())
  const baseId = useId()
  const toggle = (cve: string) => setOpen((prev) => {
    const next = new Set(prev)
    if (next.has(cve)) next.delete(cve)
    else next.add(cve)
    return next
  })
  return (
    <div className="overflow-x-auto border-t border-line" role="region" aria-label="주목 CVE 표" tabIndex={0}>
      <table className="w-full min-w-[980px] text-left text-sm">
        <thead className="border-b border-line text-xs text-ink-muted">
          <tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-line">{rows.map((r) => {
          const expanded = open.has(r.cve_id)
          const detailId = `${baseId}-${r.cve_id}`
          return <Fragment key={r.cve_id}>
            <tr data-cve={r.cve_id} data-summary={r.summary}>
              <th scope="row" className={`${cell} font-normal whitespace-nowrap`}>
                <button type="button" aria-expanded={expanded} aria-controls={detailId} onClick={() => toggle(r.cve_id)} className="inline-flex cursor-pointer items-center gap-1 font-mono text-xs font-semibold text-primary hover:underline">
                  <span aria-hidden="true" className="inline-block w-3 text-ink-muted">{expanded ? '▾' : '▸'}</span>{r.cve_id}
                </button>
              </th>
              <td className={`${cell} min-w-[220px] text-xs leading-5`}>{r.reason}</td>
              <td className={`${cell} text-xs whitespace-nowrap`}>
                {r.kev ? <>
                  <Badge tone="danger">KEV</Badge> <span className="font-mono">{r.kev.date_added}</span>
                  {r.kev.ransomware?.toLowerCase() === 'known' && <div className="mt-1"><Badge tone="danger">랜섬웨어 {ransomwareLabel(r.kev.ransomware)}</Badge></div>}
                </> : <span className="text-ink-muted">—</span>}
              </td>
              <td className={`${cell} font-mono text-xs whitespace-nowrap`}>
                {r.epss ? <>{formatProbability(r.epss.score)} <span className="text-ink-muted">({formatPercentile(r.epss.percentile)})</span></> : <span className="text-ink-muted">—</span>}
              </td>
              <td className={cell}><Badge tone={APPLICABILITY_TONE[r.summary] ?? 'neutral'}>{APPLICABILITY_LABEL[r.summary] ?? r.summary}</Badge></td>
              <td className={cell}>
                {r.assets.length === 0 ? <span className="text-xs text-ink-muted">자산 없음</span> : (
                  <ul className="m-0 flex list-none flex-wrap gap-1 p-0" aria-label={`${r.cve_id} 자산별 판정`}>
                    {r.assets.map((a) => <li key={a.asset_id}>
                      <Badge tone={APPLICABILITY_TONE[a.status] ?? 'neutral'} title={a.reason}>
                        <span className="font-mono">{a.asset_id}</span> {APPLICABILITY_LABEL[a.status] ?? a.status}
                      </Badge>
                    </li>)}
                  </ul>
                )}
              </td>
            </tr>
            {expanded && <tr id={detailId} data-detail={r.cve_id} className="bg-canvas/60">
              <td colSpan={HEAD.length} className="px-4 py-3"><WatchDetail row={r} /></td>
            </tr>}
          </Fragment>
        })}</tbody>
      </table>
    </div>
  )
}

/** 펼친 행: 설명 · 배포판 기록 · 영향 패키지 · 자산별 이유(패키지 · 설치 · 수정판) */
function WatchDetail({ row: r }: { row: WatchRow }) {
  return (
    <div className="flex flex-col gap-3 text-xs">
      {r.description && <p className="m-0 max-w-4xl leading-5">{r.description}</p>}
      <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        <Fact label="배포판 기록" value={r.record_found === null ? <span className="text-warning">조회 전</span> : r.record_found ? <span className="font-mono">{r.osv_id ?? '—'}</span> : <span className="text-warning">기록 없음</span>} />
        <Fact label="Ubuntu 등급" value={r.ubuntu_priority ? <Badge tone={ubuntuPriorityTone(r.ubuntu_priority)}>{ubuntuPriorityLabel(r.ubuntu_priority)}</Badge> : '—'} />
        <Fact label="CVSS" value={r.cvss ? <Badge tone={cvssTone(r.cvss.severity)}>{formatCvss(r.cvss.score, r.cvss.severity)}</Badge> : '—'} />
        <Fact label="기록 조회 (KST)" value={r.checked_at ? <Time value={r.checked_at} format="minute" /> : '—'} />
      </dl>
      <div className="flex flex-col gap-1">
        <span className="text-ink-muted">배포판 영향 패키지</span>
        {r.affected_packages.length === 0 ? (
          <span className="text-ink-muted">{r.record_found ? '이 릴리스의 영향 패키지가 기록에 없습니다.' : '배포판 기록이 없어 영향 패키지를 모릅니다.'}</span>
        ) : (
          <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0" aria-label={`${r.cve_id} 영향 패키지`}>
            {r.affected_packages.map((p) => <li key={`${p.ecosystem ?? ''}/${p.package}`}>
              <span className="font-mono font-medium">{p.package}</span>
              {p.ecosystem && <span className="text-ink-muted"> ({p.ecosystem})</span>}
              {' · '}
              {p.fixed ? <>수정판 <span className="font-mono">{p.fixed}</span></> : <span className="text-warning">배포판 수정판 없음</span>}
            </li>)}
          </ul>
        )}
      </div>
      {r.assets.length > 0 && <div className="w-full overflow-auto">
        <table className="w-full border-collapse text-xs" aria-label={`${r.cve_id} 자산별 대조`}>
          <thead><tr>{ASSET_HEAD.map((t) => <th key={t} scope="col" className="px-2.5 py-2 text-left font-medium whitespace-nowrap text-ink-muted shadow-hairline">{t}</th>)}</tr></thead>
          <tbody>{r.assets.map((a) => <tr key={a.asset_id} data-asset={a.asset_id} data-status={a.status}>
            <td className={`${subCell} whitespace-nowrap`}><span className="font-mono font-medium">{a.asset_id}</span> <span className="text-ink-muted">{ROLE_LABEL[a.role] ?? a.role}</span></td>
            <td className={subCell}><Badge tone={APPLICABILITY_TONE[a.status] ?? 'neutral'}>{APPLICABILITY_LABEL[a.status] ?? a.status}</Badge></td>
            <td className={`${subCell} font-mono`}>{a.package ?? '—'}</td>
            <td className={`${subCell} font-mono whitespace-nowrap`}>{a.installed ?? '—'}</td>
            <td className={`${subCell} font-mono whitespace-nowrap`}>{a.fixed ?? (a.package ? <span className="font-sans text-warning">없음</span> : '—')}</td>
            <td className={`${subCell} min-w-[220px]`}>{a.reason}</td>
          </tr>)}</tbody>
        </table>
      </div>}
    </div>
  )
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-medium break-words">{value}</dd>
    </div>
  )
}
