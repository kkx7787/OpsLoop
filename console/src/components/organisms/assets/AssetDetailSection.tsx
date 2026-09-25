/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import type { ReactNode } from 'react'
import {
  FIX_STATE_LABEL,
  lastVulnOffset,
  METHOD_LABEL,
  VULN_FILTERS,
  VULN_FILTER_LABEL,
  type AssetDetail,
  type AssetDetailResult,
  type AssetVulnPage,
  type VulnFilter,
} from '@/api/cti'
import { describeError } from '@/api/errors'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { Banner } from '@/components/molecules/Banner'
import { SegmentedControl } from '@/components/molecules/SegmentedControl'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cvssTone, FIX_STATE_TONE, formatCvss, formatPercentile, formatProbability, ransomwareLabel, truncate, ubuntuPriorityLabel, ubuntuPriorityTone } from './cti-format'

const HEAD = ['CVE', '패키지', '설치 버전', '수정 상태', 'KEV', 'CVSS', 'EPSS (백분위)', 'Ubuntu 등급', '요약']
const cell = 'px-4 py-3 align-top'
const FILTER_OPTIONS = VULN_FILTERS.map((value) => ({ value, label: VULN_FILTER_LABEL[value] }))
const EMPTY: Record<VulnFilter, string> = {
  all: '배포판 기준으로 알려진 취약점이 없습니다.',
  kev: 'KEV 에 있는 CVE 가 없습니다.',
  fix: '수정판이 있거나 재부팅하면 풀리는 취약점이 없습니다.',
}

export interface AssetDetailSectionProps {
  assetId: string
  /** 조회 결과. 없으면 첫 조회 중이거나 실패다 */
  data: AssetDetailResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  onRetry: () => void
  filter: VulnFilter
  offset: number
  /** 거르기를 바꾸면 첫 쪽부터 본다(페이지가 offset 을 0 으로) */
  onFilter: (filter: VulnFilter) => void
  onOffset: (offset: number) => void
  onClose: () => void
}

/**
 * 자산 한 대의 상세(표시만): 오래됨 · 오류 띠, OS · 커널 · 수집 시각, 주요 패키지, 도는 컨테이너 이미지, 배포판 취약점 표(거르기 · 쪽 넘김).
 * 조회 · 거르기 · 쪽 상태는 페이지가 갖는다. 컨테이너 이미지 안의 패키지는 조사하지 않아 대조에 들어가지 않는다(미확인).
 */
export function AssetDetailSection({ assetId, data, pending, fetching, error, onRetry, filter, offset, onFilter, onOffset, onClose }: AssetDetailSectionProps) {
  const asset = data?.asset
  return (
    <Card padding="none" className="min-w-0" role="region" aria-label={`${assetId} 자산 상세`}>
      <CardHeader
        title={<><span className="font-mono">{assetId}</span> 자산 상세</>}
        aside={<>
          {asset && <span>수집 <Time value={asset.collected_at} format="relative" /></span>}
          <Button size="sm" onClick={onClose}>닫기</Button>
        </>}
      />
      {pending ? <LoadingState className="m-4" /> : !data ? <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} className="m-4" /> : !data.available ? (
        <p className="p-4 text-sm text-ink-muted">공개 취약점 정보 표가 아직 없습니다.</p>
      ) : <>
        <div className="flex flex-col gap-4 p-4">
          {error ? <Banner tone="danger" title="다시 받지 못했습니다">{describeError(error)} · 이전 결과를 보입니다</Banner> : null}
          <AssetFacts asset={data.asset} />
        </div>
        <VulnTable page={data.vulnerabilities} checked={data.asset.checked_at !== null} filter={filter} offset={offset} fetching={fetching} onFilter={onFilter} onOffset={onOffset} />
      </>}
    </Card>
  )
}

/** 오래됨 · 오류 띠와 조사 결과 요약 */
function AssetFacts({ asset }: { asset: AssetDetail }) {
  const os = asset.os?.pretty ?? asset.os_pretty
  return <>
    {asset.stale && <Banner tone="warning">자산 정보가 오래됐습니다(마지막 수집 {asset.collected_at ? <Time value={asset.collected_at} format="minute" /> : '없음'}). 비해당으로 읽지 않습니다.</Banner>}
    {asset.last_error && <Banner tone="warning" title="마지막 수집 실패">{asset.last_error} · 이전 조사 결과를 보입니다</Banner>}
    {asset.check_error && <Banner tone="warning" title="배포판 대조 실패">{asset.check_error}</Banner>}

    <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-6">
      <Fact label="OS" value={os ?? '—'} />
      <Fact label="실행 커널" value={<span className="inline-flex flex-wrap items-center gap-1.5">
        <span className="font-mono">{asset.kernel_running_version ?? '—'}</span>
        {asset.reboot_pending && <Badge tone="orange" title={`설치된 최신 커널 ${asset.kernel_newest_version ?? '—'}`}>재부팅 대기</Badge>}
      </span>} />
      <Fact label="방법 · 호스트" value={<>{METHOD_LABEL[asset.method] ?? asset.method} · <span className="font-mono">{asset.host || '미기록'}</span></>} />
      <Fact label="수집 (KST)" value={<Time value={asset.collected_at} format="minute" />} />
      <Fact label="배포판 대조 (KST)" value={asset.checked_at ? <Time value={asset.checked_at} format="minute" /> : '대조 전'} />
      <Fact label="설치 패키지" value={`${asset.packages}개`} />
    </dl>

    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-ink-muted">주요 패키지</span>
      {asset.key_packages.length === 0 ? <span className="text-xs text-ink-muted">없음</span> : (
        <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3 lg:grid-cols-4">
          {asset.key_packages.map((p) => <Fact key={p.name} label={p.name} value={<span className="font-mono text-xs">{p.version}</span>} />)}
        </dl>
      )}
    </div>

    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-ink-muted">도는 컨테이너 {asset.images.length}개 · 이미지 안의 패키지는 조사하지 않아 취약점 대조에 들어가지 않습니다(미확인)</span>
      {asset.images.length === 0 ? <span className="text-xs text-ink-muted">없음</span> : (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-xs" aria-label="컨테이너 이미지">
          {asset.images.map((img) => <li key={`${img.container}-${img.image}`} className="break-all">
            <span className="font-medium">{img.container}</span> · <span className="font-mono">{img.image}</span>
          </li>)}
        </ul>
      )}
    </div>

    {asset.probe_errors.length > 0 && <div className="flex flex-col gap-1.5">
      <span className="text-xs text-ink-muted">조사 중 못 읽은 항목 · 이 항목은 미확인으로 둡니다</span>
      <ul className="m-0 flex list-none flex-col gap-1 p-0 font-mono text-xs text-warning">
        {asset.probe_errors.map((e, i) => <li key={i} className="break-all">{e}</li>)}
      </ul>
    </div>}
  </>
}

interface VulnTableProps {
  page: AssetVulnPage
  checked: boolean
  filter: VulnFilter
  offset: number
  fetching: boolean
  onFilter: (filter: VulnFilter) => void
  onOffset: (offset: number) => void
}

/**
 * 배포판 취약점 표. 정렬은 서버가 한다(KEV 먼저 → EPSS 높은 순 → 수정 상태 → CVE).
 * 총수가 있는데 이 쪽의 행이 비었으면(뒤쪽을 보는 동안 총수가 줄었다) '없음' 문구를 쓰지 않는다. 쪽 표시는 받은 쪽(page.offset) 기준이다
 */
function VulnTable({ page, checked, filter, offset, fetching, onFilter, onOffset }: VulnTableProps) {
  const { rows, total, limit } = page
  const shown = page.offset
  const from = Math.min(shown + 1, total)
  const to = Math.min(shown + rows.length, total)
  const pageEmpty = rows.length === 0 && total > 0
  const lastOffset = lastVulnOffset(total, limit)
  return <div className="border-t border-line">
    <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5">
      <h3 className="m-0 text-sm font-semibold">배포판 취약점 <span className="font-normal text-ink-muted">{total.toLocaleString()}건</span></h3>
      <SegmentedControl aria-label="취약점 거르기" options={FILTER_OPTIONS} value={filter} onChange={onFilter} />
    </div>
    {rows.length > 0 && <div className="overflow-x-auto" role="region" aria-label="배포판 취약점 표" tabIndex={0}>
      <table className="w-full min-w-[1080px] text-left text-sm">
        <thead className="border-y border-line text-xs text-ink-muted"><tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
        <tbody className="divide-y divide-line">{rows.map((v) => {
          const summary = v.kev?.name ?? v.summary
          return <tr key={`${v.source_package}-${v.osv_id}`} data-fix={v.fix_state}>
            <td className={`${cell} font-mono text-xs whitespace-nowrap`} title={v.osv_id}>{v.cve_id ?? v.osv_id}</td>
            <td className={`${cell} font-mono text-xs`}>{v.source_package}</td>
            <td className={`${cell} font-mono text-xs whitespace-nowrap`}>{v.version}</td>
            <td className={`${cell} text-xs`}>
              <Badge tone={FIX_STATE_TONE[v.fix_state] ?? 'neutral'}>{FIX_STATE_LABEL[v.fix_state] ?? v.fix_state}</Badge>
              {v.fixed_version && <div className="mt-1 whitespace-nowrap text-ink-muted">{v.fix_state === 'reboot_pending' ? '설치된 커널' : '수정판'} <span className="font-mono">{v.fixed_version}</span></div>}
            </td>
            <td className={`${cell} text-xs whitespace-nowrap`}>
              {v.kev ? <>
                <Badge tone="danger">KEV</Badge> <span className="font-mono">{v.kev.date_added}</span>
                {v.kev.ransomware?.toLowerCase() === 'known' && <div className="mt-1"><Badge tone="danger">랜섬웨어 {ransomwareLabel(v.kev.ransomware)}</Badge></div>}
              </> : <span className="text-ink-muted">—</span>}
            </td>
            <td className={cell}>{v.cvss ? <Badge tone={cvssTone(v.cvss.severity)}>{formatCvss(v.cvss.score, v.cvss.severity)}</Badge> : <span className="text-ink-muted">—</span>}</td>
            <td className={`${cell} font-mono text-xs whitespace-nowrap`}>{v.epss ? <>{formatProbability(v.epss.score)} <span className="text-ink-muted">({formatPercentile(v.epss.percentile)})</span></> : <span className="text-ink-muted">—</span>}</td>
            <td className={cell}>{v.ubuntu_priority ? <Badge tone={ubuntuPriorityTone(v.ubuntu_priority)}>{ubuntuPriorityLabel(v.ubuntu_priority)}</Badge> : <span className="text-ink-muted">—</span>}</td>
            <td className={`${cell} min-w-[240px] text-xs`} title={summary ?? undefined}>{truncate(summary)}</td>
          </tr>
        })}</tbody>
      </table>
    </div>}
    {pageEmpty && <div className="flex flex-wrap items-center gap-2 px-4 pb-4 text-sm text-ink-muted">
      <p className="m-0">이 쪽에는 행이 없습니다. 전체 {total.toLocaleString()}건 · 그사이 목록이 바뀌었을 수 있습니다.</p>
      {shown !== lastOffset && <Button size="sm" disabled={fetching} onClick={() => onOffset(lastOffset)}>마지막 쪽 보기</Button>}
    </div>}
    {rows.length === 0 && total === 0 && <p className="m-0 px-4 pb-4 text-sm text-ink-muted">{checked ? EMPTY[filter] : '배포판 취약점 대조 전입니다. 비해당으로 읽지 않습니다.'}</p>}
    {total > 0 && <nav aria-label="배포판 취약점 쪽" className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3 py-2">
      <span className="text-xs text-ink-muted" aria-live="polite">{rows.length > 0 ? `${from}–${to}` : '—'} / {total.toLocaleString()}건</span>
      <div className="flex items-center gap-1">
        <Button size="sm" disabled={offset <= 0 || fetching} onClick={() => onOffset(Math.max(0, offset - limit))}>이전</Button>
        <Button size="sm" disabled={offset + limit >= total || fetching} onClick={() => onOffset(offset + limit)}>다음</Button>
      </div>
    </nav>}
  </div>
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-medium break-words tabular-nums">{value}</dd>
    </div>
  )
}
