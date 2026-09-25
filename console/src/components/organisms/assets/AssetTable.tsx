/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { METHOD_LABEL, ROLE_LABEL, type AssetRow } from '@/api/cti'
import { Badge } from '@/components/atoms/Badge'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { formatProbability } from './cti-format'

const HEAD = ['자산', '역할', '방법', '수집 (KST)', '커널', '취약점', 'KEV', '수정판 있음', '최고 EPSS', '오류']
const cell = 'px-4 py-3 align-top'

export interface AssetTableProps {
  rows: AssetRow[]
  /** 상세가 열린 자산. 없으면 빈 문자열 */
  selected: string
  onSelect: (assetId: string) => void
}

/**
 * 자산 표(표시만). 조회 · 선택 상태는 페이지가 갖는다. 자산 이름을 누르면 상세가 열린다.
 * 대조 전인 자산은 취약점 수를 0 으로 보이지 않고 '대조 전'으로 적는다(0건은 '없음'으로 읽히기 때문이다).
 */
export function AssetTable({ rows, selected, onSelect }: AssetTableProps) {
  return (
    <Card padding="none" className="min-w-0">
      <CardHeader title={`자산 ${rows.length}대`} aside="자산 이름을 누르면 상세가 열립니다" />
      <div className="overflow-x-auto" role="region" aria-label="자산 표" tabIndex={0}>
        <table className="w-full min-w-[980px] text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted">
            <tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-line">{rows.map((r) => {
            const active = r.asset_id === selected
            const checked = r.checked_at !== null
            return <tr key={r.asset_id} data-asset={r.asset_id} className={active ? 'bg-primary-soft' : undefined}>
              <th scope="row" className={`${cell} font-normal`}>
                <button type="button" aria-pressed={active} onClick={() => onSelect(r.asset_id)} className="cursor-pointer font-mono font-semibold text-primary hover:underline">{r.asset_id}</button>
                <div className="text-xs text-ink-muted">{r.host || '미기록'}</div>
              </th>
              <td className={`${cell} whitespace-nowrap`}>{ROLE_LABEL[r.role] ?? r.role}</td>
              <td className={cell}>{METHOD_LABEL[r.method] ?? r.method}</td>
              <td className={`${cell} text-xs whitespace-nowrap`}>
                {r.collected_at ? <Time value={r.collected_at} format="short" /> : <span className="text-ink-muted">미수집</span>}
                {r.stale && <Badge tone="warning" className="ml-1.5">오래됨</Badge>}
              </td>
              <td className={`${cell} text-xs`}>
                <div className="font-mono whitespace-nowrap" title={r.os_pretty ?? undefined}>{r.kernel_running_version ?? '—'}</div>
                {r.reboot_pending && <Badge tone="orange" className="mt-1" title={`설치된 최신 커널 ${r.kernel_newest_version ?? '—'}`}>재부팅 대기</Badge>}
              </td>
              <td className={`${cell} tabular-nums whitespace-nowrap`}>{checked ? `${r.vuln_total}건` : <span className="text-ink-muted">대조 전</span>}</td>
              <td className={`${cell} whitespace-nowrap`}>{!checked ? <span className="text-ink-muted">—</span> : r.vuln_kev > 0 ? <Badge tone="danger">{r.vuln_kev}건</Badge> : '0건'}</td>
              <td className={`${cell} tabular-nums whitespace-nowrap`}>
                {checked ? <>{r.vuln_fix_available}건{r.vuln_reboot_pending > 0 && <span className="text-ink-muted"> · 재부팅 {r.vuln_reboot_pending}건</span>}</> : <span className="text-ink-muted">—</span>}
              </td>
              <td className={`${cell} font-mono text-xs`}>{formatProbability(r.max_epss)}</td>
              <td className={`${cell} max-w-64 text-xs`}>
                {!r.last_error && !r.check_error && <span className="text-ink-muted">—</span>}
                {r.last_error && <div className="break-keep text-danger">수집 · {r.last_error}</div>}
                {r.check_error && <div className="break-keep text-warning">대조 · {r.check_error}</div>}
              </td>
            </tr>
          })}</tbody>
        </table>
      </div>
      {!rows.length && <p className="p-4 text-sm text-ink-muted">수집한 자산이 없습니다. Mac 에서 자산 수집(collect-assets.sh)을 한 번 돌리면 채워집니다.</p>}
    </Card>
  )
}
