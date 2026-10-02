/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { METHOD_LABEL, ROLE_LABEL, type AssetRow } from '@/api/cti'
import { Badge } from '@/components/atoms/Badge'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { revealHidden } from '@/lib/untrusted'
import { fixUnknownNote, formatProbability, VULN_ROWS_NOTE } from './cti-format'

const HEAD = ['자산', '수집 (KST)', '취약점 · KEV', '수정판 · EPSS', '커널', '조사 상태']
const cell = 'px-4 py-3 align-top'

export interface AssetTableProps {
  rows: AssetRow[]
  /** 상세가 열린 자산. 없으면 빈 문자열 */
  selected: string
  onSelect: (assetId: string) => void
}

/**
 * 자산 표(표시만). 조회 · 선택 상태는 페이지가 갖는다. 자산 이름(단추)을 누르면 상세가 열린다.
 * 대조 전인 자산은 취약점 수를 0 으로 보이지 않고 '대조 전'으로 적는다(0건은 '없음'으로 읽히기 때문이다).
 * 수정 여부 미확인의 뜻(상세를 조회하지 않는 기록 포함 · 수정판 없음 아님)은 그 수의 말풍선으로 단다(#94).
 */
export function AssetTable({ rows, selected, onSelect }: AssetTableProps) {
  return (
    <Card padding="none" className="min-w-0">
      <CardHeader title={`자산 ${rows.length}대`} />
      <div className="overflow-x-auto" role="region" aria-label="자산 표" tabIndex={0}>
        <table className="responsive-table w-full table-fixed text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted">
            <tr>{HEAD.map((t) => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr>
          </thead>
          <tbody className="divide-y divide-line">{rows.map((r) => {
            const active = r.asset_id === selected
            const checked = r.checked_at !== null
            return <tr key={r.asset_id} data-asset={r.asset_id} className={active ? 'bg-primary-soft' : undefined}>
              <th scope="row" className={`${cell} font-normal`}>
                <button type="button" aria-pressed={active} onClick={() => onSelect(r.asset_id)} className="cursor-pointer font-mono font-semibold text-primary hover:underline">{r.asset_id}</button>
                <div className="mt-1 text-xs text-ink-muted">{ROLE_LABEL[r.role] ?? r.role}</div><div className="max-w-48 text-xs break-all text-ink-muted"><UntrustedText value={r.host} max={120} fallback="미기록" /></div>
              </th>
              <td data-label="수집 (KST)" className={`${cell} text-xs`}>
                {r.collected_at ? <Time value={r.collected_at} format="short" /> : <span className="text-ink-muted">미수집</span>}
                <div className="mt-1 text-ink-muted">{METHOD_LABEL[r.method] ?? r.method}{r.stale && <Badge tone="warning" className="ml-1.5">오래됨</Badge>}</div>
              </td>
              <td data-label="취약점 · KEV" className={`${cell} tabular-nums`}>
                {checked ? <><span className="font-semibold">{r.vuln_total}건</span><div className="mt-1 text-xs text-ink-muted">KEV {r.vuln_kev > 0 ? <Badge tone="danger">{r.vuln_kev}건</Badge> : '0건'}</div></> : <span className="text-ink-muted">대조 전</span>}
              </td>
              <td data-label="수정판 · EPSS" className={`${cell} text-xs tabular-nums`}>
                {checked ? <><span>{r.vuln_fix_available}건</span>{r.vuln_reboot_pending > 0 && <span className="text-ink-muted"> · 재부팅 {r.vuln_reboot_pending}건</span>}{(r.vuln_fix_unknown ?? 0) > 0 && <span className="text-ink-muted" title={`${fixUnknownNote(r.vuln_fix_unknown ?? 0)} ${VULN_ROWS_NOTE}`}> · 수정 여부 미확인 {r.vuln_fix_unknown}건</span>}</> : <span className="text-ink-muted">—</span>}
                <div className="mt-1 text-ink-muted">최고 EPSS <span className="font-mono">{formatProbability(r.max_epss)}</span></div>
              </td>
              <td data-label="커널" className={`${cell} text-xs`}>
                <div className="font-mono" title={r.os_pretty ? revealHidden(r.os_pretty) : undefined}><UntrustedText value={r.kernel_running_version} max={64} fallback="—" /></div>
                {r.reboot_pending && <Badge tone="orange" className="mt-1" title={`설치된 최신 커널 ${revealHidden(r.kernel_newest_version ?? '—')}`}>재부팅 대기</Badge>}
              </td>
              <td data-label="조사 상태" className={`${cell} text-xs`}>
                {!r.last_error && !r.check_error ? <span className="text-ink-muted">{checked ? '대조 완료' : '대조 대기'}</span> : <details><summary className="cursor-pointer text-warning">{r.last_error ? '수집 실패' : '대조 실패'}</summary>
                  {r.last_error && <div className="mt-2 break-words text-danger">수집 · <UntrustedText value={r.last_error} max={200} /></div>}
                  {r.check_error && <div className="mt-2 break-words text-warning">대조 · <UntrustedText value={r.check_error} max={200} /></div>}
                </details>}
              </td>
            </tr>
          })}</tbody>
        </table>
      </div>
      {!rows.length && <p className="p-4 text-sm text-ink-muted">수집한 자산이 없습니다. 자산 수집 상태를 확인해 주세요.</p>}
    </Card>
  )
}
