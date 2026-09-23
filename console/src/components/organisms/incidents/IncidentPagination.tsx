import { useId } from 'react'
import { Button } from '../../atoms/Button'
import { Select } from '../../atoms/Select'
import { PAGE_SIZES, pageNumbers } from './pagination'

interface Props {
  page: number
  pageSize: number
  total: number
  busy: boolean
  onPage: (page: number) => void
  onPageSize: (size: number) => void
}

export function IncidentPagination({ page, pageSize, total, busy, onPage, onPageSize }: Props) {
  const id = useId()
  const count = Math.max(1, Math.ceil(total / pageSize))
  return (
    <nav aria-label="인시던트 페이지" className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-black/8 px-4 py-3">
      <div className="flex items-center gap-2 text-xs text-ink-muted">
        <label htmlFor={id}>페이지당</label>
        <Select id={id} fieldSize="sm" className="w-auto" value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))}>
          {PAGE_SIZES.map((size) => <option key={size} value={size}>{size}건</option>)}
        </Select>
        <span aria-live="polite">{page} / {count}페이지</span>
      </div>
      <div className="flex flex-wrap items-center gap-1">
        <Button size="sm" disabled={page <= 1 || busy} onClick={() => onPage(page - 1)}>이전</Button>
        {pageNumbers(page, count).map((value) => typeof value === 'number'
          ? <Button key={value} size="sm" variant={value === page ? 'primary' : 'ghost'} aria-label={`${value}페이지`} aria-current={value === page ? 'page' : undefined} disabled={busy} onClick={() => onPage(value)}>{value}</Button>
          : <span key={value} className="px-1 text-ink-muted" aria-hidden="true">…</span>)}
        <Button size="sm" disabled={page >= count || busy} onClick={() => onPage(page + 1)}>다음</Button>
      </div>
    </nav>
  )
}
