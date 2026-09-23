import type { Incident } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { IncidentCard } from './IncidentCard'
import { IncidentRow } from './IncidentRow'
import { COLUMNS, ROW_GRID } from './model'
import { useIsDesktop } from './useIsDesktop'

export type IncidentListLayout = 'table' | 'cards'

export interface IncidentListProps {
  items: readonly Incident[]
  total: number
  now: number
  dataUpdatedAt: number
  offset?: number
  layout?: IncidentListLayout
  className?: string
}

/** 한 페이지(최대 100건). 표 머리글을 고정하고 목록 안에서 스크롤해 페이지 탐색을 계속 노출한다. */
export function IncidentList({ items, total, now, dataUpdatedAt, offset = 0, layout, className }: IncidentListProps) {
  const desktop = useIsDesktop()
  const table = (layout ?? (desktop ? 'table' : 'cards')) === 'table'
  const sinceFetch = dataUpdatedAt > 0 ? Math.max(0, Math.floor((now - dataUpdatedAt) / 1000)) : 0
  const elapsedOf = (incident: Incident) => incident.pending_seconds + sinceFetch

  return (
    // 키보드로도 목록 내부를 스크롤할 수 있게 초점을 제공한다.
    // oxlint-disable-next-line jsx-a11y/no-noninteractive-tabindex
    <div role="region" aria-label="사건 목록 스크롤" tabIndex={0} className={cn('max-h-[62vh] overflow-auto overscroll-contain focus-visible:outline-2 focus-visible:outline-primary', className)}>
      {table ? (
        <div role="table" aria-label="인시던트 목록" aria-rowcount={total + 1} className="min-w-[740px]">
          <div role="rowgroup" className="sticky top-0 z-10 bg-canvas shadow-hairline">
            <div role="row" aria-rowindex={1} className={cn(ROW_GRID, 'px-4 py-3 text-xs font-semibold text-ink-muted')}>
              {COLUMNS.map((column) => <div key={column.key} role="columnheader" className={column.className}>{column.label}</div>)}
            </div>
          </div>
          <div role="rowgroup">
            {items.map((incident, index) => (
              <IncidentRow key={incident.incident_key} rowIndex={offset + index + 2} incident={incident} elapsedSeconds={elapsedOf(incident)} />
            ))}
          </div>
        </div>
      ) : (
        <ul aria-label="인시던트 목록" className="m-0 flex list-none flex-col gap-2 bg-canvas p-2">
          {items.map((incident) => <IncidentCard key={incident.incident_key} incident={incident} elapsedSeconds={elapsedOf(incident)} />)}
        </ul>
      )}
    </div>
  )
}
