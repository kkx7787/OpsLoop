import { useEffect, useMemo, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useIncidentsPage } from '@/api/incidents'
import { Button } from '@/components/atoms/Button'
import { buttonClasses } from '@/components/atoms/button-styles'
import { PageHeader } from '@/components/molecules/PageHeader'
import { Banner } from '@/components/molecules/Banner'
import { describeError } from '@/api/errors'
import { clearFilters, countFilters, filtersFromSearch, ruleOptionsOf, searchFromFilters, type ListFilters } from '@/components/organisms/incidents/filters'
import { IncidentFilterBar, IncidentSortControl } from '@/components/organisms/incidents/IncidentFilterBar'
import { IncidentList } from '@/components/organisms/incidents/IncidentList'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { DEFAULT_PAGE_SIZE, paginationFromSearch } from '@/components/organisms/incidents/pagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { EmptyState } from '@/components/organisms/states/EmptyState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { useNow } from '@/lib/useNow'

/** 조건·쪽·쪽 크기를 URL에 보존한다. 페이지 이동은 기존 limit/offset API를 사용한다. */
export function IncidentsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo(() => filtersFromSearch(searchParams), [searchParams])
  const { page, pageSize } = paginationFromSearch(searchParams)
  const incidents = useIncidentsPage(filters, page, pageSize)
  const now = useNow(30_000)
  const list = incidents.data
  const rules = useMemo(() => ruleOptionsOf(list?.rules, list?.items), [list])
  const active = countFilters(filters)
  const lastPage = Math.max(1, Math.ceil((list?.total ?? 0) / pageSize))
  const outOfRange = !!list && !incidents.isPlaceholderData && page > lastPage
  const changing = incidents.isPending || incidents.isPlaceholderData || outOfRange

  // 다른 관제자가 판정해 마지막 쪽이 사라지거나 잘못된 링크를 열면 유효한 마지막 쪽으로 돌아간다.
  useEffect(() => {
    if (!outOfRange || incidents.isError) return
    const next = new URLSearchParams(searchParams)
    if (lastPage === 1) next.delete('page')
    else next.set('page', String(lastPage))
    setSearchParams(next, { replace: true })
  }, [outOfRange, lastPage, searchParams, setSearchParams, incidents.isError])

  function setFilters(nextFilters: ListFilters) {
    const next = searchFromFilters(nextFilters, searchParams)
    next.delete('page')
    setSearchParams(next)
  }

  function setPage(nextPage: number) {
    const next = new URLSearchParams(searchParams)
    if (nextPage === 1) next.delete('page')
    else next.set('page', String(nextPage))
    setSearchParams(next)
  }

  function setPageSize(size: number) {
    const next = new URLSearchParams(searchParams)
    next.delete('page')
    if (size === DEFAULT_PAGE_SIZE) next.delete('page_size')
    else next.set('page_size', String(size))
    setSearchParams(next)
  }

  let body: ReactNode
  if (changing) {
    body = <div className="min-h-[280px]"><LoadingState title="인시던트를 불러오는 중입니다" lines={6} /></div>
  } else if (incidents.isError && !list) {
    body = <ApiErrorState error={incidents.error} onRetry={() => void incidents.refetch()} retrying={incidents.isFetching} />
  } else if (!list || list.items.length === 0) {
    body = (
      <EmptyState
        eyebrow="S-03 · 결과 0건"
        title={active > 0 ? '조건에 맞는 인시던트가 없습니다' : '인시던트가 없습니다'}
        description={active > 0 ? `${active}개 조건 적용 중 · 0건이 정상인지 수집 상태부터 확인해 주세요` : '0건이 정상인지 수집 상태부터 확인해 주세요'}
        actions={<>
          {active > 0 && <Button variant="primary" size="sm" onClick={() => setFilters(clearFilters(filters))}>조건 초기화</Button>}
          <Link to="/nodes" className={buttonClasses({ size: 'sm' })}>수집 노드 보기</Link>
        </>}
      />
    )
  } else {
    body = <IncidentList key={`${page}:${pageSize}:${searchParams}`} items={list.items} total={list.total} offset={(page - 1) * pageSize} now={now} dataUpdatedAt={incidents.dataUpdatedAt} className="md:h-full md:max-h-none" />
  }

  const quickViews: Array<{ label: string; filters: ListFilters; selected: boolean }> = [
    { label: '전체 사건', filters: {}, selected: active === 0 },
    { label: '미판정만', filters: { judged: false }, selected: active === 1 && filters.judged === false },
    { label: 'critical 미판정', filters: { judged: false, severity: 'critical' }, selected: active === 2 && filters.judged === false && filters.severity === 'critical' },
    { label: '조치중', filters: { status: 'in_progress' }, selected: active === 1 && filters.status === 'in_progress' },
  ]
  const start = list?.total ? (page - 1) * pageSize + 1 : 0
  const end = Math.min((page - 1) * pageSize + (list?.items.length ?? 0), list?.total ?? 0)

  return (
    <div className="flex flex-col gap-[18px] md:h-[calc(100dvh-116px)] md:min-h-[500px]">
      <PageHeader title="인시던트" description="미판정 사건부터 확인하고 증거를 검토하세요." className="shrink-0" />
      <section aria-label="사건 탐색" className="flex shrink-0 flex-col gap-4 rounded-card bg-surface p-4 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div role="group" aria-label="빠른 보기" className="flex flex-wrap gap-2">
            {quickViews.map((view) => <Button key={view.label} size="sm" variant={view.selected ? 'primary' : 'secondary'} aria-pressed={view.selected} onClick={() => setFilters(view.filters)}>{view.label}</Button>)}
          </div>
          <IncidentSortControl value={filters} onChange={setFilters} />
        </div>
        <IncidentFilterBar value={filters} onChange={setFilters} rules={rules} />
      </section>
      <section aria-label="조회 결과" className="flex min-h-0 min-w-0 flex-col overflow-hidden rounded-card bg-surface shadow-card md:flex-1">
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-black/8 px-4 py-3 text-sm">
          <span aria-live="polite">
            {list && !changing ? <>총 <strong className="tabular-nums">{list.total.toLocaleString('ko-KR')}</strong>건 · <span className="tabular-nums">{start.toLocaleString('ko-KR')}–{end.toLocaleString('ko-KR')}건 표시</span></> : '목록 조회 중'}
          </span>
          <span className="text-xs text-ink-muted">{incidents.isFetching ? '갱신 중…' : filters.sort === 'severity' ? '심각도 높은 순' : filters.sort === 'recent' ? '최근 발생 순' : '미판정 우선 · 오래된 순'}</span>
        </div>
        {incidents.isError && list && <Banner tone="danger" title="목록을 갱신하지 못했습니다">{describeError(incidents.error)} <Button size="sm" onClick={() => void incidents.refetch()}>다시 시도</Button></Banner>}
        <div className="min-h-0 overflow-auto md:flex-1">{body}</div>
        {list && <IncidentPagination page={page} pageSize={pageSize} total={list.total} busy={incidents.isFetching || outOfRange} onPage={setPage} onPageSize={setPageSize} />}
      </section>
    </div>
  )
}
