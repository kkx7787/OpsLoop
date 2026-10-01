/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useEffect, useId, useMemo, useState, type ComponentProps, type FormEvent, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import {
  DEFAULT_SOURCE_SORT,
  FINGERPRINT_KINDS,
  FINGERPRINT_LABEL,
  isAddressPrefix,
  SOURCE_SORT_LABEL,
  SOURCE_SORTS,
  useFingerprints,
  useSources,
  type FingerprintKind,
  type SourceSort,
} from '@/api/sources'
import { useLiveState } from '@/api/live-context'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Button } from '@/components/atoms/Button'
import { buttonClasses } from '@/components/atoms/button-styles'
import { Card } from '@/components/atoms/Card'
import { Chip } from '@/components/atoms/Chip'
import { Input } from '@/components/atoms/Input'
import { Switch } from '@/components/atoms/Switch'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { SegmentedControl, type SegmentOption } from '@/components/molecules/SegmentedControl'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { DEFAULT_PAGE_SIZE, paginationFromSearch } from '@/components/organisms/incidents/pagination'
import { FingerprintsTable } from '@/components/organisms/sources/FingerprintsTable'
import { CheckerStaleBanner } from '@/components/organisms/sources/SourceBlock'
import { SourcesTable } from '@/components/organisms/sources/SourcesTable'
import {
  CHECKER_UNKNOWN_NOTE,
  checkersUnknown,
  conditionsFromSearch,
  countConditions,
  kindFromSearch,
  requestPage,
  SAME_TOOL_NOTE,
  SAME_TOOL_REASON,
  searchFromConditions,
  staleCheckers,
  tabFromSearch,
  type SourceConditions,
  type SourcesTab,
} from '@/components/organisms/sources/model'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { EmptyState } from '@/components/organisms/states/EmptyState'
import { LoadingState } from '@/components/organisms/states/LoadingState'

const TABS: Array<[SourcesTab, string]> = [['sources', '출발지'], ['fingerprints', '도구 지문']]
const SORT_OPTIONS: readonly SegmentOption<SourceSort>[] = SOURCE_SORTS.map((sort) => ({ value: sort, label: SOURCE_SORT_LABEL[sort] }))
const KIND_OPTIONS: readonly SegmentOption<FingerprintKind>[] = FINGERPRINT_KINDS.map((kind) => ({ value: kind, label: FINGERPRINT_LABEL[kind] }))
/** 지문을 꺼내는 곳(app/sources.py). 지문 탭 종류 선택 옆 도움말(ⓘ)에 싣는다 */
const KIND_SOURCE: Record<FingerprintKind, string> = {
  hassh: 'Cowrie 키 교환(cowrie.client.kex)에서 꺼낸 SSH 클라이언트 알고리즘 지문',
  ssh_version: 'Cowrie 가 받은 SSH 클라이언트 버전 문자열(cowrie.client.version)',
  user_agent: '웹 디코이 요청의 User-Agent',
}

/**
 * 출발지 분석(S-09 · 이슈 #58). 탭 둘: 출발지(주소별 사건 · 판정 · 차단)와 도구 지문(같은 도구를 쓴 출발지 묶음).
 * 탭 · 조건 · 정렬 · 쪽은 주소에 둔다. 지문 값을 누르면 출발지 탭이 그 지문 조건으로 열린다(사건 있는 출발지만).
 */
export function SourcesPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = tabFromSearch(searchParams)

  function setTab(next: SourcesTab) {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    if (next === 'fingerprints') params.set('tab', next)
    else params.delete('tab')
    setSearchParams(params)
  }

  const tabs = (
    <div role="group" aria-label="보기" className="flex shrink-0 gap-5 border-b border-line px-4">
      {TABS.map(([value, label]) => (
        <button key={value} type="button" aria-pressed={tab === value} onClick={() => setTab(value)}
          className={cn('min-h-10 cursor-pointer border-b-2 px-0.5 text-sm', tab === value ? 'border-primary font-semibold text-primary' : 'border-transparent text-ink-muted hover:text-ink')}>
          {label}
        </button>
      ))}
    </div>
  )

  return (
    <div className="worklist-page flex min-w-0 flex-col gap-3">
      <PageHeader title="출발지 분석" description="주소별 사건 · 판정 · 차단과 도구 지문 묶음을 봅니다." />
      {tab === 'sources' ? <SourceList tabs={tabs} /> : <FingerprintList tabs={tabs} />}
    </div>
  )
}

/**
 * 쪽 이동과 범위 밖 쪽 되돌리기(IncidentsPage 와 같다). total 은 받은 결과의 전체 수,
 * settled 는 지금 조건의 결과를 받았는가(이전 결과를 보이는 중이면 거짓)
 */
function usePaging(page: number, pageSize: number, total: number | undefined, settled: boolean, failed: boolean) {
  const [searchParams, setSearchParams] = useSearchParams()
  const lastPage = Math.max(1, Math.ceil((total ?? 0) / pageSize))
  const outOfRange = total !== undefined && settled && page > lastPage

  // 목록이 줄어 마지막 쪽이 사라지거나 잘못된 링크를 열면 유효한 마지막 쪽으로 돌아간다
  useEffect(() => {
    if (!outOfRange || failed) return
    const next = new URLSearchParams(searchParams)
    if (lastPage === 1) next.delete('page')
    else next.set('page', String(lastPage))
    setSearchParams(next, { replace: true })
  }, [outOfRange, lastPage, searchParams, setSearchParams, failed])

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

  return { outOfRange, setPage, setPageSize }
}

/** 표시 범위 한 줄: 총 N곳 · a–b 표시 */
function RangeLine({ total, offset, shown, unit, busy }: { total: number | undefined; offset: number; shown: number; unit: string; busy: boolean }) {
  if (total === undefined || busy) return <span aria-live="polite">목록 조회 중</span>
  const start = total ? offset + 1 : 0
  const end = Math.min(offset + shown, total)
  return (
    <span aria-live="polite">
      총 <strong className="tabular-nums">{total.toLocaleString('ko-KR')}</strong>{unit} · <span className="tabular-nums">{start.toLocaleString('ko-KR')}–{end.toLocaleString('ko-KR')}{unit} 표시</span>
    </span>
  )
}

function SourceList({ tabs }: { tabs: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const conditions = useMemo(() => conditionsFromSearch(searchParams), [searchParams])
  const pagination = paginationFromSearch(searchParams)
  const { pageSize } = pagination
  // offset 이 서버 상한을 넘는 쪽은 상한 안으로 자른다(비어 있으면 아래 되돌리기가 마지막 쪽으로 옮긴다)
  const page = requestPage(pagination.page, pageSize)
  const offset = (page - 1) * pageSize
  const query = useSources({
    q: conditions.q,
    sort: conditions.sort,
    include_test: conditions.include_test,
    fp_kind: conditions.fp?.kind,
    fp: conditions.fp?.value,
    limit: pageSize,
    offset,
  })
  const data = query.data
  const paging = usePaging(page, pageSize, data?.total, !!data && !query.isPlaceholderData, query.isError)
  const changing = query.isPending || query.isPlaceholderData || paging.outOfRange
  const active = countConditions(conditions)

  function setConditions(next: SourceConditions) {
    const params = searchFromConditions(next, searchParams)
    params.delete('page')
    setSearchParams(params)
  }

  let body: ReactNode
  if (changing) {
    body = <LoadingState title="출발지를 불러오는 중입니다" lines={6} className="min-h-[280px]" />
  } else if (query.isError && !data) {
    body = <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
  } else if ((!data || data.items.length === 0) && conditions.fp) {
    // 지문 표에 값이 있다는 것은 수집이 된다는 뜻이다. 수집 상태가 아니라 '사건 있는 출발지만' 보이는 목록이라 비었다.
    // '사건 있는 출발지만'은 제목과 표 캡션(아래 줄)이 말하므로 여기서는 함께 걸린 다른 조건만 적는다
    const also = [conditions.q && '주소 앞부분 조건도 걸려 있습니다', !conditions.include_test && '시험 대역 출발지는 빠져 있습니다'].filter(Boolean)
    body = (
      <EmptyState
        eyebrow="결과 0건"
        title="이 지문을 쓴 출발지 가운데 사건이 있는 곳이 없습니다"
        description={also.length ? also.join(' · ') : undefined}
        actions={<Button variant="primary" size="sm" onClick={() => setConditions({ ...conditions, fp: undefined })}>지문 조건 빼기</Button>}
      />
    )
  } else if (!data || data.items.length === 0) {
    body = (
      <EmptyState
        eyebrow="결과 0건"
        title={active > 0 ? '조건에 맞는 출발지가 없습니다' : '사건이 있는 출발지가 없습니다'}
        description={conditions.include_test ? '0건이 정상인지 수집 상태부터 확인해 주세요' : '시험 대역 출발지는 빠져 있습니다 · 0건이 정상인지 수집 상태부터 확인해 주세요'}
        actions={<>
          {active > 0 && <Button variant="primary" size="sm" onClick={() => setConditions({ sort: conditions.sort, include_test: conditions.include_test })}>조건 초기화</Button>}
          <Link to="/nodes" className={buttonClasses({ size: 'sm' })}>수집 · 관제 상태 보기</Link>
        </>}
      />
    )
  } else {
    body = <SourcesTable items={data.items} now={Date.parse(data.as_of)} checkers={data.checkers} />
  }

  return (
    <>
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      <CheckerStaleBanner points={staleCheckers(data?.checkers)} />
      <Card padding="none" className="worklist-panel flex min-w-0 flex-col overflow-hidden">
        {tabs}
        <SourceConditionsBar value={conditions} onChange={setConditions} />
        {/* 같은 지문 주의의 본문 한 곳. 근거(흔한 도구 · 판정은 사건마다)는 ⓘ */}
        {conditions.fp && (
          <p className="m-0 border-b border-line bg-canvas/60 px-4 py-2 text-xs text-ink-muted" data-same-tool>
            {SAME_TOOL_NOTE} <InfoTip label="도구 지문 조건">{SAME_TOOL_REASON}</InfoTip>
          </p>
        )}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2 text-xs">
          <RangeLine total={data?.total} offset={offset} shown={data?.items.length ?? 0} unit="곳" busy={changing} />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-ink-muted">{query.isFetching ? '갱신 중…' : ''}</span>
            <SegmentedControl aria-label="정렬" options={SORT_OPTIONS} value={conditions.sort ?? DEFAULT_SOURCE_SORT}
              onChange={(sort) => setConditions({ ...conditions, sort: sort === DEFAULT_SOURCE_SORT ? undefined : sort })} />
          </div>
        </div>
        <div key={`${searchParams}`} className="worklist-scroll overflow-auto" role="region" aria-label="출발지 표" tabIndex={0}>{body}</div>
        {data && <IncidentPagination label="출발지 페이지" page={page} pageSize={pageSize} total={data.total} busy={query.isFetching || paging.outOfRange} onPage={paging.setPage} onPageSize={paging.setPageSize} />}
        {/* 표 캡션 한 줄. 판정 분포 · 차단 상태의 기준은 열 머리 ⓘ(SourcesTable) */}
        <p className="m-0 border-t border-line px-4 py-3 text-xs text-ink-muted">
          주소가 있는 사건의 출발지만 보입니다(계정 · 노드 대상 사건은 빠짐).
          {/* 생존 신호 표를 읽을 수 없으면 멈춤을 가리지 못한다. 상세와 같게 적용 확인을 그대로 둔 까닭을 밝힌다 */}
          {checkersUnknown(data?.checkers) && <span className="mt-1 block">{CHECKER_UNKNOWN_NOTE}</span>}
        </p>
      </Card>
    </>
  )
}

/** 출발지 조건 띠: 주소 앞부분 · 시험 대역 포함 · 지문 조건(칩). 값은 부르는 쪽이 주소에 둔다 */
function SourceConditionsBar({ value, onChange }: { value: SourceConditions; onChange: (next: SourceConditions) => void }) {
  const active = countConditions(value)
  return (
    <div role="group" aria-label="출발지 조건" className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-2 border-b border-line px-4 py-2">
      {/* 주소가 바뀌면(초기화 · 뒤로 가기) 입력칸도 그 값으로 다시 시작한다 */}
      <AddressSearch key={value.q ?? ''} value={value.q ?? ''} onSubmit={(q) => onChange({ ...value, q })} />
      <Switch label="시험 대역 포함" checked={!!value.include_test} onChange={(event) => onChange({ ...value, include_test: event.target.checked || undefined })} />
      {value.fp && (
        <Chip onRemove={() => onChange({ ...value, fp: undefined })} removeLabel="도구 지문 조건 빼기" className="max-w-full min-w-0">
          <span className="shrink-0">{FINGERPRINT_LABEL[value.fp.kind]}</span>
          <span className="min-w-0 truncate font-mono" title={revealHidden(value.fp.value)}>
            <UntrustedText value={value.fp.value} max={48} clip />
          </span>
        </Chip>
      )}
      {active > 0 && (
        <Button variant="ghost" size="sm" onClick={() => onChange({ sort: value.sort, include_test: value.include_test })}>
          조건 초기화
        </Button>
      )}
    </div>
  )
}

/** 주소 앞부분 검색. 서버와 같은 형식(16진 숫자 · ':' · '.' 45자까지)이 아니면 묻지 않고 까닭을 보인다 */
function AddressSearch({ value, onSubmit }: { value: string; onSubmit: (q: string | undefined) => void }) {
  const [draft, setDraft] = useState(value)
  const [error, setError] = useState('')
  // 오류 문장을 입력칸 설명으로 잇는다(FormField 와 같다). alert 는 뜰 때 한 번만 읽혀 초점을 되돌리면 까닭이 들리지 않는다
  const errorId = useId()

  function submit(event: FormEvent) {
    event.preventDefault()
    const q = draft.trim()
    if (q && !isAddressPrefix(q)) {
      setError('주소 앞부분은 숫자 · a~f · 콜론(:) · 점(.)으로 45자까지 입력합니다')
      return
    }
    setError('')
    onSubmit(q || undefined)
  }

  return (
    <form role="search" aria-label="주소 검색" className="flex flex-wrap items-center gap-2" onSubmit={submit}>
      <Input aria-label="주소 앞부분" fieldSize="sm" className="w-[220px] font-mono" maxLength={45} placeholder="주소 앞부분 (예: 203.0.113.)"
        value={draft} aria-invalid={error ? true : undefined} aria-describedby={error ? errorId : undefined} onChange={(event) => setDraft(event.target.value)} />
      <Button type="submit" size="sm">검색</Button>
      {error && <p id={errorId} role="alert" className="m-0 basis-full text-xs text-danger">{error}</p>}
    </form>
  )
}

function FingerprintList({ tabs }: { tabs: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const kind = kindFromSearch(searchParams)
  const pagination = paginationFromSearch(searchParams)
  const { pageSize } = pagination
  const page = requestPage(pagination.page, pageSize)
  const offset = (page - 1) * pageSize
  const query = useFingerprints({ kind, limit: pageSize, offset })
  const data = query.data
  const paging = usePaging(page, pageSize, data?.total, !!data && !query.isPlaceholderData, query.isError)
  const changing = query.isPending || query.isPlaceholderData || paging.outOfRange

  function setKind(next: FingerprintKind) {
    const params = new URLSearchParams(searchParams)
    params.delete('page')
    if (next === 'hassh') params.delete('kind')
    else params.set('kind', next)
    setSearchParams(params)
  }

  let body: ReactNode
  if (changing) {
    body = <LoadingState title="도구 지문을 불러오는 중입니다" lines={6} className="min-h-[280px]" />
  } else if (query.isError && !data) {
    body = <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
  } else if (!data || data.items.length === 0) {
    body = <EmptyState eyebrow="결과 0건" title={`${FINGERPRINT_LABEL[kind]} 지문 기록이 없습니다`} description="0건이 정상인지 수집 상태부터 확인해 주세요"
      actions={<Link to="/nodes" className={buttonClasses({ size: 'sm' })}>수집 · 관제 상태 보기</Link>} />
  } else {
    body = <FingerprintsTable kind={kind} items={data.items} />
  }

  return (
    <>
      <FingerprintStatus updatedAt={query.dataUpdatedAt} error={data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      <Card padding="none" className="worklist-panel flex min-w-0 flex-col overflow-hidden">
        {tabs}
        {/* 어디서 꺼낸 지문인지와 같은 지문 주의는 ⓘ. 값 누름 · 누를 수 없는 값은 링크 모양과 '사건 있는 출발지' 열 머리 ⓘ 가 알린다 */}
        <InfoTip label={`${FINGERPRINT_LABEL[kind]} 지문`} render={({ button, panel }) => (<>
          <div className="flex shrink-0 flex-wrap items-center gap-x-2 gap-y-1 border-b border-line px-4 py-2">
            <SegmentedControl aria-label="지문 종류" options={KIND_OPTIONS} value={kind} onChange={setKind} />
            {button}
          </div>
          {panel}
        </>)}>
          {KIND_SOURCE[kind]}입니다. {SAME_TOOL_NOTE}. {SAME_TOOL_REASON}
        </InfoTip>
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2 text-xs">
          <RangeLine total={data?.total} offset={offset} shown={data?.items.length ?? 0} unit="개" busy={changing} />
          <span className="text-ink-muted">{query.isFetching ? '갱신 중…' : '쓴 출발지가 많은 순'}</span>
        </div>
        <div key={`${searchParams}`} className="worklist-scroll overflow-auto" role="region" aria-label="도구 지문 표" tabIndex={0}>{body}</div>
        {data && <IncidentPagination label="도구 지문 페이지" page={page} pageSize={pageSize} total={data.total} busy={query.isFetching || paging.outOfRange} onPage={paging.setPage} onPageSize={paging.setPageSize} />}
      </Card>
    </>
  )
}

/**
 * 지문 탭의 조회 상태. 지문 조회는 주기 재조회가 없어(useFingerprints) 공통 띠의 '30초마다 별도로 조회' 안내가 맞지 않는다.
 * 끊긴 동안은 지금 조회로만 새로 받는다고 알린다(다시 이어지면 resync 로 한 번 받는다). 조회 실패 · 연결 종료는 공통 띠와 같다
 */
function FingerprintStatus(props: ComponentProps<typeof MonitoringStatus>) {
  const live = useLiveState()
  if (!props.error && live.status === 'reconnecting') {
    return (
      <Banner tone="warning" title="실시간 연결이 끊겼습니다" action={<Button onClick={props.onRetry} loading={props.busy}>지금 조회</Button>}>
        다시 연결될 때까지 도구 지문은 저절로 갱신되지 않습니다
      </Banner>
    )
  }
  return <MonitoringStatus {...props} />
}
