import { useMemo, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { isDeviceNotFound, isLogsNotDeployed, LOGS_NOT_DEPLOYED, useDeviceLogs, type DeviceLogFilters, type DeviceLogsResult } from '@/api/device-logs'
import { isApiError } from '@/api/errors'
import { Button } from '@/components/atoms/Button'
import { buttonClasses } from '@/components/atoms/button-styles'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { deviceIncidentsHref, isLogDeviceId } from '@/components/molecules/device-format'
import { PageHeader } from '@/components/molecules/PageHeader'
import { LABEL_MAX } from '@/components/organisms/dashboard/target-format'
import { countLogFilters, filterScope, futureText, logFiltersFromSearch, mergeLines, searchFromLogFilters, type LogBuffer } from '@/components/organisms/device-logs/log-format'
import { LogFilterBar } from '@/components/organisms/device-logs/LogFilterBar'
import { LogList } from '@/components/organisms/device-logs/LogList'
import { LogTimes } from '@/components/organisms/device-logs/LogTimes'
import { PageRefresh } from '@/components/organisms/PageRefresh'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { EmptyState } from '@/components/organisms/states/EmptyState'
import { ErrorState } from '@/components/organisms/states/ErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { NotFoundState } from '@/components/organisms/states/NotFoundState'
import { freshnessPart } from '@/lib/freshness'

/**
 * 보호 대상 장비 최근 로그(#73 · /devices/:id/logs, 메뉴 없음). 대시보드 보호 대상 카드 · 사건 상세 장비 배지에서 연다.
 * 대상은 web-01 과 등록 노드뿐이고(그 밖은 서버 404), 줄 글자는 서버가 가려 보낸 비신뢰 값이다.
 * 5초마다 최근 창을 다시 받아 줄 id 로 합친다(숨은 탭 · 일시정지에서는 멈춘다). 새 줄은 1분 적재 회차로 들어오고 사건은 그 뒤 탐지 회차에서 생긴다.
 * 조건(종류 · 출발지 · 응답 코드)은 주소 검색 인자에 둔다. 조건이 바뀌면 합친 목록을 비운다.
 * 화면 기준 시각(as_of)은 제목 줄 오른쪽 새로고침 옆 하나다(#79). 새로고침은 일시정지 중에도 한 번 받고 일시정지는 그대로다.
 */
export function DeviceLogsPage() {
  const { id = '' } = useParams()
  // 형식 밖 id · '_unconfirmed' 는 묻지 않는다(서버도 같은 404 다)
  if (!isLogDeviceId(id)) return <DeviceNotFound id={id} />
  return <DeviceLogsScreen key={id} id={id} />
}

function DeviceNotFound({ id }: { id: string }) {
  return (
    <NotFoundState
      size="page"
      titleAs="h1"
      title="보호 대상 장비를 찾을 수 없습니다"
      description={
        <code className="font-mono text-xs break-all text-ink">
          <UntrustedText value={id} max={80} fallback="장비 id 없음" />
        </code>
      }
      actions={
        <Link to="/" className={buttonClasses({ size: 'lg' })}>
          관제 현황
        </Link>
      }
    />
  )
}

/**
 * 받은 응답을 합친 목록으로 모은다. 성공한 조회마다(dataUpdatedAt) 한 번 합치고, 조건 · 장비(scope)가 바뀌면 비운다.
 * 합친 결과는 렌더 중에 상태로 옮긴다(이전 렌더 값을 기억하는 React 방식이라 효과를 쓰지 않는다)
 */
function useLogBuffer(scope: string, data: DeviceLogsResult | undefined, updatedAt: number): LogBuffer | null {
  const [merged, setMerged] = useState<{ scope: string; at: number; buffer: LogBuffer } | null>(null)
  const current = merged?.scope === scope ? merged : null
  if (data && updatedAt !== current?.at) {
    const next = { scope, at: updatedAt, buffer: mergeLines(current?.buffer ?? null, data.items, data.limit) }
    setMerged(next)
    return next.buffer
  }
  return current?.buffer ?? null
}

/**
 * 마지막 오류. 받은 적 없는 조회를 다시 보내는 동안 react-query 는 error 를 비우고 받는 중으로 돌아간다.
 * 그동안에도 마지막으로 끝난 조회가 실패였으면(failed) 그 오류를 계속 보여 5초마다 '불러오는 중' 으로 깜빡이지 않게 한다.
 * 오류는 조건(scope)과 함께 기억해 같은 조건에서만 돌려준다(다른 조건의 422 가 조건 초기화 뒤에 남지 않게)
 */
function useShownError(scope: string, error: unknown, failed: boolean): unknown {
  const [last, setLast] = useState<{ scope: string; error: unknown } | null>(null)
  if (error && (error !== last?.error || scope !== last.scope)) setLast({ scope, error })
  return error ?? (failed && last?.scope === scope ? last.error : null)
}

function DeviceLogsScreen({ id }: { id: string }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const filters = useMemo(() => logFiltersFromSearch(searchParams), [searchParams])
  const [paused, setPaused] = useState(false)
  const query = useDeviceLogs(id, filters, paused)
  const scope = filterScope(id, filters)
  const buffer = useLogBuffer(scope, query.data, query.dataUpdatedAt)
  const data = query.data
  // 갱신 실패: react-query 는 이전 data 를 남긴 채 isError 를 켜고, 재조회 중에는 마지막으로 끝난 조회가 실패였는지로 본다
  const failed = query.isError || query.errorUpdatedAt > query.dataUpdatedAt
  const error = useShownError(scope, query.error, failed)
  const active = countLogFilters(filters)

  // 받은 뒤에 와도(폐기 · 발생원 겹침) 이 장비는 더 볼 수 없다
  if (isDeviceNotFound(error)) return <DeviceNotFound id={id} />

  function setFilters(next: DeviceLogFilters) {
    setSearchParams(searchFromLogFilters(next, searchParams))
  }

  function togglePause() {
    if (!paused) {
      setPaused(true)
      return
    }
    setPaused(false)
    void query.refetch()
  }

  const retry = () => void query.refetch()
  const invalidInput = isApiError(error) && error.status === 422
  const invalid = invalidInput ? error.detail : null
  // 조건 오류(422)는 입력 문제이고 배포 전(404)은 갱신 실패가 아니다(대시보드 상태판 404 와 같다). 본문이 알리므로 기준 시각 칸은 비운다
  const refreshParts = invalidInput || isLogsNotDeployed(error) ? [] : [freshnessPart(query, data?.as_of)]

  let body: ReactNode
  if (isLogsNotDeployed(error)) {
    body = (
      <p className="m-0 px-4 py-3 text-xs text-ink-muted" data-logs-missing="">
        {LOGS_NOT_DEPLOYED}
      </p>
    )
  } else if (!data) {
    if (!failed || !error) body = <LoadingState title="로그를 불러오는 중입니다" lines={4} className="shadow-none" />
    else if (invalid) body = null
    else if (isApiError(error) && (error.status === 401 || error.status === 403)) body = <ApiErrorState error={error} onRetry={retry} retrying={query.isFetching} className="shadow-none" />
    else body = <ErrorState title="로그를 불러오지 못함" error={error} onRetry={retry} retrying={query.isFetching} className="shadow-none" />
  } else if (!buffer || buffer.lines.length === 0) {
    body =
      active > 0 ? (
        <EmptyState
          title="조건에 맞는 줄이 없습니다"
          className="shadow-none"
          actions={
            <Button variant="primary" size="sm" onClick={() => setFilters({})}>
              조건 초기화
            </Button>
          }
        />
      ) : (
        <EmptyState title={`최근 ${data.window_days.toLocaleString('ko-KR')}일 안에 이 장비의 로그가 없습니다`} className="shadow-none" />
      )
  } else {
    body = <LogList key={scope} lines={buffer.lines} gaps={buffer.gaps} stale={failed} />
  }

  const label = data?.device.label || id
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <PageHeader
        title={
          <>
            <UntrustedText value={label} max={LABEL_MAX} /> 최근 로그
          </>
        }
        description="로그는 1분 적재 회차로 들어오고, 사건은 그 뒤 탐지 회차에서 생깁니다."
        status={<PageRefresh parts={refreshParts} />}
        aside={
          <>
            <Button size="sm" aria-pressed={paused} onClick={togglePause}>
              {paused ? '계속' : '일시정지'}
            </Button>
            <Link to={deviceIncidentsHref(id)} className={buttonClasses({ size: 'sm' })}>
              사건 보기
            </Link>
            <Link to="/" className={buttonClasses({ size: 'sm' })}>
              관제 현황
            </Link>
          </>
        }
      />
      {data && <LogTimes data={data} paused={paused} />}
      <section aria-label="최근 로그" className="flex min-w-0 flex-col rounded-card bg-surface shadow-card">
        <LogFilterBar value={filters} onChange={setFilters} className="border-b border-line px-3 py-2" />
        {(invalid || (data && failed) || (data && data.future > 0)) && (
          <div className="flex flex-col gap-2 px-3 pt-3">
            {invalid && (
              <Banner
                tone="warning"
                data-filter-invalid=""
                action={
                  <Button size="sm" onClick={() => setFilters({})}>
                    조건 초기화
                  </Button>
                }
              >
                {invalid}
              </Banner>
            )}
            {data && failed && !invalid && (
              <Banner
                tone="warning"
                title="로그를 불러오지 못함"
                data-refresh-failed=""
                action={
                  <Button size="sm" loading={query.isFetching} onClick={retry}>
                    다시 시도
                  </Button>
                }
              >
                이전 결과 유지
              </Banner>
            )}
            {data && data.future > 0 && (
              <Banner tone="warning" data-future="">
                {futureText(data.future)}
              </Banner>
            )}
          </div>
        )}
        {body}
      </section>
    </div>
  )
}
