import { useId } from 'react'
import { Link } from 'react-router'
import { useCardLogsFailed } from '@/api/device-logs'
import { useControlHealth } from '@/api/health'
import { useLiveState } from '@/api/live-context'
import { useMe } from '@/auth/useMe'
import { useSummary } from '@/api/monitoring'
import { isTargetsNotDeployed, useTargets } from '@/api/targets'
import { Time } from '@/components/atoms/Time'
import { STATUS_PATH } from '@/components/molecules/device-format'
import { PageHeader } from '@/components/molecules/PageHeader'
import { PageRefresh } from '@/components/organisms/PageRefresh'
import { AgeDistribution, ControlHealthBand, DashboardMetrics, PendingQueue, TargetBoard } from '@/components/organisms/dashboard'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cn } from '@/lib/cn'
import { freshnessPart, isPartFailed, type FreshnessPart } from '@/lib/freshness'

/**
 * 관제 현황(S-02, #72 · #83 · #84). 위에서부터 관제 이상 띠(있을 때만) → [보호 대상] 카드 → [판정 대기 사건] 대기열 · 경과 분포 · 수치 네 칸 →
 * 맨 아래 '수집 · 관제 상태 보기 →' · 최근 원문 수집 한 줄. 이 파일은 조립만 한다.
 * 관측 센서 · 관제 시스템은 수집 · 관제 상태 화면(/nodes)으로 옮겼다(#84). 그 이상은 관제 이상 띠가 싣고 그 화면 줄로 잇는다.
 * 요약 · 상태판 · 관제 이상 · 카드 로그는 따로 조회한다. 한쪽이 실패해도 다른 쪽은 그대로 보인다.
 * 화면 기준 시각은 제목 줄 오른쪽 새로고침 옆 하나다(#79): 가장 오래전에 성공한 조회의 as_of 이고, 한쪽이라도 실패하면 '일부 갱신 실패',
 * 그 자리(카드 · 대기열 · 수치)에는 '이전 결과' 를 단다. 요약 실패를 공통 띠로 되풀이하지 않는다.
 * 실시간 연결 끊김도 공통 띠 대신 관제 이상 띠의 끝 항목 하나다(#84, 띠가 둘이면 1440×800 첫 화면에서 판정 대기 첫 줄이 밀린다).
 * 공통 띠가 없으므로 받은 뒤의 갱신 실패는 기준 시각 옆 낭독 칸(role=status)이 알린다.
 * 판정 대기 사건은 상태판의 queue 가 있으면 요약과 관계없이 그린다. 요약이 한 번도 오지 않았으면 수치 자리에 오류를 작게 둔다.
 * 규칙별 비조치율은 규칙 화면(규칙별 판정 집계)에 있어 여기서는 그리로 잇기만 한다.
 */
export function DashboardPage() {
  const query = useSummary()
  const targets = useTargets()
  const health = useControlHealth()
  const live = useLiveState()
  const me = useMe()
  const logsFailed = useCardLogsFailed()
  const queueTitleId = useId()
  const data = query.data
  const queue = targets.data?.queue
  const summaryStale = !!data && isPartFailed(freshnessPart(query))
  const targetsStale = !!targets.data && isPartFailed(freshnessPart(targets))
  const parts: FreshnessPart[] = [
    freshnessPart(query, data?.as_of),
    // 상태판 API 가 없는 이전 서버(404)는 갱신 실패가 아니다(보호 대상 자리가 배포 전으로 알린다)
    ...(isTargetsNotDeployed(targets.error) && !targets.data ? [] : [freshnessPart(targets, targets.data?.as_of)]),
    freshnessPart(health, health.data?.as_of),
    // 카드 로그는 실패만 알린다(기준 시각 · 나이에 넣지 않는다)
    { dataUpdatedAt: 0, errorUpdatedAt: 0, isError: logsFailed, failureOnly: true },
  ]
  const summaryError = <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} titleAs="h3" />
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader title="관제 현황" badges={<div className="flex flex-wrap gap-x-3 gap-y-1 text-xs font-medium">{(me.data?.role === 'operator' || me.data?.role === 'admin') && <Link to="/incidents?assignment=mine&judged=false">내 담당 미판정 →</Link>}{(data || queue) && <a href="/#pending-incidents" className="hidden md:inline-flex">판정 대기로 이동 ↓</a>}</div>} status={<PageRefresh parts={parts} announce />} />
      <ControlHealthBand health={health} live={live.status} />
      <TargetBoard
        data={targets.data}
        pending={targets.isPending}
        fetching={targets.isFetching}
        error={targets.error}
        stale={targetsStale}
        updatedAt={targets.dataUpdatedAt}
        onRetry={() => void targets.refetch()}
      />
      {data || queue ? (
        <section id="pending-incidents" tabIndex={-1} aria-labelledby={queueTitleId} className="flex min-w-0 scroll-mt-16 flex-col gap-4" data-pending-section="">
          <div className={cn('grid items-start gap-4', data && 'xl:grid-cols-[minmax(0,1fr)_300px]')}>
            <PendingQueue titleId={queueTitleId} queue={queue} oldest={data?.oldest_pending} stale={queue ? targetsStale : summaryStale} />
            {data && <AgeDistribution pending={data.pending} stale={summaryStale} />}
          </div>
          {data ? <DashboardMetrics summary={data} stale={summaryStale} /> : query.isError ? summaryError : null}
        </section>
      ) : query.isPending ? (
        <LoadingState title="대시보드를 불러오는 중입니다" />
      ) : (
        summaryError
      )}
      {/* 요약이 없어도 상태 화면 링크는 늘 둔다 */}
      <p className="m-0 flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs text-ink-muted" data-dashboard-foot="">
        <Link to={STATUS_PATH} className="font-medium">
          수집 · 관제 상태 보기 →
        </Link>
        {data && (
          <span>
            최근 원문 수집 <Time value={data.latest_event} format="short" zone /> · 규칙별 비조치율은 <Link to="/rules">규칙 화면에서 보기</Link>
          </span>
        )}
      </p>
    </div>
  )
}
