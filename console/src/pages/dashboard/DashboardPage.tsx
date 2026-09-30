import { useId } from 'react'
import { Link } from 'react-router'
import { useCtiBadges } from '@/api/cti'
import { useCardLogsFailed } from '@/api/device-logs'
import { useControlHealth } from '@/api/health'
import { useSummary } from '@/api/monitoring'
import { useRefreshAll } from '@/api/page-refresh'
import { isTargetsNotDeployed, useTargets } from '@/api/targets'
import { Time } from '@/components/atoms/Time'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { PageRefresh } from '@/components/organisms/PageRefresh'
import { AgeDistribution, ControlHealthBand, DashboardMetrics, groupTargets, latestKeys, PendingQueue, SupportTargets, TargetBoard } from '@/components/organisms/dashboard'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cn } from '@/lib/cn'
import { freshnessPart, isPartFailed, type FreshnessPart } from '@/lib/freshness'

/**
 * 관제 현황(S-02, #72 · #83). 위에서부터 관제 이상 띠(있을 때만) → [보호 대상] 카드 → [판정 대기 사건] 대기열 · 경과 분포 · 수치 네 칸 →
 * 관측 센서 · 관제 시스템 접힌 줄 → 최근 원문 수집 한 줄. 이 파일은 조립만 한다.
 * 요약 · 상태판 · 관제 이상 · 카드 로그는 따로 조회한다. 한쪽이 실패해도 다른 쪽은 그대로 보인다.
 * 화면 기준 시각은 제목 줄 오른쪽 새로고침 옆 하나다(#79): 가장 오래전에 성공한 조회의 as_of 이고, 한쪽이라도 실패하면 '일부 갱신 실패',
 * 그 자리(카드 · 접힌 줄 · 대기열 · 수치)에는 '이전 결과' 를 단다. 요약 실패를 공통 띠로 되풀이하지 않는다(실시간 끊김 띠만 남는다).
 * 공통 띠가 없으므로 받은 뒤의 갱신 실패는 기준 시각 옆 낭독 칸(role=status)이 알린다.
 * 판정 대기 사건은 상태판의 queue 가 있으면 요약과 관계없이 그린다. 요약이 한 번도 오지 않았으면 수치 자리에 오류를 작게 둔다.
 * CVE 배지는 최근 사건 줄이 있는 관측 센서 · 관제 시스템 대상의 키로 여기서 한 번만 묻는다(보호 대상 카드에는 최근 사건 줄이 없다).
 * 규칙별 비조치율은 규칙 화면(규칙별 판정 집계)에 있어 여기서는 그리로 잇기만 한다.
 */
export function DashboardPage() {
  const query = useSummary()
  const targets = useTargets()
  const health = useControlHealth()
  const logsFailed = useCardLogsFailed()
  const { refresh, refreshing } = useRefreshAll()
  const queueTitleId = useId()
  const data = query.data
  const queue = targets.data?.queue
  const groups = groupTargets(targets.data?.targets ?? [])
  const badges = useCtiBadges(latestKeys([...groups.sensors, ...groups.system])).data?.badges
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
      <PageHeader title="관제 현황" status={<PageRefresh parts={parts} announce />} />
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={null} onRetry={() => void refresh()} busy={refreshing} />
      <ControlHealthBand health={health} />
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
        <section aria-labelledby={queueTitleId} className="flex min-w-0 flex-col gap-4" data-pending-section="">
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
      <SupportTargets data={targets.data} updatedAt={targets.dataUpdatedAt} badges={badges} stale={targetsStale} />
      {data && (
        <p className="m-0 text-xs text-ink-muted">
          최근 원문 수집 <Time value={data.latest_event} format="short" zone /> · 규칙별 비조치율은 <Link to="/rules">규칙 화면에서 보기</Link>
        </p>
      )}
    </div>
  )
}
