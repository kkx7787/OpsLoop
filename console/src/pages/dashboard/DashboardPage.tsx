import { Link } from 'react-router'
import { useCtiBadges } from '@/api/cti'
import { useControlHealth } from '@/api/health'
import { useSummary } from '@/api/monitoring'
import { useTargets } from '@/api/targets'
import { Time } from '@/components/atoms/Time'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { AgeDistribution, ControlHealthBand, DashboardMetrics, latestKeys, PendingQueue, SupportTargets, TargetBoard } from '@/components/organisms/dashboard'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cn } from '@/lib/cn'

/**
 * 관제 현황(S-02, 보호 대상 중심 #72). 위에서부터 관제 이상 띠(있을 때만) → 보호 대상 카드 → 미판정 수치 네 칸 →
 * 먼저 처리할 사건 · 경과 분포 → 관측 센서 · 관제 시스템 접힌 줄. 이 파일은 조립만 한다.
 * 요약 · 상태판 · 관제 이상은 따로 조회한다. 한쪽이 실패해도 다른 쪽은 그대로 보인다.
 * 먼저 처리할 사건은 상태판의 queue 가 있으면 요약과 관계없이 그린다. 요약도 queue 도 없을 때만 요약 오류 화면이다
 * (queue 가 있을 때 요약 실패는 공통 띠가 알린다).
 * CVE 배지는 모든 대상의 최근 사건 키로 여기서 한 번만 묻고 카드 · 접힌 줄에 나눠 준다.
 * 규칙별 비조치율은 규칙 화면(규칙별 판정 집계)에 있어 여기서는 그리로 잇기만 한다.
 */
export function DashboardPage() {
  const query = useSummary()
  const targets = useTargets()
  const health = useControlHealth()
  const data = query.data
  const queue = targets.data?.queue
  const badges = useCtiBadges(latestKeys(targets.data?.targets ?? [])).data?.badges
  const asOf = data?.as_of ?? targets.data?.as_of
  const retryAll = () => { void query.refetch(); void targets.refetch(); void health.refetch() }
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="관제 현황" aside={asOf && <span className="text-xs text-ink-muted"><Time value={asOf} format="time" zone /> 기준</span>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={data || queue ? query.error : null} onRetry={retryAll} busy={query.isFetching} />
    <ControlHealthBand health={health} />
    <TargetBoard data={targets.data} pending={targets.isPending} fetching={targets.isFetching} error={targets.error} updatedAt={targets.dataUpdatedAt} onRetry={() => void targets.refetch()} badges={badges} />
    {data ? <DashboardMetrics summary={data} /> : queue ? null : query.isPending ? <LoadingState title="대시보드를 불러오는 중입니다" /> : <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />}
    {(data || queue) && <div className={cn('grid items-start gap-4', data && 'xl:grid-cols-[minmax(0,1fr)_300px]')}>
      <PendingQueue queue={queue} oldest={data?.oldest_pending} />
      {data && <AgeDistribution pending={data.pending} />}
    </div>}
    <SupportTargets data={targets.data} updatedAt={targets.dataUpdatedAt} badges={badges} />
    {data && <p className="m-0 text-xs text-ink-muted">최근 원문 수집 <Time value={data.latest_event} format="short" zone /> · 규칙별 비조치율은 <Link to="/rules">규칙 화면에서 보기</Link></p>}
  </div>
}
