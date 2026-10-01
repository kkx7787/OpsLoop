import { useId } from 'react'
import { describeError } from '@/api/errors'
import type { CtiBadge } from '@/api/cti'
import { isTargetsNotDeployed, type Target, type TargetId, type TargetsResult } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { ApiErrorState } from '../states/ApiErrorState'
import { LoadingState } from '../states/LoadingState'
import { groupTargets } from './target-format'
import { TargetSummaryList } from './TargetSummaryList'

export interface SupportTargetsProps {
  /** GET /api/dashboard/targets 응답. 없으면 첫 조회 중이거나 실패다 */
  data: TargetsResult | undefined
  pending: boolean
  fetching?: boolean
  error: unknown
  onRetry: () => void
  /** 마지막 성공 조회 시각(ms). as_of 가 없을 때 상대 시각의 기준 */
  updatedAt: number
  /** 페이지가 한 번 받은 최근 사건 CVE 배지 */
  badges?: Readonly<Record<string, CtiBadge>>
  /** 받은 뒤 상태판 갱신이 실패했다(이전 결과를 보이는 중). 줄마다 '이전 결과' */
  stale?: boolean
  /** 처음 펼칠 줄(#84 ?open). 그 대상이 든 무리만 펼친다 */
  open?: TargetId
  className?: string
}

/**
 * 수집 · 관제 상태 화면(#84)의 관측 센서(허니팟 센서) · 관제 시스템(콘솔 · 데이터 노드). 모든 폭에서 대상마다 한 줄씩 접어 둔다.
 * 머리 배지(데이터 노드 확인 멈춤은 '주의', 콘솔은 '응답 중') · 요약 줄 배지(지점 적용 · 보고 문제 · 멈춤) · 미판정만 보이고, 누르면 카드를 펼친다.
 * 넓으면(md 이상) 두 무리를 나란히, 좁으면 쌓는다. 상태 화면이라 받지 못해도 두 무리 제목을 그리고, 첫 조회 실패는 제목 위에 오류 하나
 * (다시 시도 하나, 제목에 두 무리 이름 — 등록 노드 오류와 가른다), 상태판 API 가 없는 이전 서버(404)는 배포 전 한 줄이다.
 */
export function SupportTargets({ data, pending, fetching = false, error, onRetry, updatedAt, badges, stale = false, open, className }: SupportTargetsProps) {
  const groups = groupTargets(data?.targets ?? [])
  const asOf = toDate(data?.as_of)?.getTime() ?? updatedAt
  let notice = null
  if (!data) {
    notice = pending ? (
      <LoadingState title="관측 센서 · 관제 시스템을 불러오는 중입니다" lines={2} />
    ) : isTargetsNotDeployed(error) ? (
      <p className="m-0 rounded-card bg-surface px-4 py-3 text-xs text-ink-muted shadow-card" data-targets-missing="">
        {describeError(error)}
      </p>
    ) : (
      <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} titleAs="h3" title="관측 센서 · 관제 시스템을 불러오지 못했습니다" />
    )
  }
  return (
    <div className={cn('flex min-w-0 flex-col gap-2', className)}>
      {notice}
      <div className="grid items-start gap-4 md:grid-cols-2">
        <Group title="관측 센서" section="sensors" targets={groups.sensors} received={!!data} asOf={asOf} badges={badges} stale={stale} open={open} />
        <Group title="관제 시스템" section="system" targets={groups.system} received={!!data} asOf={asOf} badges={badges} stale={stale} open={open} />
      </div>
    </div>
  )
}

interface GroupProps {
  title: string
  section: 'sensors' | 'system'
  targets: Target[]
  /** 상태판을 받았다(못 받았으면 제목만 둔다. 오류 · 받는 중은 위에 하나) */
  received: boolean
  asOf: number
  badges: SupportTargetsProps['badges']
  stale: boolean
  open: TargetId | undefined
}

function Group({ title, section, targets, received, asOf, badges, stale, open }: GroupProps) {
  const titleId = useId()
  return (
    <section aria-labelledby={titleId} className="flex min-w-0 flex-col gap-2" data-status-section={section}>
      <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
        {title}
      </h2>
      {targets.length > 0 ? (
        <TargetSummaryList title={title} targets={targets} asOf={asOf} badges={badges} stale={stale} defaultOpen={open} />
      ) : (
        received && <p className="m-0 text-xs text-ink-muted">대상 없음</p>
      )}
    </section>
  )
}
