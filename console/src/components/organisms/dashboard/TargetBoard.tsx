import { useId } from 'react'
import { Link } from 'react-router'
import type { CtiBadge } from '@/api/cti'
import { describeError } from '@/api/errors'
import { UNCONFIRMED_DEVICE } from '@/api/incidents'
import { isTargetsNotDeployed, type TargetsResult } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { Button } from '../../atoms/Button'
import { Time } from '../../atoms/Time'
import { InfoTip } from '../../molecules/InfoTip'
import { ApiErrorState } from '../states/ApiErrorState'
import { LoadingState } from '../states/LoadingState'
import { badgeOf, useWide } from './dashboard-layout'
import { groupTargets, orderTargets, pendingHref } from './target-format'
import { TargetCard } from './TargetCard'
import { TargetSummaryList } from './TargetSummaryList'

export interface TargetBoardProps {
  /** GET /api/dashboard/targets 응답. 없으면 첫 조회 중이거나 실패다 */
  data: TargetsResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  /** 마지막 성공 조회 시각(ms) */
  updatedAt: number
  onRetry: () => void
  /** 페이지가 모든 대상의 최근 사건 키로 한 번 받은 CVE 배지 */
  badges?: Readonly<Record<string, CtiBadge>>
  className?: string
}

/**
 * 보호 대상 카드 격자. 카드 최소 22rem(352px, 격자보다 넓으면 격자 폭)으로 채우고 빈 칸은 접는다(auto-fit):
 * 카드 1장이면 폭 전체(넓으면 카드 안 두 단), 본문 768px 이면 2열, 1184px 이면 3열까지. gap-3(0.75rem)
 */
const TARGET_GRID = 'grid gap-3 grid-cols-[repeat(auto-fit,minmax(min(100%,22rem),1fr))]'

/**
 * 보호 대상(#72). 대시보드 맨 위에 web-01 과 등록 노드(#64, 수집 노드 표에 등록한 노드) 카드를 둔다.
 * 관측 센서(AWS 센서) · 관제 시스템(콘솔 · 데이터 노드)은 아래 SupportTargets 가 접힌 줄로 보인다.
 * 넓으면 카드 격자, 좁으면(sm 미만) 대상마다 한 줄로 접어 두고 누르면 카드를 펼친다.
 * 조회 실패는 이 자리만 오류로 보인다. 아래 수치 · 대기열은 따로 조회하므로 막지 않는다.
 * 카드 합이 전체와 다른 까닭은 제목 옆 도움말(ⓘ)에 둔다(카드를 받았을 때만).
 * 장비를 확인하지 못한 미판정 사건은 카드에 세지 않고 아래 한 줄로 목록(device=_unconfirmed)에 잇는다.
 */
export function TargetBoard({ data, pending, fetching, error, updatedAt, onRetry, badges, className }: TargetBoardProps) {
  const titleId = useId()
  const wide = useWide()
  // 각 무리 안은 서버 순서다. 섞여 와도 web-01 이 등록 노드보다 앞이다
  const targets = orderTargets(groupTargets(data?.targets ?? []).protected)
  const asOf = toDate(data?.as_of)?.getTime() ?? updatedAt
  const unconfirmed = data?.unmapped.pending ?? 0

  let body
  if (!data) {
    body = pending ? (
      <LoadingState title="보호 대상을 불러오는 중입니다" lines={2} />
    ) : isTargetsNotDeployed(error) ? (
      <p className="m-0 rounded-card bg-surface px-4 py-3 text-xs text-ink-muted shadow-card" data-targets-missing="">
        {describeError(error)}
      </p>
    ) : (
      <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} titleAs="h3" />
    )
  } else if (wide) {
    body = (
      <div className={TARGET_GRID}>
        {targets.map((target) => (
          <TargetCard key={target.id} target={target} asOf={asOf} cti={badgeOf(badges, target)} />
        ))}
      </div>
    )
  } else {
    body = <TargetSummaryList title="보호 대상" targets={targets} asOf={asOf} badges={badges} />
  }

  return (
    <section aria-labelledby={titleId} className={cn('flex min-w-0 flex-col gap-2', className)}>
      {data ? (
        <InfoTip
          label="보호 대상"
          render={({ button, panel }) => (
            <>
              <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
                <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
                  보호 대상
                </h2>
                {button}
              </div>
              {panel}
            </>
          )}
        >
          카드 수치는 대상별입니다. 한 사건이 여러 대상에 걸칠 수 있어 합이 전체와 다릅니다. 이벤트로 장비를 고르지 못한 사건은 장비 미확인으로 셉니다.
        </InfoTip>
      ) : (
        <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
          보호 대상
        </h2>
      )}
      {data && error ? (
        <div role="status" className="flex flex-wrap items-center gap-2 rounded-panel bg-warning-soft px-3 py-2 text-xs text-warning">
          <span className="min-w-0 flex-1">
            <strong className="font-semibold">대상 카드를 갱신하지 못했습니다</strong> · {describeError(error)} · 이전 결과 유지
            {updatedAt > 0 && (
              <>
                {' '}
                · 마지막 조회 <Time value={updatedAt} format="time" zone />
              </>
            )}
          </span>
          <Button size="sm" onClick={onRetry} loading={fetching}>
            다시 조회
          </Button>
        </div>
      ) : null}
      {body}
      {/* 기준 시각은 페이지 머리 하나만 둔다 */}
      {unconfirmed > 0 && (
        <p className="m-0 text-xs font-medium text-ink" data-unmapped="">
          <Link to={pendingHref(UNCONFIRMED_DEVICE)}>장비 미확인 미판정 {unconfirmed.toLocaleString('ko-KR')}</Link>
        </p>
      )}
    </section>
  )
}
