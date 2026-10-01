import { useId } from 'react'
import { Link } from 'react-router'
import { describeError } from '@/api/errors'
import { UNCONFIRMED_DEVICE } from '@/api/incidents'
import { isTargetsNotDeployed, type TargetsResult } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { InfoTip } from '../../molecules/InfoTip'
import { ApiErrorState } from '../states/ApiErrorState'
import { LoadingState } from '../states/LoadingState'
import { useWide } from './dashboard-layout'
import { ProtectedCard } from './ProtectedCard'
import { groupTargets, orderTargets, pendingHref } from './target-format'
import { TargetSummaryList } from './TargetSummaryList'

export interface TargetBoardProps {
  /** GET /api/dashboard/targets 응답. 없으면 첫 조회 중이거나 실패다 */
  data: TargetsResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  /** 받은 뒤 갱신이 실패했다(이전 결과를 보이는 중). 카드마다 '이전 결과' 를 단다 */
  stale?: boolean
  /** 마지막 성공 조회 시각(ms). as_of 가 없을 때 상대 시각의 기준 */
  updatedAt: number
  onRetry: () => void
  className?: string
}

/**
 * 보호 대상 카드 격자(#83). 넓으면(lg 이상) 두 열 고정, 좁으면 한 열. 1장이어도 반쪽 폭이라 장비가 늘어도 카드 폭 · 높이가 같다
 * (등록 노드가 생기면 빈 칸에 들어가고 web-01 카드가 다시 흐르지 않는다). 나란한 카드는 격자가 높이를 맞춘다(items-stretch)
 */
const TARGET_GRID = 'grid grid-cols-1 items-stretch gap-3 lg:grid-cols-2'

/**
 * 보호 대상(#72 · #83). 대시보드 관제 이상 띠 아래에 web-01 과 등록 노드(#64) 카드를 둔다.
 * 관측 센서(허니팟 센서) · 관제 시스템(콘솔 · 데이터 노드)은 수집 · 관제 상태 화면(#84)이 접힌 줄로 보인다.
 * 넓으면(sm 이상) 카드 격자, 좁으면 대상마다 한 줄로 접어 두고 누르면 카드를 펼친다.
 * 첫 조회 실패는 이 자리만 오류로 보인다. 받은 뒤 갱신 실패는 경고 띠를 쌓지 않고 카드마다 '이전 결과' 를 달며,
 * 다시 받기는 화면 머리의 새로고침 하나로 한다(상단 기준 시각 옆 '일부 갱신 실패', #79).
 * 카드 합이 전체와 다른 까닭은 제목 옆 도움말(ⓘ)에 둔다(카드를 받았을 때만).
 * 장비를 확인하지 못한 미판정 사건은 카드에 세지 않고 아래 한 줄로 목록(device=_unconfirmed)에 잇는다.
 */
export function TargetBoard({ data, pending, fetching, error, stale = false, updatedAt, onRetry, className }: TargetBoardProps) {
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
      <div className={TARGET_GRID} data-target-grid="">
        {targets.map((target) => (
          <ProtectedCard key={target.id} target={target} asOf={asOf} stale={stale} />
        ))}
      </div>
    )
  } else {
    body = <TargetSummaryList title="보호 대상" targets={targets} asOf={asOf} badges={undefined} card="protected" stale={stale} />
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
