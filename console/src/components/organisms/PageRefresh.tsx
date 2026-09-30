import { useContext, useLayoutEffect } from 'react'
import { PageRefreshContext, useRefreshAll } from '@/api/page-refresh'
import { cn } from '@/lib/cn'
import { failureWarning, type FreshnessPart } from '@/lib/freshness'
import { Button } from '../atoms/Button'
import { IconRefresh } from '../atoms/icons'
import { AsOfStatus } from '../molecules/AsOfStatus'

export interface PageRefreshProps {
  /** 이 화면의 조회들. freshnessPart(query, data?.as_of) 로 만든다. 카드 로그처럼 실패만 알릴 조회는 세 번째 인자 true */
  parts: readonly FreshnessPart[]
  /** 이만큼 지나면 'n분 전 기준'. 기본 90초 */
  staleMs?: number
  /** 나이를 재는 지금 시각(ms). 시험용 */
  now?: number
  /** 갱신 실패 · 일부 갱신 실패를 낭독 칸(role=status)으로 알린다. 본문에 갱신 실패 띠가 따로 없는 화면(대시보드)만 켠다 */
  announce?: boolean
  className?: string
}

/**
 * 화면 기준 시각 + 새로고침(#79). 대시보드 · 장비 로그 화면이 PageHeader status(제목 줄 오른쪽, 모든 폭)에 둔다.
 * 단추는 상단바 새로고침과 같은 동작(useRefreshAll: 전체 invalidate, 멈춘 로그도 한 번 받고 멈춤 유지)이고,
 * 이 부품이 그려져 있는 동안 상단바 새로고침은 숨는다(PageRefreshContext.claim). 떠나면 상단바 단추가 돌아온다.
 * 페인트 전에(useLayoutEffect) 알려 두 단추가 함께 보이는 순간이 없다.
 * announce 면 보이지 않는 낭독 칸을 늘 두고, 받은 뒤 갱신이 실패했을 때만 경고 글을 넣는다(기준 시각 · 나이는 넣지 않는다).
 */
export function PageRefresh({ parts, staleMs, now, announce = false, className }: PageRefreshProps) {
  const slot = useContext(PageRefreshContext)
  useLayoutEffect(() => slot?.claim(), [slot])
  const { refresh, refreshing } = useRefreshAll()
  return (
    <div className={cn('flex shrink-0 items-center gap-2', className)} data-page-refresh="">
      <AsOfStatus parts={parts} staleMs={staleMs} now={now} />
      <Button
        size="icon"
        aria-label="새로고침"
        onClick={() => void refresh()}
        disabled={refreshing}
        disabledReason="새로고침 중"
        className="text-ink print:hidden"
      >
        <IconRefresh size={14} className={cn(refreshing && 'animate-spin')} />
      </Button>
      {announce && (
        // 칸은 비어 있어도 늘 두고 글만 바꾼다(글과 함께 새로 끼우면 낭독되지 않을 수 있다)
        <span role="status" aria-live="polite" className="sr-only" data-refresh-announce="">
          {failureWarning(parts) ?? ''}
        </span>
      )}
    </div>
  )
}
