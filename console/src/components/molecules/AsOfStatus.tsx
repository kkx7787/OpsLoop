import { cn } from '@/lib/cn'
import { FRESHNESS_TICK_MS, freshnessWarning, pageFreshness, STALE_MS, type FreshnessPart } from '@/lib/freshness'
import { useNow } from '@/lib/useNow'
import { Time } from '../atoms/Time'

export interface AsOfStatusProps {
  /** 이 화면의 조회들(freshnessPart). 기준 시각은 가장 오래전에 성공한 조회의 as_of 다 */
  parts: readonly FreshnessPart[]
  /** 이만큼 지나면 'n분 전 기준'. 기본 90초 */
  staleMs?: number
  /** 나이를 재는 지금 시각(ms). 시험 · 카탈로그용. 주지 않으면 15초마다 다시 잰다 */
  now?: number
  className?: string
}

/**
 * 화면 기준 시각(#79): '기준 HH:MM:SS'. 오래되거나 갱신에 실패하면 그 뒤에 경고를 붙인다
 * ('n분 전 기준' · '갱신 실패' · '일부 갱신 실패'). 정상일 때는 시각만이다. 마우스를 올리면 KST 날짜까지 보인다.
 * 조회가 없어도 15초마다 다시 그려 나이를 잰다. 5초마다 바뀌는 글이라 낭독 알림(aria-live)은 두지 않는다.
 */
export function AsOfStatus({ parts, staleMs = STALE_MS, now, className }: AsOfStatusProps) {
  const tick = useNow(now === undefined ? FRESHNESS_TICK_MS : 0)
  const at = now ?? tick
  const freshness = pageFreshness(parts, at, staleMs)
  const warning = freshnessWarning(freshness, at)
  const shown = freshness.asOf !== null
  if (!shown && !warning) return null
  return (
    <span className={cn('text-xs whitespace-nowrap text-ink-muted', className)} data-as-of={freshness.state}>
      {shown && (
        <>
          기준 <Time value={freshness.asOf} format="time" className="font-mono text-ink" />
        </>
      )}
      {shown && warning && ' · '}
      {warning && (
        <span className="font-medium text-warning" data-as-of-warning="">
          {warning}
        </span>
      )}
    </span>
  )
}
