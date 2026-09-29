import { useSyncExternalStore } from 'react'
import type { CtiBadge } from '@/api/cti'
import type { Target } from '@/api/targets'

/**
 * 대시보드 조각이 같이 쓰는 배치 도구(#72). 컴포넌트 파일에는 컴포넌트만 둔다(.oxlintrc only-export-components).
 *  useWide  보호 대상을 카드로 그릴지(sm 이상), 접힌 요약으로 그릴지
 *  badgeOf  페이지가 한 번 받은 CVE 배지에서 그 대상의 최근 사건 배지를 고른다
 */

/** Tailwind 의 sm 과 같다. 이보다 좁으면 카드를 접힌 요약으로 보인다 */
const WIDE_QUERY = '(min-width: 640px)'

function subscribe(onChange: () => void): () => void {
  if (typeof window.matchMedia !== 'function') return () => undefined
  const mq = window.matchMedia(WIDE_QUERY)
  mq.addEventListener('change', onChange)
  return () => mq.removeEventListener('change', onChange)
}

/** matchMedia 가 없는 환경(시험)은 넓은 화면으로 본다(useIsDesktop 과 같은 기준) */
function snapshot(): boolean {
  if (typeof window.matchMedia !== 'function') return true
  return window.matchMedia(WIDE_QUERY).matches
}

/** 카드 · 접힌 요약 가운데 하나만 그린다(둘 다 DOM 에 두면 낭독 순서가 겹친다) */
export function useWide(): boolean {
  return useSyncExternalStore(subscribe, snapshot, () => true)
}

/** 최근 사건의 배지. 자기 속성만 본다 */
export function badgeOf(badges: Readonly<Record<string, CtiBadge>> | undefined, target: Pick<Target, 'security'>): CtiBadge | undefined {
  const key = target.security?.latest?.incident_key
  return key && badges && Object.hasOwn(badges, key) ? badges[key] : undefined
}

/** 대상들의 최근 사건 키. 페이지가 모든 대상의 키로 useCtiBadges 를 한 번만 부른다 */
export function latestKeys(targets: readonly Pick<Target, 'security'>[]): string[] {
  return targets.flatMap((t) => (t.security?.latest ? [t.security.latest.incident_key] : []))
}
