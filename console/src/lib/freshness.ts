import { formatRelative } from './time'

/**
 * 화면 기준 시각(#79). 한 화면이 받는 조회 몇 개를 모아 기준 시각 하나와 경고 하나로 줄인다.
 *  기준 시각은 가장 오래전에 성공한 조회의 서버 시각(as_of)이다. 한쪽이 실패했는데 기준 시각만 최신으로 바뀌지 않게 한다.
 *  나이는 브라우저 시계끼리(성공 시각 dataUpdatedAt 과 지금) 재서 DB 시계와의 차이를 타지 않는다.
 *  실패 판정은 health.ts · 장비 로그 화면과 같다: isError 거나, 마지막으로 끝난 조회가 실패(errorUpdatedAt > dataUpdatedAt).
 */

/** 조회 하나. react-query 결과를 freshnessPart 로 옮겨 넣는다 */
export interface FreshnessPart {
  /** 마지막 성공 시각(브라우저 ms). 0 이면 받은 적 없음 */
  dataUpdatedAt: number
  /** 마지막 실패 시각(브라우저 ms). 0 이면 실패한 적 없음 */
  errorUpdatedAt: number
  isError: boolean
  /** 그 응답의 서버 기준 시각(as_of). 화면에 보이는 시각 */
  asOf?: string | number | null
  /** 실패만 알리고 기준 시각 · 나이에는 넣지 않는다(카드 로그처럼 화면 일부만 채우는 조회) */
  failureOnly?: boolean
}

/**
 * pending: 아직 받은 것이 없음(시각 없음) · ok: 시각만 · stale: 'n분 전 기준' ·
 * partial: 일부 조회 실패 '일부 갱신 실패' · failed: 시각을 정하는 조회가 모두 실패 '갱신 실패'
 */
export type FreshnessState = 'pending' | 'ok' | 'stale' | 'partial' | 'failed'

export interface Freshness {
  state: FreshnessState
  /** 보일 기준 시각(가장 오래전에 성공한 조회의 as_of). 받은 적 없으면 null */
  asOf: string | number | null
  /** 가장 오래전 성공의 브라우저 시각(ms). 받은 적 없으면 null */
  since: number | null
}

/** 가장 오래된 성공이 이만큼 지나면 'n분 전 기준' 이다. 대시보드 30초 주기를 두 번 넘게 놓친 때 */
export const STALE_MS = 90_000

/** 기준 시각 나이를 다시 재는 주기. 조회 이벤트가 없어도(요청이 걸려 멈춤 · 일시정지) 이 주기로 경고가 붙는다 */
export const FRESHNESS_TICK_MS = 15_000

export function isPartFailed(part: FreshnessPart): boolean {
  return part.isError || part.errorUpdatedAt > part.dataUpdatedAt
}

/** react-query 조회 결과에서 필요한 칸만 옮긴다 */
export function freshnessPart(
  query: Pick<FreshnessPart, 'dataUpdatedAt' | 'errorUpdatedAt' | 'isError'>,
  asOf?: string | number | null,
  failureOnly = false,
): FreshnessPart {
  return { dataUpdatedAt: query.dataUpdatedAt, errorUpdatedAt: query.errorUpdatedAt, isError: query.isError, asOf: asOf ?? null, failureOnly }
}

export function pageFreshness(parts: readonly FreshnessPart[], now: number, staleMs = STALE_MS): Freshness {
  const timed = parts.filter((part) => !part.failureOnly)
  let oldest: FreshnessPart | null = null
  for (const part of timed) {
    if (part.dataUpdatedAt > 0 && (!oldest || part.dataUpdatedAt < oldest.dataUpdatedAt)) oldest = part
  }
  const asOf = oldest?.asOf ?? null
  const since = oldest?.dataUpdatedAt ?? null
  if (timed.length > 0 && timed.every(isPartFailed)) return { state: 'failed', asOf, since }
  if (parts.some(isPartFailed)) return { state: 'partial', asOf, since }
  if (since === null) return { state: 'pending', asOf, since }
  return { state: now - since > staleMs ? 'stale' : 'ok', asOf, since }
}

/**
 * 낭독 칸에 넣을 경고: '갱신 실패' · '일부 갱신 실패' 만. 기준 시각 · 'n분 전 기준' 은 넣지 않는다(주기 갱신 · 나이 재기마다 읽히지 않게).
 * 실패 판정은 시각과 무관하다
 */
export function failureWarning(parts: readonly FreshnessPart[]): string | null {
  const { state } = pageFreshness(parts, 0)
  return state === 'failed' || state === 'partial' ? freshnessWarning({ state, asOf: null, since: null }, 0) : null
}

/** 기준 시각 옆에 붙일 경고(#79 원문). 정상 · 받는 중이면 null */
export function freshnessWarning(freshness: Freshness, now: number): string | null {
  switch (freshness.state) {
    case 'failed':
      return '갱신 실패'
    case 'partial':
      return '일부 갱신 실패'
    case 'stale':
      return `${formatRelative(freshness.since, now)} 기준`
    default:
      return null
  }
}
