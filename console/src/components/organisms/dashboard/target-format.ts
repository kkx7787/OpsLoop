import type { CollectionState, SystemState, Target, TargetAssetVulns, TargetLog, TargetMetrics, TargetResponse } from '@/api/targets'
import { toDate } from '@/lib/time'
import type { Tone } from '../../atoms/tones'

/**
 * 관제 대상 카드(#52)의 값을 글로 바꾸는 규칙. 카드 컴포넌트는 여기 함수만 부르고 판단을 품지 않는다.
 * 수집 상태 · 오래됨 · 적용 확인은 서버가 정한다. 화면은 옮겨 적기만 하고, 로그 시각만으로 정상 · 장애 색을 만들지 않는다.
 */

/** 수집 상태 배지. 글자 없이 색만 쓰지 않는다. 미확인은 장애가 아니라 모른다는 뜻이라 중립색이다 */
export const COLLECTION_LABEL: Record<CollectionState, string> = {
  ok: '정상',
  quiet: '요청 없음',
  no_signal: '수신 없음',
  unknown: '생존 상태 미확인',
}

export const COLLECTION_TONE: Record<CollectionState, Tone> = {
  ok: 'success',
  quiet: 'neutral',
  no_signal: 'warning',
  unknown: 'neutral',
}

/** 모르는 상태 값은 미확인으로 읽는다(정상으로 꾸미지 않는다) */
export function collectionState(value: string | null | undefined): CollectionState {
  return value === 'ok' || value === 'quiet' || value === 'no_signal' ? value : 'unknown'
}

/** 로그 가운데 가장 최근 시각. 없으면 null */
export function latestLog(logs: readonly TargetLog[]): TargetLog | null {
  let best: TargetLog | null = null
  let bestMs = -Infinity
  for (const log of logs) {
    const ms = toDate(log.last_at)?.getTime()
    if (ms !== undefined && ms > bestMs) {
      best = log
      bestMs = ms
    }
  }
  return best
}

/** 백분율 한 칸. 값이 없으면 '—'. 소수 첫째 자리에서 반올림한다 */
export function formatPct(value: number | null | undefined): string {
  const n = Number(value)
  if (value === null || value === undefined || !Number.isFinite(n)) return '—'
  return `${Math.round(n)}%`
}

/** 시스템 구역 한 줄. ok · stale 만 수치를 보이고, 나머지는 까닭을 글로 보인다(0% 로 꾸미지 않는다) */
export const SYSTEM_TEXT: Record<Exclude<SystemState, 'ok' | 'stale'>, string> = {
  not_collected: '자원 지표 미수집',
  no_privilege: '자원 지표 읽기 권한 없음',
  no_data: '자원 지표 없음',
}

export function metricsText(metrics: TargetMetrics): string {
  return `CPU ${formatPct(metrics.cpu_pct)} · 메모리 ${formatPct(metrics.mem_used_pct)} · 디스크 ${formatPct(metrics.disk_root_pct)}`
}

export function systemText(state: SystemState, metrics: TargetMetrics | null): string {
  if ((state === 'ok' || state === 'stale') && metrics) return metricsText(metrics)
  if (state === 'ok' || state === 'stale') return SYSTEM_TEXT.no_data
  return SYSTEM_TEXT[state] ?? SYSTEM_TEXT.no_data
}

/** 대응 구역의 한 조각. tone 이 있으면 배지, 없으면 흐린 글로 그린다 */
export interface ResponsePart {
  key: 'applied' | 'failed' | 'unverified' | 'exempt' | 'stalled' | 'none' | 'unknown'
  text: string
  tone?: Tone
}

const positive = (n: number | null | undefined): n is number => typeof n === 'number' && Number.isFinite(n) && n > 0
const count = (n: number) => n.toLocaleString('ko-KR')

/**
 * 대응 구역 문구. 숫자 0 을 그리지 않는다(0 이 '막았다 · 못 막았다' 로 읽히지 않게).
 *  집행 지점이 있으면: 적용 확인 n (지점) · 적용 실패 n (지점) · 적용 여부 미확인 n · 정책상 차단 제외 n.
 *    넷 다 없으면 '<지점> 집행 대상 차단 없음'(집행 제외 차단만 있어도 거짓이 되지 않는 문구다)
 *    집행기 확인이 멈췄으면(stalled) 서버가 적용 · 실패를 미확인에 합쳐 보낸다. 그 까닭을 주의색 글로 덧붙인다
 *  집행 지점이 없으면(적용 결과를 수집하지 않는 대상): '차단 적용 여부 미확인'(숫자 없이) · 정책상 차단 제외 n
 * 적용 확인은 초록(차단 목록의 '적용 확인' 과 같다), 실패는 빨강(차단 목록 · 상세의 지점 '실패' 와 같다), 미확인은 주의색이다
 */
export function responseParts(response: TargetResponse): ResponsePart[] {
  const parts: ResponsePart[] = []
  if (response.point) {
    const label = response.point_label ?? response.point
    if (positive(response.applied)) parts.push({ key: 'applied', text: `차단 적용 ${count(response.applied)} (${label})`, tone: 'success' })
    if (positive(response.failed)) parts.push({ key: 'failed', text: `차단 적용 실패 ${count(response.failed)} (${label})`, tone: 'danger' })
    if (positive(response.unverified)) parts.push({ key: 'unverified', text: `차단 적용 여부 미확인 ${count(response.unverified)}`, tone: 'warning' })
    if (positive(response.exempt)) parts.push({ key: 'exempt', text: `정책상 차단 제외 ${count(response.exempt)}`, tone: 'neutral' })
    if (!parts.length) parts.push({ key: 'none', text: `${label} 집행 대상 차단 없음` })
    if (response.stalled) parts.push({ key: 'stalled', text: response.stalled })
    return parts
  }
  parts.push({ key: 'unknown', text: '차단 적용 여부 미확인' })
  if (positive(response.exempt)) parts.push({ key: 'exempt', text: `정책상 차단 제외 ${count(response.exempt)}`, tone: 'neutral' })
  return parts
}

/** 취약점 구역 자산 한 줄의 본문(시각 · 오래됨 표지는 카드가 붙인다) */
export function vulnText(asset: TargetAssetVulns): string {
  if (asset.missing) return '자산 정보 없음'
  if (!asset.collected_at) return '조사 기록 없음'
  // 배포판 대조 전의 0 은 '취약점 없음' 이 아니다
  if (!asset.checked_at) return '취약점 대조 전'
  return `취약점 ${count(asset.vuln_total)} · KEV ${count(asset.vuln_kev)}`
}

/** 자산 · 취약점 화면에서 그 자산을 연 주소 */
export function assetHref(assetId: string): string {
  return `/inventory?asset=${encodeURIComponent(assetId)}`
}

/** 모바일 접힌 요약의 미판정 글 */
export function pendingText(target: Pick<Target, 'security'>): string {
  return `미판정 ${count(target.security.pending)}`
}
