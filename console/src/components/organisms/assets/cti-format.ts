import type { ApplicabilityStatus, CtiFreshness, FixState } from '@/api/cti'
import { codePointLength, revealHidden, sliceCodePoints } from '@/lib/untrusted'
import type { Tone } from '../../atoms/tones'

/**
 * CVE · KEV 연계(#39) 값을 글로 바꾸는 규칙. 사건 상세의 취약점 연계 구역과 자산 · 취약점 화면이 같이 쓴다.
 * 화면 컴포넌트는 여기 함수만 부르고 판단을 품지 않는다. 오래됨 · 적용 판정은 서버가 정하고 화면은 옮겨 적기만 한다.
 * 모르는 원문(등급 · 표기)을 그대로 돌려줄 때는 revealHidden 을 거친다(수집 원본도 비신뢰다, #41).
 */

/** 적용 판정 배지 색. 미확인은 비해당과 구별되게 경고색이다 */
export const APPLICABILITY_TONE: Record<ApplicabilityStatus, Tone> = { affected: 'danger', not_affected: 'success', unknown: 'warning' }

/** 수정 상태 배지 색 */
export const FIX_STATE_TONE: Record<FixState, Tone> = { fix_available: 'info', reboot_pending: 'orange', no_fix: 'warning', unknown: 'neutral' }

/** NVD 등급(대문자) → 배지 색. 모르는 등급은 중립 */
export function cvssTone(severity: string | null | undefined): Tone {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'danger'
    case 'HIGH':
      return 'orange'
    case 'MEDIUM':
      return 'warning'
    default:
      return 'neutral'
  }
}

/** CVSS 점수 · 등급 한 덩어리('9.8 CRITICAL'). 점수는 소수 한 자리 */
export function formatCvss(score: number | string | null | undefined, severity?: string | null): string {
  const n = Number(score)
  if (score === null || score === undefined || score === '' || !Number.isFinite(n)) return '—'
  const grade = severity ? ` ${revealHidden(severity.toUpperCase())}` : ''
  return `${n.toFixed(1)}${grade}`
}

/** 0~1 확률을 백분율로. 작은 값도 0 으로 뭉개지 않는다(0.00043 → '0.04%') */
export function formatProbability(value: number | string | null | undefined): string {
  const n = Number(value)
  if (value === null || value === undefined || value === '' || !Number.isFinite(n)) return '—'
  const pct = n * 100
  if (pct >= 1) return `${pct.toFixed(1)}%`
  if (pct >= 0.01) return `${pct.toFixed(2)}%`
  return pct > 0 ? '<0.01%' : '0%'
}

/** EPSS 백분위(0~1)를 '백분위 99.9' 로 */
export function formatPercentile(value: number | string | null | undefined): string {
  const n = Number(value)
  if (value === null || value === undefined || value === '' || !Number.isFinite(n)) return '—'
  return `백분위 ${(n * 100).toFixed(1)}`
}

/** KEV 랜섬웨어 사용 표기(knownRansomwareCampaignUse). Known 만 강조한다 */
export function ransomwareLabel(value: string | null | undefined): string {
  if (!value) return '—'
  if (value.toLowerCase() === 'known') return '사용 확인'
  if (value.toLowerCase() === 'unknown') return '알려지지 않음'
  return revealHidden(value)
}

/** Ubuntu 우선순위(OSV severity type 'Ubuntu'). 소문자 원문을 그대로 보이지 않고 한국어로 옮긴다 */
const UBUNTU_PRIORITY_LABEL: Record<string, string> = { negligible: '무시 가능', low: '낮음', medium: '중간', high: '높음', critical: '긴급' }
export function ubuntuPriorityLabel(value: string | null | undefined): string {
  if (!value) return '—'
  return UBUNTU_PRIORITY_LABEL[value.toLowerCase()] ?? revealHidden(value)
}

export function ubuntuPriorityTone(value: string | null | undefined): Tone {
  switch ((value ?? '').toLowerCase()) {
    case 'critical':
      return 'danger'
    case 'high':
      return 'orange'
    case 'medium':
      return 'warning'
    default:
      return 'neutral'
  }
}

/** 신선도 한 줄: 오래된 출처 이름들. 없으면 빈 배열(KEV · EPSS · 배포판 대조 순) */
export function staleSources(freshness: CtiFreshness | null | undefined): string[] {
  if (!freshness) return []
  const names: string[] = []
  if (freshness.kev.stale) names.push('KEV')
  if (freshness.epss.stale) names.push('EPSS')
  if (freshness.osv.stale) names.push('배포판 대조')
  return names
}

/**
 * 긴 글의 앞부분(원문 글자 수 기준, 두 칸짜리 글자를 가르지 않는다). 전체는 title 로 본다.
 * 결과도 원문이므로 화면은 UntrustedText 로, title 은 revealHidden 으로 그린다
 */
export function truncate(text: string | null | undefined, max = 140): string {
  if (!text) return '—'
  return text.length > max && codePointLength(text) > max ? `${sliceCodePoints(text, max - 1)}…` : text
}
