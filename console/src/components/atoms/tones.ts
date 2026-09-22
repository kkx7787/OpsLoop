import type { Severity, Verdict } from '@/lib/domain'

/**
 * 색 조합표. Tailwind 는 소스에 적힌 클래스만 만들므로 클래스 이름을 문자열로 조립하지 않고
 * 여기 통째로 적는다. 값은 src/styles/index.css 의 토큰이다.
 */

export type Tone = 'neutral' | 'info' | 'success' | 'warning' | 'danger' | 'orange' | 'violet'

/** 배지 · 칩처럼 바탕을 칠하는 것 */
export const SOFT_TONE: Record<Tone, string> = {
  neutral: 'bg-muted-soft text-muted',
  info: 'bg-primary-soft text-primary',
  success: 'bg-success-soft text-success',
  warning: 'bg-warning-soft text-warning',
  danger: 'bg-danger-soft text-danger',
  orange: 'bg-orange-soft text-orange',
  violet: 'bg-violet-soft text-violet',
}

/** 글자에만 색을 주는 것(상태 화면의 머리말 등) */
export const TEXT_TONE: Record<Tone, string> = {
  neutral: 'text-ink-muted',
  info: 'text-primary',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  orange: 'text-orange',
  violet: 'text-violet',
}

export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'bg-severity-critical-soft text-severity-critical',
  high: 'bg-severity-high-soft text-severity-high',
  medium: 'bg-severity-medium-soft text-severity-medium',
  low: 'bg-severity-low-soft text-severity-low',
}

export const VERDICT_CLASS: Record<Verdict, string> = {
  threat: 'bg-verdict-threat-soft text-verdict-threat',
  non_actionable: 'bg-verdict-non-actionable-soft text-verdict-non-actionable',
  false_positive: 'bg-verdict-false-positive-soft text-verdict-false-positive',
  benign_positive: 'bg-verdict-benign-positive-soft text-verdict-benign-positive',
  undetermined: 'bg-verdict-undetermined-soft text-verdict-undetermined',
}
