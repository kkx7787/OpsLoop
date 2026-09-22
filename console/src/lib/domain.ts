/**
 * 화면 여러 곳이 같이 쓰는 값과 화면 표기. DB 의 CHECK 제약(infra/schema.sql)과 같은 값만 둔다.
 * 표기는 판정 기준 문서를 따른다. 화면마다 다른 말을 쓰지 않는다(화면 설계 6.1).
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
export type Severity = (typeof SEVERITIES)[number]

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value)
}

export const VERDICTS = ['threat', 'non_actionable', 'false_positive', 'benign_positive', 'undetermined'] as const
export type Verdict = (typeof VERDICTS)[number]

export const VERDICT_LABEL: Record<Verdict, string> = {
  threat: '실제 위협',
  non_actionable: '무시 가능',
  false_positive: '오탐',
  benign_positive: '양성 정탐',
  undetermined: '미결',
}

export function isVerdict(value: unknown): value is Verdict {
  return typeof value === 'string' && (VERDICTS as readonly string[]).includes(value)
}

/** 상태 전이: 신규 → 확인 → 조치중 → 종결 (화면 설계 15장). 억제는 규칙 억제 조치로 닫힌 건이다. */
export const INCIDENT_STATUSES = ['open', 'acknowledged', 'in_progress', 'resolved', 'suppressed'] as const
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number]

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  open: '신규',
  acknowledged: '확인',
  in_progress: '조치중',
  resolved: '종결',
  suppressed: '억제',
}
