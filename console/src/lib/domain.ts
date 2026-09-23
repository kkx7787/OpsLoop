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

/**
 * 발생원. 규칙 번호대로 도출한다(규칙 정의의 번호 체계).
 * 정상이 없는 환경(허니팟)과 있는 환경(웹 노드 · 콘솔)의 수치를 섞어 보지 않으려고 화면에 따로 보인다(화면 설계 4장).
 *  R0xx 허니팟 · R1xx 웹 노드 · R2xx 콘솔 · 감사 · R3xx 인프라 · 그 밖은 기타
 */
export const SENSORS = ['허니팟', '웹 노드', '콘솔 · 감사', '인프라', '기타'] as const
export type Sensor = (typeof SENSORS)[number]

const SENSOR_BY_HUNDREDS: Record<string, Sensor> = {
  '0': '허니팟',
  '1': '웹 노드',
  '2': '콘솔 · 감사',
  '3': '인프라',
}

export function sensorOf(ruleId: string | null | undefined): Sensor {
  const m = /^R(\d)\d{2}(?!\d)/.exec(ruleId ?? '')
  return (m && SENSOR_BY_HUNDREDS[m[1]]) || '기타'
}

/**
 * 심각도별 목표 시간(초). 화면 설계 3장 표. 시계는 발생 시각(first_ts)부터 세고 교대할 때 초기화하지 않는다.
 *
 * | 심각도   | 확인 목표 | 판정 목표 |
 * | critical | 15분      | 1시간     |
 * | high     | 1시간     | 4시간     |
 * | medium   | 4시간     | 12시간    |
 * | low      | —         | 24시간    |
 *
 * 콘솔 발생 건(R2xx)은 침해사고 신고 기한이 걸리므로 심각도와 관계없이 critical 목표를 따른다.
 */
export const VERDICT_TARGET_SECONDS: Record<Severity, number> = {
  critical: 1 * 3_600,
  high: 4 * 3_600,
  medium: 12 * 3_600,
  low: 24 * 3_600,
}

/** 확인(acknowledge) 목표. low 는 목표가 없다(null). */
export const ACK_TARGET_SECONDS: Record<Severity, number | null> = {
  critical: 15 * 60,
  high: 1 * 3_600,
  medium: 4 * 3_600,
  low: null,
}

/** 이 건의 판정 목표(초). 콘솔 발생 건은 critical 목표. 모르는 심각도는 가장 느슨한 low 로 본다. */
export function verdictTargetSeconds(severity: Severity | string, ruleId?: string | null): number {
  if (ruleId && sensorOf(ruleId) === '콘솔 · 감사') return VERDICT_TARGET_SECONDS.critical
  return isSeverity(severity) ? VERDICT_TARGET_SECONDS[severity] : VERDICT_TARGET_SECONDS.low
}

/** 경과 상태. ok → warn(목표의 2/3 경과, 주황) → over(목표 초과, 빨강). 화면 설계 3장 · 4장. */
export type ElapsedTone = 'ok' | 'warn' | 'over'

export const WARN_RATIO = 2 / 3

export function elapsedTone(severity: Severity | string, pendingSeconds: number, ruleId?: string | null): ElapsedTone {
  if (!Number.isFinite(pendingSeconds) || pendingSeconds <= 0) return 'ok'
  const target = verdictTargetSeconds(severity, ruleId)
  if (pendingSeconds >= target) return 'over'
  if (pendingSeconds >= target * WARN_RATIO) return 'warn'
  return 'ok'
}

/**
 * 콘솔에서 내리는 조치와 화면 표기. 서버(app/main.py ActionIn)가 받는 값 가운데 화면이 내는 네 개.
 * unblock_ip · suppress_rule 은 admin 만(auth/roles.ts 'block.release' · 'rule.suppress').
 */
export const INCIDENT_ACTIONS = ['acknowledge', 'block_ip', 'unblock_ip', 'suppress_rule'] as const
export type IncidentAction = (typeof INCIDENT_ACTIONS)[number]

export const ACTION_LABEL: Record<IncidentAction, string> = {
  acknowledge: '확인',
  block_ip: '차단',
  unblock_ip: '차단 해제',
  suppress_rule: '규칙 억제',
}

export function isIncidentAction(value: unknown): value is IncidentAction {
  return typeof value === 'string' && (INCIDENT_ACTIONS as readonly string[]).includes(value)
}

/** 이력에 남은 조치 이름. 화면이 내지 않는 값(escalate · note 등)은 값 그대로 보인다. */
export function actionLabel(action: string): string {
  return isIncidentAction(action) ? ACTION_LABEL[action] : action
}

/**
 * 조치가 사건 상태를 어떻게 바꾸는지(app/main.py ACTION_STATUS 와 같다).
 * 차단은 종결이 아니다. 종결(resolved)은 판정이 기록될 때만 일어난다. unblock_ip 는 상태를 바꾸지 않는다.
 */
export const ACTION_STATUS: Partial<Record<IncidentAction, IncidentStatus>> = {
  acknowledge: 'acknowledged',
  block_ip: 'in_progress',
  suppress_rule: 'suppressed',
}

/** 판정값의 뜻 한 줄(판정 기준 문서 2장). 판정 패널의 도움말과 제안 설명에 쓴다. */
export const VERDICT_DESCRIPTION: Record<Verdict, string> = {
  threat: '행위로 침해 또는 침해 시도가 확인됐다 — 로그인 뒤 명령 실행 · 파일 투하 · 다른 호스트로 경유 · 대량 자원 소모',
  non_actionable: '규칙은 의도대로 맞았으나 조치할 것이 없다 — 시도만 하고 끊김 · 단발성 탐색 · 이미 차단된 출발지의 이전 활동',
  false_positive: '규칙이 겨냥한 현상이 아닌 것을 잡았다 — 우리 운영 행위 · 파이프라인 사정으로 생긴 신호 · 조건의 논리 결함',
  benign_positive: '정확히 탐지했고 행위자에게 악의도 없다 — 조사 목적이 확인된 기관의 스캐너. 오탐으로 세지 않는다',
  undetermined: '근거가 부족해 판단이 서지 않는다 — 보았고 판단하지 못했다는 기록만 남기고 지표에서는 뺀다',
}
