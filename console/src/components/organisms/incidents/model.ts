import type { Incident } from '@/api/incidents'
import { INCIDENT_STATUSES, type IncidentStatus } from '@/lib/domain'
import type { Signal } from '../../atoms/StatusDot'

/**
 * 목록 화면(S-03)의 조각들이 같이 쓰는 값: 링크 · 상태 점 색 · 미판정 여부 · 열 정의.
 * 서버 값의 뜻은 lib/domain 에 있고 여기는 화면 배치만 둔다.
 */

/** 상세 화면 주소. 키는 '|' · ':' · '+' 를 품으므로 부호화한다(라우터가 풀어 준다). */
export function incidentHref(key: string): string {
  return `/incidents/${encodeURIComponent(key)}`
}

export function isIncidentStatus(value: unknown): value is IncidentStatus {
  return typeof value === 'string' && (INCIDENT_STATUSES as readonly string[]).includes(value)
}

/** 상태 점 색. 신규는 아직 손대지 않은 건이라 빨강, 확인은 주황, 조치중은 파랑, 종결은 초록, 억제는 회색. */
export const STATUS_SIGNAL: Record<IncidentStatus, Signal> = {
  open: 'bad',
  acknowledged: 'warn',
  in_progress: 'info',
  resolved: 'ok',
  suppressed: 'idle',
}

/**
 * 판정을 기다리는 건: 판정이 없고, 규칙 억제로 닫힌 건(suppressed)도 아니다.
 * 경과 시간에 목표 대비 색을 주는 기준이다. 판정된 건의 경과는 더 이상 위험이 아니다.
 */
export function isPending(incident: Pick<Incident, 'verdict' | 'status'>): boolean {
  return incident.verdict === null && incident.status !== 'suppressed'
}

/** 출발지 표기. IP 가 없는 건(user:<이름> · node:<id>)은 대상을 보인다. */
export function sourceOf(incident: Pick<Incident, 'actor_ip' | 'target'>): string {
  return incident.actor_ip ?? incident.target ?? '—'
}

/** lg 미만에서 접는 열. 머리 행과 본문 행이 같은 값을 써야 자리가 맞는다. */
export const LG_ONLY = 'hidden lg:block'

export interface Column {
  key: string
  label: string
  className?: string
}

/**
 * 여섯 개 핵심 열. 신호·세션 수는 규칙 아래, 발생원은 출발지 아래에 함께 표시한다.
 */
export const COLUMNS: readonly Column[] = [
  { key: 'elapsed', label: '경과' },
  { key: 'severity', label: '심각도' },
  { key: 'rule', label: '규칙' },
  { key: 'source', label: '출발지 · 대상' },
  { key: 'status', label: '상태' },
  { key: 'verdict', label: '판정' },
]

/**
 * 머리 행과 본문 행이 같이 쓰는 그리드. 좁은 데스크톱에서는 목록 영역만 가로 스크롤된다.
 */
export const ROW_GRID = 'grid items-center gap-3 grid-cols-[76px_76px_minmax(190px,1.5fr)_minmax(140px,1fr)_72px_88px]'
