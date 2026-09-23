import type { ActionRecord, ActorBlock, BehaviorRow, EvidenceSample, IncidentDetail, RawLine, VerdictRecord } from '@/api/incidents'
import { actionLabel, VERDICT_LABEL, type IncidentStatus, type Verdict } from '@/lib/domain'
import { formatKst, toDate } from '@/lib/time'
import type { Tone } from '../../atoms/tones'

/**
 * 상세 화면(S-04)이 서버 행을 글로 바꾸는 규칙. 화면 컴포넌트는 여기 함수만 부르고 판단을 품지 않는다.
 */

/** 표에 보이는 최대 행 수. 서버는 행위 200행 · 원문 300행까지 주지만 화면은 이 수를 넘기지 않는다 */
export const MAX_ROWS = 300

/** 판정 소요 초의 상한(서버 VerdictIn 의 le=86400) */
export const MAX_DECISION_SECONDS = 86_400

/** 차단 만료 선택지(시간). 서버는 1..720 을 받고 기본은 24 */
export const BLOCK_HOURS = [1, 6, 24, 72, 168] as const
export const DEFAULT_BLOCK_HOURS = 24

/** 만료 시간의 화면 표기. 하루 이상은 일수로 */
export function hoursLabel(hours: number): string {
  return hours >= 24 ? `${hours / 24}일 (${hours}시간)` : `${hours}시간`
}

/** 상세 경로. 목록 조각(organisms/incidents)의 것과 같은 함수다 */
export { incidentHref } from '../incidents/model'

/** 상태 배지 색. 신규는 중립색으로 심각도와 구별한다 */
export const STATUS_TONE: Record<IncidentStatus, Tone> = {
  open: 'neutral',
  acknowledged: 'info',
  in_progress: 'orange',
  resolved: 'success',
  suppressed: 'neutral',
}

/** 화면을 연 시각부터 지금까지의 초. 음수 · 상한 밖은 잘라 서버가 422 를 주지 않게 한다 */
export function decisionSeconds(openedAt: number, now: number = Date.now()): number {
  const seconds = Math.floor((now - openedAt) / 1000)
  return Math.min(MAX_DECISION_SECONDS, Math.max(0, seconds))
}

/** 행위 한 줄의 요약. 명령 → 요청 → 파일 → 계정 순으로, 있는 것 하나만 보인다 */
export function summarizeBehavior(row: BehaviorRow): string {
  if (row.input) return row.input
  if (row.url) {
    const method = row.http_method ? `${row.http_method} ` : ''
    const status = row.http_status !== null && row.http_status !== undefined ? ` → ${row.http_status}` : ''
    return `${method}${row.url}${status}`
  }
  if (row.shasum) return `파일 ${row.shasum}`
  if (row.username) return `계정 ${row.username}`
  return '—'
}

/** 원문 한 줄. 비밀번호 원문은 서버가 주지 않으므로 있었다는 표시만 남긴다 */
export function formatRawLine(row: RawLine): string {
  const parts: string[] = [formatKst(row.ts, 'datetime'), row.sensor, row.eventid]
  if (row.session) parts.push(`session=${row.session}`)
  if (row.username) parts.push(`user=${row.username}`)
  if (row.has_password) parts.push('password=[있음]')
  if (row.input) parts.push(`input=${row.input}`)
  if (row.url) parts.push(`${row.http_method ?? ''} ${row.url}${row.http_status !== null && row.http_status !== undefined ? ` ${row.http_status}` : ''}`.trim())
  if (row.shasum) parts.push(`shasum=${row.shasum}`)
  if (row.user_agent) parts.push(`ua=${row.user_agent}`)
  if (row.message) parts.push(row.message)
  return parts.join('  ')
}

/** 시각으로 보이는 열 이름(ts · first_ts · created_at · last_seen …). 값이 시각이면 KST 로 바꾼다 */
const TIME_KEY = /(^|_)(ts|at|time|seen)$/

/** 증거 표본의 값 하나를 글로. 객체 · 배열은 JSON 그대로 */
export function formatValue(value: unknown, key = ''): string {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'string') {
    if (TIME_KEY.test(key) && toDate(value)) return formatKst(value, 'datetime')
    return value
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function isSampleObject(sample: EvidenceSample): sample is Record<string, unknown> {
  return sample !== null && typeof sample === 'object'
}

/** 객체 표본들의 열 이름(처음 나온 순서). 규칙마다 표본 모양이 달라 정해 둘 수 없다 */
export function sampleColumns(samples: readonly EvidenceSample[]): string[] {
  const columns: string[] = []
  for (const sample of samples) {
    if (!isSampleObject(sample)) continue
    for (const key of Object.keys(sample)) if (!columns.includes(key)) columns.push(key)
  }
  return columns
}

export type BlockState = 'active' | 'pending' | 'released' | 'expired'

/** 차단 행의 지금 상태. active 는 집행됐고 살아 있음, pending 은 요청했지만 아직 집행 전 */
export function blockState(block: ActorBlock, now: number = Date.now()): BlockState {
  if (block.released_at) return 'released'
  const expires = toDate(block.expires_at)
  if (expires && expires.getTime() <= now) return 'expired'
  return block.enforced_at ? 'active' : 'pending'
}

export const BLOCK_STATE_LABEL: Record<BlockState, string> = {
  active: '차단 중',
  pending: '집행 대기',
  released: '해제됨',
  expired: '만료됨',
}

export const BLOCK_STATE_TONE: Record<BlockState, Tone> = {
  active: 'danger',
  pending: 'warning',
  released: 'neutral',
  expired: 'neutral',
}

/** 풀 수 있는 차단인가(해제 조치의 조건) */
export function isActiveBlock(block: ActorBlock | null, now: number = Date.now()): boolean {
  if (!block) return false
  const state = blockState(block, now)
  return state === 'active' || state === 'pending'
}

/** 판정 · 조치 이력을 한 줄로 합친 것 */
export interface HistoryEntry {
  kind: 'verdict' | 'action'
  id: number
  created_at: string
  operator: string
  /** 판정값 또는 조치 이름의 화면 표기 */
  label: string
  verdict?: Verdict
  /** 판정 사유 또는 조치 메모 */
  note: string | null
  observed_value?: number | null
  proposed?: Verdict | null
  decision_seconds?: number | null
}

function fromVerdict(v: VerdictRecord): HistoryEntry {
  return { kind: 'verdict', id: v.id, created_at: v.created_at, operator: v.operator, label: VERDICT_LABEL[v.verdict] ?? v.verdict, verdict: v.verdict, note: v.reason, observed_value: v.observed_value, proposed: v.proposed, decision_seconds: v.decision_seconds }
}

function fromAction(a: ActionRecord): HistoryEntry {
  return { kind: 'action', id: a.id, created_at: a.created_at, operator: a.operator, label: actionLabel(a.action), note: a.note }
}

/** 판정과 조치를 시각 최근 순으로 섞는다. 같은 시각이면 판정을 위에 둔다 */
export function mergeHistory(detail: Pick<IncidentDetail, 'verdicts' | 'actions'>): HistoryEntry[] {
  const entries = [...detail.verdicts.map(fromVerdict), ...detail.actions.map(fromAction)]
  return entries.sort((a, b) => {
    const diff = (toDate(b.created_at)?.getTime() ?? 0) - (toDate(a.created_at)?.getTime() ?? 0)
    if (diff !== 0) return diff
    if (a.kind !== b.kind) return a.kind === 'verdict' ? -1 : 1
    return b.id - a.id
  })
}
