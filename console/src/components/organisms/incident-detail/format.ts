import type { ActionRecord, ActorBlock, BehaviorRow, EnforcePoint, EnforcePointState, EvidenceSample, IncidentDetail, RawLine, VerdictRecord } from '@/api/incidents'
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

/** 원문 한 줄의 필드 하나. label 은 고정 글자(session= 등), value 는 원문 값(비신뢰)이다 */
export interface RawField {
  label?: string
  value?: string
}

/**
 * 원문 한 줄을 필드로. 화면은 필드마다 따로 격리해 그린다(한 필드의 방향 제어 · 줄바꿈이 뒤 필드를 건드리지 않게).
 * 비밀번호 원문은 서버가 주지 않으므로 있었다는 표시만 남긴다
 */
export function rawLineFields(row: RawLine): RawField[] {
  const fields: RawField[] = [{ value: formatKst(row.ts, 'datetime') }, { value: row.sensor }, { value: row.eventid }]
  if (row.session) fields.push({ label: 'session=', value: row.session })
  if (row.username) fields.push({ label: 'user=', value: row.username })
  if (row.has_password) fields.push({ label: 'password=[있음]' })
  if (row.input) fields.push({ label: 'input=', value: row.input })
  if (row.url) fields.push({ value: `${row.http_method ?? ''} ${row.url}${row.http_status !== null && row.http_status !== undefined ? ` ${row.http_status}` : ''}`.trim() })
  if (row.shasum) fields.push({ label: 'shasum=', value: row.shasum })
  if (row.user_agent) fields.push({ label: 'ua=', value: row.user_agent })
  if (row.message) fields.push({ value: row.message })
  return fields
}

/** 원문 한 줄을 글 하나로(필드 사이 공백 두 칸). 화면은 rawLineFields 로 필드마다 그린다 */
export function formatRawLine(row: RawLine): string {
  return rawLineFields(row)
    .map((field) => `${field.label ?? ''}${field.value ?? ''}`)
    .join('  ')
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

/**
 * 차단 행의 지금 상태(이슈 #47). 요청과 실제 차단은 다르다. 데이터 노드 집행기가 AWS 관문의 반영 결과를
 * enforce_note · enforced_at · method 에 쓰고, 화면은 그것과 만료로 가른다. 순서는 서버 BLOCK_STATES_SQL(대시보드 수)과 같다.
 *  released  해제됨. 사람이 풀었다
 *  expired   만료됨. 만료가 지나 관문에서 빠진다
 *  excluded  집행 제외. 만료 없는 옛 차단이거나 집행기가 '집행 제외 · <사유>'(금지 대역 · 대역 주소)로 적었다. 관문에 넘기지 않는다
 *  mismatch  관문 불일치. 관문 상태가 목록과 5분 넘게 다르거나 관문이 거부했다('관문 불일치 · <사유>'). enforced_at 은 마지막 확인
 *  enforced  집행 확인. 관문 집합에 들어간 것을 확인했다(방식 · 시각)
 *  pending   집행 대기. 요청했고 아직 관문 반영을 확인하지 못했다
 */
export type BlockState = 'enforced' | 'pending' | 'excluded' | 'mismatch' | 'released' | 'expired'

/** 집행기가 enforce_note 에 쓰는 말머리(서버 main.ENFORCE_EXCLUDED · ENFORCE_MISMATCH) */
export const ENFORCE_EXCLUDED = '집행 제외'
export const ENFORCE_MISMATCH = '관문 불일치'

type BlockFields = Pick<ActorBlock, 'released_at' | 'expires_at' | 'enforced_at'> & { enforce_note?: string | null }

export function blockState(block: BlockFields, now: number = Date.now()): BlockState {
  if (block.released_at) return 'released'
  const expires = toDate(block.expires_at)
  if (expires && expires.getTime() <= now) return 'expired'
  const note = block.enforce_note ?? ''
  if (!block.expires_at || note.startsWith(ENFORCE_EXCLUDED)) return 'excluded'
  if (note.startsWith(ENFORCE_MISMATCH)) return 'mismatch'
  return block.enforced_at ? 'enforced' : 'pending'
}

export const BLOCK_STATE_LABEL: Record<BlockState, string> = {
  enforced: '집행 확인',
  pending: '집행 대기',
  excluded: '집행 제외',
  mismatch: '관문 불일치',
  released: '해제됨',
  expired: '만료됨',
}

/** 집행 확인은 요청이 정상 적용됐다는 결과라 초록이다(지점별 '적용 확인' 과 같다). 주의가 필요한 것은 대기 · 불일치 쪽이다 */
export const BLOCK_STATE_TONE: Record<BlockState, Tone> = {
  enforced: 'success',
  pending: 'warning',
  excluded: 'neutral',
  mismatch: 'orange',
  released: 'neutral',
  expired: 'neutral',
}

/** 살아 있는(만료 · 해제 전) 상태. 해제할 수 있고 차단 목록의 '활성' 탭에 든다 */
export const LIVE_BLOCK_STATES: readonly BlockState[] = ['enforced', 'pending', 'excluded', 'mismatch']

/**
 * 상태 옆의 짧은 설명. 방식 · 메모처럼 DB 에서 온 글자는 넣지 않는다(그리는 쪽이 UntrustedText 로 따로 보인다).
 * 만료 없는 행은 집행기가 메모를 쓰기 전에도 제외로 보이므로 여기서 까닭을 적는다.
 * 해제 · 만료 · 제외인데 enforced_at 이 남아 있으면 관문이 그 주소를 뺀 목록을 적용했다는 보고를 아직 받지 못한 것이다
 * (집행기는 그 보고를 받아야 enforced_at 을 비운다). 관문 동기화가 멈추면 관문은 옛 만료까지 계속 막으므로 빠졌다고 적지 않는다
 */
export function blockStateHint(block: BlockFields, state: BlockState): string {
  const leaving = block.enforced_at ? '관문에서 빠졌는지 확인 전' : ''
  switch (state) {
    case 'enforced': return '관문 집합 반영 확인'
    case 'pending': return '관문 반영 확인 전'
    case 'excluded': return [block.expires_at ? '관문에 넘기지 않음' : '만료 없는 차단 · 관문에 넘기지 않음', leaving].filter(Boolean).join(' · ')
    case 'mismatch': return block.enforced_at ? '관문 상태가 목록과 다름 · 마지막 확인' : '관문 상태가 목록과 다름'
    case 'released': return `사람이 풂 · ${leaving || '관문 목록에서 빠짐'}`
    case 'expired': return `만료가 지남 · ${leaving || '관문 목록에서 빠짐'}`
  }
}

/**
 * 집행 지점(이슈 #51). 관문은 허니팟 유입(22 · 23 · 8080)을, 내부 방화벽은 실서비스(web-01) 앞에서 외부 역할 세그먼트의 출발지를 막는다.
 * 위의 상태(blockState)는 관문의 확인 열로 가른 것이고, 지점별 결과는 enforcement 로 따로 보인다
 */
export const ENFORCE_POINTS: ReadonlyArray<readonly ['gateway' | 'fw', string]> = [['gateway', 'AWS 관문'], ['fw', '내부 방화벽']]

export const POINT_STATE_LABEL: Record<EnforcePointState, string> = {
  pending: '대기',
  confirmed: '적용 확인',
  failed: '실패',
  stale: '확인 지연',
}

export const POINT_STATE_TONE: Record<EnforcePointState, Tone> = {
  pending: 'warning',
  confirmed: 'success',
  failed: 'danger',
  stale: 'warning',
}

export interface PointRow {
  key: 'gateway' | 'fw'
  label: string
  point: EnforcePoint
  /** 까닭이 화면이 덧붙인 판단 근거라 도움말(ⓘ)로 접는다(집행기 멈춤 · sources/model checkedPoints). 지점이 보낸 까닭은 본문에 둔다 */
  noteTip?: true
}

const POINT_STATES = Object.keys(POINT_STATE_LABEL) as EnforcePointState[]
const text = (value: unknown): string | null => (typeof value === 'string' && value ? value : null)

/**
 * 행의 지점별 결과. 알려진 지점 · 상태만 정해진 순서(관문 → 내부 방화벽)로 돌려준다.
 * 값은 DB 에서 온 것이라 모양을 다시 본다. 모르는 상태는 버리고, 글자가 아닌 값은 비운다. 없으면 빈 목록(이전 서버 · 집행기)
 */
export function enforcementPoints(block: Pick<ActorBlock, 'enforcement'> | null | undefined): PointRow[] {
  const raw: unknown = block?.enforcement
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return []
  const rows: PointRow[] = []
  for (const [key, label] of ENFORCE_POINTS) {
    const item: unknown = (raw as Record<string, unknown>)[key]
    if (!item || typeof item !== 'object') continue
    const value = item as Record<string, unknown>
    const state = value.state
    if (typeof state !== 'string' || !POINT_STATES.includes(state as EnforcePointState)) continue
    rows.push({ key, label, point: { state: state as EnforcePointState, since: text(value.since), mode: text(value.mode), note: text(value.note) } })
  }
  return rows
}

/** 한 지점의 적용 확인 · 실패 · 미확인 수 */
export interface PointTally {
  applied: number
  failed: number
  unverified: number
}

/** 지점 수를 세는 행: 살아 있고 집행에 넘기는 요청(집행 제외 · 해제 · 만료는 뺀다) */
const COUNTED_STATES: readonly BlockState[] = ['enforced', 'pending', 'mismatch']

/**
 * 차단 목록의 지점별 수(#72). 지점 결과가 적용 확인이면 적용, 실패면 실패, 그 밖(대기 · 확인 지연 · 기록 없음 · 모르는 값)은 미확인이다.
 * 서버 BLOCKS_SQL(대시보드 · 대상 카드의 지점별 수)과 같은 정의다. 집행기 멈춤으로 합치지 않고 보고 상태 그대로 센다
 */
export function pointCounts(rows: readonly (BlockFields & Pick<ActorBlock, 'enforcement'>)[], now: number, point: 'gateway' | 'fw'): PointTally {
  const tally: PointTally = { applied: 0, failed: 0, unverified: 0 }
  for (const row of rows) {
    if (!COUNTED_STATES.includes(blockState(row, now))) continue
    const raw: unknown = row.enforcement
    const item: unknown = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>)[point] : null
    const state = item && typeof item === 'object' ? (item as Record<string, unknown>).state : null
    if (state === 'confirmed') tally.applied += 1
    else if (state === 'failed') tally.failed += 1
    else tally.unverified += 1
  }
  return tally
}

/** 풀 수 있는 차단인가(해제 조치의 조건) */
export function isActiveBlock(block: BlockFields | null, now: number = Date.now()): boolean {
  if (!block) return false
  return LIVE_BLOCK_STATES.includes(blockState(block, now))
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
