import type { ActionRecord, ActorBlock, BehaviorRow, BlockPoint, EnforcePoint, EnforcePointState, EvidenceSample, IncidentDetail, RawLine, VerdictRecord } from '@/api/incidents'
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
 * 차단 행의 지금 종합 상태(이슈 #47 · #77). 요청과 실제 차단은 다르다. 데이터 노드 집행기가 두 지점의 반영 결과를 관문 세 열
 * (enforce_note · enforced_at · method)과 지점별 결과(enforcement)에 쓰고, 화면은 그것과 요청 지점(points) · 만료로 가른다.
 * 서버 block_points.STATE_CASE(대시보드 수 · 보고서)와 같은 규칙이다. 요청한 지점이 모두 확인이어야 집행 확인이다.
 *  released  해제됨. 사람이 풀었다
 *  expired   만료됨. 만료가 지나 지점 목록에서 빠진다
 *  excluded  집행 제외. 만료 없는 옛 차단이거나 집행기가 '집행 제외 · <사유>'(금지 대역 · 대역 주소)로 적었다. 어느 지점에도 넘기지 않는다
 *  failed    집행 실패. 요청한 지점 하나라도 거부했다고 보고했다
 *  mismatch  불일치. 요청한 지점 하나라도 상태가 목록과 5분 넘게 다르다(관문 '관문 불일치 · <사유>' 쪽지 · 지점 stale). 관문 enforced_at 은 마지막 확인
 *  pending   집행 대기. 요청한 지점 가운데 아직 반영을 확인하지 못한 곳이 있다
 *  enforced  집행 확인. 요청한 지점이 모두 반영을 확인했다
 * 우선순위는 해제 > 만료 > 제외 > 실패 > 불일치 > 대기 > 확인이다. 관문의 확인 · 불일치 쪽지는 관문 세 열로, 실패 · 지연은
 * enforcement.gateway 로 보고(요청한 관문의 결과가 대기 · 빠짐 확인 전이면 확인 시각이 남아도 대기. 다시 걸어도 세 열은 요청 시각에
 * 비지 않고 새 목록을 확인할 때까지 관문 결과가 대기다, 결정 2), 내부 방화벽은 enforcement.fw 로 본다. 요청하지 않은 지점은 남은 쪽지 · 결과가 있어도 보지 않는다
 * (그 지점 칸은 빠짐 확인 전이다. heldPoint)
 */
export type BlockState = 'enforced' | 'pending' | 'excluded' | 'failed' | 'mismatch' | 'released' | 'expired'

/** 집행기가 enforce_note 에 쓰는 말머리(서버 main.ENFORCE_EXCLUDED · ENFORCE_MISMATCH) */
export const ENFORCE_EXCLUDED = '집행 제외'
export const ENFORCE_MISMATCH = '관문 불일치'

/** 적용 지점의 정규 순서(관문 먼저). 표의 이름은 ENFORCE_POINTS, 문장 안의 짧은 이름은 pointNames */
export const BLOCK_POINTS: readonly BlockPoint[] = ['gateway', 'fw']
const POINT_NAME: Record<BlockPoint, string> = { gateway: '관문', fw: '내부 방화벽' }

/** 지점 이름들을 한 줄로('관문 · 내부 방화벽') */
export function pointNames(points: readonly BlockPoint[]): string {
  return points.map((p) => POINT_NAME[p]).join(' · ')
}

type BlockFields = Pick<ActorBlock, 'released_at' | 'expires_at' | 'enforced_at'> & Partial<Pick<ActorBlock, 'enforce_note' | 'enforcement' | 'points'>>

/** 요청 지점(정규 순서, 이슈 #77). 없거나(이전 서버) 모양이 틀리면 두 지점이다 */
export function requestedPoints(block: Pick<ActorBlock, 'points'> | null | undefined): BlockPoint[] {
  const raw: unknown = block?.points
  if (!Array.isArray(raw)) return [...BLOCK_POINTS]
  const points = BLOCK_POINTS.filter((p) => raw.includes(p))
  return points.length ? points : [...BLOCK_POINTS]
}

/** 지점 결과의 state 글자. 값은 DB 에서 온 것이라 모양을 다시 보고, 글자가 아니면 null(서버 held_sql · 집행기 held_at 도 글자만 기록으로 본다) */
function rawPointState(enforcement: unknown, point: BlockPoint): string | null {
  if (!enforcement || typeof enforcement !== 'object' || Array.isArray(enforcement)) return null
  const item: unknown = (enforcement as Record<string, unknown>)[point]
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null
  const state = (item as Record<string, unknown>).state
  return typeof state === 'string' ? state : null
}

/** 요청 지점마다 본 실패 · 불일치 · 미확인 지점(종합 상태 · 이름 · 설명이 같이 쓴다) */
function pointFacts(block: BlockFields) {
  const requested = requestedPoints(block)
  const note = block.enforce_note ?? ''
  const state = (p: BlockPoint) => rawPointState(block.enforcement, p)
  return {
    requested,
    failed: requested.filter((p) => state(p) === 'failed'),
    mismatch: requested.filter((p) => state(p) === 'stale' || (p === 'gateway' && note.startsWith(ENFORCE_MISMATCH))),
    // 다시 걸거나 연장한 뒤 새 목록을 확인하기 전(관문 결과 대기)과 다시 건 행에 남은 빠짐 확인 전(집행기 다음 회차 전)은 남은 확인
    // 시각이 있어도 확인 전이다(지점 칸 '대기' 와 같다, 결정 2)
    unconfirmed: requested.filter((p) => (p === 'gateway' ? !block.enforced_at || state(p) === 'pending' || state(p) === 'removing' : state(p) !== 'confirmed')),
  }
}

export function blockState(block: BlockFields, now: number = Date.now()): BlockState {
  if (block.released_at) return 'released'
  const expires = toDate(block.expires_at)
  if (expires && expires.getTime() <= now) return 'expired'
  if (!block.expires_at || (block.enforce_note ?? '').startsWith(ENFORCE_EXCLUDED)) return 'excluded'
  const facts = pointFacts(block)
  if (facts.failed.length) return 'failed'
  if (facts.mismatch.length) return 'mismatch'
  return facts.unconfirmed.length ? 'pending' : 'enforced'
}

/** 합친 수 · 상태 탭의 이름(지점 이름 없음). 행 하나의 이름은 blockStateLabel */
export const BLOCK_STATE_LABEL: Record<BlockState, string> = {
  enforced: '집행 확인',
  pending: '집행 대기',
  excluded: '집행 제외',
  failed: '집행 실패',
  mismatch: '불일치',
  released: '해제됨',
  expired: '만료됨',
}

/** 집행 확인은 요청이 정상 적용됐다는 결과라 초록이다(지점별 '적용 확인' 과 같다). 주의가 필요한 것은 대기 · 불일치 · 실패 쪽이다 */
export const BLOCK_STATE_TONE: Record<BlockState, Tone> = {
  enforced: 'success',
  pending: 'warning',
  excluded: 'neutral',
  failed: 'danger',
  mismatch: 'orange',
  released: 'neutral',
  expired: 'neutral',
}

/** 행 하나의 상태 이름. 불일치는 그 지점 이름을 붙인다('관문 불일치' · '내부 방화벽 불일치') */
export function blockStateLabel(block: BlockFields, state: BlockState): string {
  if (state !== 'mismatch') return BLOCK_STATE_LABEL[state]
  const { mismatch } = pointFacts(block)
  return mismatch.length ? `${pointNames(mismatch)} 불일치` : BLOCK_STATE_LABEL.mismatch
}

/** 살아 있는(만료 · 해제 전) 상태. 해제할 수 있고 차단 목록의 '활성' 탭에 든다 */
export const LIVE_BLOCK_STATES: readonly BlockState[] = ['enforced', 'pending', 'excluded', 'failed', 'mismatch']

/**
 * 그 지점에 남은 기록(결과 기록, 관문은 확인 시각 enforced_at 도). 집행기는 요청했던 지점마다 removing 을 두고 그 지점이 뺐다고
 * 보고하면 키(관문은 세 열도)를 지운다. 그래서 목록 밖 행(해제 · 만료 · 제외)이나 요청하지 않은 지점(관리자 관문 빼기 · 관문 없이 다시
 * 건 행, 이슈 #77 결정 14)에 기록이 남았으면 그 지점은 빠짐 확인 전이다. 서버 block_points.held_sql · 집행기 held_at 과 같은 정의다
 */
function heldPoint(block: BlockFields, point: BlockPoint): boolean {
  return rawPointState(block.enforcement, point) !== null || (point === 'gateway' && !!block.enforced_at)
}

/** 뺐다는 보고를 아직 받지 못한 지점. 목록 밖 행은 모든 지점, 살아 있는 목록 행은 요청하지 않은 지점만 본다(요청 지점은 결과 그대로) */
function leavingPoints(block: BlockFields, listed = false): BlockPoint[] {
  const requested = requestedPoints(block)
  return BLOCK_POINTS.filter((p) => (!listed || !requested.includes(p)) && heldPoint(block, p))
}

/** 상태 칸에 보일 관문 확인 시각. 관문을 요청했고 집행 확인이거나 관문 불일치(마지막 확인)일 때만, 아니면 null */
export function gatewayCheckedAt(block: BlockFields, state: BlockState): string | null {
  if (!block.enforced_at || !requestedPoints(block).includes('gateway')) return null
  if (state === 'enforced' || (state === 'mismatch' && pointFacts(block).mismatch.includes('gateway'))) return block.enforced_at
  return null
}

/**
 * 방식 · 집행 메모로 보일 관문 세 열(이슈 #77). 관문을 요청하지 않은 행에 남은 관문 기록(관리자 관문 빼기 뒤 · 옛 집행기 시절)은
 * 보이지 않는다(관문 칸이 빠짐 확인 전 · 미요청으로 대신한다). 집행 제외 쪽지는 지점과 무관해 그대로 보인다
 */
export function enforceRecord(block: Pick<ActorBlock, 'method'> & Partial<Pick<ActorBlock, 'enforce_note' | 'points'>>): { method: string | null; note: string | null } {
  const note = block.enforce_note ?? null
  if (requestedPoints(block).includes('gateway')) return { method: block.method ?? null, note }
  return { method: null, note: note?.startsWith(ENFORCE_EXCLUDED) ? note : null }
}

/**
 * 상태 옆의 짧은 설명. 요청 지점 이름으로 적는다(대기 · 실패 · 불일치는 그 지점만). 방식 · 메모처럼 DB 에서 온 글자는 넣지 않는다
 * (그리는 쪽이 UntrustedText 로 따로 보인다). 만료 없는 행은 집행기가 메모를 쓰기 전에도 제외로 보이므로 여기서 까닭을 적는다.
 * 해제 · 만료 · 제외인데 지점의 결과 기록이나 관문 enforced_at 이 남아 있으면 그 지점이 뺀 것을 아직 확인하지 못한 것이다. 살아 있는
 * 행도 요청하지 않은 지점(관문 빼기 뒤)에 기록이 남았으면 그렇게 덧붙인다.
 * 동기화가 멈추면 그 지점은 옛 만료까지 계속 막으므로 빠졌다고 적지 않는다
 */
export function blockStateHint(block: BlockFields, state: BlockState): string {
  const facts = pointFacts(block)
  const names = (points: BlockPoint[]) => pointNames(points.length ? points : facts.requested)
  const leaving = leavingPoints(block)
  const left = leaving.length ? `${pointNames(leaving)}에서 빠졌는지 확인 전` : ''
  const dropped = leavingPoints(block, true)
  const also = (text: string) => (dropped.length ? `${text} · ${pointNames(dropped)}에서 빠졌는지 확인 전` : text)
  switch (state) {
    case 'enforced': return also(`${names(facts.requested)} 반영 확인`)
    case 'pending': return also(`${names(facts.unconfirmed)} 반영 확인 전`)
    case 'failed': return also(`${names(facts.failed)} 적용 실패`)
    case 'excluded': return [`${block.expires_at ? '' : '만료 없는 차단 · '}${names(facts.requested)}에 넘기지 않음`, left].filter(Boolean).join(' · ')
    case 'mismatch': return gatewayCheckedAt(block, state) ? `${names(facts.mismatch)} 상태가 목록과 다름 · 마지막 확인` : also(`${names(facts.mismatch)} 상태가 목록과 다름`)
    case 'released': return `사람이 풂 · ${left || `${names(facts.requested)} 목록에서 빠짐`}`
    case 'expired': return `만료가 지남 · ${left || `${names(facts.requested)} 목록에서 빠짐`}`
  }
}

/**
 * 집행 지점(이슈 #51). 관문은 허니팟 유입(22 · 23 · 8080)을, 내부 방화벽은 실서비스(web-01) 앞에서 외부 역할 세그먼트의 출발지를 막는다.
 * 종합 상태(blockState)는 요청한 지점 모두로 가른 것이고, 지점별 결과는 enforcement 로 따로 보인다
 */
export const ENFORCE_POINTS: ReadonlyArray<readonly [BlockPoint, string]> = [['gateway', '허니팟 관문'], ['fw', '내부 방화벽']]

/**
 * 지점 칸의 상태. 결과 상태에 더해 미요청(그 지점을 요청하지 않았고 남은 기록도 없음) · 빠짐(목록에서 빠진 행을 그 지점이 뺐음)을
 * 화면이 붙인다(이슈 #77). 요청하지 않은 지점에 기록이 남았으면 미요청이 아니라 빠짐 확인 전(removing)이다(결정 14)
 */
export type PointRowState = EnforcePointState | 'unrequested' | 'gone'

export const POINT_STATE_LABEL: Record<PointRowState, string> = {
  pending: '대기',
  confirmed: '적용 확인',
  failed: '실패',
  stale: '확인 지연',
  removing: '빠짐 확인 전',
  unrequested: '미요청',
  gone: '빠짐',
}

/** 미요청은 결과가 아니라 요청 사실이라 중립색이다(미확인 · 실패와 섞지 않는다) */
export const POINT_STATE_TONE: Record<PointRowState, Tone> = {
  pending: 'warning',
  confirmed: 'success',
  failed: 'danger',
  stale: 'warning',
  removing: 'warning',
  unrequested: 'neutral',
  gone: 'neutral',
}

export interface PointRow {
  key: BlockPoint
  label: string
  point: Omit<EnforcePoint, 'state'> & { state: PointRowState }
  /** 까닭이 화면이 덧붙인 판단 근거라 도움말(ⓘ)로 접는다(집행기 멈춤 · sources/model checkedPoints). 지점이 보낸 까닭은 본문에 둔다 */
  noteTip?: true
}

const POINT_STATES: readonly EnforcePointState[] = ['pending', 'confirmed', 'failed', 'stale', 'removing']
const text = (value: unknown): string | null => (typeof value === 'string' && value ? value : null)

/**
 * 행의 지점별 결과 기록. 알려진 지점 · 상태만 정해진 순서(관문 → 내부 방화벽)로 돌려준다.
 * 값은 DB 에서 온 것이라 모양을 다시 본다. 모르는 상태는 버리고, 글자가 아닌 값은 비운다. 없으면 빈 목록(이전 서버 · 집행기).
 * 화면의 지점 칸은 요청 지점을 더한 pointRows 로 그린다
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

/**
 * 차단 행의 지점 칸(이슈 #77). ENFORCE_POINTS 를 차례로 본다. 요청하지 않은 지점은 '미요청' 이다(미확인 · 실패로 보이지 않는다).
 * 다만 그 지점에 기록이 남았으면(관리자 관문 빼기 · 관문 없이 다시 건 행, 결정 14) 그 지점이 뺐다고 확인될 때까지 '빠짐 확인 전' 이다.
 * 살아 있는 행은 요청 지점의 결과 기록(enforcementPoints, 기록이 없으면 줄이 없다)이다. 목록 행(집행 제외 밖)에 남은 removing 은
 * 빠짐 확인 전에 다시 건 행의 옛 기록이라(집행기가 다음 회차에 바꾼다) '대기' 로 보인다. 해제 · 만료 행은 요청 지점마다 결과 기록이나
 * 관문 enforced_at 이 남았으면 '빠짐 확인 전'(removing), 아니면 '빠짐' 이다. now 는 만료를 가르는 기준 시각
 */
export function pointRows(block: BlockFields | null | undefined, now: number = Date.now()): PointRow[] {
  if (!block) return []
  const requested = requestedPoints(block)
  const state = blockState(block, now)
  const dead = state === 'released' || state === 'expired'
  const results = enforcementPoints(block)
  const rows: PointRow[] = []
  for (const [key, label] of ENFORCE_POINTS) {
    const result = results.find((r) => r.key === key)
    const removing = (): PointRow => ({ key, label, point: { state: 'removing', since: result?.point.state === 'removing' ? result.point.since : null, mode: result?.point.mode ?? null, note: null } })
    if (!requested.includes(key)) rows.push(heldPoint(block, key) ? removing() : { key, label, point: { state: 'unrequested', since: null, mode: null, note: null } })
    else if (!dead) {
      if (result?.point.state === 'removing' && state !== 'excluded') rows.push({ key, label, point: { state: 'pending', since: null, mode: null, note: null } })
      else if (result) rows.push(result)
    } else rows.push(heldPoint(block, key) ? removing() : { key, label, point: { state: 'gone', since: null, mode: null, note: null } })
  }
  return rows
}

/** 한 지점의 적용 확인 · 실패 · 미확인 수와 그 지점 미요청 · 빠짐 확인 전 수 */
export interface PointTally {
  applied: number
  failed: number
  unverified: number
  /** 그 지점을 요청하지 않았고 남은 기록도 없는 행(이슈 #77). 위 세 수에 들지 않는다 */
  unrequested: number
  /** 그 지점을 요청하지 않았는데 기록이 남은 행(관리자 관문 빼기 뒤 그 지점이 뺐다고 확인하기 전, 결정 14). 위 네 수에 들지 않는다 */
  removing: number
}

/** 지점 수를 세는 행: 살아 있고 집행에 넘기는 요청(집행 제외 · 해제 · 만료는 뺀다) */
const COUNTED_STATES: readonly BlockState[] = ['enforced', 'pending', 'failed', 'mismatch']

/**
 * 차단 목록의 지점별 수(#72 · #77). 그 지점을 요청한 행만 센다. 지점 결과가 적용 확인이면 적용, 실패면 실패, 그 밖(대기 · 확인 지연 ·
 * 빠짐 확인 전 · 기록 없음 · 모르는 값)은 미확인이다. 요청하지 않은 행은 미요청으로, 그 가운데 그 지점에 기록이 남은 행은 빠짐 확인
 * 전으로 따로 센다. 서버 BLOCKS_SQL(대시보드 · 대상 카드의 지점별 수)과 같은 정의다. 집행기 멈춤으로 합치지 않고 보고 상태 그대로 센다
 */
export function pointCounts(rows: readonly BlockFields[], now: number, point: BlockPoint): PointTally {
  const tally: PointTally = { applied: 0, failed: 0, unverified: 0, unrequested: 0, removing: 0 }
  for (const row of rows) {
    if (!COUNTED_STATES.includes(blockState(row, now))) continue
    if (!requestedPoints(row).includes(point)) {
      if (heldPoint(row, point)) tally.removing += 1
      else tally.unrequested += 1
      continue
    }
    const state = rawPointState(row.enforcement, point)
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
