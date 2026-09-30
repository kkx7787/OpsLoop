import { isHttpStatus, isLogKind, LOG_KIND_LABEL, LOG_KIND_SHORT, type DeviceLogFilters, type DeviceLogLine, type DeviceLogTimeLine, type DeviceLogTimesState } from '@/api/device-logs'
import { formatKst, type TimeInput } from '@/lib/time'

/**
 * 장비 최근 로그(#73)의 값을 글로 바꾸고 줄을 합치는 규칙. 화면 부품은 여기 함수만 부르고 판단을 품지 않는다.
 * 줄 글자(경로 · UA · 사용자 · 메시지)는 서버가 가린 값이고 비신뢰라 부품이 UntrustedText 로 그린다.
 */

// ---------------------------------------------------------------- 합치기

/** 합친 목록에 남기는 줄 수. 넘으면 오래된 줄부터 버린다 */
export const MERGE_CAP = 500

/** 사이 끊김 구분선의 글 */
export const GAP_TEXT = '이 사이 줄이 빠졌을 수 있음'

/** 합친 줄 한 행. fresh 는 이번 회차에 처음 본 줄(첫 적재는 표시하지 않는다) */
export interface LogRow extends DeviceLogLine {
  fresh: boolean
}

export interface LogBuffer {
  /** (ts, id) 내림차순. 서버 응답 순서와 같다 */
  lines: LogRow[]
  /** 이 줄 아래(더 오래된 쪽)에 사이 끊김 구분선을 둔다 */
  gaps: string[]
}

/** 최신이 앞. ts 는 고정 자릿수 UTC 라 글자로 견준다. 같은 시각은 id 내림차순 */
export function compareLines(a: Pick<DeviceLogLine, 'ts' | 'id'>, b: Pick<DeviceLogLine, 'ts' | 'id'>): number {
  if (a.ts !== b.ts) return a.ts < b.ts ? 1 : -1
  if (a.id !== b.id) return a.id < b.id ? 1 : -1
  return 0
}

/**
 * 받은 최근 창(items)을 이전 목록에 합친다. 늦게 도착한 줄도 제자리(시각 순)에 들어간다.
 *  같은 id 는 한 줄이고 새 값으로 바꾼다 · 상한(cap)을 넘으면 오래된 줄부터 버린다
 *  이전 목록이 없으면(prev null: 첫 적재 · 조건 바꿈) fresh 를 달지 않는다
 *  사이 끊김: 이전 줄이 있고, 받은 줄이 limit 만큼 꽉 찼고, 받은 줄 가운데 가장 오래된 것을 전에 본 적이 없으면 받은 창이 이미 가진
 *   줄까지 닿지 않아 그 사이에 받지 못한 줄이 있을 수 있다. 받은 가장 오래된 줄 아래에 구분선을 둔다(사이에 줄이 없어도 켜질 수 있다).
 *   이전의 맨 윗줄과 견주지 않는다: 시각이 앞선 줄(서버는 as_of + 5분까지 넣는다)이 맨 위에 남아 있으면 끊김을 놓친다
 */
export function mergeLines(prev: LogBuffer | null, items: readonly DeviceLogLine[], limit: number, cap: number = MERGE_CAP): LogBuffer {
  const old = prev?.lines ?? []
  const seen = new Set(old.map((line) => line.id))
  const byId = new Map<string, LogRow>()
  for (const line of old) byId.set(line.id, { ...line, fresh: false })
  for (const item of items) byId.set(item.id, { ...item, fresh: prev !== null && !seen.has(item.id) })
  const lines = [...byId.values()].sort(compareLines).slice(0, Math.max(0, cap))

  const gaps = new Set(prev?.gaps ?? [])
  const received = [...items].sort(compareLines)
  const oldest = received[received.length - 1]
  if (old.length > 0 && oldest && received.length >= limit && !seen.has(oldest.id)) gaps.add(oldest.id)
  // 남은 줄에 붙은 것만 둔다. 맨 아래 줄 밑에는 이을 줄이 없어 구분선이 뜻이 없다
  const kept = new Set(lines.slice(0, -1).map((line) => line.id))
  return { lines, gaps: [...gaps].filter((id) => kept.has(id)) }
}

// ---------------------------------------------------------------- 주소 조건

/** 주소 검색 인자 → 조건. 모르는 종류 · 100..599 밖(000 · 99 · 600 · 1a)의 응답 코드는 버린다 */
export function logFiltersFromSearch(params: URLSearchParams): DeviceLogFilters {
  const filters: DeviceLogFilters = {}
  const kind = params.get('kind')
  if (isLogKind(kind)) filters.kind = kind
  const src = params.get('src_ip')?.trim()
  if (src) filters.src_ip = src
  const status = parseStatus(params.get('status'))
  if (status !== undefined) filters.status = status
  return filters
}

/** 조건 → 주소 검색 인자(값이 없는 조건은 빼고, 그 밖의 인자는 남긴다) */
export function searchFromLogFilters(filters: DeviceLogFilters, base?: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(base)
  for (const key of ['kind', 'src_ip', 'status'] as const) next.delete(key)
  if (filters.kind) next.set('kind', filters.kind)
  if (filters.src_ip) next.set('src_ip', filters.src_ip)
  if (filters.status !== undefined) next.set('status', String(filters.status))
  return next
}

/** 응답 코드 세 자리(100..599)만 숫자로 읽는다. 그 밖은 undefined */
export function parseStatus(raw: string | null | undefined): number | undefined {
  const text = raw?.trim() ?? ''
  if (!/^[0-9]{3}$/.test(text)) return undefined
  const n = Number(text)
  return isHttpStatus(n) ? n : undefined
}

export function countLogFilters(filters: DeviceLogFilters): number {
  return (filters.kind ? 1 : 0) + (filters.src_ip ? 1 : 0) + (filters.status !== undefined ? 1 : 0)
}

/** 합친 목록을 가르는 키. 조건이 바뀌면 목록을 비운다 */
export function filterScope(id: string, filters: DeviceLogFilters): string {
  return JSON.stringify([id, filters.kind ?? null, filters.src_ip ?? null, filters.status ?? null])
}

// ---------------------------------------------------------------- 줄 글

export const SSH_RESULT: Readonly<Record<string, string>> = {
  'sshd.login.failed': '실패',
  'sshd.login.invalid_user': '없는 사용자',
  'sshd.login.success': '성공',
}

/** SSH 결과. 모르는 이벤트는 이름 그대로 */
export function sshResult(eventid: string): string {
  return Object.hasOwn(SSH_RESULT, eventid) ? SSH_RESULT[eventid] : eventid
}

export function kindLabel(kind: string): string {
  return isLogKind(kind) ? LOG_KIND_LABEL[kind] : kind
}

/** 한 줄 요약 칸: 웹은 user_agent, SSH 는 message */
export function lineSummary(line: Pick<DeviceLogLine, 'kind' | 'user_agent' | 'message'>): string | null {
  return line.kind === 'web' ? line.user_agent : line.message
}

/** 코드 · 결과 칸: 웹은 응답 코드(없으면 '—'), SSH 는 결과 */
export function lineCode(line: Pick<DeviceLogLine, 'kind' | 'http_status' | 'eventid'>): string {
  if (line.kind === 'web') return typeof line.http_status === 'number' ? String(line.http_status) : '—'
  return sshResult(line.eventid)
}

/** 요청 칸 전체(말풍선용): 'GET /a?x=… → 200' · '실패 root' */
export function requestText(line: Pick<DeviceLogLine, 'kind' | 'http_method' | 'url' | 'http_status' | 'eventid' | 'username'>): string {
  if (line.kind === 'web') return `${line.http_method ?? '—'} ${line.url ?? ''} → ${lineCode(line)}`
  return `${sshResult(line.eventid)} ${line.username ?? ''}`.trim()
}

/** 좁은 카드 로그 칸(#83)의 짧은 종류: '웹' · 'SSH'. 모르는 종류는 이름 그대로 */
export function kindShort(kind: string): string {
  return isLogKind(kind) ? LOG_KIND_SHORT[kind] : kind
}

/**
 * 대시보드 카드 로그 칸(#83)의 시각: 기준 시각(as_of)과 같은 KST 날짜면 '시:분:초', 아니면 '월-일 시:분'(칸 폭 100px 에 맞춘다).
 * 전체 시각은 말풍선(Time 의 title)으로 본다
 */
export function logTime(ts: TimeInput, asOf: TimeInput): string {
  const date = formatKst(ts, 'date')
  if (date === '—') return date
  return date === formatKst(asOf, 'date') ? formatKst(ts, 'time') : formatKst(ts, 'short')
}

/** 좁은 폭 카드 머리의 시각(KST 월-일 시:분:초). 7일 창이라 시각만으로는 날이 모호하다 */
export function cardTime(ts: string): string {
  const date = formatKst(ts, 'date')
  if (date === '—') return date
  return `${date.slice(5)} ${formatKst(ts, 'time')}`
}

// ---------------------------------------------------------------- 시각 칸 · 경고

/** 값이 없을 때 시각 칸의 글. 노드 표를 읽을 수 없으면(열 권한 없음) 그 사실을 적는다 */
export function missingTimeText(state: DeviceLogTimesState): string {
  return state === 'unreadable' ? '노드 표를 읽을 수 없음' : '기록 없음'
}

/** 로그 종류별 마지막 줄의 글. 시각을 그려야 하면 null */
export function lineTimeText(state: DeviceLogTimesState, line: Pick<DeviceLogTimeLine, 'declared' | 'last_line_at'>): string | null {
  if (state !== 'ok') return missingTimeText(state)
  if (line.declared === false) return '수집 안 함'
  return line.last_line_at ? null : '기록 없음'
}

/** 앞선 시각으로 뺀 줄 경고. 서버가 1,001 에서 멈추므로 1,000 을 넘으면 수 대신 '1,000건 넘게' 다 */
export function futureText(n: number): string {
  const count = n > 1000 ? '1,000건 넘게는' : `${n.toLocaleString('ko-KR')}건은`
  return `시각이 5분 넘게 앞선 줄 ${count} 목록에서 뺐습니다`
}
