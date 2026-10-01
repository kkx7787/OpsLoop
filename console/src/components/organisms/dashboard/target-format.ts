import {
  PROTECTED_IDS,
  PROTECTED_KIND,
  SENSOR_IDS,
  SYSTEM_IDS,
  targetKind,
  type CollectionState,
  type SystemState,
  type Target,
  type TargetAssetVulns,
  type TargetCollection,
  type TargetLog,
  type TargetMetrics,
  type TargetResponse,
  type TargetSystem,
  type TargetLatest,
  type TargetVulns,
} from '@/api/targets'
import { toDate } from '@/lib/time'
import type { Tone } from '../../atoms/tones'

/**
 * 관제 대상 카드(#52)의 값을 글로 바꾸는 규칙. 카드 컴포넌트는 여기 함수만 부르고 판단을 품지 않는다.
 * 수집 상태 · 오래됨 · 적용 확인은 서버가 정한다. 화면은 옮겨 적기만 하고, 로그 시각만으로 정상 · 장애 색을 만들지 않는다.
 */

/**
 * 수집 상태 배지. 글자 없이 색만 쓰지 않는다. 미확인은 장애가 아니라 모른다는 뜻이라 중립색이다.
 * 콘솔의 '응답 중'(#76)은 이 조회에 응답했다는 사실일 뿐 생존 확정이 아니라 정상 초록으로 꾸미지 않는다
 */
export const COLLECTION_LABEL: Record<CollectionState, string> = {
  ok: '정상',
  quiet: '요청 없음',
  no_signal: '수신 없음',
  unknown: '생존 상태 미확인',
  responding: '응답 중',
}

export const COLLECTION_TONE: Record<CollectionState, Tone> = {
  ok: 'success',
  quiet: 'neutral',
  no_signal: 'warning',
  unknown: 'neutral',
  responding: 'neutral',
}

/** 모르는 상태 값은 미확인으로 읽는다(정상으로 꾸미지 않는다) */
export function collectionState(value: string | null | undefined): CollectionState {
  return value === 'ok' || value === 'quiet' || value === 'no_signal' || value === 'responding' ? value : 'unknown'
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
  key: 'applied' | 'failed' | 'unverified' | 'unrequested' | 'removing' | 'exempt' | 'stalled' | 'none' | 'unknown'
  text: string
  tone?: Tone
}

const positive = (n: number | null | undefined): n is number => typeof n === 'number' && Number.isFinite(n) && n > 0
const count = (n: number) => n.toLocaleString('ko-KR')

/**
 * 대응 구역 문구. 숫자 0 을 그리지 않는다(0 이 '막았다 · 못 막았다' 로 읽히지 않게).
 *  집행 지점이 있으면: 적용 확인 n (지점) · 적용 실패 n (지점) · 적용 여부 미확인 n · 미요청 n (지점) · 빠짐 확인 전 n (지점) ·
 *    정책상 차단 제외 n. 미요청(그 지점을 요청하지 않은 차단) · 빠짐 확인 전(뺐는데 그 지점이 뺐다고 아직 확인하지 못한 차단, 아직
 *    막고 있을 수 있다)은 이슈 #77 이고 적용 · 실패 · 미확인에 들지 않는다.
 *    모두 없으면 '<지점> 집행 대상 차단 없음'(집행 제외 차단만 있어도 거짓이 되지 않는 문구다)
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
    if (positive(response.unrequested)) parts.push({ key: 'unrequested', text: `차단 미요청 ${count(response.unrequested)} (${label})`, tone: 'neutral' })
    if (positive(response.removing)) parts.push({ key: 'removing', text: `차단 빠짐 확인 전 ${count(response.removing)} (${label})`, tone: 'warning' })
    if (positive(response.exempt)) parts.push({ key: 'exempt', text: `정책상 차단 제외 ${count(response.exempt)}`, tone: 'neutral' })
    if (!parts.length) parts.push({ key: 'none', text: `${label} 집행 대상 차단 없음` })
    if (response.stalled) parts.push({ key: 'stalled', text: response.stalled })
    return parts
  }
  parts.push({ key: 'unknown', text: '차단 적용 여부 미확인' })
  if (positive(response.exempt)) parts.push({ key: 'exempt', text: `정책상 차단 제외 ${count(response.exempt)}`, tone: 'neutral' })
  return parts
}

const isCount = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n)

/**
 * 취약점 구역 자산 한 줄의 본문(시각 · 오래됨 표지는 카드가 붙인다). 수정 상태별 수가 모두 오면 그것으로(0 도 적는다),
 * 아니면(이전 서버) 총수 · KEV. 총수는 자산 화면에 있다
 */
export function vulnText(asset: TargetAssetVulns): string {
  if (asset.missing) return '자산 정보 없음'
  if (!asset.collected_at) return '조사 기록 없음'
  // 배포판 대조 전의 0 은 '취약점 없음' 이 아니다
  if (!asset.checked_at) return '취약점 대조 전'
  const { vuln_fix_available: fix, vuln_reboot_pending: reboot, vuln_fix_unknown: unknown } = asset
  if (isCount(fix) && isCount(reboot) && isCount(unknown)) {
    return `수정판 있음 ${count(fix)} · 재부팅 대기 ${count(reboot)} · 수정 여부 미확인 ${count(unknown)} · KEV ${count(asset.vuln_kev)}`
  }
  return `취약점 ${count(asset.vuln_total)} · KEV ${count(asset.vuln_kev)}`
}

/** 자산 · 취약점 화면에서 그 자산을 연 주소 */
export function assetHref(assetId: string): string {
  return `/inventory?asset=${encodeURIComponent(assetId)}`
}

/**
 * 보호 대상 카드의 취약점 한 줄(#83).
 *  main    '수정판 있음 N · KEV N'(이전 서버는 '취약점 N · KEV N'). 수가 없으면 까닭 글(자산 정보 없음 · 조사 기록 없음 · 대조 전 …)
 *  unknown '미확인 N'(수정 여부 미확인, 흐린 글로 뒤에 둔다). 이전 서버 · 수가 없으면 null
 *  flags   조사 오래됨(수집 48시간) · 대조 실패(check_error) · 대조 오래됨(대조 48시간). 수를 숨기거나 0 으로 바꾸지 않고 옆에 붙인다
 * 자산이 여럿이면 수를 더하고 자산 화면 목록으로 잇는다(보호 대상은 보통 같은 이름의 자산 하나다)
 */
export interface VulnSummary {
  main: string
  /** main 이 수가 아니라 까닭 글이다(흐리게) */
  muted: boolean
  unknown: string | null
  flags: string[]
  href: string | null
}

export function vulnSummary(vulns: TargetVulns): VulnSummary {
  if (!vulns.available) return { main: '취약점 정보 없음', muted: true, unknown: null, flags: [], href: null }
  const assets = vulns.assets
  if (!assets.length) return { main: '연결된 자산 없음', muted: true, unknown: null, flags: [], href: null }
  const href = assets.length === 1 ? assetHref(assets[0].asset_id) : '/inventory'
  const flags: string[] = []
  const flag = (text: string) => {
    if (!flags.includes(text)) flags.push(text)
  }
  for (const asset of assets) {
    if (asset.missing) continue
    if (asset.stale && asset.collected_at) flag('조사 오래됨')
    if (asset.check_failed === true) flag('대조 실패')
    if (asset.check_stale === true) flag('대조 오래됨')
  }
  // 수를 믿을 수 있는 자산: 조사 · 대조를 마친 자산(대조 전의 0 은 '없음' 이 아니다)
  const counted = assets.filter((a) => !a.missing && a.collected_at && a.checked_at)
  if (!counted.length) {
    // 까닭은 첫 자산 기준(vulnText 와 같은 순서)
    const first = assets.find((a) => !a.missing) ?? assets[0]
    const main = first.missing ? '자산 정보 없음' : !first.collected_at ? '조사 기록 없음' : '취약점 대조 전'
    return { main, muted: true, unknown: null, flags, href }
  }
  const sum = (key: 'vuln_total' | 'vuln_kev' | 'vuln_fix_available' | 'vuln_fix_unknown') => counted.reduce((n, a) => n + (isCount(a[key]) ? a[key] : 0), 0)
  const split = counted.every((a) => isCount(a.vuln_fix_available) && isCount(a.vuln_fix_unknown))
  if (!split) return { main: `취약점 ${count(sum('vuln_total'))} · KEV ${count(sum('vuln_kev'))}`, muted: false, unknown: null, flags, href }
  return { main: `수정판 있음 ${count(sum('vuln_fix_available'))} · KEV ${count(sum('vuln_kev'))}`, muted: false, unknown: `미확인 ${count(sum('vuln_fix_unknown'))}`, flags, href }
}

/**
 * 카드 순서(#64): 고정 대상 뒤에 등록 노드. 서버가 이미 그렇게 주지만 섞여 와도 고정 대상이 앞자리를 잃지 않게
 * 종류로만 나눈다(각 무리 안은 서버 순서 그대로)
 */
export function orderTargets<T extends Pick<Target, 'id' | 'kind'>>(targets: readonly T[]): T[] {
  return [...targets.filter((t) => targetKind(t) === 'fixed'), ...targets.filter((t) => targetKind(t) === 'node')]
}

/** 대상 이름을 그릴 최대 글자 수. 등록 노드 이름(hostname)의 상한(253)과 같다. 넘으면 자르고 전체는 말풍선으로 본다 */
export const LABEL_MAX = 253

/** 접힌 요약의 미판정 글 */
export function pendingText(target: Pick<Target, 'security'>): string {
  return `미판정 ${count(target.security.pending)}`
}

/** 그 장비의 미판정 사건 목록(#72). 카드 수와 같은 기준(서버 device 필터)이고 기간은 넣지 않는다(카드 미판정은 기간 무관) */
export function pendingHref(deviceId: string): string {
  return `/incidents?${new URLSearchParams({ judged: 'false', device: deviceId })}`
}

/** 미결 사건 목록(#83): 최신 판정이 사람이 남긴 미결. 장비를 주면 그 장비만(카드 수와 같은 기준) */
export function undeterminedHref(deviceId?: string): string {
  return `/incidents?${new URLSearchParams(deviceId ? { undetermined: 'true', device: deviceId } : { undetermined: 'true' })}`
}

/** 최근 사건 줄의 판정 글(#83): 최신 판정이 미결이면 판정 기록이 있어도 '미결' 이다(VERDICT_LABEL 과 같은 말) */
export function latestJudgedText(latest: Pick<TargetLatest, 'judged' | 'verdict'>): string {
  if (latest.verdict === 'undetermined') return '미결'
  return latest.judged ? '판정됨' : '미판정'
}

/**
 * 최근 로그 화면(#73)이 있는 대상: web-01 과 등록 노드. 서버의 보호 대상 판정(device_options 의 protected)과 같다.
 * groupTargets 가 숨기지 않으려고 보호 대상에 둔 모르는 고정 id 는 들지 않는다(서버가 404 로 답한다)
 */
export function isLogDevice(target: Pick<Target, 'id' | 'kind'>): boolean {
  return targetKind(target) === PROTECTED_KIND || (PROTECTED_IDS as readonly string[]).includes(target.id)
}

/** 대시보드 무리(#72): 보호 대상(맨 위 카드) · 관측 센서 · 관제 시스템(아래 접힌 줄) */
export interface TargetGroups<T> {
  protected: T[]
  sensors: T[]
  system: T[]
}

/**
 * 대상을 무리로 나눈다. 각 무리 안은 서버 순서 그대로다. kind 가 없으면 targetKind(고정 네 id 인지)로 가른다.
 * 등록 노드는 모두 보호 대상이다. 모르는 고정 id 는 숨기지 않으려고 보호 대상에 둔다
 */
export function groupTargets<T extends Pick<Target, 'id' | 'kind'>>(targets: readonly T[]): TargetGroups<T> {
  const groups: TargetGroups<T> = { protected: [], sensors: [], system: [] }
  for (const target of targets) {
    if (targetKind(target) === PROTECTED_KIND || (PROTECTED_IDS as readonly string[]).includes(target.id)) groups.protected.push(target)
    else if ((SENSOR_IDS as readonly string[]).includes(target.id)) groups.sensors.push(target)
    else if ((SYSTEM_IDS as readonly string[]).includes(target.id)) groups.system.push(target)
    else groups.protected.push(target)
  }
  return groups
}

/** 머리 배지. 서버가 정상이라 했어도 데이터 노드의 확인(적재기 · 집행기) · 탐지 경로가 멈췄으면 '주의' 다. data-collection 은 서버 값 그대로 둔다 */
export function headBadge(target: { collection: Pick<TargetCollection, 'state' | 'stopped'> }): { label: string; tone: Tone } {
  const state = collectionState(target.collection.state)
  if (state === 'ok' && Array.isArray(target.collection.stopped) && target.collection.stopped.length > 0) return { label: '주의', tone: 'warning' }
  return { label: COLLECTION_LABEL[state], tone: COLLECTION_TONE[state] }
}

/** 보호 대상 카드 · 요약 줄의 정상 글(#83). 보고서 표(COLLECTION_LABEL)와 관측 센서 · 관제 시스템(콘솔은 '응답 중')은 그대로다 */
export const PROTECTED_OK_LABEL = '수집 정상'

/** 보호 대상의 머리 배지: 정상이면 '수집 정상', 그 밖은 headBadge 와 같다 */
export function protectedHeadBadge(target: { collection: Pick<TargetCollection, 'state' | 'stopped'> }): { label: string; tone: Tone } {
  const head = headBadge(target)
  return head.label === COLLECTION_LABEL.ok ? { ...head, label: PROTECTED_OK_LABEL } : head
}

/**
 * 접힌 요약 줄의 머리 배지(#84). 보호 대상은 protectedHeadBadge, 그 밖은 headBadge. 콘솔 '응답 중' 은 이번 조회에 응답했다는
 * 사실이라 상태판 갱신이 실패해 이전 결과를 보이는 동안에는 두지 않는다(null, 줄 끝 '이전 결과' 하나만, 결정 5)
 */
export function summaryHeadBadge(target: { collection: Pick<TargetCollection, 'state' | 'stopped'> }, card: 'protected' | 'full', stale: boolean): { label: string; tone: Tone } | null {
  if (stale && collectionState(target.collection.state) === 'responding') return null
  return card === 'protected' ? protectedHeadBadge(target) : headBadge(target)
}

/** 접힌 요약 줄의 경고 배지 하나 */
export interface SummaryFlag {
  key: 'failed' | 'enforcer' | 'unreadable' | 'loader' | 'detect' | 'parse' | 'delayed' | 'checking' | 'removing' | 'report' | 'metrics'
  text: string
  tone: Tone
}

/**
 * 접힌 요약 줄의 경고 배지: 지점 적용 실패 n(빨강) · 집행기 멈춤 · 적재기 멈춤 · 탐지 멈춤 · 웹 로그 적재 없음(주의색) ·
 * 집행 확인 불가(중립색, 생존 신호 표를 읽을 수 없어 멈춤을 모른다 #82). 0 · 해당 없음은 만들지 않는다.
 * 집행기 멈춤은 대응(stalled)과 데이터 노드 멈춤(stopped)에서 한 번만 나온다. 수집 끊김은 머리 배지 '수신 없음' 이 말한다(Q13)
 */
export function summaryFlags(target: {
  response: Pick<TargetResponse, 'failed' | 'stalled' | 'unreadable'>
  collection: Pick<TargetCollection, 'stopped' | 'warnings'>
}): SummaryFlag[] {
  const flags: SummaryFlag[] = []
  const add = (flag: SummaryFlag) => {
    if (!flags.some((f) => f.key === flag.key)) flags.push(flag)
  }
  if (positive(target.response.failed)) add({ key: 'failed', text: `적용 실패 ${count(target.response.failed)}`, tone: 'danger' })
  if (target.response.stalled) {
    add(target.response.unreadable === true ? { key: 'unreadable', text: '집행 확인 불가', tone: 'neutral' } : { key: 'enforcer', text: '집행기 멈춤', tone: 'warning' })
  }
  for (const stop of Array.isArray(target.collection.stopped) ? target.collection.stopped : []) {
    if (stop === 'loader') add({ key: 'loader', text: '적재기 멈춤', tone: 'warning' })
    else if (stop === 'enforcer') add({ key: 'enforcer', text: '집행기 멈춤', tone: 'warning' })
    else if (stop === 'detect') add({ key: 'detect', text: '탐지 멈춤', tone: 'warning' })
  }
  for (const warning of Array.isArray(target.collection.warnings) ? target.collection.warnings : []) {
    if (warning?.key === 'parse') add({ key: 'parse', text: '웹 로그 적재 없음', tone: 'warning' })
  }
  return flags
}

/**
 * 접힌 요약 줄(TargetSummaryList: 수집 · 관제 상태 화면의 관측 센서 · 관제 시스템, 모바일 대시보드의 보호 대상)의 배지(#84 결정 1 · 6 · 7).
 * 넓은 화면의 보호 대상 카드 머리(ProtectedCard)는 한 줄 높이를 지키려고 summaryFlags 그대로다.
 *  지점 적용(요청한 지점만, 미요청 제외) — 지점마다 하나: 적용 실패(빨강, 명시적 실패) > 적용 확인 지연(주의, 5분 넘은 확인 전 · 불일치) >
 *    적용 확인 중(중립, 정상 반영 시간 5분 안의 확인 전). 수는 차단 건수다(n건). 해제 확인 중(중립, 빠짐 확인 전)은 따로.
 *    그 지점 집행기가 멈췄거나 집행 확인 불가면 그 경고 하나로 합친다(서버가 수를 미확인에 합쳐 보낸다)
 *  보고 문제(주의) — 서버 report_issue(관제 이상 띠 report:<지점> 과 같은 판정)
 *  적재기 · 탐지 멈춤 · 웹 로그 적재 없음 — summaryFlags 와 같다
 *  지표 오래됨(주의) — 자원 지표가 오래됨(system.state stale). 지표를 모으는 보호 대상에만 생긴다
 * 이전 서버(checking · delayed · report_issue 없음)는 그 배지를 만들지 않는다. 상세(펼친 카드 · 차단 목록)는 지점별 수를 그대로 보인다
 */
export function summaryLineFlags(target: {
  response: Pick<TargetResponse, 'point' | 'failed' | 'stalled' | 'unreadable'> & Partial<Pick<TargetResponse, 'checking' | 'delayed' | 'removing' | 'report_issue'>>
  collection: Pick<TargetCollection, 'stopped' | 'warnings'>
  system?: Pick<TargetSystem, 'state'>
}): SummaryFlag[] {
  const response = target.response
  const flags: SummaryFlag[] = []
  if (response.point && !response.stalled) {
    if (positive(response.failed)) flags.push({ key: 'failed', text: `적용 실패 ${count(response.failed)}건`, tone: 'danger' })
    else if (positive(response.delayed)) flags.push({ key: 'delayed', text: `적용 확인 지연 ${count(response.delayed)}건`, tone: 'warning' })
    else if (positive(response.checking)) flags.push({ key: 'checking', text: `적용 확인 중 ${count(response.checking)}건`, tone: 'neutral' })
    if (positive(response.removing)) flags.push({ key: 'removing', text: `해제 확인 중 ${count(response.removing)}건`, tone: 'neutral' })
    if (typeof response.report_issue === 'string' && response.report_issue) flags.push({ key: 'report', text: '보고 문제', tone: 'warning' })
  }
  // 집행기 멈춤 · 집행 확인 불가 · 적재기 · 탐지 멈춤 · 웹 로그 적재 없음(적용 실패 수는 위 지점 배지가 대신한다)
  for (const flag of summaryFlags(target)) if (flag.key !== 'failed') flags.push(flag)
  if (target.system?.state === 'stale') flags.push({ key: 'metrics', text: '지표 오래됨', tone: 'warning' })
  return flags
}
