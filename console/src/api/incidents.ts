import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData } from '@tanstack/react-query'
import { ACTION_STATUS, isIncidentAction, type IncidentAction, type IncidentStatus, type Severity, type Verdict } from '@/lib/domain'
import { api } from './client'
import { monitoringKeys } from './monitoring-keys'

/**
 * 인시던트 API(app/main.py). 응답 필드 이름은 서버 그대로 둔다(snake_case).
 *  목록  GET  /api/incidents?…&limit&offset      → IncidentPage
 *  상세  GET  /api/incidents/{key}               → IncidentDetail
 *  판정  POST /api/incidents/{key}/verdict       → VerdictCreated (사건은 resolved)
 *  조치  POST /api/incidents/{key}/actions       → ActionCreated (상태는 ACTION_STATUS)
 *  품질  GET  /api/rules/quality                 → RuleQuality[]
 * 시각은 전부 UTC ISO 8601 문자열. 화면은 lib/time 으로 KST 로 바꿔 보인다.
 * 관련 장비(devices)는 서버가 조회 때 기존 근거로 계산해 싣는다(저장하지 않음). 대체 추정을 거르는 판단은 molecules/device-format 에만 둔다.
 */

/** 한 번에 받는 목록 크기. 서버 기본값과 같다(최대 500). */
export const PAGE_SIZE = 50

// ---------------------------------------------------------------- 응답 자료형

/** 사건과 장비를 이은 근거. 확인(대상 열 · 근거 발생원 · 이벤트) · 규칙 범위(규칙이 보는 장비) · 대체 추정(확인하지 않음) */
export type DeviceBasis = 'confirmed' | 'rule_scope' | 'fallback'
/** 장비 무리. 보호 대상(web-01 · 등록 노드) · 관측 센서(aws-sensor) · 관제 시스템(console · data-node) */
export type DeviceGroup = 'protected' | 'sensor' | 'monitor'
/** 사건의 장비 상태. devices 에 확인이 있으면 confirmed, 규칙 범위만 있으면 rule_scope, 없으면 unconfirmed('장비 미확인') */
export type DeviceState = 'confirmed' | 'rule_scope' | 'unconfirmed'

/** 관련 장비 하나. part 는 aws-sensor 의 나눔(SSH 허니팟(Cowrie) · 웹 디코이 · 허니팟 관문)에만 있다. 등록 노드의 label 은 hostname 이라 비신뢰다 */
export interface IncidentDevice {
  id: string
  part: 'cowrie' | 'decoy' | 'gateway' | null
  label: string
  group: DeviceGroup
  /** 로그 종류('웹 접근' · 'SSH 세션' …) */
  logs: string[]
  basis: DeviceBasis
}

/** 목록 장비 필터의 선택지. 등록 노드의 label 은 hostname 이라 비신뢰다 */
export interface DeviceOption {
  id: string
  label: string
  group: DeviceGroup
}

/** 목록 device 예약값: 장비를 확인하지 못한 사건. 노드 id 형식 밖이다 */
export const UNCONFIRMED_DEVICE = '_unconfirmed'

/** 목록 · 상세가 같이 갖는 사건 필드 */
export interface IncidentBase {
  incident_key: string
  rule_id: string
  rule_version: string
  rule_name: string
  severity: Severity
  /** 출발지. 대상(target)이 있는 사건은 null 일 수 있다 */
  actor_ip: string | null
  /** IP 가 아닌 대상(user:<이름> · node:<id>) */
  target: string | null
  first_ts: string
  last_ts: string
  signal_count: number
  session_count: number
  status: IncidentStatus
  created_at: string
  /** 관련 장비(확인 · 규칙 범위, 보호 대상 먼저). 이전 서버에서는 생략된다 */
  devices?: IncidentDevice[]
  device_state?: DeviceState
  /** 대체 추정 장비. 확정으로 보이지 않고 상세 ⓘ 에만 쓴다 */
  device_fallback?: IncidentDevice[]
}

/** 목록 한 행. verdict 는 최근 판정 하나(재판정이 있어도 마지막 판단), pending_seconds 는 now - first_ts */
export interface Incident extends IncidentBase {
  verdict: Verdict | null
  pending_seconds: number
}

export interface IncidentPage {
  total: number
  limit: number
  offset: number
  items: Incident[]
  /** 전체 사건의 규칙 선택지. 이전 서버에서는 생략된다. */
  rules?: IncidentRule[]
  /** 장비 필터 선택지. 행과 관계없이 온다(등록 노드는 id 순). 이전 서버에서는 생략된다 */
  device_options?: DeviceOption[]
}

export interface IncidentRule {
  rule_id: string
  rule_name?: string
}

/** 규칙이 본 것. sample 은 규칙마다 다른 detail(보통 객체지만 문자열 등이 올 수도 있다) */
export type EvidenceSample = Record<string, unknown> | string | number | boolean | null

export interface IncidentEvidence {
  sample: EvidenceSample[]
  sessions: string[]
  /** 임계치와 비교된 관측값(신호 전체의 최댓값). 세는 규칙에만 있다 */
  observed_count_max?: number
  observed_sigma_max?: number
  [extra: string]: unknown
}

export interface VerdictRecord {
  id: number
  verdict: Verdict
  reason: string | null
  observed_value: number | null
  operator: string
  created_at: string
  /** 이전 이력은 미기록(null), 미지원 서버는 생략될 수 있다. */
  proposed?: Verdict | null
  decision_seconds?: number | null
}

/** POST /verdict 의 201 응답. 기록 필드에 제안값 · 소요 시간 · 사건 키가 더 온다 */
export interface VerdictCreated extends VerdictRecord {
  proposed: Verdict | null
  decision_seconds: number | null
  incident_key: string
}

export interface ActionRecord {
  id: number
  /** 보통 IncidentAction. 화면이 내지 않는 값(escalate · note)이 이력에 남아 있을 수 있어 넓게 둔다 */
  action: IncidentAction | string
  operator: string
  note: string | null
  created_at: string
}

export interface ActionCreated extends ActionRecord {
  incident_key: string
  /**
   * 흡수 출발지를 함께 다룬 조치. 차단(include_absorbed)은 blocked(이 사건 흡수 차단) · kept(다른 사건 차단으로 둠) ·
   * skipped_total(사람이 풀어 넣지 않음) · unblockable(차단 금지 대역) · follow_expires_at(후속 차단 약속 만료),
   * 함께 해제는 released · follow_stopped, 한 곳 해제(actor_ip)는 released = 1 · actor_ip
   */
  absorbed?: {
    blocked?: number
    kept?: number
    skipped?: string[]
    skipped_total?: number
    unblockable?: number
    follow_expires_at?: string | null
    released?: number
    follow_stopped?: boolean
    actor_ip?: string
  }
}

/** 같은 출발지의 다른 사건(최근 20건) */
export interface RelatedIncident {
  incident_key: string
  rule_id: string
  severity: Severity
  first_ts: string
  signal_count: number
  status: IncidentStatus
}

/** 규칙이 보지 않은 증거: 같은 구간(앞 5분 · 뒤 30분) 같은 출발지가 실제로 한 일(최대 200행) */
export interface BehaviorRow {
  ts: string
  sensor: string
  eventid: string
  session: string | null
  username: string | null
  input: string | null
  url: string | null
  shasum: string | null
  http_method: string | null
  http_status: number | null
}

/** 원문 로그 줄(최대 300행). 비밀번호 원문은 오지 않고 있었는지(has_password)만 온다 */
export interface RawLine extends BehaviorRow {
  has_password: boolean
  user_agent: string | null
  message: string | null
}

export interface ActorHistory {
  first_seen: string | null
  last_seen: string | null
  events: number
  sensors: string[] | null
  sessions: number
}

export interface ActorRuleHit {
  rule_id: string
  incidents: number
}

/**
 * 차단 목록의 행. 요청(created_at)과 집행(enforced_at)은 다르다. 집행기가 관문 반영을 확인하면 method · enforced_at ·
 * enforce_note('관문 반영 · …')를 쓰고, 불일치 · 제외는 enforce_note('관문 불일치 · …' · '집행 제외 · …')로 알린다(이슈 #47).
 * 관문 세 열(method · enforced_at · enforce_note 의 관문 쪽지)은 관문을 요청한 행에만 쓴다(이슈 #77). 다시 걸어도 요청 시각에 비지 않고,
 * 관문이 뺐다는 보고 없이 다시 건 차단을 새 보고로 확인하면 쪽지 끝에 관문 보고가 이어졌으면 '· 기존 차단 유지', 아니면
 * '· 연속성 확인 불가' 가 붙는다(결정 2 · 3)
 */
export interface ActorBlock {
  reason: string | null
  /** 관문이 보고한 집행 방식(fail2ban · nft) */
  method: string | null
  created_at: string
  expires_at: string | null
  released_at: string | null
  enforced_at: string | null
  /** 집행 결과 메모. 이전 서버의 상세에는 없다 */
  enforce_note?: string | null
  /** 요청자(콘솔 사용자 · triage:<판정자>). 이전 서버의 상세에는 없다 */
  requested_by?: string | null
  /**
   * 집행 지점(허니팟 관문 · 내부 방화벽)별 결과(이슈 #51). 집행기만 쓴다. 요청하지 않은 지점은 키가 없다(요청했다가 뺀 지점은 그 지점이
   * 뺐다고 확인하기 전까지 removing, #77 결정 14). 이전 서버 · 집행기에는 없다
   */
  enforcement?: BlockEnforcement | null
  /** 요청 지점(이슈 #77, 정규 순서 ['gateway','fw'] 또는 ['fw']). 내부 방화벽은 늘 든다. 이전 서버에는 없고 그때는 두 지점이다 */
  points?: BlockPoint[] | null
}

/** 차단 적용 지점. 관문(허니팟 유입 앞 · 관측) · 내부 방화벽(보호 대상 앞 · 보호) */
export type BlockPoint = 'gateway' | 'fw'

/**
 * 집행 지점 하나의 결과. state 는 대기 · 적용 확인 · 실패 · 확인 지연 · 빠짐 확인 전(removing, 이슈 #77: 목록에서 빠진 행이나
 * 요청했다가 뺀 지점(관리자 관문 빼기)을 그 지점이 뺐다고 보고하기 전. 목록 행의 요청 지점에는 없다)
 */
export type EnforcePointState = 'pending' | 'confirmed' | 'failed' | 'stale' | 'removing'
export interface EnforcePoint {
  state: EnforcePointState
  /** 그 상태가 된 시각(적용 확인이면 처음 확인한 지점 보고의 시각) */
  since: string | null
  /** 지점이 보고한 방식(nft · fail2ban). 지점이 보낸 값이라 글자로만 그린다 */
  mode: string | null
  /** 실패 · 확인 지연의 까닭 */
  note: string | null
}
export type BlockEnforcement = Partial<Record<BlockPoint, EnforcePoint>>

/** 차단 기본값의 까닭(확인 창 ⓘ). 규칙이 허니팟 남용 → 장비 미확인 → 관측 센서뿐 → 보호 대상 포함 → 관제 시스템 포함 순으로 고른다 */
export type BlockPointsBasis = 'honeypot_abuse' | 'sensor_only' | 'protected' | 'monitor' | 'unconfirmed'

/**
 * 사건의 차단 적용 지점(이슈 #77). default 는 규칙만으로 정한 기본값(허니팟 남용 규칙이면 두 지점, 아니면 내부 방화벽),
 * basis 는 그 까닭(장비는 여기만 쓴다), requested 는 이 출발지의 살아 있는 차단이 요청한 지점(없으면 null)
 */
export interface BlockPointsInfo {
  default: BlockPoint[]
  basis: BlockPointsBasis
  requested: BlockPoint[] | null
}

/** 이 출발지가 드는 차단 금지 대역(block_exempt). 콘솔 · triage · 흡수 어느 경로로도 차단 목록에 들어가지 않는다 */
export interface BlockExempt {
  cidr: string
  note: string
}

/**
 * 같은 페이로드 흡수(규칙 v3 · incident_absorbed) 한 행. 이 사건이 첫 사건일 때만 있다.
 *  kind absorbed    같은 페이로드를 24시간 안에 다시 투하 · 심어 첫 사건에 묶여 지워진 인시던트
 *  kind suppressed  가린 것이 흡수된 인시던트뿐이라 억제로 지운 같은 출발지의 낮은 알림(via_key 가 가린 흡수 인시던트)
 */
export interface AbsorbedRow {
  actor_ip: string | null
  kind: 'absorbed' | 'suppressed'
  rule_id: string
  member_key: string
  via_key: string | null
  first_ts: string
  last_ts: string
  signal_count: number
  /** 세션 수 */
  sessions: number
  /** 페이로드(파일 해시 · 키 지문) 첫 값 */
  payload: string | null
  /** 흡수 사유 한 줄(서버가 쓴다) */
  reason: string
}

/**
 * 흡수 기록. 첫 사건의 근거(evidence.absorbed)는 판정 때 굳고 앞 100곳만 담으므로 차단 근거는 이것이다.
 * items 는 흡수 먼저 · 첫 시각 순 최대 200행, 수는 전체를 센다.
 */
export interface AbsorbedInfo {
  items: AbsorbedRow[]
  /** 기록 전체(억제 포함) */
  total: number
  /** 흡수 출발지 수(이 사건 출발지 제외 · 중복 제거) */
  sources: number
  /** 이 사건의 흡수 차단으로 지금 살아 있는 행 수(함께 풀 수) */
  blocked: number
  /** 다른 사건 차단으로 살아 있는 흡수 출발지(함께 차단해도 그 사건 것으로 둔다) */
  kept?: number
  /** 사람이 풀어 함께 차단 · 후속 차단에서 빼는 출발지(앞 20곳)와 그 전체 수 */
  skipped?: string[]
  skipped_total?: number
  /** 차단 금지 대역(사설 · 예약 · 인프라 주소, 한 주소가 아닌 것 포함)이라 넣지 않는 출발지 수 */
  unblockable?: number
  /** 규칙이 같은 페이로드 흡수를 쓰는가. 흡수 기록이 아직 없어도 함께 차단(후속 차단 약속)을 고를 수 있다 */
  absorbs?: boolean
  /**
   * 살아 있는 후속 차단 약속. 만료 전까지 새로 흡수되는 출발지를 콘솔이 같은 만료로 차단한다.
   * verdict 는 첫 사건의 마지막 판정이다. 위협일 때만 후속 차단이 돈다(없거나 다른 판정이면 멈춤). 이전 서버에는 없다
   */
  follow?: { expires_at: string; requested_by: string | null; verdict?: Verdict | null } | null
}

export interface ActorInfo {
  /** 이 출발지의 실제 이벤트 이력. 출발지가 없는 사건(target 만 있는 건)은 null */
  history: ActorHistory | null
  rules: ActorRuleHit[]
  blocked: ActorBlock | null
  /** 차단 금지 대역에 들면 그 대역. 차단 단추를 흐리고 까닭을 보인다. 이전 서버에는 없다 */
  exempt?: BlockExempt | null
}

export interface IncidentDetail extends IncidentBase {
  evidence: IncidentEvidence | null
  actions: ActionRecord[]
  verdicts: VerdictRecord[]
  related: RelatedIncident[]
  behavior: BehaviorRow[]
  actor: ActorInfo
  raw: RawLine[]
  /** 판정 근거와 규칙 조건이 겹치는 규칙(R002 · R003 · R004 · R006)의 경고 문장. 아니면 null */
  circular: string | null
  /** 같은 페이로드 흡수 기록(규칙 v3). 이전 서버에서는 생략된다 */
  absorbed?: AbsorbedInfo
  /** 서버가 전체 관측 구간에서 계산한 제안. 없으면 추측하지 않는다. */
  proposal?: { verdict: Verdict | null; reasons: string[] }
  /** 차단 적용 지점의 기본값 · 까닭 · 살아 있는 요청(이슈 #77). 이전 서버에는 없고 그때 확인 창은 지점을 보내지 않는다 */
  block_points?: BlockPointsInfo
}

/** GET /api/rules/quality 한 행(infra/schema.sql 의 rule_quality 뷰). 비율은 % 값이고 판정이 없으면 null */
export interface RuleQuality {
  rule_id: string
  rule_version: string
  incidents: number
  judged: number
  threats: number
  non_actionable: number
  false_positives: number
  false_positive_rate: number | null
  non_action_rate: number | null
  benign_positives: number
  undetermined: number
  /** 미결을 뺀 판정 수(비율의 분모) */
  judged_effective: number
}

// ---------------------------------------------------------------- 요청 자료형

export type IncidentSort = 'pending' | 'severity' | 'recent'

/** 목록 필터. 비우거나(undefined · '') 넘기지 않은 칸은 쿼리에 붙지 않는다 */
export interface IncidentFilters {
  status?: IncidentStatus
  severity?: Severity
  rule_id?: string
  /** true 판정된 건만 · false 미판정만 */
  judged?: boolean
  /**
   * true 최신 판정이 사람이 남긴 미결(undetermined, 시스템 전환 기록 제외)인 사건만(#83). judged 와 함께 주면 둘 다 맞는 것.
   * 대시보드 미결 수 · 카드 미결 수와 같은 식이다. 이전 서버는 모르는 인자를 무시한다
   */
  undetermined?: boolean
  /** 기본 pending(미판정 오래된 순). 심각도순이 아니다(화면 설계 4장) */
  sort?: IncidentSort
  actor_ip?: string
  target?: string
  /** 관련 장비 id 또는 UNCONFIRMED_DEVICE. 서버가 쪽 나누기 전에 거른다 */
  device?: string
  /** 기간(first_ts). ISO 8601 */
  since?: string
  until?: string
}

export interface VerdictInput {
  verdict: Verdict
  reason?: string
  observed_value?: number
  /** 화면이 보인 제안값. 뒤집힘 비율을 재려면 판정과 함께 남아야 한다 */
  proposed?: Verdict
  /** 판정 소요 초(0..86400) */
  decision_seconds?: number
}

export interface ActionInput {
  action: IncidentAction
  note?: string
  /** 차단 만료(1..720시간, 기본 24) */
  expires_hours?: number
  /** 차단 · 해제에 이 사건(첫 사건)의 흡수 출발지를 함께 넣는가. 넣지 않으면 이 출발지만(서버 기본 false) */
  include_absorbed?: boolean
  /**
   * 해제할 차단 행의 출발지(차단 목록 화면). 이 사건 출발지와 다르면 이 사건의 흡수 차단 그 한 행만 푼다.
   * 흡수 차단 행은 근거 사건(첫 사건)의 출발지와 행의 출발지가 다르다
   */
  actor_ip?: string
  /**
   * 차단 적용 지점(이슈 #77). ['fw'] 또는 ['gateway', 'fw']. 없으면 서버가 두 지점으로 본다(이전 화면). 흡수 함께 차단 · 후속 차단
   * 약속도 같은 지점이다. 살아 있는 차단보다 좁히면(관문 빼기) admin 만 되고 서버가 한 번에 해제 뒤 다시 건다(operator 는 403)
   */
  points?: BlockPoint[]
}

// ---------------------------------------------------------------- 쿼리 키

type FilterValue = string | boolean | undefined

/** 비어 있는 칸을 뺀 필터. 같은 뜻의 필터는 같은 키 · 같은 쿼리가 된다 */
export function normalizeFilters(filters: IncidentFilters = {}): Partial<Record<keyof IncidentFilters, string | boolean>> {
  const out: Partial<Record<keyof IncidentFilters, string | boolean>> = {}
  for (const [key, raw] of Object.entries(filters) as Array<[keyof IncidentFilters, FilterValue]>) {
    if (raw === undefined || raw === null || raw === '') continue
    out[key] = raw
  }
  return out
}

export const incidentKeys = {
  all: ['incidents'] as const,
  lists: () => [...incidentKeys.all, 'list'] as const,
  list: (filters: IncidentFilters = {}) => [...incidentKeys.lists(), normalizeFilters(filters)] as const,
  page: (filters: IncidentFilters, page: number, pageSize: number) => [...incidentKeys.list(filters), 'page', page, pageSize] as const,
  details: () => [...incidentKeys.all, 'detail'] as const,
  detail: (key: string) => [...incidentKeys.details(), key] as const,
}

export const ruleKeys = {
  all: ['rules'] as const,
  quality: () => [...ruleKeys.all, 'quality'] as const,
}

// ---------------------------------------------------------------- 요청

/** 사건 키는 '|' · ':' · '+' 를 품으므로 경로에 넣기 전에 부호화한다(서버 경로는 {incident_key:path}) */
export function incidentPath(key: string): string {
  return `/api/incidents/${encodeURIComponent(key)}`
}

export function fetchIncidents(filters: IncidentFilters, offset = 0, signal?: AbortSignal, limit = PAGE_SIZE): Promise<IncidentPage> {
  return api.get<IncidentPage>('/api/incidents', { query: { ...normalizeFilters(filters), limit, offset }, signal })
}

/** 페이지 번호와 크기도 캐시 키에 포함한다. 실시간 통보는 기존 lists 키로 모든 페이지를 무효화한다. */
export function useIncidentsPage(filters: IncidentFilters, page: number, pageSize: number) {
  return useQuery({
    queryKey: incidentKeys.page(filters, page, pageSize),
    queryFn: ({ signal }) => fetchIncidents(filters, (page - 1) * pageSize, signal, pageSize),
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
}

export function fetchIncident(key: string, signal?: AbortSignal): Promise<IncidentDetail> {
  return api.get<IncidentDetail>(incidentPath(key), { signal })
}

export function postVerdict(key: string, input: VerdictInput): Promise<VerdictCreated> {
  return api.post<VerdictCreated>(`${incidentPath(key)}/verdict`, input)
}

export function postAction(key: string, input: ActionInput): Promise<ActionCreated> {
  return api.post<ActionCreated>(`${incidentPath(key)}/actions`, input)
}

export function fetchRulesQuality(signal?: AbortSignal): Promise<RuleQuality[]> {
  return api.get<RuleQuality[]>('/api/rules/quality', { signal })
}

// ---------------------------------------------------------------- 목록(무한 스크롤)

/** 다음 offset. 받은 만큼 더한 값이 total 보다 작을 때만. 빈 쪽이 오면 끝이다 */
export function nextOffset(lastPage: IncidentPage): number | undefined {
  if (lastPage.items.length === 0) return undefined
  const next = lastPage.offset + lastPage.items.length
  return next < lastPage.total ? next : undefined
}

export interface IncidentList {
  items: Incident[]
  /** 필터에 맞는 전체 건수(마지막 쪽 기준) */
  total: number
  rules?: IncidentRule[]
}

/**
 * 쪽들을 한 배열로 편다. offset 쪽 넘김이라 사이에 새 사건이 끼면 같은 건이 두 쪽에 걸칠 수 있어 키로 거른다(먼저 온 것을 남긴다).
 */
export function flattenPages(data: InfiniteData<IncidentPage, number>): IncidentList {
  const seen = new Set<string>()
  const items: Incident[] = []
  for (const page of data.pages) {
    for (const item of page.items) {
      if (seen.has(item.incident_key)) continue
      seen.add(item.incident_key)
      items.push(item)
    }
  }
  const last = data.pages[data.pages.length - 1]
  return { items, total: last?.total ?? 0, ...(last?.rules ? { rules: last.rules } : {}) }
}

/** 목록. 50건씩 offset 으로 더 받는다. data 는 { items(평탄화 · 중복 제거), total } */
export function useIncidentsInfinite(filters: IncidentFilters = {}) {
  return useInfiniteQuery({
    queryKey: incidentKeys.list(filters),
    queryFn: ({ pageParam, signal }) => fetchIncidents(filters, pageParam, signal),
    initialPageParam: 0,
    getNextPageParam: nextOffset,
    staleTime: 30_000,
    select: flattenPages,
  })
}

// ---------------------------------------------------------------- 상세

/** 사건 한 건. 키가 비어 있으면 묻지 않는다 */
export function useIncident(key: string) {
  return useQuery({
    queryKey: incidentKeys.detail(key),
    queryFn: ({ signal }) => fetchIncident(key, signal),
    staleTime: 60_000,
    enabled: key !== '',
  })
}

/** 판정이 기록된 상세: 판정을 이력 끝에 붙이고 사건은 종결(resolved). 서버(add_verdict)와 같은 규칙 */
export function applyVerdict(detail: IncidentDetail, created: VerdictCreated): IncidentDetail {
  return { ...detail, status: 'resolved', verdicts: [...detail.verdicts, created] }
}

/** 조치가 기록된 상세: 조치를 이력 끝에 붙이고 상태는 ACTION_STATUS 대로(없는 조치는 그대로) */
export function applyAction(detail: IncidentDetail, created: ActionCreated): IncidentDetail {
  const status = (isIncidentAction(created.action) && ACTION_STATUS[created.action]) || detail.status
  return { ...detail, status, actions: [...detail.actions, created] }
}

/** 차단 목록을 건드리는 조치. 상세의 actor.blocked 는 서버만 알므로 다시 받는다 */
const BLOCKLIST_ACTIONS: ReadonlySet<string> = new Set(['block_ip', 'unblock_ip'])

/**
 * 판정 등록. 성공하면 상세 캐시를 바로 고쳐(판정 추가 · 종결) 화면이 기다리지 않게 하고,
 * 목록과 규칙 품질은 무효화해 다시 받는다. 재시도는 없다(queryClient.ts: 판정이 두 번 들어가면 안 된다).
 */
export function useVerdictMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: VerdictInput) => postVerdict(key, input),
    onSuccess: (created) => {
      queryClient.setQueryData<IncidentDetail>(incidentKeys.detail(key), (prev) => (prev ? applyVerdict(prev, created) : prev))
      void queryClient.invalidateQueries({ queryKey: incidentKeys.lists() })
      void queryClient.invalidateQueries({ queryKey: ruleKeys.quality() })
      void queryClient.invalidateQueries({ queryKey: monitoringKeys.summary })
    },
  })
}

/** 조치 등록. 성공하면 상세 캐시를 바로 고치고(조치 추가 · 상태 변경) 목록은 무효화한다. 차단 · 해제는 상세도 다시 받는다 */
export function useActionMutation(key: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: ActionInput) => postAction(key, input),
    onSuccess: (created) => {
      queryClient.setQueryData<IncidentDetail>(incidentKeys.detail(key), (prev) => (prev ? applyAction(prev, created) : prev))
      void queryClient.invalidateQueries({ queryKey: incidentKeys.lists() })
      if (BLOCKLIST_ACTIONS.has(created.action)) void queryClient.invalidateQueries({ queryKey: incidentKeys.detail(key) })
      void queryClient.invalidateQueries({ queryKey: monitoringKeys.summary })
      if (BLOCKLIST_ACTIONS.has(created.action)) void queryClient.invalidateQueries({ queryKey: monitoringKeys.blocklist })
    },
  })
}

// ---------------------------------------------------------------- 규칙 품질

/** 규칙별 오탐률 · 비조치율(판정 기준 문서 3장). 판정이 들어오면 무효화된다(useVerdictMutation · live) */
export function useRulesQuality() {
  return useQuery({
    queryKey: ruleKeys.quality(),
    queryFn: ({ signal }) => fetchRulesQuality(signal),
    staleTime: 60_000,
  })
}
