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
 */

/** 한 번에 받는 목록 크기. 서버 기본값과 같다(최대 500). */
export const PAGE_SIZE = 50

// ---------------------------------------------------------------- 응답 자료형

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

/** 차단 목록의 행. 요청(created_at)과 집행(enforced_at)은 다르다 */
export interface ActorBlock {
  reason: string | null
  method: string | null
  created_at: string
  expires_at: string | null
  released_at: string | null
  enforced_at: string | null
}

export interface ActorInfo {
  /** 이 출발지의 실제 이벤트 이력. 출발지가 없는 사건(target 만 있는 건)은 null */
  history: ActorHistory | null
  rules: ActorRuleHit[]
  blocked: ActorBlock | null
}

export interface IncidentDetail extends IncidentBase {
  evidence: IncidentEvidence | null
  actions: ActionRecord[]
  verdicts: VerdictRecord[]
  related: RelatedIncident[]
  behavior: BehaviorRow[]
  actor: ActorInfo
  raw: RawLine[]
  /** 판정 근거와 규칙 조건이 겹치는 규칙(R002 · R003 · R004)의 경고 문장. 아니면 null */
  circular: string | null
  /** 서버가 전체 관측 구간에서 계산한 제안. 없으면 추측하지 않는다. */
  proposal?: { verdict: Verdict | null; reasons: string[] }
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
  /** 기본 pending(미판정 오래된 순). 심각도순이 아니다(화면 설계 4장) */
  sort?: IncidentSort
  actor_ip?: string
  target?: string
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
