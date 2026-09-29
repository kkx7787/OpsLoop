import { keepPreviousData, useQuery } from '@tanstack/react-query'
import type { IncidentStatus, Severity, Verdict } from '@/lib/domain'
import { codePointLength } from '@/lib/untrusted'
import { api } from './client'
import type { ActorBlock, BlockExempt } from './incidents'

/**
 * 출발지 분석(S-09 · 이슈 #58). 서버 계약은 app/sources.py. 응답 필드 이름은 서버 그대로 둔다(snake_case).
 *  목록  GET /api/sources?q&sort&include_test&fp_kind&fp&limit&offset → SourcesResult
 *  상세  GET /api/sources/detail?ip=                                  → SourceDetail (잘못된 주소 422 · 사건도 이벤트도 없으면 404)
 *  지문  GET /api/sources/fingerprints?kind&limit&offset              → FingerprintsResult
 * 사건 · 이벤트 수는 실제 수집(provenance='real')만 센다. as_of 는 DB 시각이고 시각은 전부 UTC ISO 8601 문자열이다.
 * SSH 버전 · User-Agent · 지문 값은 공격자가 보낸 글자다. 서버는 512자로 자르기만 하고 화면은 UntrustedText 로만 그린다.
 */

export const SOURCE_SORTS = ['recent', 'incidents', 'severity'] as const
export type SourceSort = (typeof SOURCE_SORTS)[number]
/** 기본은 마지막 사건(last_ts)이 최근인 순. 주소에 붙이지 않는다 */
export const DEFAULT_SOURCE_SORT: SourceSort = 'recent'
export const SOURCE_SORT_LABEL: Record<SourceSort, string> = { recent: '최근 사건순', incidents: '사건 많은 순', severity: '심각도순' }

export function isSourceSort(value: unknown): value is SourceSort {
  return typeof value === 'string' && (SOURCE_SORTS as readonly string[]).includes(value)
}

/**
 * 도구 지문 종류. 서버가 이벤트에서 꺼낸다(열이 따로 없다).
 *  hassh        cowrie.client.kex 문구의 32자 16진
 *  ssh_version  cowrie.client.version 문구의 원격 SSH 버전
 *  user_agent   웹 디코이 요청의 User-Agent
 */
export const FINGERPRINT_KINDS = ['hassh', 'ssh_version', 'user_agent'] as const
export type FingerprintKind = (typeof FINGERPRINT_KINDS)[number]
export const FINGERPRINT_LABEL: Record<FingerprintKind, string> = { hassh: 'HASSH', ssh_version: 'SSH 버전', user_agent: 'User-Agent' }

export function isFingerprintKind(value: unknown): value is FingerprintKind {
  return typeof value === 'string' && (FINGERPRINT_KINDS as readonly string[]).includes(value)
}

/** 목록 · 지문 조회의 offset 상한(서버 cti.MAX_OFFSET). 넘으면 서버가 422 를 준다 */
export const SOURCES_MAX_OFFSET = 1_000_000

/** 서버가 비신뢰 글자(UA · SSH 버전)를 자르는 길이. 지문 조건(fp)도 이 길이까지만 받는다 */
export const FINGERPRINT_MAX = 512

/** 지문 조건으로 보낼 수 있는 값인가: 1~512자(코드 포인트) · NUL 없음(서버가 422 를 준다) */
export function isFingerprintValue(value: string): boolean {
  return value !== '' && !value.includes('\0') && codePointLength(value) <= FINGERPRINT_MAX
}

/** 주소 앞부분 검색(q). 서버와 같은 규칙: 16진 숫자 · ':' · '.' 1~45자 */
export function isAddressPrefix(value: string): boolean {
  return /^[0-9A-Fa-f:.]{1,45}$/.test(value)
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/

/** IPv6 한 토막(:: 앞이나 뒤)의 16비트 묶음 수. 끝 묶음만 IPv4 꼴(2묶음)일 수 있다. 틀리면 null */
function groupCount(part: string): number | null {
  if (part === '') return 0
  const groups = part.split(':')
  let count = 0
  for (const [i, group] of groups.entries()) {
    if (i === groups.length - 1 && IPV4.test(group)) count += 2
    else if (HEX_GROUP.test(group)) count += 1
    else return null
  }
  return count
}

/**
 * 주소 하나(IPv4 · IPv6)인가. 서버(ipaddress)가 받는 꼴만 참이다: IPv4 는 앞자리 0 없는 네 칸,
 * IPv6 는 여덟 묶음 또는 '::' 한 번으로 줄인 꼴(끝에 IPv4 가능). 대역(/24) · 영역 표기(%eth0)는 받지 않는다.
 * 주소창에서 온 값을 서버에 넘기기 전에 거른다(사건 목록 actor_ip · 출발지 상세 ip)
 */
export function isIpAddress(value: string): boolean {
  if (IPV4.test(value)) return true
  if (value.length > 45 || !value.includes(':')) return false
  const halves = value.split('::')
  if (halves.length > 2) return false
  if (halves.length === 1) return groupCount(value) === 8
  const [head, tail] = halves
  if (head.includes('.')) return false
  const before = groupCount(head)
  const after = groupCount(tail)
  return before !== null && after !== null && before + after <= 7
}

// ---------------------------------------------------------------- 응답 자료형

/** 최신 판정(사건마다 마지막 하나)별 사건 수 */
export type VerdictCounts = Record<Verdict, number>

/**
 * 집행기 확인이 멈췄는가(sensor_heartbeats 의 block:gateway · block:fw, 10분 기준). 멈췄으면 지점의 '적용 확인'을 믿지 않는다.
 * 생존 신호 표를 읽을 수 없으면 null
 */
export interface BlockCheckers {
  gateway_stale: boolean | null
  fw_stale: boolean | null
}

/** 출발지 한 곳. 목록 한 행이자 상세의 요약 */
export interface SourceSummary {
  ip: string
  incidents: number
  /** 판정이 없는 사건 수 */
  unjudged: number
  /** 가장 높은 심각도(critical > high > medium > low) */
  severity: Severity
  rules: string[]
  /** 노린 대상(aws-sensor · web-01 · console · data-node 뒤에 등록 노드의 node_id, #64). 이벤트 발생원에서 고른다 */
  targets: string[]
  /** 첫 사건 · 마지막 사건 시각(사건 기준). 사건 뒤에도 이어진 이벤트는 last_seen 으로 본다 */
  first_ts: string
  last_ts: string
  /** 마지막 관측: 이 주소의 수집 이벤트(실제 수집) 가운데 가장 늦은 시각. 마지막 사건보다 늦을 수 있다. 없으면 null */
  last_seen: string | null
  verdicts: VerdictCounts
  /** 시험 대역(test_ranges)의 출발지. 목록은 기본으로 뺀다 */
  test_source: boolean
  /** 차단 금지 대역(사설 · 예약 · 인프라)에 드는가. 금지 대역 표를 읽을 수 없으면 null */
  exempt: boolean | null
  /** 지금 차단 목록 행(사건 상세의 actor.blocked 와 같은 모양). 차단한 적 없으면 null */
  block: ActorBlock | null
}

export interface SourcesResult {
  as_of: string
  total: number
  limit: number
  offset: number
  checkers: BlockCheckers
  items: SourceSummary[]
}

/** 이 출발지의 사건 한 건(사건 흐름) */
export interface SourceIncident {
  incident_key: string
  rule_id: string
  /** 같은 출발지 · 같은 시각의 사건이 규칙 버전(v1 · v2 …)마다 따로 있을 수 있어 함께 보인다 */
  rule_version: string
  rule_name: string
  severity: Severity
  status: IncidentStatus
  first_ts: string
  last_ts: string
  target: string | null
  /** 최신 판정. 없으면 null */
  verdict: Verdict | null
}

/** 발생원 · 이벤트 종류별 수 */
export interface SourceEventKind {
  sensor: string
  eventid: string
  count: number
  first_ts: string
  last_ts: string
}

export interface FingerprintCount {
  value: string
  /** 이 출발지가 이 지문을 쓴 이벤트 수 */
  count: number
}

/** 이 주소 사건들의 차단 · 해제 조치 */
export interface SourceAction {
  incident_key: string
  action: string
  operator: string
  note: string | null
  created_at: string
}

export interface SourceDetail {
  as_of: string
  ip: string
  /** 목록 한 행과 같은 모양. 사건 없이 이벤트만 있는 출발지는 null */
  summary: SourceSummary | null
  /** 마지막 관측(summary.last_seen 과 같다). 사건 없는 출발지도 낸다. 없으면 null */
  last_seen: string | null
  checkers: BlockCheckers
  /** 첫 시각 순 최대 200건. 전체 수는 incidents_total */
  incidents: SourceIncident[]
  incidents_total: number
  /** 수 많은 순 최대 50종 */
  event_kinds: SourceEventKind[]
  /** 종류별 많이 쓴 순 최대 10개 */
  fingerprints: Record<FingerprintKind, FingerprintCount[]>
  /** 최근 50건 */
  actions: SourceAction[]
  block: ActorBlock | null
  /** 이 주소가 드는 차단 금지 대역(block_exempt). 없거나 표를 읽을 수 없으면 null */
  exempt: BlockExempt | null
  /**
   * 금지 대역에 드는가(목록 exempt 와 같은 판단: 코드 상수 + block_exempt). 사건 없는 출발지도 낸다.
   * 표를 읽을 수 없으면 null(위 exempt 는 '들지 않음'과 '읽을 수 없음'을 가르지 못한다)
   */
  exempt_flag: boolean | null
  /** 같은 페이로드 흡수로 지워진 사건 기록(incident_absorbed) 수. 표를 읽을 수 없으면 null */
  absorbed: number | null
}

/** 지문 하나를 쓴 출발지 묶음 */
export interface Fingerprint {
  value: string
  /** 쓴 출발지 수 */
  sources: number
  /** 이 지문이 나온 이벤트 수 */
  connections: number
  /** 쓴 출발지 가운데 사건이 있는 출발지 수 */
  incident_sources: number
  first_ts: string
  last_ts: string
}

export interface FingerprintsResult {
  as_of: string
  kind: FingerprintKind
  total: number
  limit: number
  offset: number
  items: Fingerprint[]
}

// ---------------------------------------------------------------- 요청 자료형 · 쿼리 키

/** 목록 조건. 비어 있는 칸은 쿼리에 붙지 않는다(client.buildUrl 이 undefined 를 뺀다). fp_kind 와 fp 는 함께만 보낸다 */
export interface SourcesQuery {
  q?: string
  sort?: SourceSort
  include_test?: boolean
  fp_kind?: FingerprintKind
  fp?: string
  limit: number
  offset: number
}

export interface FingerprintsQuery {
  kind: FingerprintKind
  limit: number
  offset: number
}

export const sourceKeys = {
  all: ['sources'] as const,
  lists: () => [...sourceKeys.all, 'list'] as const,
  list: (query: SourcesQuery) => [...sourceKeys.lists(), query] as const,
  details: () => [...sourceKeys.all, 'detail'] as const,
  detail: (ip: string) => [...sourceKeys.details(), ip] as const,
  fingerprints: (query: FingerprintsQuery) => [...sourceKeys.all, 'fingerprints', query] as const,
}

const REFRESH = { staleTime: 10_000, refetchInterval: 30_000 } as const

/** 출발지 목록. 조건 · 쪽을 바꾸는 동안 이전 결과를 유지한다 */
export function useSources(query: SourcesQuery) {
  return useQuery({
    queryKey: sourceKeys.list(query),
    queryFn: ({ signal }) =>
      api.get<SourcesResult>('/api/sources', {
        signal,
        query: {
          q: query.q,
          sort: query.sort,
          include_test: query.include_test || undefined,
          fp_kind: query.fp ? query.fp_kind : undefined,
          fp: query.fp_kind ? query.fp : undefined,
          limit: query.limit,
          offset: query.offset,
        },
      }),
    placeholderData: keepPreviousData,
    ...REFRESH,
  })
}

/**
 * 출발지 한 곳. 주소가 비어 있으면 묻지 않는다.
 * 이전 결과를 유지하지 않는다(다른 주소로 옮겼을 때 앞 주소의 차단 · 사건이 새 주소 이름 아래 보이면 안 된다)
 */
export function useSourceDetail(ip: string) {
  return useQuery({
    queryKey: sourceKeys.detail(ip),
    queryFn: ({ signal }) => api.get<SourceDetail>('/api/sources/detail', { signal, query: { ip } }),
    enabled: ip !== '',
    ...REFRESH,
  })
}

/**
 * 도구 지문 묶음. 종류 · 쪽을 바꾸는 동안 이전 결과를 유지한다.
 * 이벤트 전체를 묶는 조회라 주기 재조회는 두지 않는다(지문 분포는 분 단위로 바뀌지 않는다). 탭에 돌아오면 1분이 지났을 때만 다시 받는다
 */
export function useFingerprints(query: FingerprintsQuery) {
  return useQuery({
    queryKey: sourceKeys.fingerprints(query),
    queryFn: ({ signal }) => api.get<FingerprintsResult>('/api/sources/fingerprints', { signal, query: { ...query } }),
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  })
}
