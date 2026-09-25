import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import { incidentPath } from './incidents'

/**
 * CVE · KEV 연계(#39). 서버 계약은 app/cti.py.
 *  GET /api/incidents/{key}/cti                    → IncidentCti (서명 규칙 사건의 제품 · CVE · KEV · EPSS · 자산 적용 판정)
 *  GET /api/assets                                 → AssetsResult (자산별 수집 · 대조 요약)
 *  GET /api/assets/{asset_id}?filter&limit&offset  → AssetDetailResult (자산 한 대의 조사 결과와 배포판 취약점 한 쪽)
 *  GET /api/cti/watch                              → WatchResult (주목 CVE: 정해 둔 CVE 마다 자산 설치 버전과 배포판 수정판 대조)
 * 원본은 데이터 노드 수집기(opsloop-cti)가 하루 한 번 받는다. 화면은 신선도(freshness)를 함께 보이고
 * 오래된 정보는 '비해당'으로 읽지 않는다. CVE · KEV · EPSS · CVSS 는 판정값이 아니라 조사 우선순위 정보다.
 * 공개 데이터라 캐시에 두어도 된다. 사건 상세 키(incidentKeys) 밑에 두지 않는다: 판정 · 조치 통보마다 다시 받을 까닭이 없다.
 */

/** 자산 적용 판정. 오래된 정보 · 대조 전은 unknown 이다 */
export const APPLICABILITY_STATUSES = ['affected', 'not_affected', 'unknown'] as const
export type ApplicabilityStatus = (typeof APPLICABILITY_STATUSES)[number]
export const APPLICABILITY_LABEL: Record<ApplicabilityStatus, string> = { affected: '해당', not_affected: '비해당', unknown: '미확인' }

/** 서명과 CVE 의 대응 근거. explicit 은 NVD 설명이 경로를 직접 적은 것, analyst 는 공개 PoC · 제품 경로로 분석가가 맞춘 것 */
export const SIGNATURE_MAPPINGS = ['explicit', 'analyst'] as const
export type SignatureMapping = (typeof SIGNATURE_MAPPINGS)[number]
export const MAPPING_LABEL: Record<SignatureMapping, string> = { explicit: '명시 대응', analyst: '분석가 대응' }

/** 배포판 기준 수정 상태(asset_vulnerabilities.fix_state) */
export const FIX_STATES = ['fix_available', 'reboot_pending', 'no_fix', 'unknown'] as const
export type FixState = (typeof FIX_STATES)[number]
export const FIX_STATE_LABEL: Record<FixState, string> = {
  fix_available: '수정판 있음',
  reboot_pending: '재부팅하면 해소',
  no_fix: '배포판 수정판 없음',
  unknown: '수정 여부 미확인',
}

export const ASSET_ROLES = ['target', 'platform', 'sensor'] as const
export type AssetRole = (typeof ASSET_ROLES)[number]
export const ROLE_LABEL: Record<AssetRole, string> = { target: '대상', platform: '플랫폼', sensor: '센서' }

export const ASSET_METHODS = ['ssh', 'ssm'] as const
export type AssetMethod = (typeof ASSET_METHODS)[number]
export const METHOD_LABEL: Record<AssetMethod, string> = { ssh: 'SSH', ssm: 'SSM' }

/** 자산 취약점 표의 거르기. kev = KEV 에 있는 CVE 만, fix = 수정판 있음 · 재부팅하면 해소 */
export const VULN_FILTERS = ['all', 'kev', 'fix'] as const
export type VulnFilter = (typeof VULN_FILTERS)[number]
export const VULN_FILTER_LABEL: Record<VulnFilter, string> = { all: '전체', kev: 'KEV', fix: '수정 가능' }

/** 자산 취약점 한 쪽의 행 수(서버는 1~200 을 받는다) */
export const VULN_PAGE_SIZE = 50

/** 총수 total 에서 마지막 쪽의 offset. 0건이면 0(첫 쪽)이다 */
export function lastVulnOffset(total: number, limit: number = VULN_PAGE_SIZE): number {
  if (!(total > 0) || !(limit > 0)) return 0
  return Math.floor((total - 1) / limit) * limit
}

/** 서버 asset_id 형식(app/cti.py 의 Path pattern). 주소에서 받은 값은 이 형식일 때만 묻는다 */
export const ASSET_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/

// ---------------------------------------------------------------- 자료형

/** 출처 하나의 신선도. fetched_at 은 마지막 성공 수집, source_ts 는 원천이 밝힌 기준 시각 */
export interface SourceFreshness {
  fetched_at: string | null
  source_ts: string | null
  /** 오래됨(서버 STALE_HOURS 기준). nvd 는 초점 CVE 만 받으므로 늘 false */
  stale: boolean
}

export interface AssetsFreshness {
  /** 자산 수집 시각 가운데 가장 오래된 것 */
  oldest_collected_at: string | null
  /** 수집이 오래됐거나 없는 자산 */
  stale_assets: string[]
}

export interface CtiFreshness {
  kev: SourceFreshness
  epss: SourceFreshness
  /** 배포판 취약점(OSV) 대조 */
  osv: SourceFreshness
  nvd: SourceFreshness
  assets: AssetsFreshness
}

/** 서명의 kev_match 에 맞은 KEV 항목(제품 식별 탐색 R105) */
export interface KevItem {
  cve_id: string
  vendor_project: string
  product: string
  name: string
  /** YYYY-MM-DD(달력 날짜) */
  date_added: string
  due_date: string | null
  /** Known · Unknown */
  ransomware: string | null
}

/** 자산 한 대에 대한 서명 제품의 적용 판정 */
export interface AssetApplicability {
  asset_id: string
  role: AssetRole
  /** 이 사건의 요청을 받은 자산인가(evidence.sensors 기준) */
  targeted: boolean
  status: ApplicabilityStatus
  /** 판정 이유 한 문장(안의 시각은 KST) */
  reason: string
  collected_at: string | null
}

/** 사건에 남은 서명 하나와 그 제품 · CVE · 적용 판정 */
export interface SignatureCti {
  id: string
  product: string
  vendor: string
  mapping: SignatureMapping
  /** 대응 근거 문장 */
  source: string
  /** 서명이 보는 HTTP 메서드. null 이면 모든 메서드 */
  methods: string[] | null
  /** 서명에 적힌 CVE(R106). 제품 식별(R105)은 빈 목록 */
  cves: string[]
  /** kev_match 가 있는 서명만. 등재일 내림차순 */
  kev_products: KevItem[] | null
  applicability: AssetApplicability[]
  summary: ApplicabilityStatus
}

export interface CveKev {
  date_added: string
  due_date: string | null
  ransomware: string | null
  name: string
  vendor_project: string
  product: string
}

export interface CveCvss {
  score: number
  version: string | null
  vector: string | null
  /** NVD 등급(대문자: CRITICAL · HIGH · MEDIUM · LOW) */
  severity: string | null
}

export interface CveEpss {
  /** 0~1 */
  score: number
  /** 0~1 */
  percentile: number
  date: string | null
}

/** 사건에 이어진 CVE 하나. 정렬은 서버가 한다(KEV 먼저 → EPSS 내림차순 → cve_id) */
export interface CveCti {
  cve_id: string
  /** 이 CVE 를 부른 서명 */
  signature_ids: string[]
  kev: CveKev | null
  cvss: CveCvss | null
  epss: CveEpss | null
  description: string | null
  nvd_fetched_at: string | null
}

/** 서명 규칙 사건이 아니다(url_signature 가 아니거나 evidence.signatures 가 없다). 구역을 그리지 않는다 */
export interface IncidentCtiNotApplicable {
  as_of: string
  incident_key: string
  applicable: false
}

/** 서명 규칙 사건이지만 CTI 표가 아직 없다(마이그레이션 전) */
export interface IncidentCtiUnavailable {
  as_of: string
  incident_key: string
  applicable: true
  available: false
  rule_id: string
  rule_version: string
}

export interface IncidentCtiDetail {
  as_of: string
  incident_key: string
  applicable: true
  available: true
  rule_id: string
  rule_version: string
  /** kev · epss · osv 중 하나라도 오래됨 */
  stale: boolean
  freshness: CtiFreshness
  signatures: SignatureCti[]
  cves: CveCti[]
}

export type IncidentCti = IncidentCtiNotApplicable | IncidentCtiUnavailable | IncidentCtiDetail

/** 자산 목록의 한 행(asset_inventory + asset_vulnerabilities 집계) */
export interface AssetRow {
  asset_id: string
  role: AssetRole
  method: AssetMethod
  /** 호스트명 또는 인스턴스 ID */
  host: string | null
  /** 마지막으로 성공한 조사 시각(노드가 적은 시각) */
  collected_at: string | null
  received_at: string | null
  stale: boolean
  last_attempt_at: string | null
  /** 마지막 시도가 실패한 이유. 옛 조사 결과는 그대로 남는다 */
  last_error: string | null
  os_pretty: string | null
  kernel_running: string | null
  kernel_running_version: string | null
  kernel_newest_version: string | null
  /** 설치된 가장 높은 커널이 실행 중인 커널과 다르다 */
  reboot_pending: boolean
  /** 설치 패키지 수 */
  packages: number
  /** 도는 컨테이너 수 */
  images: number
  /** 배포판 취약점 대조를 마친 시각 */
  checked_at: string | null
  check_error: string | null
  vuln_total: number
  vuln_kev: number
  vuln_fix_available: number
  vuln_reboot_pending: number
  max_epss: number | null
}

export interface AssetsResult {
  as_of: string
  /** CTI 표가 없으면 false. 이때 freshness 는 null, rows 는 빈 목록이다 */
  available: boolean
  freshness: CtiFreshness | null
  rows: AssetRow[]
}

export interface AssetOs {
  id: string | null
  version_id: string | null
  codename: string | null
  pretty: string | null
}

export interface AssetKernel {
  running: string | null
  running_package: string | null
  running_version: string | null
  installed: Array<{ package: string; version: string }>
}

export interface AssetImage {
  container: string
  image: string
  image_id: string | null
}

/** 자산 상세. 목록 행과 같은 필드에 조사 결과 일부를 더한다(images 는 개수가 아니라 목록) */
export interface AssetDetail extends Omit<AssetRow, 'images'> {
  os: AssetOs | null
  kernel: AssetKernel | null
  images: AssetImage[]
  /** 조사 중 못 읽은 항목(예: 'images: …') */
  probe_errors: string[]
  /** 설치된 주요 패키지(서버 KEY_PACKAGES 순서) */
  key_packages: Array<{ name: string; version: string }>
}

/** 목록 행에 붙는 KEV 요약(등재일 · 랜섬웨어 · 이름) */
export interface KevBrief {
  /** YYYY-MM-DD(달력 날짜) */
  date_added: string
  /** Known · Unknown */
  ransomware: string | null
  name: string
}

/** 목록 행에 붙는 CVSS 요약 */
export interface CvssBrief {
  score: number
  severity: string | null
}

export interface AssetVulnerability {
  osv_id: string
  cve_id: string | null
  source_package: string
  /** 대조한 소스 버전(커널은 실행 중인 커널 패키지 버전) */
  version: string
  fix_state: FixState
  fixed_version: string | null
  kev: KevBrief | null
  epss: CveEpss | null
  cvss: CvssBrief | null
  /** negligible · low · medium · high · critical */
  ubuntu_priority: string | null
  summary: string | null
}

export interface AssetVulnPage {
  rows: AssetVulnerability[]
  total: number
  limit: number
  offset: number
  filter: VulnFilter
}

export interface AssetDetailAvailable {
  as_of: string
  available: true
  asset: AssetDetail
  vulnerabilities: AssetVulnPage
  freshness: CtiFreshness
}

/** CTI 표가 없다(마이그레이션 전). 나머지 칸은 null 이다 */
export interface AssetDetailUnavailable {
  as_of: string
  available: false
  asset: null
  vulnerabilities: null
  freshness: null
}

export type AssetDetailResult = AssetDetailAvailable | AssetDetailUnavailable

/** 주목 CVE 의 배포판 영향 패키지 하나(자산 생태계 기준) */
export interface WatchAffectedPackage {
  /** 소스 패키지(커널은 linux · linux-aws 등) */
  package: string
  /** 배포판 수정판. null 이면 수정판이 없다 */
  fixed: string | null
  /** 자산 생태계가 여럿일 때만 온다(예: Ubuntu:24.04:LTS) */
  ecosystem?: string
}

/** 주목 CVE 하나에 대한 자산 한 대의 판정(서버 judge_watch). 패키지 · 설치 · 수정판은 이유가 가리키는 영향 패키지다 */
export interface WatchAsset {
  asset_id: string
  role: AssetRole
  status: ApplicabilityStatus
  /** 판정 이유 한 문장(안의 시각은 KST) */
  reason: string
  package: string | null
  /** 설치 버전(커널은 실행 중인 커널 패키지 버전) */
  installed: string | null
  fixed: string | null
}

/** 주목 CVE 한 행. 정렬은 서버가 한다(해당 먼저 → KEV 있음 → EPSS 내림차순 → cve_id) */
export interface WatchRow {
  cve_id: string
  /** 목록(cti/watchlist.json)에 적은 주목 이유 */
  reason: string
  /** 배포판(Ubuntu) 기록 id. 기록이 없거나 조회 전이면 null */
  osv_id: string | null
  /** null 조회 전 · true 기록 있음 · false 기록 없음 */
  record_found: boolean | null
  /** 배포판 기록을 마지막으로 조회한 시각 */
  checked_at: string | null
  /** negligible · low · medium · high · critical */
  ubuntu_priority: string | null
  /** NVD 설명, 없으면 배포판 기록 요약 */
  description: string | null
  kev: KevBrief | null
  epss: CveEpss | null
  cvss: CvssBrief | null
  affected_packages: WatchAffectedPackage[]
  /** 자산 정렬은 자산 목록과 같다(대상 → 플랫폼 → 센서, asset_id) */
  assets: WatchAsset[]
  summary: ApplicabilityStatus
}

export interface WatchResult {
  as_of: string
  /** CTI 표가 없으면 false. 이때 freshness 는 null, rows 는 빈 목록이다 */
  available: boolean
  freshness: CtiFreshness | null
  rows: WatchRow[]
}

// ---------------------------------------------------------------- 쿼리 키 · 요청

export const ctiKeys = {
  all: ['cti'] as const,
  incident: (key: string) => [...ctiKeys.all, 'incident', key] as const,
  assets: () => [...ctiKeys.all, 'assets'] as const,
  asset: (assetId: string, filter: VulnFilter, offset: number) => [...ctiKeys.assets(), assetId, filter, offset] as const,
  watch: () => [...ctiKeys.all, 'watch'] as const,
}

/** 주목 CVE 경로. /api/assets/{asset_id} 와 겹치지 않게 /api/cti 아래에 있다 */
export const WATCH_PATH = '/api/cti/watch'

/** 사건 키 부호화는 incidentPath 를 그대로 쓴다('|' · ':' · '+' 를 품는다) */
export function incidentCtiPath(key: string): string {
  return `${incidentPath(key)}/cti`
}

export function assetPath(assetId: string): string {
  return `/api/assets/${encodeURIComponent(assetId)}`
}

export function fetchIncidentCti(key: string, signal?: AbortSignal): Promise<IncidentCti> {
  return api.get<IncidentCti>(incidentCtiPath(key), { signal })
}

export function fetchAssets(signal?: AbortSignal): Promise<AssetsResult> {
  return api.get<AssetsResult>('/api/assets', { signal })
}

export function fetchAsset(assetId: string, filter: VulnFilter, offset: number, signal?: AbortSignal): Promise<AssetDetailResult> {
  return api.get<AssetDetailResult>(assetPath(assetId), { signal, query: { filter, limit: VULN_PAGE_SIZE, offset } })
}

export function fetchWatch(signal?: AbortSignal): Promise<WatchResult> {
  return api.get<WatchResult>(WATCH_PATH, { signal })
}

/** 사건 한 건의 취약점 연계. 원본이 하루 단위로 바뀌므로 5분 동안은 다시 묻지 않는다. 키가 비어 있으면 묻지 않는다 */
export function useIncidentCti(key: string) {
  return useQuery({
    queryKey: ctiKeys.incident(key),
    queryFn: ({ signal }) => fetchIncidentCti(key, signal),
    staleTime: 5 * 60_000,
    enabled: key !== '',
  })
}

/** 자산 목록 요약 */
export function useAssets() {
  return useQuery({
    queryKey: ctiKeys.assets(),
    queryFn: ({ signal }) => fetchAssets(signal),
    staleTime: 60_000,
  })
}

/**
 * 자산 한 대와 그 취약점 한 쪽. 거르기 · 쪽을 바꾸는 동안 이전 결과를 유지한다(keepPreviousData).
 * 다른 자산으로 옮기면 이전 자산의 취약점을 새 자산 것처럼 보이지 않게 유지하지 않는다. 자산이 비어 있으면 묻지 않는다
 */
export function useAsset(assetId: string, filter: VulnFilter, offset: number) {
  return useQuery({
    queryKey: ctiKeys.asset(assetId, filter, offset),
    queryFn: ({ signal }) => fetchAsset(assetId, filter, offset, signal),
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[2] === assetId ? keepPreviousData(previous) : undefined),
    staleTime: 60_000,
    enabled: assetId !== '',
  })
}

/** 주목 CVE 대조. 자산 목록과 같이 60초 동안은 다시 묻지 않는다(원본이 하루 단위로 바뀐다) */
export function useWatch() {
  return useQuery({
    queryKey: ctiKeys.watch(),
    queryFn: ({ signal }) => fetchWatch(signal),
    staleTime: 60_000,
  })
}
