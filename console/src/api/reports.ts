import { useQuery } from '@tanstack/react-query'
import type { Severity, Verdict } from '@/lib/domain'
import { api } from './client'
import type { ApplicabilityStatus, CtiFreshness } from './cti'
import type { RuleQuality } from './incidents'
import type { BlockCounts } from './monitoring'
import type { TargetCollection, TargetResponse } from './targets'

/**
 * 기간 보고서(S-11 · #58). 서버 계약은 app/reports.py GET /api/reports/period?period=&sections=…
 * 끝 = 출력 시각(as_of), 시작 = 끝 - 기간이고 경계는 [시작, 끝). 날짜 묶음은 KST.
 * 구역마다 기준이 다르다: 기간 집계(period) · 출력 시점 값(as_of) · 둘을 섞음(mixed). 인쇄 머리에 그대로 적는다.
 * 표 권한이 없는 구역은 { available: false, reason } 으로 온다(나머지 구역은 그대로 나온다).
 */

export const REPORT_PERIODS = ['24h', '7d', '14d', '30d'] as const
export type ReportPeriod = (typeof REPORT_PERIODS)[number]
export const PERIOD_LABEL: Record<ReportPeriod, string> = { '24h': '최근 24시간', '7d': '최근 7일', '14d': '최근 14일', '30d': '최근 30일' }

/** 구역. 이 순서대로 싣는다 */
export const REPORT_SECTIONS = ['overview', 'rules', 'blocks', 'targets', 'cti', 'ops'] as const
export type ReportSection = (typeof REPORT_SECTIONS)[number]
export const SECTION_LABEL: Record<ReportSection, string> = {
  overview: '요약 · 운영 부담',
  rules: '규칙별 판정 · 비조치율',
  blocks: '차단 · 집행',
  targets: '관제 대상 · 수집',
  cti: '취약점 · CVE',
  ops: '운영 기록',
}
/** 관리자만 고를 수 있는 구역. 서버는 비관리자의 요청을 403 으로 막는다 */
export const ADMIN_SECTIONS: ReadonlySet<ReportSection> = new Set(['ops'])

export type ReportBasis = 'period' | 'as_of' | 'mixed'
export const BASIS_LABEL: Record<ReportBasis, string> = { period: '기간 집계', as_of: '출력 시점 값', mixed: '기간 집계 · 출력 시점 값' }

export function isReportPeriod(value: unknown): value is ReportPeriod {
  return typeof value === 'string' && (REPORT_PERIODS as readonly string[]).includes(value)
}
export function isReportSection(value: unknown): value is ReportSection {
  return typeof value === 'string' && (REPORT_SECTIONS as readonly string[]).includes(value)
}

// ---------------------------------------------------------------- 응답 자료형

/** 표 권한이 없어 만들지 못한 구역 */
export interface SectionUnavailable { available: false; reason: string }
interface SectionBase {
  available: true
  basis: ReportBasis
  /** 기준 설명(무엇을 세었고 무엇을 뺐는지). 구역 끝에 작은 글씨로 싣는다 */
  notes: string[]
}

export interface OverviewSection extends SectionBase {
  /** 기간 사건(발생 시각 기준). 시험 출발지 사건은 합계에서 빼고 test_source 로 따로 센다. 발생원 키는 R0xx · R1xx · R2xx · R3xx · other */
  incidents: { total: number; by_severity: Partial<Record<Severity, number>>; by_origin: Partial<Record<string, number>>; test_source: number }
  /** 기간에 기록된 판정(재판정 포함). 시험 출발지 판정은 따로 */
  verdicts: { total: number; by_verdict: Partial<Record<Verdict, number>>; test_source: number }
  /** 출력 시점 잔량 · 목표 초과(대시보드와 같은 계산) */
  backlog: { unjudged: number; undetermined: number; overdue: number; warning: number; oldest_seconds: number | null }
  /** 판정 대기: 기간에 만들어진 사건의 생성 → 첫 판정. 백분위는 판정된 것만 */
  wait: { incidents: number; judged: number; p50_seconds: number | null; p90_seconds: number | null }
  /** 판정 소요: 콘솔 판정 화면이 잰 시간(verdicts.decision_seconds). triage · 일괄 판정은 값이 없다 */
  decision: { n: number; p50_seconds: number | null; p90_seconds: number | null }
  /** KST 날짜별 생성 · 판정 수. 없는 날도 0 으로 온다 */
  daily: Array<{ date: string; created: number; judged: number }>
  /** 상위 5 출발지와 전체 출발지 수(시험 대역 제외) */
  top_sources: { total: number; items: Array<{ ip: string; incidents: number; severity: Severity | null; last_ts: string | null }> }
}

export interface RulesSection extends SectionBase {
  /** 규칙 화면(/api/rules/quality)과 같은 계산을 기간 사건에 적용한 행 */
  rows: RuleQuality[]
  /** 기간에 기록된 흡수 · 억제(규칙별 포함). 흡수 기록 표를 읽을 수 없으면 null */
  absorbed: { absorbed: number; suppressed: number; rules: Array<{ rule_id: string; rule_version: string; absorbed: number; suppressed: number }> } | null
  /** 기간 중 만든 규칙 버전(정의 본문 없이 규칙 id 만) */
  versions: Array<{ rule_version: string; reason: string | null; created_at: string; rules: string[] }>
}

export interface BlocksSection extends SectionBase {
  /** 기간 차단 · 해제 조치 수(사건 조치 기록) */
  actions: { block_ip: number; unblock_ip: number }
  /** 기간 새 차단 요청(감사 created · rearmed · 만료 뒤 다시 건 extended)의 요청자 종류: 콘솔 사용자 · 'triage:' 접두 · 'system:' 접두 · 미기록(extended 는 요청자가 없다) */
  requests: { total: number; console: number; triage: number; system: number; unknown: number }
  /** 기간 차단 감사 이벤트 종류별 수(없는 종류도 0). 행위자 · 내용은 싣지 않는다 */
  audit: Array<{ eventid: string; count: number }>
  /** 기간 새 차단 요청의 집행 지연(요청 → 관문 반영). created 는 새 요청 수(requests.total 과 같다), enforced 는 그중 집행 확인된 수 */
  enforcement: { created: number; enforced: number; p50_seconds: number | null; max_seconds: number | null }
  /** 출력 시점 살아 있는 차단 요청의 집행 상태(대시보드와 같은 분류) */
  states: BlockCounts & { total: number }
}

export interface TargetsSection extends SectionBase {
  /** 출력 시점 대상별 수집 상태 · 대응 요약(상태판에서 추림). 지점은 이름(point_label)만 온다 */
  targets: Array<{
    id: string
    label: string
    collection: Pick<TargetCollection, 'state' | 'reason'>
    response: Pick<TargetResponse, 'point_label' | 'applied' | 'failed' | 'unverified' | 'exempt' | 'stalled'>
  }>
  /** 기간 센서별 실제 이벤트 수 */
  sensors: Array<{ sensor: string; events: number }>
  /** 기간 탐지 실행 수와 실행 사이 최대 공백(초) */
  detector: { runs: number; max_gap_seconds: number | null }
  /** 기간 web-01 자원 최대와 지표 공백. 지표 표를 읽을 수 없으면 null */
  web: { samples: number; cpu_pct: number | null; mem_used_pct: number | null; disk_root_pct: number | null; max_gap_seconds: number | null } | null
}

export interface CtiSection extends SectionBase {
  /** 자산별 취약점(출력 시점) */
  assets: Array<{ asset_id: string; role: string | null; vuln_total: number; vuln_kev: number; vuln_fix_available: number; vuln_reboot_pending: number; collected_at: string | null; stale: boolean }>
  /** 주목 CVE 대조 요약(출력 시점). 표를 읽을 수 없으면 null */
  watch: ({ total: number; affected_cves: string[] } & Record<ApplicabilityStatus, number>) | null
  /** 기간 중 KEV 등재 수와 그 가운데 우리 자산에 걸린 것 */
  kev_added: { total: number; ours: Array<{ cve_id: string; name: string | null; date_added: string; assets: string[] }> }
  freshness: CtiFreshness
}

export interface OpsSection extends SectionBase {
  /** 기간 감사 이벤트 종류별 수 */
  audit: Array<{ eventid: string; count: number }>
  /** 기간 콘솔 로그인 실패 수 */
  login_failed: number
  /** 기간 알림 발송(시험 발송 제외). 지연은 보낸 것의 넣은 때 → 보낸 때. 표를 읽을 수 없으면 null */
  notify: { total: number; failed: number; p50_seconds: number | null; rows: Array<{ event: string; status: string; count: number }> } | null
}

export interface ReportSectionMap {
  overview: OverviewSection
  rules: RulesSection
  blocks: BlocksSection
  targets: TargetsSection
  cti: CtiSection
  ops: OpsSection
}

export interface PeriodReport {
  /** 출력 시각(DB now()). 기간의 끝이다 */
  as_of: string
  since: string
  until: string
  period: ReportPeriod
  tz: string
  /** 출력자(세션 사용자 이름) */
  generated_by: string
  sections: { [K in ReportSection]?: ReportSectionMap[K] | SectionUnavailable }
}

// ---------------------------------------------------------------- 조회

export interface ReportRequest { period: ReportPeriod; sections: ReportSection[] }

export const reportKeys = {
  all: ['reports'] as const,
  period: (request: ReportRequest) => [...reportKeys.all, 'period', request.period, request.sections] as const,
}

/**
 * 기간 보고서 한 벌. 만든 뒤에는 인쇄하는 동안 바뀌지 않게 다시 묻지 않는다(주기 · 창 초점 없음, 실시간 통보 목록에도 없다).
 * 조건을 바꾸면 이전 결과는 버린다(gcTime 0). 같은 주소로 돌아오면 새로 만들어 출력 시각이 주소를 연 때가 된다.
 */
export function usePeriodReport(request: ReportRequest | null) {
  return useQuery({
    queryKey: request ? reportKeys.period(request) : [...reportKeys.all, 'none'],
    queryFn: ({ signal }) => api.get<PeriodReport>('/api/reports/period', { signal, query: { period: request?.period, sections: request?.sections } }),
    enabled: request !== null,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
  })
}
