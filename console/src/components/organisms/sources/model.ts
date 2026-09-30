import {
  DEFAULT_SOURCE_SORT,
  isAddressPrefix,
  isFingerprintKind,
  isFingerprintValue,
  isSourceSort,
  SOURCES_MAX_OFFSET,
  type BlockCheckers,
  type FingerprintKind,
  type SourceDetail,
  type SourceSort,
} from '@/api/sources'
import type { ActorBlock } from '@/api/incidents'
import { pointRows, type PointRow } from '../incident-detail/format'

/**
 * 출발지 분석 화면(S-09)의 조각들이 같이 쓰는 값: 주소창 조건 · 경로 · 대상 이름 · 집행 지점 결과.
 * 조건은 주소에 둔다(새로고침 · 공유해도 같은 목록). 모르는 값은 버린다.
 *   /sources?q=203.0.113.&sort=severity&include_test=true&fp_kind=hassh&fp=<값>&page=2&page_size=50
 *   /sources?tab=fingerprints&kind=user_agent
 */

export type SourcesTab = 'sources' | 'fingerprints'

export function tabFromSearch(params: URLSearchParams): SourcesTab {
  return params.get('tab') === 'fingerprints' ? 'fingerprints' : 'sources'
}

/** 출발지 탭의 조건. 정렬 · 시험 대역 포함은 조건이 아니라 보기 방식이라 초기화해도 남긴다 */
export interface SourceConditions {
  q?: string
  sort?: SourceSort
  include_test?: boolean
  /** 도구 지문 조건. 종류와 값이 함께 있을 때만 */
  fp?: { kind: FingerprintKind; value: string }
}

/** 이 탭이 주소에 두는 칸 */
export const CONDITION_PARAMS = ['q', 'sort', 'include_test', 'fp_kind', 'fp'] as const

/** 주소 → 조건. 형식이 틀린 주소 앞부분 · 한쪽만 있거나 보낼 수 없는(NUL · 512자 초과) 지문 조건은 뺀다(서버가 422 를 주지 않게) */
export function conditionsFromSearch(params: URLSearchParams): SourceConditions {
  const out: SourceConditions = {}
  const q = params.get('q')?.trim()
  if (q && isAddressPrefix(q)) out.q = q
  const sort = params.get('sort')
  if (isSourceSort(sort) && sort !== DEFAULT_SOURCE_SORT) out.sort = sort
  if (params.get('include_test') === 'true') out.include_test = true
  const kind = params.get('fp_kind')
  const value = params.get('fp')
  if (isFingerprintKind(kind) && value && isFingerprintValue(value)) out.fp = { kind, value }
  return out
}

/** 조건 → 주소. base 의 다른 칸(탭 · 쪽)은 그대로 두고 조건 칸만 다시 쓴다 */
export function searchFromConditions(conditions: SourceConditions, base?: URLSearchParams): URLSearchParams {
  const params = new URLSearchParams(base)
  for (const key of CONDITION_PARAMS) params.delete(key)
  if (conditions.q) params.set('q', conditions.q)
  if (conditions.sort && conditions.sort !== DEFAULT_SOURCE_SORT) params.set('sort', conditions.sort)
  if (conditions.include_test) params.set('include_test', 'true')
  if (conditions.fp) {
    params.set('fp_kind', conditions.fp.kind)
    params.set('fp', conditions.fp.value)
  }
  return params
}

/** 좁히는 조건 수(주소 앞부분 · 지문). 정렬 · 시험 대역 포함은 세지 않는다 */
export function countConditions(conditions: SourceConditions): number {
  return (conditions.q ? 1 : 0) + (conditions.fp ? 1 : 0)
}

/** 지문 탭에서 고른 종류. 기본 HASSH */
export function kindFromSearch(params: URLSearchParams): FingerprintKind {
  const kind = params.get('kind')
  return isFingerprintKind(kind) ? kind : 'hassh'
}

/** 출발지 상세. IPv6 의 ':' 때문에 경로가 아니라 쿼리에 둔다 */
export function sourceHref(ip: string): string {
  return `/sources/detail?${new URLSearchParams({ ip })}`
}

/**
 * 이 지문을 쓴 출발지 가운데 사건 있는 출발지 목록(출발지 탭 · 지문 조건). 목록은 사건 있는 출발지만 보이므로
 * 도착 목록의 수는 지문 표의 '출발지' 칸이 아니라 '사건 있는 출발지' 칸과 같다. 그 칸이 시험 대역도 세므로 목록도 시험 대역을 넣어 수를 맞춘다
 */
export function fingerprintHref(kind: FingerprintKind, value: string): string {
  return `/sources?${searchFromConditions({ include_test: true, fp: { kind, value } })}`
}

/**
 * 요청할 쪽. 주소창 쪽 번호는 1,000,000 까지 받지만(pagination.ts) offset 이 서버 상한(SOURCES_MAX_OFFSET)을 넘으면 422 라
 * offset 이 상한 안에 드는 쪽까지만 자른다. 그 쪽은 비어 있어 범위 밖 되돌리기(usePaging)가 유효한 마지막 쪽으로 옮긴다
 */
export function requestPage(page: number, pageSize: number): number {
  return Math.min(page, Math.floor(SOURCES_MAX_OFFSET / pageSize) + 1)
}

/**
 * 상세 머리 · 차단 상태 구역의 금지 대역 판단. 사건 없는 출발지(summary null)는 서버가 따로 낸 exempt_flag 를 쓴다
 * (목록과 같은 판단). 표를 읽을 수 없으면 null 이라 '확인 불가'로 보인다
 */
export function sourceExempt(detail: Pick<SourceDetail, 'summary' | 'exempt_flag'>): boolean | null {
  return detail.summary ? detail.summary.exempt : detail.exempt_flag
}

/** 이 출발지의 사건 목록(S-03 의 actor_ip 조건) */
export function incidentsOfHref(ip: string): string {
  return `/incidents?${new URLSearchParams({ actor_ip: ip })}`
}

/** 고정 관제 대상 이름(app/targets.py TARGETS 와 같다). 모르는 값(등록 노드의 node_id 등, #64)은 원문을 비신뢰 문자열로 그린다 */
export const TARGET_LABEL: Record<string, string> = {
  'aws-sensor': 'AWS 센서',
  'web-01': 'web-01',
  console: '관제 콘솔',
  'data-node': '데이터 노드',
}

export function targetLabel(id: string): string | null {
  return Object.hasOwn(TARGET_LABEL, id) ? TARGET_LABEL[id] : null
}

/**
 * 집행기 확인이 멈춘 지점의 '적용 확인'을 바꾸는 까닭(targets.py response_block 과 같은 판단).
 * 판단 근거라 '확인 지연' 배지 옆 도움말(ⓘ · EnforcePointList)로 보인다. 멈춘 사실은 멈춤 띠(CheckerStaleBanner)가 본문에 적는다.
 * AWS 관문 · 내부 방화벽 두 지점이 같이 쓰므로 지점 이름을 넣지 않는다
 */
export const CHECKER_STALE_NOTE = '집행기 확인이 10분 넘게 멈춰 마지막 적용 확인을 믿지 않습니다. 그사이 이 지점이 규칙을 잃어도 드러나지 않습니다.'

/**
 * 차단 행의 지점 칸(format.pointRows)에 집행기 확인 상태를 더한다. 집행기가 멈춘 지점의 '적용 확인'은 '확인 지연'으로 보인다
 * (관문이 그 사이 규칙을 잃었어도 아무도 알리지 않는다). 확인 상태를 모르면(null) 지점 결과를 그대로 둔다.
 * 미요청 · 빠짐 줄은 결과가 아니라 요청 · 목록 사실이라 멈춤으로 덮지 않는다(이슈 #77). now 는 만료를 가르는 기준 시각
 */
export function checkedPoints(block: ActorBlock | null | undefined, checkers: BlockCheckers | undefined, now: number = Date.now()): PointRow[] {
  return pointRows(block, now).map((row) => {
    const stale = row.key === 'gateway' ? checkers?.gateway_stale : checkers?.fw_stale
    if (stale !== true || row.point.state !== 'confirmed') return row
    return { ...row, point: { ...row.point, state: 'stale', note: CHECKER_STALE_NOTE }, noteTip: true }
  })
}

/** 생존 신호 표를 읽을 수 없어(null) 멈춤을 가릴 수 없을 때의 안내(집행 미확인 경고라 본문에 둔다). 목록 · 상세가 같이 쓴다 */
export const CHECKER_UNKNOWN_NOTE = '집행기 확인 기록을 읽을 수 없음 · 지점 결과는 보고된 그대로'

/** 같은 지문 주의. 본문에는 지문 조건 띠(출발지 탭) 한 곳에만 두고, 지문 탭 · 상세는 도움말(ⓘ)로 둔다 */
export const SAME_TOOL_NOTE = '같은 지문이 같은 행위자라는 뜻은 아닙니다'
/** 같은 지문 주의의 근거(도움말) */
export const SAME_TOOL_REASON = '흔한 라이브러리 · 도구(Go · paramiko · curl 등)는 지문이 겹칩니다. 묶음은 조사 참고용이고 판정은 사건마다 합니다.'

/** 집행기 확인 상태를 모르는 지점이 있는가(표 권한 없음 · 마이그레이션 전) */
export function checkersUnknown(checkers: BlockCheckers | undefined): boolean {
  return checkers?.gateway_stale === null || checkers?.fw_stale === null
}

/** 집행기 확인이 멈춘 지점 이름들(띠 문구). 없으면 빈 배열 */
export function staleCheckers(checkers: BlockCheckers | undefined): string[] {
  const out: string[] = []
  if (checkers?.gateway_stale) out.push('AWS 관문')
  if (checkers?.fw_stale) out.push('내부 방화벽')
  return out
}
