import type { Incident, IncidentFilters, IncidentSort, IncidentRule } from '@/api/incidents'
import { isSeverity } from '@/lib/domain'
import { isIncidentStatus } from './model'

/**
 * 목록 조건과 URL 검색 매개변수의 짝. 새로고침 · 공유해도 같은 목록이 보이도록 조건은 주소에 둔다.
 *   /incidents?status=open&severity=critical&rule_id=R003&judged=false&sort=recent
 * 모르는 값은 버린다(주소를 손으로 고쳐도 화면이 깨지지 않는다). 기본 정렬(pending)은 붙이지 않는다.
 */

export const SORTS = ['pending', 'severity', 'recent'] as const satisfies readonly IncidentSort[]

/** 기본 정렬은 미판정 오래된 순. 심각도순이 아니다(화면 설계 4장). */
export const DEFAULT_SORT: IncidentSort = 'pending'

export const SORT_LABEL: Record<IncidentSort, string> = {
  pending: '미판정 우선',
  severity: '심각도순',
  recent: '최신순',
}

export function isSort(value: unknown): value is IncidentSort {
  return typeof value === 'string' && (SORTS as readonly string[]).includes(value)
}

/** 이 화면이 주소에 두는 칸. 이 순서로 붙인다. */
export const FILTER_PARAMS = ['status', 'severity', 'rule_id', 'judged', 'sort'] as const

export type ListFilters = Pick<IncidentFilters, (typeof FILTER_PARAMS)[number]>

/** 주소 → 조건. 모르는 값 · 빈 값은 뺀다. */
export function filtersFromSearch(params: URLSearchParams): ListFilters {
  const out: ListFilters = {}
  const status = params.get('status')
  if (isIncidentStatus(status)) out.status = status
  const severity = params.get('severity')
  if (isSeverity(severity)) out.severity = severity
  const ruleId = params.get('rule_id')?.trim()
  if (ruleId) out.rule_id = ruleId
  const judged = params.get('judged')
  if (judged === 'true') out.judged = true
  else if (judged === 'false') out.judged = false
  const sort = params.get('sort')
  if (isSort(sort) && sort !== DEFAULT_SORT) out.sort = sort
  return out
}

/** 조건 → 주소. base 의 다른 칸은 그대로 두고 조건 칸만 다시 쓴다. */
export function searchFromFilters(filters: ListFilters, base?: URLSearchParams): URLSearchParams {
  const params = new URLSearchParams(base)
  for (const key of FILTER_PARAMS) params.delete(key)
  if (filters.status) params.set('status', filters.status)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.rule_id) params.set('rule_id', filters.rule_id)
  if (filters.judged !== undefined) params.set('judged', String(filters.judged))
  if (filters.sort && filters.sort !== DEFAULT_SORT) params.set('sort', filters.sort)
  return params
}

/** 적용 중인 조건 수. 정렬은 조건이 아니다. */
export function countFilters(filters: ListFilters): number {
  let n = 0
  if (filters.status) n++
  if (filters.severity) n++
  if (filters.rule_id) n++
  if (filters.judged !== undefined) n++
  return n
}

/** 조건은 비우고 정렬만 남긴다. */
export function clearFilters(filters: ListFilters): ListFilters {
  return filters.sort ? { sort: filters.sort } : {}
}

/** 규칙 선택지 한 줄 */
export interface RuleOption {
  id: string
  /** 목록에서 본 규칙 이름. 품질 목록에는 이름이 없다 */
  name?: string
}

/**
 * 목록 API의 전체 규칙 선택지에 지금 목록에서 본 규칙과 이름을 합친다.
 * 이전 서버가 선택지를 보내지 않아도 목록에 보이는 규칙은 고를 수 있다.
 */
export function ruleOptionsOf(rules: readonly IncidentRule[] | undefined, items: readonly Incident[] | undefined): RuleOption[] {
  const names = new Map<string, string>()
  for (const rule of rules ?? []) if (rule.rule_name) names.set(rule.rule_id, rule.rule_name)
  for (const item of items ?? []) if (!names.has(item.rule_id)) names.set(item.rule_id, item.rule_name)
  const ids = new Set<string>()
  for (const row of rules ?? []) ids.add(row.rule_id)
  for (const id of names.keys()) ids.add(id)
  return [...ids].sort().map((id) => ({ id, name: names.get(id) }))
}
