import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { ruleKeys, type RuleQuality } from './incidents'

export const nodeKey = ['nodes'] as const
export const auditKey = ['audit'] as const
export interface RuleDefinition { id: string; name: string; enabled: boolean; severity: string; rationale: string | null; change: string | null }
export interface RulesResult {
  as_of: string; since: string | null; until: string | null; rows: RuleQuality[]
  versions: Array<{ version: string; created_at: string; reason: string | null; rules: RuleDefinition[] }>
  runs: Array<{ id: number; rule_version: string; since: string | null; until: string | null; started_at: string; finished_at: string; incidents: number }>
}
export interface NodeEntry {
  node_id: string; hostname: string | null; addr: string | null; logs: string[]; status: string
  registered_at: string | null; last_seen_at: string | null; first_loaded_at: string | null
  last_loaded_at: string | null; reception: 'normal' | 'silent' | 'waiting' | 'revoked'
  enrollment_expires_at: string | null; checked_at: string
}
export interface NodesResult { as_of: string; rows: NodeEntry[] }
export interface Enrollment { id: number; node_id: string; token: string; issued_at: string; expires_at: string }
export interface EnrollmentInput { node_id: string; hostname: string; addr: string; logs: string[] }
export interface AuditEntry { ts: string; eventid: string; actor: string | null; target: string | null; db_client: string | null; detail: string | null }
export interface AuditFilters { actor: string; target: string; since?: string; until?: string; limit: number; offset: number }
export interface AuditResult { rows: AuditEntry[]; total: number; limit: number; offset: number }
const REFRESH = { staleTime: 10_000, refetchInterval: 30_000 } as const
export function useRulesResult(since?: string, until?: string) {
  return useQuery({ queryKey: [...ruleKeys.quality(), 'details', since, until], queryFn: ({ signal }) => api.get<RulesResult>('/api/rules/quality', { signal, query: { details: true, since, until } }), ...REFRESH })
}
export function useNodes() {
  return useQuery({ queryKey: nodeKey, queryFn: ({ signal }) => api.get<NodesResult>('/api/nodes', { signal }), ...REFRESH })
}
export function useAudit(filters: AuditFilters, enabled: boolean) {
  return useQuery({ queryKey: [...auditKey, filters], queryFn: ({ signal }) => api.get<AuditResult>('/api/audit', { signal, query: { ...filters } }), enabled, ...REFRESH })
}
/** 비밀값을 Query/Mutation 캐시에 보관하지 않는다. 발급 결과는 화면의 메모리에서만 다룬다. */
export function issueEnrollment(input: EnrollmentInput) { return api.post<Enrollment>('/api/nodes/enrollments', input) }
export function cancelEnrollment(nodeId: string, id: number) { return api.post(`/api/nodes/${encodeURIComponent(nodeId)}/enrollments/${id}/cancel`) }
