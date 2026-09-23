/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useState, type FormEvent } from 'react'
import { useAudit, type AuditFilters } from '@/api/operations'
import { useMe } from '@/auth/useMe'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { Banner } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { readInterval } from '@/lib/interval'

const EVENTS: Record<string, string> = {
  'console.block.released': '차단 해제',
  'console.block.extended': '차단 연장',
  'console.block.shortened': '차단 만료 단축',
  'console.node.token.issued': '등록 토큰 발급',
  'console.node.token.canceled': '등록 토큰 취소',
}
const defaults: AuditFilters = { actor: '', target: '', limit: 25, offset: 0 }
const cell = 'px-4 py-3 align-top'

export function AuditPage() {
  const me = useMe()
  const [filters, setFilters] = useState<AuditFilters>(defaults)
  const [actor, setActor] = useState(''), [target, setTarget] = useState('')
  const [start, setStart] = useState(''), [end, setEnd] = useState(''), [error, setError] = useState('')
  const allowed = me.data?.role === 'admin'
  const query = useAudit(filters, allowed)
  function submit(event: FormEvent) {
    event.preventDefault()
    try { const period = readInterval(start, end); setFilters({ actor: actor.trim(), target: target.trim(), limit: filters.limit, ...period, offset: 0 }); setError('') }
    catch (e) { setError((e as Error).message) }
  }
  function reset() { setActor(''); setTarget(''); setStart(''); setEnd(''); setFilters(defaults); setError('') }
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="감사 기록" description="차단 변경과 노드 등록 토큰의 발급·취소 이력을 확인합니다." />
    {me.isPending ? <LoadingState /> : !allowed ? <ForbiddenState title="이 화면은 admin 만 볼 수 있습니다" requiredRoles="admin" currentRole={me.data?.role} /> : <>
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      <Card><form className="grid gap-3 sm:flex sm:flex-wrap sm:items-end" onSubmit={submit}>
        <label htmlFor="audit-field-0" className="grid gap-1 text-xs">행위자<Input id="audit-field-0" value={actor} maxLength={128} placeholder="계정 이름" onChange={e => setActor(e.target.value)} /></label>
        <label htmlFor="audit-field-1" className="grid gap-1 text-xs">대상<Input id="audit-field-1" value={target} maxLength={128} placeholder="노드 이름 또는 IP" onChange={e => setTarget(e.target.value)} /></label>
        <label htmlFor="audit-field-2" className="grid gap-1 text-xs">시작 (KST)<Input id="audit-field-2" type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
        <label htmlFor="audit-field-3" className="grid gap-1 text-xs">종료 (KST)<Input id="audit-field-3" type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
        <div className="flex gap-2"><Button type="submit" variant="primary">조회</Button><Button onClick={reset}>초기화</Button></div>
      </form></Card>
      {error && <Banner tone="danger" title={error} />}
      {query.isPending ? <LoadingState /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} /> : <Card padding="none" className="min-w-0">
        <CardHeader title="변경 이력" aside={`${query.data.total.toLocaleString()}건`} />
        <div className="overflow-x-auto" role="region" aria-label="감사 기록 표" tabIndex={0}><table className="w-full min-w-[720px] text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{['시각 (KST)','행위자','종류','대상','기록'].map(t => <th key={t} className={cell}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{query.data.rows.map((r,i) => <tr key={`${r.ts}:${r.eventid}:${i}`}>
            <td className={`${cell} whitespace-nowrap`}><Time value={r.ts} /></td><td className={cell}>{r.actor || '미기록'}</td>
            <td className={`${cell} whitespace-nowrap`}>{EVENTS[r.eventid] ?? r.eventid}</td><td className={`${cell} font-mono`}>{r.target || '—'}</td>
            <td className={`${cell} max-w-md`}><details><summary aria-label={`${r.target || "대상 미기록"} 감사 상세 보기`} className="cursor-pointer text-ink-muted">상세 보기</summary><p className="break-all font-mono text-xs leading-5">{r.detail || '내용 미기록'}</p><p className="text-xs text-ink-muted">이벤트 {r.eventid}<br />DB 연결 주소 {r.db_client || '미기록'}</p></details></td>
          </tr>)}</tbody>
        </table></div>
        {!query.data.rows.length && <p className="p-4 text-sm text-ink-muted">조건에 맞는 감사 기록이 없습니다.</p>}
        <IncidentPagination label="감사 기록 페이지" page={Math.floor(filters.offset/filters.limit)+1} pageSize={filters.limit} total={query.data.total} busy={query.isFetching} onPage={page => setFilters({ ...filters, offset: (page-1)*filters.limit })} onPageSize={limit => setFilters({ ...filters, limit, offset: 0 })} />
        <p className="m-0 border-t border-line px-4 py-3 text-xs text-ink-muted">추가된 기록은 이 화면에서 수정·삭제할 수 없습니다. 판정·조치 이력은 각 인시던트 상세에서 확인합니다.</p>
      </Card>}
    </>}
  </div>
}
