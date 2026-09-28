/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useState, type FormEvent } from 'react'
import { useAudit, type AuditFilters } from '@/api/operations'
import { useMe } from '@/auth/useMe'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { readInterval } from '@/lib/interval'
import { revealHidden } from '@/lib/untrusted'

const EVENTS: Record<string, string> = {
  'console.block.released': '차단 해제',
  'console.block.extended': '차단 연장',
  'console.block.shortened': '차단 만료 단축',
  'console.block.created': '차단 요청',
  'console.block.rearmed': '차단 재요청',
  'console.block.enforced': '관문 집행 확인',
  'console.block.unenforced': '관문 집행 해제',
  'console.block.expired': '차단 만료',
  'console.node.token.issued': '등록 토큰 발급',
  'console.node.token.canceled': '등록 토큰 취소',
  'console.notify.channel.created': '알림 채널 추가',
  'console.notify.channel.changed': '알림 채널 변경',
  // 계정 변경(#59). 화면 · 명령줄의 변경을 DB 트리거가 남긴다. 비밀번호는 바뀐 사실만
  'console.account.created': '계정 추가',
  'console.account.role.changed': '계정 역할 변경',
  'console.account.disabled': '계정 비활성',
  'console.account.enabled': '계정 재활성',
  'console.account.password.changed': '계정 비밀번호 변경',
  'console.account.deleted': '계정 삭제',
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
  return <div className="worklist-page flex min-w-0 flex-col gap-3">
    <PageHeader title="감사 기록" description="차단 변경, 노드 등록 토큰의 발급·취소, 알림 채널의 추가·변경, 계정의 추가·역할·활성·비밀번호 변경 이력을 확인합니다." />
    {me.isPending ? <LoadingState /> : !allowed ? <ForbiddenState title="이 화면은 admin 만 볼 수 있습니다" requiredRoles="admin" currentRole={me.data?.role} /> : <>
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      <Card><form className="grid gap-3 sm:flex sm:flex-wrap sm:items-end" onSubmit={submit}>
        <label htmlFor="audit-field-0" className="grid gap-1 text-xs">행위자<Input id="audit-field-0" value={actor} maxLength={128} placeholder="계정 이름" onChange={e => setActor(e.target.value)} /></label>
        <label htmlFor="audit-field-1" className="grid gap-1 text-xs">대상<Input id="audit-field-1" value={target} maxLength={128} placeholder="노드 · IP · 채널 · 계정 이름" onChange={e => setTarget(e.target.value)} /></label>
        <label htmlFor="audit-field-2" className="grid gap-1 text-xs">시작 (KST)<Input id="audit-field-2" type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
        <label htmlFor="audit-field-3" className="grid gap-1 text-xs">종료 (KST)<Input id="audit-field-3" type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
        <div className="flex gap-2"><Button type="submit" variant="primary">조회</Button><Button onClick={reset}>초기화</Button></div>
      </form></Card>
      {error && <Banner tone="danger" title={error} />}
      {query.isPending ? <LoadingState /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} /> : <Card padding="none" className="worklist-panel flex min-w-0 flex-col overflow-hidden">
        <CardHeader title="변경 이력" aside={`${query.data.total.toLocaleString()}건`} />
        <div key={JSON.stringify(filters)} className="worklist-scroll overflow-auto" role="region" aria-label="감사 기록 표" tabIndex={0}><table className="responsive-table w-full text-left text-sm">
          <thead className="sticky top-0 bg-surface border-b border-line text-xs text-ink-muted"><tr>{['시각 (KST)','행위자','종류','대상','기록'].map(t => <th key={t} className={cell}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{query.data.rows.map((r,i) => <tr key={`${r.ts}:${r.eventid}:${i}`}>
            <td className={`${cell} whitespace-nowrap`}><Time value={r.ts} /></td><td data-label="행위자" className={cell}><UntrustedText value={r.actor} max={64} fallback="미기록" /></td>
            <td data-label="종류" className={`${cell} whitespace-nowrap`}>{EVENTS[r.eventid] ?? <UntrustedText value={r.eventid} max={64} />}</td><td data-label="대상" className={`${cell} max-w-60 font-mono break-all`}><UntrustedText value={r.target} fallback="—" /></td>
            <td data-label="기록" className={`${cell} max-w-md`}><details><summary aria-label={`${r.target ? revealHidden(r.target) : '대상 미기록'} 감사 상세 보기`} className="cursor-pointer text-ink-muted">상세 보기</summary><p className="break-all font-mono text-xs leading-5"><UntrustedText value={r.detail} fallback="내용 미기록" /></p><p className="text-xs text-ink-muted">이벤트 <UntrustedText value={r.eventid} max={64} /><br />DB 연결 주소 <UntrustedText value={r.db_client} max={64} fallback="미기록" /></p></details></td>
          </tr>)}</tbody>
        </table></div>
        {!query.data.rows.length && <p className="p-4 text-sm text-ink-muted">조건에 맞는 감사 기록이 없습니다.</p>}
        <IncidentPagination label="감사 기록 페이지" page={Math.floor(filters.offset/filters.limit)+1} pageSize={filters.limit} total={query.data.total} busy={query.isFetching} onPage={page => setFilters({ ...filters, offset: (page-1)*filters.limit })} onPageSize={limit => setFilters({ ...filters, limit, offset: 0 })} />
        <p className="m-0 border-t border-line px-4 py-3 text-xs text-ink-muted">추가된 기록은 이 화면에서 수정·삭제할 수 없습니다. 판정·조치 이력은 각 인시던트 상세에서 확인합니다.</p>
      </Card>}
    </>}
  </div>
}
