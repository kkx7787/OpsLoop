/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useState } from 'react'
import { Link } from 'react-router'
import { useNodes, type NodeEntry } from '@/api/operations'
import { usePermission } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { buttonClasses } from '@/components/atoms/button-styles'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'

const RECEPTION = { normal: '정상', silent: '침묵', waiting: '대기', revoked: '폐기' } as const
export function ReceptionBadge({ node }: { node: NodeEntry }) {
  return <Badge tone={node.reception === 'silent' ? 'warning' : node.reception === 'normal' ? 'success' : 'neutral'}>{RECEPTION[node.reception]}</Badge>
}
export function NodesPage() {
  const query = useNodes(), permission = usePermission('node.token')
  const [search,setSearch] = useState(''), [page,setPage] = useState(1), [pageSize,setPageSize] = useState(25)
  const rows = query.data?.rows ?? []
  const filtered = rows.filter(r => `${r.node_id} ${r.hostname ?? ''} ${r.addr ?? ''}`.toLowerCase().includes(search.toLowerCase()))
  const currentPage = Math.min(page,Math.max(1,Math.ceil(filtered.length/pageSize)))
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="수집 노드" description="등록된 에이전트의 마지막 수신과 침묵 상태를 확인합니다." aside={<><Link className={buttonClasses({})} to="/inventory">자산 · 취약점</Link>{permission.allowed && <Link className={buttonClasses({variant:'primary'})} to="/nodes/new">노드 추가</Link>}</>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
    {query.isPending ? <LoadingState /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} /> : <>
      <Card className="grid grid-cols-2 gap-4 sm:grid-cols-4">{Object.entries(RECEPTION).map(([state,label]) => <div key={state}><div className="text-xs text-ink-muted">{label}</div><div className="mt-1 text-xl font-semibold tabular-nums">{rows.filter(r => r.reception===state).length}개</div></div>)}</Card>
      <Card padding="none" className="min-w-0"><CardHeader title={`등록 노드 ${rows.length}개`} aside={<Input aria-label="노드 검색" placeholder="노드 · 호스트 · 주소 검색" fieldSize="sm" value={search} onChange={e=>{setSearch(e.target.value);setPage(1)}} />} />
        <div className="overflow-x-auto" role="region" aria-label="수집 노드 표" tabIndex={0}><table className="w-full text-left text-sm"><thead className="border-b border-line text-xs text-ink-muted"><tr>{['노드 · 호스트','주소','수집 항목','등록 시각 (KST)','마지막 수신 (KST)','상태',...(permission.allowed?['등록 토큰']:[])].map(t => <th key={t} className="px-4 py-2 whitespace-nowrap">{t}</th>)}</tr></thead><tbody className="divide-y divide-line">{filtered.slice((currentPage-1)*pageSize,currentPage*pageSize).map(n => <tr key={n.node_id}>
          <td className="px-4 py-3"><div className="font-mono font-semibold">{n.node_id}</div><div className="text-xs text-ink-muted">{n.hostname || '미기록'}</div></td>
          <td className="px-4 py-3 font-mono">{n.addr || '미기록'}</td><td className="px-4 py-3 text-xs">{n.logs.join(' · ') || '미기록'}</td>
          <td className="px-4 py-3 text-xs whitespace-nowrap"><Time value={n.registered_at} format="short" /></td><td className="px-4 py-3 text-xs whitespace-nowrap"><Time value={n.last_seen_at} format="short" /></td>
          <td className="px-4 py-3"><ReceptionBadge node={n} /></td>{permission.allowed && <td className="px-4 py-3 text-xs whitespace-nowrap"><Link to={`/nodes/new?node=${encodeURIComponent(n.node_id)}`}>재발급</Link>{n.enrollment_expires_at && <div className="mt-1 text-ink-muted">유효 토큰 있음</div>}</td>}
        </tr>)}</tbody></table></div>
        {!filtered.length && <p className="p-4 text-sm text-ink-muted">{search ? '검색 조건에 맞는 노드가 없습니다.' : '등록된 노드가 없습니다.'}</p>}
        <IncidentPagination label="수집 노드 페이지" page={currentPage} pageSize={pageSize} total={filtered.length} busy={query.isPending} onPage={setPage} onPageSize={n=>{setPageSize(n);setPage(1)}} />
      </Card>
      <p className="m-0 text-xs leading-5 text-ink-muted">정상: 10분 이내 수신 · 침묵: 등록 또는 마지막 수신 이후 10분 초과 · 대기: 등록 전 또는 첫 수신 대기. 침묵은 새 로그가 적재되지 않았다는 뜻이며 서버 장애를 확정하지 않습니다.<br /><Time value={query.data.as_of} format="time" zone /> 기준 · 30초마다 재조회</p>
    </>}
  </div>
}
