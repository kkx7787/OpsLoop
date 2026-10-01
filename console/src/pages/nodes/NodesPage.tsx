/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useEffect, useId, useLayoutEffect, useRef, useState, type RefObject } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useCtiBadges } from '@/api/cti'
import { useNodes, type NodeEntry } from '@/api/operations'
import { useRefreshAll } from '@/api/page-refresh'
import { isTargetsNotDeployed, SENSOR_IDS, SYSTEM_IDS, useTargets, type Target, type TargetId } from '@/api/targets'
import { usePermission } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { buttonClasses } from '@/components/atoms/button-styles'
import { deviceLogsHref, STATUS_OPEN_PARAM } from '@/components/molecules/device-format'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { PageRefresh } from '@/components/organisms/PageRefresh'
import { groupTargets, isLogDevice, latestKeys, SupportTargets } from '@/components/organisms/dashboard'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { freshnessPart, isPartFailed, type FreshnessPart } from '@/lib/freshness'

const RECEPTION = { normal: '정상', silent: '침묵', waiting: '대기', revoked: '폐기' } as const
/** '상태' 열 머리 ⓘ 의 판정 기준 · 해석. 지표 오래됨은 상태판 카드의 자원 지표 판정이다(app/targets.py METRICS_STALE) */
const STATE_NOTE = '정상: 10분 안에 수신 · 침묵: 등록 또는 마지막 수신 뒤 10분 넘게 없음 · 대기: 등록 전이거나 첫 수신 전 · 지표 오래됨: 마지막 자원 지표가 10분 넘음. 침묵은 새 로그가 적재되지 않았다는 뜻이며 서버 장애를 확정하지 않습니다.'
export function ReceptionBadge({ node }: { node: NodeEntry }) {
  return <Badge tone={node.reception === 'silent' ? 'warning' : node.reception === 'normal' ? 'success' : 'neutral'}>{RECEPTION[node.reception]}</Badge>
}

/** ?open 값: 관측 센서 · 관제 시스템의 고정 id 일 때만 그 줄을 펼친다(모르는 값 · 보호 대상 id 는 무시) */
function openTarget(value: string | null): TargetId | undefined {
  return value && ([...SENSOR_IDS, ...SYSTEM_IDS] as readonly string[]).includes(value) ? value : undefined
}

/**
 * 스크롤(#84). ?open 이 없으면 맨 위에서 연다(대시보드 맨 아래 링크로 와도 이전 화면의 스크롤 위치에 머물지 않는다).
 * ?open 이면 노드 조회와 상태판 조회가 모두 끝난 뒤(성공이든 실패든) 그 줄로 한 번 스크롤하고 줄 단추에 초점을 준다.
 * 표가 늦게 와도 표를 그린 뒤라 펼친 줄이 밀려나지 않는다. 주기 재조회로는 다시 하지 않고, open 이 바뀌면 다시 한다.
 * 줄을 찾은 뒤에만 한 것으로 친다: 상태판 첫 조회가 실패했다가 다시 받으면(received 가 바뀐다. 다시 시도 단추가 사라져 초점을 잃는다)
 * 그때 한 번 한다
 */
function useStatusScroll(root: RefObject<HTMLElement | null>, open: TargetId | undefined, settled: boolean, received: boolean) {
  const done = useRef<TargetId | null>(null)
  useLayoutEffect(() => {
    if (!open) (document.scrollingElement ?? document.documentElement).scrollTop = 0
  }, [open])
  useEffect(() => {
    if (!open) {
      done.current = null
      return
    }
    if (!settled || done.current === open) return
    const row = root.current?.querySelector<HTMLElement>(`[data-target-summary="${open}"]`)
    if (!row) return
    done.current = open
    row.scrollIntoView?.({ block: 'start' })
    row.querySelector<HTMLButtonElement>('button')?.focus({ preventScroll: true })
  }, [root, open, settled, received])
}

/**
 * 수집 · 관제 상태(S-08 · #84, 주소는 /nodes 그대로). 수집(노드 에이전트 · 허니팟 업로더) → 적재 · 탐지(데이터 노드) → 집행(집행기 보고)
 * 가운데 어디가 멈췄는지 본다. 세 구역: 등록 노드(수 네 칸 + 표) → 관측 센서 | 관제 시스템(접힌 줄, 넓으면 나란히).
 * 노드 표와 상태판은 따로 조회하고 기준 시각은 제목 줄 하나다(#79): 한쪽이 실패하면 '일부 갱신 실패', 그 구역에 '이전 결과'.
 * 상단바 새로고침은 숨는다(PageRefresh). 공통 띠는 실시간 끊김만 남는다(조회 실패를 띠로 되풀이하지 않는다).
 * 보호 대상 노드 행에는 최근 로그 링크(상태판의 보호 대상 카드가 있는 노드만, 서버 node_logs 와 같은 기준), 상태 칸에는 그 카드의 지표 오래됨.
 * 관제 이상 띠 항목은 ?open=<id> 로 그 줄을 펼쳐 잇는다. 노드 추가 · 재발급 동선은 그대로다.
 */
export function NodesPage() {
  const query = useNodes(), targets = useTargets(), permission = usePermission('node.token')
  const { refresh, refreshing } = useRefreshAll()
  const [params] = useSearchParams()
  const open = openTarget(params.get(STATUS_OPEN_PARAM))
  const [search,setSearch] = useState(''), [page,setPage] = useState(1), [pageSize,setPageSize] = useState(25)
  const rows = query.data?.rows ?? []
  const filtered = rows.filter(r => `${r.node_id} ${r.hostname ?? ''} ${r.addr ?? ''}`.toLowerCase().includes(search.toLowerCase()))
  const currentPage = Math.min(page,Math.max(1,Math.ceil(filtered.length/pageSize)))
  const stateNote = useId(), nodesTitleId = useId()
  const root = useRef<HTMLDivElement>(null)
  const groups = groupTargets(targets.data?.targets ?? [])
  // 보호 대상 카드(node_id 로 맞춘다). 상태판을 받지 못했으면 비어 있어 링크 · 지표 배지를 추측하지 않는다
  const cards = new Map<string, Target>(groups.protected.map(t => [t.id, t]))
  const badges = useCtiBadges(latestKeys([...groups.sensors, ...groups.system])).data?.badges
  const nodesStale = !!query.data && isPartFailed(freshnessPart(query))
  const targetsStale = !!targets.data && isPartFailed(freshnessPart(targets))
  const parts: FreshnessPart[] = [
    freshnessPart(query, query.data?.as_of),
    // 상태판 API 가 없는 이전 서버(404)는 갱신 실패가 아니다(구역이 배포 전으로 알린다)
    ...(isTargetsNotDeployed(targets.error) && !targets.data ? [] : [freshnessPart(targets, targets.data?.as_of)]),
  ]
  useStatusScroll(root, open, !query.isPending && !targets.isPending, !!targets.data)
  return <div ref={root} className="flex min-w-0 flex-col gap-4">
    <PageHeader title="수집 · 관제 상태" description="수집 · 탐지 · 집행 가운데 어디가 멈췄는지 확인합니다." status={<PageRefresh parts={parts} announce />} aside={<><Link className={buttonClasses({})} to="/inventory">자산 · 취약점</Link>{permission.allowed && <Link className={buttonClasses({variant:'primary'})} to="/nodes/new">노드 추가</Link>}</>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={null} onRetry={() => void refresh()} busy={refreshing} />
    <section aria-labelledby={nodesTitleId} className="flex min-w-0 flex-col gap-2" data-status-section="nodes">
      <h2 id={nodesTitleId} className="m-0 text-sm font-semibold tracking-heading">등록 노드</h2>
      {query.isPending ? <LoadingState /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} titleAs="h3" title="등록 노드를 불러오지 못했습니다" /> : <>
        <Card className="grid grid-cols-2 gap-4 sm:grid-cols-4">{Object.entries(RECEPTION).map(([state,label]) => <div key={state}><div className="text-xs text-ink-muted">{label}</div><div className="mt-1 text-xl font-semibold tabular-nums">{rows.filter(r => r.reception===state).length}개</div></div>)}</Card>
        <Card padding="none" className="min-w-0"><CardHeader titleAs="h3" title={`등록 노드 ${rows.length}개`} aside={<>{nodesStale && <Badge tone="warning" data-stale-badge="">이전 결과</Badge>}<Input aria-label="노드 검색" placeholder="노드 · 호스트 · 주소 검색" fieldSize="sm" value={search} onChange={e=>{setSearch(e.target.value);setPage(1)}} /></>} />
          <InfoTip label="상태" id={stateNote} render={({ button, panel }) => <>{panel}
          <div className="overflow-x-auto" role="region" aria-label="등록 노드 표" tabIndex={0}><table className="w-full text-left text-sm"><thead className="border-b border-line text-xs text-ink-muted"><tr>{['노드 · 호스트','주소','수집 항목','등록 시각 (KST)','마지막 수신 (KST)','상태',...(permission.allowed?['등록 토큰']:[])].map(t => t === '상태'
            ? <th key={t} className="px-4 py-2 whitespace-nowrap" aria-describedby={stateNote}>상태 {button}</th>
            : <th key={t} className="px-4 py-2 whitespace-nowrap">{t}</th>)}</tr></thead><tbody className="divide-y divide-line">{filtered.slice((currentPage-1)*pageSize,currentPage*pageSize).map(n => {
            const card = cards.get(n.node_id)
            return <tr key={n.node_id}>
              <td className="px-4 py-3"><div className="font-mono font-semibold">{n.node_id}</div><div className="text-xs text-ink-muted">{n.hostname || '미기록'}{card && isLogDevice(card) && <>{' · '}<Link to={deviceLogsHref(n.node_id)} aria-label={`${n.node_id} 최근 로그`} className="whitespace-nowrap" data-node-logs="">최근 로그 →</Link></>}</div></td>
              <td className="px-4 py-3 font-mono">{n.addr || '미기록'}</td><td className="px-4 py-3 text-xs">{n.logs.join(' · ') || '미기록'}</td>
              <td className="px-4 py-3 text-xs whitespace-nowrap"><Time value={n.registered_at} format="short" /></td><td className="px-4 py-3 text-xs whitespace-nowrap"><Time value={n.last_seen_at} format="short" /></td>
              <td className="px-4 py-3"><span className="flex flex-wrap items-center gap-1"><ReceptionBadge node={n} />{card?.system.state === 'stale' && <Badge tone="warning" className="whitespace-nowrap" data-metrics-stale="">지표 오래됨</Badge>}</span></td>{permission.allowed && <td className="px-4 py-3 text-xs whitespace-nowrap"><Link to={`/nodes/new?node=${encodeURIComponent(n.node_id)}`}>재발급</Link>{n.enrollment_expires_at && <div className="mt-1 text-ink-muted">유효 토큰 있음</div>}</td>}
            </tr>
          })}</tbody></table></div></>}>{STATE_NOTE}</InfoTip>
          {!filtered.length && <p className="p-4 text-sm text-ink-muted">{search ? '검색 조건에 맞는 노드가 없습니다.' : '등록된 노드가 없습니다.'}</p>}
          <IncidentPagination label="등록 노드 페이지" page={currentPage} pageSize={pageSize} total={filtered.length} busy={query.isPending} onPage={setPage} onPageSize={n=>{setPageSize(n);setPage(1)}} />
        </Card>
      </>}
    </section>
    <SupportTargets
      key={open ?? ''}
      data={targets.data}
      pending={targets.isPending}
      fetching={targets.isFetching}
      error={targets.error}
      onRetry={() => void targets.refetch()}
      updatedAt={targets.dataUpdatedAt}
      badges={badges}
      stale={targetsStale}
      open={open}
    />
  </div>
}
