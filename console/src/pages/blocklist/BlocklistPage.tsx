import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useBlocklist, type BlockEntry } from '@/api/monitoring'
import { useActionMutation } from '@/api/incidents'
import { describeError } from '@/api/errors'
import { usePermission } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { blockState, isActiveBlock } from '@/components/organisms/incident-detail/format'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { useNow } from '@/lib/useNow'
import { cn } from '@/lib/cn'

type Tab = 'active' | 'expired' | 'released'
const TABS: Array<[Tab, string]> = [['active', '활성'], ['expired', '만료'], ['released', '해제']]
const COLUMNS = 'xl:grid-cols-[130px_minmax(160px,1fr)_120px_145px_95px_65px]'
type Notice = { tone: 'success' | 'danger'; message: string }

export function BlocklistPage() {
  const query = useBlocklist()
  const permission = usePermission('block.release')
  const clock = useNow(1_000)
  const [params, setParams] = useSearchParams()
  const tab: Tab = params.get('tab') === 'expired' ? 'expired' : params.get('tab') === 'released' ? 'released' : 'active'
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [notice, setNotice] = useState<Notice | null>(null)
  const rows = query.data ?? []
  // 브라우저 시계가 서버와 달라도 만료 판단은 서버 조회 시각부터 경과한 시간으로 계산한다.
  const checked = rows[0]?.checked_at ? Date.parse(rows[0].checked_at) : NaN
  const now = Number.isFinite(checked) ? checked + Math.max(0, clock - query.dataUpdatedAt) : clock
  const groups = { active: [] as BlockEntry[], expired: [] as BlockEntry[], released: [] as BlockEntry[] }
  for (const entry of rows) {
    const state = blockState(entry, now)
    groups[state === 'pending' || state === 'active' ? 'active' : state].push(entry)
  }
  const keyword = search.trim().toLowerCase()
  const filtered = groups[tab].filter(entry => `${entry.actor_ip} ${entry.reason ?? ''} ${entry.incident_key ?? ''}`.toLowerCase().includes(keyword))
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)))
  const shown = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize)
  const pending = groups.active.filter(entry => !entry.enforced_at).length

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="차단 목록" description="차단 요청과 집행 결과를 함께 확인합니다." aside={<span className="text-xs text-ink-muted">해제 권한: admin</span>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
    {notice && <Banner tone={notice.tone} title={notice.message} action={<Button size="sm" onClick={() => setNotice(null)}>닫기</Button>} />}
    {query.isPending ? <LoadingState title="차단 목록을 불러오는 중입니다" /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : <>
      <Card padding="none" className="grid grid-cols-2 divide-x divide-line md:grid-cols-4">
        <Count label="활성 요청" value={groups.active.length} /><Count label="집행 확인" value={groups.active.length - pending} /><Count label="집행 대기" value={pending} warning /><Count label="24시간 내 만료" value={groups.active.filter(entry => entry.expires_at && Date.parse(entry.expires_at) <= now + 86_400_000).length} />
      </Card>
      <Card padding="none" className="min-w-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2">
          <div role="group" aria-label="차단 상태" className="flex gap-5">{TABS.map(([value, label]) => <button key={value} type="button" aria-pressed={tab === value} className={cn('min-h-9 cursor-pointer border-b-2 px-0.5 text-sm', tab === value ? 'border-primary font-semibold text-primary' : 'border-transparent text-ink-muted')} onClick={() => { const next = new URLSearchParams(params); next.set('tab', value); setParams(next); setPage(1) }}>{label} <span className="tabular-nums">{groups[value].length}</span></button>)}</div>
          <Input aria-label="차단 검색" placeholder="출발지 · 사유 · 사건 검색" className="max-w-[260px]" value={search} onChange={event => { setSearch(event.target.value); setPage(1) }} />
        </div>
        <div className={cn('hidden gap-3 border-b border-line bg-canvas/60 px-4 py-2 text-xs text-ink-muted xl:grid', COLUMNS)} aria-hidden="true">{['출발지', '사유 · 근거 사건', '집행 결과', '만료 시각 (KST)', '요청자', '조치'].map(label => <span key={label}>{label}</span>)}</div>
        <ul className="m-0 list-none divide-y divide-line p-0">{shown.map(entry => <BlockRow key={`${entry.actor_ip}:${entry.created_at}`} entry={entry} now={now} allowed={permission.allowed} stale={query.isError} onNotice={setNotice} refresh={() => void query.refetch()} />)}</ul>
        {!shown.length && <p className="m-0 px-4 py-10 text-center text-ink-muted">{search ? '검색 조건에 맞는 차단이 없습니다.' : `${TABS.find(([value]) => value === tab)?.[1]} 항목이 없습니다.`}</p>}
        <IncidentPagination label="차단 목록 페이지" page={currentPage} pageSize={pageSize} total={filtered.length} busy={query.isPending} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1) }} />
      </Card>
      <p className="m-0 text-xs text-ink-muted">활성은 만료·해제 전 요청입니다. 집행 확인 여부는 별도로 표시합니다. {query.dataUpdatedAt > 0 && <>마지막 조회 <Time value={query.dataUpdatedAt} format="time" zone /> · </>}30초마다 재조회</p>
    </>}
  </div>
}

function Count({ label, value, warning }: { label: string; value: number; warning?: boolean }) {
  return <div className="px-4 py-4"><div className="text-xs text-ink-muted">{label}</div><div className={cn('mt-1.5 text-xl font-semibold tabular-nums', warning && value > 0 && 'text-warning')}>{value.toLocaleString()}건</div></div>
}

/** 같은 페이로드 흡수 차단 행(규칙 v3). 근거 사건은 첫 사건이고 행의 출발지는 흡수 출발지다(서버 absorbed_reason_tag) */
function isAbsorbedBlock(entry: Pick<BlockEntry, 'reason'>): boolean {
  return entry.reason?.startsWith('흡수: ') ?? false
}

function BlockRow({ entry, now, allowed, stale, onNotice, refresh }: { entry: BlockEntry; now: number; allowed: boolean; stale: boolean; onNotice: (notice: Notice) => void; refresh: () => void }) {
  const mutation = useActionMutation(entry.incident_key ?? '')
  const [confirming, setConfirming] = useState(false)
  const [note, setNote] = useState('')
  const live = isActiveBlock(entry, now)
  const absorbed = isAbsorbedBlock(entry)
  const canRelease = allowed && live && !!entry.incident_key && !stale
  const label = entry.released_at ? '해제됨' : !live ? '만료됨' : entry.enforced_at ? '집행 확인' : '집행 대기'
  // 풀 행의 출발지를 함께 보낸다. 흡수 차단 행은 근거 사건(첫 사건)의 출발지와 이 행의 출발지가 달라,
  // 사건 키만 보내면 서버가 첫 사건 출발지의 차단을 푼다. 서버는 이 행이 그 사건의 흡수 차단일 때만 이 행 하나를 푼다
  function release(event: FormEvent) {
    event.preventDefault()
    if (!canRelease) return
    mutation.mutate({ action: 'unblock_ip', actor_ip: entry.actor_ip, ...(note.trim() ? { note: note.trim() } : {}) }, {
      onSuccess: () => { setConfirming(false); onNotice({ tone: 'success', message: `${entry.actor_ip} 차단 해제를 기록했습니다` }) },
      onError: error => { onNotice({ tone: 'danger', message: describeError(error) }); refresh() },
    })
  }
  return <li className={cn('grid min-w-0 grid-cols-2 items-start gap-3 px-4 py-3 text-sm', COLUMNS)}>
    <div className="col-span-2 font-mono font-semibold break-all xl:col-span-1">{entry.actor_ip}</div>
    <div className="col-span-2 min-w-0 xl:col-span-1"><div className="break-words"><UntrustedText value={entry.reason} fallback="사유 미기록" /></div><div className="mt-1 text-xs">{entry.incident_key ? <Link className="break-all" to={`/incidents/${encodeURIComponent(entry.incident_key)}`}>{entry.incident_key.split('|')[0]} · {absorbed ? '첫 사건 보기' : '사건 보기'}</Link> : <span className="text-ink-muted">근거 사건 없음</span>}</div></div>
    <div><Badge tone={live && !entry.enforced_at ? 'warning' : 'neutral'}>{label}</Badge><div className="mt-1 break-all text-xs text-ink-muted"><UntrustedText value={entry.method} fallback="집행 정보 없음" /></div>{entry.enforce_note && <p className="m-0 mt-1 break-words text-xs text-ink-muted"><UntrustedText value={entry.enforce_note} /></p>}</div>
    <div className="text-xs"><span className="block text-ink-muted xl:hidden">만료 시각 (KST)</span>{entry.expires_at ? <Time value={entry.expires_at} format="short" /> : '만료 없음'}{entry.released_at && <div className="mt-1 text-ink-muted">해제 <Time value={entry.released_at} format="short" />{entry.released_by && <> · <UntrustedText value={entry.released_by} max={64} /></>}</div>}</div>
    <div className="break-words text-xs text-ink-muted"><span className="xl:hidden">요청자 </span><UntrustedText value={entry.requested_by} max={64} fallback="미기록" /></div>
    <div className="justify-self-end xl:justify-self-start">{allowed && live ? <Button size="sm" disabled={!canRelease || mutation.isPending} disabledReason={stale ? '최신 목록을 확인한 뒤 해제해 주세요' : '연결된 근거 사건이 없어 해제할 수 없습니다'} onClick={() => setConfirming(!confirming)} aria-expanded={confirming}>해제</Button> : <span className="text-xs text-ink-muted">{live ? 'admin만' : '—'}</span>}</div>
    {confirming && live && <form className="col-span-2 flex flex-col gap-2 rounded-panel border border-line bg-canvas p-3 xl:col-span-6" aria-label={`${entry.actor_ip} 해제 확인`} onSubmit={release}>
      <p className="m-0 text-sm">{absorbed
        ? `${entry.actor_ip} 의 흡수 차단 한 곳만 해제할까요? 첫 사건 출발지의 차단과 다른 흡수 차단은 그대로 두고, 이 출발지는 이후 후속 차단에서도 빠집니다. 요청은 첫 사건의 조치·감사 이력에 남습니다.`
        : `${entry.actor_ip} 차단을 해제할까요? 요청은 조치·감사 이력에 남습니다.`}</p>
      <Input aria-label="해제 사유" maxLength={1000} placeholder="해제 사유 (선택)" value={note} onChange={event => setNote(event.target.value)} />
      <div className="flex gap-2"><Button type="submit" variant="primary" loading={mutation.isPending} disabled={!canRelease}>해제 확정</Button><Button onClick={() => setConfirming(false)} disabled={mutation.isPending}>취소</Button></div>
    </form>}
  </li>
}
