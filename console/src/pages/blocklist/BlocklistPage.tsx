import { useId, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useBlocklist, type BlockEntry } from '@/api/monitoring'
import { useControlHealthView, useControlHealth } from '@/api/health'
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
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { IncidentPagination } from '@/components/organisms/incidents/IncidentPagination'
import { BLOCK_STATE_TONE, blockState, blockStateHint, blockStateLabel, enforceRecord, gatewayCheckedAt, LIVE_BLOCK_STATES, pointCounts, pointRows, type BlockState } from '@/components/organisms/incident-detail/format'
import { EnforcePointList } from '@/components/organisms/incident-detail/EnforcePointList'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { useNow } from '@/lib/useNow'
import { cn } from '@/lib/cn'

type Tab = 'active' | 'expired' | 'released'
const TABS: Array<[Tab, string]> = [['active', '활성'], ['expired', '만료'], ['released', '해제']]
const COLUMNS = 'lg:grid-cols-[120px_minmax(130px,1fr)_190px_110px_70px_55px] xl:grid-cols-[140px_minmax(160px,1fr)_220px_135px_75px_65px]'
type Notice = { tone: 'success' | 'danger'; message: string }

export function BlocklistPage() {
  const query = useBlocklist()
  // 관제 상태는 틀(AppLayout)이 받아 둔 캐시만 읽는다(따로 묻지 않는다). 확인 불가면 멈춤을 붙이지 않는다
  const health = useControlHealthView(useControlHealth(false))
  const permission = usePermission('block.release')
  const clock = useNow(1_000)
  const [params, setParams] = useSearchParams()
  const tab: Tab = params.get('tab') === 'expired' ? 'expired' : params.get('tab') === 'released' ? 'released' : 'active'
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [allCounts, setAllCounts] = useState(false)
  const countsId = useId()
  const rows = query.data ?? []
  // 브라우저 시계가 서버와 달라도 만료 판단은 서버 조회 시각부터 경과한 시간으로 계산한다.
  const checked = rows[0]?.checked_at ? Date.parse(rows[0].checked_at) : NaN
  const now = Number.isFinite(checked) ? checked + Math.max(0, clock - query.dataUpdatedAt) : clock
  const groups = { active: [] as BlockEntry[], expired: [] as BlockEntry[], released: [] as BlockEntry[] }
  // 활성 요청의 종합 상태별 수(이슈 #47 · #77). 요청 수를 막은 수로 읽지 않게 집행 확인 · 대기 · 실패 · 불일치 · 제외로 나눈다.
  // 요청한 지점이 모두 확인해야 집행 확인이라 칸 이름에 지점을 넣지 않는다
  const live: Record<BlockState, number> = { enforced: 0, pending: 0, excluded: 0, failed: 0, mismatch: 0, released: 0, expired: 0 }
  for (const entry of rows) {
    const state = blockState(entry, now)
    if (LIVE_BLOCK_STATES.includes(state)) live[state] += 1
    groups[LIVE_BLOCK_STATES.includes(state) ? 'active' : state as 'expired' | 'released'].push(entry)
  }
  // 내부 방화벽은 실패 · 미확인만 센다(#72). 대시보드 지점별 수와 같은 정의이고 보고 상태 그대로다.
  // 집행기가 멈춰 대시보드가 적용 · 실패를 미확인에 합칠 때는 수를 바꾸지 않고 두 칸 뒤에 '집행기 멈춤' 만 붙인다
  const fw = pointCounts(rows, now, 'fw')
  // 관문 미요청(이슈 #77): 내부 방화벽만 요청한 살아 있는 차단. 관문 수가 아니라 요청 사실이라 0 이면 칸을 두지 않는다.
  // 관문을 뺐는데 관문이 뺐다고 확인하기 전인 차단은 미요청이 아니라 관문 빠짐 확인 전으로 따로 둔다(결정 14, 0 이면 없음)
  const gateway = pointCounts(rows, now, 'gateway')
  const fwStalled = health.state === 'ok' && health.alerts.some(item => item.key === 'enforcer:fw') ? '집행기 멈춤' : undefined
  // 좁은 화면(sm 미만)은 핵심 칸 넷(활성 요청 · 집행 실패 · 불일치 · 내부 방화벽 실패)을 먼저 두고 나머지는 접는다(이슈 #94).
  // 접힌 주의 칸의 0 보다 큰 값은 접힘 줄에 적는다. sm 이상은 그대로다(칸은 늘 DOM 에 있고 CSS 로만 숨긴다)
  const core = 'max-sm:order-first'
  const rest = cn(!allCounts && 'max-sm:hidden')
  const restCount = 5 + (gateway.unrequested > 0 ? 1 : 0) + (gateway.removing > 0 ? 1 : 0)
  const foldedWarnings = ([['집행 대기', live.pending], ['내부 방화벽 미확인', fw.unverified]] as const).filter(([, value]) => value > 0)
  const keyword = search.trim().toLowerCase()
  const filtered = groups[tab].filter(entry => `${entry.actor_ip} ${entry.reason ?? ''} ${entry.incident_key ?? ''}`.toLowerCase().includes(keyword))
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)))
  const shown = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  return <div className="worklist-page flex min-w-0 flex-col gap-3">
    <PageHeader title="차단 목록" description="차단 요청과 집행 지점의 결과를 함께 확인합니다." aside={<span className="text-xs text-ink-muted">해제 권한: admin</span>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
    {notice && <Banner tone={notice.tone} title={notice.message} action={<Button size="sm" onClick={() => setNotice(null)}>닫기</Button>} />}
    {query.isPending ? <LoadingState title="차단 목록을 불러오는 중입니다" /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : <>
      <Card id={countsId} padding="none" className="grid grid-cols-2 divide-x divide-line sm:grid-cols-5">
        <Count className={core} label="활성 요청" value={groups.active.length} /><Count className={rest} label="집행 확인" value={live.enforced} /><Count className={rest} label="집행 대기" value={live.pending} warning /><Count className={core} label="집행 실패" value={live.failed} warning /><Count className={core} label="불일치" value={live.mismatch} warning /><Count className={core} label="내부 방화벽 실패" value={fw.failed} warning note={fwStalled} /><Count className={rest} label="내부 방화벽 미확인" value={fw.unverified} warning note={fwStalled} />{gateway.unrequested > 0 && <Count className={rest} label="관문 미요청" value={gateway.unrequested} />}{gateway.removing > 0 && <Count className={rest} label="관문 빠짐 확인 전" value={gateway.removing} />}<Count className={rest} label="집행 제외" value={live.excluded} /><Count className={rest} label="24시간 내 만료" value={groups.active.filter(entry => entry.expires_at && Date.parse(entry.expires_at) <= now + 86_400_000).length} />
      </Card>
      <Button variant="ghost" size="sm" className="h-auto min-h-9 flex-wrap justify-start self-start px-0 text-left whitespace-normal sm:hidden" aria-expanded={allCounts} aria-controls={countsId} onClick={() => setAllCounts(!allCounts)} data-count-fold="">
        {allCounts ? '나머지 칸 접기' : `나머지 칸 ${restCount}개 보기`}{!allCounts && foldedWarnings.map(([label, value]) => <span key={label} className="text-warning"> · {label} {value.toLocaleString()}건</span>)}
      </Button>
      <p className="m-0 text-xs text-ink-muted">집행 확인은 요청한 지점이 모두 확인한 것입니다. 내부 방화벽은 실패 · 미확인을 따로 셉니다. <InfoTip label="집행 범위">활성은 만료 · 해제 전 요청입니다. 허니팟 관문은 허니팟 유입(22 · 23 · 8080)을, 내부 방화벽은 web-01 접근을 막습니다. 관문 미요청은 내부 방화벽만 요청한 차단입니다. 관문 빠짐 확인 전은 관문을 뺐지만 관문이 뺐다고 아직 확인하지 못한 차단입니다. 미확인은 대기 · 확인 지연 · 기록 없음입니다.</InfoTip></p>
      <Card padding="none" className="worklist-panel flex min-w-0 flex-col overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2">
          <div role="group" aria-label="차단 상태" className="flex gap-5">{TABS.map(([value, label]) => <button key={value} type="button" aria-pressed={tab === value} className={cn('min-h-9 cursor-pointer border-b-2 px-0.5 text-sm', tab === value ? 'border-primary font-semibold text-primary' : 'border-transparent text-ink-muted')} onClick={() => { const next = new URLSearchParams(params); next.set('tab', value); setParams(next); setPage(1) }}>{label} <span className="tabular-nums">{groups[value].length}</span></button>)}</div>
          <Input aria-label="차단 검색" placeholder="출발지 · 사유 · 사건 검색" className="max-w-[260px]" value={search} onChange={event => { setSearch(event.target.value); setPage(1) }} />
        </div>
        <div className={cn('hidden gap-3 border-b border-line bg-canvas/60 px-4 py-2 text-xs text-ink-muted lg:grid', COLUMNS)} aria-hidden="true">{['출발지', '사유 · 근거 사건', '집행 결과', '만료 시각 (KST)', '요청자', '조치'].map(label => <span key={label}>{label}</span>)}</div>
        <div className="worklist-scroll" key={`${tab}:${currentPage}:${pageSize}:${search}`}><ul className="m-0 list-none divide-y divide-line p-0">{shown.map(entry => <BlockRow key={`${entry.actor_ip}:${entry.created_at}`} entry={entry} now={now} allowed={permission.allowed} stale={query.isError} onNotice={setNotice} refresh={() => void query.refetch()} />)}</ul>
        {!shown.length && <p className="m-0 px-4 py-10 text-center text-ink-muted">{search ? '검색 조건에 맞는 차단이 없습니다.' : `${TABS.find(([value]) => value === tab)?.[1]} 항목이 없습니다.`}</p>}</div>
        <IncidentPagination label="차단 목록 페이지" page={currentPage} pageSize={pageSize} total={filtered.length} busy={query.isPending} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1) }} />
      </Card>
    </>}
  </div>
}

/** 상단 칸. note 는 값 뒤에 붙는 주의 글자(집행기 멈춤) */
function Count({ label, value, warning, note, className }: { label: string; value: number; warning?: boolean; note?: string; className?: string }) {
  return <div className={cn('px-4 py-4', className)}><div className="text-xs text-ink-muted">{label}</div><div className={cn('mt-1.5 text-xl font-semibold tabular-nums', warning && value > 0 && 'text-warning')}>{value.toLocaleString()}건{note && <> <span className="text-xs font-medium whitespace-nowrap text-warning">· {note}</span></>}</div></div>
}

/** 같은 페이로드 흡수 차단 행(규칙 v3). 근거 사건은 첫 사건이고 행의 출발지는 흡수 출발지다(서버 absorbed_reason_tag) */
function isAbsorbedBlock(entry: Pick<BlockEntry, 'reason'>): boolean {
  return entry.reason?.startsWith('흡수: ') ?? false
}

/**
 * 집행 결과 칸의 둘째 줄: 상태 설명 · 방식 · 관문 확인 시각. 방식은 관문이 보고한 값이라 글자로만 그린다.
 * 까닭(제외 · 불일치 사유)은 그 아래 집행 메모(enforce_note)로 보인다. 관문을 요청하지 않은 행에 남은 관문 방식 · 메모는
 * 보이지 않는다(enforceRecord, 관문 칸이 대신한다)
 */
function EnforceFacts({ entry, state }: { entry: BlockEntry; state: BlockState }) {
  const checkedAt = gatewayCheckedAt(entry, state)
  const { method } = enforceRecord(entry)
  return <div className="mt-1 break-all text-xs text-ink-muted">
    {blockStateHint(entry, state)}
    {checkedAt && <> <Time value={checkedAt} format="short" /></>}
    {method && <> · <UntrustedText value={method} /></>}
  </div>
}

function BlockRow({ entry, now, allowed, stale, onNotice, refresh }: { entry: BlockEntry; now: number; allowed: boolean; stale: boolean; onNotice: (notice: Notice) => void; refresh: () => void }) {
  const mutation = useActionMutation(entry.incident_key ?? '')
  const [confirming, setConfirming] = useState(false)
  const [note, setNote] = useState('')
  const state = blockState(entry, now)
  const live = LIVE_BLOCK_STATES.includes(state)
  const absorbed = isAbsorbedBlock(entry)
  // 지점 칸(이슈 #77): 요청하지 않은 지점은 미요청(관문 빼기 뒤 확인 전이면 빠짐 확인 전), 해제 · 만료는 지점마다 빠짐 확인 전 · 빠짐
  const points = pointRows(entry, now)
  const gateway = points.find(p => p.key === 'gateway')
  // 관문 칸이 종합 상태를 대신하는 것은 종합이 집행 확인이고 관문 칸도 적용 확인일 때뿐이다(결정 b: 요청한 지점이 모두 확인해야
  // 적용). 그 밖(대기 · 실패 · 불일치 · 제외 · 해제 · 만료, 관문 결과 없음 · 관문 미요청 · 관문 빠짐 확인 전)은 배지로 종합 상태를 보인다
  const badge = state !== 'enforced' || gateway?.point.state !== 'confirmed'
  // 집행 상세의 지점별 시각 · 방식은 살아 있는 행의 결과 기록만(미요청은 기록이 아니고, 목록 밖 행은 빠짐 칸이 대신한다)
  const recorded = live ? points.filter(p => p.point.state !== 'unrequested') : []
  const record = enforceRecord(entry)
  const canRelease = allowed && live && !!entry.incident_key && !stale
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
    <div className="col-span-2 font-mono font-semibold break-all lg:col-span-1">{entry.actor_ip}</div>
    <div className="col-span-2 min-w-0 lg:col-span-1"><div className="break-words"><UntrustedText value={entry.reason} fallback="사유 미기록" /></div><div className="mt-1 text-xs">{entry.incident_key ? <Link className="break-all" to={`/incidents/${encodeURIComponent(entry.incident_key)}`}>{entry.incident_key.split('|')[0]} · {absorbed ? '첫 사건 보기' : '사건 보기'}</Link> : <span className="text-ink-muted">근거 사건 없음</span>}</div></div>
    <div data-block-state={state} className="col-span-2 min-w-0 lg:col-span-1">
      {badge && <Badge tone={BLOCK_STATE_TONE[state]}>{blockStateLabel(entry, state)}</Badge>}
      <EnforcePointList compact points={points} />
      <details className="mt-1 text-xs text-ink-muted">
        <summary className="cursor-pointer" aria-label={`${entry.actor_ip} 집행 상세`}>집행 상세</summary>
        <EnforceFacts entry={entry} state={state} />
        {record.note && <p className="my-2 break-words"><UntrustedText value={record.note} /></p>}
        {recorded.map(({ key, label, point }) => <div key={key} className="mt-2 break-words"><span className="font-medium">{label}</span> · {point.since ? <Time value={point.since} format="short" /> : '확인 시각 없음'}{point.mode && <> · <UntrustedText value={point.mode} max={16} /></>}</div>)}
      </details>
    </div>
    <div className="text-xs"><span className="block text-ink-muted lg:hidden">만료 시각 (KST)</span>{entry.expires_at ? <Time value={entry.expires_at} format="short" /> : '만료 없음'}{entry.released_at && <div className="mt-1 text-ink-muted">해제 <Time value={entry.released_at} format="short" />{entry.released_by && <> · <UntrustedText value={entry.released_by} max={64} /></>}</div>}</div>
    <div className="break-words text-xs text-ink-muted"><span className="lg:hidden">요청자 </span><UntrustedText value={entry.requested_by} max={64} fallback="미기록" /></div>
    <div className="col-span-2 justify-self-end lg:col-span-1 lg:justify-self-start">{allowed && live ? <Button size="sm" disabled={!canRelease || mutation.isPending} disabledReason={stale ? '최신 목록을 확인한 뒤 해제해 주세요' : '연결된 근거 사건이 없어 해제할 수 없습니다'} onClick={() => setConfirming(!confirming)} aria-expanded={confirming}>해제</Button> : <span className="text-xs text-ink-muted">{live ? 'admin만' : '—'}</span>}</div>
    {confirming && live && <form className="col-span-2 flex flex-col gap-2 rounded-panel border border-line bg-canvas p-3 lg:col-span-6" aria-label={`${entry.actor_ip} 해제 확인`} onSubmit={release}>
      <p className="m-0 text-sm">{absorbed
        ? `${entry.actor_ip} 의 흡수 차단 한 곳만 해제할까요? 이 출발지는 이후 후속 차단에서도 빠집니다.`
        : `${entry.actor_ip} 차단을 해제할까요?`}</p>
      <Input aria-label="해제 사유" maxLength={1000} placeholder="해제 사유 (선택)" value={note} onChange={event => setNote(event.target.value)} />
      <div className="flex gap-2"><Button type="submit" variant="primary" loading={mutation.isPending} disabled={!canRelease}>해제 확정</Button><Button onClick={() => setConfirming(false)} disabled={mutation.isPending}>취소</Button></div>
    </form>}
  </li>
}
