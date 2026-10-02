import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { issueEnrollment, cancelEnrollment, useNodes, nodeKey, auditKey, type Enrollment, type EnrollmentInput, type NodeEntry } from '@/api/operations'
import { describeError } from '@/api/errors'
import { useMe } from '@/auth/useMe'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Button } from '@/components/atoms/Button'
import { Input } from '@/components/atoms/Input'
import { Time } from '@/components/atoms/Time'
import { Banner } from '@/components/molecules/Banner'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { useNow } from '@/lib/useNow'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ReceptionBadge } from './NodesPage'

export function NodeEnrollmentPage() {
  const me=useMe(), query=useNodes(), [params]=useSearchParams()
  const selected=params.get('node'), initial=query.data?.rows.find(n=>n.node_id===selected)
  if (me.isPending) return <LoadingState />
  if (me.data?.role !== 'admin') return <ForbiddenState requiredRoles="admin" currentRole={me.data?.role} />
  if (query.isPending) return <LoadingState />
  if (!query.data) return <ApiErrorState error={query.error} onRetry={()=>void query.refetch()} />
  if (selected && !initial) return <Banner tone="danger" title="등록된 노드를 찾을 수 없습니다" action={<Link to="/nodes">목록으로</Link>} />
  return <><MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.error} onRetry={()=>void query.refetch()} busy={query.isFetching} /><EnrollmentForm key={selected || 'new'} initial={initial} nodes={query.data.rows} /></>
}
function EnrollmentForm({initial,nodes}:{initial?:NodeEntry;nodes:NodeEntry[]}) {
  const client=useQueryClient(), clock=useNow(1000)
  const [form,setForm]=useState<EnrollmentInput>({node_id:initial?.node_id ?? '',hostname:initial?.hostname ?? '',addr:initial?.addr ?? '',logs:initial?.logs ?? ['nginx','auth','metrics']})
  const [issued,setIssued]=useState<(Enrollment & {receivedAt:number}) | null>(null)
  const [busy,setBusy]=useState(false), [error,setError]=useState(''), [notice,setNotice]=useState(''), [visible,setVisible]=useState(false)
  const pending=useRef(false)
  const remaining=issued ? Math.max(0, Math.ceil((Date.parse(issued.expires_at)-Date.parse(issued.issued_at)-Math.max(0,clock-issued.receivedAt))/1000)) : 0
  const node=nodes.find(n=>n.node_id===issued?.node_id)
  useEffect(() => {
    if (!issued?.token) return
    const delay = Math.max(0, Date.parse(issued.expires_at)-Date.parse(issued.issued_at)-(Date.now()-issued.receivedAt))
    const timer = window.setTimeout(() => setIssued(v => v ? { ...v, token: '' } : null), delay)
    return () => window.clearTimeout(timer)
  }, [issued])
  async function refresh() { await Promise.all([client.invalidateQueries({queryKey:nodeKey}),client.invalidateQueries({queryKey:auditKey})]) }
  async function issue(event:FormEvent) {
    event.preventDefault()
    if(pending.current) return
    if(!form.logs.length) {setError('수집 항목을 하나 이상 선택해 주세요.');return}
    pending.current=true;setBusy(true);setError('');setNotice('');setIssued(null);setVisible(false)
    try { const result=await issueEnrollment(form);setIssued({...result,receivedAt:Date.now()});await refresh() }
    catch(e) {setError(`${describeError(e)} · 발급 응답을 받지 못했다면 목록에서 확인 후 다시 발급해 주세요.`)}
    finally {pending.current=false;setBusy(false)}
  }
  async function cancel() {
    if(!issued || pending.current) return
    pending.current=true;setBusy(true);setError('')
    try {await cancelEnrollment(issued.node_id,issued.id);setIssued(null);setVisible(false);setNotice('등록 토큰을 취소했습니다.');await refresh()}
    catch(e) {setError(describeError(e))} finally {pending.current=false;setBusy(false)}
  }
  async function copy() {
    if(!issued?.token) return
    try {await navigator.clipboard.writeText(issued.token);setNotice('등록 토큰을 복사했습니다.')} catch {setError('복사할 수 없습니다. 토큰 보기에서 직접 복사해 주세요.')}
  }
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title={initial ? '등록 토큰 재발급' : '노드 추가'} description="대상 정보를 확인하고 설치에 사용할 등록 토큰을 발급합니다." aside={<Link to="/nodes">노드 목록</Link>} />
    {error && <Banner tone="danger" title={error} />}{notice && <Banner tone="info" title={notice} />}
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <Card padding="none"><CardHeader title="대상 정보" /><form className="grid gap-4 p-4" onSubmit={issue}>
        <label htmlFor="node-field-0" className="grid gap-1 text-sm">노드 이름<Input id="node-field-0" value={form.node_id} required pattern="[a-z0-9][a-z0-9-]{0,62}" maxLength={63} placeholder="web-01" readOnly={!!initial} disabled={busy || !!issued} onChange={e=>setForm({...form,node_id:e.target.value})} /></label>
        <label htmlFor="node-field-1" className="grid gap-1 text-sm">호스트 이름<Input id="node-field-1" value={form.hostname} required maxLength={253} placeholder="opsloop-web-01" readOnly={!!initial} disabled={busy || !!issued} onChange={e=>setForm({...form,hostname:e.target.value})} /></label>
        <label htmlFor="node-field-2" className="grid gap-1 text-sm">노드 IP 주소<Input id="node-field-2" value={form.addr} required maxLength={45} placeholder="192.168.50.21" readOnly={!!initial} disabled={busy || !!issued} onChange={e=>setForm({...form,addr:e.target.value})} /></label>
        <fieldset disabled={busy || !!issued || !!initial} className="m-0 flex flex-wrap gap-4 border-0 p-0 text-sm"><legend className="mb-2">수집 항목</legend>{[['nginx','웹 접근'],['auth','인증'],['metrics','시스템 지표']].map(([value,label])=><label key={value} className="flex items-center gap-2"><input type="checkbox" checked={form.logs.includes(value)} onChange={e=>setForm({...form,logs:e.target.checked?[...form.logs,value]:form.logs.filter(v=>v!==value)})} />{label}</label>)}</fieldset>
        <p className="m-0 text-xs leading-5 text-ink-muted">{initial ? <>등록 토큰은 1시간 · 1회용이며, 다시 발급하면 쓰지 않은 이전 토큰은 취소됩니다. <InfoTip label="재발급">이미 등록된 에이전트의 키는 그대로 둡니다.</InfoTip></> : '등록 토큰은 1시간 · 1회용입니다.'}</p>
        {/* 내부 방화벽은 web-01 주소만 수집 관문을 허용한다(이슈 #94). 안내만 하고 방화벽은 바꾸지 않는다 */}
        <p className="m-0 text-xs leading-5 text-ink-muted">설치 전에 내부 방화벽의 수집 허용(이 노드 → 192.168.60.11:3101)이 먼저 있어야 합니다. 운영자가 운영 문서(infra/vmware/README.md)의 '방화벽 설정 올리기 · 되돌리기' 절로 반영합니다.</p>
        {!issued && <Button type="submit" variant="primary" loading={busy}>{initial ? '등록 토큰 다시 발급' : '등록 토큰 발급'}</Button>}
      </form></Card>
      <div className="flex min-w-0 flex-col gap-4">
        {issued && <Card padding="none"><CardHeader title="토큰 발급 · 설치" aside={remaining ? `${Math.floor(remaining/60)}분 ${remaining%60}초 남음` : '만료'} /><div className="flex flex-col gap-3 p-4">
          <p className="m-0 text-xs text-ink-muted">이 화면을 나가면 토큰 원문을 다시 조회할 수 없습니다.</p>
          {remaining>0 ? <><Input aria-label="등록 토큰" type={visible?'text':'password'} value={issued.token} readOnly autoComplete="off" className="font-mono text-xs" /><div className="flex flex-wrap gap-2"><Button size="sm" onClick={()=>setVisible(!visible)}>{visible?'토큰 숨기기':'토큰 보기'}</Button><Button size="sm" onClick={()=>void copy()}>복사</Button></div></> : <p className="m-0 text-sm text-warning">토큰이 만료됐습니다. 취소 후 다시 발급해 주세요.</p>}
          <p className="m-0 text-xs text-ink-muted">만료 <Time value={issued.expires_at} format="short" zone /></p>
          <p className="m-0 text-sm leading-6">관리 단말에서 대상 노드의 Ansible 수집 플레이북을 실행하세요. 토큰은 <code>OPSLOOP_ENROLL_TOKEN</code> 환경 변수로 전달합니다.</p>
          <details className="text-xs"><summary className="cursor-pointer">web-01 설치 예시</summary><pre className="overflow-x-auto rounded-panel bg-canvas p-3 leading-5">{'cd infra/ansible\nread -rs OPSLOOP_ENROLL_TOKEN\nexport OPSLOOP_ENROLL_TOKEN\nansible-playbook web01.yml\nunset OPSLOOP_ENROLL_TOKEN'}</pre><p>다른 노드는 해당 인벤토리와 수집 설정을 먼저 준비해야 합니다.</p></details>
          <Button onClick={()=>void cancel()} loading={busy}>등록 토큰 취소</Button>
        </div></Card>}
        {issued && <Card padding="none"><InfoTip label="등록 · 첫 수신 확인" render={({ button, panel }) => <>
          <CardHeader title="등록 · 첫 수신 확인" aside={<span className="inline-flex items-center gap-1">30초마다 확인{button}</span>} />
          {panel}
        </>}>재등록한 노드는 과거 수신 기록이 남아 있을 수 있습니다. 형식 변환과 규칙 적용은 설치 플레이북의 첫 수신 점검으로 확인하세요.</InfoTip><dl className="m-0 grid grid-cols-[auto_1fr] gap-3 p-4 text-sm"><dt>등록 상태</dt><dd className="m-0">{node ? <ReceptionBadge node={node} /> : '확인 중'}</dd><dt>자기 등록</dt><dd className="m-0"><Time value={node?.registered_at} format="short" zone /></dd><dt>첫 적재</dt><dd className="m-0"><Time value={node?.first_loaded_at} format="short" zone /></dd><dt>마지막 수신</dt><dd className="m-0"><Time value={node?.last_seen_at} format="short" zone /></dd></dl></Card>}
      </div>
    </div>
  </div>
}
