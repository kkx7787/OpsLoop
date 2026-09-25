import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RulesPage } from './rules/RulesPage'
import { NodesPage } from './nodes/NodesPage'
import { NodeEnrollmentPage } from './nodes/NodeEnrollmentPage'
import { AuditPage } from './audit/AuditPage'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { RULES, nodeEntry, auditEntry } from '@/test/operations-fixtures'
import { applyLiveMessage } from '@/api/live'
import { expectInertDom, expectLongFolds, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

const TOKEN = 'olE_local-test-not-a-real-token'
function setup(path: string, role='admin', failure=false) {
  const rows = [nodeEntry(),nodeEntry({node_id:'quiet-01',reception:'silent'}),nodeEntry({node_id:'pending-01',reception:'waiting',last_seen_at:null})]
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url=new URL(String(input),'http://localhost')
    if(url.pathname==='/api/me') return json({username:'tester',role})
    if(failure) return json({detail:'일시 오류'},503)
    if(url.pathname==='/api/rules/quality') return json(RULES)
    if(url.pathname==='/api/nodes') return json({as_of:rows[0].checked_at,rows})
    if(url.pathname==='/api/audit') return json({rows: [auditEntry(Number(url.searchParams.get('offset') || 0))],total:26,limit:25,offset:Number(url.searchParams.get('offset') || 0)})
    if(url.pathname==='/api/nodes/enrollments' && init?.method==='POST') return json({id:1,node_id:'web-01',token:TOKEN,issued_at:new Date().toISOString(),expires_at:new Date(Date.now()+3600000).toISOString()},201)
    if(url.pathname.endsWith('/cancel')) return json({canceled:true})
    return json({},404)
  })
  vi.stubGlobal('fetch',fetch)
  const client=noRetryClient()
  const view=renderRoutes([{path:'/rules',element:<RulesPage />},{path:'/nodes',element:<NodesPage />},{path:'/nodes/new',element:<NodeEnrollmentPage />},{path:'/audit',element:<AuditPage />}],path,client)
  return {fetch,client,...view}
}
afterEach(()=>vi.unstubAllGlobals())

describe('규칙 결과',()=>{
  it('마지막 판정 집계와 미결 제외 비조치율을 보여 주며 실행 신규 수와 구분한다',async()=>{
    setup('/rules')
    expect(await screen.findByText('50.0%')).toBeInTheDocument()
    expect(screen.getByText(/사건별 마지막 판정 기준/)).toBeInTheDocument()
    expect(screen.getByText('최근 30회 · 신규 생성 수')).toBeInTheDocument()
    expect(screen.getByText('서로 다른 두 버전과 동일한 시작·종료 구간을 선택해 주세요.')).toBeInTheDocument()
    expect(screen.getByRole('link',{name:'R001 · v2'})).toHaveAttribute('href','/incidents?rule_id=R001')
  })
  it('순환 규칙(R006 포함)은 오탐률 대신 순환 규칙으로 표시한다',async()=>{
    setup('/rules')
    const row=(await screen.findByRole('link',{name:'R006 · v3'})).closest('tr')!
    expect(within(row).getByText('순환 규칙')).toBeInTheDocument()
    const plain=screen.getByRole('link',{name:'R001 · v2'}).closest('tr')!
    expect(within(plain).queryByText('순환 규칙')).toBeNull()
  })
  it('KST 구간을 UTC로 전달하고 한쪽만 입력하면 조회하지 않는다',async()=>{
    const {fetch}=setup('/rules')
    await screen.findByText('50.0%')
    fireEvent.change(screen.getByLabelText('시작 (KST)'),{target:{value:'2026-09-22T09:00'}})
    fireEvent.click(screen.getByRole('button',{name:'구간 조회'}))
    expect(await screen.findByRole('alert')).toHaveTextContent('시작과 종료')
    fireEvent.change(screen.getByLabelText('종료 (KST)'),{target:{value:'2026-09-23T09:00'}})
    fireEvent.click(screen.getByRole('button',{name:'구간 조회'}))
    await waitFor(()=>expect(fetch.mock.calls.some(([url])=>String(url).includes('since=2026-09-22T00%3A00%3A00.000Z'))).toBe(true))
    expect(await screen.findByText(/원문을 다시 실행하지 않습니다/)).toBeInTheDocument()
  })
  it('판정 통보는 확장 규칙 조회도 다시 불러온다',async()=>{
    const {fetch,client}=setup('/rules');await screen.findByText('50.0%')
    const calls=()=>fetch.mock.calls.filter(([u])=>String(u).includes('/api/rules/quality')).length
    const count=calls();act(()=>applyLiveMessage(client,{type:'verdict.created'}))
    await waitFor(()=>expect(calls()).toBeGreaterThan(count))
  })
})

describe('노드와 토큰',()=>{
  it('침묵·대기 상태를 구분하고 검색한다',async()=>{
    setup('/nodes');await screen.findByText('quiet-01')
    const region=screen.getByRole('region',{name:'수집 노드 표'})
    expect(within(region).getByText('침묵')).toBeInTheDocument()
    expect(within(region).getByText('대기')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox'),{target:{value:'quiet'}})
    expect(screen.queryByText('web-01')).toBeNull()
    expect(screen.getByText('quiet-01')).toBeInTheDocument()
  })
  it('머리에 자산 · 취약점 화면 링크를 둔다(역할과 무관)',async()=>{
    setup('/nodes','viewer');await screen.findByText('web-01')
    expect(screen.getByRole('link',{name:'자산 · 취약점'})).toHaveAttribute('href','/inventory')
  })
  it.each(['viewer','operator'])('%s는 노드 추가와 발급을 할 수 없다',async role=>{
    const {router}=setup('/nodes',role);await screen.findByText('web-01')
    expect(screen.queryByRole('link',{name:'노드 추가'})).toBeNull()
    await act(()=>router.navigate('/nodes/new'))
    expect(await screen.findByText('이 동작은 admin 만 할 수 있습니다')).toBeInTheDocument()
    expect(screen.queryByRole('button',{name:'등록 토큰 발급'})).toBeNull()
  })
  it('토큰은 마스킹하고 캐시·저장소에 남기지 않으며 취소 후 지운다',async()=>{
    const {fetch,client}=setup('/nodes/new?node=web-01')
    fireEvent.click(await screen.findByRole('button',{name:'등록 토큰 다시 발급'}))
    const input=await screen.findByLabelText('등록 토큰')
    expect(input).toHaveAttribute('type','password')
    fireEvent.click(screen.getByRole('button',{name:'토큰 보기'}))
    expect(input).toHaveValue(TOKEN)
    expect(JSON.stringify(client.getQueryCache().getAll().map(q=>q.state.data))).not.toContain(TOKEN)
    expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain(TOKEN)
    expect(JSON.stringify(localStorage)).not.toContain(TOKEN)
    expect(JSON.stringify(sessionStorage)).not.toContain(TOKEN)
    fireEvent.click(screen.getByRole('button',{name:'등록 토큰 취소'}))
    expect(await screen.findByText('등록 토큰을 취소했습니다.')).toBeInTheDocument()
    expect(screen.queryByLabelText('등록 토큰')).toBeNull()
    expect(fetch.mock.calls.some(([u])=>String(u)==='/api/nodes/web-01/enrollments/1/cancel')).toBe(true)
  })
  it('페이지를 떠났다 돌아와도 토큰 원문을 복구하지 않는다',async()=>{
    const {router}=setup('/nodes/new?node=web-01')
    fireEvent.click(await screen.findByRole('button',{name:'등록 토큰 다시 발급'}));await screen.findByLabelText('등록 토큰')
    await act(()=>router.navigate('/nodes'));await screen.findByText('quiet-01')
    await act(()=>router.navigate('/nodes/new?node=web-01'))
    await screen.findByRole('button',{name:'등록 토큰 다시 발급'})
    expect(screen.queryByLabelText('등록 토큰')).toBeNull()
  })
})

describe('감사 기록',()=>{
  it('행위자·대상·KST 구간 필터와 서버 페이지를 전달한다',async()=>{
    const {fetch}=setup('/audit');await screen.findByText('web-0')
    fireEvent.click(screen.getByRole('button',{name:'다음'}));await screen.findByText('web-25')
    fireEvent.change(screen.getByLabelText('행위자'),{target:{value:'admin'}})
    fireEvent.change(screen.getByLabelText('대상'),{target:{value:'web-01'}})
    fireEvent.change(screen.getByLabelText('시작 (KST)'),{target:{value:'2026-09-22T09:00'}})
    fireEvent.change(screen.getByLabelText('종료 (KST)'),{target:{value:'2026-09-23T09:00'}})
    fireEvent.click(screen.getByRole('button',{name:'조회'}))
    await waitFor(()=>expect(fetch.mock.calls.some(([raw])=>{const u=new URL(String(raw),'http://localhost');return u.searchParams.get('actor')==='admin'&&u.searchParams.get('target')==='web-01'&&u.searchParams.get('since')==='2026-09-22T00:00:00.000Z'&&u.searchParams.get('offset')==='0'})).toBe(true))
    expect(await screen.findByText('1 / 2페이지')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button',{name:'초기화'}))
    expect(screen.getByLabelText('행위자')).toHaveValue('')
  })
  it.each(['viewer','operator'])('%s는 감사 API를 호출하지 않는다',async role=>{
    const {fetch}=setup('/audit',role)
    expect(await screen.findByText('이 화면은 admin 만 볼 수 있습니다')).toBeInTheDocument()
    expect(fetch.mock.calls.some(([u])=>String(u).startsWith('/api/audit'))).toBe(false)
  })
  it.each(['/rules','/nodes','/audit'])('%s 조회 실패를 빈 목록으로 숨기지 않는다',async path=>{
    setup(path,'admin',true)
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText('조건에 맞는 감사 기록이 없습니다.')).toBeNull()
  })
})

describe('감사 기록 · 비신뢰 문자열(#41)', () => {
  it('행위자 · 대상 · 기록 · DB 주소를 글자로만 그리고 숨은 문자는 표식 · 2만 자는 접는다', async () => {
    const row = { ...auditEntry(0), actor: HOSTILE.rlo, target: MIXED, detail: LONG, db_client: HOSTILE.zwsp }
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/me') return json({ username: 'tester', role: 'admin' })
      if (url.pathname === '/api/audit') return json({ rows: [row], total: 1, limit: 25, offset: 0 })
      return json({}, 404)
    }))
    const { container } = renderRoutes([{ path: '/audit', element: <AuditPage /> }], '/audit', noRetryClient())
    const table = await screen.findByRole('region', { name: '감사 기록 표' })
    expectInertDom(container)
    expectMixedRevealed(table)
    expect(within(table).getAllByRole('cell')[1].textContent).toBe('admin⟨U+202E⟩gnp.exe')
    expect(table.textContent).toContain('DB 연결 주소 ad⟨U+200B⟩min')
    expectLongFolds(table)
  })
})
