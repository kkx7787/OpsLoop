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
    // 비조치율 산식 · 분모는 캡션 줄 ⓘ 로 접고, 열 머리도 같은 설명을 읽는다
    const rate = /비조치 = 무시 가능 \+ 오탐 \+ 양성 정탐\. 분모는 미결을 뺀 유효 판정입니다/
    expect(screen.getByRole('button',{name:'비조치율 설명'})).toHaveAccessibleDescription(rate)
    expect(screen.getByRole('columnheader',{name:/^비조치율/})).toHaveAccessibleDescription(rate)
    expect(screen.getByText('최근 30회 · 신규 생성 수')).toBeInTheDocument()
    expect(screen.getByText('구간을 조회하고 서로 다른 두 버전을 고르세요.')).toBeInTheDocument()
    // 규칙 정의의 활성 여부는 배지('정의상 활성')가 말한다. 되풀이하던 문단은 뺐다
    expect(screen.queryByText(/현재 실행 중인 버전이라는 뜻은 아닙니다/)).toBeNull()
    expect(screen.getByRole('link',{name:'R001 · v2'})).toHaveAttribute('href','/incidents?rule_id=R001')
    // 대시보드에서 옮긴 비조치 · 유효 판정 수(#52). 미결은 분모에서 빠진다
    expect(screen.getByText('비조치 1 / 유효 판정 2')).toBeInTheDocument()
  })
  it('최근 실행은 5회로 요약하고 나머지 이력도 펼쳐 확인한다', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async input => {
      if (String(input).startsWith('/api/rules/quality')) return json({ ...RULES, runs: Array.from({ length: 12 }, (_, i) => ({ ...RULES.runs[0], id: i + 1 })) })
      return json({}, 404)
    }))
    renderRoutes([{ path: '/rules', element: <RulesPage /> }], '/rules', noRetryClient())
    const runs = await screen.findByRole('region', { name: '최근 탐지 실행 표' })
    expect(within(runs).getAllByRole('row')).toHaveLength(6)
    fireEvent.click(screen.getByRole('button', { name: '실행 이력 모두 보기' }))
    expect(within(runs).getAllByRole('row')).toHaveLength(13)
    fireEvent.click(screen.getByRole('button', { name: '최근 5회만' }))
    expect(within(runs).getAllByRole('row')).toHaveLength(6)
  })
  it('순환 규칙(R006 포함)은 오탐률 대신 순환 규칙으로 표시한다',async()=>{
    setup('/rules')
    const row=(await screen.findByRole('link',{name:'R006 · v3'})).closest('tr')!
    expect(within(row).getByText('순환 규칙')).toBeInTheDocument()
    // 마우스 올림 말풍선(title) 대신 누르면 펼치는 ⓘ. 터치 · 키보드로도 까닭을 본다
    const tip=within(row).getByRole('button',{name:'순환 규칙 설명'})
    expect(tip).toHaveAccessibleDescription(/규칙 조건과 판정 근거가 겹쳐 오탐률을 정확도 지표로 쓰지 않습니다/)
    expect(within(row).getByText('순환 규칙')).not.toHaveAttribute('title')
    fireEvent.click(tip)
    expect(tip).toHaveAttribute('aria-expanded','true')
    const plain=screen.getByRole('link',{name:'R001 · v2'}).closest('tr')!
    expect(within(plain).queryByText('순환 규칙')).toBeNull()
    expect(within(plain).queryByRole('button',{name:'순환 규칙 설명'})).toBeNull()
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
    // 구간이 정해지면 비교 표가 나오고, 해석 주의는 카드 머리 '저장된 사건 기준' 옆 ⓘ 에 있다
    expect(await screen.findByRole('columnheader',{name:'증감'})).toBeInTheDocument()
    expect(screen.queryByText('구간을 조회하고 서로 다른 두 버전을 고르세요.')).toBeNull()
    expect(screen.getByRole('button',{name:'저장된 사건 기준 설명'})).toHaveAccessibleDescription(/원문을 다시 실행하지 않고 저장된 결과만 비교합니다/)
    expect(screen.getByRole('button',{name:'조회 구간 설명'})).toHaveAccessibleDescription(/구간을 고르면 사건 시작 시각으로 셉니다/)
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
    // 상태 기준 · 해석은 '상태' 열 머리 ⓘ (이 표는 좁은 화면에서도 머리를 보인다). 조회 시각은 카드 머리
    expect(within(region).getByRole('columnheader',{name:/^상태/})).toHaveAccessibleDescription(/침묵: 등록 또는 마지막 수신 뒤 10분 넘게 없음.*서버 장애를 확정하지 않습니다/)
    expect(screen.getByRole('heading',{name:'등록 노드 3개'}).parentElement).toHaveTextContent(/KST 기준/)
    expect(screen.queryByText(/기준 · 30초마다 재조회/)).toBeNull()
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
    // 보안 경고는 본문에 그대로 둔다
    expect(screen.getByText('이 화면을 나가면 토큰 원문을 다시 조회할 수 없습니다.').closest('[data-infotip]')).toBeNull()
    expect(screen.getByText(/다시 발급하면 쓰지 않은 이전 토큰은 취소됩니다/).closest('[data-infotip]')).toBeNull()
    expect(screen.getByRole('button',{name:'재발급 설명'})).toHaveAccessibleDescription('이미 등록된 에이전트의 키는 그대로 둡니다.')
    expect(screen.getByRole('button',{name:'등록 · 첫 수신 확인 설명'})).toHaveAccessibleDescription(/재등록한 노드는 과거 수신 기록이 남아 있을 수 있습니다/)
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
  it('새 노드 화면은 재발급 설명 없이 토큰 수명만 적는다',async()=>{
    setup('/nodes/new')
    expect(await screen.findByRole('button',{name:'등록 토큰 발급'})).toBeInTheDocument()
    expect(screen.getByText('등록 토큰은 1시간 · 1회용입니다.')).toBeInTheDocument()
    expect(screen.queryByText(/이전 토큰은 취소됩니다/)).toBeNull()
    expect(screen.queryByRole('button',{name:'재발급 설명'})).toBeNull()
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
  it('계정 변경(#59)을 한글 이름으로 보이고 대상 아이디로 찾는다', async () => {
    const at = (eventid: string, detail: string) => ({ ...auditEntry(0), actor: eventid.endsWith('password.changed') ? 'cli:han' : 'root', target: 'kim', eventid, detail })
    const rows = [
      at('console.account.created', 'by=cli:han target=kim role=operator'), at('console.account.role.changed', 'by=root target=kim from=operator to=viewer'),
      at('console.account.disabled', 'by=root target=kim'), at('console.account.enabled', 'by=root target=kim'),
      at('console.account.password.changed', 'by=cli:han target=kim'), at('console.account.deleted', 'by=db:opsloop target=kim role=viewer'),
    ]
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/me') return json({ username: 'root', role: 'admin' })
      if (url.pathname === '/api/audit') return json({ rows, total: rows.length, limit: 25, offset: 0 })
      return json({}, 404)
    })
    vi.stubGlobal('fetch', fetch)
    renderRoutes([{ path: '/audit', element: <AuditPage /> }], '/audit', noRetryClient())
    const table = await screen.findByRole('region', { name: '감사 기록 표' })
    expect(within(table).getAllByRole('row').slice(1).map(r => within(r).getAllByRole('cell')[2].textContent)).toEqual(['계정 추가', '계정 역할 변경', '계정 비활성', '계정 재활성', '계정 비밀번호 변경', '계정 삭제'])
    expect(screen.getByText(/차단 · 노드 토큰 · 알림 채널 · 계정의 변경 이력입니다/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('대상'), { target: { value: 'kim' } })
    fireEvent.click(screen.getByRole('button', { name: '조회' }))
    await waitFor(() => expect(fetch.mock.calls.some(([raw]) => new URL(String(raw), 'http://localhost').searchParams.get('target') === 'kim')).toBe(true))
  })
  it('차단 감사는 한글 이름으로 보이고, 살아 있는 차단의 지점 넓힘(#77)은 차단 지점 넓힘이다', async () => {
    const at = (eventid: string, detail: string) => ({ ...auditEntry(0), actor: 'han', target: '203.0.113.10', eventid, detail })
    const rows = [at('console.block.points', 'ip=203.0.113.10 from=fw to=gateway,fw'), at('console.block.rearmed', 'ip=203.0.113.10 expires=x points=fw released_by=boss requested_by=boss')]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/me') return json({ username: 'root', role: 'admin' })
      if (url.pathname === '/api/audit') return json({ rows, total: rows.length, limit: 25, offset: 0 })
      return json({}, 404)
    }))
    renderRoutes([{ path: '/audit', element: <AuditPage /> }], '/audit', noRetryClient())
    const table = await screen.findByRole('region', { name: '감사 기록 표' })
    expect(within(table).getAllByRole('row').slice(1).map(r => within(r).getAllByRole('cell')[2].textContent)).toEqual(['차단 지점 넓힘', '차단 재요청'])
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
