import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DashboardPage } from './DashboardPage'
import { LiveContext } from '@/api/live-context'
import { applyLiveMessage } from '@/api/live'
import { noRetryClient, renderRoutes } from '@/test/render'
import { MONITORING_SUMMARY, json } from '@/test/monitoring-fixtures'
import { LATEST_KEY, nodeTarget, targetsResult } from '@/test/targets-fixtures'
import { revealHidden } from '@/lib/untrusted'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

afterEach(() => vi.unstubAllGlobals())
function renderPage() { return renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', noRetryClient()) }

type Answer = unknown | (() => Response)
/** 요약 · 대상 상태판 · CVE 배지에 답하는 fetch. 값 대신 함수를 주면 그 응답을 그대로 돌려준다 */
function stubDashboard({ summary = MONITORING_SUMMARY as Answer, targets = targetsResult() as Answer, badges = { as_of: '', available: true, badges: {} } as Answer } = {}) {
  const answer = (value: Answer) => (typeof value === 'function' ? (value as () => Response)() : json(value))
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/stats/summary') return answer(summary)
    if (url.pathname === '/api/dashboard/targets') return answer(targets)
    if (url.pathname === '/api/cti/badges') return answer(badges)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}
const paths = (fetch: ReturnType<typeof stubDashboard>) => fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost').pathname)

describe('대시보드', () => {
  it('요약 · 대상 상태판을 따로 조회해 경과 · 목표 초과를 표시하고 근거 사건으로 연결한다', async () => {
    const fetch = stubDashboard()
    renderPage()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
    expect(screen.getByText('판정 목표 초과')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /악성코드 투하/ })).toHaveAttribute('href', '/incidents/R003%7Cv2%7C192.0.2.8')
    expect(await screen.findByRole('region', { name: 'AWS 센서' })).toBeInTheDocument()
    expect(new Set(paths(fetch))).toEqual(new Set(['/api/stats/summary', '/api/dashboard/targets', '/api/cti/badges']))
  })

  it('제목은 관제 현황이고 대상 카드 → 수치 네 칸 → 먼저 확인할 사건 순서다', async () => {
    stubDashboard()
    renderPage()
    expect(screen.getByRole('heading', { level: 1, name: '관제 현황' })).toBeInTheDocument()
    const board = await screen.findByRole('heading', { level: 2, name: '관제 대상' })
    const metric = await screen.findByText('가장 오래된 미판정')
    const queue = screen.getByRole('heading', { name: '먼저 확인할 사건' })
    expect(board.compareDocumentPosition(metric) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(metric.compareDocumentPosition(queue) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    for (const name of ['AWS 센서', 'web-01', '관제 콘솔', '데이터 노드']) expect(screen.getByRole('region', { name })).toBeInTheDocument()
  })

  it('규칙별 비조치율 표는 규칙 화면으로 옮기고 여기서는 링크만 둔다', async () => {
    stubDashboard()
    renderPage()
    await screen.findByText('6시간 12분')
    expect(screen.queryByRole('heading', { name: '규칙별 비조치율' })).toBeNull()
    expect(screen.queryByText('30.0%')).toBeNull()
    expect(screen.getByRole('link', { name: '규칙 화면에서 보기' })).toHaveAttribute('href', '/rules')
  })

  it('대상 카드 조회가 실패해도 수치 네 칸 · 판정 대기열은 그대로 보이고 카드 자리만 오류다', async () => {
    stubDashboard({ targets: () => json({ detail: '상태판 집계 실패' }, 503) })
    renderPage()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /악성코드 투하/ })).toBeInTheDocument()
    const board = screen.getByRole('region', { name: '관제 대상' })
    const alert = await within(board).findByRole('alert')
    expect(alert).toHaveTextContent('상태판 집계 실패')
    expect(within(alert).getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
  })

  it('상태판 API 가 없는 이전 서버(404)는 콘솔 API 배포 전으로 알린다', async () => {
    stubDashboard({ targets: () => json({ detail: 'Not Found' }, 404) })
    renderPage()
    expect(await screen.findByText(/콘솔 API 배포 전/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '관제 대상' })).queryByRole('alert')).toBeNull()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
  })

  it('요약 조회가 실패해도 대상 카드는 보인다', async () => {
    stubDashboard({ summary: () => json({ detail: 'DB unavailable' }, 503) })
    renderPage()
    expect(await screen.findByRole('region', { name: 'AWS 센서' })).toBeInTheDocument()
    expect(await screen.findByText(/DB unavailable/)).toBeInTheDocument()
  })

  it('최근 사건 줄의 CVE 배지는 네 카드의 키를 모아 한 번에 묻는다', async () => {
    const fetch = stubDashboard({ badges: { as_of: '', available: true, badges: { [LATEST_KEY]: { cves: 1, kev: 1, applicability: 'unknown', stale: true } } } })
    renderPage()
    const aws = await screen.findByRole('region', { name: 'AWS 센서' })
    expect(await within(aws).findByText('CVE 1 · KEV 1 · 자산 미확인')).toHaveAttribute('title', '공개 정보 48시간 넘음 · 우리 자산 해당 여부를 확정하지 않음')
    const calls = fetch.mock.calls.map(([input]) => String(input)).filter((url) => url.startsWith('/api/cti/badges'))
    expect(calls).toHaveLength(1)
    expect(new URL(calls[0], 'http://localhost').searchParams.getAll('key')).toEqual(['R105|c1|203.0.113.7|2026-09-28T09:40:00+00:00', 'R201|v2|user:root|x'])
  })

  it('배지 조회가 실패해도 카드는 배지 없이 그린다', async () => {
    stubDashboard({ badges: () => json({ detail: '배지 실패' }, 503) })
    renderPage()
    const aws = await screen.findByRole('region', { name: 'AWS 센서' })
    expect(within(aws).getByRole('link', { name: /R105/ })).toBeInTheDocument()
    expect(aws.querySelector('[data-cti-badge]')).toBeNull()
  })

  it('카드 합이 전체와 다른 까닭과 대상 미분류 사건을 숨기지 않는다', async () => {
    stubDashboard({ targets: targetsResult({ unmapped: { incidents_1h: 2, pending: 5 } }) })
    renderPage()
    expect(await screen.findByText(/카드 수치는 대상별입니다. 한 사건이 여러 대상에 걸칠 수 있어 합이 전체와 다릅니다./)).toBeInTheDocument()
    expect(screen.getByText('대상 미분류 사건: 최근 1시간 2 · 미판정 5')).toBeInTheDocument()
  })

  it('미분류 사건이 없으면 그 줄을 그리지 않는다', async () => {
    stubDashboard()
    renderPage()
    await screen.findByRole('region', { name: 'AWS 센서' })
    expect(screen.queryByText(/대상 미분류 사건/)).toBeNull()
  })

  it('모바일(sm 미만)은 대상마다 한 줄로 접고 누르면 그 카드를 펼친다', async () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })))
    stubDashboard()
    renderPage()
    const list = await screen.findByRole('list', { name: '관제 대상 요약' })
    const buttons = within(list).getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual(['▸AWS 센서정상미판정 12', '▸web-01요청 없음미판정 0', '▸관제 콘솔생존 상태 미확인미판정 1', '▸데이터 노드수신 없음미판정 0'])
    expect(screen.queryByRole('region', { name: 'AWS 센서' })).toBeNull()
    fireEvent.click(buttons[0])
    expect(buttons[0]).toHaveAttribute('aria-expanded', 'true')
    const card = screen.getByRole('region', { name: 'AWS 센서' })
    expect(card).toHaveTextContent('차단 적용 2 (AWS 관문)')
    expect(buttons[0]).toHaveAttribute('aria-controls', card.parentElement?.id)
    fireEvent.click(buttons[0])
    expect(screen.queryByRole('region', { name: 'AWS 센서' })).toBeNull()
  })

  it('대상 카드 갱신이 실패하면 이전 카드를 유지하고 다시 조회를 둔다', async () => {
    let fail = false
    stubDashboard({ targets: () => (fail ? json({ detail: '상태판 집계 실패' }, 503) : json(targetsResult())) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByRole('region', { name: 'AWS 센서' })
    fail = true
    await act(async () => { await client.invalidateQueries({ queryKey: ['dashboard', 'targets'] }) })
    const status = await screen.findByText('대상 카드를 갱신하지 못했습니다')
    expect(status.closest('[role="status"]')).toHaveTextContent('이전 결과 유지')
    expect(screen.getByRole('region', { name: 'AWS 센서' })).toBeInTheDocument()
    fail = false
    fireEvent.click(within(status.closest('[role="status"]') as HTMLElement).getByRole('button', { name: '다시 조회' }))
    await waitFor(() => expect(screen.queryByText('대상 카드를 갱신하지 못했습니다')).toBeNull())
  })

  it('활성 차단 요청을 집행 확인 · 대기 · 제외로 나눠 막은 수로 읽히지 않게 한다(이슈 #47)', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 16, blocks: { enforced: 2, pending: 0, excluded: 13, mismatch: 1 } } })
    renderPage()
    expect(await screen.findByText('활성 차단 요청 16건')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '집행 확인 2 · 대기 0 · 제외 13' })).toHaveAttribute('href', '/blocklist')
    expect(screen.getByText('관문 불일치 1건')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '16건' })).toBeNull()
  })

  it('집행 상태가 없는 이전 서버는 요청 수와 미확인을 보인다', async () => {
    // JSON 은 undefined 칸을 싣지 않는다(이전 서버처럼 blocks 가 없다)
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocks: undefined } })
    renderPage()
    expect(await screen.findByRole('link', { name: '2건 · 집행 상태 미확인' })).toBeInTheDocument()
  })

  it('판정 뒤에 흡수됐는데 차단이 없는 출발지를 활성 차단 옆에 알린다', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, absorbed_unblocked: { sources: 12, incidents: 2, first_key: 'R006|v3|192.0.2.1|x' } } })
    renderPage()
    expect(await screen.findByText('판정 뒤 흡수 미차단 12곳 · 첫 사건 2건')).toBeInTheDocument()
  })

  it('0건도 정상 수신 여부를 확인하도록 안내하며 비율을 만들어내지 않는다', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, pending: { total: 0, overdue: 0, warning: 0, oldest_seconds: 0, age_distribution: [0,0,0,0,0] }, oldest_pending: [], rule_quality: [] } })
    renderPage()
    expect(await screen.findByText(/미판정 사건이 없습니다/)).toBeInTheDocument()
    expect(screen.queryByText('0.0%')).toBeNull()
  })

  it('옛 API 응답을 0건으로 표시하지 않고 서버 버전을 안내한다', async () => {
    stubDashboard({ summary: { open_by_severity: {} } })
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('이전 버전')
  })

  it('웹소켓 판정 통보로 요약과 대상 카드를 다시 조회한다', async () => {
    const client = noRetryClient()
    let total = 12
    stubDashboard({
      summary: () => json({ ...MONITORING_SUMMARY, pending: { ...MONITORING_SUMMARY.pending, total } }),
      targets: () => {
        const result = targetsResult()
        result.targets[0].security.pending = total
        return json(result)
      },
    })
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByRole('link', { name: '12건' })
    const aws = await screen.findByRole('region', { name: 'AWS 센서' })
    expect(aws).toHaveTextContent('높음 이상 1 · 미판정 12')
    total = 11
    act(() => applyLiveMessage(client, { type: 'verdict.created', data: { incident_key: 'k' } }))
    expect(await screen.findByRole('link', { name: '11건' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('region', { name: 'AWS 센서' })).toHaveTextContent('높음 이상 1 · 미판정 11'))
  })

  it('조회 실패 시 이전 수치를 유지하고 마지막 조회와 다시 시도를 표시한다', async () => {
    let fail = false
    stubDashboard({ summary: () => fail ? json({ detail: 'DB unavailable' }, 503) : json(MONITORING_SUMMARY) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByText('6시간 12분')
    fail = true
    await act(async () => { await client.invalidateQueries() })
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('이전 결과 유지')
    expect(screen.getByText('6시간 12분')).toBeInTheDocument()
    fail = false
    fireEvent.click(within(alert).getByRole('button', { name: '다시 조회' }))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })

  it('S-10은 실시간 끊김과 주기 조회를 안내하며 작성·조회 상태를 지우지 않는다', async () => {
    stubDashboard()
    renderRoutes([{ path: '/', element: <LiveContext.Provider value={{ status: 'reconnecting', retries: 1 }}><DashboardPage /></LiveContext.Provider> }], '/', noRetryClient())
    expect(await screen.findByText('실시간 연결이 끊겼습니다')).toBeInTheDocument()
    expect(screen.getByText(/30초마다 별도로 조회/)).toBeInTheDocument()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
  })
})

describe('대시보드 · 비신뢰 문자열(#41)', () => {
  it('먼저 확인할 사건의 대상은 표식으로 바꾼 뒤 한 줄로 자르고 링크 안에 단추를 두지 않는다', async () => {
    const base = MONITORING_SUMMARY.oldest_pending[0]
    const oldest = [
      { ...base, incident_key: `R201|v2|user:${MIXED}|x`, rule_id: 'R201', actor_ip: null, target: `user:${MIXED}` },
      { ...base, incident_key: 'R201|v2|user:long|x', rule_id: 'R201', actor_ip: null, target: `user:${LONG}` },
    ]
    stubDashboard({ summary: { ...MONITORING_SUMMARY, oldest_pending: oldest } })
    const { container } = renderPage()
    const first = await screen.findByTitle(revealHidden(`user:${MIXED}`))
    expect(first).toHaveClass('truncate')
    expectInertDom(container)
    expectMixedRevealed(container)
    const long = screen.getByTitle(`user:${LONG}`)
    expect(long.textContent).toBe(`user:${'L'.repeat(495)}…`)
    expect(long.closest('a')?.querySelector('button')).toBeNull()
  })

  it('먼저 확인할 사건의 긴 규칙 이름도 링크 안에서 단추 없이 잘리고 전체는 말풍선으로 본다', async () => {
    const base = MONITORING_SUMMARY.oldest_pending[0]
    stubDashboard({ summary: { ...MONITORING_SUMMARY, oldest_pending: [{ ...base, rule_name: LONG }] } })
    renderPage()
    const name = await screen.findByTitle(LONG)
    expect(name.textContent).toBe(`${base.rule_id}${'L'.repeat(500)}…`)
    const link = name.closest('a')
    expect(link).not.toBeNull()
    expect(link?.querySelector('button')).toBeNull()
  })
})

describe('대시보드 · 등록 노드 카드(#64)', () => {
  /** 고정 네 대상 뒤에 등록 노드 n 개 */
  const withNodes = (...ids: string[]) => targetsResult({ targets: [...targetsResult().targets, ...ids.map((id) => nodeTarget(id))] })
  const narrow = () => vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })))

  it.each([
    ['5개', ['web-02']],
    ['6개', ['web-02', 'web-03']],
  ])('카드 %s: 등록 노드는 고정 네 대상 뒤에 붙고 그리드 규칙(sm 두 개 · 2xl 네 개씩)은 그대로다', async (_name, ids) => {
    stubDashboard({ targets: withNodes(...ids) })
    renderPage()
    const board = await screen.findByRole('region', { name: '관제 대상' })
    await within(board).findByRole('region', { name: 'opsloop-web-02' })
    const cards = [...board.querySelectorAll<HTMLElement>('[data-target]')]
    expect(cards.map((c) => c.dataset.target)).toEqual(['aws-sensor', 'web-01', 'console', 'data-node', ...ids])
    expect(cards.map((c) => c.dataset.targetKind)).toEqual(['fixed', 'fixed', 'fixed', 'fixed', ...ids.map(() => 'node')])
    // 카드는 모두 한 그리드의 칸이다. 넘치는 카드는 다음 줄로 간다(가로 스크롤 없음)
    const grid = cards[0].parentElement as HTMLElement
    expect(grid).toHaveClass('grid', 'sm:grid-cols-2', '2xl:grid-cols-4')
    expect(cards.every((c) => c.parentElement === grid)).toBe(true)
  })

  it('서버가 섞어 보내도 고정 대상이 앞이다', async () => {
    const [aws, web, con, data] = targetsResult().targets
    stubDashboard({ targets: targetsResult({ targets: [nodeTarget('web-02'), aws, web, con, data] }) })
    renderPage()
    const board = await screen.findByRole('region', { name: '관제 대상' })
    await within(board).findByRole('region', { name: 'opsloop-web-02' })
    expect([...board.querySelectorAll<HTMLElement>('[data-target]')].map((c) => c.dataset.target)).toEqual(['aws-sensor', 'web-01', 'console', 'data-node', 'web-02'])
  })

  it('최근 사건의 CVE 배지는 등록 노드 카드의 키도 한 번에 묻는다', async () => {
    const fetch = stubDashboard({ targets: withNodes('web-02') })
    renderPage()
    await screen.findByRole('region', { name: 'opsloop-web-02' })
    await waitFor(() => expect(fetch.mock.calls.some(([input]) => String(input).startsWith('/api/cti/badges'))).toBe(true))
    const calls = fetch.mock.calls.map(([input]) => String(input)).filter((url) => url.startsWith('/api/cti/badges'))
    expect(calls).toHaveLength(1)
    expect(new URL(calls[0], 'http://localhost').searchParams.getAll('key').toSorted()).toEqual(['R101|v3|198.51.100.9|web-02', LATEST_KEY, 'R201|v2|user:root|x'])
  })

  it('모바일은 등록 노드도 한 줄로 접히고(6줄) 누르면 그 카드를 펼친다', async () => {
    narrow()
    stubDashboard({ targets: withNodes('web-02', 'web-03') })
    renderPage()
    const list = await screen.findByRole('list', { name: '관제 대상 요약' })
    const buttons = within(list).getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual([
      '▸AWS 센서정상미판정 12', '▸web-01요청 없음미판정 0', '▸관제 콘솔생존 상태 미확인미판정 1', '▸데이터 노드수신 없음미판정 0',
      '▸opsloop-web-02정상미판정 3', '▸opsloop-web-03정상미판정 3'])
    expect(screen.queryByRole('region', { name: 'opsloop-web-02' })).toBeNull()
    fireEvent.click(buttons[4])
    const card = screen.getByRole('region', { name: 'opsloop-web-02' })
    expect(card).toHaveTextContent('등록 노드 · web-02')
    expect(card).toHaveTextContent('차단 적용 여부 미확인')
    expect(buttons[4]).toHaveAttribute('aria-controls', card.parentElement?.id)
    // 요소 id 에는 노드 id 가 아니라 순번이 들어간다
    expect(card.parentElement?.id).not.toContain('web-02')
    expect(screen.queryByRole('region', { name: 'opsloop-web-03' })).toBeNull()
  })

  it('악성 hostname 은 카드 · 접힌 줄 모두 표식으로 보이고 실행 · 외부 요청을 만들지 않는다', async () => {
    const hostile = nodeTarget('web-02', { label: MIXED })
    stubDashboard({ targets: targetsResult({ targets: [...targetsResult().targets, hostile], unmapped: { incidents_1h: 1, pending: 1 } }) })
    const wide = renderPage()
    const board = await screen.findByRole('region', { name: '관제 대상' })
    await waitFor(() => expect(board.querySelector('[data-target="web-02"]')).not.toBeNull())
    const title = board.querySelector('[data-target="web-02"] h3') as HTMLElement
    expect(title).toHaveAttribute('title', revealHidden(MIXED))
    expect(title).toHaveTextContent(/^<img src=\/\/a\.attacker\.test/)
    expectInertDom(wide.container)
    expect(screen.getByText('대상 미분류 사건: 최근 1시간 1 · 미판정 1')).toBeInTheDocument()
    wide.unmount()

    narrow()
    const folded = renderPage()
    const list = await screen.findByRole('list', { name: '관제 대상 요약' })
    const row = within(list).getAllByRole('button').at(-1) as HTMLElement
    expect(row.querySelector('[title]')).toHaveAttribute('title', revealHidden(MIXED))
    // 253자에서 자르고(펼치기 단추 없음) 전체는 말풍선으로 본다
    expect(row.textContent).toMatch(/^▸<img src=\/\/a\.attacker\.test\/p\.png onerror=alert\(1\)>.*…정상미판정 3$/)
    fireEvent.click(row)
    expect(row.querySelector('button')).toBeNull()
    expectInertDom(folded.container)
  })

  it('짧은 악성 hostname 은 자르지 않고 모든 표식을 보인다', async () => {
    narrow()
    const label = `${HOSTILE.rlo}${HOSTILE.zwsp}${HOSTILE.bom}`
    stubDashboard({ targets: targetsResult({ targets: [...targetsResult().targets, nodeTarget('web-02', { label })] }) })
    const { container } = renderPage()
    const list = await screen.findByRole('list', { name: '관제 대상 요약' })
    expect(within(list).getAllByRole('button').at(-1)).toHaveTextContent('admin⟨U+202E⟩gnp.exead⟨U+200B⟩min⟨U+FEFF⟩')
    expectInertDom(container)
  })
})
