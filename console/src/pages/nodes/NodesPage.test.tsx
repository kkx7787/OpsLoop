import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LiveContext } from '@/api/live-context'
import type { NodeEntry } from '@/api/operations'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { nodeEntry } from '@/test/operations-fixtures'
import { LATEST_KEY, awsSensor, consoleTarget, dataNode, dataNodeStopped, nodeTarget, targetsResult, web01 } from '@/test/targets-fixtures'
import { NodesPage } from './NodesPage'

type Answer = unknown | (() => Response | Promise<Response>)
const answer = (value: Answer) => (typeof value === 'function' ? (value as () => Response | Promise<Response>)() : json(value))

/** 등록 노드 넷: web-01(고정 카드) · web-02(등록 노드 카드) · pend-01(등록 대기, 카드 없음) · old-01(폐기, 카드 없음) */
const NODES: NodeEntry[] = [
  nodeEntry(),
  nodeEntry({ node_id: 'web-02', hostname: 'opsloop-web-02', addr: '192.0.2.22' }),
  nodeEntry({ node_id: 'pend-01', hostname: 'opsloop-pend-01', reception: 'waiting', last_seen_at: null }),
  nodeEntry({ node_id: 'old-01', hostname: 'opsloop-old-01', reception: 'revoked', status: 'revoked' }),
]
const TARGETS = () => targetsResult({ targets: [awsSensor(), web01(), consoleTarget(), dataNode(), nodeTarget('web-02')] })

function stub({ role = 'admin', nodes = { as_of: NODES[0].checked_at, rows: NODES } as Answer, targets = TARGETS() as Answer, badges = { as_of: '', available: true, badges: {} } as Answer } = {}) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'tester', role })
    if (url.pathname === '/api/nodes') return answer(nodes)
    if (url.pathname === '/api/dashboard/targets') return answer(targets)
    if (url.pathname === '/api/cti/badges') return answer(badges)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}
const paths = (fetch: ReturnType<typeof stub>) => fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost').pathname)
function renderPage(path = '/nodes', client = noRetryClient()) {
  return { client, ...renderRoutes([{ path: '/nodes', element: <NodesPage /> }], path, client) }
}
const pageStatus = () => document.querySelector<HTMLElement>('[data-page-status]') as HTMLElement
const table = () => screen.getByRole('region', { name: '등록 노드 표' })
const rowOf = (id: string) => within(table()).getByText(id).closest('tr') as HTMLElement
/** 접힌 목록의 한 줄 단추 글 */
const rows = (name: string) => within(screen.getByRole('list', { name })).getAllByRole('button').map((b) => b.textContent)
const summary = (id: string) => document.querySelector<HTMLElement>(`[data-target-summary="${id}"]`) as HTMLElement
/** 접힌 줄 단추(펼친 카드 안의 ⓘ 단추는 빼고) */
const rowButton = (id: string) => summary(id).querySelector(':scope > button') as HTMLButtonElement
function expand(id: string): HTMLElement {
  fireEvent.click(rowButton(id))
  return summary(id).querySelector('[data-target]') as HTMLElement
}

const scrollIntoView = vi.fn<(this: HTMLElement, options?: boolean | ScrollIntoViewOptions) => void>()
beforeEach(() => {
  scrollIntoView.mockReset()
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, writable: true, value: scrollIntoView })
})
afterEach(() => {
  vi.unstubAllGlobals()
  delete (HTMLElement.prototype as Partial<HTMLElement>).scrollIntoView
})

describe('수집 · 관제 상태(#84)', () => {
  it('제목은 수집 · 관제 상태이고 등록 노드 → 관측 센서 → 관제 시스템 세 구역이다. 노드 추가 · 재발급 동선은 그대로다', async () => {
    stub()
    renderPage()
    expect(screen.getByRole('heading', { level: 1, name: '수집 · 관제 상태' })).toBeInTheDocument()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    await screen.findByText('pend-01')
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings).toEqual(['등록 노드', '관측 센서', '관제 시스템'])
    expect([...document.querySelectorAll<HTMLElement>('[data-status-section]')].map((s) => s.dataset.statusSection)).toEqual(['nodes', 'sensors', 'system'])
    expect(screen.getByRole('region', { name: '등록 노드' })).toContainElement(table())
    expect(screen.getByRole('heading', { level: 3, name: '등록 노드 4개' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '노드 추가' })).toHaveAttribute('href', '/nodes/new')
    expect(within(rowOf('web-02')).getByRole('link', { name: '재발급' })).toHaveAttribute('href', '/nodes/new?node=web-02')
    expect(screen.getByRole('link', { name: '자산 · 취약점' })).toHaveAttribute('href', '/inventory')
  })

  it('보호 대상 노드 행에만 최근 로그 링크를 둔다(상태판의 보호 대상 카드가 있는 노드). 등록 대기 · 폐기 · 카드 없는 노드는 없다', async () => {
    stub()
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    await waitFor(() => expect(within(rowOf('web-02')).queryByRole('link', { name: 'web-02 최근 로그' })).not.toBeNull())
    expect(within(rowOf('web-01')).getByRole('link', { name: 'web-01 최근 로그' })).toHaveAttribute('href', '/devices/web-01/logs')
    expect(within(rowOf('web-02')).getByRole('link', { name: 'web-02 최근 로그' })).toHaveTextContent('최근 로그 →')
    expect(within(rowOf('web-02')).getByRole('link', { name: 'web-02 최근 로그' })).toHaveAttribute('href', '/devices/web-02/logs')
    for (const id of ['pend-01', 'old-01']) expect(within(rowOf(id)).queryByRole('link', { name: /최근 로그/ })).toBeNull()
  })

  it('노드 id 에 주소 조각 글자가 있으면 감싸서 잇는다', async () => {
    stub({ nodes: { as_of: NODES[0].checked_at, rows: [nodeEntry({ node_id: 'a b/1' })] }, targets: targetsResult({ targets: [...TARGETS().targets, nodeTarget('a b/1')] }) })
    renderPage()
    expect(await screen.findByRole('link', { name: 'a b/1 최근 로그' })).toHaveAttribute('href', '/devices/a%20b%2F1/logs')
  })

  it('상태판 카드의 자원 지표가 오래됐으면 노드 상태 칸에 지표 오래됨(주의색), 기준은 상태 ⓘ 에 있다', async () => {
    const stale = { state: 'stale' as const, metrics: web01().system.metrics }
    stub({ targets: targetsResult({ targets: [awsSensor(), web01(), consoleTarget(), dataNode(), nodeTarget('web-02', { system: stale })] }) })
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    const badge = await within(rowOf('web-02')).findByText('지표 오래됨')
    expect(badge).toHaveClass('bg-warning-soft')
    expect(badge.closest('td')).toHaveTextContent(/^정상지표 오래됨$/)
    expect(within(rowOf('web-01')).queryByText('지표 오래됨')).toBeNull()
    expect(within(table()).getByRole('columnheader', { name: /^상태/ })).toHaveAccessibleDescription(/지표 오래됨: 마지막 자원 지표가 10분 넘음/)
  })

  it('상태판 조회가 처음부터 실패하면 두 구역 제목 위에 오류 하나(다시 시도 하나)이고, 노드 표는 그대로 보이되 최근 로그 링크는 없다', async () => {
    stub({ targets: () => json({ detail: '상태판 집계 실패' }, 503) })
    renderPage()
    await screen.findByText('pend-01')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('상태판 집계 실패')
    // 제목이 어느 조회인지 이름을 가진다(제목 탐색에서 등록 노드 아래 오류로 들리지 않게)
    expect(within(alert).getByRole('heading', { level: 3 })).toHaveTextContent(/^관측 센서 · 관제 시스템을 불러오지 못했습니다$/)
    expect(screen.getAllByRole('alert')).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '다시 시도' })).toHaveLength(1)
    const sensors = screen.getByRole('heading', { level: 2, name: '관측 센서' })
    expect(alert.compareDocumentPosition(sensors) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByRole('heading', { level: 2, name: '관제 시스템' })).toBeInTheDocument()
    expect(within(table()).queryByRole('link', { name: /최근 로그/ })).toBeNull()
  })

  it('상태판 API 가 없는 이전 서버(404)는 배포 전 한 줄이고 갱신 실패로 세지 않는다', async () => {
    stub({ targets: () => json({ detail: 'Not Found' }, 404) })
    renderPage()
    expect(await screen.findByText(/콘솔 API 배포 전/)).toHaveAttribute('data-targets-missing')
    await screen.findByText('pend-01')
    expect(screen.queryByRole('alert')).toBeNull()
    await waitFor(() => expect(pageStatus()).toHaveTextContent(/^기준 \d\d:\d\d:\d\d$/))
  })

  it('노드 조회가 처음부터 실패해도 관측 센서 · 관제 시스템은 보인다', async () => {
    stub({ nodes: () => json({ detail: '일시 오류' }, 503) })
    renderPage()
    expect(await within(screen.getByRole('region', { name: '등록 노드' })).findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(await screen.findByRole('list', { name: '관측 센서 요약' })).toBeInTheDocument()
    expect(screen.getByRole('list', { name: '관제 시스템 요약' })).toBeInTheDocument()
  })

  it('두 조회가 모두 처음부터 실패하면 오류 제목이 어느 조회인지로 갈린다(같은 제목 둘이 아니다)', async () => {
    stub({ nodes: () => json({ detail: '일시 오류' }, 503), targets: () => json({ detail: '일시 오류' }, 503) })
    renderPage()
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2))
    expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual(['등록 노드를 불러오지 못했습니다', '관측 센서 · 관제 시스템을 불러오지 못했습니다'])
    expect(screen.queryByRole('heading', { name: '데이터를 불러오지 못했습니다' })).toBeNull()
  })

  it('기준 시각은 제목 줄 하나(노드 · 상태판)이고 표 머리 시각 · 조회 실패 띠는 없다. 새로고침은 두 조회를 모두 다시 받는다', async () => {
    const fetch = stub()
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    await waitFor(() => expect(pageStatus()).toHaveTextContent(/^기준 \d\d:\d\d:\d\d$/))
    expect(document.querySelectorAll('[data-as-of]')).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 3, name: '등록 노드 4개' }).parentElement).not.toHaveTextContent(/KST 기준/)
    expect(screen.queryByText('데이터를 갱신하지 못했습니다')).toBeNull()
    const count = (path: string) => paths(fetch).filter((p) => p === path).length
    const before = [count('/api/nodes'), count('/api/dashboard/targets')]
    fireEvent.click(within(pageStatus()).getByRole('button', { name: '새로고침' }))
    await waitFor(() => expect([count('/api/nodes'), count('/api/dashboard/targets')].every((n, i) => n > before[i])).toBe(true))
  })

  it('받은 뒤 갱신이 실패하면 제목 줄 일부 갱신 실패, 그 구역에 이전 결과(콘솔은 응답 중 대신 이전 결과 하나)', async () => {
    let failNodes = false
    let failTargets = false
    stub({ nodes: () => (failNodes ? json({ detail: '일시 오류' }, 503) : json({ as_of: NODES[0].checked_at, rows: NODES })), targets: () => (failTargets ? json({ detail: '상태판 집계 실패' }, 503) : json(TARGETS())) })
    const { client } = renderPage()
    await screen.findByRole('list', { name: '관제 시스템 요약' })
    await screen.findByText('pend-01')
    const live = within(pageStatus()).getByRole('status')
    expect(live).toBeEmptyDOMElement()
    expect(summary('console').querySelector('[data-head-badge]')).toHaveTextContent('응답 중')
    failNodes = true
    await act(async () => { await client.invalidateQueries({ queryKey: ['nodes'] }) })
    await waitFor(() => expect(pageStatus()).toHaveTextContent('일부 갱신 실패'))
    expect(live).toHaveTextContent(/^일부 갱신 실패$/)
    const head = screen.getByRole('heading', { level: 3, name: '등록 노드 4개' }).parentElement as HTMLElement
    expect(within(head).getByText('이전 결과')).toHaveAttribute('data-stale-badge')
    expect(screen.getByText('pend-01')).toBeInTheDocument()
    expect(summary('aws-sensor').querySelector('[data-stale-badge]')).toBeNull()
    failNodes = false
    failTargets = true
    await act(async () => { await client.invalidateQueries() })
    await waitFor(() => expect(summary('aws-sensor').querySelector('[data-stale-badge]')).not.toBeNull())
    expect(within(head).queryByText('이전 결과')).toBeNull()
    for (const id of ['aws-sensor', 'console', 'data-node']) expect(summary(id).querySelector('[data-stale-badge]')).toHaveTextContent('이전 결과')
    // '응답 중' 은 이번 조회에 응답했다는 사실이라 갱신 실패 동안 두지 않는다(결정 5)
    expect(summary('console').querySelector('[data-head-badge]')).toBeNull()
    expect(rowButton('console')).not.toHaveTextContent('응답 중')
    expect(summary('aws-sensor').querySelector('[data-head-badge]')).toHaveTextContent('정상')
  })

  it('실시간 연결이 끊기면 이 화면은 공통 끊김 띠를 그대로 보인다(대시보드만 띠 항목으로 합친다)', async () => {
    stub()
    renderRoutes([{ path: '/nodes', element: <LiveContext.Provider value={{ status: 'reconnecting', retries: 1 }}><NodesPage /></LiveContext.Provider> }], '/nodes', noRetryClient())
    expect(await screen.findByText('실시간 연결이 끊겼습니다')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '지금 조회' })).toBeInTheDocument()
  })
})

describe('수집 · 관제 상태 · 관측 센서 · 관제 시스템 접힌 줄(대시보드에서 옮김)', () => {
  it('넓은 화면에서도 접혀 있고 누르면 그 자리에 카드가 펼쳐진다. 줄 단추 안에는 링크가 없다', async () => {
    stub()
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    expect(rows('관측 센서 요약')).toEqual(['▸허니팟 센서정상적용 확인 중 1건미판정 12'])
    expect(rows('관제 시스템 요약')).toEqual(['▸관제 콘솔응답 중미판정 1', '▸데이터 노드수신 없음미판정 0'])
    expect(screen.queryByRole('region', { name: '허니팟 센서' })).toBeNull()
    const aws = expand('aws-sensor')
    expect(screen.getByRole('region', { name: '허니팟 센서' })).toBe(aws)
    expect(aws).toHaveTextContent('차단 적용 2 (허니팟 관문)')
    expect(within(aws).getByRole('link', { name: '미판정 12' })).toHaveAttribute('href', '/incidents?judged=false&device=aws-sensor')
    for (const button of within(screen.getByRole('list', { name: '관측 센서 요약' })).getAllByRole('button')) expect(button.querySelector('a')).toBeNull()
    // 콘솔을 펼치면 DB 연결 확인 줄(#76)
    expect(expand('console').querySelector('[data-db-links]')).toHaveTextContent('DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)')
  })

  it('접힌 줄은 머리 배지(데이터 노드 확인 멈춤은 주의)와 요약 배지(적용 실패 · 집행기 · 적재기 멈춤)를 보인다', async () => {
    const aws = awsSensor({ response: { ...awsSensor().response, failed: 2, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' } })
    const failedOnly = awsSensor({ response: { ...awsSensor().response, failed: 2 } })
    stub({ targets: targetsResult({ targets: [aws, web01(), consoleTarget(), dataNodeStopped()] }) })
    const view = renderPage()
    await screen.findByRole('list', { name: '관제 시스템 요약' })
    // 같은 지점의 집행기 멈춤과 겹치면 그 경고 하나다(결정 6)
    expect(rows('관측 센서 요약')).toEqual(['▸허니팟 센서정상집행기 멈춤미판정 12'])
    expect(rows('관제 시스템 요약')).toEqual(['▸관제 콘솔응답 중미판정 1', '▸데이터 노드주의적재기 멈춤집행기 멈춤미판정 0'])
    const data = summary('data-node')
    expect(data.querySelector('[data-head-badge]')).toHaveClass('bg-warning-soft')
    expect(data.querySelector('[data-summary-flag="loader"]')).toHaveClass('bg-warning-soft')
    expect(expand('data-node')).toHaveAttribute('data-collection', 'ok')
    view.unmount()

    stub({ targets: targetsResult({ targets: [failedOnly, web01(), consoleTarget(), dataNode()] }) })
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    expect(rows('관측 센서 요약')).toEqual(['▸허니팟 센서정상적용 실패 2건미판정 12'])
    expect(summary('aws-sensor').querySelector('[data-summary-flag="failed"]')).toHaveClass('bg-danger-soft')
  })

  it('최근 사건 CVE 배지는 관측 센서 · 관제 시스템 키만 한 번에 묻고 펼친 카드에 보인다', async () => {
    const fetch = stub({ badges: { as_of: '', available: true, badges: { [LATEST_KEY]: { cves: 1, kev: 1, applicability: 'unknown', stale: true } } } })
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    await waitFor(() => expect(paths(fetch)).toContain('/api/cti/badges'))
    const calls = fetch.mock.calls.map(([input]) => String(input)).filter((url) => url.startsWith('/api/cti/badges'))
    expect(calls).toHaveLength(1)
    expect(new URL(calls[0], 'http://localhost').searchParams.getAll('key').toSorted()).toEqual([LATEST_KEY, 'R201|v2|user:root|x'])
    expect(await within(expand('aws-sensor')).findByText('CVE 1 · KEV 1 · 자산 미확인')).toBeInTheDocument()
  })

  it('배지 조회가 실패해도 카드는 배지 없이 그린다', async () => {
    stub({ badges: () => json({ detail: '배지 실패' }, 503) })
    renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    const aws = expand('aws-sensor')
    expect(within(aws).getByRole('link', { name: /R105/ })).toBeInTheDocument()
    expect(aws.querySelector('[data-cti-badge]')).toBeNull()
  })
})

describe('수집 · 관제 상태 · ?open 펼침(#84)', () => {
  it.each([
    ['aws-sensor', '관측 센서 요약', '허니팟 센서'],
    ['data-node', '관제 시스템 요약', '데이터 노드'],
  ])('?open=%s 면 그 줄만 펼치고 조회가 끝난 뒤 한 번 스크롤하며 줄 단추에 초점을 준다', async (id, list, name) => {
    stub()
    renderPage(`/nodes?open=${id}`)
    const card = await screen.findByRole('region', { name })
    const button = rowButton(id)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    expect(summary(id)).toContainElement(card)
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1))
    expect(scrollIntoView.mock.contexts[0]).toBe(summary(id))
    expect(scrollIntoView).toHaveBeenCalledWith({ block: 'start' })
    expect(document.activeElement).toBe(button)
    // 상단바(sticky) 아래로 오게 위 여백을 둔다
    expect(summary(id)).toHaveClass('scroll-mt-16')
    const others = [...document.querySelectorAll<HTMLElement>('[data-target-summary]')].filter((li) => li.dataset.targetSummary !== id)
    for (const li of others) expect(rowButton(li.dataset.targetSummary as string)).toHaveAttribute('aria-expanded', 'false')
    expect(within(screen.getByRole('list', { name: list })).getAllByRole('button').filter((b) => b.getAttribute('aria-expanded') === 'true')).toHaveLength(1)
  })

  it.each(['web-01', 'bogus', ''])('?open=%s(보호 대상 · 모르는 값)은 무시한다', async (value) => {
    stub()
    renderPage(`/nodes?open=${value}`)
    await screen.findByRole('list', { name: '관측 센서 요약' })
    await screen.findByText('pend-01')
    for (const li of document.querySelectorAll<HTMLElement>('[data-target-summary]')) expect(rowButton(li.dataset.targetSummary as string)).toHaveAttribute('aria-expanded', 'false')
    expect(scrollIntoView).not.toHaveBeenCalled()
  })

  it('노드 표가 상태판보다 늦게 와도 표를 그린 뒤에 한 번만 스크롤한다(펼친 줄이 밀려나지 않게)', async () => {
    let release: (() => void) | undefined
    const late = () => new Promise<Response>((resolve) => { release = () => resolve(json({ as_of: NODES[0].checked_at, rows: NODES })) })
    stub({ nodes: late })
    scrollIntoView.mockImplementation(() => {
      // 부를 때 노드 표가 이미 있어야 한다
      expect(document.querySelector('[aria-label="등록 노드 표"]')).not.toBeNull()
    })
    renderPage('/nodes?open=data-node')
    await screen.findByRole('region', { name: '데이터 노드' })
    await act(async () => { await new Promise((r) => setTimeout(r, 20)) })
    expect(scrollIntoView).not.toHaveBeenCalled()
    await act(async () => { release?.() })
    await screen.findByText('pend-01')
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1))
  })

  it('상태판이 노드 표보다 늦게 와도 받은 뒤 펼치고 스크롤한다. 주기 재조회로는 다시 스크롤하지 않는다', async () => {
    let release: (() => void) | undefined
    let calls = 0
    stub({ targets: () => (++calls === 1 ? new Promise<Response>((resolve) => { release = () => resolve(json(TARGETS())) }) : json(TARGETS())) })
    const { client } = renderPage('/nodes?open=aws-sensor')
    await screen.findByText('pend-01')
    expect(scrollIntoView).not.toHaveBeenCalled()
    await act(async () => { release?.() })
    expect(await screen.findByRole('region', { name: '허니팟 센서' })).toBeInTheDocument()
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1))
    await act(async () => { await client.invalidateQueries() })
    await waitFor(() => expect(calls).toBe(2))
    expect(scrollIntoView).toHaveBeenCalledTimes(1)
  })

  it('상태판 첫 조회가 실패했다가 다시 시도로 받으면 그때 한 번 스크롤하고 줄 단추에 초점을 준다(사라진 다시 시도 단추에 머물지 않게)', async () => {
    let fail = true
    stub({ targets: () => (fail ? json({ detail: '일시 오류' }, 503) : json(TARGETS())) })
    renderPage('/nodes?open=data-node')
    const retry = await screen.findByRole('button', { name: '다시 시도' })
    await screen.findByText('pend-01')
    expect(scrollIntoView).not.toHaveBeenCalled()
    fail = false
    retry.focus()
    fireEvent.click(retry)
    expect(await screen.findByRole('region', { name: '데이터 노드' })).toBeInTheDocument()
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1))
    expect(scrollIntoView.mock.contexts[0]).toBe(summary('data-node'))
    expect(document.activeElement).toBe(rowButton('data-node'))
  })

  it('open 이 바뀌면(뒤로 · 앞으로) 다시 펼치고 스크롤한다', async () => {
    stub()
    const { router } = renderPage('/nodes?open=aws-sensor')
    await screen.findByRole('region', { name: '허니팟 센서' })
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(1))
    await act(async () => { await router.navigate('/nodes?open=data-node') })
    expect(await screen.findByRole('region', { name: '데이터 노드' })).toBeInTheDocument()
    await waitFor(() => expect(scrollIntoView).toHaveBeenCalledTimes(2))
    expect(rowButton('aws-sensor')).toHaveAttribute('aria-expanded', 'false')
  })
})

describe('수집 · 관제 상태 · 대상 표기(#78)', () => {
  it('허니팟 센서 · 허니팟 관문 이름으로 보이고 옛 위치 이름은 없다', async () => {
    stub()
    const { container } = renderPage()
    await screen.findByRole('list', { name: '관측 센서 요약' })
    const aws = expand('aws-sensor')
    expect(aws).toHaveTextContent('SSH 허니팟(Cowrie) · 웹 디코이 · 허니팟 관문 (AWS DMZ)')
    expect(container.textContent).not.toMatch(/AWS 센서|AWS 관문/)
  })
})
