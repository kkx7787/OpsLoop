import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DashboardPage } from './DashboardPage'
import { LiveContext } from '@/api/live-context'
import { applyLiveMessage } from '@/api/live'
import { loginHref } from '@/api/client'
import type { MonitorItem } from '@/api/health'
import { noRetryClient, renderRoutes } from '@/test/render'
import { BLOCKS_BY_POINT, MONITOR, MONITORING_SUMMARY, controlHealth, json } from '@/test/monitoring-fixtures'
import { awsSensor, consoleTarget, dataNodeStopped, device, nodeTarget, queueItem, targetsQueue, targetsResult, web01 } from '@/test/targets-fixtures'
import { logsResult } from '@/test/device-logs-fixtures'
import { revealHidden } from '@/lib/untrusted'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})
function renderPage() { return renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', noRetryClient()) }

type Answer = unknown | (() => Response)
/** 요약 · 대상 상태판 · 관제 상태 · CVE 배지 · 카드 로그(#83)에 답하는 fetch. 값 대신 함수를 주면 그 응답을 그대로 돌려준다 */
function stubDashboard({ summary = MONITORING_SUMMARY as Answer, targets = targetsResult() as Answer, health = controlHealth() as Answer, badges = { as_of: '', available: true, badges: {} } as Answer, logs = logsResult() as Answer } = {}) {
  const answer = (value: Answer) => (typeof value === 'function' ? (value as () => Response)() : json(value))
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'han', role: 'operator' })
    if (url.pathname === '/api/stats/summary') return answer(summary)
    if (url.pathname === '/api/dashboard/targets') return answer(targets)
    if (url.pathname === '/api/dashboard/monitor') return answer(health)
    if (url.pathname === '/api/cti/badges') return answer(badges)
    if (/^\/api\/devices\/[^/]+\/logs$/.test(url.pathname)) return answer(logs)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}
const paths = (fetch: ReturnType<typeof stubDashboard>) => fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost').pathname)
/** 제목 줄 오른쪽 기준 시각 칸(#79) */
const pageStatus = () => document.querySelector<HTMLElement>('[data-page-status]') as HTMLElement
/** 가짜 시계를 ms 만큼 돌리고 조회 · 렌더를 비운다(장비 로그 화면 시험과 같다) */
async function settle(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
    for (let i = 0; i < 10; i += 1) await vi.advanceTimersByTimeAsync(1)
  })
}
function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  act(() => void window.dispatchEvent(new Event('visibilitychange')))
}
/** 판정 대기 사건 구역(대기열 카드 머리 h2 가 이름) */
const queueSection = () => screen.getByRole('region', { name: '판정 대기 사건' })
const narrow = () => vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })))
/** 접힌 목록의 한 줄 단추 글 */
const rows = (name: string) => within(screen.getByRole('list', { name })).getAllByRole('button').map((b) => b.textContent)
/** 접힌 목록에서 그 대상 줄을 펼치고 카드를 돌려준다 */
function expand(list: string, target: string): HTMLElement {
  const row = within(screen.getByRole('list', { name: list })).getAllByRole('button').find((b) => b.closest('li')?.dataset.targetSummary === target) as HTMLElement
  fireEvent.click(row)
  return row.closest('li')?.querySelector('[data-target]') as HTMLElement
}

describe('대시보드', () => {
  it('요약 · 대상 상태판 · 관제 상태를 따로 조회해 경과 · 목표 초과를 표시하고 근거 사건으로 연결한다', async () => {
    const fetch = stubDashboard()
    renderPage()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
    expect(screen.getByText('판정 목표 초과')).toBeInTheDocument()
    // 판정 목표 · 임박 기준은 수치 이름 옆 도움말(ⓘ)에 있고 본문 문단으로 되풀이하지 않는다
    const target = screen.getByRole('button', { name: '판정 목표 설명' })
    expect(target).toHaveAttribute('aria-expanded', 'false')
    expect(target).toHaveAccessibleDescription(/critical 1시간 · high 4시간 · medium 12시간 · low 24시간이고, 관제 자기 탐지\(R2xx\) 사건은 1시간입니다\. 목표 임박은 목표 시간의 2\/3 를 넘긴 사건입니다/)
    expect(screen.getAllByText(/critical 1시간/)).toHaveLength(1)
    expect(screen.getByRole('link', { name: /악성코드 투하/ })).toHaveAttribute('href', '/incidents/R003%7Cv2%7C192.0.2.8')
    expect(await screen.findByRole('region', { name: 'web-01' })).toBeInTheDocument()
    // 관측 센서 · 관제 시스템은 수집 · 관제 상태 화면으로 옮겨 CVE 배지를 묻지 않는다(#84)
    await waitFor(() => expect(new Set(paths(fetch))).toEqual(new Set(['/api/me', '/api/stats/summary', '/api/dashboard/targets', '/api/dashboard/monitor', '/api/devices/web-01/logs'])))
    expect(screen.getByRole('link', { name: '전체 미판정 →' })).toHaveAttribute('href', '/incidents?judged=false')
    // 보호 대상 카드는 최근 10줄만 묻는다(로그 화면 100줄과 캐시가 다르다)
    expect(fetch.mock.calls.map(([input]) => String(input))).toContain('/api/devices/web-01/logs?limit=10')
  })

  it('제목은 관제 현황이고 관제 이상 띠 → 보호 대상 → 판정 대기 사건(대기열 → 수치) → 맨 아래 수집 · 관제 상태 링크 순서다(#83 · #84)', async () => {
    stubDashboard({ targets: targetsResult({ queue: targetsQueue() }), health: controlHealth({ items: [MONITOR.loader] }) })
    renderPage()
    expect(screen.getByRole('heading', { level: 1, name: '관제 현황' })).toBeInTheDocument()
    const band = await screen.findByRole('region', { name: '관제 이상' })
    const board = await screen.findByRole('heading', { level: 2, name: '보호 대상' })
    const queue = await screen.findByRole('heading', { level: 2, name: '판정 대기 사건' })
    const metric = await screen.findByText('가장 오래된 미판정')
    const status = screen.getByRole('link', { name: '수집 · 관제 상태 보기 →' })
    expect(status).toHaveAttribute('href', '/nodes')
    const order = [band, board, queue, metric, status, screen.getByText(/최근 원문 수집/)]
    for (let i = 1; i < order.length; i++) expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // 두 구역: 보호 대상 · 판정 대기 사건. 판정 대기 구역의 이름은 대기열 카드 머리의 h2 하나다(구역 제목을 따로 두지 않는다)
    expect(screen.getByRole('region', { name: '보호 대상' })).toContainElement(screen.getByRole('region', { name: 'web-01' }))
    const section = queueSection()
    expect(section).toContainElement(queue)
    expect(section).toContainElement(metric)
    expect(section).toContainElement(screen.getByRole('heading', { name: '미판정 경과 시간' }))
    expect(screen.getAllByRole('heading', { name: '판정 대기 사건' })).toHaveLength(1)
    // 대시보드의 카드는 보호 대상(web-01)뿐이고 관측 센서 · 관제 시스템 줄은 없다(수집 · 관제 상태 화면, #84)
    expect(screen.getByRole('region', { name: 'web-01' })).toBeInTheDocument()
    for (const name of ['허니팟 센서', '관제 콘솔', '데이터 노드']) expect(screen.queryByRole('region', { name })).toBeNull()
    expect(screen.queryByRole('heading', { name: '관측 센서' })).toBeNull()
    expect(screen.queryByRole('heading', { name: '관제 시스템' })).toBeNull()
    expect(screen.queryByRole('list', { name: '관측 센서 요약' })).toBeNull()
    expect(document.querySelector('[data-target-summary]')).toBeNull()
  })

  it('맨 아래 수집 · 관제 상태 링크는 요약 조회가 실패해도 있다(#84)', async () => {
    stubDashboard({ summary: () => json({ detail: 'DB unavailable' }, 503) })
    renderPage()
    expect(await screen.findByText(/DB unavailable/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '수집 · 관제 상태 보기 →' })).toHaveAttribute('href', '/nodes')
    expect(screen.queryByText(/최근 원문 수집/)).toBeNull()
  })

  it('규칙별 비조치율 표는 규칙 화면으로 옮기고 여기서는 링크만 둔다', async () => {
    stubDashboard()
    renderPage()
    await screen.findByText('6시간 12분')
    expect(screen.queryByRole('heading', { name: '규칙별 비조치율' })).toBeNull()
    expect(screen.queryByText('30.0%')).toBeNull()
    expect(screen.getByRole('link', { name: '규칙 화면에서 보기' })).toHaveAttribute('href', '/rules')
    // 페이지 끝 줄은 수집 시각과 규칙 화면 링크만. 갱신 방식은 공통 띠가 알린다
    expect(screen.getByText(/최근 원문 수집/)).not.toHaveTextContent(/웹소켓|30초/)
  })

  it('대상 조회가 실패해도 수치 네 칸 · 대기열은 그대로 보이고 보호 대상 자리만 오류다', async () => {
    stubDashboard({ targets: () => json({ detail: '상태판 집계 실패' }, 503) })
    renderPage()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /악성코드 투하/ })).toBeInTheDocument()
    const board = screen.getByRole('region', { name: '보호 대상' })
    const alert = await within(board).findByRole('alert')
    expect(alert).toHaveTextContent('상태판 집계 실패')
    expect(within(alert).getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
    expect(screen.getAllByRole('alert')).toHaveLength(1)
    expect(screen.queryByRole('heading', { name: '관측 센서' })).toBeNull()
    expect(screen.queryByRole('heading', { name: '관제 시스템' })).toBeNull()
  })

  it('상태판 API 가 없는 이전 서버(404)는 콘솔 API 배포 전으로 알린다', async () => {
    stubDashboard({ targets: () => json({ detail: 'Not Found' }, 404) })
    renderPage()
    expect(await screen.findByText(/콘솔 API 배포 전/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '보호 대상' })).queryByRole('alert')).toBeNull()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
  })

  it('요약 조회가 실패해도 대상 카드는 보인다(queue 가 없으면 요약 오류 화면)', async () => {
    stubDashboard({ summary: () => json({ detail: 'DB unavailable' }, 503) })
    renderPage()
    expect(await screen.findByRole('region', { name: 'web-01' })).toBeInTheDocument()
    expect(await screen.findByText(/DB unavailable/)).toBeInTheDocument()
  })

  it('요약 500 · 대상 200(queue 있음)이면 판정 대기 사건이 보이고, 수치 자리에 요약 오류를 작게 두며 상단은 일부 갱신 실패다', async () => {
    stubDashboard({ summary: () => json({ detail: 'DB unavailable' }, 503), targets: targetsResult({ queue: targetsQueue() }) })
    renderPage()
    const queue = await screen.findByRole('heading', { name: '판정 대기 사건' })
    const card = queue.closest('[data-queue]') as HTMLElement
    expect(card).toHaveAttribute('data-queue', 'lanes')
    expect(within(card).getByRole('link', { name: /웹 경로 탐색/ })).toHaveAttribute('href', `/incidents/${encodeURIComponent(queueItem().incident_key)}`)
    // 요약 실패는 공통 띠로 되풀이하지 않고 판정 대기 구역 안 수치 자리에 둔다
    const alert = await within(queueSection()).findByRole('alert')
    expect(alert).toHaveTextContent('DB unavailable')
    expect(screen.queryByText('데이터를 갱신하지 못했습니다')).toBeNull()
    await waitFor(() => expect(pageStatus()).toHaveTextContent('일부 갱신 실패'))
    // 요약에서 오는 수치 · 경과 분포 · 끝 줄은 없다
    expect(screen.queryByText('가장 오래된 미판정')).toBeNull()
    expect(screen.queryByRole('heading', { name: '미판정 경과 시간' })).toBeNull()
    expect(screen.queryByText(/최근 원문 수집/)).toBeNull()
  })


  it('카드 합이 전체와 다른 까닭은 보호 대상 제목 옆 도움말에, 장비 미확인 미판정은 그 목록으로 잇는다', async () => {
    stubDashboard({ targets: targetsResult({ unmapped: { incidents_1h: 2, pending: 5 } }) })
    const { container } = renderPage()
    const tip = await screen.findByRole('button', { name: '보호 대상 설명' })
    expect(tip).toHaveAccessibleDescription('카드 수치는 대상별입니다. 한 사건이 여러 대상에 걸칠 수 있어 합이 전체와 다릅니다. 이벤트로 장비를 고르지 못한 사건은 장비 미확인으로 셉니다.')
    const board = screen.getByRole('region', { name: '보호 대상' })
    expect(board).toContainElement(tip)
    expect(container.querySelector('[data-targets-note]')).toBeNull()
    const link = within(board).getByRole('link', { name: '장비 미확인 미판정 5' })
    expect(link).toHaveAttribute('href', '/incidents?judged=false&device=_unconfirmed')
    expect(screen.queryByText(/대상 미분류/)).toBeNull()
  })

  it('대상 카드를 받지 못하면 카드 합 도움말을 두지 않는다', async () => {
    stubDashboard({ targets: () => json({ detail: '상태판 집계 실패' }, 503) })
    renderPage()
    await within(screen.getByRole('region', { name: '보호 대상' })).findByRole('alert')
    expect(screen.queryByRole('button', { name: '보호 대상 설명' })).toBeNull()
  })

  it('장비 미확인 미판정이 0 이면 그 줄을 그리지 않는다(최근 1시간 수만 있어도)', async () => {
    stubDashboard({ targets: targetsResult({ unmapped: { incidents_1h: 3, pending: 0 } }) })
    const { container } = renderPage()
    const board = await screen.findByRole('region', { name: '보호 대상' })
    await within(board).findByRole('region', { name: 'web-01' })
    expect(container.querySelector('[data-unmapped]')).toBeNull()
    expect(within(board).queryByRole('link', { name: /장비 미확인/ })).toBeNull()
  })

  it('모바일(sm 미만)은 보호 대상도 한 줄로 접고 누르면 그 카드를 펼친다', async () => {
    narrow()
    stubDashboard()
    renderPage()
    await screen.findByRole('list', { name: '보호 대상 요약' })
    // 요약 줄 배지(#84 결정 7): web-01 은 받은 보고 없음이라 보고 문제
    expect(rows('보호 대상 요약')).toEqual(['▸web-01요청 없음보고 문제미판정 0'])
    expect(screen.queryByRole('list', { name: '관측 센서 요약' })).toBeNull()
    expect(screen.queryByRole('list', { name: '관제 시스템 요약' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'web-01' })).toBeNull()
    const button = within(screen.getByRole('list', { name: '보호 대상 요약' })).getByRole('button')
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    const card = screen.getByRole('region', { name: 'web-01' })
    // 펼친 자리는 보호 대상 카드(#83): 수신 · 성능 · 최근 로그 상자 · 취약점 · 동선. 대응 구역은 없다
    expect(card).toHaveTextContent('마지막 수신 1분 전')
    expect(await within(card).findByRole('region', { name: 'web-01 최근 로그' })).toBeInTheDocument()
    expect(card).not.toHaveTextContent('내부 방화벽 집행 대상 차단 없음')
    expect(button).toHaveAttribute('aria-controls', card.parentElement?.id)
    fireEvent.click(button)
    expect(screen.queryByRole('region', { name: 'web-01' })).toBeNull()
  })

  it('모바일은 접혀 있는 동안 카드 로그를 묻지 않는다', async () => {
    narrow()
    const fetch = stubDashboard()
    renderPage()
    await screen.findByRole('list', { name: '보호 대상 요약' })
    await waitFor(() => expect(paths(fetch)).toContain('/api/dashboard/monitor'))
    expect(paths(fetch)).not.toContain('/api/devices/web-01/logs')
    fireEvent.click(within(screen.getByRole('list', { name: '보호 대상 요약' })).getByRole('button'))
    await waitFor(() => expect(paths(fetch)).toContain('/api/devices/web-01/logs'))
  })

  it('모바일 보호 대상 접힌 줄에도 요약 배지(지점 적용 · 보고 문제 · 지표 오래됨)를 올리고, 넓은 화면 카드 머리는 그대로다(#84 결정 7)', async () => {
    const busy = web01({ system: { state: 'stale', metrics: web01().system.metrics }, response: { ...web01().response, delayed: 2 } })
    stubDashboard({ targets: targetsResult({ targets: [awsSensor(), busy, consoleTarget(), dataNodeStopped(), nodeTarget('web-02')] }) })
    const wide = renderPage()
    const card = await screen.findByRole('region', { name: 'web-01' })
    expect([...card.querySelectorAll<HTMLElement>('[data-summary-flag]')].map((f) => f.dataset.summaryFlag)).toEqual([])
    wide.unmount()

    narrow()
    renderPage()
    await screen.findByRole('list', { name: '보호 대상 요약' })
    expect(rows('보호 대상 요약')).toEqual(['▸web-01요청 없음적용 확인 지연 2건보고 문제지표 오래됨미판정 0', '▸opsloop-web-02수집 정상미판정 3'])
    const row = document.querySelector<HTMLElement>('[data-target-summary="web-01"]') as HTMLElement
    expect(row.querySelector('[data-summary-flag="delayed"]')).toHaveClass('bg-warning-soft')
    expect(row.querySelector('[data-summary-flag="metrics"]')).toHaveClass('bg-warning-soft')
  })

  it('대상 카드 갱신이 실패하면 카드마다 이전 결과를 달고 상단은 일부 갱신 실패다(경고 띠 · 다시 조회는 쌓지 않는다)', async () => {
    let fail = false
    stubDashboard({ targets: () => (fail ? json({ detail: '상태판 집계 실패' }, 503) : json(targetsResult({ targets: [...targetsResult().targets, nodeTarget('web-02')], queue: targetsQueue() }))) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByRole('region', { name: 'opsloop-web-02' })
    await waitFor(() => expect(pageStatus()).toHaveTextContent(/^기준 \d\d:\d\d:\d\d$/))
    const asOf = pageStatus().querySelector('time')?.textContent
    // 받은 뒤의 갱신 실패는 공통 띠가 없어 기준 시각 옆 낭독 칸이 알린다(그 전에는 비어 있다)
    const live = within(pageStatus()).getByRole('status')
    expect(live).toBeEmptyDOMElement()
    fail = true
    await act(async () => { await client.invalidateQueries({ queryKey: ['dashboard', 'targets'] }) })
    await waitFor(() => expect(pageStatus()).toHaveTextContent('일부 갱신 실패'))
    expect(live).toHaveTextContent(/^일부 갱신 실패$/)
    // 기준 시각은 가장 오래된 성공(상태판) 그대로다. 한 화면에 기준 시각은 하나다
    expect(pageStatus().querySelector('time')?.textContent).toBe(asOf)
    expect(document.querySelectorAll('[data-as-of]')).toHaveLength(1)
    for (const name of ['web-01', 'opsloop-web-02']) {
      const card = screen.getByRole('region', { name })
      expect(within(card).getByText('이전 결과')).toHaveAttribute('data-stale-badge')
      expect(card.querySelector('[data-vuln-flag="조회 실패"]')).not.toBeNull()
    }
    // 대기열(상태판 queue)도 이전 결과다
    expect(within(queueSection()).getByText('이전 결과')).toBeInTheDocument()
    expect(screen.queryByText('대상 카드를 갱신하지 못했습니다')).toBeNull()
    expect(screen.queryByRole('button', { name: '다시 조회' })).toBeNull()
    fail = false
    fireEvent.click(within(pageStatus()).getByRole('button', { name: '새로고침' }))
    await waitFor(() => expect(pageStatus()).not.toHaveTextContent('일부 갱신 실패'))
    expect(screen.queryByText('이전 결과')).toBeNull()
    expect(live).toBeEmptyDOMElement()
  })

  it('좁은 폭(sm 미만)에서 상태판 갱신이 실패하면 보호 대상 접힌 줄마다 이전 결과를 달고, 펼친 카드 안에는 되풀이하지 않는다', async () => {
    narrow()
    let fail = false
    stubDashboard({ targets: () => (fail ? json({ detail: '상태판 집계 실패' }, 503) : json(targetsResult({ targets: [...targetsResult().targets, nodeTarget('web-02')] }))) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    const list = await screen.findByRole('list', { name: '보호 대상 요약' })
    await waitFor(() => expect(pageStatus()).toHaveTextContent(/^기준 \d\d:\d\d:\d\d$/))
    expect(list.querySelector('[data-stale-badge]')).toBeNull()
    fail = true
    await act(async () => { await client.invalidateQueries({ queryKey: ['dashboard', 'targets'] }) })
    await waitFor(() => expect(pageStatus()).toHaveTextContent('일부 갱신 실패'))
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    for (const li of items) expect(within(li).getByRole('button')).toHaveTextContent('이전 결과')
    const card = expand('보호 대상 요약', 'web-01')
    expect(within(card).queryByText('이전 결과')).toBeNull()
    expect(card.querySelector('[data-vuln-flag="조회 실패"]')).not.toBeNull()
  })

  it('활성 차단 요청을 지점별 두 줄(적용 · 실패 · 미확인)로 나누고, 집행 제외 · 불일치는 아래 줄에 둔다(#72)', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 16, blocks: { enforced: 2, pending: 0, excluded: 13, mismatch: 1 }, blocks_by_point: BLOCKS_BY_POINT } })
    const { container } = renderPage()
    expect(await screen.findByText('활성 차단 요청 16건')).toBeInTheDocument()
    const gateway = container.querySelector('[data-block-point="gateway"]') as HTMLElement
    const fw = container.querySelector('[data-block-point="fw"]') as HTMLElement
    expect(gateway).toHaveTextContent(/^허니팟 관문 적용 2 · 실패 0 · 미확인 1$/)
    expect(fw).toHaveTextContent(/^내부 방화벽 적용 0 · 실패 0 · 미확인 3 · 집행기 멈춤$/)
    // 두 줄은 차단 목록 링크 하나 안에 있고, 멈춤은 그 지점 줄 끝에 주의색으로 붙는다
    const link = gateway.closest('a') as HTMLElement
    expect(link).toHaveAttribute('href', '/blocklist')
    expect(link).toContainElement(fw)
    expect(fw.querySelector('[data-block-stalled]')).toHaveClass('text-warning')
    expect(gateway.querySelector('[data-block-stalled]')).toBeNull()
    // 요청 수(16)에는 집행 제외가 들어 있어 두 줄 합(3)과 다르다. 그 차이를 아래 줄 맨 앞에 둔다
    expect(screen.getByText('집행 제외 13건 · 불일치 1건')).toBeInTheDocument()
    expect(screen.queryByText(/집행 확인 2/)).toBeNull()
    expect(screen.queryByRole('link', { name: '16건' })).toBeNull()
  })

  it('생존 신호 표를 읽을 수 없어 합친 지점은 집행기 멈춤이 아니라 집행 확인 불가(흐린 글)이고 서버 까닭은 말풍선이다(#82)', async () => {
    const unread = '집행 보고를 읽을 수 없음 · 적용 여부 확인 불가'
    const points = BLOCKS_BY_POINT.map((p) => ({ ...p, applied: 0, failed: 0, unverified: 3, stalled: unread, unreadable: true }))
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 3, blocks_by_point: points } })
    const { container } = renderPage()
    await screen.findByText('활성 차단 요청 3건')
    for (const point of ['gateway', 'fw']) {
      const line = container.querySelector(`[data-block-point="${point}"]`) as HTMLElement
      expect(line).toHaveTextContent(/적용 0 · 실패 0 · 미확인 3 · 집행 확인 불가$/)
      expect(line).not.toHaveTextContent('집행기 멈춤')
      const mark = line.querySelector('[data-block-stalled="unreadable"]')
      expect(mark).toHaveClass('text-ink-muted')
      expect(mark).toHaveAttribute('title', unread)
    }
  })

  it('지점을 요청하지 않은 행은 그 지점 줄 끝의 미요청 n 이고, 0 이면 적지 않는다(#77)', async () => {
    const points = [{ ...BLOCKS_BY_POINT[0], applied: 1, unverified: 0, unrequested: 2 }, { ...BLOCKS_BY_POINT[1], applied: 3, unverified: 0, stalled: null }]
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 3, blocks: { enforced: 3, pending: 0, excluded: 0, mismatch: 0, failed: 0 }, blocks_by_point: points } })
    const { container } = renderPage()
    await screen.findByText('활성 차단 요청 3건')
    // 관문 합(1) = 요청(3) − 제외(0) − 관문 미요청(2). 미요청은 미확인 · 실패에 섞지 않는다
    expect(container.querySelector('[data-block-point="gateway"]')).toHaveTextContent(/^허니팟 관문 적용 1 · 실패 0 · 미확인 0 · 미요청 2$/)
    expect(container.querySelector('[data-block-point="fw"]')).toHaveTextContent(/^내부 방화벽 적용 3 · 실패 0 · 미확인 0$/)
    expect(container.querySelector('[data-block-point="fw"] [data-block-unrequested]')).toBeNull()
    expect(container.querySelector('[data-block-removing]')).toBeNull()
  })

  it('관문을 뺐는데 관문이 뺐다고 확인하기 전인 행은 관문 줄 끝의 빠짐 확인 전 n 이다(#77 결정 14)', async () => {
    const points = [{ ...BLOCKS_BY_POINT[0], applied: 1, unverified: 0, unrequested: 1, removing: 1 }, { ...BLOCKS_BY_POINT[1], applied: 3, unverified: 0, removing: 0, stalled: null }]
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 3, blocks: { enforced: 3, pending: 0, excluded: 0, mismatch: 0, failed: 0 }, blocks_by_point: points } })
    const { container } = renderPage()
    await screen.findByText('활성 차단 요청 3건')
    // 관문 합(1) = 요청(3) − 제외(0) − 관문 미요청(1) − 관문 빠짐 확인 전(1)
    expect(container.querySelector('[data-block-point="gateway"]')).toHaveTextContent(/^허니팟 관문 적용 1 · 실패 0 · 미확인 0 · 미요청 1 · 빠짐 확인 전 1$/)
    expect(container.querySelector('[data-block-point="fw"]')).toHaveTextContent(/^내부 방화벽 적용 3 · 실패 0 · 미확인 0$/)
  })

  it('집행 제외가 0 이면 아래 줄에 적지 않는다', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocks_by_point: [{ ...BLOCKS_BY_POINT[0], applied: 1, unverified: 1 }, { ...BLOCKS_BY_POINT[1], unverified: 2, stalled: null }] } })
    const { container } = renderPage()
    await screen.findByText('활성 차단 요청 2건')
    expect(container.querySelector('[data-block-point="fw"]')).toHaveTextContent(/^내부 방화벽 적용 0 · 실패 0 · 미확인 2$/)
    expect(screen.queryByText(/집행 제외/)).toBeNull()
  })

  it('지점별이 없는 이전 서버는 집행 확인 · 대기 · 제외 한 줄이다(이슈 #47)', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocked_ips: 16, blocks: { enforced: 2, pending: 0, excluded: 13, mismatch: 1 } } })
    renderPage()
    expect(await screen.findByText('활성 차단 요청 16건')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '집행 확인 2 · 대기 0 · 제외 13' })).toHaveAttribute('href', '/blocklist')
    expect(screen.getByText('불일치 1건')).toBeInTheDocument()
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
    // '첫 사건' 의 뜻은 그 줄 끝 도움말(ⓘ)에 있다
    expect(screen.getByRole('button', { name: '첫 사건 설명' })).toHaveAccessibleDescription(/같은 페이로드의 출발지를 흡수한 사건입니다/)
  })

  it('흡수 미차단이 없으면 첫 사건 도움말을 두지 않는다', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, blocks: { enforced: 2, pending: 0, excluded: 13, mismatch: 1 } } })
    renderPage()
    expect(await screen.findByText('불일치 1건')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '첫 사건 설명' })).toBeNull()
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
        result.targets[1].security.pending = total
        return json(result)
      },
    })
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByRole('link', { name: '12건' })
    const web = await screen.findByRole('region', { name: 'web-01' })
    await waitFor(() => expect(within(web).getByRole('link', { name: '미판정 12건' })).toBeInTheDocument())
    total = 11
    act(() => applyLiveMessage(client, { type: 'verdict.created', data: { incident_key: 'k' } }))
    expect(await screen.findByRole('link', { name: '11건' })).toBeInTheDocument()
    await waitFor(() => expect(within(screen.getByRole('region', { name: 'web-01' })).getByRole('link', { name: '미판정 11건' })).toBeInTheDocument())
  })

  it('요약 갱신이 실패하면 이전 수치를 유지하고 수치 · 분포에 이전 결과, 제목 줄 새로고침은 요약 · 대상 · 관제 상태 · 로그를 모두 다시 묻는다', async () => {
    let fail = false
    const fetch = stubDashboard({ summary: () => fail ? json({ detail: 'DB unavailable' }, 503) : json(MONITORING_SUMMARY) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByText('6시간 12분')
    fail = true
    await act(async () => { await client.invalidateQueries() })
    await waitFor(() => expect(pageStatus()).toHaveTextContent('일부 갱신 실패'))
    expect(screen.queryByRole('alert')).toBeNull()
    // 빨간 띠(alert) 대신 기준 시각 옆 낭독 칸(status)이 알린다
    expect(within(pageStatus()).getByRole('status')).toHaveTextContent(/^일부 갱신 실패$/)
    expect(screen.getByText('6시간 12분')).toBeInTheDocument()
    // 요약에서 오는 대기열(queue 없는 이전 서버) · 경과 분포 · 수치 네 칸에 하나씩
    expect(within(queueSection()).getAllByText('이전 결과')).toHaveLength(3)
    fail = false
    const watched = ['/api/stats/summary', '/api/dashboard/targets', '/api/dashboard/monitor', '/api/devices/web-01/logs']
    const count = (path: string) => paths(fetch).filter((p) => p === path).length
    const before = watched.map(count)
    fireEvent.click(within(pageStatus()).getByRole('button', { name: '새로고침' }))
    await waitFor(() => expect(pageStatus()).not.toHaveTextContent('일부 갱신 실패'))
    await waitFor(() => expect(watched.map(count).every((n, i) => n > before[i])).toBe(true))
    expect(screen.queryByText('이전 결과')).toBeNull()
  })

  it('로그 자동 갱신 정지는 그 카드 로그만 멈춘다: 요약 · 상태판 · 관제 이상은 30초마다 계속, 새로고침은 로그도 한 번 받고 정지는 그대로(#83)', async () => {
    vi.useFakeTimers()
    const fetch = stubDashboard()
    renderPage()
    await settle()
    const count = (path: string) => paths(fetch).filter((p) => p === path).length
    const logs = () => count('/api/devices/web-01/logs')
    expect(logs()).toBe(1)
    await settle(10_000)
    expect(logs()).toBe(2)
    fireEvent.click(screen.getByRole('button', { name: '로그 자동 갱신 정지' }))
    const watched = ['/api/stats/summary', '/api/dashboard/targets', '/api/dashboard/monitor']
    const before = watched.map(count)
    await settle(30_000)
    expect(logs()).toBe(2)
    expect(watched.map(count).every((n, i) => n > before[i])).toBe(true)
    fireEvent.click(within(pageStatus()).getByRole('button', { name: '새로고침' }))
    await settle()
    expect(logs()).toBe(3)
    expect(screen.getByRole('button', { name: '로그 자동 갱신 정지' })).toHaveAttribute('aria-pressed', 'true')
    await settle(30_000)
    expect(logs()).toBe(3)
  })

  it('탭이 뒤로 가면 카드 로그 주기 조회를 멈추고, 앞으로 오면 한 번 받는다', async () => {
    vi.useFakeTimers()
    const fetch = stubDashboard()
    renderPage()
    await settle()
    const logs = () => paths(fetch).filter((p) => p === '/api/devices/web-01/logs').length
    expect(logs()).toBe(1)
    setVisibility('hidden')
    await settle(30_000)
    expect(logs()).toBe(1)
    setVisibility('visible')
    await settle()
    expect(logs()).toBe(2)
  })

  it('화면 기준 시각은 제목 줄 오른쪽 하나이고 새로고침은 그 옆 하나다(#79)', async () => {
    stubDashboard()
    renderPage()
    await screen.findByText('6시간 12분')
    await waitFor(() => expect(pageStatus()).toHaveTextContent(/^기준 \d\d:\d\d:\d\d$/))
    expect(document.querySelectorAll('[data-as-of]')).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '새로고침' })).toHaveLength(1)
    expect(screen.queryByText(/마지막 조회/)).toBeNull()
  })

  it('미결(사람이 남긴 판단 유보)은 미판정 칸 아래에 따로 세고 미결 목록으로 잇는다. 0 이면 적지 않는다(#83)', async () => {
    stubDashboard({ summary: { ...MONITORING_SUMMARY, pending: { ...MONITORING_SUMMARY.pending, undetermined: 2 } } })
    const view = renderPage()
    const link = await screen.findByRole('link', { name: '미결 2건' })
    expect(link).toHaveAttribute('href', '/incidents?undetermined=true')
    expect(screen.getByRole('button', { name: '미결 설명' })).toHaveAccessibleDescription(/시스템 전환 처리 제외/)
    view.unmount()

    stubDashboard({ summary: { ...MONITORING_SUMMARY, pending: { ...MONITORING_SUMMARY.pending, undetermined: 0 } } })
    renderPage()
    await screen.findByText('6시간 12분')
    expect(screen.queryByText(/미결/)).toBeNull()
    expect(screen.queryByRole('button', { name: '미결 설명' })).toBeNull()
  })

  it('AI 추천 일치는 카드 아래 한 줄이고, AI 서버에 닿지 않으면 마지막 연결을 적되 경고색은 쓰지 않는다 · 정보가 없는 서버는 줄이 없다(#120)', async () => {
    const status = { checked_at: '2026-10-06T06:05:00+00:00', reachable: true, last_ok_at: '2026-10-06T06:05:00+00:00', model: 'gpt-oss:20b', pending: 0, error: null }
    stubDashboard({ summary: { ...MONITORING_SUMMARY, ai: { agreed: 12, judged: 14, status } } })
    let view = renderPage()
    let line = await screen.findByText('AI 추천 일치 12/14')
    expect(line.closest('[data-ai-agreement]')).not.toHaveTextContent('연결 안 됨')
    expect(screen.getByRole('button', { name: 'AI 추천 일치 설명' })).toHaveAccessibleDescription(/판정과 차단은 사람이 합니다/)
    view.unmount()

    stubDashboard({ summary: { ...MONITORING_SUMMARY, ai: { agreed: 0, judged: 0, status: { ...status, reachable: false, last_ok_at: '2026-10-06T04:00:00+00:00' } } } })
    view = renderPage()
    line = await screen.findByText('AI 추천 일치 아직 없음')
    const row = line.closest('[data-ai-agreement]') as HTMLElement
    expect(row).toHaveTextContent('AI 서버 연결 안 됨')
    expect(row).toHaveTextContent('마지막 연결')
    expect(row.querySelector('.text-warning')).toBeNull()
    view.unmount()

    stubDashboard()
    renderPage()
    await screen.findByText('6시간 12분')
    expect(screen.queryByText(/AI 추천 일치/)).toBeNull()
  })

  it('S-10: 실시간 끊김은 공통 띠 대신 관제 이상 띠의 끝 항목 하나이고 주기 조회를 ⓘ 로 안내하며 조회 상태를 지우지 않는다(#84)', async () => {
    stubDashboard()
    renderRoutes([{ path: '/', element: <LiveContext.Provider value={{ status: 'reconnecting', retries: 1 }}><DashboardPage /></LiveContext.Provider> }], '/', noRetryClient())
    const band = await screen.findByRole('region', { name: '관제 이상' })
    expect(band.querySelector('[data-monitor-item="live"]')).toHaveTextContent(/^실시간 연결 · 끊김 · 다시 연결 중$/)
    expect(screen.queryByText('실시간 연결이 끊겼습니다')).toBeNull()
    expect(screen.getByText(/30초마다 별도로 조회/)).toBeInTheDocument()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
  })

  it('실시간 끊김과 관제 이상이 함께여도 띠는 하나(한 줄 목록)이고 실시간 항목이 끝이다. 세션 종료면 다시 로그인으로 잇는다(#84)', async () => {
    stubDashboard({ health: controlHealth({ items: [MONITOR.sensor] }) })
    const view = renderRoutes([{ path: '/', element: <LiveContext.Provider value={{ status: 'reconnecting', retries: 1 }}><DashboardPage /></LiveContext.Provider> }], '/', noRetryClient())
    await waitFor(() => expect(document.querySelectorAll('[data-monitor-item]')).toHaveLength(2))
    expect(screen.getAllByRole('region', { name: '관제 이상' })).toHaveLength(1)
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect([...band.querySelectorAll<HTMLElement>('[data-monitor-item]')].map((li) => li.dataset.monitorItem)).toEqual(['sensor', 'live'])
    expect(within(band).getAllByRole('list')).toHaveLength(1)
    view.unmount()

    stubDashboard()
    renderRoutes([{ path: '/', element: <LiveContext.Provider value={{ status: 'closed', retries: 0 }}><DashboardPage /></LiveContext.Provider> }], '/', noRetryClient())
    const closed = await screen.findByRole('region', { name: '관제 이상' })
    expect(within(closed).getByRole('link', { name: '다시 로그인' })).toHaveAttribute('href', loginHref())
    expect(screen.queryByText('실시간 연결이 종료됐습니다')).toBeNull()
  })
})

describe('대시보드 · 관제 이상 띠(#72)', () => {
  it('이상이 없으면 띠를 그리지 않는다(받는 중에도 없다)', async () => {
    const fetch = stubDashboard()
    renderPage()
    await screen.findByText('6시간 12분')
    await waitFor(() => expect(paths(fetch)).toContain('/api/dashboard/monitor'))
    await waitFor(() => expect(screen.queryByRole('region', { name: '관제 이상' })).toBeNull())
    expect(screen.queryByText('관제 상태 확인 불가')).toBeNull()
  })

  it('관제 상태 조회가 실패하면 관제 상태 확인 불가 한 줄이다', async () => {
    stubDashboard({ health: () => json({ detail: 'DB unavailable' }, 503) })
    renderPage()
    const band = await screen.findByRole('region', { name: '관제 이상' })
    expect(within(band).getByRole('status')).toHaveTextContent(/^관제 상태 확인 불가$/)
    expect(band.querySelectorAll('li')).toHaveLength(0)
  })

  it('이전 서버(404) · 모양이 다른 응답도 확인 불가다(이상 없음으로 꾸미지 않는다)', async () => {
    stubDashboard({ health: { as_of: '', detect_paths: [] } })
    renderPage()
    expect(within(await screen.findByRole('region', { name: '관제 이상' })).getByRole('status')).toHaveTextContent('관제 상태 확인 불가')
  })

  it.each<[string, MonitorItem[], Array<[string, string, string | null]>]>([
    ['적재기 · 집행기 멈춤', [MONITOR.loader, MONITOR.enforcerFw], [
      ['loader', '적재기 · 적재기 확인 중단 · 마지막 45분 전', '/nodes?open=data-node'],
      ['enforcer:fw', '내부 방화벽 집행기 · 집행기 확인 중단 · 마지막 확인 12분 전', '/blocklist']]],
    ['탐지 경로 멈춤', [MONITOR.detectBridge], [['detect:bridge', '노드 · 관제 탐지(1분) · w2 마지막 실행 16분 전', '/nodes?open=data-node']]],
    ['적용 실패 · 관문 불일치', [MONITOR.failedGateway, MONITOR.mismatch], [
      ['block_failed:gateway', '허니팟 관문 적용 실패 · 2건', '/blocklist'],
      ['gateway_mismatch', '관문 불일치 · 1건', '/blocklist']]],
    ['활성 노드 전부 수신 없음', [MONITOR.nodesSilent], [['nodes_silent', '노드 수신 · 노드 2대 수신 끊김', '/nodes']]],
    // #82
    ['센서 · 관문 기록 수신 끊김', [MONITOR.sensor, MONITOR.gatewayUploader], [
      ['sensor', '허니팟 센서 수신 · 업로더 생존 신호 40분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음 · 관문 기록 신호 40분 전', '/nodes?open=aws-sensor'],
      ['gateway_uploader', '허니팟 관문 기록 수신 · 관문 기록 신호 40분 전 · 적재기 확인 2분 전 · 확인 때 이미 15분 넘게 새 신호 없음', '/nodes?open=aws-sensor']]],
    ['기대 탐지 버전 기록 없음', [MONITOR.detectBridgeMissing], [['detect:bridge', '노드 · 관제 탐지(1분) · c1 · sg1 24시간 넘게 실행 없음', '/nodes?open=data-node']]],
    ['내부 방화벽 불일치 · 지점 보고 멈춤', [MONITOR.pointStaleFw, MONITOR.reportFw], [
      ['point_stale:fw', '내부 방화벽 불일치 · 2건', '/blocklist'],
      ['report:fw', '내부 방화벽 보고 · 마지막 보고 20분 전', '/blocklist']]],
    ['활성 노드 일부 수신 없음 · 웹 로그 적재 없음 · 자원 지표 오래됨', [MONITOR.nodesSilentSome, MONITOR.parse, MONITOR.metrics], [
      ['nodes_silent', '노드 수신 · node-b 수신 끊김 · 마지막 수신 12분 전', '/nodes'],
      ['parse:web-01', 'web-01 웹 로그 적재 · 로그는 도착하는데 적재되지 않음 · 마지막 도착 3분 전', '/devices/web-01/logs'],
      ['metrics:node-e', 'node-e 자원 지표 · 마지막 지표 25분 전', '/nodes']]],
  ])('%s 를 띠에 항목마다 한 줄로 보이고 볼 화면으로 잇는다', async (_name, items, expected) => {
    stubDashboard({ health: controlHealth({ items }) })
    renderPage()
    const band = await screen.findByRole('region', { name: '관제 이상' })
    expect(band).toHaveAttribute('data-control-health', 'alert')
    expect(band).toHaveClass('bg-warning-soft')
    const lines = [...band.querySelectorAll<HTMLElement>('[data-monitor-item]')]
    expect(lines.map((li) => [li.dataset.monitorItem, li.textContent, li.querySelector('a')?.getAttribute('href') ?? null])).toEqual(expected)
    // 기준은 ⓘ 하나에 둔다
    expect(within(band).getByRole('button', { name: '관제 이상 기준 설명' })).toHaveAccessibleDescription('적재기 30분 · 집행기 10분 · 센서 15분 · 탐지 15분 · 노드 10분 넘게 확인이 없으면 멈춤입니다.')
    expect(within(band).getAllByRole('button')).toHaveLength(1)
  })

  it('이상 뒤에 모름(표를 읽을 수 없음)을 흐린 글로 두고, 모름만 있으면 주의색 띠가 아니다', async () => {
    stubDashboard({ health: controlHealth({ items: [MONITOR.heartbeats, MONITOR.loader, MONITOR.nodes] }) })
    const view = renderPage()
    const band = await screen.findByRole('region', { name: '관제 이상' })
    expect([...band.querySelectorAll<HTMLElement>('[data-monitor-item]')].map((li) => [li.dataset.monitorItem, li.dataset.monitorLevel])).toEqual([
      ['loader', 'alert'], ['heartbeats', 'unknown'], ['nodes', 'unknown']])
    expect(band.querySelector('[data-monitor-item="heartbeats"]')).toHaveClass('text-ink-muted')
    expect(band.querySelector('[data-monitor-item="nodes"] a')).toHaveAttribute('href', '/nodes')
    view.unmount()

    stubDashboard({ health: controlHealth({ items: [MONITOR.heartbeats] }) })
    renderPage()
    const only = await screen.findByRole('region', { name: '관제 이상' })
    expect(only).toHaveAttribute('data-control-health', 'unknown')
    expect(only).not.toHaveClass('bg-warning-soft')
    expect(only).toHaveTextContent('생존 신호 · 생존 신호 표를 읽을 수 없음')
  })

  it('이상 2건을 받은 뒤 다음 조회가 503 이면 이전 항목이 사라지고 관제 상태 확인 불가 한 줄만 남는다(Q14)', async () => {
    let fail = false
    stubDashboard({ health: () => (fail ? json({ detail: 'DB unavailable' }, 503) : json(controlHealth({ items: [MONITOR.loader, MONITOR.mismatch] }))) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    const band = await screen.findByRole('region', { name: '관제 이상' })
    await waitFor(() => expect(band.querySelectorAll('[data-monitor-item]')).toHaveLength(2))
    fail = true
    await act(async () => { await client.invalidateQueries({ queryKey: ['dashboard', 'monitor'] }) })
    await waitFor(() => expect(screen.getByRole('region', { name: '관제 이상' })).toHaveTextContent(/^관제 상태 확인 불가$/))
    const after = screen.getByRole('region', { name: '관제 이상' })
    expect(after.querySelectorAll('[data-monitor-item]')).toHaveLength(0)
    expect(screen.queryByText(/적재기 확인 중단/)).toBeNull()
    // 다시 받으면 항목이 돌아온다
    fail = false
    await act(async () => { await client.invalidateQueries({ queryKey: ['dashboard', 'monitor'] }) })
    await waitFor(() => expect(screen.getByRole('region', { name: '관제 이상' }).querySelectorAll('[data-monitor-item]')).toHaveLength(2))
  })

  it('한 번도 받지 못한 채 다시 조회하는 동안에도 확인 불가를 유지한다(띠가 사라졌다 돌아오지 않는다)', async () => {
    let calls = 0
    let hold: ((response: Response) => void) | undefined
    const held = () => new Promise<Response>((resolve) => { hold = resolve }) as unknown as Response
    stubDashboard({ health: () => (++calls === 1 ? json({ detail: 'DB unavailable' }, 503) : held()) })
    const client = noRetryClient()
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    const status = within(await screen.findByRole('region', { name: '관제 이상' })).getByRole('status')
    expect(status).toHaveTextContent('관제 상태 확인 불가')
    act(() => void client.refetchQueries({ queryKey: ['dashboard', 'monitor'] }))   // 30초 재조회와 같은 다시 조회
    await waitFor(() => expect(calls).toBe(2))
    expect(client.getQueryState(['dashboard', 'monitor'])?.status).toBe('pending')
    const band = screen.getByRole('region', { name: '관제 이상' })
    expect(band).toHaveTextContent(/^관제 상태 확인 불가$/)
    expect(within(band).getByRole('status')).toBe(status)
    act(() => hold?.(json(controlHealth({ items: [MONITOR.loader] }))))
    await waitFor(() => expect(screen.getByRole('region', { name: '관제 이상' }).querySelectorAll('[data-monitor-item]')).toHaveLength(1))
  })

  it('항목 글에 섞인 비신뢰 문자열은 표식으로 보이고 실행되지 않는다', async () => {
    stubDashboard({ health: controlHealth({ items: [{ ...MONITOR.detectBridge, reason: `${MIXED} 마지막 실행 16분 전` }] }) })
    const { container } = renderPage()
    const band = await screen.findByRole('region', { name: '관제 이상' })
    expectInertDom(container)
    expectMixedRevealed(band)
    expect(band.querySelector('[data-monitor-item] [title]')).toHaveAttribute('title', revealHidden(`${MIXED} 마지막 실행 16분 전`))
    expect(within(band).getAllByRole('button')).toHaveLength(1)
  })
})

describe('대시보드 · 판정 대기 사건(#72 · #83)', () => {
  const queueCard = async () => (await screen.findByRole('heading', { name: '판정 대기 사건' })).closest('[data-queue]') as HTMLElement

  it('우선 확인 묶음 뒤에 허니팟 · 디코이 묶음을 서버 순서대로 두고, 한 줄에 관련 장비(보호 대상 먼저)를 보인다', async () => {
    stubDashboard({ targets: targetsResult({ queue: targetsQueue() }) })
    renderPage()
    const card = await queueCard()
    expect(card).toHaveAttribute('data-queue', 'lanes')
    expect(card.querySelector('[data-queue-counts]')).toHaveTextContent(/^우선 확인 21 · 허니팟 · 디코이 118$/)
    const front = card.querySelector('ol[data-lane="front"]') as HTMLElement
    const back = within(card).getByRole('list', { name: '허니팟 · 디코이' })
    expect(back).toHaveAttribute('data-lane', 'back')
    expect(within(card).getByRole('heading', { level: 3, name: '허니팟 · 디코이' }).compareDocumentPosition(back) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    const frontLinks = within(front).getAllByRole('link')
    expect(frontLinks.map((a) => a.getAttribute('href'))).toEqual(targetsQueue().items.slice(0, 3).map((i) => `/incidents/${encodeURIComponent(i.incident_key)}`))
    // 여러 장비: 서버가 디코이를 먼저 보내도 보호 대상(web-01)이 앞이다. 목록 행과 같은 '장비 · 로그 종류' 배지
    const devices = [...frontLinks[0].querySelectorAll<HTMLElement>('[data-device]')]
    expect(devices.map((d) => d.dataset.device)).toEqual(['web-01', 'aws-sensor'])
    expect(devices[0]).toHaveTextContent('web-01 · 웹 접근')
    expect(devices[1]).toHaveTextContent('웹 디코이 · 웹 요청')
    // 규칙 범위도 같은 모양(근거 글자는 상세에만)
    expect(frontLinks[1].querySelector('[data-device="data-node"]')).toHaveAttribute('data-device-basis', 'rule_scope')
    expect(frontLinks[1]).toHaveTextContent('데이터 노드 · 수집 관문 · 원장 가져오기')
    expect(frontLinks[1]).not.toHaveTextContent('규칙 범위')
    // 대체 추정만 있으면 장비 미확인이고 추정 이름은 없다
    expect(frontLinks[2].querySelector('[data-device-unknown]')).toHaveTextContent('장비 미확인')
    expect(frontLinks[2]).not.toHaveTextContent('Cowrie')
    expect(card.querySelector('[data-device-basis="fallback"]')).toBeNull()
    // 뒤 묶음
    const backLink = within(back).getByRole('link')
    expect(backLink).toHaveTextContent('SSH 무차별 대입')
    expect(backLink.querySelector('[data-device]')).toHaveTextContent('SSH 허니팟(Cowrie) · SSH 세션')
    // 링크 안에는 단추가 없다(#41). 요약의 옛 대기열은 그리지 않는다
    for (const link of within(card).getAllByRole('link')) expect(link.querySelector('button')).toBeNull()
    expect(screen.queryByRole('link', { name: /악성코드 투하/ })).toBeNull()
    expect(within(card).queryByText(/· 허니팟$/)).toBeNull()
  })

  it('정렬 기준 · 최대 8건은 제목 옆 도움말(ⓘ)에 두고 끝 줄로 적지 않는다', async () => {
    stubDashboard({ targets: targetsResult({ queue: targetsQueue() }) })
    renderPage()
    const card = await queueCard()
    expect(within(card).getByRole('button', { name: '판정 대기 사건 설명' })).toHaveAccessibleDescription(
      '보호 대상 · 관제 시스템 · 장비 미확인 사건을 우선 확인으로 앞에, 허니팟 · 디코이 사건을 뒤에 두고 각각 오래된 순입니다. 최대 8건 · 전체 규칙 버전.')
    expect(within(card).getByRole('link', { name: '미판정 전체 보기 →' })).toHaveAttribute('href', '/incidents?judged=false')
    expect(screen.queryByText('오래된 순 · 최대 8건 · 전체 규칙 버전')).toBeNull()
  })

  it('앞 묶음이 8건을 채워 뒤 묶음 항목이 없어도 뒤 수를 보인다(front 9 · back 3)', async () => {
    const items = Array.from({ length: 8 }, (_, i) => queueItem({ incident_key: `R101|w2|198.51.100.${i}|x`, actor_ip: `198.51.100.${i}` }))
    stubDashboard({ targets: targetsResult({ queue: targetsQueue({ total: 12, front: 9, back: 3, unconfirmed: 0, overdue: 0, items }) }) })
    renderPage()
    const card = await queueCard()
    expect(card.querySelector('[data-queue-counts]')).toHaveTextContent(/^우선 확인 9 · 허니팟 · 디코이 3$/)
    expect(within(card.querySelector('ol[data-lane="front"]') as HTMLElement).getAllByRole('link')).toHaveLength(8)
    expect(within(card).queryByRole('heading', { level: 3 })).toBeNull()
    expect(card.querySelector('[data-queue-back]')).toHaveTextContent(/^허니팟 · 디코이 3건$/)
    // 목록 끝이다
    const frontList = card.querySelector('ol[data-lane="front"]') as HTMLElement
    expect(frontList.compareDocumentPosition(card.querySelector('[data-queue-back]') as HTMLElement) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('뒤 묶음 항목이 목록에 있으면 끝 줄을 두지 않는다 · 뒤 묶음뿐이면 묶음 제목부터', async () => {
    stubDashboard({ targets: targetsResult({ queue: targetsQueue({ total: 1, front: 0, back: 1, items: [targetsQueue().items[3]] }) }) })
    renderPage()
    const card = await queueCard()
    expect(card.querySelector('ol[data-lane="front"]')).toBeNull()
    expect(within(card).getByRole('heading', { level: 3, name: '허니팟 · 디코이' })).not.toHaveClass('border-t')
    expect(card.querySelector('[data-queue-back]')).toBeNull()
  })

  it('queue 가 없으면(이전 서버 · 상태판 실패) 요약의 오래된 미판정을 발생원 표기로 그린다', async () => {
    stubDashboard()
    renderPage()
    const card = await queueCard()
    expect(card).toHaveAttribute('data-queue', 'oldest')
    expect(await within(card).findByRole('link', { name: /악성코드 투하/ })).toHaveTextContent('192.0.2.8· 허니팟')
    expect(card.querySelector('[data-queue-counts]')).toBeNull()
    expect(card.querySelector('[data-device], [data-device-unknown]')).toBeNull()
    expect(within(card).getByRole('button', { name: '판정 대기 사건 설명' })).toHaveAccessibleDescription('오래된 순입니다. 최대 8건 · 전체 규칙 버전.')
  })

  it('미판정이 없으면 수집 시각도 확인하라고 적는다', async () => {
    stubDashboard({ targets: targetsResult({ queue: targetsQueue({ total: 0, front: 0, back: 0, unconfirmed: 0, overdue: 0, items: [] }) }) })
    renderPage()
    const card = await queueCard()
    expect(card).toHaveTextContent('미판정 사건이 없습니다. 최근 수집 시각도 함께 확인해 주세요.')
    expect(card.querySelector('[data-queue-counts]')).toHaveTextContent('우선 확인 0 · 허니팟 · 디코이 0')
  })

  it('등록 노드 이름(hostname)이 장비 배지에 오면 표식으로 보이고 실행되지 않는다', async () => {
    const hostile = queueItem({ devices: [device({ id: 'web-02', label: MIXED, logs: ['SSH 인증'] })] })
    stubDashboard({ targets: targetsResult({ queue: targetsQueue({ items: [hostile] }) }) })
    const { container } = renderPage()
    const card = await queueCard()
    const badge = card.querySelector('[data-device="web-02"]') as HTMLElement
    expect(badge).toHaveAttribute('title', revealHidden(`${MIXED} · SSH 인증`))
    expectInertDom(container)
    expect(badge.closest('a')?.querySelector('button')).toBeNull()
  })
})

describe('대시보드 · 비신뢰 문자열(#41)', () => {
  it('먼저 처리할 사건의 대상은 표식으로 바꾼 뒤 한 줄로 자르고 링크 안에 단추를 두지 않는다', async () => {
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

  it('queue 의 대상 · 규칙 이름도 같게 자르고 전체는 말풍선으로 본다', async () => {
    const items = [
      queueItem({ incident_key: 'a', actor_ip: null, target: `user:${MIXED}`, rule_name: LONG }),
      queueItem({ incident_key: 'b', actor_ip: null, target: `user:${LONG}`, lane: 'back' }),
    ]
    stubDashboard({ targets: targetsResult({ queue: targetsQueue({ items }) }) })
    const { container } = renderPage()
    const first = await screen.findByTitle(revealHidden(`user:${MIXED}`))
    expect(first).toHaveClass('truncate')
    expect(screen.getByTitle(LONG).textContent).toBe(`R102${'L'.repeat(500)}…`)
    expect(screen.getByTitle(`user:${LONG}`).textContent).toBe(`user:${'L'.repeat(495)}…`)
    expectInertDom(container)
    expectMixedRevealed(container)
  })

  it('먼저 처리할 사건의 긴 규칙 이름도 링크 안에서 단추 없이 잘리고 전체는 말풍선으로 본다', async () => {
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

  it.each([
    ['2장', ['web-02']],
    ['3장', ['web-02', 'web-03']],
  ])('보호 대상 카드 %s: 등록 노드는 web-01 뒤에 붙고 격자는 1200px 이상에서 두 열 고정이다(#83 · #94)', async (_name, ids) => {
    stubDashboard({ targets: withNodes(...ids) })
    renderPage()
    const board = await screen.findByRole('region', { name: '보호 대상' })
    await within(board).findByRole('region', { name: 'opsloop-web-02' })
    const cards = [...board.querySelectorAll<HTMLElement>('[data-target]')]
    expect(cards.map((c) => c.dataset.target)).toEqual(['web-01', ...ids])
    expect(cards.map((c) => c.dataset.targetKind)).toEqual(['fixed', ...ids.map(() => 'node')])
    // 카드는 모두 한 그리드의 칸이다. 1장이어도 반쪽 폭이라 장비가 늘어도 카드 폭 · 높이가 같다(세 열 없음). jsdom 은 배치를 계산하지 않아 규칙만 본다
    // 두 열은 1200px 부터다. lg(1024)면 1024 ~ 약 1180 에서 카드가 28rem 보다 좁아 요청 경로가 사라진다(#94)
    const grid = cards[0].parentElement as HTMLElement
    expect(grid).toHaveClass('grid', 'gap-3', 'grid-cols-1', 'min-[1200px]:grid-cols-2', 'items-stretch')
    expect(grid.className).not.toMatch(/auto-fit|grid-cols-3|lg:grid-cols/)
    expect(cards.every((c) => c.parentElement === grid)).toBe(true)
    // 카드마다 최근 로그를 따로 묻는다
    await waitFor(() => expect(cards.every((c) => c.querySelector('[data-log-box] table'))).toBe(true))
  })

  it('서버가 섞어 보내도 web-01 이 등록 노드 앞이다', async () => {
    const [aws, web, con, data] = targetsResult().targets
    stubDashboard({ targets: targetsResult({ targets: [nodeTarget('web-02'), aws, web, con, data] }) })
    renderPage()
    const board = await screen.findByRole('region', { name: '보호 대상' })
    await within(board).findByRole('region', { name: 'opsloop-web-02' })
    expect([...board.querySelectorAll<HTMLElement>('[data-target]')].map((c) => c.dataset.target)).toEqual(['web-01', 'web-02'])
  })

  it('CVE 배지는 묻지 않는다(보호 대상 카드에는 최근 사건 줄이 없고 관측 센서 · 관제 시스템은 수집 · 관제 상태 화면이다, #84)', async () => {
    const fetch = stubDashboard({ targets: withNodes('web-02') })
    renderPage()
    await screen.findByRole('region', { name: 'opsloop-web-02' })
    await waitFor(() => expect(paths(fetch)).toContain('/api/devices/web-02/logs'))
    expect(paths(fetch)).not.toContain('/api/cti/badges')
  })

  it('모바일은 등록 노드도 보호 대상 요약에 한 줄로 접히고 누르면 그 카드를 펼친다', async () => {
    narrow()
    stubDashboard({ targets: withNodes('web-02', 'web-03') })
    renderPage()
    const list = await screen.findByRole('list', { name: '보호 대상 요약' })
    const buttons = within(list).getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual(['▸web-01요청 없음보고 문제미판정 0', '▸opsloop-web-02수집 정상미판정 3', '▸opsloop-web-03수집 정상미판정 3'])
    expect(screen.queryByRole('region', { name: 'opsloop-web-02' })).toBeNull()
    fireEvent.click(buttons[1])
    const card = screen.getByRole('region', { name: 'opsloop-web-02' })
    expect(card).toHaveAttribute('data-target', 'web-02')
    expect(card).toHaveTextContent('마지막 수신 2분 전')
    expect(card).not.toHaveTextContent('차단 적용 여부 미확인')
    expect(buttons[1]).toHaveAttribute('aria-controls', card.parentElement?.id)
    // 요소 id 에는 노드 id 가 아니라 순번이 들어간다
    expect(card.parentElement?.id).not.toContain('web-02')
    expect(screen.queryByRole('region', { name: 'opsloop-web-03' })).toBeNull()
  })

  it('악성 hostname 은 카드 · 접힌 줄 모두 표식으로 보이고 실행 · 외부 요청을 만들지 않는다', async () => {
    const hostile = nodeTarget('web-02', { label: MIXED })
    stubDashboard({ targets: targetsResult({ targets: [...targetsResult().targets, hostile], unmapped: { incidents_1h: 1, pending: 1 } }) })
    const wide = renderPage()
    const board = await screen.findByRole('region', { name: '보호 대상' })
    await waitFor(() => expect(board.querySelector('[data-target="web-02"]')).not.toBeNull())
    const title = board.querySelector('[data-target="web-02"] h3') as HTMLElement
    expect(title).toHaveAttribute('title', revealHidden(MIXED))
    expect(title).toHaveTextContent(/^<img src=\/\/a\.attacker\.test/)
    expectInertDom(wide.container)
    expect(within(board).getByRole('link', { name: '장비 미확인 미판정 1' })).toBeInTheDocument()
    wide.unmount()

    narrow()
    const folded = renderPage()
    const list = await screen.findByRole('list', { name: '보호 대상 요약' })
    const row = within(list).getAllByRole('button').at(-1) as HTMLElement
    expect(row.querySelector('[title]')).toHaveAttribute('title', revealHidden(MIXED))
    // 253자에서 자르고(펼치기 단추 없음) 전체는 말풍선으로 본다
    expect(row.textContent).toMatch(/^▸<img src=\/\/a\.attacker\.test\/p\.png onerror=alert\(1\)>.*…수집 정상미판정 3$/)
    fireEvent.click(row)
    expect(row.querySelector('button')).toBeNull()
    expectInertDom(folded.container)
  })

  it('짧은 악성 hostname 은 자르지 않고 모든 표식을 보인다', async () => {
    narrow()
    const label = `${HOSTILE.rlo}${HOSTILE.zwsp}${HOSTILE.bom}`
    stubDashboard({ targets: targetsResult({ targets: [...targetsResult().targets, nodeTarget('web-02', { label })] }) })
    const { container } = renderPage()
    const list = await screen.findByRole('list', { name: '보호 대상 요약' })
    expect(within(list).getAllByRole('button').at(-1)).toHaveTextContent('admin⟨U+202E⟩gnp.exead⟨U+200B⟩min⟨U+FEFF⟩')
    expectInertDom(container)
  })
})
