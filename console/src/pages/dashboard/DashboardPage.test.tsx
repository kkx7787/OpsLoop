import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DashboardPage } from './DashboardPage'
import { LiveContext } from '@/api/live-context'
import { applyLiveMessage } from '@/api/live'
import { noRetryClient, renderRoutes } from '@/test/render'
import { MONITORING_SUMMARY, json } from '@/test/monitoring-fixtures'
import { revealHidden } from '@/lib/untrusted'
import { expectInertDom, expectMixedRevealed, LONG, MIXED } from '@/test/hostile-fixtures'

afterEach(() => vi.unstubAllGlobals())
function renderPage() { return renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', noRetryClient()) }

describe('대시보드', () => {
  it('기존 요약 API만 호출해 경과·목표 초과·비조치율을 표시하고 근거 사건으로 연결한다', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(async () => json(MONITORING_SUMMARY))
    vi.stubGlobal('fetch', fetch)
    renderPage()
    expect(await screen.findByText('6시간 12분')).toBeInTheDocument()
    expect(screen.getByText('판정 목표 초과')).toBeInTheDocument()
    expect(screen.getByText('30.0%')).toBeInTheDocument()
    expect(screen.getByText('판정 없음')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /악성코드 투하/ })).toHaveAttribute('href', '/incidents/R003%7Cv2%7C192.0.2.8')
    expect(fetch.mock.calls.every(([path]) => String(path) === '/api/stats/summary')).toBe(true)
  })

  it('판정 뒤에 흡수됐는데 차단이 없는 출발지를 활성 차단 옆에 알린다', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...MONITORING_SUMMARY, absorbed_unblocked: { sources: 12, incidents: 2, first_key: 'R006|v3|192.0.2.1|x' } })))
    renderPage()
    expect(await screen.findByText('판정 뒤 흡수 미차단 12곳 · 첫 사건 2건')).toBeInTheDocument()
  })

  it('0건도 정상 수신 여부를 확인하도록 안내하며 비율을 만들어내지 않는다', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...MONITORING_SUMMARY, pending: { total: 0, overdue: 0, warning: 0, oldest_seconds: 0, age_distribution: [0,0,0,0,0] }, oldest_pending: [], rule_quality: [] })))
    renderPage()
    expect(await screen.findByText(/미판정 사건이 없습니다/)).toBeInTheDocument()
    expect(screen.getByText('집계할 사건이 없습니다.')).toBeInTheDocument()
    expect(screen.queryByText('0.0%')).toBeNull()
  })

  it('옛 API 응답을 0건으로 표시하지 않고 서버 버전을 안내한다', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json({ open_by_severity: {} })))
    renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('이전 버전')
  })

  it('웹소켓 판정 통보로 요약을 다시 조회한다', async () => {
    const client = noRetryClient()
    let total = 12
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...MONITORING_SUMMARY, pending: { ...MONITORING_SUMMARY.pending, total } })))
    renderRoutes([{ path: '/', element: <DashboardPage /> }], '/', client)
    await screen.findByRole('link', { name: '12건' })
    total = 11
    act(() => applyLiveMessage(client, { type: 'verdict.created', data: { incident_key: 'k' } }))
    expect(await screen.findByRole('link', { name: '11건' })).toBeInTheDocument()
  })

  it('조회 실패 시 이전 수치를 유지하고 마지막 조회와 다시 시도를 표시한다', async () => {
    let fail = false
    const fetch = vi.fn<typeof globalThis.fetch>(async () => fail ? json({ detail: 'DB unavailable' }, 503) : json(MONITORING_SUMMARY))
    vi.stubGlobal('fetch', fetch)
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
    vi.stubGlobal('fetch', vi.fn(async () => json(MONITORING_SUMMARY)))
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
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...MONITORING_SUMMARY, oldest_pending: oldest })))
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
    vi.stubGlobal('fetch', vi.fn(async () => json({ ...MONITORING_SUMMARY, oldest_pending: [{ ...base, rule_name: LONG }] })))
    renderPage()
    const name = await screen.findByTitle(LONG)
    expect(name.textContent).toBe(`${base.rule_id}${'L'.repeat(500)}…`)
    const link = name.closest('a')
    expect(link).not.toBeNull()
    expect(link?.querySelector('button')).toBeNull()
  })
})
