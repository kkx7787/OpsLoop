import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { BlocklistPage } from './BlocklistPage'
import { applyLiveMessage } from '@/api/live'
import { noRetryClient, renderRoutes } from '@/test/render'
import { blockEntry, json } from '@/test/monitoring-fixtures'

afterEach(() => vi.unstubAllGlobals())
function setup(role = 'admin', failing = false) {
  let rows = [blockEntry(), blockEntry({ actor_ip: '192.0.2.9', expires_at: '2026-09-23T08:00:00Z' }), blockEntry({ actor_ip: '192.0.2.10', released_at: '2026-09-23T07:00:00Z' })]
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = String(input)
    if (url === '/api/me') return json({ username: 'tester', role })
    if (url.startsWith('/api/blocklist')) return json(rows)
    if (init?.method === 'POST') {
      if (failing) return json({ detail: '차단 상태가 변경됐습니다' }, 409)
      rows = rows.map(row => row.actor_ip === '192.0.2.8' ? { ...row, released_at: row.checked_at } : row)
      return json({ id: 1, action: 'unblock_ip', incident_key: rows[0].incident_key, operator: 'tester', created_at: rows[0].checked_at }, 201)
    }
    return json({}, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const client = noRetryClient()
  const render = renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', client)
  return { fetch, client, ...render }
}

describe('차단 목록', () => {
  it('서버 시각으로 활성·만료·해제를 구분하고 상태 탭을 주소에 보존한다', async () => {
    const { router, fetch } = setup()
    expect(await screen.findByText('192.0.2.8')).toBeInTheDocument()
    expect(screen.queryByText('192.0.2.9')).toBeNull()
    expect(screen.getAllByText('집행 대기').length).toBeGreaterThan(0)
    expect(screen.getByRole('link', { name: 'R001 · 사건 보기' })).toHaveAttribute('href', '/incidents/R001%7Cv2%7C192.0.2.8')
    fireEvent.click(screen.getByRole('button', { name: '만료 1' }))
    expect(screen.getByText('192.0.2.9')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '해제' })).toBeNull()
    expect(router.state.location.search).toContain('tab=expired')
    expect(fetch.mock.calls.some(([url]) => String(url) === '/api/blocklist?active_only=false')).toBe(true)
  })

  it.each(['viewer', 'operator'])('%s는 해제 버튼을 받지 않는다', async role => {
    setup(role)
    await screen.findByText('192.0.2.8')
    expect(screen.queryByRole('button', { name: '해제' })).toBeNull()
  })

  it('관리자는 두 단계 확인 후 기존 조치 API로 해제하고 활성 목록에서 빠진다', async () => {
    const { fetch } = setup()
    fireEvent.click(await screen.findByRole('button', { name: '해제' }))
    const form = screen.getByRole('form', { name: '192.0.2.8 해제 확인' })
    fireEvent.change(within(form).getByRole('textbox', { name: '해제 사유' }), { target: { value: '정상 운영 확인' } })
    fireEvent.click(within(form).getByRole('button', { name: '해제 확정' }))
    expect(await screen.findByText('192.0.2.8 차단 해제를 기록했습니다')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('192.0.2.8', { exact: true })).toBeNull())
    const post = fetch.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(post[0])).toBe('/api/incidents/R001%7Cv2%7C192.0.2.8/actions')
    expect(JSON.parse(String(post[1]?.body))).toEqual({ action: 'unblock_ip', actor_ip: '192.0.2.8', note: '정상 운영 확인' })
  })

  it('흡수 차단 행은 그 행의 출발지만 풀도록 출발지를 함께 보내고 첫 사건으로 이어진다', async () => {
    const first = 'R006|v3|192.0.2.1|2026-09-20T00:00:00+00:00'
    const row = blockEntry({ actor_ip: '198.51.100.7', reason: `흡수: ${first}`, incident_key: first })
    const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'admin' })
      if (url.startsWith('/api/blocklist')) return json([row])
      if (init?.method === 'POST') return json({ id: 1, action: 'unblock_ip', incident_key: first, operator: 'tester', created_at: row.checked_at, absorbed: { released: 1, actor_ip: '198.51.100.7' } }, 201)
      return json({}, 404)
    })
    vi.stubGlobal('fetch', fetch)
    renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByRole('link', { name: 'R006 · 첫 사건 보기' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '해제' }))
    const form = screen.getByRole('form', { name: '198.51.100.7 해제 확인' })
    expect(within(form).getByText(/흡수 차단 한 곳만 해제할까요\? 첫 사건 출발지의 차단과 다른 흡수 차단은 그대로/)).toBeInTheDocument()
    fireEvent.click(within(form).getByRole('button', { name: '해제 확정' }))
    expect(await screen.findByText('198.51.100.7 차단 해제를 기록했습니다')).toBeInTheDocument()
    const post = fetch.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(post[0])).toBe(`/api/incidents/${encodeURIComponent(first)}/actions`)
    expect(JSON.parse(String(post[1]?.body))).toEqual({ action: 'unblock_ip', actor_ip: '198.51.100.7' })
  })

  it('다른 사람이 먼저 해제한 충돌은 성공으로 표시하지 않는다', async () => {
    setup('admin', true)
    fireEvent.click(await screen.findByRole('button', { name: '해제' }))
    fireEvent.click(screen.getByRole('button', { name: '해제 확정' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('차단 상태가 변경됐습니다')
    expect(screen.queryByText(/차단 해제를 기록했습니다/)).toBeNull()
  })

  it('차단 통보를 받으면 목록을 재조회한다', async () => {
    const { fetch, client } = setup()
    await screen.findByText('192.0.2.8')
    const before = fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/blocklist')).length
    act(() => applyLiveMessage(client, { type: 'action.created', data: { action: 'block_ip' } }))
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/blocklist')).length).toBeGreaterThan(before))
  })
})
