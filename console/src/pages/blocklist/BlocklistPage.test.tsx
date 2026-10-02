import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { BlocklistPage } from './BlocklistPage'
import { applyLiveMessage } from '@/api/live'
import { monitoringKeys } from '@/api/monitoring-keys'
import type { ControlHealth, MonitorItem } from '@/api/health'
import type { BlockEntry } from '@/api/monitoring'
import type { EnforcePointState } from '@/api/incidents'
import { noRetryClient, renderRoutes } from '@/test/render'
import { AS_OF, blockEntry, json } from '@/test/monitoring-fixtures'
import { expectInertDom, expectLongFolds, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

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
  it('활성 행에 집행 지점별 결과를 보이고 까닭은 글자로만 그린다(이슈 #51)', async () => {
    const rows = [
      blockEntry({ actor_ip: '203.0.113.10', method: 'nft', enforced_at: '2026-09-23T07:59:00Z', enforce_note: '관문 반영 · abcd1234 · 2026-09-23T07:59:00Z',
        enforcement: { gateway: { state: 'confirmed', since: '2026-09-23T07:59:00Z', mode: 'nft', note: null },
          fw: { state: 'failed', since: '2026-09-23T08:00:00Z', mode: HOSTILE.style, note: MIXED } } }),
      blockEntry({ actor_ip: '203.0.113.11', enforcement: { gateway: { state: 'pending', since: '2026-09-23T07:59:00Z', mode: null, note: null } } }),
      blockEntry({ actor_ip: '203.0.113.12', released_at: '2026-09-23T07:00:00Z', enforcement: { gateway: { state: 'confirmed', since: null, mode: null, note: null } } }),
    ]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    }))
    const { container } = renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('203.0.113.10')).toBeInTheDocument()
    // 집행 수를 막은 수로 잘못 읽지 않게 하는 한 줄은 본문에, 용어 · 집행 범위는 ⓘ 에
    expect(screen.getByText(/^집행 확인은 요청한 지점이 모두 확인한 것입니다\. 내부 방화벽은 실패 · 미확인을 따로 셉니다/).closest('[data-infotip]')).toBeNull()
    expect(screen.getByRole('button', { name: '집행 범위 설명' })).toHaveAccessibleDescription(/관문 미요청은 내부 방화벽만 요청한 차단입니다/)
    expect(screen.getByRole('button', { name: '집행 범위 설명' })).toHaveAccessibleDescription(/허니팟 관문은 허니팟 유입\(22 · 23 · 8080\)을, 내부 방화벽은 web-01 접근을 막습니다/)
    expect(screen.getByRole('button', { name: '집행 범위 설명' })).toHaveAccessibleDescription(/미확인은 대기 · 확인 지연 · 기록 없음입니다\.$/)
    // 내부 방화벽 칸(#72): 실패 1(203.0.113.10) · 미확인 1(203.0.113.11 기록 없음). 해제된 행은 세지 않는다
    const count = (label: string) => screen.getByText(label, { selector: 'div' }).nextElementSibling as HTMLElement
    expect([count('내부 방화벽 실패').textContent, count('내부 방화벽 미확인').textContent]).toEqual(['1건', '1건'])
    expect(count('내부 방화벽 실패')).toHaveClass('text-warning')
    const points = (ip: string) => [...screen.getByText(ip).closest('li')!.querySelectorAll('[data-enforce-point]')]
      .map(el => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])
    expect(points('203.0.113.10')).toEqual([['gateway', 'confirmed'], ['fw', 'failed']])
    expect(points('203.0.113.11')).toEqual([['gateway', 'pending']])
    const fw = screen.getByText('203.0.113.10').closest('li')!.querySelector('[data-enforce-point="fw"]')!
    expect(fw.textContent).toMatch(/^내부 방화벽실패/)
    // 지점이 보낸 방식 · 까닭은 글자로만, 길면 접는다 (방식 16자 · 까닭 160자)
    const row = screen.getByText('203.0.113.10').closest('li')!
    const disclosure = within(row).getByLabelText('203.0.113.10 집행 상세')
    expect(disclosure.closest('details')).not.toHaveAttribute('open')
    fireEvent.click(disclosure)
    expect(disclosure.closest('details')).toHaveAttribute('open')
    expect(row.textContent).toContain(HOSTILE.style.slice(0, 16))
    expect(fw.textContent).toMatch(/자 더 · 펼치기/)
    expectInertDom(container)
    // 해제된 행은 요청 지점마다 빠짐 확인 전(결과 기록이 남음) · 빠짐이다(#77, 해제 탭)
    fireEvent.click(screen.getByRole('button', { name: /^해제 / }))
    expect(await screen.findByText('203.0.113.12')).toBeInTheDocument()
    expect(points('203.0.113.12')).toEqual([['gateway', 'removing'], ['fw', 'gone']])
  })

  it('지점이 보낸 확인 지연 까닭은 ⓘ 로 접지 않고 본문에 둔다(오류 안내)', async () => {
    const note = '허니팟 관문 보고가 5분 넘게 멈춤 (마지막 2026-09-23T07:50:00Z)'
    const rows = [blockEntry({ actor_ip: '203.0.113.20', enforcement: { gateway: { state: 'stale', since: '2026-09-23T07:59:00Z', mode: 'nft', note } } })]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    }))
    renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('203.0.113.20')).toBeInTheDocument()
    const gateway = screen.getByText('203.0.113.20').closest('li')!.querySelector('[data-enforce-point="gateway"]')!
    expect(gateway).toHaveAttribute('data-point-state', 'stale')
    expect(within(gateway as HTMLElement).getByText('확인 지연')).toBeInTheDocument()
    expect(within(gateway as HTMLElement).getByText(note).closest('[data-infotip]')).toBeNull()
    expect(within(gateway as HTMLElement).queryByRole('button', { name: /설명$/ })).toBeNull()
  })

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
    expect(within(form).getByText('198.51.100.7 의 흡수 차단 한 곳만 해제할까요? 이 출발지는 이후 후속 차단에서도 빠집니다.')).toBeInTheDocument()
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

  it('활성 요청을 집행 확인 · 대기 · 실패 · 불일치 · 제외로 나눠 세고 행마다 까닭을 보인다(이슈 #47 · #77)', async () => {
    const rows = [
      blockEntry({ actor_ip: '198.51.100.1', method: 'fail2ban', enforced_at: '2026-09-23T07:59:00Z', enforce_note: '관문 반영 · abcd1234 · 2026-09-23T07:59:00Z',
        enforcement: { fw: { state: 'confirmed', since: '2026-09-23T07:59:30Z', mode: 'nft', note: null } } }),
      blockEntry(),
      blockEntry({ actor_ip: '198.51.100.2', expires_at: null, enforce_note: '집행 제외 · 만료 없음' }),
      blockEntry({ actor_ip: '198.51.100.3', expires_at: null }),
      blockEntry({ actor_ip: '198.51.100.4', method: 'nft', enforced_at: '2026-09-23T07:00:00Z', enforce_note: '관문 불일치 · 관문 상태가 7분 전' }),
      blockEntry({ actor_ip: '198.51.100.5', released_at: '2026-09-23T07:00:00Z', enforced_at: null }),
      blockEntry({ actor_ip: '198.51.100.6', expires_at: '2026-09-23T07:00:00Z' }),
      // 풀었지만 관문이 뺀 목록을 적용했다는 보고가 아직 없다(enforced_at 이 남음). 관문은 아직 막고 있을 수 있다
      blockEntry({ actor_ip: '198.51.100.7', released_at: '2026-09-23T07:00:00Z', method: 'nft', enforced_at: '2026-09-23T06:00:00Z', enforce_note: '관문 반영 · abcd1234 · 2026-09-23T06:00:00Z' }),
    ]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    }))
    const { container } = renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('198.51.100.1')).toBeInTheDocument()
    const count = (label: string) => screen.getByText(label, { selector: 'div' }).nextElementSibling?.textContent
    // 합친 수는 지점 이름 없이 종합 상태로 센다(요청한 지점이 모두 확인해야 집행 확인)
    expect([count('활성 요청'), count('집행 확인'), count('집행 대기'), count('집행 실패'), count('불일치'), count('집행 제외')]).toEqual(['5건', '1건', '1건', '0건', '1건', '2건'])
    // 지점 기록이 없는 집행 대상 행(대기 · 불일치)은 내부 방화벽 미확인이다. 제외 · 해제 · 만료는 세지 않는다
    expect([count('내부 방화벽 실패'), count('내부 방화벽 미확인')]).toEqual(['0건', '2건'])
    // 관문 미요청이 없으면 칸을 두지 않는다
    expect(screen.queryByText('관문 미요청', { selector: 'div' })).toBeNull()
    const states = [...container.querySelectorAll('[data-block-state]')].map(el => el.getAttribute('data-block-state'))
    expect(states.sort()).toEqual(['enforced', 'excluded', 'excluded', 'mismatch', 'pending'])
    const cell = (ip: string) => screen.getByText(ip).closest('li')!.querySelector('[data-block-state]')!.textContent!.replace('집행 상세', '')
    expect(cell('198.51.100.1')).toMatch(/^집행 확인내부 방화벽적용 확인관문 · 내부 방화벽 반영 확인 \S+ \S+ · fail2ban관문 반영 · abcd1234/)
    expect(cell('192.0.2.8')).toBe('집행 대기관문 · 내부 방화벽 반영 확인 전')
    expect(cell('198.51.100.2')).toBe('집행 제외만료 없는 차단 · 관문 · 내부 방화벽에 넘기지 않음집행 제외 · 만료 없음')
    expect(cell('198.51.100.3')).toBe('집행 제외만료 없는 차단 · 관문 · 내부 방화벽에 넘기지 않음')
    expect(cell('198.51.100.4')).toMatch(/^관문 불일치관문 상태가 목록과 다름 · 마지막 확인 \S+ \S+ · nft관문 불일치 · 관문 상태가 7분 전$/)
    fireEvent.click(screen.getByRole('button', { name: '해제 2' }))
    // 목록 밖 행은 요청 지점마다 빠짐 확인 전(관문 enforced_at · 결과 기록이 남음) · 빠짐이다(#77)
    expect(cell('198.51.100.5')).toBe('해제됨허니팟 관문빠짐내부 방화벽빠짐사람이 풂 · 관문 · 내부 방화벽 목록에서 빠짐')
    expect(cell('198.51.100.7')).toBe('해제됨허니팟 관문빠짐 확인 전내부 방화벽빠짐사람이 풂 · 관문에서 빠졌는지 확인 전 · nft관문 반영 · abcd1234 · 2026-09-23T06:00:00Z')
    fireEvent.click(screen.getByRole('button', { name: '만료 1' }))
    expect(cell('198.51.100.6')).toBe('만료됨허니팟 관문빠짐내부 방화벽빠짐만료가 지남 · 관문 · 내부 방화벽 목록에서 빠짐')
  })

  it('관제 상태 캐시에 내부 방화벽 집행기 멈춤이 있으면 두 칸 뒤에 집행기 멈춤을 붙이고 수는 그대로 둔다(#72)', async () => {
    const rows = [
      blockEntry({ actor_ip: '203.0.113.30', enforcement: { fw: { state: 'confirmed', since: AS_OF, mode: 'nft', note: null } } }),
      blockEntry({ actor_ip: '203.0.113.31', enforcement: { fw: { state: 'failed', since: AS_OF, mode: 'nft', note: null } } }),
    ]
    const item = (key: string): MonitorItem => ({ key, level: 'alert', label: key, reason: '집행기 확인 중단 · 마지막 확인 12분 전', at: null, count: null })
    const health = (items: MonitorItem[]): ControlHealth => ({ as_of: AS_OF, items, detect_paths: [] })
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    })
    vi.stubGlobal('fetch', fetch)
    const count = (label: string) => screen.getByText(label, { selector: 'div' }).nextElementSibling as HTMLElement

    // 관문 집행기만 멈추면 붙이지 않는다
    const client = noRetryClient()
    client.setQueryData(monitoringKeys.health, health([item('enforcer:gateway')]))
    const view = renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', client)
    expect(await screen.findByText('203.0.113.30')).toBeInTheDocument()
    expect(count('내부 방화벽 실패').textContent).toBe('1건')

    // 틀이 받아 둔 캐시가 바뀌면 따라간다
    act(() => client.setQueryData(monitoringKeys.health, health([item('enforcer:gateway'), item('enforcer:fw')])))
    await waitFor(() => expect(count('내부 방화벽 실패').textContent).toBe('1건 · 집행기 멈춤'))
    expect(count('내부 방화벽 미확인').textContent).toBe('0건 · 집행기 멈춤')
    expect(within(count('내부 방화벽 미확인')).getByText('· 집행기 멈춤')).toHaveClass('text-warning')
    expect(count('불일치').textContent).toBe('0건')
    // 관제 상태를 따로 묻지 않는다(캐시만 읽는다)
    expect(fetch.mock.calls.some(([url]) => String(url).startsWith('/api/dashboard/monitor'))).toBe(false)
    view.unmount()

    // 캐시가 없으면(받기 전) 붙이지 않는다
    renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('203.0.113.30')).toBeInTheDocument()
    expect(count('내부 방화벽 실패').textContent).toBe('1건')
    expect(fetch.mock.calls.some(([url]) => String(url).startsWith('/api/dashboard/monitor'))).toBe(false)
  })

  it('내부 방화벽만 요청한 행은 관문 칸이 미요청(관문 빼기 뒤 확인 전이면 빠짐 확인 전)이고, 그 수를 따로 두며 배지로 종합 상태를 보인다(#77)', async () => {
    const at = '2026-09-23T07:59:00Z'
    const point = (state: EnforcePointState) => ({ state, since: at, mode: 'nft', note: null })
    const rows: BlockEntry[] = [
      blockEntry({ actor_ip: '203.0.113.40', points: ['fw'], enforcement: { fw: point('confirmed') } }),
      blockEntry({ actor_ip: '203.0.113.41', points: ['fw'] }),
      blockEntry({ actor_ip: '203.0.113.42', method: 'nft', enforced_at: at, enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('confirmed'), fw: point('confirmed') } }),
      blockEntry({ actor_ip: '203.0.113.43', enforcement: { gateway: point('failed'), fw: point('confirmed') } }),
      blockEntry({ actor_ip: '203.0.113.44', method: 'nft', enforced_at: at, enforcement: { gateway: point('confirmed'), fw: point('stale') } }),
      // 관문이 내부 방화벽보다 먼저 확인된 새 두 지점 차단: 종합은 집행 대기다
      blockEntry({ actor_ip: '203.0.113.45', method: 'nft', enforced_at: at, enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('confirmed'), fw: point('pending') } }),
      // 관리자 관문 빼기 뒤 관문이 뺐다고 확인하기 전(결정 14): 관문 세 열 · 관문 결과가 남아 관문 칸은 빠짐 확인 전이다
      blockEntry({ actor_ip: '203.0.113.46', points: ['fw'], method: 'nft', enforced_at: at, enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('removing'), fw: point('confirmed') } }),
    ]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    }))
    renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('203.0.113.40')).toBeInTheDocument()
    const count = (label: string) => screen.getByText(label, { selector: 'div' }).nextElementSibling as HTMLElement
    const text = (label: string) => count(label).textContent
    expect([text('활성 요청'), text('집행 확인'), text('집행 대기'), text('집행 실패'), text('불일치')]).toEqual(['7건', '3건', '2건', '1건', '1건'])
    // 내부 방화벽 수는 요청 행 그대로(미확인: 기록 없음 · 지연 · 대기). 관문 미요청 · 빠짐 확인 전은 따로 두고 주의색이 아니다(미확인 · 실패와 섞지 않는다)
    expect([text('내부 방화벽 실패'), text('내부 방화벽 미확인'), text('관문 미요청'), text('관문 빠짐 확인 전')]).toEqual(['0건', '3건', '2건', '1건'])
    expect(count('관문 미요청')).not.toHaveClass('text-warning')
    expect(count('관문 빠짐 확인 전')).not.toHaveClass('text-warning')
    const li = (ip: string) => screen.getByText(ip).closest('li')!
    const points = (ip: string) => [...li(ip).querySelectorAll('[data-enforce-point]')].map(el => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])
    expect(points('203.0.113.40')).toEqual([['gateway', 'unrequested'], ['fw', 'confirmed']])
    expect(points('203.0.113.41')).toEqual([['gateway', 'unrequested']])
    expect(points('203.0.113.46')).toEqual([['gateway', 'removing'], ['fw', 'confirmed']])
    expect(li('203.0.113.40').querySelector('[data-enforce-point="gateway"]')).toHaveTextContent(/^허니팟 관문미요청$/)
    // 배지: 관문 칸이 종합 상태를 대신하지 못하는 행(종합이 집행 확인이 아니거나 관문 칸이 적용 확인이 아님)에만. 불일치는 그 지점 이름이다
    const cell = (ip: string) => li(ip).querySelector('[data-block-state]')!.textContent!.replace('집행 상세', '')
    expect(cell('203.0.113.40')).toMatch(/^집행 확인허니팟 관문미요청내부 방화벽적용 확인내부 방화벽 반영 확인/)
    expect(cell('203.0.113.41')).toMatch(/^집행 대기허니팟 관문미요청내부 방화벽 반영 확인 전/)
    expect(cell('203.0.113.42')).toMatch(/^허니팟 관문적용 확인내부 방화벽적용 확인/)
    expect(cell('203.0.113.43')).toMatch(/^집행 실패허니팟 관문실패내부 방화벽적용 확인/)
    expect(cell('203.0.113.44')).toMatch(/^내부 방화벽 불일치허니팟 관문적용 확인내부 방화벽확인 지연/)
    expect(cell('203.0.113.45')).toMatch(/^집행 대기허니팟 관문적용 확인내부 방화벽대기내부 방화벽 반영 확인 전/)
    expect(cell('203.0.113.46')).toMatch(/^집행 확인허니팟 관문빠짐 확인 전내부 방화벽적용 확인내부 방화벽 반영 확인 · 관문에서 빠졌는지 확인 전/)
    // 집행 상세의 지점별 시각 · 방식은 결과 기록이 있는 줄만(미요청은 기록이 아니다)
    fireEvent.click(within(li('203.0.113.40')).getByLabelText('203.0.113.40 집행 상세'))
    expect(li('203.0.113.40').querySelector('details')!.textContent).not.toContain('허니팟 관문 ·')
    // 관문을 뺀 행에 남은 관문 메모(관문 세 열)는 집행 상세에 보이지 않는다(관문 칸이 빠짐 확인 전으로 대신한다). 관문 요청 행은 그대로다
    fireEvent.click(within(li('203.0.113.46')).getByLabelText('203.0.113.46 집행 상세'))
    expect(li('203.0.113.46').querySelector('details')!.textContent).not.toContain('관문 반영 · abcd1234')
    fireEvent.click(within(li('203.0.113.42')).getByLabelText('203.0.113.42 집행 상세'))
    expect(li('203.0.113.42').querySelector('details')!.textContent).toContain('관문 반영 · abcd1234 · x')
  })

  it('차단 통보를 받으면 목록을 재조회한다', async () => {
    const { fetch, client } = setup()
    await screen.findByText('192.0.2.8')
    const before = fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/blocklist')).length
    act(() => applyLiveMessage(client, { type: 'action.created', data: { action: 'block_ip' } }))
    await waitFor(() => expect(fetch.mock.calls.filter(([url]) => String(url).startsWith('/api/blocklist')).length).toBeGreaterThan(before))
  })
})

describe('차단 목록 · 비신뢰 문자열(#41)', () => {
  it('사유 · 방식 · 집행 메모 · 요청자 · 해제자를 글자로만 그리고 숨은 문자는 표식 · 2만 자는 접는다', async () => {
    const rows = [
      blockEntry({ reason: MIXED, method: HOSTILE.style, enforce_note: LONG, requested_by: HOSTILE.rlo }),
      blockEntry({ actor_ip: '192.0.2.10', released_at: '2026-09-23T07:00:00Z', released_by: HOSTILE.zwsp }),
    ]
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'admin' })
      if (url.startsWith('/api/blocklist')) return json(rows)
      return json({}, 404)
    }))
    const { container } = renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('192.0.2.8')).toBeInTheDocument()
    expectInertDom(container)
    expectMixedRevealed(container)
    expect(container.textContent).toContain(HOSTILE.style)
    expect(container.textContent).toContain('요청자 admin⟨U+202E⟩gnp.exe')
    expectLongFolds(container)

    fireEvent.click(screen.getByRole('button', { name: '해제 1' }))
    expect(await screen.findByText('192.0.2.10')).toBeInTheDocument()
    expect(container.textContent).toContain(' · ad⟨U+200B⟩min')
    expectInertDom(container)
  })

  it('좁은 화면은 핵심 칸 넷을 먼저 두고 나머지는 접으며, 접힌 주의 칸의 수를 접힘 줄에 적는다(이슈 #94)', async () => {
    setup()
    expect(await screen.findByText('192.0.2.8')).toBeInTheDocument()
    const cell = (label: string) => screen.getByText(label, { selector: 'div' }).parentElement as HTMLElement
    const core = ['활성 요청', '집행 실패', '불일치', '내부 방화벽 실패']
    const rest = ['집행 확인', '집행 대기', '내부 방화벽 미확인', '집행 제외', '24시간 내 만료']
    // 칸은 늘 DOM 에 있고 sm 미만에서만 CSS 로 숨긴다(sm 이상은 그대로). 핵심 칸은 펼친 뒤에도 앞에 온다
    for (const label of core) expect(cell(label)).toHaveClass('max-sm:order-first')
    for (const label of core) expect(cell(label)).not.toHaveClass('max-sm:hidden')
    for (const label of rest) expect(cell(label)).toHaveClass('max-sm:hidden')
    // 접힌 주의 칸 중 0 보다 큰 값만 적는다(집행 대기 1 · 내부 방화벽 미확인 1)
    const fold = screen.getByRole('button', { name: /^나머지 칸/ })
    expect(fold).toHaveClass('sm:hidden')
    expect(fold).toHaveAttribute('aria-expanded', 'false')
    expect(fold.textContent).toBe('나머지 칸 5개 보기 · 집행 대기 1건 · 내부 방화벽 미확인 1건')
    fireEvent.click(fold)
    expect(fold).toHaveAttribute('aria-expanded', 'true')
    expect(fold.textContent).toBe('나머지 칸 접기')
    for (const label of rest) expect(cell(label)).not.toHaveClass('max-sm:hidden')
  })

  it('접힌 주의 칸이 모두 0 이면 접힘 줄에 수를 적지 않는다(이슈 #94)', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = String(input)
      if (url === '/api/me') return json({ username: 'tester', role: 'viewer' })
      if (url.startsWith('/api/blocklist')) return json([blockEntry({ actor_ip: '198.51.100.2', expires_at: null })])
      return json({}, 404)
    }))
    renderRoutes([{ path: '/blocklist', element: <BlocklistPage /> }], '/blocklist', noRetryClient())
    expect(await screen.findByText('198.51.100.2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^나머지 칸/ }).textContent).toBe('나머지 칸 5개 보기')
  })
})
