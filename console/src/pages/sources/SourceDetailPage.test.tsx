import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SourceDetail } from '@/api/sources'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { expectInertDom, expectLongFolds, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'
import { HASSH, LIVE_BLOCK, sourceDetail, sourceSummary } from '@/test/sources-fixtures'
import { COWRIE, device } from '@/test/targets-fixtures'
import { IncidentsPage } from '@/pages/incidents/IncidentsPage'
import { SourceDetailPage } from './SourceDetailPage'

afterEach(() => vi.unstubAllGlobals())

const IP = '198.51.100.23'

/** 상세 응답을 정한 fetch. 사건 목록 화면으로 넘어가면 그 요청에도 답한다 */
function setup(path: string, detail: (url: URL) => Response = () => json(sourceDetail())) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/sources/detail') return detail(url)
    if (url.pathname === '/api/incidents') return json({ total: 0, limit: 25, offset: 0, items: [] })
    if (url.pathname === '/api/cti/badges') return json({ badges: {} })
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const view = renderRoutes([
    { path: '/sources/detail', element: <SourceDetailPage /> },
    { path: '/sources', element: <p>출발지 목록 본문</p> },
    { path: '/incidents', element: <IncidentsPage /> },
    { path: '/incidents/:key', element: <p>사건 상세 본문</p> },
  ], path, noRetryClient())
  return { fetch, ...view }
}

/** 요약 구역의 한 항목(dt 이름 → dd) */
function fact(region: HTMLElement, label: string): HTMLElement {
  return within(region).getByText(label, { selector: 'dt' }).nextElementSibling as HTMLElement
}

function detailRequests(fetch: ReturnType<typeof setup>['fetch']): URLSearchParams[] {
  return fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost')).filter((url) => url.pathname === '/api/sources/detail').map((url) => url.searchParams)
}

describe('출발지 상세', () => {
  it('요약 · 사건 흐름 · 이벤트 종류 · 도구 지문 · 차단 상태 · 조치 이력을 보인다', async () => {
    const { fetch } = setup(`/sources/detail?ip=${IP}`)
    expect(await screen.findByRole('heading', { level: 1, name: IP })).toBeInTheDocument()
    expect(detailRequests(fetch).map((params) => params.get('ip'))).toEqual([IP])

    const summary = screen.getByRole('region', { name: '요약' })
    expect(within(summary).getByText('4건 · 미판정 1')).toBeInTheDocument()
    expect(within(summary).getByText('R001 · R003')).toBeInTheDocument()
    expect(within(summary).getByText('허니팟 센서')).toBeInTheDocument()
    // 흡수 기록은 요약 항목 하나, 계산 기준(사건 수에 들지 않음)은 이름 옆 ⓘ
    expect(fact(summary, '흡수 기록')).toHaveTextContent('3건')
    expect(within(summary).getByRole('button', { name: '흡수 기록 설명' })).toHaveAccessibleDescription(/흡수된 사건은 사건 수에 들지 않습니다/)
    expect(fact(summary, '판정 분포')).toHaveAccessibleDescription('사건마다 마지막 판정입니다.')
    // 사건 시각(첫 · 마지막 사건)과 마지막 관측(이벤트)을 따로 적는다. 마지막 관측이 사건보다 늦을 수 있다
    expect(fact(summary, '첫 사건')).toHaveTextContent('2026-09-27 10:00:00')
    expect(fact(summary, '마지막 사건')).toHaveTextContent('2026-09-29 11:40:00')
    expect(fact(summary, '마지막 관측')).toHaveTextContent('2026-09-29 11:55:00')
    expect(within(summary).queryByText('마지막 활동')).toBeNull()

    // 사건 흐름: 첫 시각 순, 규칙을 누르면 사건 상세
    const flow = screen.getByRole('table', { name: '사건 흐름' })
    const links = within(flow).getAllByRole('link')
    expect(links.map((a) => a.textContent)).toEqual(['R001', 'R003'])
    expect(links[1]).toHaveAttribute('href', `/incidents/${encodeURIComponent(`R003|v3|${IP}|2026-09-29T02:30:00+00:00`)}`)
    expect(within(flow).getByText('미판정')).toBeInTheDocument()
    expect(within(flow).getByText('실제 위협')).toBeInTheDocument()

    const events = screen.getByRole('table', { name: '이벤트 종류' })
    expect(within(events).getByText('cowrie.login.failed')).toBeInTheDocument()
    expect(within(events).getByText('120')).toBeInTheDocument()

    const prints = screen.getByRole('region', { name: '도구 지문' })
    expect(within(prints).getByText(HASSH)).toBeInTheDocument()
    expect(within(prints).getByText('SSH-2.0-Go')).toBeInTheDocument()
    // 같은 지문 주의는 구역 머리 ⓘ(구역 이름에는 섞이지 않는다)
    const sameTool = within(prints).getByRole('button', { name: '도구 지문 설명' })
    expect(sameTool).toHaveAccessibleDescription(/^같은 지문이 같은 행위자라는 뜻은 아닙니다/)
    fireEvent.click(sameTool)
    expect(sameTool).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('region', { name: '도구 지문' })).toBe(prints)
    expect(within(prints).getAllByRole('link', { name: '같은 지문 출발지' })[0]).toHaveAttribute('href', `/sources?include_test=true&fp_kind=hassh&fp=${HASSH}`)

    // 차단 상태: 사건 상세와 같은 나눔 · 지점별 결과(EnforcePointList). 요청한 두 지점 가운데 내부 방화벽이 대기라 집행 대기다(#77)
    const block = screen.getByRole('region', { name: '차단 상태' })
    expect(block.querySelector('[data-block-state]')).toHaveAttribute('data-block-state', 'pending')
    expect(within(block).getByText('내부 방화벽 반영 확인 전')).toBeInTheDocument()
    expect([...block.querySelectorAll('[data-enforce-point]')].map((el) => el.getAttribute('data-point-state'))).toEqual(['confirmed', 'pending'])
    expect(within(block).getByText('han')).toBeInTheDocument()

    const actions = screen.getByRole('table', { name: '조치 이력' })
    expect(within(actions).getByText('차단')).toBeInTheDocument()
    expect(within(actions).getByRole('link', { name: 'R003' })).toBeInTheDocument()

    expect(screen.getByRole('link', { name: '사건 목록에서 보기' })).toHaveAttribute('href', `/incidents?actor_ip=${IP}`)
  })

  it('사건 흐름의 장비 열은 사건 목록과 같은 장비 배지이고, 장비를 못 정한 사건은 장비 미확인이다', async () => {
    const [first, second] = sourceDetail().incidents
    const detail = sourceDetail({
      incidents: [
        { ...first, devices: [device(), COWRIE], device_state: 'confirmed' },
        // 대체 추정 장비는 배지에 쓰지 않는다
        { ...second, devices: [], device_state: 'unconfirmed', device_fallback: [{ ...COWRIE, basis: 'fallback' }] },
      ],
    })
    setup(`/sources/detail?ip=${IP}`, () => json(detail))
    const flow = await screen.findByRole('table', { name: '사건 흐름' })
    expect(within(flow).getByRole('columnheader', { name: '장비' })).toBeInTheDocument()
    expect(within(flow).queryByRole('columnheader', { name: '대상' })).toBeNull()

    const cells = [...flow.querySelectorAll('td[data-label="장비"]')] as HTMLElement[]
    expect(cells).toHaveLength(2)
    expect([...cells[0].querySelectorAll('[data-device]')].map((el) => el.textContent)).toEqual(['web-01 · 웹 접근', 'SSH 허니팟(Cowrie) · SSH 세션'])
    expect(cells[1].querySelector('[data-device-unknown]')).toHaveTextContent('장비 미확인')
    expect(cells[1].querySelector('[data-device]')).toBeNull()
    expect(cells[1]).not.toHaveTextContent('Cowrie')

    // 요약 '노린 대상' 은 이벤트 발생원 기준이라 따로 그린다
    expect(fact(screen.getByRole('region', { name: '요약' }), '노린 대상')).toHaveTextContent('허니팟 센서')
  })

  it('사건 목록에서 보기는 출발지 조건으로 사건 목록을 열고, 조건 칩으로 뺄 수 있다', async () => {
    const v6 = '2001:db8::5'
    const { fetch, router } = setup(`/sources/detail?ip=${encodeURIComponent(v6)}`, () => json(sourceDetail({ ip: v6, summary: sourceSummary({ ip: v6 }) })))
    fireEvent.click(await screen.findByRole('link', { name: '사건 목록에서 보기' }))
    const chip = await screen.findByRole('button', { name: '출발지 조건 빼기' })
    expect(chip.parentElement).toHaveTextContent(`출발지 ${v6}`)
    await waitFor(() => expect(fetch.mock.calls.some(([input]) => new URL(String(input), 'http://localhost').searchParams.get('actor_ip') === v6)).toBe(true))
    expect(screen.getByText('조건에 맞는 인시던트가 없습니다')).toBeInTheDocument()
    fireEvent.click(chip)
    await waitFor(() => expect(router.state.location.search).toBe(''))
    expect(screen.queryByRole('button', { name: '출발지 조건 빼기' })).toBeNull()
  })

  it('사건이 없는 출발지(이벤트만)는 요약 대신 안내를 보이고 사건 목록 링크를 두지 않는다', async () => {
    setup(`/sources/detail?ip=${IP}`, () => json(sourceDetail({ summary: null, incidents: [], incidents_total: 0, actions: [], block: null, absorbed: null, last_seen: '2026-09-28T07:20:34Z', exempt_flag: false })))
    expect(await screen.findByText('사건 없음 · 수집 이벤트만 있습니다')).toBeInTheDocument()
    expect(fact(screen.getByRole('region', { name: '요약' }), '마지막 관측')).toHaveTextContent('2026-09-28 16:20:34')
    // 금지 대역이 아니면(exempt_flag false) 표지를 두지 않는다
    expect(screen.queryByText('금지 대역 확인 불가')).toBeNull()
    expect(screen.queryByRole('button', { name: '금지 대역 확인 불가 설명' })).toBeNull()
    // 흡수 기록을 읽을 수 없으면 0 이 아니라 확인 불가
    expect(fact(screen.getByRole('region', { name: '요약' }), '흡수 기록')).toHaveTextContent(/^확인 불가$/)
    expect(screen.getByText('사건이 없습니다.')).toBeInTheDocument()
    expect(screen.getByText('차단한 적 없음')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '사건 목록에서 보기' })).toBeNull()
  })

  it('사건 없는 출발지도 금지 대역 판단(exempt_flag)을 머리 표지와 차단 상태에 보인다. 표를 읽을 수 없으면 확인 불가', async () => {
    const noIncidents = { summary: null, incidents: [], incidents_total: 0, actions: [], block: null }
    setup(`/sources/detail?ip=10.0.21.10`, () => json(sourceDetail({ ...noIncidents, ip: '10.0.21.10', exempt: null, exempt_flag: null })))
    await screen.findByRole('heading', { level: 1, name: '10.0.21.10' })
    // block_exempt 를 읽을 수 없으면 '아님'으로 뭉개지 않는다. 경고는 머리 표지로 본문에, 까닭은 표지 옆 ⓘ
    expect(screen.getByText('금지 대역 확인 불가').closest('[data-infotip]')).toBeNull()
    expect(screen.getByRole('button', { name: '금지 대역 확인 불가 설명' })).toHaveAccessibleDescription(/차단 금지 대역 표를 읽을 수 없어 이 주소가 금지 대역인지 모릅니다/)
    // 차단 상태 구역은 머리 표지를 되풀이하지 않는다
    const block = screen.getByRole('region', { name: '차단 상태' })
    expect(within(block).queryByText(/금지 대역/)).toBeNull()
    expect(block.querySelector('[data-block-exempt]')).toBeNull()
  })

  it('사건 없는 출발지가 금지 대역이면(exempt_flag true) 표지와 차단 상태 문구를 보인다', async () => {
    const noIncidents = { summary: null, incidents: [], incidents_total: 0, actions: [], block: null }
    setup(`/sources/detail?ip=10.0.21.10`, () => json(sourceDetail({ ...noIncidents, ip: '10.0.21.10', exempt: { cidr: '10.0.0.0/8', note: '사설 대역' }, exempt_flag: true })))
    await screen.findByRole('heading', { level: 1, name: '10.0.21.10' })
    expect(screen.queryByText('금지 대역 확인 불가')).toBeNull()
    const block = screen.getByRole('region', { name: '차단 상태' })
    expect(block.querySelector('[data-block-exempt]')).toHaveTextContent(/^차단 금지 대역 10\.0\.0\.0\/8\(사설 대역\)$/)
    expect(screen.getAllByText('차단 금지 대역').length).toBeGreaterThan(0)
  })

  it('금지 대역 · 집행기 확인 멈춤을 보인다', async () => {
    setup(`/sources/detail?ip=10.0.3.7`, () => json(sourceDetail({
      ip: '10.0.3.7',
      summary: sourceSummary({ ip: '10.0.3.7', exempt: true }),
      exempt: { cidr: '10.0.0.0/8', note: '사설 대역' },
      checkers: { gateway_stale: true, fw_stale: false },
    })))
    await screen.findByRole('heading', { level: 1, name: '10.0.3.7' })
    expect(screen.getAllByText('차단 금지 대역').length).toBeGreaterThan(0)
    const block = screen.getByRole('region', { name: '차단 상태' })
    expect(block.querySelector('[data-block-exempt]')).toHaveTextContent(/^차단 금지 대역 10\.0\.0\.0\/8\(사설 대역\)$/)
    expect(block.querySelector('[data-enforce-point="gateway"]')).toHaveAttribute('data-point-state', 'stale')
    expect(screen.getByText('집행기 확인이 멈췄습니다')).toBeInTheDocument()
    // 멈춤 띠 · 금지 대역 줄은 경고라 도움말 안이 아니라 본문에 있다
    expect(screen.getByText(/허니팟 관문 · 10분 넘게 확인 없음$/).closest('[data-infotip]')).toBeNull()
    expect(block.querySelector('[data-block-exempt]')!.closest('[data-infotip]')).toBeNull()
    expect(within(block.querySelector<HTMLElement>('[data-enforce-point="gateway"]')!).getByRole('button', { name: /설명$/ })).toHaveAccessibleDescription(/마지막 적용 확인을 믿지 않습니다/)
  })

  it('내부 방화벽만 요청한 차단은 관문 칸이 미요청이고 멈춤으로 덮지 않으며, 해제 뒤에는 요청 지점마다 빠짐 확인 전 · 빠짐이다(#77)', async () => {
    const fwOnly = { ...LIVE_BLOCK, points: ['fw' as const], method: null, enforced_at: null, enforce_note: null, enforcement: { fw: { state: 'confirmed' as const, since: '2026-09-29T02:00:30Z', mode: 'nft', note: null } } }
    const { unmount } = setup(`/sources/detail?ip=${IP}`, () => json(sourceDetail({ block: fwOnly, checkers: { gateway_stale: true, fw_stale: false } })))
    const block = await screen.findByRole('region', { name: '차단 상태' })
    const states = () => [...block.querySelectorAll('[data-enforce-point]')].map((el) => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])
    expect(block.querySelector('[data-block-state]')).toHaveAttribute('data-block-state', 'enforced')
    expect(within(block).getByText('내부 방화벽 반영 확인')).toBeInTheDocument()
    // 관문 집행기가 멈췄어도 미요청은 요청 사실이라 확인 지연으로 바꾸지 않는다
    expect(states()).toEqual([['gateway', 'unrequested'], ['fw', 'confirmed']])
    expect(block.querySelector('[data-enforce-point="gateway"]')).toHaveTextContent(/^허니팟 관문미요청$/)
    unmount()

    const released = { ...LIVE_BLOCK, released_at: '2026-09-29T02:30:00Z', enforced_at: null, enforcement: { fw: { state: 'removing' as const, since: '2026-09-29T02:31:00Z', mode: 'nft', note: null } } }
    setup(`/sources/detail?ip=${IP}`, () => json(sourceDetail({ block: released })))
    const after = await screen.findByRole('region', { name: '차단 상태' })
    expect([...after.querySelectorAll('[data-enforce-point]')].map((el) => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])).toEqual([['gateway', 'gone'], ['fw', 'removing']])
    expect(within(after).getByText('사람이 풂 · 내부 방화벽에서 빠졌는지 확인 전')).toBeInTheDocument()
    expect(after.querySelector('[data-enforce-point="fw"]')).toHaveTextContent(/^내부 방화벽빠짐 확인 전/)
  })

  it('기록이 없는 주소(404)는 없음 화면과 목록으로 돌아가는 링크를 보인다', async () => {
    setup(`/sources/detail?ip=192.0.2.200`, () => json({ detail: '이 주소의 사건 · 이벤트가 없습니다' }, 404))
    expect(await screen.findByRole('heading', { level: 1, name: '이 출발지의 기록이 없습니다' })).toBeInTheDocument()
    expect(screen.getByText(/이 주소의 사건 · 이벤트가 없습니다/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('link', { name: '출발지 목록으로' }))
    expect(await screen.findByText('출발지 목록 본문')).toBeInTheDocument()
  })

  it.each(['abc', '203.0.113.0/24', '01.2.3.4', 'fe80::1%eth0'])('주소 하나가 아닌 값(%s)은 묻지 않는다', async (bad) => {
    const { fetch } = setup(`/sources/detail?${new URLSearchParams({ ip: bad })}`)
    expect(await screen.findByRole('heading', { level: 1, name: '출발지 주소가 올바르지 않습니다' })).toBeInTheDocument()
    expect(screen.getByText(bad)).toBeInTheDocument()
    expect(detailRequests(fetch)).toEqual([])
  })

  it('서버가 422 를 주면 같은 화면을 보인다', async () => {
    const { fetch } = setup(`/sources/detail?ip=${IP}`, () => json({ detail: [{ loc: ['query', 'ip'], msg: '주소 형식이 아닙니다' }] }, 422))
    expect(await screen.findByRole('heading', { level: 1, name: '출발지 주소가 올바르지 않습니다' })).toBeInTheDocument()
    expect(detailRequests(fetch)).toHaveLength(1)
  })

  it('주소가 비어 있으면 주소 없음으로 알린다', async () => {
    const { fetch } = setup('/sources/detail')
    expect(await screen.findByText('주소 없음')).toBeInTheDocument()
    expect(detailRequests(fetch)).toEqual([])
  })

  it('조회가 실패하면(5xx) 오류 화면과 다시 시도를 보인다', async () => {
    setup(`/sources/detail?ip=${IP}`, () => json({ detail: '일시 오류' }, 503))
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
  })
})

describe('출발지 상세 · 악성 문자열(#41)', () => {
  it('지문 · 이벤트 · 조치 · 차단 · 사건 · 장비의 비신뢰 값을 글자로만 그리고 긴 값은 접는다', async () => {
    const detail: SourceDetail = sourceDetail({
      summary: sourceSummary({ block: LIVE_BLOCK, targets: [HOSTILE.svg] }),
      incidents: [{ ...sourceDetail().incidents[0], rule_name: HOSTILE.style, devices: [device({ id: 'web-02', label: MIXED })] }],
      event_kinds: [{ sensor: HOSTILE.prefetch, eventid: HOSTILE.rlo, count: 1, first_ts: '2026-09-27T01:00:00Z', last_ts: '2026-09-27T01:00:00Z' }],
      fingerprints: { hassh: [{ value: HOSTILE.zwsp, count: 1 }], ssh_version: [{ value: MIXED, count: 3 }], user_agent: [{ value: LONG, count: 1 }] },
      actions: [{ incident_key: sourceDetail().incidents[0].incident_key, action: HOSTILE.mention, operator: HOSTILE.jsUrl, note: MIXED, created_at: '2026-09-29T02:00:00Z' }],
      block: { ...LIVE_BLOCK, reason: LONG, method: HOSTILE.img, requested_by: HOSTILE.decoy, enforce_note: MIXED,
        enforcement: { gateway: { state: 'failed', since: null, mode: HOSTILE.style, note: MIXED } } },
      exempt: { cidr: '198.51.100.0/24', note: HOSTILE.mdLink },
    })
    const { container } = setup(`/sources/detail?ip=${IP}`, () => json(detail))
    expect(await screen.findByRole('heading', { level: 1, name: IP })).toBeInTheDocument()
    expectInertDom(container)
    expectMixedRevealed(container)
    expectLongFolds(container)
    expectInertDom(container)
  })

  it('주소창의 악성 값은 묻지 않고 글자로만 보인다', async () => {
    const { container, fetch } = setup(`/sources/detail?${new URLSearchParams({ ip: MIXED })}`)
    expect(await screen.findByRole('heading', { level: 1, name: '출발지 주소가 올바르지 않습니다' })).toBeInTheDocument()
    expect(detailRequests(fetch)).toEqual([])
    expectInertDom(container)
  })
})
