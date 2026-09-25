import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, type RouteObject } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type Incident, type IncidentPage } from '@/api/incidents'
import { IncidentList } from '@/components/organisms/incidents/IncidentList'
import { revealHidden } from '@/lib/untrusted'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'
import { noRetryClient, renderRoutes, stubHanging } from '@/test/render'
import { IncidentsPage } from './IncidentsPage'
import { applyLiveMessage } from '@/api/live'

// ---------------------------------------------------------------- 표본

const KEY = 'R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00'

function incident(n: number, extra: Partial<Incident> = {}): Incident {
  return {
    incident_key: `R003|v2|4.4.66.${n}|2026-09-18T06:00:00+00:00`,
    rule_id: 'R003',
    rule_version: 'v2',
    rule_name: '악성코드 투하',
    severity: 'critical',
    actor_ip: `4.4.66.${n}`,
    target: null,
    first_ts: '2026-09-18T06:00:00+00:00',
    last_ts: '2026-09-18T06:10:00+00:00',
    signal_count: 3,
    session_count: 1,
    status: 'open',
    created_at: '2026-09-18T06:10:05+00:00',
    verdict: null,
    pending_seconds: 22_320,
    ...extra,
  }
}

function page(offset: number, items: Incident[], total: number): IncidentPage {
  return { total, limit: 25, offset, items }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** 주소별 응답을 정한 fetch 를 전역에 끼운다. */
function stubApi(incidents: (url: URL) => Response | undefined) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(raw, 'http://localhost')
    if (url.pathname === '/api/incidents') return incidents(url) ?? json({ detail: '없는 경로' }, 404)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function calledUrls(fetch: ReturnType<typeof stubApi>): string[] {
  return fetch.mock.calls.map(([input]) => (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url))
}

function routes(): RouteObject[] {
  return [
    { path: '/incidents', element: <IncidentsPage /> },
    { path: '/incidents/:key', element: <p>상세 본문</p> },
  ]
}

const TWO = [
  incident(84),
  incident(85, {
    rule_id: 'R201',
    rule_name: '콘솔 로그인 실패',
    severity: 'low',
    actor_ip: null,
    target: 'user:root',
    status: 'resolved',
    verdict: 'threat',
    pending_seconds: 600,
  }),
]

describe('IncidentsPage', () => {
  it('목록 API의 전체 규칙 선택지를 써서 아직 로드하지 않은 규칙도 필터링한다', async () => {
    const fetch = stubApi(() => json({ ...page(0, [incident(84)], 80), rules: [{ rule_id: 'R003', rule_name: '악성코드 투하' }, { rule_id: 'R301', rule_name: '자원 경보' }] }))
    renderRoutes(routes(), '/incidents')
    const option = await screen.findByRole('option', { name: /R301.*자원 경보/ })
    expect(option).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: '규칙' }), { target: { value: 'R301' } })
    await waitFor(() => expect(calledUrls(fetch).some((url) => url.includes('rule_id=R301'))).toBe(true))
    expect(calledUrls(fetch).every((url) => url.startsWith('/api/incidents'))).toBe(true)
  })
  // 가상화가 행 높이를 다시 잴 때 창을 스크롤한다. jsdom 에는 scrollTo 가 없어 소음만 낸다
  beforeEach(() => {
    vi.stubGlobal('scrollTo', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('행마다 경과 · 심각도 · 규칙 · 관측값 · 출발지 · 발생원 · 상태 · 판정을 보이고 총 건수를 센다', async () => {
    stubApi(() => json(page(0, TWO, 2)))
    renderRoutes(routes(), '/incidents')

    expect(await screen.findByRole('heading', { level: 1, name: '인시던트' })).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: '인시던트 목록' })
    for (const label of ['경과', '심각도', '규칙', '출발지 · 대상', '상태', '판정']) {
      expect(within(table).getByRole('columnheader', { name: label })).toBeInTheDocument()
    }
    expect(table).toHaveAttribute('aria-rowcount', '3')

    const first = within(table).getByRole('row', { name: /4\.4\.66\.84/ })
    expect(first).toHaveAttribute('aria-rowindex', '2')
    expect(first).toHaveTextContent('R003')
    expect(first).toHaveTextContent('악성코드 투하')
    expect(first).toHaveTextContent('critical')
    expect(first).toHaveTextContent('3 신호 · 1 세션')
    expect(first).toHaveTextContent('허니팟')
    expect(first).toHaveTextContent('신규')
    expect(first).toHaveTextContent('미판정')
    // critical 목표 1시간을 넘긴 6시간 12분: 빨강 + 낭독기용 글
    const elapsed = within(first).getByText('6h 12m')
    expect(elapsed).toHaveAttribute('data-tone', 'over')
    expect(elapsed).toHaveTextContent('(목표 초과)')
    expect(within(first).getByRole('link', { name: 'R003' })).toHaveAttribute('href', `/incidents/${encodeURIComponent(KEY)}`)

    const second = within(table).getByRole('row', { name: /user:root/ })
    expect(second).toHaveTextContent('콘솔 · 감사')
    expect(second).toHaveTextContent('종결')
    expect(second).toHaveTextContent('실제 위협')
    expect(within(second).getByText('10m')).not.toHaveAttribute('data-tone')

    expect(screen.getByText(/총/)).toHaveTextContent('총 2건')
    expect(screen.getByText('1 / 1페이지')).toBeInTheDocument()
  })

  it('조건은 주소에서 읽어 쿼리 문자열로 보내고, 바꾸면 주소가 바뀌어 다시 묻는다', async () => {
    const fetch = stubApi(() => json(page(0, [incident(84)], 1)))
    const { router } = renderRoutes(routes(), '/incidents?status=open&severity=critical&rule_id=R003&judged=false&sort=recent&other=1')
    await screen.findByRole('table', { name: '인시던트 목록' })

    expect(calledUrls(fetch)).toContain(
      '/api/incidents?status=open&severity=critical&rule_id=R003&judged=false&sort=recent&limit=25&offset=0',
    )
    expect(screen.getByRole('combobox', { name: '상태' })).toHaveValue('open')
    expect(screen.getByRole('combobox', { name: '심각도' })).toHaveValue('critical')
    expect(screen.getByRole('combobox', { name: '규칙' })).toHaveValue('R003')
    expect(screen.getByRole('combobox', { name: '판정' })).toHaveValue('false')
    expect(within(screen.getByRole('group', { name: '정렬' })).getByRole('button', { name: '최신순' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    fireEvent.change(screen.getByRole('combobox', { name: '상태' }), { target: { value: 'acknowledged' } })
    await waitFor(() =>
      expect(router.state.location.search).toBe('?other=1&status=acknowledged&severity=critical&rule_id=R003&judged=false&sort=recent'),
    )
    await waitFor(() =>
      expect(calledUrls(fetch)).toContain(
        '/api/incidents?status=acknowledged&severity=critical&rule_id=R003&judged=false&sort=recent&limit=25&offset=0',
      ),
    )

    fireEvent.click(within(screen.getByRole('group', { name: '정렬' })).getByRole('button', { name: '미판정 우선' }))
    await waitFor(() =>
      expect(router.state.location.search).toBe('?other=1&status=acknowledged&severity=critical&rule_id=R003&judged=false'),
    )

    fireEvent.click(screen.getByRole('button', { name: '조건 초기화' }))
    await waitFor(() => expect(router.state.location.search).toBe('?other=1'))
    await waitFor(() => expect(calledUrls(fetch)).toContain('/api/incidents?limit=25&offset=0'))
    expect(screen.queryByRole('button', { name: '조건 초기화' })).toBeNull()
  })

  it('행 어디를 눌러도 상세로 간다. 안쪽 링크를 눌러도 한 번만 간다', async () => {
    stubApi(() => json(page(0, TWO, 2)))
    const { router } = renderRoutes(routes(), '/incidents')
    const table = await screen.findByRole('table', { name: '인시던트 목록' })

    fireEvent.click(within(table).getByText('악성코드 투하'))
    expect(await screen.findByText('상세 본문')).toBeInTheDocument()
    expect(decodeURIComponent(router.state.location.pathname)).toBe(`/incidents/${KEY}`)

    await router.navigate(-1)
    const again = await screen.findByRole('table', { name: '인시던트 목록' })
    const before = router.state.location.key
    fireEvent.click(within(again).getByRole('link', { name: 'R003' }))
    expect(await screen.findByText('상세 본문')).toBeInTheDocument()
    expect(router.state.location.key).not.toBe(before)
    await router.navigate(-1)
    expect(await screen.findByRole('table', { name: '인시던트 목록' })).toBeInTheDocument()
  })

  it('0건이면 조건 수와 초기화 · 수집 노드 링크를 보인다', async () => {
    const fetch = stubApi(() => json(page(0, [], 0)))
    const { router } = renderRoutes(routes(), '/incidents?status=open&judged=false')

    expect(await screen.findByRole('heading', { name: '조건에 맞는 인시던트가 없습니다' })).toBeInTheDocument()
    expect(screen.getByText(/2개 조건 적용 중/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '수집 노드 보기' })).toHaveAttribute('href', '/nodes')
    expect(screen.getByText(/총/)).toHaveTextContent('총 0건')

    fireEvent.click(screen.getAllByRole('button', { name: '조건 초기화' })[0])
    await waitFor(() => expect(router.state.location.search).toBe(''))
    await waitFor(() => expect(calledUrls(fetch)).toContain('/api/incidents?limit=25&offset=0'))
    expect(await screen.findByRole('heading', { name: '인시던트가 없습니다' })).toBeInTheDocument()
  })

  it('불러오는 동안은 상태 화면', async () => {
    stubHanging()
    renderRoutes(routes(), '/incidents')
    expect(await screen.findByRole('heading', { level: 1, name: '인시던트' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveAccessibleName('인시던트를 불러오는 중입니다')
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('불러오지 못하면 오류 화면과 다시 시도', async () => {
    const fetch = stubApi(() => json({ detail: '데이터베이스에 연결할 수 없습니다' }, 503))
    renderRoutes(routes(), '/incidents', noRetryClient())

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('데이터를 불러오지 못했습니다')
    expect(alert).toHaveTextContent('데이터베이스에 연결할 수 없습니다')
    const calls = calledUrls(fetch).filter((url) => url.startsWith('/api/incidents')).length
    fireEvent.click(within(alert).getByRole('button', { name: '다시 시도' }))
    await waitFor(() => expect(calledUrls(fetch).filter((url) => url.startsWith('/api/incidents')).length).toBeGreaterThan(calls))
  })

  it('이전·다음·페이지 번호로 해당 쪽만 받고 URL과 표시 범위를 유지한다', async () => {
    const fetch = stubApi((url) => {
      const offset = Number(url.searchParams.get('offset'))
      return json(page(offset, Array.from({ length: Math.min(25, 60 - offset) }, (_, i) => incident(offset + i)), 60))
    })
    const { router } = renderRoutes(routes(), '/incidents')
    await screen.findByRole('table', { name: '인시던트 목록' })
    expect(screen.getByRole('button', { name: '이전' })).toBeDisabled()
    expect(calledUrls(fetch)).toEqual(['/api/incidents?limit=25&offset=0'])
    fireEvent.click(screen.getByRole('button', { name: '다음' }))
    await screen.findByText('26–50건 표시')
    expect(router.state.location.search).toBe('?page=2')
    expect(calledUrls(fetch)).toContain('/api/incidents?limit=25&offset=25')
    expect(screen.getByRole('button', { name: '2페이지' })).toHaveAttribute('aria-current', 'page')
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(26)
    expect(within(screen.getByRole('table')).queryByText('4.4.66.0')).toBeNull()
    expect(within(screen.getByRole('table')).getByRole('row', { name: /4\.4\.66\.25/ })).toHaveAttribute('aria-rowindex', '27')
    fireEvent.click(screen.getByRole('button', { name: '3페이지' }))
    await screen.findByText('51–60건 표시')
    expect(screen.getByRole('button', { name: '다음' })).toBeDisabled()
    await router.navigate(-1)
    await screen.findByText('26–50건 표시')
  })

  it('페이지당 건수와 필터를 바꾸면 첫 페이지로 돌아간다', async () => {
    const fetch = stubApi((url) => {
      const offset = Number(url.searchParams.get('offset'))
      const limit = Number(url.searchParams.get('limit'))
      return json({ ...page(offset, Array.from({ length: Math.min(limit, 120 - offset) }, (_, i) => incident(offset + i)), 120), limit })
    })
    const { router } = renderRoutes(routes(), '/incidents?page=3&severity=critical')
    await screen.findByRole('table')
    expect(calledUrls(fetch)).toContain('/api/incidents?severity=critical&limit=25&offset=50')
    fireEvent.change(screen.getByRole('combobox', { name: '페이지당' }), { target: { value: '50' } })
    await waitFor(() => expect(calledUrls(fetch)).toContain('/api/incidents?severity=critical&limit=50&offset=0'))
    expect(router.state.location.search).toBe('?severity=critical&page_size=50')
    await screen.findByRole('table')
    fireEvent.click(screen.getByRole('button', { name: '다음' }))
    await screen.findByText('51–100건 표시')
    fireEvent.change(screen.getByRole('combobox', { name: '판정' }), { target: { value: 'false' } })
    await waitFor(() => expect(calledUrls(fetch)).toContain('/api/incidents?severity=critical&judged=false&limit=50&offset=0'))
    expect(new URLSearchParams(router.state.location.search).has('page')).toBe(false)
  })

  it('URL을 다시 열면 페이지·크기를 복원하고, 빠른 보기는 첫 페이지에 적용한다', async () => {
    const fetch = stubApi(() => json(page(50, [incident(84)], 120)))
    renderRoutes(routes(), '/incidents?page=2&page_size=50')
    await screen.findByRole('table')
    expect(calledUrls(fetch)).toContain('/api/incidents?limit=50&offset=50')
    expect(screen.getByRole('combobox', { name: '페이지당' })).toHaveValue('50')
    fireEvent.click(screen.getByRole('button', { name: 'critical 미판정' }))
    await waitFor(() => expect(calledUrls(fetch)).toContain('/api/incidents?severity=critical&judged=false&limit=50&offset=0'))
    expect(screen.getByRole('button', { name: 'critical 미판정' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('실시간 판정으로 마지막 쪽이 사라지면 유효한 마지막 쪽으로 이동한다', async () => {
    let total = 26
    const fetch = stubApi((url) => {
      const offset = Number(url.searchParams.get('offset'))
      return json(page(offset, offset < total ? [incident(offset)] : [], total))
    })
    const client = noRetryClient()
    const { router } = renderRoutes(routes(), '/incidents?judged=false&page=2', client)
    await screen.findByRole('table')
    total = 25
    applyLiveMessage(client, { type: 'verdict.created', data: { incident_key: 'updated' } })
    await waitFor(() => expect(router.state.location.search).toBe('?judged=false'))
    await screen.findByRole('table')
    expect(calledUrls(fetch)).toContain('/api/incidents?judged=false&limit=25&offset=0')
    expect(screen.getByText('1 / 1페이지')).toBeInTheDocument()
  })

  it('페이지 조회 실패는 이전 페이지를 새 페이지처럼 보이지 않고 재시도한다', async () => {
    let failed = true
    stubApi((url) => Number(url.searchParams.get('offset')) === 25 && failed
      ? json({ detail: '페이지 조회 실패' }, 503)
      : json(page(Number(url.searchParams.get('offset')), [incident(Number(url.searchParams.get('offset')))], 26)))
    renderRoutes(routes(), '/incidents', noRetryClient())
    await screen.findByRole('table')
    fireEvent.click(screen.getByRole('button', { name: '다음' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('페이지 조회 실패')
    expect(screen.queryByRole('table')).toBeNull()
    failed = false
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }))
    await screen.findByRole('table')
    expect(screen.getByText('26–26건 표시')).toBeInTheDocument()
  })

  it('좁은 화면에서는 열 대신 카드 한 장(경과 · 심각도 · 규칙 · 출발지)', async () => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn(() => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })),
    )
    stubApi(() => json(page(0, TWO, 2)))
    renderRoutes(routes(), '/incidents')

    const list = await screen.findByRole('list', { name: '인시던트 목록' })
    expect(screen.queryByRole('table')).toBeNull()
    const cards = within(list).getAllByRole('link')
    expect(cards).toHaveLength(2)
    expect(cards[0]).toHaveAttribute('href', `/incidents/${encodeURIComponent(KEY)}`)
    expect(cards[0]).toHaveTextContent('6시간 12분')
    expect(cards[0]).toHaveTextContent('critical')
    expect(cards[0]).toHaveTextContent('R003')
    expect(cards[0]).toHaveTextContent('악성코드 투하')
    expect(cards[0]).toHaveTextContent('4.4.66.84')
    expect(cards[0]).not.toHaveTextContent('신호')
    expect(cards[1]).toHaveTextContent('user:root')
    expect(cards[0]).toHaveTextContent('미판정')
    expect(cards[1]).toHaveTextContent('종결')
    expect(cards[1]).toHaveTextContent('실제 위협')
  })
})

// ---------------------------------------------------------------- #41 비신뢰 문자열 표시

describe('IncidentsPage · 비신뢰 문자열(#41)', () => {
  beforeEach(() => {
    vi.stubGlobal('scrollTo', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const HOSTILE_ROWS = [
    incident(84, { target: `user:${MIXED}` }),
    incident(85, { actor_ip: null, target: `user:${HOSTILE.rlo}` }),
    incident(86, { actor_ip: null, target: `user:${LONG}` }),
  ]

  it('행은 출발지 · 대상을 표식으로 바꾼 뒤 한 줄로 자르고 말풍선도 표식이다', async () => {
    stubApi(() => json(page(0, HOSTILE_ROWS, 3)))
    const { container } = renderRoutes(routes(), '/incidents', noRetryClient())
    const table = await screen.findByRole('table', { name: '인시던트 목록' })
    expectInertDom(container)
    expectMixedRevealed(table)

    // 출발지 + 대상: 대상 줄은 말줄임 · 말풍선 표식
    const mixed = container.querySelector('[data-incident-key="R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00"]') as HTMLElement
    const targetLine = within(mixed).getByTitle(revealHidden(`user:${MIXED}`))
    expect(targetLine).toHaveClass('truncate')
    expect(targetLine.textContent).toBe(`대상 user:${revealHidden(MIXED)}`)

    // 출발지가 없으면 대상을 출발지 칸에 보인다
    const rlo = container.querySelector('[data-incident-key="R003|v2|4.4.66.85|2026-09-18T06:00:00+00:00"]') as HTMLElement
    expect(within(rlo).getByTitle('user:admin⟨U+202E⟩gnp.exe')).toHaveTextContent('user:admin⟨U+202E⟩gnp.exe')

    // 2만 자 대상: 행 안에는 펼치기 단추를 두지 않고(행을 누르면 상세로 간다) 앞 500자에서 자른다
    const long = container.querySelector('[data-incident-key="R003|v2|4.4.66.86|2026-09-18T06:00:00+00:00"]') as HTMLElement
    expect(within(long).queryByRole('button')).toBeNull()
    expect(within(long).getByTitle(`user:${LONG}`).textContent).toBe(`user:${'L'.repeat(495)}…`)
  })

  it('모바일 카드도 같은 규칙으로 그린다', () => {
    const { container } = render(
      <MemoryRouter>
        <IncidentList items={HOSTILE_ROWS} total={3} now={Date.now()} dataUpdatedAt={0} layout="cards" />
      </MemoryRouter>,
    )
    expectInertDom(container)
    expectMixedRevealed(container)
    expect(screen.getByTitle(revealHidden(`user:${MIXED}`))).toHaveClass('truncate')
    expect(screen.getByTitle('user:admin⟨U+202E⟩gnp.exe')).toHaveTextContent('user:admin⟨U+202E⟩gnp.exe')
    expect(screen.queryByRole('button')).toBeNull()
    expect(container.textContent).not.toContain(LONG)
  })

  it('규칙 이름도 행 · 카드에서 표식으로 보인다', () => {
    const rows = [incident(87, { rule_name: `이름${HOSTILE.rlo}` })]
    for (const layout of ['table', 'cards'] as const) {
      const { container, unmount } = render(
        <MemoryRouter>
          <IncidentList items={rows} total={1} now={Date.now()} dataUpdatedAt={0} layout={layout} />
        </MemoryRouter>,
      )
      expect(container.textContent).not.toContain('\u202e')
      expect(screen.getByTitle('이름admin⟨U+202E⟩gnp.exe')).toHaveTextContent('이름admin⟨U+202E⟩gnp.exe')
      unmount()
    }
  })

  it('주소의 규칙 값(rule_id)도 선택지에 표식으로 보인다', async () => {
    stubApi(() => json(page(0, [incident(84)], 1)))
    renderRoutes(routes(), `/incidents?rule_id=${encodeURIComponent(HOSTILE.rlo)}`, noRetryClient())
    expect(await screen.findByRole('option', { name: 'admin⟨U+202E⟩gnp.exe' })).toBeInTheDocument()
  })
})
