import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { LiveState } from '@/api/live'
import { LiveContext } from '@/api/live-context'
import type { FingerprintsResult, SourcesResult } from '@/api/sources'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { expectInertDom, expectMixedRevealed, HOSTILE, MIXED, MIXED_MARKS } from '@/test/hostile-fixtures'
import { fingerprint, fingerprintsResult, HASSH, LIVE_BLOCK, sourceSummary, sourcesResult } from '@/test/sources-fixtures'
import { SourcesPage } from './SourcesPage'

afterEach(() => vi.unstubAllGlobals())

const ITEMS = [
  sourceSummary({ block: LIVE_BLOCK }),
  sourceSummary({ ip: '203.0.113.9', incidents: 1, unjudged: 1, severity: 'low', rules: ['R201'], targets: ['console'], test_source: true, verdicts: { threat: 0, non_actionable: 0, false_positive: 0, benign_positive: 0, undetermined: 0 } }),
  sourceSummary({ ip: '10.0.3.7', severity: 'high', rules: ['R101'], targets: ['web-01', 'console'], exempt: true }),
  sourceSummary({ ip: '2001:db8::5', severity: 'medium', exempt: null, last_seen: null }),
]

interface Stub {
  sources?: (url: URL) => Response
  fingerprints?: (url: URL) => Response
  /** 실시간 연결 상태(기본은 앱 기본값) */
  live?: LiveState
}

/** 주소별 응답을 정한 fetch. 그 밖의 주소는 404 */
function setup(path: string, stub: Stub = {}) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/sources') return stub.sources?.(url) ?? json(sourcesResult(ITEMS))
    if (url.pathname === '/api/sources/fingerprints') return stub.fingerprints?.(url) ?? json(fingerprintsResult([fingerprint(), fingerprint({ value: 'a'.repeat(32), sources: 3, incident_sources: 0 })]))
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const page = stub.live ? <LiveContext.Provider value={stub.live}><SourcesPage /></LiveContext.Provider> : <SourcesPage />
  const view = renderRoutes([
    { path: '/sources', element: page },
    { path: '/sources/detail', element: <p>출발지 상세 본문</p> },
    { path: '/nodes', element: <p>노드</p> },
  ], path, noRetryClient())
  return { fetch, ...view }
}

/** 나간 요청의 주소(경로 + 검색). 경로로 거른다 */
function requests(fetch: ReturnType<typeof setup>['fetch'], pathname: string): URL[] {
  return fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost')).filter((url) => url.pathname === pathname)
}

/** 화면 주소의 검색 칸(순서 무시) */
function searchOf(router: ReturnType<typeof setup>['router']): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(router.state.location.search))
}

function lastRequest(fetch: ReturnType<typeof setup>['fetch'], pathname: string): URLSearchParams {
  const all = requests(fetch, pathname)
  return all[all.length - 1].searchParams
}

describe('출발지 목록', () => {
  it('주소별 사건 · 미판정 · 최고 심각도 · 규칙 · 대상 · 판정 분포 · 차단 상태를 보인다', async () => {
    setup('/sources')
    const row = (await screen.findByRole('link', { name: '198.51.100.23' })).closest('tr')!
    expect(within(row).getByText('4건')).toBeInTheDocument()
    expect(within(row).getByText('미판정 1')).toBeInTheDocument()
    expect(within(row).getByText('critical')).toHaveAttribute('data-severity', 'critical')
    expect(row.textContent).toContain('R001 · R003')
    expect(within(row).getByText('허니팟 센서')).toBeInTheDocument()
    const mix = within(row).getByRole('list', { name: '판정 분포' })
    expect([...mix.querySelectorAll('li')].map((li) => li.textContent)).toEqual(['실제 위협2', '무시 가능1'])
    // 차단 상태는 사건 상세 · 차단 목록과 같은 나눔 · 같은 지점별 결과. 요청한 두 지점 가운데 내부 방화벽이 대기라 집행 대기다(#77)
    expect(row.querySelector('[data-block-state]')).toHaveAttribute('data-block-state', 'pending')
    expect(within(row).getByText('집행 대기')).toBeInTheDocument()
    expect([...row.querySelectorAll('[data-enforce-point]')].map((el) => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')]))
      .toEqual([['gateway', 'confirmed'], ['fw', 'pending']])
    // 사건 시각(마지막 · 첫 사건)과 마지막 관측(이벤트)을 따로 적는다
    expect(screen.getByRole('columnheader', { name: '마지막 사건 (KST)' })).toBeInTheDocument()
    expect(within(row).getByText('09-29 11:40')).toBeInTheDocument()
    expect(row.querySelector('[data-last-seen]')).toHaveTextContent('마지막 관측 09-29 11:55')
    expect(row.textContent).toContain('첫 사건 09-27 10:00')
    expect(screen.getByRole('button', { name: '최근 사건순' })).toHaveAttribute('aria-pressed', 'true')

    const test = screen.getByRole('link', { name: '203.0.113.9' }).closest('tr')!
    expect(within(test).getByText('시험 대역')).toBeInTheDocument()
    expect(within(test).getByText('관제 콘솔')).toBeInTheDocument()
    expect(within(test).getByText('판정 없음')).toBeInTheDocument()
    expect(within(test).getByText('차단 없음')).toBeInTheDocument()
    const internal = screen.getByRole('link', { name: '10.0.3.7' }).closest('tr')!
    expect(within(internal).getByText('차단 금지 대역')).toBeInTheDocument()
    expect(within(internal).getByText('web-01')).toBeInTheDocument()
    // 금지 대역 표를 읽을 수 없으면 추측하지 않고 확인 불가
    const v6 = screen.getByRole('link', { name: '2001:db8::5' }).closest('tr')!
    // 경고라 도움말(ⓘ) 안이 아니라 본문 표지로 보인다
    expect(within(v6).getByText('금지 대역 확인 불가').closest('[data-infotip]')).toBeNull()
    // 관측 시각이 없으면 비워 둔다
    expect(v6.querySelector('[data-last-seen]')).toHaveTextContent('마지막 관측 —')
    // 금지 대역 확인 불가는 표지로 본문에 두고, 까닭만 ⓘ 로 둔다(ⓘ 를 눌러도 행 이동이 아니다)
    const why = within(v6).getByRole('button', { name: '금지 대역 확인 불가 설명' })
    expect(why).toHaveAccessibleDescription(/차단 금지 대역 표를 읽을 수 없어/)
    fireEvent.click(why)
    expect(why).toHaveAttribute('aria-expanded', 'true')
    expect(screen.queryByText('출발지 상세 본문')).toBeNull()
    // 펼친 설명을 눌러도 행 이동이 아니다(읽다가 누르면 화면이 바뀌지 않게)
    fireEvent.click(within(v6).getByText(/차단 금지 대역 표를 읽을 수 없어/))
    expect(screen.queryByText('출발지 상세 본문')).toBeNull()
    // 표 캡션은 한 줄. 판정 분포 · 차단 상태의 계산 기준은 그 열 머리 ⓘ 에 있다
    expect(screen.getByText(/주소가 있는 사건의 출발지만 보입니다/)).toBeInTheDocument()
    expect(screen.queryByText(/차단 상태는 지금 차단 목록 행 기준입니다/)).toBeNull()
    expect(screen.getByRole('button', { name: '판정 분포 설명' })).toHaveAccessibleDescription(/사건마다 마지막 판정입니다. 같은 페이로드 흡수로 지워진 사건은 세지 않습니다/)
    expect(screen.getByRole('columnheader', { name: /^차단 상태/ })).toHaveAccessibleDescription('지금 차단 목록 행 기준입니다.')
  })

  it('주소 링크 · 행 누름은 상세로 간다(IPv6 도 쿼리로 부호화)', async () => {
    const { router } = setup('/sources')
    expect(await screen.findByRole('link', { name: '2001:db8::5' })).toHaveAttribute('href', '/sources/detail?ip=2001%3Adb8%3A%3A5')
    fireEvent.click(within(screen.getByRole('link', { name: '198.51.100.23' }).closest('tr')!).getByText('4건'))
    expect(await screen.findByText('출발지 상세 본문')).toBeInTheDocument()
    expect(router.state.location.search).toBe('?ip=198.51.100.23')
  })

  it('주소창의 조건 · 정렬 · 쪽이 요청 인자로 가고, 바꾼 조건은 주소창에 남는다', async () => {
    const { fetch, router } = setup('/sources?q=203.0.113.&sort=severity&include_test=true&page=2&page_size=50', {
      sources: () => json(sourcesResult(ITEMS, { total: 120, limit: 50, offset: 50 })),
    })
    await screen.findByRole('link', { name: '198.51.100.23' })
    let params = lastRequest(fetch, '/api/sources')
    expect(Object.fromEntries(params)).toEqual({ q: '203.0.113.', sort: 'severity', include_test: 'true', limit: '50', offset: '50' })
    expect(screen.getByRole('textbox', { name: '주소 앞부분' })).toHaveValue('203.0.113.')
    expect(screen.getByRole('switch', { name: '시험 대역 포함' })).toBeChecked()

    // 정렬을 바꾸면 첫 쪽으로 돌아간다
    fireEvent.click(screen.getByRole('button', { name: '사건 많은 순' }))
    await waitFor(() => expect(searchOf(router)).toEqual({ q: '203.0.113.', sort: 'incidents', include_test: 'true', page_size: '50' }))
    await waitFor(() => expect(lastRequest(fetch, '/api/sources').get('sort')).toBe('incidents'))
    expect(lastRequest(fetch, '/api/sources').get('offset')).toBe('0')

    // 시험 대역을 빼고 주소 앞부분을 바꾼다
    fireEvent.click(screen.getByRole('switch', { name: '시험 대역 포함' }))
    await waitFor(() => expect(searchOf(router)).toEqual({ q: '203.0.113.', sort: 'incidents', page_size: '50' }))
    fireEvent.change(screen.getByRole('textbox', { name: '주소 앞부분' }), { target: { value: ' 2001:db8: ' } })
    fireEvent.click(screen.getByRole('button', { name: '검색' }))
    await waitFor(() => expect(lastRequest(fetch, '/api/sources').get('q')).toBe('2001:db8:'))
    params = lastRequest(fetch, '/api/sources')
    expect(params.has('include_test')).toBe(false)
    expect(searchOf(router)).toEqual({ q: '2001:db8:', sort: 'incidents', page_size: '50' })

    // 조건 초기화는 주소 앞부분만 비우고 정렬은 남긴다
    fireEvent.click(screen.getByRole('button', { name: '조건 초기화' }))
    await waitFor(() => expect(searchOf(router)).toEqual({ sort: 'incidents', page_size: '50' }))
  })

  it('형식이 틀린 주소 앞부분은 묻지 않고 까닭을 보인다. 주소창의 틀린 값 · 한쪽만 있는 지문 조건은 버린다', async () => {
    const { fetch } = setup('/sources?q=abc%20xyz&fp=only-value&sort=nope')
    await screen.findByRole('link', { name: '198.51.100.23' })
    expect(Object.fromEntries(lastRequest(fetch, '/api/sources'))).toEqual({ limit: '25', offset: '0' })
    const count = requests(fetch, '/api/sources').length
    fireEvent.change(screen.getByRole('textbox', { name: '주소 앞부분' }), { target: { value: "1.2.3.4'--" } })
    fireEvent.click(screen.getByRole('button', { name: '검색' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('숫자 · a~f · 콜론(:) · 점(.)')
    expect(requests(fetch, '/api/sources').length).toBe(count)
    // 오류 문장이 입력칸의 설명으로 이어져 초점을 되돌려도 까닭이 읽힌다
    const input = screen.getByRole('textbox', { name: '주소 앞부분' })
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAccessibleDescription('주소 앞부분은 숫자 · a~f · 콜론(:) · 점(.)으로 45자까지 입력합니다')
    // 고쳐서 검색하면 오류와 설명을 뗀다
    fireEvent.change(input, { target: { value: '1.2.3.' } })
    fireEvent.click(screen.getByRole('button', { name: '검색' }))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    expect(input).not.toHaveAttribute('aria-describedby')
  })

  it('조건에 맞는 출발지가 없으면 0건 안내와 조건 초기화를 보인다', async () => {
    const { router } = setup('/sources?q=192.0.2.', { sources: () => json(sourcesResult([])) })
    expect(await screen.findByText('조건에 맞는 출발지가 없습니다')).toBeInTheDocument()
    expect(screen.getByText(/시험 대역 출발지는 빠져 있습니다/)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: '조건 초기화' })[0])
    await waitFor(() => expect(router.state.location.search).toBe(''))
  })

  it('첫 조회가 실패하면 오류 화면과 다시 시도를 보인다', async () => {
    setup('/sources', { sources: () => json({ detail: '일시 오류' }, 503) })
    expect(await screen.findByText('데이터를 불러오지 못했습니다')).toBeInTheDocument()
    expect(screen.getByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
  })

  it('범위 밖 쪽을 열면 마지막 쪽으로 돌아간다', async () => {
    const { router, fetch } = setup('/sources?page=9', {
      sources: (url) => json(sourcesResult(url.searchParams.get('offset') === '0' ? ITEMS : [], { total: ITEMS.length, offset: Number(url.searchParams.get('offset')) })),
    })
    await waitFor(() => expect(router.state.location.search).toBe(''))
    expect(await screen.findByRole('link', { name: '198.51.100.23' })).toBeInTheDocument()
    expect(lastRequest(fetch, '/api/sources').get('offset')).toBe('0')
  })

  it('offset 이 서버 상한(1,000,000)을 넘는 쪽은 상한 안으로 잘라 묻고(422 를 받지 않게) 마지막 쪽으로 돌아간다', async () => {
    const { router, fetch } = setup('/sources?page=40002', {
      sources: (url) => {
        const offset = Number(url.searchParams.get('offset'))
        if (offset > 1_000_000) return json({ detail: [{ loc: ['query', 'offset'], msg: 'less_than_equal' }] }, 422)
        return json(sourcesResult(offset === 0 ? ITEMS : [], { total: ITEMS.length, offset }))
      },
    })
    await waitFor(() => expect(router.state.location.search).toBe(''))
    expect(await screen.findByRole('link', { name: '198.51.100.23' })).toBeInTheDocument()
    const offsets = requests(fetch, '/api/sources').map((url) => Number(url.searchParams.get('offset')))
    expect(offsets[0]).toBe(1_000_000)
    expect(offsets.every((offset) => offset <= 1_000_000)).toBe(true)
  })

  it('지문 조건 목록이 비면 수집이 아니라 사건 있는 출발지만 보인다는 것을 알리고 지문 조건을 빼게 한다', async () => {
    const { router, container } = setup('/sources?include_test=true&fp_kind=user_agent&fp=zgrab', { sources: () => json(sourcesResult([])) })
    expect(await screen.findByText('이 지문을 쓴 출발지 가운데 사건이 있는 곳이 없습니다')).toBeInTheDocument()
    // '사건 있는 출발지만'은 제목과 표 캡션이 말한다. 수집 상태를 의심하게 하지 않는다
    expect(screen.getByText(/주소가 있는 사건의 출발지만 보입니다/)).toBeInTheDocument()
    expect(screen.queryByText(/수집 상태부터 확인/)).toBeNull()
    expect(screen.queryByRole('link', { name: '수집 · 관제 상태 보기' })).toBeNull()
    // 지문 조건 띠: '같은 지문 ≠ 같은 행위자'는 본문 한 줄, 근거는 ⓘ
    expect(container.querySelector('[data-same-tool]')).toHaveTextContent(/^같은 지문이 같은 행위자라는 뜻은 아닙니다/)
    expect(screen.getByRole('button', { name: '도구 지문 조건 설명' })).toHaveAccessibleDescription(/흔한 라이브러리 · 도구.*판정은 사건마다 합니다/)
    fireEvent.click(screen.getByRole('button', { name: '지문 조건 빼기' }))
    await waitFor(() => expect(router.state.location.search).toBe('?include_test=true'))
  })

  it('지문 조건에 다른 조건이 함께 걸려 있으면 그것도 적는다', async () => {
    setup('/sources?q=203.&fp_kind=hassh&fp=abc', { sources: () => json(sourcesResult([])) })
    expect(await screen.findByText('이 지문을 쓴 출발지 가운데 사건이 있는 곳이 없습니다')).toBeInTheDocument()
    expect(screen.getByText(/주소 앞부분 조건도 걸려 있습니다 · 시험 대역 출발지는 빠져 있습니다/)).toBeInTheDocument()
  })

  it('집행기 확인이 멈추면 띠로 알리고 그 지점의 적용 확인을 확인 지연으로 보인다', async () => {
    setup('/sources', { sources: () => json(sourcesResult(ITEMS, { checkers: { gateway_stale: true, fw_stale: null } })) })
    const row = (await screen.findByRole('link', { name: '198.51.100.23' })).closest('tr')!
    expect(screen.getByText('집행기 확인이 멈췄습니다')).toBeInTheDocument()
    // 띠는 멈춘 지점과 사실 한 줄(집행 미확인 경고라 본문. 도움말 안이 아니다)
    expect(screen.getByText(/허니팟 관문 · 10분 넘게 확인 없음$/).closest('[data-infotip]')).toBeNull()
    const gateway = row.querySelector<HTMLElement>('[data-enforce-point="gateway"]')!
    expect(gateway).toHaveAttribute('data-point-state', 'stale')
    expect(gateway.textContent).toContain('확인 지연')
    // 적용 확인을 확인 지연으로 바꾼 까닭은 본문 줄이 아니라 배지 옆 ⓘ
    expect(within(gateway).getByRole('button', { name: /설명$/ })).toHaveAccessibleDescription(/마지막 적용 확인을 믿지 않습니다/)
    // 내부 방화벽은 확인 기록을 읽을 수 없다(null). 멈춤으로 추측하지 않고 보고된 그대로 두되 그렇다고 본문에 적는다
    expect(row.querySelector('[data-enforce-point="fw"]')).toHaveAttribute('data-point-state', 'pending')
    expect(screen.getByText('집행기 확인 기록을 읽을 수 없음 · 지점 결과는 보고된 그대로').closest('[data-infotip]')).toBeNull()
  })

  it('집행기 확인 상태를 알면 확인 불가 안내를 붙이지 않는다', async () => {
    setup('/sources')
    await screen.findByRole('link', { name: '198.51.100.23' })
    expect(screen.queryByText(/집행기 확인 기록을 읽을 수 없음/)).toBeNull()
    expect(screen.queryByText('집행기 확인이 멈췄습니다')).toBeNull()
  })
})

describe('도구 지문 탭', () => {
  it('탭을 바꾸면 주소창에 남고 종류별로 묻는다', async () => {
    const { fetch, router } = setup('/sources?q=198.&page=2')
    await screen.findByRole('link', { name: '198.51.100.23' })
    fireEvent.click(screen.getByRole('button', { name: '도구 지문' }))
    await waitFor(() => expect(router.state.location.search).toBe('?q=198.&tab=fingerprints'))
    expect(await screen.findByRole('link', { name: HASSH })).toBeInTheDocument()
    expect(Object.fromEntries(lastRequest(fetch, '/api/sources/fingerprints'))).toEqual({ kind: 'hassh', limit: '25', offset: '0' })
    // 어디서 꺼낸 지문인지와 같은 지문 주의는 종류 옆 ⓘ 로 둔다(본문 띠는 지문 조건 목록 한 곳)
    const kindTip = screen.getByRole('button', { name: 'HASSH 지문 설명' })
    expect(kindTip).toHaveAccessibleDescription(/cowrie\.client\.kex.*같은 지문이 같은 행위자라는 뜻은 아닙니다/)
    expect(kindTip).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(kindTip)
    expect(kindTip).toHaveAttribute('aria-expanded', 'true')
    const row = screen.getByRole('link', { name: HASSH }).closest('tr')!
    expect(within(row).getByText('12곳')).toBeInTheDocument()
    expect(within(row).getByText('340회')).toBeInTheDocument()
    expect(within(row).getByText('9곳')).toBeInTheDocument()
    // 칸의 뜻은 표 아래 문단이 아니라 그 열 머리 ⓘ 에 있다
    expect(screen.getByRole('button', { name: '연결 설명' })).toHaveAccessibleDescription('그 지문이 나온 이벤트 수입니다.')
    expect(screen.getByRole('button', { name: '사건 있는 출발지 설명' })).toHaveAccessibleDescription(/사건이 하나라도 있는 곳입니다/)
    expect(screen.queryByText(/값을 누르면/)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'User-Agent' }))
    await waitFor(() => expect(router.state.location.search).toBe('?q=198.&tab=fingerprints&kind=user_agent'))
    await waitFor(() => expect(lastRequest(fetch, '/api/sources/fingerprints').get('kind')).toBe('user_agent'))
    expect(screen.getByRole('button', { name: 'User-Agent 지문 설명' })).toHaveAccessibleDescription(/^웹 디코이 요청의 User-Agent입니다/)

    fireEvent.click(screen.getByRole('button', { name: '출발지' }))
    await waitFor(() => expect(router.state.location.search).toBe('?q=198.&kind=user_agent'))
    expect(await screen.findByRole('link', { name: '198.51.100.23' })).toBeInTheDocument()
  })

  it('지문 값을 누르면 출발지 탭이 그 지문 조건으로 열리고, 칩으로 뺄 수 있다', async () => {
    const ua = 'Mozilla/5.0 (compatible; zgrab/0.x)'
    const { fetch, router } = setup('/sources?tab=fingerprints&kind=user_agent', {
      fingerprints: () => json(fingerprintsResult([fingerprint({ value: ua })], { kind: 'user_agent' })),
    })
    fireEvent.click(await screen.findByRole('link', { name: ua }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/sources'))
    expect(new URLSearchParams(router.state.location.search).get('tab')).toBeNull()
    // 도착 목록의 수는 '사건 있는 출발지' 칸과 같다. 그 칸이 시험 대역도 세므로 목록도 시험 대역을 넣어 연다
    expect(Object.fromEntries(new URLSearchParams(router.state.location.search))).toEqual({ include_test: 'true', fp_kind: 'user_agent', fp: ua })
    await screen.findByRole('link', { name: '198.51.100.23' })
    const params = lastRequest(fetch, '/api/sources')
    expect(params.get('include_test')).toBe('true')
    expect(params.get('fp_kind')).toBe('user_agent')
    expect(params.get('fp')).toBe(ua)
    expect(screen.getByRole('button', { name: '출발지' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText(/같은 지문이 같은 행위자라는 뜻은 아닙니다/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '도구 지문 조건 빼기' }))
    await waitFor(() => expect(router.state.location.search).toBe('?include_test=true'))
    await waitFor(() => expect(lastRequest(fetch, '/api/sources').has('fp')).toBe(false))
  })

  it('사건 있는 출발지가 없는 값은 링크로 걸지 않고(빈 목록으로 가지 않게) 까닭을 적는다', async () => {
    const zero = 'a'.repeat(32)
    setup('/sources?tab=fingerprints')
    expect(await screen.findByRole('link', { name: HASSH })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: zero })).toBeNull()
    const row = screen.getByText(zero).closest('tr')!
    expect(within(row).queryByRole('link')).toBeNull()
    expect(within(row).getByText('0곳')).toBeInTheDocument()
    // 까닭은 행마다 되풀이하지 않고 '사건 있는 출발지' 열 머리 ⓘ 에 한 번 적는다
    expect(within(row).queryByText(/출발지 목록에 나오지 않습니다/)).toBeNull()
    expect(screen.getByRole('columnheader', { name: /^사건 있는 출발지/ })).toHaveAccessibleDescription(/출발지 목록에는 이 출발지만 나오므로 0곳인 값은 누를 수 없습니다/)
  })

  it('offset 이 서버 상한을 넘는 쪽은 상한 안으로 잘라 묻는다', async () => {
    const { router, fetch } = setup('/sources?tab=fingerprints&page=10002&page_size=100', {
      fingerprints: (url) => {
        const offset = Number(url.searchParams.get('offset'))
        if (offset > 1_000_000) return json({ detail: [{ loc: ['query', 'offset'], msg: 'less_than_equal' }] }, 422)
        return json(fingerprintsResult(offset === 0 ? [fingerprint()] : [], { total: 1, limit: 100, offset }))
      },
    })
    await waitFor(() => expect(router.state.location.search).toBe('?tab=fingerprints&page_size=100'))
    expect(await screen.findByRole('link', { name: HASSH })).toBeInTheDocument()
    const offsets = requests(fetch, '/api/sources/fingerprints').map((url) => Number(url.searchParams.get('offset')))
    expect(offsets[0]).toBe(1_000_000)
    expect(offsets.every((offset) => offset <= 1_000_000)).toBe(true)
  })

  it('실시간 연결이 끊기면 지문 탭은 주기 조회가 없다고 알린다(출발지 탭은 공통 띠)', async () => {
    const { router } = setup('/sources?tab=fingerprints', { live: { status: 'reconnecting', retries: 1 } })
    expect(await screen.findByRole('link', { name: HASSH })).toBeInTheDocument()
    expect(screen.getByText('실시간 연결이 끊겼습니다')).toBeInTheDocument()
    expect(screen.getByText(/다시 연결될 때까지 도구 지문은 저절로 갱신되지 않습니다$/)).toBeInTheDocument()
    expect(screen.queryByText(/30초마다/)).toBeNull()
    expect(screen.getByRole('button', { name: '지금 조회' })).toBeInTheDocument()

    // 출발지 탭은 주기 조회가 있어 공통 띠(MonitoringStatus)로 돌아간다. 지문 탭 문장은 빠진다
    fireEvent.click(screen.getByRole('button', { name: '출발지' }))
    await waitFor(() => expect(router.state.location.search).toBe(''))
    expect(await screen.findByRole('link', { name: '198.51.100.23' })).toBeInTheDocument()
    expect(screen.getByText('실시간 연결이 끊겼습니다')).toBeInTheDocument()
    expect(screen.getByText(/30초마다/)).toBeInTheDocument()
    expect(screen.queryByText(/도구 지문은 저절로 갱신되지 않습니다/)).toBeNull()
  })

  it('지문 기록이 없으면 수집 확인을 안내하고, 어디서 꺼내는지는 종류 옆 ⓘ 로 보인다', async () => {
    setup('/sources?tab=fingerprints&kind=ssh_version', { fingerprints: () => json(fingerprintsResult([], { kind: 'ssh_version' })) })
    expect(await screen.findByText('SSH 버전 지문 기록이 없습니다')).toBeInTheDocument()
    expect(screen.getByText('0건이 정상인지 수집 상태부터 확인해 주세요')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'SSH 버전 지문 설명' })).toHaveAccessibleDescription(/cowrie\.client\.version/)
  })
})

describe('출발지 분석 · 악성 문자열(#41)', () => {
  it('지문 탭: 지문 값을 글자로만 그리고, 누른 뒤의 지문 조건 칩도 그렇다', async () => {
    const hostile: FingerprintsResult = fingerprintsResult([fingerprint({ value: MIXED }), fingerprint({ value: HOSTILE.jsUrl })], { kind: 'user_agent' })
    const { container } = setup('/sources?tab=fingerprints&kind=user_agent', { fingerprints: () => json(hostile) })
    const link = await screen.findByRole('link', { name: HOSTILE.jsUrl })
    expect(link.getAttribute('href')).toMatch(/^\/sources\?include_test=true&fp_kind=user_agent&fp=javascript%3Aalert/)
    expectInertDom(container)
    // 링크 안은 앞 160자 말줄임이고, 전체는 숨은 문자를 표식으로 바꾼 title 로 보인다
    const mixed = screen.getAllByRole('link').find((a) => a.getAttribute('title')?.startsWith('<img'))!
    expect(mixed.textContent).toContain(HOSTILE.img)
    expect(mixed.textContent).toMatch(/…$/)
    expect(MIXED_MARKS.filter((mark) => !mixed.getAttribute('title')!.includes(mark))).toEqual([])
    fireEvent.click(link)
    await screen.findByRole('link', { name: '198.51.100.23' })
    expectInertDom(container)
  })

  it('출발지 탭: 주소창의 악성 지문 조건과 서버가 준 모르는 대상 이름', async () => {
    const list: SourcesResult = sourcesResult([sourceSummary({ targets: [MIXED, 'aws-sensor'] })])
    const { container, fetch, router } = setup(`/sources?${new URLSearchParams({ fp_kind: 'ssh_version', fp: MIXED })}`, { sources: () => json(list) })
    await screen.findByRole('link', { name: '198.51.100.23' })
    expect(lastRequest(fetch, '/api/sources').get('fp')).toBe(MIXED)
    // 칩은 말줄임(전체는 title 에 표식으로), 대상 이름은 64자에서 접힌다
    expect(screen.getByTitle(/^<img src=.*⟨U\+202E⟩/)).toBeInTheDocument()
    expectInertDom(container)
    // 행 안의 펼치기 단추는 행 누름(상세로 이동)이 아니다
    const before = router.state.location.search
    for (const button of screen.getAllByRole('button', { name: /자 더 · 펼치기/ })) fireEvent.click(button)
    expect(router.state.location.search).toBe(before)
    expectInertDom(container)
    expectMixedRevealed(container)
  })
})
