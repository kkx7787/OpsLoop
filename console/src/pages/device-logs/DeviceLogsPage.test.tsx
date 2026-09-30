import { onlineManager } from '@tanstack/react-query'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEVICE_NOT_FOUND, LOGS_NOT_DEPLOYED, type DeviceLogsResult } from '@/api/device-logs'
import { lineId, logsResult, sshLine, webLine } from '@/test/device-logs-fixtures'
import { expectInertDom, expectMixedRevealed, MIXED } from '@/test/hostile-fixtures'
import { noRetryClient, renderRoutes } from '@/test/render'
import { DeviceLogsPage } from './DeviceLogsPage'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** 장비 로그 경로에만 답한다(그 밖은 404). respond 는 부를 때마다 다시 읽는다 */
function stubLogs(respond: (url: URL) => Response) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const url = new URL(raw, 'http://localhost')
    if (url.pathname.startsWith('/api/devices/')) return respond(url)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const calls = () => fetch.mock.calls.map(([input]) => String(input))
  return { fetch, calls }
}

function routes(): RouteObject[] {
  return [
    { path: '/devices/:id/logs', element: <DeviceLogsPage /> },
    { path: '/', element: <p>관제 현황 본문</p> },
    { path: '/incidents', element: <p>사건 목록 본문</p> },
  ]
}

function renderPage(path = '/devices/web-01/logs') {
  return renderRoutes(routes(), path, noRetryClient())
}

/**
 * 가짜 시계를 ms 만큼 돌리고 그 사이 약속(조회 · 렌더)을 비운다. 주기 조회는 창 끝에서 시작하고, 가짜 시계는 도는 중에 건
 * 0초 타이머를 1ms 뒤로 미루므로 1ms 씩 몇 번 더 돌려 응답 처리 · 렌더를 끝낸다
 */
async function settle(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
    for (let i = 0; i < 10; i += 1) await vi.advanceTimersByTimeAsync(1)
  })
}

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  // react-query 의 focusManager 는 window 에서 visibilitychange 를 듣는다
  act(() => void window.dispatchEvent(new Event('visibilitychange')))
}

/** react-query 의 onlineManager 는 window 에서 online · offline 을 듣는다 */
function setNetwork(state: 'online' | 'offline') {
  act(() => void window.dispatchEvent(new Event(state)))
}

function timeCell(name: string): HTMLElement {
  const cell = screen.getByRole('region', { name: '시각' }).querySelector<HTMLElement>(`[data-time="${name}"]`)
  if (!cell) throw new Error(`${name} 칸 없음`)
  return cell.querySelector('dd') as HTMLElement
}

function lineRow(container: HTMLElement, n: number): HTMLElement {
  const row = container.querySelector<HTMLElement>(`[data-line="${lineId(n)}"]`)
  if (!row) throw new Error(`${n} 번 줄 없음`)
  return row
}

/** 긴 비신뢰 값의 '… N자 더 · 펼치기' 를 모두 누른다 */
function expandAll(root: HTMLElement) {
  for (const button of within(root).queryAllByRole('button', { name: /펼치기$/ })) fireEvent.click(button)
}

const mobile = () => vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} })))

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  Reflect.deleteProperty(document, 'visibilityState')
  onlineManager.setOnline(true)
})

describe('장비 최근 로그 화면(#73)', () => {
  it('제목 · 한 줄 설명 · 사건 보기 · 관제 현황, 표는 최신 순이고 요청 · SSH 칸을 가른다', async () => {
    const { calls } = stubLogs(() => json(logsResult({ items: [webLine(3), sshLine(2, { has_password: true }), webLine(1, { http_status: 404, url: '/reset/…(가림)?…' })] })))
    const { container } = renderPage()
    expect(await screen.findByRole('heading', { level: 1, name: 'web-01 최근 로그' })).toBeInTheDocument()
    expect(screen.getByText('로그는 1분 적재 회차로 들어오고, 사건은 그 뒤 탐지 회차에서 생깁니다.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '사건 보기' })).toHaveAttribute('href', '/incidents?device=web-01')
    expect(screen.getByRole('link', { name: '관제 현황' })).toHaveAttribute('href', '/')
    expect(calls()).toEqual(['/api/devices/web-01/logs?limit=100'])

    const table = await screen.findByRole('table', { name: '최근 로그, 최신 순' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((row) => row.getAttribute('data-line'))).toEqual([3, 2, 1].map(lineId))
    expect(rows[0]).toHaveTextContent('2026-09-30 13:43:28웹 접근203.0.113.7GET /search?q=…&page=… → 200curl/8.5.0')
    expect(rows[1]).toHaveTextContent('SSH 인증198.51.100.9실패 · root비밀번호 기록 있음Failed password for root')
    expect(rows[2]).toHaveTextContent('/reset/…(가림)?… → 404')
    expect(within(rows[1]).getByText('비밀번호 기록 있음')).toHaveAttribute('data-has-password')
    expect(within(rows[0]).queryByText('비밀번호 기록 있음')).toBeNull()
    // 첫 적재는 새 줄 표시가 없고, 낭독이 끊임없이 이어지지 않게 aria-live 를 두지 않는다
    expect(container.querySelector('[data-fresh]')).toBeNull()
    expect(container.querySelector('[aria-live]')).toBeNull()
  })

  it('시각 네 가지는 따로 있고, 계산 기준은 ⓘ 에 있다. 선언했는데 값이 없으면 기록 없음', async () => {
    stubLogs(() => json(logsResult()))
    renderPage()
    await screen.findByRole('table')
    const region = screen.getByRole('region', { name: '시각' })
    expect([...region.querySelectorAll('[data-time]')].map((el) => el.getAttribute('data-time'))).toEqual(['loaded', 'lines', 'detect', 'refreshed'])
    expect(timeCell('loaded')).toHaveTextContent('24초 전 · 13:59:41')
    expect(timeCell('lines')).toHaveTextContent('웹 접근 35초 전 · 13:59:30SSH 인증 기록 없음')
    expect(timeCell('detect')).toHaveTextContent('21초 전 · 13:59:43')
    expect(timeCell('detect')).not.toHaveTextContent('멈춤')
    expect(timeCell('refreshed')).toHaveTextContent('14:00:05 KST · 5초마다')

    const tip = within(region).getByRole('button', { name: '시각 기준 설명' })
    fireEvent.click(tip)
    const panel = document.getElementById(tip.getAttribute('aria-controls') ?? '') as HTMLElement
    expect(panel).not.toHaveClass('hidden')
    expect(panel).toHaveTextContent('마지막 적재: 1분 적재 회차가 이 장비의 새 줄을 넣은 마지막 시각입니다.')
    expect(panel).toHaveTextContent('이 장비 규칙 버전 가운데 가장 오래된 것이 기준입니다 (c1 21초 전 · sg1 15초 전 · w2 10초 전).')
    expect(panel).toHaveTextContent('화면 갱신: 5초마다 다시 받는 주기일 뿐, 새 줄이 들어오는 주기가 아닙니다.')
    expect(panel).toHaveTextContent('목록에 없는 줄(시험 · 형식 밖 · sshd 외)도 셉니다.')
    expect(panel).toHaveTextContent('최근 7일 안에서 한 번에 최신 100줄을 받습니다.')
  })

  it('노드 표를 읽을 수 없음 · 수집 안 함 · 탐지 멈춤은 본문에 적는다', async () => {
    const base = logsResult()
    const unreadable = logsResult({
      times: {
        state: 'unreadable',
        loaded_at: null,
        lines: base.times.lines.map((line) => ({ ...line, declared: null, last_line_at: null })),
        detect: { ...base.times.detect, stale: true, reason: 'w2 마지막 실행 16분 전', last_at: '2026-09-30T04:44:00.000000+00:00' },
      },
    })
    stubLogs(() => json(unreadable))
    const first = renderPage()
    await screen.findByRole('table')
    expect(timeCell('loaded')).toHaveTextContent('노드 표를 읽을 수 없음')
    expect(timeCell('lines')).toHaveTextContent('웹 접근 노드 표를 읽을 수 없음SSH 인증 노드 표를 읽을 수 없음')
    expect(timeCell('detect')).toHaveTextContent('16분 전 · 13:44:00멈춤w2 마지막 실행 16분 전')
    expect(within(timeCell('detect')).getByText('멈춤')).toHaveClass('bg-warning-soft')
    first.unmount()

    stubLogs(() => json(logsResult({ times: { ...base.times, lines: [{ ...base.times.lines[0], declared: false }, base.times.lines[1]] } })))
    renderPage()
    await screen.findByRole('table')
    expect(timeCell('lines')).toHaveTextContent('웹 접근 수집 안 함SSH 인증 기록 없음')
  })

  it('비신뢰 글자(이름 · 경로 · UA · 사용자 · 메시지 · 탐지 까닭)는 글자로만 그리고 숨은 문자를 드러낸다', async () => {
    const hostile = logsResult({
      device: { id: 'web-02', label: MIXED, kind: 'node' },
      times: { ...logsResult().times, detect: { last_at: null, stale: true, reason: MIXED, versions: [{ rule_version: MIXED, last_at: null, stale: true }] } },
      items: [webLine(2, { url: MIXED, user_agent: MIXED, http_method: MIXED, src_ip: MIXED }), sshLine(1, { username: MIXED, message: MIXED })],
    })
    stubLogs(() => json(hostile))
    const { container, unmount } = renderPage('/devices/web-02/logs')
    await screen.findByRole('table')
    expectInertDom(container)
    // 긴 값은 앞부분만 보이므로 펼친 뒤 본다
    expandAll(container)
    expectInertDom(container)
    expectMixedRevealed(screen.getByRole('heading', { level: 1 }))
    expectMixedRevealed(lineRow(container, 2))
    expectMixedRevealed(lineRow(container, 1))
    expectMixedRevealed(timeCell('detect'))
    expect(lineRow(container, 2).querySelector('td[title]')?.getAttribute('title')).toContain('⟨U+202E⟩')
    unmount()

    // 좁은 폭 카드를 펼쳐도 같다
    mobile()
    const narrow = renderPage('/devices/web-02/logs')
    const list = await screen.findByRole('list', { name: '최근 로그, 최신 순' })
    for (const button of within(list).getAllByRole('button', { expanded: false })) fireEvent.click(button)
    expandAll(narrow.container)
    expectInertDom(narrow.container)
    expectMixedRevealed(lineRow(narrow.container, 2))
    expectMixedRevealed(lineRow(narrow.container, 1))
  })

  it('5초마다 다시 받고, 일시정지 · 숨은 탭에서는 받지 않는다. 계속을 누르면 바로 받는다', async () => {
    vi.useFakeTimers()
    const { calls } = stubLogs(() => json(logsResult()))
    renderPage()
    await settle()
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(calls()).toHaveLength(1)
    await settle(5_000)
    expect(calls()).toHaveLength(2)

    fireEvent.click(screen.getByRole('button', { name: '일시정지' }))
    expect(screen.getByRole('button', { name: '계속' })).toHaveAttribute('aria-pressed', 'true')
    expect(timeCell('refreshed')).toHaveTextContent('· 일시정지')
    await settle(30_000)
    expect(calls()).toHaveLength(2)
    // 멈춘 동안은 초점 조회도, 네트워크가 다시 붙을 때의 재연결 조회도 하지 않는다
    setVisibility('visible')
    await settle()
    expect(calls()).toHaveLength(2)
    setNetwork('offline')
    setNetwork('online')
    await settle()
    expect(calls()).toHaveLength(2)
    expect(screen.getByRole('button', { name: '계속' })).toHaveAttribute('aria-pressed', 'true')

    fireEvent.click(screen.getByRole('button', { name: '계속' }))
    await settle()
    expect(calls()).toHaveLength(3)
    expect(screen.getByRole('button', { name: '일시정지' })).toHaveAttribute('aria-pressed', 'false')
    await settle(5_000)
    expect(calls()).toHaveLength(4)

    // 숨은 탭에서는 주기 조회가 멈추고, 돌아오면 한 번 받는다
    setVisibility('hidden')
    await settle(30_000)
    expect(calls()).toHaveLength(4)
    setVisibility('visible')
    await settle()
    expect(calls()).toHaveLength(5)
  })

  it('일시정지 중에 조건을 바꾸면 한 번만 받는다', async () => {
    vi.useFakeTimers()
    const { calls } = stubLogs(() => json(logsResult()))
    renderPage()
    await settle()
    fireEvent.click(screen.getByRole('button', { name: '일시정지' }))
    fireEvent.click(within(screen.getByRole('group', { name: '로그 종류' })).getByRole('button', { name: 'SSH 인증' }))
    await settle(30_000)
    expect(calls()).toEqual(['/api/devices/web-01/logs?limit=100', '/api/devices/web-01/logs?kind=ssh&limit=100'])
  })

  it('새로 받은 줄은 표시하고, 받은 줄이 꽉 차 사이를 건너뛰면 구분선을 둔다', async () => {
    vi.useFakeTimers()
    let items = [webLine(3), webLine(2), webLine(1)]
    stubLogs(() => json(logsResult({ limit: 3, items })))
    const { container } = renderPage()
    await settle()
    items = [webLine(12), webLine(11), webLine(10)]
    await settle(5_000)
    const rows = [...container.querySelectorAll<HTMLElement>('tbody tr')]
    expect(rows.map((row) => row.getAttribute('data-line') ?? 'gap')).toEqual([lineId(12), lineId(11), lineId(10), 'gap', lineId(3), lineId(2), lineId(1)])
    expect(rows[3]).toHaveTextContent('이 사이 줄이 빠졌을 수 있음')
    expect(rows.filter((row) => row.hasAttribute('data-fresh')).map((row) => row.getAttribute('data-line'))).toEqual([12, 11, 10].map(lineId))
  })

  it('받은 뒤 갱신이 실패하면 이전 줄을 흐리게 남기고 본문에 경고와 다시 시도를 둔다', async () => {
    vi.useFakeTimers()
    let fail = false
    const { calls } = stubLogs(() => (fail ? json({ detail: 'DB 오류' }, 503) : json(logsResult())))
    const { container } = renderPage()
    await settle()
    expect(container.querySelector('[data-stale]')).toBeNull()
    fail = true
    // 5xx 는 두 번 더 보낸다(1초 · 2초 뒤)
    await settle(5_000)
    await settle(3_100)
    expect(calls()).toHaveLength(4)
    const banner = container.querySelector<HTMLElement>('[data-refresh-failed]') as HTMLElement
    expect(banner).toHaveTextContent('로그를 불러오지 못함 · 마지막 갱신 14:00:05')
    expect(container.querySelector('[data-stale]')).toContainElement(lineRow(container, 3))
    expect(container.querySelector('[data-stale]')).toHaveClass('opacity-50')

    fail = false
    fireEvent.click(within(banner).getByRole('button', { name: '다시 시도' }))
    await settle()
    expect(container.querySelector('[data-refresh-failed]')).toBeNull()
    expect(container.querySelector('[data-stale]')).toBeNull()
  })

  it('브라우저가 오프라인이 되어도 조용히 멈추지 않는다: 보내서 실패하면 갱신 실패 경고와 흐림, 다시 붙으면 바로 받는다', async () => {
    vi.useFakeTimers()
    let offline = false
    const { calls } = stubLogs(() => {
      if (offline) throw new TypeError('Failed to fetch')
      return json(logsResult())
    })
    const { container } = renderPage()
    await settle()
    offline = true
    setNetwork('offline')
    // 네트워크 오류는 두 번 더 보낸다(1초 · 2초 뒤)
    await settle(5_000)
    await settle(3_100)
    expect(calls()).toHaveLength(4)
    expect(container.querySelector('[data-refresh-failed]')).toHaveTextContent('로그를 불러오지 못함 · 마지막 갱신 14:00:05')
    expect(container.querySelector('[data-stale]')).toHaveClass('opacity-50')

    offline = false
    setNetwork('online')
    await settle()
    expect(calls()).toHaveLength(5)
    expect(container.querySelector('[data-refresh-failed]')).toBeNull()
    expect(container.querySelector('[data-stale]')).toBeNull()
  })

  it('받은 뒤에 404(보호 대상 아님)가 오면 찾을 수 없음으로 바꾸고 더 묻지 않는다', async () => {
    vi.useFakeTimers()
    let gone = false
    const { calls } = stubLogs(() => (gone ? json({ detail: DEVICE_NOT_FOUND }, 404) : json(logsResult())))
    renderPage()
    await settle()
    gone = true
    await settle(5_000)
    expect(screen.getByRole('heading', { level: 1, name: '보호 대상 장비를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '관제 현황' })).toHaveAttribute('href', '/')
    expect(screen.queryByRole('table')).toBeNull()
    await settle(30_000)
    expect(calls()).toHaveLength(2)
    expect(screen.getByRole('heading', { level: 1, name: '보호 대상 장비를 찾을 수 없습니다' })).toBeInTheDocument()
    // 네트워크가 다시 붙어도 같은 404 를 다시 보내지 않는다
    setNetwork('offline')
    setNetwork('online')
    await settle()
    expect(calls()).toHaveLength(2)
  })

  it('처음부터 실패하면 오류 상태와 다시 시도. 다시 받는 동안에도 불러오는 중으로 깜빡이지 않는다', async () => {
    vi.useFakeTimers()
    let fail = true
    stubLogs(() => (fail ? json({ detail: 'DB 오류' }, 503) : json(logsResult())))
    renderPage()
    await settle(3_100)
    expect(screen.getByRole('heading', { name: '로그를 불러오지 못함' })).toBeInTheDocument()
    expect(screen.getByText('DB 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '시각' })).toBeNull()
    // 5초 뒤 다시 받는 중(재시도 사이)에도 오류 상태가 남는다
    await settle(5_000)
    expect(screen.getByRole('heading', { name: '로그를 불러오지 못함' })).toBeInTheDocument()
    expect(screen.queryByText('로그를 불러오는 중입니다')).toBeNull()

    // 재시도까지 끝나면 다시 오류 상태이고, 다시 시도로 받는다
    await settle(3_100)
    expect(screen.getByRole('heading', { name: '로그를 불러오지 못함' })).toBeInTheDocument()
    fail = false
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }))
    await settle()
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '로그를 불러오지 못함' })).toBeNull()
  })

  it('404 두 가지: 서버 문장이면 찾을 수 없음, 기본 Not Found 면 배포 전 안내. 둘 다 다시 묻지 않는다', async () => {
    vi.useFakeTimers()
    const missing = stubLogs(() => json({ detail: DEVICE_NOT_FOUND }, 404))
    const first = renderPage('/devices/aws-sensor/logs')
    await settle(30_000)
    expect(screen.getByRole('heading', { level: 1, name: '보호 대상 장비를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(missing.calls()).toHaveLength(1)
    first.unmount()

    const old = stubLogs(() => json({ detail: 'Not Found' }, 404))
    const { container } = renderPage()
    await settle(30_000)
    expect(container.querySelector('[data-logs-missing]')).toHaveTextContent(LOGS_NOT_DEPLOYED)
    expect(screen.getByRole('heading', { level: 1, name: 'web-01 최근 로그' })).toBeInTheDocument()
    expect(old.calls()).toHaveLength(1)
  })

  it.each(['/devices/Web_01/logs', '/devices/_unconfirmed/logs', `/devices/${'a'.repeat(64)}/logs`])('형식 밖 장비 id(%s)는 묻지 않고 찾을 수 없음', async (path) => {
    const { fetch } = stubLogs(() => json(logsResult()))
    renderPage(path)
    expect(await screen.findByRole('heading', { level: 1, name: '보호 대상 장비를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('빈 상태: 조건이 없으면 최근 7일 안내, 조건이 있으면 초기화 단추. 시각 칸은 그대로 보인다', async () => {
    const { calls } = stubLogs(() => json(logsResult({ items: [] })))
    const first = renderPage()
    expect(await screen.findByRole('heading', { name: '최근 7일 안에 이 장비의 로그가 없습니다' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '시각' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '조건 초기화' })).toBeNull()
    first.unmount()

    const { router } = renderPage('/devices/web-01/logs?kind=ssh')
    expect(await screen.findByRole('heading', { name: '조건에 맞는 줄이 없습니다' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '시각' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '조건 초기화' }))
    await screen.findByRole('heading', { name: '최근 7일 안에 이 장비의 로그가 없습니다' })
    expect(router.state.location.search).toBe('')
    expect(calls().slice(1)).toEqual(['/api/devices/web-01/logs?kind=ssh&limit=100', '/api/devices/web-01/logs?limit=100'])
  })

  it('422 는 조건 막대 아래에 서버 문장과 초기화 단추를 두고 다시 묻지 않는다', async () => {
    vi.useFakeTimers()
    const { calls } = stubLogs((url) => (url.searchParams.has('src_ip') ? json({ detail: 'src_ip 는 IP 주소여야 합니다' }, 422) : json(logsResult())))
    const { container, router } = renderPage('/devices/web-01/logs?src_ip=nope')
    await settle(30_000)
    expect(calls()).toEqual(['/api/devices/web-01/logs?src_ip=nope&limit=100'])
    const banner = container.querySelector<HTMLElement>('[data-filter-invalid]') as HTMLElement
    expect(banner).toHaveTextContent('src_ip 는 IP 주소여야 합니다')
    expect(screen.getByRole('group', { name: '로그 조건' }).compareDocumentPosition(banner) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '로그를 불러오지 못함' })).toBeNull()
    fireEvent.click(within(banner).getByRole('button', { name: '조건 초기화' }))
    await settle()
    expect(router.state.location.search).toBe('')
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(container.querySelector('[data-filter-invalid]')).toBeNull()
  })

  it('다른 조건에서 받은 422 는 조건 초기화 뒤 조건 없는 화면에 남지 않는다(조건 없는 조회가 실패한 채 캐시에 있어도)', async () => {
    vi.useFakeTimers()
    stubLogs((url) => (url.searchParams.has('src_ip') ? json({ detail: 'src_ip 는 IP 주소여야 합니다' }, 422) : json({ detail: 'DB 오류' }, 503)))
    const { container, router } = renderPage()
    await settle(3_100)
    expect(screen.getByRole('heading', { name: '로그를 불러오지 못함' })).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('출발지'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByRole('button', { name: '적용' }))
    await settle()
    const banner = container.querySelector<HTMLElement>('[data-filter-invalid]') as HTMLElement
    expect(banner).toHaveTextContent('src_ip 는 IP 주소여야 합니다')

    fireEvent.click(within(banner).getByRole('button', { name: '조건 초기화' }))
    for (const ms of [50, 450, 1_000, 1_000]) {
      await settle(ms)
      expect(router.state.location.search).toBe('')
      expect(container.querySelector('[data-filter-invalid]')).toBeNull()
    }
    // 조건 없는 조회의 재시도가 끝나면 그 조회의 오류다
    await settle(1_100)
    expect(screen.getByRole('heading', { name: '로그를 불러오지 못함' })).toBeInTheDocument()
    expect(screen.getByText('DB 오류 (HTTP 503)')).toBeInTheDocument()
  })

  it('주소의 모르는 종류 · 범위 밖 응답 코드는 버리고 보낸다', async () => {
    const { calls } = stubLogs(() => json(logsResult()))
    renderPage('/devices/web-01/logs?kind=all&status=600&src_ip=%20')
    await screen.findByRole('table')
    expect(calls()).toEqual(['/api/devices/web-01/logs?limit=100'])
    expect(within(screen.getByRole('group', { name: '로그 종류' })).getByRole('button', { name: '전체' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('조건 막대: 종류는 바로, 출발지 · 응답 코드는 적용으로 주소에 둔다. 틀린 응답 코드는 보내지 않고 초기화는 두 칸을 비운다', async () => {
    const { calls } = stubLogs(() => json(logsResult()))
    const { router } = renderPage()
    await screen.findByRole('table')
    fireEvent.click(within(screen.getByRole('group', { name: '로그 종류' })).getByRole('button', { name: '웹 접근' }))
    await screen.findByRole('table')
    expect(router.state.location.search).toBe('?kind=web')

    fireEvent.change(screen.getByLabelText('출발지'), { target: { value: ' 198.51.100.9 ' } })
    fireEvent.change(screen.getByLabelText('응답 코드'), { target: { value: '99' } })
    fireEvent.click(screen.getByRole('button', { name: '적용' }))
    expect(screen.getByRole('alert')).toHaveTextContent('응답 코드는 100~599 사이 세 자리 숫자입니다')
    expect(screen.getByLabelText('응답 코드')).toHaveAttribute('aria-invalid', 'true')
    expect(router.state.location.search).toBe('?kind=web')

    fireEvent.change(screen.getByLabelText('응답 코드'), { target: { value: '404' } })
    fireEvent.click(screen.getByRole('button', { name: '적용' }))
    await screen.findByRole('table')
    expect(router.state.location.search).toBe('?kind=web&src_ip=198.51.100.9&status=404')

    fireEvent.click(screen.getByRole('button', { name: '초기화' }))
    await screen.findByRole('table')
    expect(router.state.location.search).toBe('?kind=web')
    expect(screen.getByLabelText('출발지')).toHaveValue('')
    expect(screen.getByLabelText('응답 코드')).toHaveValue('')
    // 초기화 뒤의 kind=web 은 방금 받은 캐시라 다시 묻지 않을 수 있다
    expect(calls().slice(0, 3)).toEqual([
      '/api/devices/web-01/logs?limit=100',
      '/api/devices/web-01/logs?kind=web&limit=100',
      '/api/devices/web-01/logs?kind=web&src_ip=198.51.100.9&status=404&limit=100',
    ])
  })

  it('조건을 바꾸면 합친 목록을 비운다(이전 조건의 줄이 남지 않는다)', async () => {
    stubLogs((url) => json(logsResult({ items: url.searchParams.get('kind') === 'ssh' ? [sshLine(9)] : [webLine(3), webLine(1)] })))
    const { container } = renderPage()
    await screen.findByRole('table')
    expect(container.querySelectorAll('tbody [data-line]')).toHaveLength(2)
    fireEvent.click(within(screen.getByRole('group', { name: '로그 종류' })).getByRole('button', { name: 'SSH 인증' }))
    await waitFor(() => expect([...container.querySelectorAll('tbody [data-line]')].map((row) => row.getAttribute('data-line'))).toEqual([lineId(9)]))
  })

  it('앞선 시각 줄: 본문 경고 한 줄, 1,001 이면 1,000건 넘게', async () => {
    stubLogs(() => json(logsResult({ future: 3 })))
    const first = renderPage()
    await screen.findByRole('table')
    expect(first.container.querySelector('[data-future]')).toHaveTextContent('시각이 5분 넘게 앞선 줄 3건은 목록에서 뺐습니다')
    first.unmount()

    stubLogs(() => json(logsResult({ future: 1001 })))
    const { container } = renderPage()
    await screen.findByRole('table')
    expect(container.querySelector('[data-future]')).toHaveTextContent('시각이 5분 넘게 앞선 줄 1,000건 넘게는 목록에서 뺐습니다')
  })

  it('좁은 폭은 접은 카드: 머리에 월-일 시각 · 종류 · 출발지 · 코드/결과, 펼침은 갱신 뒤에도 남는다', async () => {
    vi.useFakeTimers()
    mobile()
    let body: DeviceLogsResult = logsResult()
    stubLogs(() => json(body))
    const { container } = renderPage()
    await settle()
    expect(screen.queryByRole('table')).toBeNull()
    const list = screen.getByRole('list', { name: '최근 로그, 최신 순' })
    const head = (n: number) => within(lineRow(container, n)).getAllByRole('button')[0]
    expect(head(3)).toHaveTextContent('09-30 13:43:28웹 접근203.0.113.7200')
    expect(head(2)).toHaveTextContent('09-30 13:43:27SSH 인증198.51.100.9실패')
    expect(head(2)).toHaveAttribute('aria-expanded', 'false')
    expect(within(list).queryByText('Failed password for root from 198.51.100.9 port 40022 ssh2')).toBeNull()

    fireEvent.click(head(2))
    expect(head(2)).toHaveAttribute('aria-expanded', 'true')
    const panel = document.getElementById(head(2).getAttribute('aria-controls') ?? '') as HTMLElement
    expect(panel).toHaveTextContent('출발지198.51.100.9사용자root요약Failed password for root from 198.51.100.9 port 40022 ssh2포트40022')

    // 새 줄이 위에 붙어 순번이 바뀌어도 같은 줄이 펼쳐져 있다
    body = logsResult({ items: [webLine(4), ...logsResult().items] })
    await settle(5_000)
    expect(lineRow(container, 4)).toHaveAttribute('data-fresh')
    expect(head(2)).toHaveAttribute('aria-expanded', 'true')
    expect(head(4)).toHaveAttribute('aria-expanded', 'false')
    expect(document.getElementById(head(2).getAttribute('aria-controls') ?? '')).toHaveTextContent('포트40022')

    fireEvent.click(head(3))
    expect(document.getElementById(head(3).getAttribute('aria-controls') ?? '')).toHaveTextContent('출발지203.0.113.7경로GET /search?q=…&page=…UAcurl/8.5.0포트51234')
  })

  it('좁은 폭 카드를 펼치면 머리에서 잘린 출발지(IPv6)를 줄바꿈해 끝까지 보인다', async () => {
    mobile()
    const ipv6 = '2001:db8:abcd:12:3456:789a:bcde:f012'
    stubLogs(() => json(logsResult({ items: [webLine(2, { src_ip: ipv6 }), sshLine(1, { src_ip: '185.224.128.123', eventid: 'sshd.login.invalid_user' })] })))
    const { container } = renderPage()
    await screen.findByRole('list', { name: '최근 로그, 최신 순' })
    const head = (n: number) => within(lineRow(container, n)).getAllByRole('button')[0]
    const panel = (n: number) => document.getElementById(head(n).getAttribute('aria-controls') ?? '') as HTMLElement
    fireEvent.click(head(2))
    fireEvent.click(head(1))
    expect(panel(2)).toHaveTextContent(`출발지${ipv6}경로`)
    expect(within(panel(2)).getByText(ipv6).closest('dd')).toHaveClass('break-all')
    expect(panel(1)).toHaveTextContent('출발지185.224.128.123사용자')
  })
})
