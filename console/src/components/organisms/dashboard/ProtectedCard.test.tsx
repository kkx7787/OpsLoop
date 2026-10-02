import { QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEVICE_NOT_FOUND, LOGS_NOT_DEPLOYED } from '@/api/device-logs'
import type { Target } from '@/api/targets'
import { revealHidden } from '@/lib/untrusted'
import { lineId, logsResult, sshLine, webLine } from '@/test/device-logs-fixtures'
import { expectInertDom, MIXED } from '@/test/hostile-fixtures'
import { json } from '@/test/monitoring-fixtures'
import { noRetryClient } from '@/test/render'
import { minutesAgo, nodeTarget, TARGETS_AS_OF, web01 } from '@/test/targets-fixtures'
import { ProtectedCard } from './ProtectedCard'

const AS_OF = Date.parse(TARGETS_AS_OF)

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

type Answer = unknown | (() => Response | Promise<Response>)

/** 카드 로그 조회(/api/devices/{id}/logs)에 답하는 fetch. 부른 주소를 돌려준다 */
function stubLogs(answer: Answer = logsResult()) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (/^\/api\/devices\/[^/]+\/logs$/.test(url.pathname)) return typeof answer === 'function' ? (answer as () => Response)() : json(answer)
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return { fetch, calls: () => fetch.mock.calls.map(([input]) => String(input)) }
}

function renderCard(target: Target, props: { stale?: boolean; variant?: 'card' | 'inline' } = {}, client = noRetryClient()) {
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ProtectedCard target={target} asOf={AS_OF} {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  const card = view.container.querySelector<HTMLElement>('[data-target]') as HTMLElement
  const box = () => card.querySelector<HTMLElement>('[data-log-box]') as HTMLElement
  return { ...view, card, box, client }
}

/** 가짜 시계를 ms 만큼 돌리고 조회 · 렌더를 비운다(장비 로그 화면 시험과 같다) */
async function settle(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
    for (let i = 0; i < 10; i += 1) await vi.advanceTimersByTimeAsync(1)
  })
}

describe('ProtectedCard(#83)', () => {
  it('위에서부터 이름 · 수집 상태 / 마지막 수신 / 성능 / 최근 로그 머리 · 상자 / 취약점 / 동선 순서이고 보안 · 최근 사건 · 대응 구역은 없다', async () => {
    stubLogs()
    const { card, box } = renderCard(nodeTarget('web-02', { security: { ...nodeTarget().security, undetermined: 2 } }))
    expect(card).toHaveAttribute('role', 'region')
    expect(screen.getByRole('region', { name: 'opsloop-web-02' })).toBe(card)
    expect(card).toHaveAttribute('data-target-kind', 'node')
    expect(card).toHaveAttribute('data-collection', 'ok')
    // 머리: 이름 · 역할(등록 노드는 node_id) · 수집 정상 배지
    expect(within(card).getByRole('heading', { level: 3 })).toHaveTextContent('opsloop-web-02')
    expect(card).toHaveTextContent('등록 노드 · web-02')
    expect(card.querySelector('[data-collection-badge]')).toHaveTextContent(/^수집 정상$/)
    expect(card.querySelector('[data-collection-badge]')).toHaveClass('bg-success-soft')
    expect(card.querySelector('[data-signal]')).toHaveTextContent(/^마지막 수신 2분 전$/)
    expect(card.querySelector('[data-system]')).toHaveTextContent('자원 지표 미수집')
    const logs = await within(card).findByRole('region', { name: 'opsloop-web-02 최근 로그' })
    expect(logs).toBe(box())
    expect(card.querySelector('[data-vulns]')).toHaveTextContent(/^취약점 연결된 자산 없음$/)
    const links = card.querySelector('[data-device-links]') as HTMLElement
    expect(within(links).getAllByRole('link').map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
      ['미판정 3건 →', '/incidents?judged=false&device=web-02'],
      ['미결 2건 →', '/incidents?undetermined=true&device=web-02'],
      ['사건 보기 →', '/incidents?device=web-02'],
      ['로그 더 보기 →', '/devices/web-02/logs'],
    ])
    // 화살표는 낭독하지 않는다
    expect(within(links).getByRole('link', { name: '로그 더 보기' })).toHaveClass('ml-auto')
    expect(links).toHaveClass('print:hidden', 'flex-nowrap', 'whitespace-nowrap')
    const order = ['[data-collection-badge]', '[data-signal]', '[data-system]', '[data-last-log]', '[data-log-box]', '[data-vulns]', '[data-device-links]'].map((sel) => card.querySelector(sel) as HTMLElement)
    for (let i = 1; i < order.length; i++) expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    for (const gone of ['최근 1시간 신규', '높음 이상', '차단 적용 여부 미확인', 'SSH 무차별 대입']) expect(card).not.toHaveTextContent(gone)
  })

  it('미판정 0 은 링크 없이 글만(Q18), 미결 0 · 이전 서버(칸 없음)는 적지 않는다', () => {
    stubLogs()
    const { card } = renderCard(web01())
    const links = card.querySelector('[data-device-links]') as HTMLElement
    expect(links).toHaveTextContent(/^미판정 0건사건 보기 →로그 더 보기 →$/)
    expect(within(links).queryByRole('link', { name: /미판정/ })).toBeNull()
    expect(card.querySelector('[data-undetermined-link]')).toBeNull()
  })

  it('요청 없음 · 성능 수치(load1 은 말풍선) · 취약점 한 줄(수정판 있음 · KEV · 흐린 수정 여부 미확인 · 조사 오래됨 · 대조 오래됨)', () => {
    stubLogs()
    const { card } = renderCard(web01())
    expect(card.querySelector('[data-collection-badge]')).toHaveTextContent(/^요청 없음$/)
    const system = card.querySelector('[data-system]') as HTMLElement
    expect(system).toHaveTextContent(/^CPU 12% · 메모리 42% · 디스크 63%$/)
    expect(system).toHaveAttribute('title', 'load1 0.42')
    const vulns = card.querySelector('[data-vulns]') as HTMLElement
    expect(vulns).toHaveTextContent(/^취약점 수정판 있음 12 · KEV 0 · 수정 여부 미확인 4 → · 조사 오래됨 · 대조 오래됨$/)
    expect(within(vulns).getByRole('link', { name: '취약점 수정판 있음 12 · KEV 0 · 수정 여부 미확인 4' })).toHaveAttribute('href', '/inventory?asset=web-01')
    const unknown = within(vulns).getByText('수정 여부 미확인 4')
    expect(unknown).toHaveClass('text-ink-muted')
    // 뜻은 말풍선(#94): 상세를 조회하지 않는 기록을 포함하고 수정판 없음이 아니다. 수를 사유별로 나누지 않는다
    expect(unknown).toHaveAttribute('title', expect.stringMatching(/^수정 여부 미확인 4건 — 현재 수집 정책에서 상세 정보를 조회하지 않는 기록\(커널 질의에서만 나온 KEV 밖 기록\)을 포함합니다\. 수정판 없음이라는 뜻은 아닙니다\. 취약점 수는 패키지별 대조 행 수입니다\./))
    expect(vulns.querySelector('[data-vuln-flag="조사 오래됨"]')).toHaveClass('text-warning')
    // 상태 글이 붙으면 좁은 카드에서 잘리지 않게 줄을 바꾼다. 정상은 한 줄 말줄임
    expect(vulns).toHaveClass('break-words')
    expect(vulns).not.toHaveClass('truncate')
  })

  it('대조 실패 · 대조 오래됨도 수를 그대로 두고 주의색 글로 붙인다', () => {
    stubLogs()
    const asset = { ...web01().vulns.assets[0], stale: false, check_failed: true, check_stale: true }
    // 이전 서버(대조 칸 없음)는 상태 글을 만들지 않는다
    const { card } = renderCard(web01({ vulns: { available: true, assets: [asset] } }))
    expect(card.querySelector('[data-vulns]')).toHaveTextContent(/^취약점 수정판 있음 12 · KEV 0 · 수정 여부 미확인 4 → · 대조 실패 · 대조 오래됨$/)
    const legacy = { ...asset, check_failed: undefined, check_stale: undefined }
    const old = renderCard(web01({ vulns: { available: true, assets: [legacy] } }))
    expect(old.card.querySelector('[data-vulns]')).toHaveTextContent(/^취약점 수정판 있음 12 · KEV 0 · 수정 여부 미확인 4 →$/)
    expect(old.card.querySelector('[data-vulns]')).toHaveClass('truncate')
  })

  it('경고 배지(적용 실패 · 집행기 멈춤)는 머리 둘째 줄 오른쪽에, 웹 로그 적재 없음 · 읽기 문제 · 수신 없음 까닭은 본문 줄에 둔다', () => {
    stubLogs()
    const target = web01({
      collection: {
        ...web01().collection,
        state: 'no_signal',
        reason: '노드 수신 15분 전 · 10분 넘게 새 신호 없음',
        signal: { ...web01().collection.signal!, seen_at: minutesAgo(15), problem: '형식이 틀림' },
        warnings: [{ key: 'parse', label: '웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖)', at: minutesAgo(3) }],
      },
      response: { ...web01().response, failed: 2, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' },
      system: { state: 'stale', metrics: web01().system.metrics },
    })
    const { card } = renderCard(target)
    expect(card.querySelector('[data-collection-badge]')).toHaveTextContent(/^수신 없음$/)
    expect([...card.querySelectorAll('[data-summary-flag]')].map((b) => b.textContent)).toEqual(['적용 실패 2', '집행기 멈춤'])
    expect(card.querySelector('[data-summary-flag="failed"]')).toHaveClass('bg-danger-soft')
    // 웹 로그 적재 없음은 배지가 아니라 마지막 도착과 함께 본문 줄이다
    expect(card.querySelector('[data-summary-flag="parse"]')).toBeNull()
    const alerts = card.querySelector('[data-card-alerts]') as HTMLElement
    expect(alerts.querySelector('[data-collection-warning="parse"]')).toHaveTextContent('웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖) · 마지막 도착 3분 전')
    expect(alerts.querySelector('[data-collection-warning="parse"]')).toHaveClass('text-warning')
    expect(alerts.querySelector('[data-signal-problem]')).toHaveTextContent('읽기 문제: 형식이 틀림')
    expect(alerts.querySelector('[data-collection-reason]')).toHaveTextContent('노드 수신 15분 전 · 10분 넘게 새 신호 없음')
    expect(alerts).toHaveClass('break-words')
    expect(card.querySelector('[data-system-stale]')).toHaveTextContent('오래됨')
  })

  it('정상 상태에는 경고 줄이 없고, 수신 없음 기준 · 정상 까닭은 마지막 수신 옆 도움말(ⓘ)에 둔다', () => {
    stubLogs()
    const { card } = renderCard(nodeTarget('web-02'))
    expect(card.querySelector('[data-card-alerts]')).toBeNull()
    const tip = within(card).getByRole('button', { name: '수집 상태 설명' })
    expect(tip).toHaveAccessibleDescription('10분 넘게 새 신호가 없으면 수신 없음입니다. 노드 수신 2분 전 · 최근 1시간 로그 있음')
  })

  it('집행 확인 불가(#82)는 중립 배지, 받은 뒤 상태판 갱신 실패면 이전 결과 배지와 취약점 조회 실패', () => {
    stubLogs()
    const { card } = renderCard(web01({ response: { ...web01().response, stalled: '집행 보고를 읽을 수 없음', unreadable: true } }), { stale: true })
    expect(card.querySelector('[data-summary-flag="unreadable"]')).toHaveTextContent('집행 확인 불가')
    expect(card.querySelector('[data-stale-badge]')).toHaveTextContent('이전 결과')
    expect(card).toHaveAttribute('data-stale')
    expect(card.querySelector('[data-vuln-flag="조회 실패"]')).toHaveClass('text-warning')
  })

  it('최근 로그 상자: 10줄을 서버 순서대로, 칸마다 한 줄 한 글꼴 · 머리는 붙박이 · 키보드 초점', async () => {
    const items = Array.from({ length: 12 }, (_, i) => (i % 3 === 2 ? sshLine(20 - i) : webLine(20 - i)))
    stubLogs(logsResult({ items }))
    const { box } = renderCard(web01())
    await waitFor(() => expect(box().querySelectorAll('tbody tr')).toHaveLength(10))
    expect(box()).toHaveAttribute('tabindex', '0')
    expect(box()).toHaveClass('h-61', 'overflow-y-auto')
    expect([...box().querySelectorAll('tbody tr')].map((tr) => tr.getAttribute('data-line'))).toEqual(items.slice(0, 10).map((l) => l.id))
    for (const th of box().querySelectorAll('th')) expect(th).toHaveClass('sticky', 'top-0')
    for (const td of box().querySelectorAll('tbody td')) {
      // 좁은 폭 낭독용 전체 이름(sr-only)은 넓어지면 truncate 로 바뀐다. 넓은 요청 칸(웹)은 경로만 truncate, 결과는 줄지 않는다
      for (const span of td.querySelectorAll(':scope > span:not([data-request]), [data-request] > span:not([data-request-code])')) {
        expect(span.className).toMatch(/(^| |:)truncate( |$)/)
      }
    }
    expect(box().querySelector('caption')).toHaveTextContent('최근 로그 10줄, 최신 순')
    // 웹 줄: 좁으면 '웹' · 결과, 넓으면 '웹 접근' · 요청 한 줄(카드 폭 컨테이너로만 가른다)
    const web = box().querySelector(`[data-line="${lineId(20)}"]`) as HTMLElement
    const cells = [...web.querySelectorAll('td')]
    expect(cells[0]).toHaveTextContent(/^13:43:\d\d$/)
    expect(cells[0].querySelector('time')).toHaveAttribute('title', expect.stringMatching(/^2026-09-30 13:43:\d\d KST$/))
    expect(cells[1].children[0]).toHaveTextContent('웹')
    expect(cells[1].children[0]).toHaveClass('@md:hidden')
    expect(cells[1].children[1]).toHaveTextContent('웹 접근')
    expect(cells[1].children[1]).toHaveClass('sr-only', '@md:not-sr-only')
    expect(cells[2]).toHaveTextContent('203.0.113.7')
    expect(cells[3].children[0]).toHaveTextContent(/^200$/)
    expect(cells[3].children[1]).toHaveTextContent('GET /search?q=…&page=… → 200')
    // 넓은 요청 칸: 한 글꼴(font-mono) 안에서 경로만 말줄임하고 '→ 200' 은 오른쪽에 늘 보인다
    expect(cells[3].children[1]).toHaveClass('hidden', '@md:flex', 'font-mono')
    expect(cells[3].children[1].children[0]).toHaveTextContent(/^GET \/search\?q=…&page=…$/)
    expect(cells[3].children[1].children[0]).toHaveClass('min-w-0', 'truncate')
    expect(cells[3].children[1].children[1]).toHaveTextContent(/^→ 200$/)
    expect(cells[3].children[1].children[1]).toHaveClass('shrink-0')
    expect(cells[3].children[1].querySelector('.font-sans')).toBeNull()
    expect(cells[3]).toHaveAttribute('title', 'GET /search?q=…&page=… → 200')
    const ssh = box().querySelector(`[data-line="${lineId(18)}"]`) as HTMLElement
    expect(ssh.querySelectorAll('td')[3].children[0]).toHaveTextContent(/^실패$/)
    expect(ssh.querySelectorAll('td')[3].children[1]).toHaveTextContent('실패 root')
  })

  it('로그 머리의 마지막 로그는 상태판 마지막 로그와 받은 첫 줄 가운데 늦은 것이고, 1분 적재 안내는 ⓘ 에 둔다', async () => {
    stubLogs()
    const { card } = renderCard(web01())
    // web01 의 상태판 마지막 로그는 이틀 전, 받은 첫 줄은 logs as_of 보다 997초 앞
    await waitFor(() => expect(card.querySelector('[data-last-log]')).toHaveTextContent(/^· 마지막 로그 16분 전$/))
    expect(within(card).getByRole('button', { name: '최근 로그 설명' })).toHaveAccessibleDescription('로그는 1분 적재 회차로 들어오고, 사건은 그 뒤 탐지 회차에서 생깁니다.')
    expect(card).not.toHaveTextContent('10초')
  })

  it('앞선 시각 줄 안내는 상자 안 첫 줄이고, 0줄이면 상자 가운데 최근 7일 로그 없음(같은 높이)', async () => {
    stubLogs(logsResult({ future: 1001 }))
    const first = renderCard(web01())
    await waitFor(() => expect(first.box().querySelector('[data-log-future]')).toHaveTextContent('시각이 5분 넘게 앞선 줄 1,000건 넘게는 목록에서 뺐습니다'))
    expect(first.box().querySelector('tbody tr')).toHaveAttribute('data-log-future')
    first.unmount()

    stubLogs(logsResult({ items: [] }))
    const empty = renderCard(web01())
    await waitFor(() => expect(empty.box().querySelector('[data-log-empty]')).toHaveTextContent('최근 7일 로그 없음'))
    expect(empty.box()).toHaveClass('h-61')
  })

  it('받은 뒤 로그 갱신이 실패하면 줄을 흐리게 두고 머리에 이전 결과, 첫 조회 실패 · 없는 장비 · 배포 전은 상자 안 글이다', async () => {
    let fail = false
    stubLogs(() => (fail ? json({ detail: 'DB 오류' }, 503) : json(logsResult())))
    const view = renderCard(web01())
    await waitFor(() => expect(view.box().querySelector('table')).not.toBeNull())
    fail = true
    await act(async () => { await view.client.invalidateQueries() })
    await waitFor(() => expect(view.card.querySelector('[data-logs-stale]')).toHaveTextContent('이전 결과'), { timeout: 5000 })
    expect(view.box()).toHaveAttribute('data-stale')
    expect(view.box().querySelector('table')).toHaveClass('opacity-50')
    view.unmount()

    for (const [response, text] of [
      [() => json({ detail: DEVICE_NOT_FOUND }, 404), DEVICE_NOT_FOUND],
      [() => json({ detail: 'Not Found' }, 404), LOGS_NOT_DEPLOYED],
      [() => json({ detail: '권한 없음' }, 403), '최근 로그를 불러오지 못함'],
    ] as const) {
      stubLogs(response)
      const card = renderCard(web01())
      await waitFor(() => expect(card.box().querySelector('[data-log-message]')).toHaveTextContent(text))
      expect(card.box()).toHaveClass('h-61')
      card.unmount()
    }
  })

  it('로그 화면이 없는 보호 대상(모르는 고정 id)은 로그를 묻지 않고 같은 높이로 대상 아님을 적는다', () => {
    const { fetch } = stubLogs()
    const { card, box } = renderCard(web01({ id: 'edge-9', kind: 'fixed', label: 'edge-9' }))
    expect(box()).toHaveTextContent('최근 로그 없음(장비 로그 대상 아님)')
    expect(box()).toHaveClass('h-61')
    expect(fetch).not.toHaveBeenCalled()
    expect(within(card).queryByRole('button', { name: '로그 자동 갱신 정지' })).toBeNull()
    expect(within(card).queryByRole('link', { name: '로그 더 보기' })).toBeNull()
  })

  it('자동 갱신 정지: 보이는 글은 고정 · 이름은 로그 자동 갱신 정지 · 누름 상태. 정지하면 10초가 지나도 받지 않고 풀면 다시 받는다', async () => {
    vi.useFakeTimers()
    const { calls } = stubLogs()
    const { card } = renderCard(web01())
    await settle()
    expect(calls()).toEqual(['/api/devices/web-01/logs?limit=10'])
    await settle(10_000)
    expect(calls()).toHaveLength(2)
    const button = within(card).getByRole('button', { name: '로그 자동 갱신 정지' })
    expect(button).toHaveTextContent(/^자동 갱신 정지$/)
    expect(button).toHaveAttribute('aria-pressed', 'false')
    expect(button.className).toContain('aria-pressed:bg-primary-soft')
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-pressed', 'true')
    expect(button).toHaveTextContent(/^자동 갱신 정지$/)
    await settle(30_000)
    expect(calls()).toHaveLength(2)
    // 풀면 마지막으로 받은 지 10초가 넘었으니 바로 한 번 받고 다시 10초마다
    fireEvent.click(button)
    await settle()
    expect(calls()).toHaveLength(3)
    await settle(10_000)
    expect(calls()).toHaveLength(4)
  })

  it('상자가 화면 밖이면 주기 조회를 멈추고, 다시 보이면 10초가 넘었을 때 한 번 받는다', async () => {
    vi.useFakeTimers()
    const observers: IntersectionObserverCallback[] = []
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(callback: IntersectionObserverCallback) {
          observers.push(callback)
        }
        observe() {}
        disconnect() {}
      },
    )
    const { calls } = stubLogs()
    renderCard(web01())
    await settle()
    expect(calls()).toHaveLength(1)
    const see = (isIntersecting: boolean) => act(() => observers.at(-1)?.([{ isIntersecting } as IntersectionObserverEntry], {} as IntersectionObserver))
    see(false)
    await settle(30_000)
    expect(calls()).toHaveLength(1)
    see(true)
    await settle()
    expect(calls()).toHaveLength(2)
    await settle(10_000)
    expect(calls()).toHaveLength(3)
  })

  it('모바일 펼침(inline)은 이름 줄 · 경고 배지 없이 수신 줄부터(이름은 낭독용 제목으로 남는다)', () => {
    stubLogs()
    const { card } = renderCard(web01({ response: { ...web01().response, failed: 2 } }), { variant: 'inline' })
    expect(card).not.toHaveClass('shadow-card')
    expect(within(card).getByRole('heading', { level: 3 })).toHaveClass('sr-only')
    expect(card.querySelector('[data-collection-badge]')).toBeNull()
    expect(card.querySelector('[data-summary-flag]')).toBeNull()
    expect(card.querySelector('[data-signal]')).toHaveTextContent('마지막 수신 1분 전')
    expect(screen.getByRole('region', { name: 'web-01 최근 로그' })).toBeInTheDocument()
  })

  it('악성 hostname · 로그 줄(출발지 · 경로)은 표식으로 보이고 실행 · 외부 요청을 만들지 않는다', async () => {
    const hostile = logsResult({ items: [webLine(5, { src_ip: MIXED, url: `/x?${MIXED}` }), sshLine(4, { username: MIXED })] })
    stubLogs(hostile)
    const { container, card, box } = renderCard(nodeTarget('web-02', { label: MIXED }))
    await waitFor(() => expect(box().querySelectorAll('tbody tr')).toHaveLength(2))
    const title = within(card).getByRole('heading', { level: 3 })
    expect(title).toHaveAttribute('title', revealHidden(MIXED))
    const row = box().querySelector(`[data-line="${lineId(5)}"]`) as HTMLElement
    // 칸은 한 줄로 자르고(출발지 45자) 전체는 표식으로 바꾼 말풍선으로 본다
    expect(row.querySelectorAll('td')[2]).toHaveAttribute('title', revealHidden(MIXED))
    expect(row.querySelectorAll('td')[3]).toHaveAttribute('title', revealHidden(`GET /x?${MIXED} → 200`))
    expect(row.querySelectorAll('td')[2]).toHaveTextContent(/^<img src=\/\/a\.attacker\.test\/p\.png onerror=aler…$/)
    expectInertDom(container)
    // 상자 이름은 노드 이름 문자열이 아니라 제목 요소를 가리킨다
    expect(box().getAttribute('aria-label')).toBeNull()
    expect(box().getAttribute('aria-labelledby')?.split(' ')).toHaveLength(2)
  })
})
