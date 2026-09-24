import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AlertsPage } from './AlertsPage'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { DEFAULT_TEMPLATE_HEADER, DEFAULT_TEMPLATE_ITEM, NOTIFY_EVENTS, notifyKeys, type Delivery, type NotifyChannel } from '@/api/notify'
import { deliveryProblem } from '@/components/organisms/notify/problem'
import { renderTemplate } from '@/components/organisms/notify/template'

const TEAMS_HOST = 'default0123456789abcdef.cd.environment.api.powerplatform.com'
const URL_TEAMS = `https://${TEAMS_HOST}:443/powerautomate/automations/direct/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=zzzz9999`
function channel(overrides: Partial<NotifyChannel> = {}): NotifyChannel {
  return {
    id: 1, name: 'SOC Teams', kind: 'teams', grade: 'immediate', events: ['incident.created', 'pending.overdue'], min_severity: 'high', batch_seconds: 300,
    template_header: DEFAULT_TEMPLATE_HEADER, template_item: DEFAULT_TEMPLATE_ITEM, enabled: true, url_tail: '9999', url_host: TEAMS_HOST,
    created_at: '2026-09-24T00:00:00Z', updated_at: '2026-09-24T00:00:00Z', updated_by: 'admin',
    last_delivery: { status: 'sent', sent_at: '2026-09-24T00:10:00Z', response_code: 202, error: null, at: '2026-09-24T00:10:00Z' }, ...overrides,
  }
}
function delivery(i: number, overrides: Partial<Delivery> = {}): Delivery {
  return { id: i, channel_id: 1, channel_name: 'SOC Teams', event: 'incident.created', subject_key: `R101|v2|203.0.113.${i}`, status: 'sent', attempts: 1, response_code: 202, error: null, created_at: '2026-09-24T00:05:00Z', sent_at: '2026-09-24T00:10:00Z', next_attempt_at: null, ...overrides }
}

type TestReply = { status: string; response_code: number | null; error: string | null }
function setup(role = 'admin', options: { failure?: boolean; test?: TestReply | Promise<TestReply>; deliveriesFail?: { value: boolean } } = {}) {
  const channels = [channel(), channel({ id: 2, name: '운영 웹훅', kind: 'webhook', grade: 'daily', events: ['node.silent'], enabled: false, url_tail: 'ab12', url_host: 'hooks.example.net',
    last_delivery: { status: 'failed', sent_at: null, response_code: null, error: 'gaierror', at: '2026-09-24T00:20:00Z' } })]
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'tester', role })
    if (options.failure) return json({ detail: '일시 오류' }, 503)
    if (url.pathname === '/api/notify/channels' && init?.method === 'POST') { const body = JSON.parse(String(init.body)); return json(channel({ id: 3, ...body, url: undefined, url_tail: 'zzzz' }), 201) }
    if (url.pathname === '/api/notify/channels') return json(channels)
    if (/^\/api\/notify\/channels\/\d+\/test$/.test(url.pathname)) return json(await (options.test ?? { status: 'sent', response_code: 202, error: null }))
    if (/^\/api\/notify\/channels\/\d+$/.test(url.pathname) && init?.method === 'PUT') { const body = JSON.parse(String(init.body)); return json(channel({ id: Number(url.pathname.split('/').pop()), ...body })) }
    if (url.pathname === '/api/notify/deliveries') {
      if (options.deliveriesFail?.value) return json({ detail: '이력 조회 오류' }, 500)
      const offset = Number(url.searchParams.get('offset') || 0)
      const rows = url.searchParams.get('status') === 'failed' ? [delivery(offset + 1, { status: 'failed', attempts: 4, response_code: 500, error: 'HTTP 500' })] : [delivery(offset + 1)]
      return json({ rows, total: 30, limit: Number(url.searchParams.get('limit') || 25), offset })
    }
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const client = noRetryClient()
  const view = renderRoutes([{ path: '/alerts', element: <AlertsPage /> }], '/alerts', client)
  return { fetch, client, ...view }
}
const calls = (fetch: ReturnType<typeof setup>['fetch'], method: string, path: RegExp) => fetch.mock.calls.filter(([u, init]) => path.test(new URL(String(u), 'http://localhost').pathname) && (init?.method ?? 'GET') === method)
const cached = (client: ReturnType<typeof setup>['client']) => JSON.stringify([client.getQueryCache().getAll().map((q) => q.state), client.getMutationCache().getAll().map((m) => m.state)])

afterEach(() => vi.unstubAllGlobals())

describe('알림 설정', () => {
  it('채널 표에 종류 · 등급 · 사건 종류 · 묶음 · 주소 끝 4자 · 마지막 발송을 보이고 일일 요약은 사건 종류 · 심각도를 비운다', async () => {
    setup()
    const region = await screen.findByRole('region', { name: '알림 채널 표' })
    expect(within(region).getByRole('rowheader', { name: /SOC Teams/ })).toBeInTheDocument()
    expect(within(region).getByText('Teams')).toBeInTheDocument()
    expect(within(region).getByText('웹훅')).toBeInTheDocument()
    expect(within(region).getByText('즉시')).toBeInTheDocument()
    expect(within(region).getByText('일일 요약')).toBeInTheDocument()
    expect(within(region).getByText('새 인시던트 · 판정 지연')).toBeInTheDocument()
    // 일일 요약 채널은 사건 종류 · 심각도로 거르지 않으므로 보이지 않는다
    expect(within(region).queryByText('노드 수신 끊김')).toBeNull()
    const daily = within(region).getByRole('row', { name: /운영 웹훅/ })
    expect(within(daily).getAllByText('—')).toHaveLength(2)
    expect(within(region).getByText('5분')).toBeInTheDocument()
    expect(within(region).getByText('09:00 KST')).toBeInTheDocument()
    expect(within(region).getByText('…9999')).toBeInTheDocument()
    expect(within(region).getByText(TEAMS_HOST)).toBeInTheDocument()
    expect(within(region).getByText('성공')).toBeInTheDocument()
    // 실패도 언제였는지와 원인 안내를 보인다
    expect(within(daily).getByText('실패')).toBeInTheDocument()
    expect(within(daily).getByText(/이름 해석 실패/)).toBeInTheDocument()
    expect(within(daily).getAllByRole('time')).toHaveLength(2)
    expect(within(region).getByRole('switch', { name: 'SOC Teams 사용' })).toBeChecked()
    expect(within(region).getByRole('switch', { name: '운영 웹훅 사용' })).not.toBeChecked()
    expect(within(region).getByRole('button', { name: '운영 웹훅 수정' })).toBeInTheDocument()
    expect(within(region).getByRole('button', { name: '운영 웹훅 시험 발송' })).toBeInTheDocument()
  })

  it('채널 추가 요청 본문에 이름 · 종류 · 주소 · 사건 종류 · 메시지 틀을 담고, 입력한 주소는 캐시 어디에도 남지 않는다', async () => {
    const { fetch, client } = setup()
    fireEvent.click(await screen.findByRole('button', { name: '채널 추가' }))
    const form = screen.getByRole('form', { name: '채널 추가 양식' })
    expect(within(form).getByLabelText(/^이름/)).toHaveFocus()
    // 양식이 열려 있으면 머리글의 '채널 추가'는 막아 둔다(입력 중인 내용이 확인 없이 사라지지 않게)
    expect(screen.getAllByRole('button', { name: '채널 추가' })[0]).toBeDisabled()
    expect(within(form).getByLabelText(/^주소/)).toHaveAttribute('type', 'password')
    fireEvent.change(within(form).getByLabelText(/^이름/), { target: { value: ' 야간 Teams ' } })
    fireEvent.change(within(form).getByLabelText(/^주소/), { target: { value: URL_TEAMS } })
    fireEvent.change(within(form).getByLabelText('최소 심각도'), { target: { value: 'high' } })
    fireEvent.change(within(form).getByLabelText('묶음 시간(초)'), { target: { value: '600' } })
    fireEvent.click(within(form).getByLabelText('노드 수신 끊김'))
    fireEvent.change(within(form).getByLabelText('메시지 틀 · 머리말'), { target: { value: '[야간] {event_label} {count}건' } })
    fireEvent.click(within(form).getByRole('button', { name: '채널 추가' }))
    await waitFor(() => expect(calls(fetch, 'POST', /^\/api\/notify\/channels$/)).toHaveLength(1))
    const [, init] = calls(fetch, 'POST', /^\/api\/notify\/channels$/)[0]
    expect(JSON.parse(String(init?.body))).toEqual({
      name: '야간 Teams', kind: 'teams', url: URL_TEAMS, grade: 'immediate', events: ['incident.created', 'pending.overdue'], min_severity: 'high', batch_seconds: 600,
      template_header: '[야간] {event_label} {count}건', template_item: DEFAULT_TEMPLATE_ITEM, enabled: true,
    })
    expect(await screen.findByText('채널 야간 Teams 을(를) 추가했습니다.')).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: '채널 추가 양식' })).toBeNull()
    await waitFor(() => expect(calls(fetch, 'GET', /^\/api\/notify\/channels$/).length).toBeGreaterThan(1))
    const snapshot = cached(client)
    expect(snapshot).not.toContain(URL_TEAMS)
    expect(snapshot).not.toContain('sig=')
    expect(snapshot).not.toContain('zzzz9999')
  })

  it('https 가 아닌 주소는 보내지 않고, 수정 때 비운 주소는 본문에서 뺀다', async () => {
    const { fetch } = setup()
    fireEvent.click(await screen.findByRole('button', { name: '채널 추가' }))
    fireEvent.change(screen.getByLabelText(/^이름/), { target: { value: '새 채널' } })
    fireEvent.change(screen.getByLabelText(/^주소/), { target: { value: 'http://hooks.example.net/x' } })
    fireEvent.click(within(screen.getByRole('form', { name: '채널 추가 양식' })).getByRole('button', { name: '채널 추가' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('주소는 https 로 시작해야 합니다.')
    expect(calls(fetch, 'POST', /^\/api\/notify\/channels$/)).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: '취소' }))
    fireEvent.click(within(screen.getByRole('region', { name: '알림 채널 표' })).getByRole('button', { name: 'SOC Teams 수정' }))
    const form = screen.getByRole('form', { name: '채널 수정 양식' })
    expect(within(form).getByLabelText(/^이름/)).toHaveFocus()
    expect(within(form).getByText(new RegExp(`기존 주소\\(${TEAMS_HOST.replaceAll('.', '\\.')} …9999\\)를 유지`))).toBeInTheDocument()
    fireEvent.change(within(form).getByLabelText(/^이름/), { target: { value: 'SOC Teams 2' } })
    fireEvent.click(within(form).getByRole('button', { name: '변경 저장' }))
    await waitFor(() => expect(calls(fetch, 'PUT', /^\/api\/notify\/channels\/1$/)).toHaveLength(1))
    const body = JSON.parse(String(calls(fetch, 'PUT', /^\/api\/notify\/channels\/1$/)[0][1]?.body))
    expect(body).not.toHaveProperty('url')
    expect(body.name).toBe('SOC Teams 2')
    expect(body.template_item).toBe(DEFAULT_TEMPLATE_ITEM)
  })

  it('형식 지정자가 든 메시지 틀은 서버와 같은 규칙으로 화면에서 막는다', async () => {
    const { fetch } = setup()
    fireEvent.click(await screen.findByRole('button', { name: '채널 추가' }))
    const form = screen.getByRole('form', { name: '채널 추가 양식' })
    fireEvent.change(within(form).getByLabelText(/^이름/), { target: { value: '새 채널' } })
    fireEvent.change(within(form).getByLabelText(/^주소/), { target: { value: URL_TEAMS } })
    fireEvent.change(within(form).getByLabelText('메시지 틀 · 항목 한 줄'), { target: { value: '{rule_id:>5} {who}' } })
    fireEvent.click(within(form).getByRole('button', { name: '채널 추가' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('자리표시자는 {이름} 꼴만 쓸 수 있습니다')
    expect(calls(fetch, 'POST', /^\/api\/notify\/channels$/)).toHaveLength(0)
    fireEvent.change(within(form).getByLabelText('메시지 틀 · 항목 한 줄'), { target: { value: '{rule_id} {unknown} {who}' } })
    fireEvent.click(within(form).getByRole('button', { name: '채널 추가' }))
    await waitFor(() => expect(calls(fetch, 'POST', /^\/api\/notify\/channels$/)).toHaveLength(1))
  })

  it('일일 요약 등급은 사건 종류 · 최소 심각도 · 묶음 시간 · 항목 틀을 숨기고 요약 모양으로 미리 본다', async () => {
    const { fetch } = setup()
    fireEvent.click(await screen.findByRole('button', { name: '채널 추가' }))
    const form = screen.getByRole('form', { name: '채널 추가 양식' })
    fireEvent.click(within(form).getByLabelText('새 인시던트'))
    fireEvent.click(within(form).getByLabelText('판정 지연'))
    fireEvent.click(within(form).getByLabelText('노드 수신 끊김'))
    fireEvent.change(within(form).getByLabelText('등급'), { target: { value: 'daily' } })
    for (const label of ['최소 심각도', '묶음 시간(초)', '메시지 틀 · 항목 한 줄', '새 인시던트']) expect(within(form).queryByLabelText(label)).toBeNull()
    expect(within(form).getByText(/매일 09:00 KST 에 미판정 수/)).toBeInTheDocument()
    const preview = within(form).getByRole('group', { name: '메시지 미리보기' })
    expect(preview).toHaveTextContent('[OpsLoop] 일일 요약 4건')
    expect(preview).toHaveTextContent('미판정 4건 · 최고 경과 3시간 전 · 목표 초과 1건 · 최근 24시간 사건 9건')
    expect(preview).not.toHaveTextContent('R101')
    fireEvent.change(within(form).getByLabelText(/^이름/), { target: { value: '아침 요약' } })
    fireEvent.change(within(form).getByLabelText(/^주소/), { target: { value: URL_TEAMS } })
    fireEvent.click(within(form).getByRole('button', { name: '채널 추가' }))
    await waitFor(() => expect(calls(fetch, 'POST', /^\/api\/notify\/channels$/)).toHaveLength(1))
    const body = JSON.parse(String(calls(fetch, 'POST', /^\/api\/notify\/channels$/)[0][1]?.body))
    // 사건 종류를 모두 끈 채 일일로 바꿔도 서버 계약상 값은 기본값으로 보낸다
    expect(body).toMatchObject({ grade: 'daily', events: [...NOTIFY_EVENTS], batch_seconds: 300 })
  })

  it('사용/중지 토글은 기존 값을 그대로 두고 enabled 만 바꿔 보낸다', async () => {
    const { fetch } = setup()
    fireEvent.click(await screen.findByRole('switch', { name: 'SOC Teams 사용' }))
    await waitFor(() => expect(calls(fetch, 'PUT', /^\/api\/notify\/channels\/1$/)).toHaveLength(1))
    const body = JSON.parse(String(calls(fetch, 'PUT', /^\/api\/notify\/channels\/1$/)[0][1]?.body))
    expect(body).toEqual({ name: 'SOC Teams', kind: 'teams', grade: 'immediate', events: ['incident.created', 'pending.overdue'], min_severity: 'high', batch_seconds: 300, template_header: DEFAULT_TEMPLATE_HEADER, template_item: DEFAULT_TEMPLATE_ITEM, enabled: false })
    expect(await screen.findByText('채널 SOC Teams 을(를) 중지했습니다.')).toBeInTheDocument()
  })

  it('시험 발송 실패는 응답 코드를 한 번만 보이고 조치 안내로 바꾸며 이력을 다시 조회한다', async () => {
    const { fetch } = setup('admin', { test: { status: 'failed', response_code: 404, error: 'HTTP 404' } })
    const region = await screen.findByRole('region', { name: '알림 채널 표' })
    await screen.findByRole('region', { name: '발송 이력 표' })
    const before = calls(fetch, 'GET', /^\/api\/notify\/deliveries$/).length
    fireEvent.click(within(region).getByRole('button', { name: 'SOC Teams 시험 발송' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('시험 발송 실패 · SOC Teams')
    expect(alert).toHaveTextContent('HTTP 404 · 워크플로가 삭제됐거나 주소가 만료됐습니다')
    expect(alert.textContent?.match(/404/g)).toHaveLength(1)
    expect(calls(fetch, 'POST', /^\/api\/notify\/channels\/1\/test$/)).toHaveLength(1)
    await waitFor(() => expect(calls(fetch, 'GET', /^\/api\/notify\/deliveries$/).length).toBeGreaterThan(before))
  })

  it('발송 실패 원인 이름을 한국어 조치 안내로 바꾼다', () => {
    expect(deliveryProblem('gaierror', null)).toMatch(/^이름 해석 실패/)
    expect(deliveryProblem('TimeoutError', null)).toMatch(/방화벽/)
    expect(deliveryProblem('SSLCertVerificationError', null)).toMatch(/^인증서 오류/)
    expect(deliveryProblem('HTTP 429', 429)).toBe('HTTP 429 · Teams 전송 제한에 걸렸습니다 · 잠시 뒤 자동으로 다시 보냅니다')
    expect(deliveryProblem('HTTP 401', 401)).toMatch(/서명|권한/)
    expect(deliveryProblem('ChannelDisabled', null)).toMatch(/중지/)
    expect(deliveryProblem('OSError', null)).toBe('OSError')
    expect(deliveryProblem(null, 202)).toBe('')
  })

  it('시험 발송 중에는 다른 행의 토글 · 시험 발송도 막아 둔다', async () => {
    let reply: (value: TestReply) => void = () => undefined
    setup('admin', { test: new Promise<TestReply>((resolve) => { reply = resolve }) })
    const region = await screen.findByRole('region', { name: '알림 채널 표' })
    fireEvent.click(within(region).getByRole('button', { name: 'SOC Teams 시험 발송' }))
    await waitFor(() => expect(within(region).getByRole('button', { name: '운영 웹훅 시험 발송' })).toBeDisabled())
    expect(within(region).getByRole('switch', { name: '운영 웹훅 사용' })).toBeDisabled()
    expect(within(region).getByRole('switch', { name: 'SOC Teams 사용' })).toBeDisabled()
    await act(async () => reply({ status: 'sent', response_code: 202, error: null }))
    await waitFor(() => expect(within(region).getByRole('button', { name: '운영 웹훅 시험 발송' })).toBeEnabled())
  })

  it('시험 발송 성공은 응답 코드와 함께 알린다', async () => {
    setup()
    fireEvent.click(await screen.findByRole('button', { name: 'SOC Teams 시험 발송' }))
    expect(await screen.findByRole('status', { name: '' })).toBeInTheDocument()
    expect(screen.getByText('시험 발송 성공 · SOC Teams')).toBeInTheDocument()
    expect(screen.getByText(/응답 202/)).toBeInTheDocument()
  })

  it('미리보기는 1건 · 여러 건을 같이 보이고 자리표시자를 예시 값으로 바꾸며 모르는 것은 그대로 둔다', async () => {
    setup()
    fireEvent.click(await screen.findByRole('button', { name: '채널 추가' }))
    const preview = screen.getByRole('group', { name: '메시지 미리보기' })
    expect(preview).toHaveTextContent('[OpsLoop] 새 인시던트 1건')
    expect(preview).toHaveTextContent('[OpsLoop] 새 인시던트 2건')
    expect(preview).toHaveTextContent('R101 SSH 무차별 대입 · high · 203.0.113.10 · 12분 전')
    fireEvent.change(screen.getByLabelText('메시지 틀 · 머리말'), { target: { value: '{event_label} {count}건 {rule_id} {unknown} {count:>5}' } })
    fireEvent.change(screen.getByLabelText('메시지 틀 · 항목 한 줄'), { target: { value: '{incident_key} {first_ts}' } })
    // 1건이면 서버처럼 머리말에도 그 사건 값이 들어가고, 여러 건이면 '-' 다
    expect(preview).toHaveTextContent('새 인시던트 1건 R101 {unknown} {count:>5}')
    expect(preview).toHaveTextContent('새 인시던트 2건 - {unknown} {count:>5}')
    expect(preview).toHaveTextContent('R101|v2|203.0.113.10 2026-09-24 09:12')
    fireEvent.click(screen.getByRole('button', { name: '기본값으로' }))
    expect(screen.getByLabelText('메시지 틀 · 머리말')).toHaveValue(DEFAULT_TEMPLATE_HEADER)
    expect(screen.getByLabelText('메시지 틀 · 항목 한 줄')).toHaveValue(DEFAULT_TEMPLATE_ITEM)
    expect(renderTemplate('{who} {elapsed} {nope}', { who: '', elapsed: null })).toBe('- - {nope}')
  })

  it.each(['viewer', 'operator'])('%s는 403 안내를 보고 알림 API 를 부르지 않는다', async (role) => {
    const { fetch } = setup(role)
    expect(await screen.findByText('이 화면은 admin 만 볼 수 있습니다')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`현재 역할 ${role}`))).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '채널 추가' })).toBeNull()
    expect(fetch.mock.calls.some(([u]) => String(u).startsWith('/api/notify'))).toBe(false)
  })

  it('이력 필터(채널 · 상태)와 페이지를 쿼리 문자열로 보낸다', async () => {
    const { fetch } = setup()
    const region = await screen.findByRole('region', { name: '발송 이력 표' })
    expect(within(region).getByText('R101|v2|203.0.113.1')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('채널'), { target: { value: '1' } })
    fireEvent.change(screen.getByLabelText('상태'), { target: { value: 'failed' } })
    await waitFor(() => expect(fetch.mock.calls.some(([raw]) => { const u = new URL(String(raw), 'http://localhost'); return u.pathname === '/api/notify/deliveries' && u.searchParams.get('channel_id') === '1' && u.searchParams.get('status') === 'failed' && u.searchParams.get('limit') === '25' && u.searchParams.get('offset') === '0' })).toBe(true))
    expect(await screen.findByText(/HTTP 500 · 받는 쪽 서버 오류/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '발송 이력 표' })).getByText('실패')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '다음' }))
    await waitFor(() => expect(fetch.mock.calls.some(([raw]) => { const u = new URL(String(raw), 'http://localhost'); return u.pathname === '/api/notify/deliveries' && u.searchParams.get('status') === 'failed' && u.searchParams.get('offset') === '25' })).toBe(true))
    expect(await screen.findByText('2 / 2페이지')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('상태'), { target: { value: '' } })
    await waitFor(() => expect(fetch.mock.calls.filter(([raw]) => { const u = new URL(String(raw), 'http://localhost'); return u.pathname === '/api/notify/deliveries' && !u.searchParams.has('status') && u.searchParams.get('channel_id') === '1' && u.searchParams.get('offset') === '0' }).length).toBeGreaterThan(0))
  })

  it('이력 재조회가 실패하면 이전 행을 두고 상단 띠로 알린다', async () => {
    const deliveriesFail = { value: false }
    const { client } = setup('admin', { deliveriesFail })
    await screen.findByRole('region', { name: '발송 이력 표' })
    deliveriesFail.value = true
    await act(async () => { await client.invalidateQueries({ queryKey: notifyKeys.all }) })
    expect(await screen.findByText('데이터를 갱신하지 못했습니다')).toBeInTheDocument()
    expect(screen.getByText(/이력 조회 오류/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '발송 이력 표' })).getByText('R101|v2|203.0.113.1')).toBeInTheDocument()
  })

  it('조회 실패를 빈 목록으로 숨기지 않는다', async () => {
    setup('admin', { failure: true })
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText('등록된 채널이 없습니다.')).toBeNull()
  })
})
