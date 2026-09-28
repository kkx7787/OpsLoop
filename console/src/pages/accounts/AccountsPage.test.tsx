import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AccountsPage } from './AccountsPage'
import { accountKeys, type Account } from '@/api/accounts'
import { auditKey } from '@/api/operations'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { ACCOUNTS, account } from '@/test/accounts-fixtures'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

type Reply = (path: string, body: Record<string, unknown>) => Response | Promise<Response>
/** 계정 API 가짜. 쓰기는 기본으로 적용하고 바뀐 행을 돌려준다(다음 조회에도 반영). setRows 는 다른 콘솔 · 명령줄의 변경을 흉내 낸다 */
function setup(role = 'admin', options: { accounts?: Account[]; reply?: Reply; failure?: boolean } = {}) {
  let rows = options.accounts ?? ACCOUNTS
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'root', role })
    if (options.failure) return json({ detail: '일시 오류' }, 503)
    if (url.pathname === '/api/accounts' && (init?.method ?? 'GET') === 'GET') return json({ accounts: rows })
    if (init?.method === 'POST' && (url.pathname === '/api/accounts/role' || url.pathname === '/api/accounts/active')) {
      const body = JSON.parse(String(init.body))
      if (options.reply) return options.reply(url.pathname, body)
      rows = rows.map((a) => a.username !== body.username ? a : 'role' in body ? { ...a, role: body.role } : { ...a, active: body.active, disabled_at: body.active ? null : '2026-09-29T01:00:00Z' })
      return json({ result: 'ok', account: rows.find((a) => a.username === body.username) })
    }
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const client = noRetryClient()
  const view = renderRoutes([{ path: '/accounts', element: <AccountsPage /> }], '/accounts', client)
  return { fetch, client, setRows: (next: Account[]) => { rows = next }, ...view }
}
const calls = (fetch: ReturnType<typeof setup>['fetch'], method: string, path: string) => fetch.mock.calls.filter(([u, init]) => new URL(String(u), 'http://localhost').pathname === path && (init?.method ?? 'GET') === method)
const bodies = (fetch: ReturnType<typeof setup>['fetch'], path: string) => calls(fetch, 'POST', path).map(([, init]) => JSON.parse(String(init?.body)))
/** 표의 행(머리 행 뺌). ACCOUNTS 순서: han · kim · ops-admin · root */
async function rows() {
  const region = await screen.findByRole('region', { name: '계정 표' })
  return within(region).getAllByRole('row').slice(1)
}

afterEach(() => vi.unstubAllGlobals())

describe('계정', () => {
  it.each(['viewer', 'operator'])('%s는 403 안내를 보고 계정 API 를 부르지 않는다', async (role) => {
    const { fetch } = setup(role)
    expect(await screen.findByText('이 화면은 admin 만 볼 수 있습니다')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`현재 역할 ${role}`))).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '명령줄에서 하는 일' })).toBeNull()
    expect(fetch.mock.calls.some(([u]) => String(u).startsWith('/api/accounts'))).toBe(false)
  })

  it('목록: 아이디 · 역할 · 상태 · 마지막 로그인 · 변경 시각을 보이고, 관리자 · 본인 행은 버튼 대신 까닭을 보인다', async () => {
    setup()
    const [han, kim, opsAdmin, root] = await rows()
    expect(within(han).getByRole('rowheader')).toHaveTextContent('han')
    expect(han).toHaveTextContent('관제사')
    expect(han).toHaveTextContent('operator')
    expect(within(han).getByText('활성')).toBeInTheDocument()
    expect(within(han).getByText('09-29 08:10')).toBeInTheDocument()
    expect(within(han).getByRole('button', { name: 'han 조회자로 낮추기' })).toHaveAttribute('aria-expanded', 'false')
    expect(within(han).getByRole('button', { name: 'han 비활성' })).toBeInTheDocument()
    // 비활성 계정: 비활성 시각 · 로그인 기록 없음 · 변경 시각, 버튼은 반대 방향
    expect(kim).toHaveTextContent('조회자')
    expect(within(kim).getByText('비활성')).toBeInTheDocument()
    expect(within(kim).getAllByText('09-28 10:00')).toHaveLength(2)
    expect(within(kim).getByText('기록 없음')).toBeInTheDocument()
    expect(within(kim).getByRole('button', { name: 'kim 관제사로 바꾸기' })).toBeInTheDocument()
    expect(within(kim).getByRole('button', { name: 'kim 재활성' })).toBeInTheDocument()
    expect(opsAdmin).toHaveTextContent('관리자')
    expect(within(opsAdmin).getByText('명령줄에서만 변경')).toBeInTheDocument()
    expect(within(opsAdmin).queryAllByRole('button')).toHaveLength(0)
    expect(within(root).getByText('본인 계정')).toBeInTheDocument()
    expect(within(root).queryAllByRole('button')).toHaveLength(0)
    // 명령줄 안내: 비밀값 없이 명령 모양만
    const cli = screen.getByRole('heading', { name: '명령줄에서 하는 일' }).closest('div')?.parentElement as HTMLElement
    expect(within(cli).getByText('python3 auth.py add <아이디> <역할> --by <내 이름>')).toBeInTheDocument()
    expect(within(cli).getByText('python3 auth.py role <아이디> admin --by <내 이름>')).toBeInTheDocument()
    expect(within(cli).getByText('python3 auth.py passwd <아이디> --by <내 이름>')).toBeInTheDocument()
    expect(within(cli).getByText('python3 auth.py disable <아이디> --by <내 이름>')).toBeInTheDocument()
    expect(cli.textContent).not.toMatch(/postgresql:\/\/|POSTGRES_PASSWORD/)
  })

  it('서버가 잠금을 주지 않아도 관리자 계정에는 버튼을 두지 않는다', async () => {
    setup('admin', { accounts: [account({ username: 'boss', role: 'admin', locked: null })] })
    const [boss] = await rows()
    expect(within(boss).getByText('명령줄에서만 변경')).toBeInTheDocument()
    expect(within(boss).queryAllByRole('button')).toHaveLength(0)
  })

  it('역할 낮추기: 줄 안 확인 양식 → 확정하면 본문을 보내고 성공 띠 · 목록과 감사를 다시 조회 · 연 버튼으로 초점을 돌린다', async () => {
    const { fetch, client } = setup()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 조회자로 낮추기' }))
    const form = screen.getByRole('form', { name: 'han 조회자로 낮추기 확인' })
    expect(within(han).getByRole('button', { name: 'han 조회자로 낮추기' })).toHaveAttribute('aria-expanded', 'true')
    expect(form).toHaveTextContent('han 의 역할을 조회자로 낮춥니다')
    expect(form).toHaveTextContent('열린 세션은 끊겨 다시 로그인해야 합니다(실시간 연결은 30초 안에 끊깁니다)')
    expect(form).toHaveTextContent('감사 기록에 남습니다')
    expect(calls(fetch, 'POST', '/api/accounts/role')).toHaveLength(0)
    const before = calls(fetch, 'GET', '/api/accounts').length
    fireEvent.click(within(form).getByRole('button', { name: '조회자로 낮추기 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/role')).toEqual([{ username: 'han', role: 'viewer' }]))
    expect(await screen.findByRole('status')).toHaveTextContent('han 의 역할을 조회자로 바꿨습니다 · 그 계정의 열린 세션은 다시 로그인해야 합니다.')
    expect(screen.queryByRole('form', { name: 'han 조회자로 낮추기 확인' })).toBeNull()
    expect(calls(fetch, 'GET', '/api/accounts').length).toBeGreaterThan(before)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: accountKeys.all })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: auditKey })
    const [again] = await rows()
    expect(again).toHaveTextContent('조회자')
    await waitFor(() => expect(within(again).getByRole('button', { name: 'han 관제사로 바꾸기' })).toHaveFocus())
  })

  it.each([
    ['han', '비활성', '/api/accounts/active', { username: 'han', active: false }, 'han 계정을 비활성했습니다', '로그인할 수 없게 되며'],
    ['kim', '재활성', '/api/accounts/active', { username: 'kim', active: true }, 'kim 계정을 재활성했습니다', '비활성 전에 받은 세션은 되살아나지 않아'],
    ['kim', '관제사로 바꾸기', '/api/accounts/role', { username: 'kim', role: 'operator' }, 'kim 의 역할을 관제사로 바꿨습니다', '판정 · 차단 요청을 할 수 있게 됩니다'],
  ])('%s %s → %s', async (name, label, path, body, done, sentence) => {
    const { fetch } = setup()
    await rows()
    fireEvent.click(screen.getByRole('button', { name: `${name} ${label}` }))
    const form = screen.getByRole('form', { name: `${name} ${label} 확인` })
    expect(form).toHaveTextContent(sentence)
    fireEvent.click(within(form).getByRole('button', { name: `${label} 확정` }))
    await waitFor(() => expect(bodies(fetch, path)).toEqual([body]))
    expect(await screen.findByRole('status')).toHaveTextContent(done)
  })

  it('409 는 서버 설명을 그대로 띠에 보이고 양식을 닫지 않으며 목록을 다시 받는다', async () => {
    const { fetch } = setup('admin', { reply: () => json({ detail: '관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다' }, 409) })
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 비활성' }))
    const before = calls(fetch, 'GET', '/api/accounts').length
    fireEvent.click(within(screen.getByRole('form', { name: 'han 비활성 확인' })).getByRole('button', { name: '비활성 확정' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('han · 비활성 실패 · 관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다 (HTTP 409)')
    expect(screen.getByRole('form', { name: 'han 비활성 확인' })).toBeInTheDocument()
    await waitFor(() => expect(calls(fetch, 'GET', '/api/accounts').length).toBeGreaterThan(before))
    fireEvent.click(within(alert).getByRole('button', { name: '닫기' }))
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('확정을 여러 번 눌러도 한 번만 보내고, 처리 중에는 다른 행의 버튼도 막는다', async () => {
    let answer: (value: Response) => void = () => undefined
    const { fetch } = setup('admin', { reply: () => new Promise<Response>((resolve) => { answer = resolve }) })
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 비활성' }))
    const form = screen.getByRole('form', { name: 'han 비활성 확인' })
    const submit = within(form).getByRole('button', { name: '비활성 확정' })
    fireEvent.click(submit)
    fireEvent.click(submit)
    fireEvent.submit(form)
    await waitFor(() => expect(calls(fetch, 'POST', '/api/accounts/active')).toHaveLength(1))
    expect(submit).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('button', { name: 'kim 재활성' })).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('button', { name: 'kim 재활성' })).toHaveAttribute('title', '다른 계정 변경을 처리하는 중입니다')
    fireEvent.click(screen.getByRole('button', { name: 'kim 재활성' }))
    expect(screen.queryByRole('form', { name: 'kim 재활성 확인' })).toBeNull()
    await act(async () => answer(json({ result: 'ok', account: account({ active: false, disabled_at: '2026-09-29T01:00:00Z' }) })))
    await waitFor(() => expect(screen.getByRole('button', { name: 'kim 재활성' })).not.toHaveAttribute('aria-disabled'))
    expect(calls(fetch, 'POST', '/api/accounts/active')).toHaveLength(1)
  })

  it('다른 행의 확정도 처리 중에는 까닭을 보이며 막고, 끝나면 보낼 수 있다', async () => {
    let answer: (value: Response) => void = () => undefined
    const { fetch } = setup('admin', { reply: (_, body) => body.username === 'han' ? new Promise<Response>((resolve) => { answer = resolve }) : json({ result: 'ok', account: account({ username: 'kim', role: 'viewer' }) }) })
    const [han, kim] = await rows()
    fireEvent.click(within(kim).getByRole('button', { name: 'kim 재활성' }))
    fireEvent.click(within(han).getByRole('button', { name: 'han 비활성' }))
    fireEvent.click(within(screen.getByRole('form', { name: 'han 비활성 확인' })).getByRole('button', { name: '비활성 확정' }))
    await waitFor(() => expect(calls(fetch, 'POST', '/api/accounts/active')).toHaveLength(1))
    expect(within(han).getByRole('button', { name: 'han 비활성' })).toHaveAttribute('title', '이 계정 변경을 처리하는 중입니다')
    const other = within(screen.getByRole('form', { name: 'kim 재활성 확인' })).getByRole('button', { name: '재활성 확정' })
    expect(other).toHaveAttribute('aria-disabled', 'true')
    expect(other).toHaveAttribute('title', '다른 계정 변경을 처리하는 중입니다')
    fireEvent.click(other)
    expect(calls(fetch, 'POST', '/api/accounts/active')).toHaveLength(1)
    await act(async () => answer(json({ result: 'ok', account: account({ active: false, disabled_at: '2026-09-29T01:00:00Z' }) })))
    await waitFor(() => expect(other).not.toHaveAttribute('aria-disabled'))
    fireEvent.click(other)
    await waitFor(() => expect(bodies(fetch, '/api/accounts/active')).toEqual([{ username: 'han', active: false }, { username: 'kim', active: true }]))
  })

  it('양식을 연 뒤 목록이 바뀌어도 읽은 문장의 변경을 보낸다(반대 방향으로 뒤집지 않는다)', async () => {
    const { fetch, client, setRows } = setup()
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 조회자로 낮추기' }))
    // 그사이 다른 관리자가 han 을 조회자로 낮췄다. 다시 받은 행의 버튼은 반대 방향이 된다
    setRows(ACCOUNTS.map((a) => a.username === 'han' ? { ...a, role: 'viewer' } : a))
    await act(() => client.refetchQueries({ queryKey: accountKeys.all }))
    expect(await within(han).findByRole('button', { name: 'han 관제사로 바꾸기' })).toHaveAttribute('aria-expanded', 'true')
    const form = screen.getByRole('form', { name: 'han 조회자로 낮추기 확인' })
    expect(form).toHaveTextContent('han 의 역할을 조회자로 낮춥니다')
    fireEvent.click(within(form).getByRole('button', { name: '조회자로 낮추기 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/role')).toEqual([{ username: 'han', role: 'viewer' }]))
  })

  it.each([
    ['연결 끊김', () => { throw new TypeError('Failed to fetch') }, '서버에 연결할 수 없습니다'],
    ['502', () => json({}, 502), '콘솔 서버가 응답하지 않습니다 (HTTP 502)'],
  ])('응답을 받지 못하면(%s) 실패로 단정하지 않고 다시 받은 목록을 보게 한다', async (_, reply, detail) => {
    const { fetch } = setup('admin', { reply })
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 비활성' }))
    const before = calls(fetch, 'GET', '/api/accounts').length
    fireEvent.click(within(screen.getByRole('form', { name: 'han 비활성 확인' })).getByRole('button', { name: '비활성 확정' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(`han · 비활성 결과 확인 필요 · ${detail} · 적용됐을 수 있으니 다시 받은 목록에서 상태를 확인해 주세요.`)
    await waitFor(() => expect(calls(fetch, 'GET', '/api/accounts').length).toBeGreaterThan(before))
  })

  it('이미 그 값이면(unchanged) 바뀐 것이 없다고 알린다', async () => {
    setup('admin', { reply: (_, body) => json({ result: 'unchanged', account: account({ username: String(body.username) }) }) })
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 조회자로 낮추기' }))
    fireEvent.click(screen.getByRole('button', { name: '조회자로 낮추기 확정' }))
    expect(await screen.findByRole('status')).toHaveTextContent('han 은(는) 이미 조회자 상태입니다 · 바뀐 것이 없어 감사 기록도 남지 않았습니다.')
  })

  it('취소하면 보내지 않고 양식을 닫아 연 버튼으로 초점을 돌린다', async () => {
    const { fetch } = setup()
    const [, kim] = await rows()
    fireEvent.click(within(kim).getByRole('button', { name: 'kim 재활성' }))
    fireEvent.click(within(screen.getByRole('form', { name: 'kim 재활성 확인' })).getByRole('button', { name: '취소' }))
    expect(screen.queryByRole('form', { name: 'kim 재활성 확인' })).toBeNull()
    expect(within(kim).getByRole('button', { name: 'kim 재활성' })).toHaveFocus()
    expect(calls(fetch, 'POST', '/api/accounts/active')).toHaveLength(0)
  })

  it('조회 실패를 빈 목록으로 숨기지 않는다', async () => {
    setup('admin', { failure: true })
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText('계정이 없습니다.')).toBeNull()
  })
})

describe('계정 · 비신뢰 문자열(#41)', () => {
  it('아이디를 글자로만 그리고 숨은 문자는 표식 · 긴 아이디는 접으며, 변경 본문에는 원문 그대로 보낸다', async () => {
    const accounts = [account({ username: MIXED }), account({ username: HOSTILE.rlo, role: 'viewer' }), account({ username: LONG })]
    const { fetch, container } = setup('admin', { accounts })
    const region = await screen.findByRole('region', { name: '계정 표' })
    const [mixed, rlo, long] = within(region).getAllByRole('row').slice(1)
    expect(within(rlo).getByRole('rowheader').querySelector('bdi')?.textContent).toBe('admin⟨U+202E⟩gnp.exe')
    expect(long.textContent).not.toContain(LONG)
    // 아이디 칸은 64자까지만 보이고 펼친다
    for (const more of within(region).getAllByRole('button', { name: /자 더 · 펼치기$/ })) fireEvent.click(more)
    expectMixedRevealed(region)
    expect(long.textContent).toContain(LONG)
    fireEvent.click(within(mixed).getByRole('button', { name: / 비활성$/ }))
    const form = within(region).getByRole('form')
    expectInertDom(container)
    fireEvent.click(within(form).getByRole('button', { name: '비활성 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/active')).toEqual([{ username: MIXED, active: false }]))
    await screen.findByRole('status')
    expectInertDom(container)
  })
})
