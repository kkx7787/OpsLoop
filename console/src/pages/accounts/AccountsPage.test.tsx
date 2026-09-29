import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AccountsPage } from './AccountsPage'
import { accountKeys, type Account } from '@/api/accounts'
import { auditKey } from '@/api/operations'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { ACCOUNTS, account, TEST_PASSWORD, TEST_PASSWORD_2 } from '@/test/accounts-fixtures'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, MIXED } from '@/test/hostile-fixtures'

type Reply = (path: string, body: Record<string, unknown>) => Response | Promise<Response>
const WRITES = ['/api/accounts', '/api/accounts/role', '/api/accounts/active', '/api/accounts/password', '/api/accounts/delete']
/** 계정 API 가짜. 쓰기는 기본으로 적용하고 바뀐 행을 돌려준다(다음 조회에도 반영). setRows 는 다른 콘솔 · 명령줄의 변경을 흉내 낸다 */
function setup(role = 'admin', options: { accounts?: Account[]; reply?: Reply; failure?: boolean } = {}) {
  let rows = options.accounts ?? ACCOUNTS
  const one = (username: unknown) => rows.find((a) => a.username === username)
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'root', role })
    if (options.failure) return json({ detail: '일시 오류' }, 503)
    if (url.pathname === '/api/accounts' && (init?.method ?? 'GET') === 'GET') return json({ accounts: rows })
    if (init?.method === 'POST' && WRITES.includes(url.pathname)) {
      const body = JSON.parse(String(init.body))
      if (options.reply) return options.reply(url.pathname, body)
      switch (url.pathname) {
        case '/api/accounts':
          rows = [...rows, account({ username: body.username, role: body.role, last_login_at: null, updated_at: '2026-09-29T02:00:00Z', deletable: true })].sort((a, b) => a.username.localeCompare(b.username))
          return json({ result: 'ok', account: one(body.username) }, 201)
        case '/api/accounts/delete':
          rows = rows.filter((a) => a.username !== body.username)
          return json({ result: 'ok' })
        case '/api/accounts/password':
          rows = rows.map((a) => a.username !== body.username ? a : { ...a, updated_at: '2026-09-29T02:00:00Z' })
          return json({ result: 'ok', account: one(body.username) })
      }
      rows = rows.map((a) => a.username !== body.username ? a : 'role' in body ? { ...a, role: body.role } : { ...a, active: body.active, disabled_at: body.active ? null : '2026-09-29T01:00:00Z' })
      return json({ result: 'ok', account: one(body.username) })
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
/** 비밀번호 칸은 역할이 없어(type=password) 라벨로 찾는다. 필수 라벨 끝에는 '*필수' 가 붙는다 */
const field = (scope: HTMLElement, label: string) => within(scope).getByLabelText(new RegExp(`^${label}\\*`)) as HTMLInputElement
const type = (input: HTMLElement, value: string) => fireEvent.change(input, { target: { value } })
/** 머리의 '계정 추가' 로 추가 양식을 연다 */
function openAdd() {
  fireEvent.click(screen.getByRole('button', { name: '계정 추가', expanded: false }))
  return screen.getByRole('form', { name: '계정 추가 양식' })
}
const addForm = () => screen.queryByRole('form', { name: '계정 추가 양식' }) ?? openAdd()
/** 추가 양식 채우기(닫혀 있으면 연다). 역할은 기본(조회자)이 아닐 때만 고른다 */
function fillAdd(username: string, password: string, confirm = password, role?: string) {
  const form = addForm()
  type(field(form, '아이디'), username)
  if (role) fireEvent.change(within(form).getByRole('combobox', { name: '역할' }), { target: { value: role } })
  type(field(form, '비밀번호'), password)
  type(field(form, '비밀번호 확인'), confirm)
  return form
}
/** 행의 비밀번호 재설정 양식 열고 채우기 */
function fillReset(name: string, password: string, confirm = password) {
  fireEvent.click(screen.getByRole('button', { name: `${name} 비밀번호 재설정` }))
  const form = screen.getByRole('form', { name: `${name} 비밀번호 재설정 확인` })
  type(field(form, '새 비밀번호'), password)
  type(field(form, '새 비밀번호 확인'), confirm)
  return form
}

afterEach(() => vi.unstubAllGlobals())

describe('계정', () => {
  it.each(['viewer', 'operator'])('%s는 403 안내를 보고 계정 API 를 부르지 않는다', async (role) => {
    const { fetch } = setup(role)
    expect(await screen.findByText('이 화면은 admin 만 볼 수 있습니다')).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`현재 역할 ${role}`))).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '명령줄에서 하는 일' })).toBeNull()
    expect(screen.queryByRole('button', { name: '계정 추가' })).toBeNull()
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
    expect(within(han).getByRole('button', { name: 'han 비밀번호 재설정' })).toBeInTheDocument()
    // 이력(로그인 기록)이 있는 계정에는 삭제 단추가 없다
    expect(within(han).queryByRole('button', { name: 'han 삭제' })).toBeNull()
    // 비활성 계정: 비활성 시각 · 로그인 기록 없음 · 변경 시각, 버튼은 반대 방향
    expect(kim).toHaveTextContent('조회자')
    expect(within(kim).getByText('비활성')).toBeInTheDocument()
    expect(within(kim).getAllByText('09-28 10:00')).toHaveLength(2)
    expect(within(kim).getByText('기록 없음')).toBeInTheDocument()
    expect(within(kim).getByRole('button', { name: 'kim 관제사로 바꾸기' })).toBeInTheDocument()
    expect(within(kim).getByRole('button', { name: 'kim 재활성' })).toBeInTheDocument()
    expect(within(kim).getByRole('button', { name: 'kim 삭제' })).toBeInTheDocument()
    expect(opsAdmin).toHaveTextContent('관리자')
    expect(within(opsAdmin).getByText('명령줄에서만 변경')).toBeInTheDocument()
    expect(within(opsAdmin).queryAllByRole('button')).toHaveLength(0)
    expect(within(root).getByText('본인 계정')).toBeInTheDocument()
    expect(within(root).queryAllByRole('button')).toHaveLength(0)
    // 명령줄 안내: 비밀값 없이 명령 모양만
    const cli = screen.getByRole('heading', { name: '명령줄에서 하는 일' }).closest('div')?.parentElement as HTMLElement
    expect(within(cli).getByText('관리자 계정 추가')).toBeInTheDocument()
    expect(within(cli).getByText('python3 auth.py add <아이디> admin --by <내 이름>')).toBeInTheDocument()
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

describe('계정 추가 · 비밀번호 재설정 · 삭제(#63)', () => {
  it('추가: 머리 단추로 양식을 열고 닫으면 단추로 초점을 돌리며, 다시 열면 칸이 비어 있다', async () => {
    const { fetch } = setup()
    await rows()
    expect(screen.queryByRole('form', { name: '계정 추가 양식' })).toBeNull()
    const opener = screen.getByRole('button', { name: '계정 추가', expanded: false })
    let form = openAdd()
    expect(opener).toHaveAttribute('aria-expanded', 'true')
    expect(opener).toHaveAttribute('aria-disabled', 'true')
    await waitFor(() => expect(field(form, '아이디')).toHaveFocus())
    type(field(form, '아이디'), 'draft-op')
    type(field(form, '비밀번호'), TEST_PASSWORD)
    fireEvent.click(within(form).getByRole('button', { name: '닫기' }))
    expect(screen.queryByRole('form', { name: '계정 추가 양식' })).toBeNull()
    await waitFor(() => expect(opener).toHaveFocus())
    form = openAdd()
    expect(field(form, '아이디')).toHaveValue('')
    expect(field(form, '비밀번호')).toHaveValue('')
    expect(calls(fetch, 'POST', '/api/accounts')).toHaveLength(0)
  })

  it('추가: 아이디 · 역할 · 비밀번호를 보내고 성공 띠 · 목록 갱신 · 칸을 비우고 아이디 칸으로 초점을 옮긴다', async () => {
    const { fetch, client } = setup()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    await rows()
    const form = openAdd()
    expect(within(form).getByRole('combobox', { name: '역할' })).toHaveValue('viewer')
    expect(within(form).getAllByRole('option').map((o) => o.textContent)).toEqual(['관제사', '조회자'])
    for (const label of ['비밀번호', '비밀번호 확인']) {
      expect(field(form, label)).toHaveAttribute('type', 'password')
      expect(field(form, label)).toHaveAttribute('autocomplete', 'new-password')
      expect(field(form, label)).not.toHaveAttribute('name')
    }
    fillAdd('new.op-1', TEST_PASSWORD, TEST_PASSWORD, 'operator')
    // 브라우저처럼 누른 단추에 초점이 간다. 성공 뒤 아이디 칸으로 옮기는지 본다
    const submit = within(form).getByRole('button', { name: '계정 추가' })
    submit.focus()
    fireEvent.click(submit)
    await waitFor(() => expect(bodies(fetch, '/api/accounts')).toEqual([{ username: 'new.op-1', role: 'operator', password: TEST_PASSWORD }]))
    expect(await screen.findByRole('status')).toHaveTextContent('new.op-1 계정을 관제사로 추가했습니다')
    expect(invalidate).toHaveBeenCalledWith({ queryKey: accountKeys.all })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: auditKey })
    const added = (await rows()).find((r) => within(r).getByRole('rowheader').textContent?.startsWith('new.op-1'))
    expect(added).toBeDefined()
    expect(within(added as HTMLElement).getByRole('button', { name: 'new.op-1 삭제' })).toBeInTheDocument()
    expect(field(form, '아이디')).toHaveValue('')
    expect(field(form, '비밀번호')).toHaveValue('')
    expect(field(form, '비밀번호 확인')).toHaveValue('')
    expect(within(form).getByRole('combobox', { name: '역할' })).toHaveValue('viewer')
    expect(field(form, '아이디')).toHaveFocus()
  })

  it.each([
    ['비밀번호가 다르면', 'new-op', TEST_PASSWORD, TEST_PASSWORD_2, '비밀번호 확인', '비밀번호가 서로 다릅니다.'],
    ['비밀번호가 11자면', 'new-op', 'short-pw-11', 'short-pw-11', '비밀번호', '12자 이상이어야 합니다.'],
    ['비밀번호가 257자면', 'new-op', 'p'.repeat(257), 'p'.repeat(257), '비밀번호', '256자 이하여야 합니다.'],
    ['아이디에 빈칸이 있으면', 'new op', TEST_PASSWORD, TEST_PASSWORD, '아이디', '영문 · 숫자 · . _ - 로 64자까지입니다.'],
    ['아이디가 한글이면', '관제사', TEST_PASSWORD, TEST_PASSWORD, '아이디', '영문 · 숫자 · . _ - 로 64자까지입니다.'],
    ['아이디가 비었으면', '', TEST_PASSWORD, TEST_PASSWORD, '아이디', '아이디를 입력해 주세요.'],
  ])('추가: %s 보내지 않고 그 칸에 까닭을 보인다', async (_, username, password, confirm, label, message) => {
    const { fetch } = setup()
    await rows()
    const form = fillAdd(username, password, confirm)
    fireEvent.click(within(form).getByRole('button', { name: '계정 추가' }))
    const input = field(form, label)
    await waitFor(() => expect(input).toHaveAccessibleDescription(expect.stringContaining(message)))
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveFocus()
    expect(calls(fetch, 'POST', '/api/accounts')).toHaveLength(0)
    // 고치면 그 칸의 오류가 사라진다
    type(input, label === '아이디' ? 'new-op' : TEST_PASSWORD)
    expect(input).not.toHaveAttribute('aria-invalid')
  })

  it('추가: 256자 · 유니코드 비밀번호는 글자 수로 센다(서버 len 과 같다)', async () => {
    const { fetch } = setup()
    await rows()
    const password = '😀'.repeat(256)
    fireEvent.click(within(fillAdd('emoji-pw', password)).getByRole('button', { name: '계정 추가' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts')).toEqual([{ username: 'emoji-pw', role: 'viewer', password }]))
  })

  it.each([
    ['409 이미 있는 아이디', json({ detail: '이미 있는 아이디입니다' }, 409), 'han · 계정 추가 실패 · 이미 있는 아이디입니다 (HTTP 409)'],
    ['422 입력 검증', json({ detail: [{ loc: ['body', 'password'], msg: '비밀번호는 12자 이상이어야 합니다' }] }, 422), 'han · 계정 추가 실패 · 비밀번호는 12자 이상이어야 합니다 (HTTP 422)'],
  ])('추가 %s: 서버 설명을 띠에 보이고 고쳐 보낼 수 있게 값을 둔다', async (_, response, text) => {
    const { fetch } = setup('admin', { reply: () => response })
    await rows()
    const form = fillAdd('han', TEST_PASSWORD)
    const before = calls(fetch, 'GET', '/api/accounts').length
    fireEvent.click(within(form).getByRole('button', { name: '계정 추가' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(text)
    expect(field(form, '아이디')).toHaveValue('han')
    expect(field(form, '비밀번호')).toHaveValue(TEST_PASSWORD)
    await waitFor(() => expect(calls(fetch, 'GET', '/api/accounts').length).toBeGreaterThan(before))
  })

  it('추가 중에는 두 번 보내지 않고 행 버튼도 막으며, 행을 처리하는 중에는 추가를 막는다', async () => {
    let answer: (value: Response) => void = () => undefined
    const { fetch } = setup('admin', { reply: () => new Promise<Response>((resolve) => { answer = resolve }) })
    await rows()
    const form = fillAdd('new-op', TEST_PASSWORD)
    const submit = within(form).getByRole('button', { name: '계정 추가' })
    fireEvent.click(submit)
    fireEvent.click(submit)
    fireEvent.submit(form)
    await waitFor(() => expect(calls(fetch, 'POST', '/api/accounts')).toHaveLength(1))
    expect(submit).toHaveAttribute('aria-busy', 'true')
    // 보내는 동안 칸은 끄지 않고 읽기 전용이다(끄면 Enter 를 누른 칸에서 초점이 빠져 거부 뒤 제자리를 잃는다)
    for (const label of ['아이디', '비밀번호', '비밀번호 확인']) {
      expect(field(form, label)).not.toBeDisabled()
      expect(field(form, label)).toHaveAttribute('readonly')
    }
    expect(screen.getByRole('button', { name: 'han 비밀번호 재설정' })).toHaveAttribute('title', '다른 계정 변경을 처리하는 중입니다')
    await act(async () => answer(json({ result: 'ok', account: account({ username: 'new-op', role: 'viewer' }) }, 201)))
    await waitFor(() => expect(submit).not.toHaveAttribute('aria-busy'))
    // 행 쪽이 처리 중이면 추가 단추가 까닭을 보이며 막힌다
    fireEvent.click(screen.getByRole('button', { name: 'han 비활성' }))
    fireEvent.click(within(screen.getByRole('form', { name: 'han 비활성 확인' })).getByRole('button', { name: '비활성 확정' }))
    await waitFor(() => expect(submit).toHaveAttribute('aria-disabled', 'true'))
    expect(submit).toHaveAttribute('title', '다른 계정 변경을 처리하는 중입니다')
    fillAdd('other-op', TEST_PASSWORD)
    fireEvent.submit(addForm())
    expect(calls(fetch, 'POST', '/api/accounts')).toHaveLength(1)
    await act(async () => answer(json({ result: 'ok', account: account({ active: false }) })))
  })

  it('비밀번호 재설정: 줄 안 양식(두 칸) → 확정하면 본문을 보내고 성공 띠 · 양식을 닫아 연 버튼으로 초점을 돌린다', async () => {
    const { fetch } = setup()
    const [han] = await rows()
    fireEvent.click(within(han).getByRole('button', { name: 'han 비밀번호 재설정' }))
    const form = screen.getByRole('form', { name: 'han 비밀번호 재설정 확인' })
    expect(form).toHaveTextContent('han 의 비밀번호를 바꿉니다. 그 계정의 열린 세션은 끊겨 다시 로그인해야 합니다(실시간 연결은 30초 안에 끊깁니다).')
    expect(field(form, '새 비밀번호')).toHaveFocus()
    for (const label of ['새 비밀번호', '새 비밀번호 확인']) {
      expect(field(form, label)).toHaveAttribute('type', 'password')
      expect(field(form, label)).toHaveAttribute('autocomplete', 'new-password')
      expect(field(form, label)).not.toHaveAttribute('name')
      expect(field(form, label)).not.toHaveAttribute('readonly')
    }
    type(field(form, '새 비밀번호'), TEST_PASSWORD)
    type(field(form, '새 비밀번호 확인'), TEST_PASSWORD)
    fireEvent.click(within(form).getByRole('button', { name: '비밀번호 재설정 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/password')).toEqual([{ username: 'han', password: TEST_PASSWORD }]))
    expect(await screen.findByRole('status')).toHaveTextContent('han 의 비밀번호를 바꿨습니다 · 그 계정의 열린 세션은 새 비밀번호로 다시 로그인해야 합니다.')
    expect(screen.queryByRole('form', { name: 'han 비밀번호 재설정 확인' })).toBeNull()
    await waitFor(() => expect(within(han).getByRole('button', { name: 'han 비밀번호 재설정' })).toHaveFocus())
    // 다시 열면 빈 칸이다
    fireEvent.click(within(han).getByRole('button', { name: 'han 비밀번호 재설정' }))
    expect(field(screen.getByRole('form', { name: 'han 비밀번호 재설정 확인' }), '새 비밀번호')).toHaveValue('')
  })

  it('비밀번호 재설정: 두 칸이 다르거나 짧으면 보내지 않고, 취소하면 칸을 비운다', async () => {
    const { fetch } = setup()
    const [han] = await rows()
    const form = fillReset('han', TEST_PASSWORD, TEST_PASSWORD_2)
    fireEvent.click(within(form).getByRole('button', { name: '비밀번호 재설정 확정' }))
    expect(field(form, '새 비밀번호 확인')).toHaveAccessibleDescription('비밀번호가 서로 다릅니다.')
    expect(field(form, '새 비밀번호 확인')).toHaveFocus()
    type(field(form, '새 비밀번호'), 'short')
    fireEvent.submit(form)
    expect(field(form, '새 비밀번호')).toHaveAccessibleDescription(expect.stringContaining('12자 이상이어야 합니다.'))
    expect(calls(fetch, 'POST', '/api/accounts/password')).toHaveLength(0)
    fireEvent.click(within(form).getByRole('button', { name: '취소' }))
    expect(screen.queryByRole('form', { name: 'han 비밀번호 재설정 확인' })).toBeNull()
    expect(within(han).getByRole('button', { name: 'han 비밀번호 재설정' })).toHaveFocus()
    // 다시 열면 칸이 비어 있다(닫을 때 입력 요소째 없어진다)
    fireEvent.click(within(han).getByRole('button', { name: 'han 비밀번호 재설정' }))
    const again = screen.getByRole('form', { name: 'han 비밀번호 재설정 확인' })
    expect(field(again, '새 비밀번호')).toHaveValue('')
    expect(field(again, '새 비밀번호')).not.toHaveAttribute('aria-invalid')
  })

  it('비밀번호 재설정 409(관리자 · 본인)는 서버 설명을 보이고 양식을 닫지 않는다', async () => {
    setup('admin', { reply: () => json({ detail: '관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다' }, 409) })
    await rows()
    const form = fillReset('han', TEST_PASSWORD)
    fireEvent.click(within(form).getByRole('button', { name: '비밀번호 재설정 확정' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('han · 비밀번호 재설정 실패 · 관리자 계정과 관리자 부여는 명령줄에서만 바꿉니다 (HTTP 409)')
    expect(screen.getByRole('form', { name: 'han 비밀번호 재설정 확인' })).toBeInTheDocument()
  })

  it('비밀번호 재설정을 Enter 로 보내 거부되면(409) 초점과 값이 그 칸에 남고, 보내는 동안 칸은 읽기 전용이다', async () => {
    let answer: (value: Response) => void = () => undefined
    setup('admin', { reply: () => new Promise<Response>((resolve) => { answer = resolve }) })
    await rows()
    const form = fillReset('han', TEST_PASSWORD)
    const again = field(form, '새 비밀번호 확인')
    again.focus()
    fireEvent.submit(form)
    await waitFor(() => expect(within(form).getByRole('button', { name: '비밀번호 재설정 확정' })).toHaveAttribute('aria-busy', 'true'))
    expect(again).not.toBeDisabled()
    expect(again).toHaveAttribute('readonly')
    await act(async () => answer(json({ detail: '본인 계정은 여기서 바꿀 수 없습니다' }, 409)))
    expect(await screen.findByRole('alert')).toHaveTextContent('han · 비밀번호 재설정 실패 · 본인 계정은 여기서 바꿀 수 없습니다 (HTTP 409)')
    expect(again).toHaveFocus()
    expect(again).not.toHaveAttribute('readonly')
    expect(again).toHaveValue(TEST_PASSWORD)
  })

  it('다른 관리자가 먼저 지워 404 로 행이 빠지면 초점을 표로 옮긴다(연 버튼 · 양식이 함께 없어진다)', async () => {
    let gone: () => void = () => undefined
    const view = setup('admin', { reply: () => { gone(); return json({ detail: '계정을 찾을 수 없습니다' }, 404) } })
    gone = () => view.setRows(ACCOUNTS.filter((a) => a.username !== 'han'))
    await rows()
    const confirm = within(fillReset('han', TEST_PASSWORD)).getByRole('button', { name: '비밀번호 재설정 확정' })
    confirm.focus()
    fireEvent.click(confirm)
    expect(await screen.findByRole('alert')).toHaveTextContent('han · 비밀번호 재설정 실패 · 계정을 찾을 수 없습니다 (HTTP 404)')
    await waitFor(() => expect(screen.queryByRole('rowheader', { name: /^han/ })).toBeNull())
    expect(screen.getByRole('region', { name: '계정 표' })).toHaveFocus()
  })

  it('삭제: 지울 수 있는 계정에만 단추가 있고, 줄 안 확인 → 확정하면 행이 빠지고 초점은 표로 간다', async () => {
    const accounts = [...ACCOUNTS, account({ username: 'unknown', deletable: null, last_login_at: null })]
    const { fetch } = setup('admin', { accounts })
    const all = await rows()
    // deletable 이 true 인 kim 만. false(han) · 모름(null) · 관리자 · 본인은 단추가 없다
    expect(all.flatMap((r) => within(r).queryAllByRole('button', { name: / 삭제$/ })).map((b) => b.getAttribute('aria-label'))).toEqual(['kim 삭제'])
    fireEvent.click(screen.getByRole('button', { name: 'kim 삭제' }))
    const form = screen.getByRole('form', { name: 'kim 삭제 확인' })
    expect(form).toHaveTextContent('kim 계정을 지웁니다. 되돌릴 수 없고, 판정 · 조치 · 로그인 기록이 있으면 서버가 거부합니다.')
    const confirm = within(form).getByRole('button', { name: '삭제 확정' })
    expect(confirm.className).toMatch(/danger/)
    fireEvent.click(confirm)
    await waitFor(() => expect(bodies(fetch, '/api/accounts/delete')).toEqual([{ username: 'kim' }]))
    expect(await screen.findByRole('status')).toHaveTextContent('kim 계정을 지웠습니다')
    await waitFor(() => expect(screen.queryByRole('rowheader', { name: /^kim/ })).toBeNull())
    expect(screen.getByRole('region', { name: '계정 표' })).toHaveFocus()
  })

  it('삭제 409(이력 있음)는 서버 설명을 그대로 보이고 행과 양식을 둔다', async () => {
    const detail = '판정 · 조치 · 로그인 기록이 있는 계정은 지울 수 없습니다. 비활성으로 막아 주세요'
    setup('admin', { reply: () => json({ detail }, 409) })
    await rows()
    fireEvent.click(screen.getByRole('button', { name: 'kim 삭제' }))
    fireEvent.click(within(screen.getByRole('form', { name: 'kim 삭제 확인' })).getByRole('button', { name: '삭제 확정' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(`kim · 삭제 실패 · ${detail} (HTTP 409)`)
    expect(screen.getByRole('form', { name: 'kim 삭제 확인' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'kim 삭제' })).toBeInTheDocument()
  })

  it('비밀번호는 요청 본문에만 싣고 DOM · 주소 · 쿼리 캐시 · 콘솔에 남기지 않는다', async () => {
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map((level) => vi.spyOn(console, level))
    const { fetch, client, container, router } = setup()
    await rows()
    const form = fillAdd('new-op', TEST_PASSWORD)
    // 제어하지 않는 입력이라 value 특성(마크업)에 적히지 않는다
    expect(container.innerHTML).not.toContain(TEST_PASSWORD)
    fireEvent.click(within(form).getByRole('button', { name: '계정 추가' }))
    await screen.findByRole('status')
    const reset = fillReset('han', TEST_PASSWORD_2)
    expect(container.innerHTML).not.toContain(TEST_PASSWORD_2)
    fireEvent.click(within(reset).getByRole('button', { name: '비밀번호 재설정 확정' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('han 의 비밀번호를 바꿨습니다'))
    for (const secret of [TEST_PASSWORD, TEST_PASSWORD_2]) {
      // 본문에 실린 요청은 그 쓰기 하나뿐이고 주소에는 없다
      const carrying = fetch.mock.calls.filter(([u, init]) => `${String(u)} ${String(init?.body ?? '')}`.includes(secret))
      expect(carrying.map(([u, init]) => `${init?.method} ${String(u)}`)).toEqual([secret === TEST_PASSWORD ? 'POST /api/accounts' : 'POST /api/accounts/password'])
      expect(container.innerHTML).not.toContain(secret)
      expect(container.textContent).not.toContain(secret)
      expect(JSON.stringify(client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]))).not.toContain(secret)
      expect(`${router.state.location.pathname}${router.state.location.search}${router.state.location.hash}`).not.toContain(secret)
      for (const spy of logs) expect(JSON.stringify(spy.mock.calls)).not.toContain(secret)
    }
    expect(client.getMutationCache().getAll()).toHaveLength(0)
    expect(field(form, '비밀번호')).toHaveValue('')
    for (const spy of logs) spy.mockRestore()
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

  it('악성 아이디 계정도 비밀번호 재설정 · 삭제 본문에 원문 그대로 보내고, 양식 · 띠는 글자로만 그린다', async () => {
    const accounts = [account({ username: MIXED, deletable: true, last_login_at: null }), account({ username: HOSTILE.rlo, role: 'viewer' })]
    const { fetch, container } = setup('admin', { accounts })
    const region = await screen.findByRole('region', { name: '계정 표' })
    const [mixed, rlo] = within(region).getAllByRole('row').slice(1)
    fireEvent.click(within(rlo).getByRole('button', { name: / 비밀번호 재설정$/ }))
    const form = within(region).getByRole('form')
    expect(form).toHaveAccessibleName('admin⟨U+202E⟩gnp.exe 비밀번호 재설정 확인')
    type(field(form, '새 비밀번호'), TEST_PASSWORD)
    type(field(form, '새 비밀번호 확인'), TEST_PASSWORD)
    fireEvent.click(within(form).getByRole('button', { name: '비밀번호 재설정 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/password')).toEqual([{ username: HOSTILE.rlo, password: TEST_PASSWORD }]))
    await screen.findByRole('status')
    expectInertDom(container)
    fireEvent.click(within(mixed).getByRole('button', { name: / 삭제$/ }))
    fireEvent.click(within(within(region).getByRole('form')).getByRole('button', { name: '삭제 확정' }))
    await waitFor(() => expect(bodies(fetch, '/api/accounts/delete')).toEqual([{ username: MIXED }]))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('계정을 지웠습니다'))
    expectInertDom(container)
  })

  it('악성 아이디는 추가 양식이 형식 검사로 막고 보내지 않는다', async () => {
    const { fetch, container } = setup()
    await rows()
    for (const username of [HOSTILE.img, HOSTILE.rlo, HOSTILE.zwsp, HOSTILE.crlf, MIXED.slice(0, 64)]) {
      fireEvent.click(within(fillAdd(username, TEST_PASSWORD)).getByRole('button', { name: '계정 추가' }))
      expect(field(addForm(), '아이디')).toHaveAttribute('aria-invalid', 'true')
    }
    expect(calls(fetch, 'POST', '/api/accounts')).toHaveLength(0)
    expectInertDom(container)
  })
})
