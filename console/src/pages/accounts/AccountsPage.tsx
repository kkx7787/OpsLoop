/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { Fragment, useEffect, useId, useRef, useState, type FormEvent, type ReactNode, type RefObject } from 'react'
import { Link } from 'react-router'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import {
  accountKeys, createAccount, deleteAccount, MAX_PASSWORD, MIN_PASSWORD, resetAccountPassword, setAccountActive, setAccountRole, useAccounts, USERNAME_PATTERN,
  type Account, type AccountChange, type AccountsResult, type AssignableRole,
} from '@/api/accounts'
import { describeError, isApiError } from '@/api/errors'
import { can, ROLE_LABEL } from '@/auth/roles'
import { useMe } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Select } from '@/components/atoms/Select'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner, type BannerTone } from '@/components/molecules/Banner'
import { FormField } from '@/components/molecules/FormField'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'

/** 줄 안 확인 양식이 확정할 변경. 여는 순간의 값을 잡아 둬서, 그사이 목록이 바뀌어도 본 문장과 다른 변경을 보내지 않는다 */
type Change = { kind: 'role'; role: AssignableRole } | { kind: 'active'; active: boolean } | { kind: 'password' } | { kind: 'delete' }
type Kind = Change['kind']
/** 값을 뒤집는 변경(역할 · 활성). 응답이 unchanged 일 수 있다 */
type Toggle = Extract<Change, { kind: 'role' | 'active' }>
interface Notice { tone: BannerTone; title: ReactNode; body?: ReactNode }
/** 칸마다 오류 문장. 보낼 때 검사하고, 고치면(입력하면) 그 칸의 오류를 지운다 */
type FieldErrors = Partial<Record<'username' | 'password' | 'confirm', string>>

const HEAD = ['아이디', '역할', '상태', '마지막 로그인', '변경 시각', '동작']
const cell = 'px-4 py-3 align-top'
const BUSY_REASON = '다른 계정 변경을 처리하는 중입니다'
const OWN_BUSY_REASON = '이 계정 변경을 처리하는 중입니다'
/** 추가 양식의 역할 선택(보이는 순서). 기본은 권한이 적은 조회자 */
const ADD_ROLES: AssignableRole[] = ['operator', 'viewer']
const DEFAULT_ROLE: AssignableRole = 'viewer'
/** 보내는 동안 입력칸은 끄지(disabled) 않고 읽기 전용으로 둔다. 끄면 Enter 를 누른 칸에서 초점이 빠져, 거부(409 · 422) 뒤 키보드 사용자가
 *  제자리를 잃는다(처리 중 버튼을 aria-disabled 로 두는 것과 같은 까닭). 모양만 꺼진 칸처럼 보인다 */
const READ_ONLY_FIELD = 'read-only:bg-canvas read-only:text-ink-muted'

/** 명령줄로만 하는 일(콘솔이 뚫려도 스스로 관리자가 되지 못하게). 비밀번호는 명령이 묻고 인자로 받지 않는다 */
const CLI: Array<[string, string]> = [
  ['관리자 계정 추가', 'python3 auth.py add <아이디> admin --by <내 이름>'],
  ['관리자 부여', 'python3 auth.py role <아이디> admin --by <내 이름>'],
  ['관리자 해제', 'python3 auth.py role <아이디> operator --by <내 이름>'],
  ['관리자 · 본인 비밀번호', 'python3 auth.py passwd <아이디> --by <내 이름>'],
  ['관리자 비활성', 'python3 auth.py disable <아이디> --by <내 이름>'],
  ['관리자 재활성', 'python3 auth.py enable <아이디> --by <내 이름>'],
  ['목록', 'python3 auth.py list'],
]

/** 행 버튼이 여는 변경. 역할은 관제사 ↔ 조회자, 활성은 비활성 ↔ 재활성으로 지금 값의 반대다 */
function nextChange(account: Account, kind: Kind): Change {
  if (kind === 'role') return { kind, role: account.role === 'operator' ? 'viewer' : 'operator' }
  if (kind === 'active') return { kind, active: !account.active }
  return { kind }
}

/** 할 수 있는 일을 줄이거나 지우는 변경(조회자로 · 비활성 · 삭제). 확정 버튼 색만 가른다: 그러면 danger, 아니면 primary */
function reduces(change: Change): boolean {
  if (change.kind === 'role') return change.role === 'viewer'
  if (change.kind === 'active') return !change.active
  return change.kind === 'delete'
}

function changeLabel(change: Change): string {
  if (change.kind === 'role') return change.role === 'viewer' ? '조회자로 낮추기' : '관제사로 바꾸기'
  if (change.kind === 'active') return change.active ? '재활성' : '비활성'
  return change.kind === 'password' ? '비밀번호 재설정' : '삭제'
}

/**
 * 확인 양식의 설명(아이디 뒤에 붙는 문장). 세션 끊김 · 감사 기록 안내는 이 양식 한 곳에만 둔다(표 아래 · 결과 띠에서 되풀이하지 않는다).
 * cut: 세션을 끊는 변경(역할 · 비활성 · 비밀번호). 실시간 연결이 끊기는 시간은 양식의 ⓘ 로 접는다
 */
function consequence(change: Change): { text: string; cut: boolean } {
  const cut = ' 그 계정의 열린 세션은 끊겨 다시 로그인해야 합니다.'
  switch (change.kind) {
    case 'role':
      return {
        cut: true,
        text: change.role === 'viewer'
          ? ` 의 역할을 ${ROLE_LABEL.viewer}로 낮춥니다. 판정 · 차단 요청을 더는 할 수 없습니다.${cut}`
          : ` 의 역할을 ${ROLE_LABEL.operator}로 바꿉니다. 판정 · 차단 요청을 할 수 있게 됩니다.${cut}`,
      }
    case 'active':
      return change.active
        ? { cut: false, text: ' 계정을 다시 활성합니다. 새로 로그인해야 쓸 수 있습니다.' }
        : { cut: true, text: ' 계정을 비활성합니다. 로그인할 수 없게 되며 열린 세션은 끊깁니다.' }
    case 'password':
      return { cut: true, text: ` 의 비밀번호를 바꿉니다.${cut}` }
    case 'delete':
      return { cut: false, text: ' 계정을 지웁니다. 되돌릴 수 없습니다.' }
  }
}

/** 성공 띠(역할 · 활성). 이미 그 값이었으면(unchanged) 그렇다고 알린다. 세션 끊김은 확인 양식에서 이미 읽었으므로 되풀이하지 않는다 */
function outcome(account: Account, change: Toggle, done: AccountChange): Notice {
  const name = <UntrustedText value={account.username} max={64} />
  const value = change.kind === 'role' ? ROLE_LABEL[change.role] : change.active ? '활성' : '비활성'
  if (done.result === 'unchanged') return { tone: 'info', title: <>{name} 은(는) 이미 {value} 상태입니다</> }
  if (change.kind === 'role') return { tone: 'success', title: <>{name} 의 역할을 {value}로 바꿨습니다</> }
  return { tone: 'success', title: change.active ? <>{name} 계정을 재활성했습니다</> : <>{name} 계정을 비활성했습니다</> }
}

/** 행 변경 하나를 보내고 성공 띠를 만든다. 비밀번호는 이 요청의 본문에만 싣는다 */
async function send(client: QueryClient, account: Account, change: Change, password: string): Promise<Notice> {
  const name = <UntrustedText value={account.username} max={64} />
  switch (change.kind) {
    case 'role': return outcome(account, change, await setAccountRole(client, account.username, change.role))
    case 'active': return outcome(account, change, await setAccountActive(client, account.username, change.active))
    case 'password':
      await resetAccountPassword(client, account.username, password)
      return { tone: 'success', title: <>{name} 의 비밀번호를 바꿨습니다</> }
    case 'delete':
      await deleteAccount(client, account.username)
      return { tone: 'success', title: <>{name} 계정을 지웠습니다</> }
  }
}

/** 새 아이디 검사. 서버와 같은 형식이다(다르면 서버가 422) */
function usernameError(username: string): FieldErrors {
  if (!username) return { username: '아이디를 입력해 주세요.' }
  return USERNAME_PATTERN.test(username) ? {} : { username: '영문 · 숫자 · . _ - 로 64자까지입니다.' }
}

/** 비밀번호 두 칸 검사. 길이는 글자(코드 포인트) 수로 서버와 같게 센다. 서버가 같은 길이로 다시 거부한다(422) */
function passwordErrors(password: string, confirm: string): FieldErrors {
  const length = [...password].length
  if (!length) return { password: '비밀번호를 입력해 주세요.' }
  if (length < MIN_PASSWORD) return { password: `${MIN_PASSWORD}자 이상이어야 합니다.` }
  if (length > MAX_PASSWORD) return { password: `${MAX_PASSWORD}자 이하여야 합니다.` }
  return password === confirm ? {} : { confirm: '비밀번호가 서로 다릅니다.' }
}

function clear(...inputs: Array<RefObject<HTMLInputElement | null>>) {
  for (const input of inputs) if (input.current) input.current.value = ''
}

/**
 * 계정(S-15 · #59 · #63). admin 이 관제사 · 조회자 계정을 추가하고, 행마다 역할 변경 · 비활성 · 재활성 · 비밀번호 재설정 ·
 * 삭제(이력 없는 계정만)를 줄 안 확인 양식으로 확정한다. 관리자 계정과 본인 행은 버튼 대신 까닭을 보인다(서버 locked).
 * 관리자 계정 추가 · 관리자 부여 · 관리자와 본인 비밀번호는 아래 명령줄 안내를 따른다.
 * 서버(DB 함수)가 같은 규칙으로 다시 거부하므로(409) 화면의 잠금은 보안 경계가 아니다. 목록은 30초마다, 변경 뒤에는 바로 다시 조회한다.
 */
export function AccountsPage() {
  const me = useMe(), client = useQueryClient()
  const allowed = can(me.data?.role, 'account.manage')
  const query = useAccounts(allowed)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const pending = useRef(false)
  const table = useRef<HTMLDivElement>(null), addButton = useRef<HTMLButtonElement>(null)
  const addFormId = useId()
  const anyBusy = busy !== null || adding
  // 추가 양식을 닫으면 연 버튼으로 초점을 돌린다(AlertsPage 채널 추가와 같다)
  const addWasOpen = useRef(false)
  useEffect(() => {
    if (!addOpen && addWasOpen.current) addButton.current?.focus()
    addWasOpen.current = addOpen
  }, [addOpen])

  /** 보내기 하나. 처리 중이면 무시한다(두 번 누름 · 다른 행 · 추가 양식). 성공하면 true 를 돌려 양식을 닫거나 비우게 한다 */
  async function perform(username: string, label: string, row: boolean, run: () => Promise<Notice>): Promise<boolean> {
    if (pending.current) return false
    pending.current = true; setNotice(null)
    if (row) setBusy(username); else setAdding(true)
    try {
      setNotice(await run())
      return true
    } catch (e) {
      // 4xx 는 서버가 거부한 것이다(409 이미 있는 아이디 · 이력 있는 계정 · 관리자 계정 · 본인은 서버 detail 을 그대로 보인다).
      // 시간 초과 · 연결 끊김 · 5xx 는 DB 에 이미 적용됐을 수 있어 '실패' 로 단정하지 않고 다시 받은 목록을 보게 한다
      const refused = isApiError(e) && e.kind === 'http' && e.status < 500
      setNotice({
        tone: 'danger',
        title: <><UntrustedText value={username} max={64} /> · {label} {refused ? '실패' : '결과 확인 필요'}</>,
        body: refused ? describeError(e) : `${describeError(e)} · 적용됐을 수 있으니 다시 받은 목록에서 상태를 확인해 주세요.`,
      })
      return false
    } finally { pending.current = false; setBusy(null); setAdding(false) }
  }

  async function submit(account: Account, change: Change, password = ''): Promise<boolean> {
    const done = await perform(account.username, changeLabel(change), true, () => send(client, account, change, password))
    // 다시 받은 목록에서 행이 빠지면(지움 · 다른 관리자가 먼저 지워 404) 연 버튼과 양식이 함께 없어진다. 초점을 표로 옮긴다
    // (목록을 못 받아 행이 남으면 성공은 행이 연 버튼으로 돌리고, 실패는 양식에 둔다). 쓰기가 끝나면 목록을 다시 받은 뒤다(api/accounts change)
    const rows = client.getQueryData<AccountsResult>(accountKeys.all)?.accounts
    if (rows && !rows.some((a) => a.username === account.username)) table.current?.focus()
    return done
  }

  function add(username: string, role: AssignableRole, password: string): Promise<boolean> {
    return perform(username, '계정 추가', false, async () => {
      await createAccount(client, username, role, password)
      return { tone: 'success', title: <><UntrustedText value={username} max={64} /> 계정을 {ROLE_LABEL[role]}로 추가했습니다</> }
    })
  }

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="계정" description="관제사 · 조회자 계정을 추가 · 삭제하고 역할 · 활성 · 비밀번호를 바꿉니다." aside={allowed && <Button ref={addButton} variant="primary" aria-expanded={addOpen} aria-controls={addFormId} disabled={addOpen} disabledReason="아래 추가 양식이 열려 있습니다" onClick={() => setAddOpen(true)}>계정 추가</Button>} />
    {me.isPending ? <LoadingState /> : !allowed ? <ForbiddenState title="이 화면은 admin 만 볼 수 있습니다" requiredRoles="admin" currentRole={me.data?.role} /> : <>
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      {notice && <Banner tone={notice.tone} title={notice.title} action={<Button size="sm" onClick={() => setNotice(null)}>닫기</Button>}>{notice.body}</Banner>}
      {addOpen && <AddAccountForm id={addFormId} busy={adding} blocked={anyBusy && !adding} onSubmit={add} onClose={() => setAddOpen(false)} />}
      {query.isPending ? <LoadingState title="계정 목록을 불러오는 중입니다" /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : <Card padding="none" className="min-w-0">
        <InfoTip label="콘솔 계정" panelAs="div" panelClassName="mx-4 my-2" render={({ button, panel }) => <>
          <CardHeader title="콘솔 계정" aside={<><span>{`${query.data.accounts.length}개 · 시각 KST`}</span><Link to="/audit">감사 기록</Link>{button}</>} />
          {panel}
        </>}>
          <ul className="m-0 list-disc space-y-0.5 pl-4">
            <li>변경 시각은 역할 · 활성 · 비밀번호가 마지막으로 바뀐 때이며, 그보다 먼저 받은 세션은 쓸 수 없습니다.</li>
            <li>삭제는 판정 · 조치 · 로그인 기록이 없는 계정만 할 수 있습니다. 기록이 있으면 비활성해 이력의 주체를 남깁니다.</li>
          </ul>
        </InfoTip>
        <div ref={table} className="overflow-x-auto" role="region" aria-label="계정 표" tabIndex={0}><table className="responsive-table w-full text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{HEAD.map(t => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{query.data.accounts.map(a => <AccountRow key={a.username} account={a} busy={busy === a.username} anyBusy={anyBusy} onSubmit={submit} />)}</tbody>
        </table></div>
        {!query.data.accounts.length && <p className="p-4 text-sm text-ink-muted">계정이 없습니다.</p>}
      </Card>}
      <Card padding="none" className="min-w-0">
        <InfoTip label="명령줄에서 하는 일" panelAs="div" panelClassName="mx-4 my-2" render={({ button, panel }) => <>
          {/* 실행 위치(콘솔 노드 · 소유자 접속)는 본문 첫 줄에 한 번만 적는다 */}
          <CardHeader title="명령줄에서 하는 일" aside={button} />
          {panel}
        </>}>
          <ul className="m-0 list-disc space-y-0.5 pl-4">
            <li>콘솔이 뚫려도 스스로 관리자가 될 수 없게, 관리자 계정과 본인 계정은 화면에서 바꾸지 않습니다.</li>
            <li><code>--by</code> 에 적은 이름이 감사 기록의 행위자(<code>cli:이름</code>)로 남습니다.</li>
            <li>명령은 비밀번호를 두 번 묻고(12자 이상) 인자 · 감사 기록에 남기지 않습니다.</li>
            <li>마지막 활성 관리자는 낮추거나 비활성할 수 없습니다.</li>
          </ul>
        </InfoTip>
        <div className="flex flex-col gap-3 p-4 text-sm">
          <p className="m-0 leading-6">콘솔 노드의 API 컨테이너 안에서 소유자 접속(<code>DATABASE_URL</code>)으로 실행합니다.</p>
          <dl className="m-0 grid gap-x-4 gap-y-2 sm:grid-cols-[max-content_minmax(0,1fr)]">{CLI.map(([label, command]) => <Fragment key={label}>
            <dt className="text-ink-muted">{label}</dt><dd className="m-0 min-w-0"><code className="font-mono text-xs break-all">{command}</code></dd>
          </Fragment>)}</dl>
          <p className="m-0 text-xs leading-5 text-ink-muted">접속 방법은 운영 문서(infra/vmware/README.md)의 '콘솔 계정' 절을 따릅니다.</p>
        </div>
      </Card>
    </>}
  </div>
}

/**
 * 비밀번호 두 칸. 값은 React 상태 · 쿼리 캐시에 두지 않고 입력 요소에만 둔다(제어하지 않는 입력).
 * 제어 입력은 React 가 value 특성에도 값을 적어 마크업에 비밀번호가 드러난다. name 을 두지 않아 양식이 어떤 길로 제출돼도 주소에 실리지 않는다
 */
function PasswordFields({ password, confirm, errors, label, readOnly, onEdit }: {
  password: RefObject<HTMLInputElement | null>; confirm: RefObject<HTMLInputElement | null>; errors: FieldErrors; label: string; readOnly: boolean
  onEdit: (field: 'password' | 'confirm') => void
}) {
  const common = { type: 'password', autoComplete: 'new-password', spellCheck: false, readOnly, className: READ_ONLY_FIELD } as const
  return <>
    <FormField label={label} required hint={`${MIN_PASSWORD} ~ ${MAX_PASSWORD}자`} error={errors.password}>{(f) => <Input {...f} {...common} ref={password} onChange={() => onEdit('password')} />}</FormField>
    <FormField label={`${label} 확인`} required error={errors.confirm}>{(f) => <Input {...f} {...common} ref={confirm} onChange={() => onEdit('confirm')} />}</FormField>
  </>
}

/**
 * 계정 추가 양식(관제사 · 조회자). 머리의 '계정 추가' 로 열고 열리면 아이디 칸으로 초점을 옮긴다. 아이디는 서버와 같은 형식이고
 * 비밀번호는 두 번 받는다. 해시는 서버가 만든다. 성공하면 칸을 모두 비우고(이어서 추가할 수 있게 열어 둔다) 아이디 칸으로 초점을
 * 옮긴다. 실패하면 고쳐 다시 보낼 수 있게 값을 둔다. 닫으면 입력 요소째 없어져 값도 남지 않는다
 */
function AddAccountForm({ id, busy, blocked, onSubmit, onClose }: {
  id: string; busy: boolean; blocked: boolean; onSubmit: (username: string, role: AssignableRole, password: string) => Promise<boolean>; onClose: () => void
}) {
  const [username, setUsername] = useState('')
  const [role, setRole] = useState<AssignableRole>(DEFAULT_ROLE)
  const [errors, setErrors] = useState<FieldErrors>({})
  const nameInput = useRef<HTMLInputElement>(null), password = useRef<HTMLInputElement>(null), confirm = useRef<HTMLInputElement>(null)
  const forget = (field: keyof FieldErrors) => setErrors((e) => e[field] ? { ...e, [field]: undefined } : e)
  // 열 때와 성공 뒤에 아이디 칸으로 초점을 옮긴다(보내는 동안은 기다렸다가 끝난 뒤에). 실패하면 초점은 보낸 자리에 남는다
  const refocus = useRef(true)
  useEffect(() => {
    if (busy || !refocus.current) return
    refocus.current = false
    nameInput.current?.focus()
  }, [busy, username])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy || blocked) return
    const value = password.current?.value ?? ''
    const found = { ...usernameError(username), ...passwordErrors(value, confirm.current?.value ?? '') }
    setErrors(found)
    // 첫 오류 칸으로 초점을 옮긴다(오류 문장은 칸의 설명으로 읽힌다)
    const first = found.username ? nameInput : found.password ? password : found.confirm ? confirm : null
    if (first) { first.current?.focus(); return }
    if (!await onSubmit(username, role, value)) return
    refocus.current = true
    setUsername(''); setRole(DEFAULT_ROLE); clear(password, confirm)
  }

  return <Card padding="none" className="min-w-0">
    <CardHeader title="계정 추가" aside="관제사 · 조회자" />
    <form id={id} aria-label="계정 추가 양식" noValidate onSubmit={submit} className="grid gap-4 p-4 sm:grid-cols-2 xl:grid-cols-4">
      <FormField label="아이디" required hint="영문 · 숫자 · . _ - 64자까지" error={errors.username}>
        {(f) => <Input {...f} ref={nameInput} value={username} maxLength={64} autoComplete="off" autoCapitalize="none" spellCheck={false} readOnly={busy} className={READ_ONLY_FIELD} onChange={(e) => { setUsername(e.target.value); forget('username') }} />}
      </FormField>
      <FormField label="역할">
        {(f) => <Select {...f} value={role} disabled={busy} onChange={(e) => setRole(e.target.value as AssignableRole)}>{ADD_ROLES.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}</Select>}
      </FormField>
      <PasswordFields password={password} confirm={confirm} errors={errors} label="비밀번호" readOnly={busy} onEdit={forget} />
      <div className="flex flex-wrap items-center gap-2 sm:col-span-2 xl:col-span-4">
        <Button type="submit" variant="primary" loading={busy} disabled={blocked} disabledReason={BUSY_REASON}>계정 추가</Button>
        <Button variant="ghost" onClick={onClose} disabled={busy}>닫기</Button>
      </div>
    </form>
  </Card>
}

/** 확인 양식의 문장. 세션을 끊는 변경이면 세션 끊김 문장 바로 뒤에 ⓘ(실시간 연결이 끊기는 시간)를 두고 설명은 문단 아래에 펼친다 */
function Consequence({ account, change }: { account: Account; change: Change }) {
  const { text, cut } = consequence(change)
  const name = <span className="font-medium break-all"><UntrustedText value={account.username} max={64} /></span>
  if (!cut) return <p className="m-0 text-sm leading-6">{name}{text} 변경은 감사 기록에 남습니다.</p>
  return <InfoTip label="세션 끊김" render={({ button, panel }) => <>
    <p className="m-0 text-sm leading-6">{name}{text} {button} 변경은 감사 기록에 남습니다.</p>
    {panel}
  </>}>실시간 연결은 30초 안에 끊깁니다.</InfoTip>
}

function AccountRow({ account, busy, anyBusy, onSubmit }: { account: Account; busy: boolean; anyBusy: boolean; onSubmit: (account: Account, change: Change, password?: string) => Promise<boolean> }) {
  const [open, setOpen] = useState<Change | null>(null)
  const [errors, setErrors] = useState<FieldErrors>({})
  const openers = useRef<Partial<Record<Kind, HTMLButtonElement | null>>>({})
  const returnTo = useRef<Kind | null>(null)
  const password = useRef<HTMLInputElement>(null), again = useRef<HTMLInputElement>(null)
  const formId = useId()
  // 양식을 닫으면(확정 · 취소) 연 버튼으로 초점을 돌린다
  useEffect(() => {
    if (open || !returnTo.current) return
    openers.current[returnTo.current]?.focus()
    returnTo.current = null
  }, [open])
  // 관리자 계정이면 서버가 locked 를 주지 않아도 잠근다(관리자 변경은 명령줄 전용)
  const lock = account.locked ?? (account.role === 'admin' ? 'admin' : null)
  const shown = lock ? null : open
  const name = revealHidden(account.username)
  // 비밀번호 양식을 열면 첫 칸으로 초점을 옮긴다. 닫으면 칸이 사라져 입력값도 함께 없어진다
  const typing = shown?.kind === 'password'
  useEffect(() => { if (typing) password.current?.focus() }, [typing])
  // 삭제는 이력이 없다고 서버가 알린 계정에만 둔다(null = 서버가 모름)
  const kinds: Kind[] = account.deletable === true ? ['role', 'active', 'password', 'delete'] : ['role', 'active', 'password']

  function toggle(kind: Kind) { setErrors({}); setOpen(open?.kind === kind ? null : nextChange(account, kind)) }
  function close() { returnTo.current = open?.kind ?? null; setOpen(null); setErrors({}) }
  async function confirm(event: FormEvent) {
    event.preventDefault()
    if (!shown) return
    let secret = ''
    if (shown.kind === 'password') {
      secret = password.current?.value ?? ''
      const found = passwordErrors(secret, again.current?.value ?? '')
      setErrors(found)
      if (found.password || found.confirm) { (found.password ? password : again).current?.focus(); return }
    }
    if (await onSubmit(account, shown, secret)) close()
  }

  return <>
    <tr className={cn(!account.active && 'text-ink-muted', shown && 'border-b-0')}>
      <th scope="row" className={`${cell} font-normal`}>
        <div className="font-semibold break-words"><UntrustedText value={account.username} max={64} /></div>
        <div className="mt-1 text-xs whitespace-nowrap text-ink-muted">추가 <Time value={account.created_at} format="date" /></div>
      </th>
      <td data-label="역할" className={`${cell} whitespace-nowrap`}><span className="font-medium">{ROLE_LABEL[account.role] ?? account.role}</span> <span className="font-mono text-xs text-ink-muted">{account.role}</span></td>
      <td data-label="상태" className={cell}>{account.active ? <Badge tone="success">활성</Badge> : <>
        <Badge tone="neutral">비활성</Badge><div className="mt-1 text-xs whitespace-nowrap"><Time value={account.disabled_at} format="short" /></div>
      </>}</td>
      <td data-label="마지막 로그인" className={`${cell} whitespace-nowrap`}>{account.last_login_at ? <Time value={account.last_login_at} format="short" /> : <span className="text-ink-muted">기록 없음</span>}</td>
      <td data-label="변경 시각" className={`${cell} whitespace-nowrap`}><Time value={account.updated_at} format="short" /></td>
      <td data-label="동작" data-wide className={cell}>{lock ? <span className="text-xs text-ink-muted">{lock === 'self' ? '본인 계정' : '명령줄에서만 변경'}</span> : <div className="flex flex-wrap gap-1.5">
        {kinds.map(kind => {
          const label = changeLabel(nextChange(account, kind))
          return <Button key={kind} ref={el => { openers.current[kind] = el }} size="sm" aria-label={`${name} ${label}`} aria-expanded={open?.kind === kind} aria-controls={formId} disabled={anyBusy} disabledReason={busy ? OWN_BUSY_REASON : BUSY_REASON} onClick={() => toggle(kind)}>{label}</Button>
        })}
      </div>}</td>
    </tr>
    {shown && <tr>
      {/* 폭 0 · 최소 100% 로 감싸 긴 설명이 표 열 너비를 바꾸지 않게 한다(양식을 열어도 위 행이 다시 배치되지 않는다) */}
      <td colSpan={HEAD.length} className="px-4 pb-3"><div className="w-0 min-w-full">
        <form id={formId} aria-label={`${name} ${changeLabel(shown)} 확인`} noValidate onSubmit={confirm} className="flex flex-col gap-3 rounded-panel border border-line bg-canvas p-3">
          <Consequence account={account} change={shown} />
          {typing && <div className="grid gap-3 sm:max-w-xl sm:grid-cols-2">
            <PasswordFields password={password} confirm={again} errors={errors} label="새 비밀번호" readOnly={busy} onEdit={(field) => setErrors((e) => e[field] ? { ...e, [field]: undefined } : e)} />
          </div>}
          <div className="flex flex-wrap gap-2">
            {/* 다른 행을 처리하는 중이면 이 행의 확정도 까닭을 보이며 막는다(누름이 말없이 버려지지 않게) */}
            <Button type="submit" variant={reduces(shown) ? 'danger' : 'primary'} loading={busy} disabled={anyBusy && !busy} disabledReason={BUSY_REASON}>{changeLabel(shown)} 확정</Button>
            <Button variant="ghost" onClick={close} disabled={busy}>취소</Button>
          </div>
        </form>
      </div></td>
    </tr>}
  </>
}
