/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { Fragment, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { setAccountActive, setAccountRole, useAccounts, type Account, type AccountChange, type AssignableRole } from '@/api/accounts'
import { describeError, isApiError } from '@/api/errors'
import { can, ROLE_LABEL } from '@/auth/roles'
import { useMe } from '@/auth/useMe'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner, type BannerTone } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'

/** 줄 안 확인 양식이 확정할 변경. 여는 순간의 값을 잡아 둬서, 그사이 목록이 바뀌어도 본 문장과 다른 변경을 보내지 않는다 */
type Change = { kind: 'role'; role: AssignableRole } | { kind: 'active'; active: boolean }
type Kind = Change['kind']
interface Notice { tone: BannerTone; title: ReactNode; body?: ReactNode }

const HEAD = ['아이디', '역할', '상태', '마지막 로그인', '변경 시각', '동작']
const cell = 'px-4 py-3 align-top'
const BUSY_REASON = '다른 계정 변경을 처리하는 중입니다'
const OWN_BUSY_REASON = '이 계정 변경을 처리하는 중입니다'

/** 명령줄로만 하는 일(콘솔이 뚫려도 스스로 관리자가 되지 못하게). 비밀번호는 명령이 묻고 인자로 받지 않는다 */
const CLI: Array<[string, string]> = [
  ['계정 추가', 'python3 auth.py add <아이디> <역할> --by <내 이름>'],
  ['관리자 부여', 'python3 auth.py role <아이디> admin --by <내 이름>'],
  ['관리자 해제', 'python3 auth.py role <아이디> operator --by <내 이름>'],
  ['비밀번호 재설정', 'python3 auth.py passwd <아이디> --by <내 이름>'],
  ['관리자 비활성', 'python3 auth.py disable <아이디> --by <내 이름>'],
  ['관리자 재활성', 'python3 auth.py enable <아이디> --by <내 이름>'],
  ['목록', 'python3 auth.py list'],
]

/** 지금 값의 반대. 역할은 관제사 ↔ 조회자, 활성은 비활성 ↔ 재활성 */
function nextChange(account: Account, kind: Kind): Change {
  return kind === 'role' ? { kind, role: account.role === 'operator' ? 'viewer' : 'operator' } : { kind, active: !account.active }
}

/** 할 수 있는 일을 늘리는 변경(관제사로 · 재활성). 확정 버튼 색만 가른다: 늘리면 primary, 줄이면 danger */
function raises(change: Change): boolean {
  return change.kind === 'role' ? change.role === 'operator' : change.active
}

function changeLabel(change: Change): string {
  if (change.kind === 'role') return change.role === 'viewer' ? '조회자로 낮추기' : '관제사로 바꾸기'
  return change.active ? '재활성' : '비활성'
}

/** 확인 양식의 설명. 세션을 끊는 변경(역할 · 비활성)은 다시 로그인해야 한다는 것과 실시간 연결이 끊기는 시간을 밝힌다 */
function consequence(change: Change): string {
  const cut = ' 그 계정의 열린 세션은 끊겨 다시 로그인해야 합니다(실시간 연결은 30초 안에 끊깁니다).'
  if (change.kind === 'role') {
    return change.role === 'viewer'
      ? ` 의 역할을 ${ROLE_LABEL.viewer}로 낮춥니다. 판정 · 차단 요청을 더는 할 수 없습니다.${cut}`
      : ` 의 역할을 ${ROLE_LABEL.operator}로 바꿉니다. 판정 · 차단 요청을 할 수 있게 됩니다.${cut}`
  }
  return change.active
    ? ' 계정을 다시 활성합니다. 비활성 전에 받은 세션은 되살아나지 않아 새로 로그인해야 합니다.'
    : ` 계정을 비활성합니다. 로그인할 수 없게 되며, 지우지 않으므로 판정 · 조치 이력의 주체는 그대로 남습니다.${cut}`
}

/** 성공 띠. 이미 그 값이었으면(unchanged) 바뀐 것도 감사 행도 없다고 알린다 */
function outcome(account: Account, change: Change, done: AccountChange): Notice {
  const name = <UntrustedText value={account.username} max={64} />
  const value = change.kind === 'role' ? ROLE_LABEL[change.role] : change.active ? '활성' : '비활성'
  if (done.result === 'unchanged') return { tone: 'info', title: <>{name} 은(는) 이미 {value} 상태입니다</>, body: '바뀐 것이 없어 감사 기록도 남지 않았습니다.' }
  if (change.kind === 'role') return { tone: 'success', title: <>{name} 의 역할을 {value}로 바꿨습니다</>, body: '그 계정의 열린 세션은 다시 로그인해야 합니다.' }
  return change.active
    ? { tone: 'success', title: <>{name} 계정을 재활성했습니다</>, body: '새로 로그인하면 쓸 수 있습니다.' }
    : { tone: 'success', title: <>{name} 계정을 비활성했습니다</>, body: '열린 세션은 끊깁니다(실시간 연결은 30초 안).' }
}

/**
 * 계정(S-15 · #59). admin 만 관제사 ↔ 조회자 역할 변경과 비활성 · 재활성을 한다. 각 행에서 줄 안 확인 양식을 펼쳐 확정한다.
 * 관리자 계정과 본인 행은 버튼 대신 까닭을 보인다(서버 locked). 관리자 부여 · 계정 추가 · 비밀번호는 아래 명령줄 안내를 따른다.
 * 서버(DB 함수)가 같은 규칙으로 다시 거부하므로(409) 화면의 잠금은 보안 경계가 아니다. 목록은 30초마다, 변경 뒤에는 바로 다시 조회한다.
 */
export function AccountsPage() {
  const me = useMe(), client = useQueryClient()
  const allowed = can(me.data?.role, 'account.manage')
  const query = useAccounts(allowed)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const pending = useRef(false)

  /** 확정. 처리 중이면 무시한다(두 번 누름 · 다른 행). 성공하면 true 를 돌려 줄 안 양식을 닫게 한다 */
  async function submit(account: Account, change: Change): Promise<boolean> {
    if (pending.current) return false
    pending.current = true; setBusy(account.username); setNotice(null)
    try {
      const done = change.kind === 'role' ? await setAccountRole(client, account.username, change.role) : await setAccountActive(client, account.username, change.active)
      setNotice(outcome(account, change, done))
      return true
    } catch (e) {
      // 4xx 는 서버가 거부한 것이다(409 관리자 계정 · 본인은 서버 detail 을 그대로 보인다).
      // 시간 초과 · 연결 끊김 · 5xx 는 DB 에 이미 적용됐을 수 있어 '실패' 로 단정하지 않고 다시 받은 목록을 보게 한다
      const refused = isApiError(e) && e.kind === 'http' && e.status < 500
      setNotice({
        tone: 'danger',
        title: <><UntrustedText value={account.username} max={64} /> · {changeLabel(change)} {refused ? '실패' : '결과 확인 필요'}</>,
        body: refused ? describeError(e) : `${describeError(e)} · 적용됐을 수 있으니 다시 받은 목록에서 상태를 확인해 주세요.`,
      })
      return false
    } finally { pending.current = false; setBusy(null) }
  }

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="계정" description="관제사 · 조회자의 역할과 활성 상태를 바꿉니다. 관리자 계정 · 계정 추가 · 비밀번호는 명령줄에서 합니다." />
    {me.isPending ? <LoadingState /> : !allowed ? <ForbiddenState title="이 화면은 admin 만 볼 수 있습니다" requiredRoles="admin" currentRole={me.data?.role} /> : <>
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
      {notice && <Banner tone={notice.tone} title={notice.title} action={<Button size="sm" onClick={() => setNotice(null)}>닫기</Button>}>{notice.body}</Banner>}
      {query.isPending ? <LoadingState title="계정 목록을 불러오는 중입니다" /> : !query.data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : <Card padding="none" className="min-w-0">
        <CardHeader title="콘솔 계정" aside={`${query.data.accounts.length}개 · 시각 KST`} />
        <div className="overflow-x-auto" role="region" aria-label="계정 표" tabIndex={0}><table className="responsive-table w-full text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{HEAD.map(t => <th key={t} scope="col" className={`${cell} whitespace-nowrap`}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{query.data.accounts.map(a => <AccountRow key={a.username} account={a} busy={busy === a.username} anyBusy={busy !== null} onSubmit={submit} />)}</tbody>
        </table></div>
        {!query.data.accounts.length && <p className="p-4 text-sm text-ink-muted">계정이 없습니다.</p>}
        <p className="m-0 border-t border-line px-4 py-3 text-xs leading-5 text-ink-muted">역할 변경 · 비활성은 그 계정의 열린 세션을 끊습니다. 다음 요청부터 로그인 화면으로 가고 실시간 연결은 30초 안에 끊깁니다. 변경 시각은 역할 · 활성 · 비밀번호가 마지막으로 바뀐 때이며 그보다 먼저 받은 세션은 쓸 수 없습니다. 계정은 지우지 않고(판정 · 조치 이력의 주체가 남도록) 변경은 <Link to="/audit">감사 기록</Link>에 대상 아이디로 남습니다. 30초마다 재조회</p>
      </Card>}
      <Card padding="none" className="min-w-0">
        <CardHeader title="명령줄에서 하는 일" aside="콘솔 노드 · 소유자 접속" />
        <div className="flex flex-col gap-3 p-4 text-sm">
          <p className="m-0 leading-6">계정 추가 · 관리자 부여와 해제 · 관리자 계정의 비활성과 재활성 · 비밀번호는 화면에서 하지 않습니다. 콘솔이 뚫려도 스스로 관리자가 될 수 없게 하려는 경계입니다. 콘솔 노드의 API 컨테이너 안에서 소유자 접속(<code>DATABASE_URL</code>)으로 돌리며, <code>--by</code> 에 적은 이름이 감사 기록의 행위자(<code>cli:이름</code>)로 남습니다.</p>
          <dl className="m-0 grid gap-x-4 gap-y-2 sm:grid-cols-[max-content_minmax(0,1fr)]">{CLI.map(([label, command]) => <Fragment key={label}>
            <dt className="text-ink-muted">{label}</dt><dd className="m-0 min-w-0"><code className="font-mono text-xs break-all">{command}</code></dd>
          </Fragment>)}</dl>
          <p className="m-0 text-xs leading-5 text-ink-muted">비밀번호는 명령이 두 번 묻고(12자 이상) 인자 · 화면 · 감사 기록에 남지 않습니다. 마지막 활성 관리자는 낮추거나 비활성할 수 없습니다. 접속 방법은 운영 문서(infra/vmware/README.md)의 '콘솔 계정' 절을 따릅니다.</p>
        </div>
      </Card>
    </>}
  </div>
}

function AccountRow({ account, busy, anyBusy, onSubmit }: { account: Account; busy: boolean; anyBusy: boolean; onSubmit: (account: Account, change: Change) => Promise<boolean> }) {
  const [open, setOpen] = useState<Change | null>(null)
  const openers = useRef<Partial<Record<Kind, HTMLButtonElement | null>>>({})
  const returnTo = useRef<Kind | null>(null)
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

  function close() { returnTo.current = open?.kind ?? null; setOpen(null) }
  async function confirm(event: FormEvent) {
    event.preventDefault()
    if (shown && await onSubmit(account, shown)) close()
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
        {(['role', 'active'] as const).map(kind => {
          const label = changeLabel(nextChange(account, kind))
          return <Button key={kind} ref={el => { openers.current[kind] = el }} size="sm" aria-label={`${name} ${label}`} aria-expanded={open?.kind === kind} aria-controls={formId} disabled={anyBusy} disabledReason={busy ? OWN_BUSY_REASON : BUSY_REASON} onClick={() => setOpen(open?.kind === kind ? null : nextChange(account, kind))}>{label}</Button>
        })}
      </div>}</td>
    </tr>
    {shown && <tr>
      {/* 폭 0 · 최소 100% 로 감싸 긴 설명이 표 열 너비를 바꾸지 않게 한다(양식을 열어도 위 행이 다시 배치되지 않는다) */}
      <td colSpan={HEAD.length} className="px-4 pb-3"><div className="w-0 min-w-full">
        <form id={formId} aria-label={`${name} ${changeLabel(shown)} 확인`} onSubmit={confirm} className="flex flex-col gap-3 rounded-panel border border-line bg-canvas p-3">
          <p className="m-0 text-sm leading-6"><span className="font-medium break-all"><UntrustedText value={account.username} max={64} /></span>{consequence(shown)} 변경은 감사 기록에 남습니다.</p>
          <div className="flex flex-wrap gap-2">
            {/* 다른 행을 처리하는 중이면 이 행의 확정도 까닭을 보이며 막는다(누름이 말없이 버려지지 않게) */}
            <Button type="submit" variant={raises(shown) ? 'primary' : 'danger'} loading={busy} disabled={anyBusy && !busy} disabledReason={BUSY_REASON}>{changeLabel(shown)} 확정</Button>
            <Button variant="ghost" onClick={close} disabled={busy}>취소</Button>
          </div>
        </form>
      </div></td>
    </tr>}
  </>
}
