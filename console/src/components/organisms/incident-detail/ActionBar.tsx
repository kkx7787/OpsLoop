import { useId, useState, type FormEvent } from 'react'
import { useActionMutation, type ActionInput, type IncidentDetail } from '@/api/incidents'
import { describeError } from '@/api/errors'
import { useMe, usePermission } from '@/auth/useMe'
import { cn } from '@/lib/cn'
import { ACTION_LABEL, actionLabel, INCIDENT_STATUS_LABEL, type IncidentAction } from '@/lib/domain'
import { Button } from '../../atoms/Button'
import { Input } from '../../atoms/Input'
import { Select } from '../../atoms/Select'
import { Banner } from '../../molecules/Banner'
import { FormField } from '../../molecules/FormField'
import { BLOCK_HOURS, DEFAULT_BLOCK_HOURS, hoursLabel, isActiveBlock } from './format'
import { ackPermission } from './permissions'

export interface ActionBarProps {
  detail: IncidentDetail
  className?: string
}

/** 확인 단계가 있는 조치. 되돌리기 어려운 것(차단 · 억제)과 되돌리는 것(해제)은 두 번째 단추로 확정한다 */
type Confirmable = Exclude<IncidentAction, 'acknowledge'>

/**
 * 조치 바(⑤): 확인 · 차단 · 차단 해제 · 규칙 억제. 권한 밖의 조치는 숨긴다.
 *  확인      operator 이상 · 신규 상태에서만
 *  차단      operator 이상 · 출발지가 있어야 · 만료 시간과 메모를 받고 확정
 *  차단 해제 admin · 살아 있는 차단이 있어야 · 확정
 *  규칙 억제 admin · 확정
 * 결과는 useActionMutation 이 상세 캐시에 바로 반영한다(이력 추가 · 상태 전이).
 */
export function ActionBar({ detail, className }: ActionBarProps) {
  const mutation = useActionMutation(detail.incident_key)
  const me = useMe()
  const ack = ackPermission(me.data?.role)
  const block = usePermission('block.request')
  const release = usePermission('block.release')
  const suppress = usePermission('rule.suppress')

  const [pending, setPending] = useState<Confirmable | null>(null)
  const [hours, setHours] = useState(String(DEFAULT_BLOCK_HOURS))
  const [note, setNote] = useState('')
  const panelId = useId()

  const acked = detail.status !== 'open'
  const activeBlock = isActiveBlock(detail.actor.blocked)
  const busy = mutation.isPending
  const canConfirm = pending === 'block_ip' ? block.allowed : pending === 'unblock_ip' ? release.allowed : suppress.allowed

  function open(action: Confirmable) {
    mutation.reset()
    setPending((current) => (current === action ? null : action))
  }

  function close() {
    setPending(null)
    setNote('')
    setHours(String(DEFAULT_BLOCK_HOURS))
  }

  function send(input: ActionInput) {
    mutation.mutate(input, { onSuccess: close })
  }

  function acknowledge() {
    mutation.reset()
    send({ action: 'acknowledge' })
  }

  function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!pending || !canConfirm) return
    const trimmed = note.trim()
    const input: ActionInput = { action: pending }
    if (trimmed) input.note = trimmed
    if (pending === 'block_ip') input.expires_hours = Number(hours)
    send(input)
  }

  const blockReason = !detail.actor_ip ? '출발지가 없는 사건은 차단할 수 없습니다' : block.reason
  const releaseReason = !release.allowed
    ? release.reason
    : !detail.actor.blocked
      ? '차단한 적이 없는 출발지입니다'
      : !activeBlock
        ? '이미 풀렸거나 만료된 차단입니다'
        : ''

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      <div className="flex flex-wrap gap-2" role="group" aria-label="조치">
        {ack.allowed && <Button
          disabled={!ack.allowed || acked}
          disabledReason={!ack.allowed ? ack.reason : `이미 ${INCIDENT_STATUS_LABEL[detail.status] ?? detail.status} 상태라 확인할 것이 없습니다`}
          loading={busy && mutation.variables?.action === 'acknowledge'}
          onClick={acknowledge}
        >
          {ACTION_LABEL.acknowledge}
        </Button>}
        {block.allowed && <Button
          variant="secondary"
          className="text-danger"
          disabled={!block.allowed || !detail.actor_ip}
          disabledReason={blockReason}
          aria-expanded={pending === 'block_ip'}
          aria-controls={panelId}
          onClick={() => open('block_ip')}
        >
          {ACTION_LABEL.block_ip}
        </Button>}
        {release.allowed && <Button
          disabled={releaseReason !== ''}
          disabledReason={releaseReason}
          aria-expanded={pending === 'unblock_ip'}
          aria-controls={panelId}
          onClick={() => open('unblock_ip')}
        >
          {ACTION_LABEL.unblock_ip}
        </Button>}
        {suppress.allowed && <Button
          variant="secondary"
          className="text-danger"
          disabled={!suppress.allowed}
          disabledReason={suppress.reason}
          aria-expanded={pending === 'suppress_rule'}
          aria-controls={panelId}
          onClick={() => open('suppress_rule')}
        >
          {ACTION_LABEL.suppress_rule}
        </Button>}
        {me.data?.role === 'viewer' && <p className="m-0 text-xs text-ink-muted">조회 전용 계정입니다. 조치는 operator · admin이 수행합니다.</p>}
      </div>

      {pending && canConfirm && (
        <form
          id={panelId}
          onSubmit={confirm}
          aria-label={`${ACTION_LABEL[pending]} 확인`}
          className="flex flex-col gap-3 rounded-panel bg-canvas p-3"
        >
          <p className="m-0 text-sm">
            {pending === 'block_ip' && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 를 <strong>{hoursLabel(Number(hours))}</strong> 동안 차단합니다. 만료되면 저절로 풀립니다.
                {activeBlock && ' 이미 살아 있는 차단이 있으면 만료를 앞당기지 않습니다.'}
              </>
            )}
            {pending === 'unblock_ip' && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 의 차단을 지금 풉니다. 되돌리려면 다시 차단해야 합니다.
              </>
            )}
            {pending === 'suppress_rule' && (
              <>
                규칙 <span className="font-mono font-medium">{detail.rule_id} {detail.rule_version}</span> 을 억제하고 이 사건을 억제 상태로 닫습니다. 기준을 바꾸는 행위라 감사 기록에 남습니다.
              </>
            )}
          </p>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,160px)_minmax(0,1fr)]">
            {pending === 'block_ip' && (
              <FormField label="만료">
                {(f) => (
                  <Select {...f} value={hours} onChange={(e) => setHours(e.target.value)}>
                    {BLOCK_HOURS.map((h) => (
                      <option key={h} value={h}>
                        {hoursLabel(h)}
                      </option>
                    ))}
                  </Select>
                )}
              </FormField>
            )}
            <FormField label="메모" hint="선택. 이력에 남습니다" className={pending !== 'block_ip' ? 'sm:col-span-2' : undefined}>
              {(f) => <Input {...f} value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} placeholder="예: 세션 3개에서 명령 실행 확인" />}
            </FormField>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant={pending === 'unblock_ip' ? 'primary' : 'danger'} loading={busy}>
              {ACTION_LABEL[pending]} 확정
            </Button>
            <Button variant="ghost" onClick={close} disabled={busy}>
              취소
            </Button>
          </div>
        </form>
      )}

      {mutation.isSuccess && (
        <Banner tone="success" title={`${actionLabel(mutation.data.action)} 조치를 기록했습니다`}>
          {mutation.data.operator} · 상태 {INCIDENT_STATUS_LABEL[detail.status] ?? detail.status}
        </Banner>
      )}
      {mutation.isError && (
        <Banner tone="danger" title="조치를 기록하지 못했습니다">
          {describeError(mutation.error)}
        </Banner>
      )}
    </div>
  )
}
