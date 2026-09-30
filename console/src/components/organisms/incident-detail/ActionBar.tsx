import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { useActionMutation, type ActionCreated, type ActionInput, type BlockPointsBasis, type IncidentDetail } from '@/api/incidents'
import { describeError } from '@/api/errors'
import { useMe, usePermission } from '@/auth/useMe'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { ACTION_LABEL, actionLabel, INCIDENT_STATUS_LABEL, type IncidentAction } from '@/lib/domain'
import { Button } from '../../atoms/Button'
import { Input } from '../../atoms/Input'
import { Select } from '../../atoms/Select'
import { UntrustedText } from '../../atoms/UntrustedText'
import { Banner } from '../../molecules/Banner'
import { FormField } from '../../molecules/FormField'
import { InfoTip } from '../../molecules/InfoTip'
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
 * 첫 사건(같은 페이로드 흡수, 규칙 v3)이면 차단 확인에 '흡수된 출발지 n곳도 함께 차단', 해제 확인에 '흡수 차단 n곳도
 * 함께 해제'를 둔다(include_absorbed, 기본 끔). 흡수된 인시던트는 지워져 상세가 없으므로 첫 사건에서만 걸고 푼다.
 * 함께 차단하면 만료 전까지 새로 흡수되는 출발지도 서버가 같은 만료로 올린다(후속 차단). 흡수는 판정 · 차단 뒤에도
 * 붙으므로, 흡수 기록이 아직 없어도 흡수를 쓰는 규칙(absorbs)이면 선택을 보인다. 사람이 푼 곳 · 차단 금지 대역은 넣지 않는다.
 * 차단은 요청이다. 데이터 노드 집행기가 요청 지점(AWS 관문 · web-01 앞 내부 방화벽)에 넘기고, 실제 적용 결과는 지점별로 따로 본다(이슈 #47 · #51).
 * 차단 확인에는 '적용 지점' 묶음을 둔다(이슈 #77, BlockPointsField). 내부 방화벽은 늘 막고 관문은 확인란 하나로 더한다. 기본값은 서버
 * block_points.default(규칙만으로 정함)이고 흡수 함께 차단 · 후속 차단도 같은 지점이다. 이전 서버(block_points 없음)는 묶음을 두지 않고
 * 지점을 보내지 않는다(서버가 두 지점으로 본다).
 * 이 출발지가 차단 금지 대역(actor.exempt)이면 차단 단추를 흐리고 까닭을 보인다. 서버도 400 과 같은 까닭으로 거부한다.
 * 결과는 useActionMutation 이 상세 캐시에 바로 반영한다(이력 추가 · 상태 전이).
 * 확인 양식은 무엇을 하는지 한 문장과 안전 경고(집행 제외 · 대량 해제 알림 · 넣지 않을 곳)만 본문에 두고,
 * 처리 과정 · 예외 · 사용 지침은 문장 끝 도움말(ⓘ)에 둔다.
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
  const [withAbsorbed, setWithAbsorbed] = useState(false)
  // 관문에서도 막기. null 이면 고르지 않은 것이라 기본값(살아 있는 요청 · 서버 기본값)을 따른다
  const [gateway, setGateway] = useState<boolean | null>(null)
  const panelId = useId()

  const acked = detail.status !== 'open'
  const activeBlock = isActiveBlock(detail.actor.blocked)
  // 만료 없는 옛 차단이 살아 있다(운영 13건 꼴). 살아 있는 차단의 만료는 앞당기지 않으므로 다시 걸어도 만료가 그대로 없고
  // 집행기는 만료 없는 행을 어느 지점에도 넘기지 않는다(집행 제외). 확인 창이 '몇 시간 동안 차단' 이라 하지 않는다
  const legacyBlock = activeBlock && !detail.actor.blocked?.expires_at
  // 함께 차단할 흡수 출발지(이 출발지 제외) · 함께 풀 흡수 차단. 첫 사건이 아니거나 이전 서버면 0
  const absorbedSources = detail.absorbed?.sources ?? 0
  const absorbedBlocked = detail.absorbed?.blocked ?? 0
  const follow = detail.absorbed?.follow ?? null
  const offerAbsorbed = absorbedSources > 0 || !!detail.absorbed?.absorbs
  // 함께 풀 것: 살아 있는 흡수 차단이나 후속 차단 약속
  const absorbedRelease = absorbedBlocked > 0 || !!follow
  // 이 출발지의 차단이 이미 풀렸어도 흡수 차단 · 약속이 살아 있으면 해제할 수 있다. 그때는 흡수 차단만 푼다
  const absorbedOnlyRelease = !activeBlock && absorbedRelease
  // 적용 지점(이슈 #77). 살아 있는 차단이 관문을 요청했으면 체크한 채 잠근다(넓히기만). admin 은 풀 수 있고, 그러면 서버가
  // 한 번에 해제 뒤 다시 건다(operator 가 보내면 403)
  const blockPoints = detail.block_points ?? null
  const liveGateway = !!blockPoints?.requested?.includes('gateway')
  const withGateway = gateway ?? (liveGateway || !!blockPoints?.default.includes('gateway'))
  const gatewayLocked = liveGateway && me.data?.role !== 'admin'
  // 관문 빼기(admin). 서버가 해제 뒤 다시 걸되 만료는 살아 있는 차단처럼 앞당기지 않는다
  const narrowing = !!blockPoints && liveGateway && !withGateway
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
    setWithAbsorbed(false)
    setGateway(null)
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
    if (pending === 'block_ip' && blockPoints) input.points = withGateway ? ['gateway', 'fw'] : ['fw']
    if (pending === 'block_ip' && withAbsorbed && offerAbsorbed) input.include_absorbed = true
    if (pending === 'unblock_ip' && (withAbsorbed || absorbedOnlyRelease) && absorbedRelease) input.include_absorbed = true
    send(input)
  }

  const exempt = detail.actor.exempt ?? null
  const blockReason = !detail.actor_ip
    ? '출발지가 없는 사건은 차단할 수 없습니다'
    : exempt
      ? `차단 금지 대역 ${exempt.cidr}(${revealHidden(exempt.note)})에 들어 차단할 수 없습니다`
      : block.reason
  const releaseReason = !release.allowed
    ? release.reason
    : absorbedOnlyRelease
      ? ''
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
          disabled={!block.allowed || !detail.actor_ip || !!exempt}
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
        {me.data?.role === 'viewer' && <p className="m-0 text-xs text-ink-muted">조회 전용 계정입니다. 조치 · 판정은 operator · admin 이 합니다.</p>}
      </div>

      {exempt && detail.actor_ip && block.allowed && (
        <p className="m-0 text-xs text-ink-muted">
          {blockReason}
          <span className="whitespace-nowrap">
            .{' '}
            <InfoTip label="차단 금지 대역">인프라 · 사설 · 예약 주소는 막지 않습니다.</InfoTip>
          </span>
        </p>
      )}

      {pending && canConfirm && (
        <form
          id={panelId}
          onSubmit={confirm}
          aria-label={`${ACTION_LABEL[pending]} 확인`}
          className="flex flex-col gap-3 rounded-panel bg-canvas p-3"
        >
          <p className="m-0 text-sm">
            {pending === 'block_ip' && !legacyBlock && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 를 <strong>{hoursLabel(Number(hours))}</strong> 동안{' '}
                {/* ⓘ 가 마지막 낱말과 떨어져 홀로 다음 줄로 가지 않게 묶는다 */}
                <span className="whitespace-nowrap">
                  차단합니다.{' '}
                  <InfoTip label="차단">
                    {activeBlock && '이미 살아 있는 차단이 있으면 만료를 앞당기지 않습니다. '}
                    {!blockPoints && '적용 대상: AWS 관문 · web-01 앞 내부 방화벽. '}
                    실제 적용 결과는 지점별로 확인합니다.
                  </InfoTip>
                </span>
              </>
            )}
            {pending === 'block_ip' && legacyBlock && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 에는 만료 없는 옛 차단이 살아 있어 두 지점 집행에서 빠집니다(집행 제외). 이 요청은 사유 · 요청자{narrowing ? ' · 적용 지점' : ''}만 바꿉니다. 지점에서 막으려면 admin 이 해제한 뒤 다시{' '}
                <span className="whitespace-nowrap">
                  차단합니다.{' '}
                  <InfoTip label="옛 차단">살아 있는 차단의 만료는 앞당기지 않아, 다시 걸어도 만료가 그대로 없습니다.</InfoTip>
                </span>
              </>
            )}
            {pending === 'unblock_ip' && !absorbedOnlyRelease && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 의 차단을 지금 풉니다.
              </>
            )}
            {pending === 'unblock_ip' && absorbedOnlyRelease && (
              <>
                출발지 <span className="font-mono font-medium">{detail.actor_ip}</span> 의 차단은 이미 풀렸거나 만료됐습니다. 이 사건의 흡수 차단 <strong>{absorbedBlocked}곳</strong>만 지금 풉니다{follow ? '(후속 차단도 멈춥니다)' : ''}.
              </>
            )}
            {pending === 'suppress_rule' && (
              <>
                규칙 <span className="font-mono font-medium">{detail.rule_id} {detail.rule_version}</span> 을 억제하고 이 사건을 억제 상태로 닫습니다.
              </>
            )}
          </p>
          {pending === 'block_ip' && blockPoints && (
            <BlockPointsField
              checked={withGateway}
              locked={gatewayLocked}
              basis={blockPoints.basis}
              live={liveGateway}
              onChange={setGateway}
            />
          )}
          {pending === 'block_ip' && offerAbsorbed && (
            <AbsorbedCheck
              checked={withAbsorbed}
              onChange={setWithAbsorbed}
              label={absorbedSources > 0 ? `흡수된 출발지 ${absorbedSources}곳도 함께 차단` : '앞으로 흡수되는 출발지도 함께 차단'}
              hint={blockHint(detail.absorbed)}
              tip={`같은 페이로드로 이 사건에 묶인 출발지를 같은 만료로 올리고, 만료 전까지 새로 흡수되는 출발지도 같은 만료로 올립니다(첫 사건의 마지막 판정이 위협일 때만). 다른 사건으로 살아 있는 차단은 그 사건 것으로 두고 만료도 바꾸지 않습니다.${blockPoints ? ' 적용 지점은 이 출발지와 같고, 살아 있는 차단은 넓히기만 합니다.' : ''}`}
            />
          )}
          {pending === 'unblock_ip' && absorbedRelease && (
            <AbsorbedCheck
              checked={withAbsorbed || absorbedOnlyRelease}
              disabled={absorbedOnlyRelease}
              onChange={setWithAbsorbed}
              label={`흡수 차단 ${absorbedBlocked}곳도 함께 해제${follow ? ' · 후속 차단 중지' : ''}`}
              hint={absorbedBlocked >= 3 ? '3곳 이상을 한꺼번에 풀면 차단 대량 해제(R201) 알림이 뜹니다.' : undefined}
              tip={
                absorbedBlocked >= 3
                  ? 'R201 알림은 의도된 감사입니다. 흡수 판단 전체가 틀렸을 때만 쓰고, 평소에는 만료로 풀리게 둡니다.'
                  : '흡수 판단 전체가 틀렸을 때만 씁니다. 평소에는 만료로 풀리게 둡니다.'
              }
            />
          )}
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
            <FormField label="메모 (선택)" className={pending !== 'block_ip' ? 'sm:col-span-2' : undefined}>
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
          <UntrustedText value={mutation.data.operator} max={64} /> · 상태 {INCIDENT_STATUS_LABEL[detail.status] ?? detail.status}
          {absorbedResult(mutation.data.absorbed)}
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

/** 기본값의 까닭(서버 block_points.basis, 확인 창 ⓘ). 기본값은 규칙만으로 정하고 장비는 까닭에만 쓴다 */
const BASIS_NOTE: Record<BlockPointsBasis, string> = {
  honeypot_abuse: '허니팟 남용 규칙(프록시 남용 시도)이라 기본으로 관문에서도 막습니다.',
  sensor_only: '허니팟 센서에서만 본 위협이라 관측이 이어지게 기본은 내부 방화벽만입니다. 허니팟 자원 소모 · 침해 의심이면 관문을 더합니다.',
  protected: '보호 대상에서 본 위협이라 기본은 내부 방화벽입니다.',
  monitor: '관제 시스템(콘솔 · 데이터 노드)에서 본 위협이라 기본은 내부 방화벽입니다.',
  unconfirmed: '장비를 확인하지 못해 기본은 내부 방화벽입니다.',
}

interface BlockPointsFieldProps {
  checked: boolean
  /** 살아 있는 차단이 관문을 요청해 operator 는 뺄 수 없다 */
  locked: boolean
  basis: BlockPointsBasis
  /** 살아 있는 차단이 관문을 요청했다. 풀면(admin) 서버가 해제 뒤 다시 건다 */
  live: boolean
  onChange: (checked: boolean) => void
}

/**
 * 적용 지점(이슈 #77): 내부 방화벽(늘 적용 · 고정) · 'AWS 관문에서도 막기' 확인란 하나. 관문 전용은 없다.
 * 까닭은 확인란 옆 ⓘ, 늘 보이는 한 줄은 안전 경고(허니팟 관측이 끊김) · 관문 빼기 기록 · 잠긴 까닭뿐이다
 */
function BlockPointsField({ checked, locked, basis, live, onChange }: BlockPointsFieldProps) {
  const noteId = useId()
  const tipId = useId()
  const note = locked
    ? '살아 있는 차단이 관문도 막고 있어 admin 만 뺄 수 있습니다.'
    : live && !checked
      ? '해제 뒤 다시 걸기로 기록됩니다.'
      : checked && !live
        ? '허니팟 관측이 끊깁니다.'
        : ''
  return (
    <fieldset className="m-0 flex min-w-0 flex-col gap-1 border-0 p-0" data-block-points="">
      <legend className="mb-1 p-0 text-xs text-ink-muted">적용 지점</legend>
      <label className="flex items-center gap-2 text-sm font-medium">
        <input type="checkbox" checked disabled />
        내부 방화벽 · 늘 적용
      </label>
      <InfoTip
        label="AWS 관문에서도 막기"
        id={tipId}
        render={({ button, panel }) => (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-1.5">
              <label className="flex items-center gap-2 text-sm font-medium">
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={locked}
                  aria-describedby={[note ? noteId : null, tipId].filter(Boolean).join(' ')}
                  onChange={(e) => onChange(e.target.checked)}
                />
                AWS 관문에서도 막기
              </label>
              {button}
            </div>
            {panel}
          </div>
        )}
      >
        {BASIS_NOTE[basis] ?? '기본값은 규칙으로 정합니다.'}
      </InfoTip>
      {note && (
        <p id={noteId} className={cn('m-0 text-xs', locked ? 'text-ink-muted' : 'text-warning')} data-block-points-note="">
          {note}
        </p>
      )}
    </fieldset>
  )
}

interface AbsorbedCheckProps {
  checked: boolean
  disabled?: boolean
  onChange: (checked: boolean) => void
  label: string
  /** 늘 보이는 안내(넣지 않을 곳 · 대량 해제 알림). 없으면 줄을 두지 않는다 */
  hint?: string
  /** 동작 규칙 · 사용 지침. 선택 옆 도움말(ⓘ)로 펼친다 */
  tip: ReactNode
}

/** 흡수 출발지를 함께 다루는 선택. 기본은 꺼져 있어 이 출발지만 다룬다. ⓘ 는 label 밖에 둔다(선택 이름에 섞이지 않게) */
function AbsorbedCheck({ checked, disabled, onChange, label, hint, tip }: AbsorbedCheckProps) {
  const hintId = useId()
  const tipId = useId()
  return (
    <InfoTip
      label={label}
      id={tipId}
      render={({ button, panel }) => (
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-1.5">
            <label className="flex items-center gap-2 text-sm font-medium">
              <input
                type="checkbox"
                checked={checked}
                disabled={disabled}
                aria-describedby={[hint ? hintId : null, tipId].filter(Boolean).join(' ')}
                onChange={(e) => onChange(e.target.checked)}
              />
              {label}
            </label>
            {button}
          </div>
          {panel}
          {hint && (
            <p id={hintId} className="m-0 text-xs text-ink-muted">
              {hint}
            </p>
          )}
        </div>
      )}
    >
      {tip}
    </InfoTip>
  )
}

/** 함께 차단 확인의 늘 보이는 안내: 넣지 않을 곳(사람이 푼 곳 · 차단 금지 대역). 없으면 undefined */
function blockHint(absorbed: IncidentDetail['absorbed']): string | undefined {
  const parts: string[] = []
  const skipped = absorbed?.skipped_total ?? 0
  if (skipped > 0) {
    const list = (absorbed?.skipped ?? []).join(', ')
    parts.push(`사람이 푼 ${skipped}곳(${list}${skipped > (absorbed?.skipped?.length ?? 0) ? ' …' : ''})은 다시 걸지 않습니다.`)
  }
  if (absorbed?.unblockable) parts.push(`차단 금지 대역(사설 · 예약 · 인프라 주소) ${absorbed.unblockable}곳은 넣지 않습니다.`)
  return parts.length ? parts.join(' ') : undefined
}

/** 흡수 출발지를 함께 다룬 결과 한 줄(서버 응답의 absorbed) */
function absorbedResult(absorbed: ActionCreated['absorbed']): string {
  if (!absorbed) return ''
  if (absorbed.actor_ip) return ` · 흡수 차단 ${absorbed.actor_ip} 한 곳 해제`
  if (absorbed.released !== undefined) return ` · 흡수 차단 ${absorbed.released}곳 함께 해제${absorbed.follow_stopped ? ' · 후속 차단 중지' : ''}`
  const extra = [
    absorbed.kept ? `${absorbed.kept}곳은 다른 사건으로 차단 중` : '',
    absorbed.skipped_total ? `사람이 푼 ${absorbed.skipped_total}곳 제외` : '',
    absorbed.unblockable ? `차단 금지 대역 ${absorbed.unblockable}곳 제외` : '',
  ].filter(Boolean)
  return ` · 흡수 출발지 ${absorbed.blocked ?? 0}곳 함께 차단${extra.length ? ` (${extra.join(' · ')})` : ''}${absorbed.follow_expires_at ? ' · 만료 전 새 흡수도 차단' : ''}`
}
