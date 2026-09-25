import { useId, useState, type FormEvent } from 'react'
import { useVerdictMutation, type IncidentDetail, type VerdictInput } from '@/api/incidents'
import { describeError } from '@/api/errors'
import { usePermission } from '@/auth/useMe'
import { cn } from '@/lib/cn'
import { VERDICT_DESCRIPTION, VERDICT_LABEL, VERDICTS, type Verdict } from '@/lib/domain'
import { formatDuration } from '@/lib/time'
import { useNow } from '@/lib/useNow'
import { Button } from '../../atoms/Button'
import { Textarea } from '../../atoms/Textarea'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { Banner } from '../../molecules/Banner'
import { FormField } from '../../molecules/FormField'
import { Gated } from '../../molecules/Gated'
import { decisionSeconds } from './format'

/** 판정값 이름의 글자 색(배지 색 조합표에서 글자 색만). 클래스는 통째로 적는다(Tailwind 가 소스에서 읽는다) */
const VERDICT_TEXT: Record<Verdict, string> = {
  threat: 'text-verdict-threat',
  non_actionable: 'text-verdict-non-actionable',
  false_positive: 'text-verdict-false-positive',
  benign_positive: 'text-verdict-benign-positive',
  undetermined: 'text-verdict-undetermined',
}

export interface VerdictPanelProps {
  detail: IncidentDetail
  /** 이 사건 화면을 연 시각(ms). 제출까지 걸린 초가 decision_seconds 로 남는다(화면 설계 6.3) */
  openedAt: number
  className?: string
}

/**
 * 판정 패널(S-05). 판정값 다섯 개(판정 기준 2장) · 사유 · 관측값(자동) · 소요 시간.
 * 사유는 강제하지 않는다. 비어 있으면 경고만 하고 기록한다 — 억지로 채운 사유는 없는 사유보다 나쁘다.
 * 이미 판정된 사건은 재판정이다. 목록에는 마지막 판단이 보인다.
 * 권한(incident.verdict)이 없으면 패널을 숨기지 않고 흐리게 둔다.
 */
export function VerdictPanel({ detail, openedAt, className }: VerdictPanelProps) {
  const gate = usePermission('incident.verdict')
  const mutation = useVerdictMutation(detail.incident_key)
  const [verdict, setVerdict] = useState<Verdict | null>(null)
  const [reason, setReason] = useState('')
  const [missing, setMissing] = useState(false)
  const headingId = useId()
  const missingId = useId()

  const last = detail.verdicts[detail.verdicts.length - 1]
  const judged = last !== undefined
  const emptyReason = reason.trim() === ''
  const proposal = detail.proposal

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!verdict) {
      setMissing(true)
      return
    }
    const input: VerdictInput = {
      verdict,
      observed_value: detail.signal_count,
      decision_seconds: decisionSeconds(openedAt),
    }
    const trimmed = reason.trim()
    if (proposal?.verdict) input.proposed = proposal.verdict
    if (trimmed) input.reason = trimmed
    mutation.mutate(input, {
      onSuccess: () => {
        setVerdict(null)
        setReason('')
        setMissing(false)
      },
    })
  }

  return (
    <Gated {...gate} showReason className={cn('flex w-full flex-col', className)}>
      <form onSubmit={submit} aria-labelledby={headingId} className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id={headingId} className="m-0 text-base font-semibold tracking-heading">
            {judged ? '재판정' : '판정'}
          </h3>
          {judged && (
            <span className="text-xs text-ink-muted">
              현재 <VerdictBadge verdict={last.verdict} /> <UntrustedText value={last.operator} max={64} /> · <Time value={last.created_at} format="short" />
            </span>
          )}
        </div>

        <div className="border-l-2 border-primary/40 bg-canvas px-3 py-2 text-sm" aria-label="도구 제안">
          <p className="m-0 font-medium">
            도구 제안 · {proposal?.verdict ? <VerdictBadge verdict={proposal.verdict} /> : '제안 없음'}
          </p>
          <ul className="mb-0 mt-2 list-disc space-y-1 pl-4 text-xs text-ink-muted">
            {(proposal?.reasons ?? ['제안 정보가 없습니다. 증거를 보고 직접 판정하세요.']).map((reason, i) => (
              <li key={`${i}-${reason}`}>
                <UntrustedText value={reason} />
              </li>
            ))}
          </ul>
          {proposal?.verdict && verdict && (
            <p role="status" className="mb-0 mt-2 font-medium">
              {proposal.verdict === verdict ? '제안 수락' : '제안 뒤집힘'} · 최종 선택은 담당자가 기록합니다.
            </p>
          )}
        </div>

        <fieldset className="m-0 flex min-w-0 flex-col gap-1.5 border-0 p-0" aria-describedby={missing && !verdict ? missingId : undefined}>
          <legend className="mb-1.5 p-0 text-sm font-medium">판정값</legend>
          {VERDICTS.map((value) => {
            const selected = verdict === value
            return (
              <label
                key={value}
                className={cn(
                  'grid cursor-pointer grid-cols-[auto_minmax(0,1fr)] gap-x-2.5 gap-y-0.5 rounded-control border border-line px-3 py-2 transition-colors',
                  selected ? 'border-primary bg-primary-soft' : 'hover:bg-canvas',
                )}
              >
                <input
                  type="radio"
                  name="verdict"
                  value={value}
                  checked={selected}
                  onChange={() => {
                    setVerdict(value)
                    setMissing(false)
                  }}
                  className="mt-1 size-3.5 accent-primary"
                />
                <span className={cn('text-sm font-medium', selected && VERDICT_TEXT[value])}>{VERDICT_LABEL[value]}</span>
                <span className="col-start-2 text-xs text-ink-muted">{VERDICT_DESCRIPTION[value]}</span>
              </label>
            )
          })}
        </fieldset>
        {missing && !verdict && (
          <p id={missingId} role="alert" className="m-0 text-xs text-danger">
            판정값을 고르세요.
          </p>
        )}

        <FormField label="사유" hint="왜 그렇게 판단했는지. 근거가 된 행위(② 의 행)를 적으면 나중에 다시 볼 수 있습니다">
          {(f) => (
            <Textarea
              {...f}
              value={reason}
              maxLength={1000}
              rows={3}
              onChange={(e) => setReason(e.target.value)}
              placeholder="예: 로그인 성공 뒤 wget 으로 파일 투하 · 세션 2개"
            />
          )}
        </FormField>
        {emptyReason && (
          <p className="m-0 text-xs text-warning" role="status">
            사유가 비어 있습니다. 기록은 되지만 왜 그렇게 판단했는지 남지 않습니다.
          </p>
        )}

        <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-ink-muted">
          <div className="flex flex-col">
            <dt>관측값 (자동)</dt>
            <dd className="m-0 font-medium text-ink tabular-nums">{detail.signal_count}건 · 신호 수</dd>
          </div>
          <div className="flex flex-col">
            <dt>판정 소요</dt>
            <dd className="m-0 font-medium text-ink tabular-nums">
              <DecisionTimer openedAt={openedAt} />
            </dd>
          </div>
        </dl>

        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" size="lg" className="w-full" loading={mutation.isPending}>
            {judged ? '재판정 기록' : '판정 기록'}
          </Button>
          <span className="text-xs text-ink-muted">기록하면 사건은 종결됩니다.</span>
        </div>

        {mutation.isSuccess && (
          <Banner tone="success" title="판정을 기록했습니다">
            <VerdictBadge verdict={mutation.data.verdict} /> · 사건이 종결됐습니다
            {mutation.data.decision_seconds !== null && ` · 소요 ${formatDuration(mutation.data.decision_seconds * 1000)}`}
          </Banner>
        )}
        {mutation.isError && (
          <Banner tone="danger" title="판정을 기록하지 못했습니다">
            {describeError(mutation.error)}
          </Banner>
        )}
      </form>
    </Gated>
  )
}

/** 화면을 연 뒤 흐른 시간. 제출 때 decision_seconds 로 같이 간다 */
function DecisionTimer({ openedAt }: { openedAt: number }) {
  const now = useNow(1000)
  return <>{formatDuration(decisionSeconds(openedAt, now) * 1000)}</>
}
