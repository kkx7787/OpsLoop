import { useEffect, useRef, useState, type FormEvent } from 'react'
import {
  BATCH_MAX, DEFAULT_TEMPLATE_HEADER, DEFAULT_TEMPLATE_ITEM, EVENT_LABEL, GRADE_LABEL, KIND_LABEL, NOTIFY_EVENTS, NOTIFY_GRADES, NOTIFY_KINDS, TEMPLATE_MAX,
  type ChannelInput, type NotifyChannel, type NotifyEvent, type NotifyGrade, type NotifyKind,
} from '@/api/notify'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Select } from '@/components/atoms/Select'
import { Switch } from '@/components/atoms/Switch'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { FormField } from '@/components/molecules/FormField'
import { SEVERITIES, type Severity } from '@/lib/domain'
import { PLACEHOLDERS, previewSections } from './template'

interface Props {
  /** 수정이면 기존 채널. 없으면 추가 */
  initial?: NotifyChannel
  busy: boolean
  onSubmit: (input: ChannelInput) => void | Promise<void>
  onCancel: () => void
}

/** 화면 상태. 묶음 시간은 입력 중인 글자를 그대로 두려고 문자열로 든다. */
interface Draft {
  name: string; kind: NotifyKind; url: string; grade: NotifyGrade; events: NotifyEvent[]; min_severity: Severity
  batch: string; template_header: string; template_item: string; enabled: boolean
}

const URL_HINT: Record<NotifyKind, string> = {
  teams: 'Power Automate 워크플로("Teams 웹훅 요청을 받으면")의 https 주소. 호스트는 *.environment.api.powerplatform.com 이어야 합니다. 옛 logic.azure.com 주소는 동작하지 않으니 흐름을 다시 저장해 새 주소를 받아 주세요.',
  webhook: 'https 주소로 JSON 을 POST 합니다. 사설 · 링크로컬 · localhost 등 공인 인터넷이 아닌 주소는 서버가 거부합니다.',
}

function draftOf(initial?: NotifyChannel): Draft {
  return {
    name: initial?.name ?? '', kind: initial?.kind ?? 'teams', url: '', grade: initial?.grade ?? 'immediate',
    events: initial?.events ?? [...NOTIFY_EVENTS], min_severity: initial?.min_severity ?? 'low',
    batch: String(initial?.batch_seconds ?? 300), template_header: initial?.template_header ?? DEFAULT_TEMPLATE_HEADER,
    template_item: initial?.template_item ?? DEFAULT_TEMPLATE_ITEM, enabled: initial?.enabled ?? true,
  }
}

/** 화면 검증. 서버가 같은 규칙으로 다시 검사한다(app/notify.py). 일일 요약은 사건 종류 · 묶음 시간을 쓰지 않는다. */
function validate(draft: Draft, editing: boolean): string {
  const immediate = draft.grade === 'immediate'
  if (!draft.name.trim()) return '이름을 입력해 주세요.'
  if (draft.name.trim().length > 64) return '이름은 64자까지입니다.'
  if (!editing && !draft.url) return '주소를 입력해 주세요.'
  if (draft.url && !/^https:\/\/\S+$/.test(draft.url)) return '주소는 https 로 시작해야 합니다.'
  if (immediate && !draft.events.length) return '사건 종류를 하나 이상 선택해 주세요.'
  const batch = Number(draft.batch)
  if (immediate && (!/^\d+$/.test(draft.batch.trim()) || batch > BATCH_MAX)) return `묶음 시간은 0~${BATCH_MAX.toLocaleString()}초 사이여야 합니다.`
  for (const t of [draft.template_header, draft.template_item]) {
    if (!t.trim() || t.length > TEMPLATE_MAX) return `메시지 틀은 1~${TEMPLATE_MAX}자여야 합니다.`
    // 서버(app/notifier.py validate_template)와 같은 규칙: 중괄호 안은 소문자 이름만. {x:>5} · {x.attr} 는 값 노출 위험이라 막는다
    for (const [, inner] of t.matchAll(/\{([^{}]*)\}/g)) if (!/^[a-z_]+$/.test(inner)) return '자리표시자는 {이름} 꼴만 쓸 수 있습니다 (형식 지정자 불가).'
  }
  return ''
}

/** 채널 추가 · 수정 양식. 주소는 password 형으로 받고 수정 때 비우면 서버가 기존 주소를 유지한다. 열리면 이름 칸으로 초점을 옮긴다. */
export function ChannelForm({ initial, busy, onSubmit, onCancel }: Props) {
  const [draft, setDraft] = useState<Draft>(() => draftOf(initial))
  const [error, setError] = useState('')
  const card = useRef<HTMLDivElement>(null), nameInput = useRef<HTMLInputElement>(null)
  const editing = !!initial
  const immediate = draft.grade === 'immediate'
  const patch = (next: Partial<Draft>) => setDraft((d) => ({ ...d, ...next }))
  const sections = previewSections(draft.template_header, draft.template_item, draft.grade)

  useEffect(() => {
    card.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
    nameInput.current?.focus({ preventScroll: true })
  }, [])

  function submit(event: FormEvent) {
    event.preventDefault()
    const message = validate(draft, editing)
    setError(message)
    if (message) return
    // 일일 요약은 사건 종류 · 묶음 시간을 쓰지 않지만 서버 계약상 값은 보낸다(숨긴 칸의 값 그대로, 비었으면 기본값)
    const events = NOTIFY_EVENTS.filter((e) => draft.events.includes(e))
    const input: ChannelInput = {
      name: draft.name.trim(), kind: draft.kind, grade: draft.grade, events: events.length ? events : [...NOTIFY_EVENTS],
      min_severity: draft.min_severity, batch_seconds: /^\d+$/.test(draft.batch.trim()) ? Math.min(Number(draft.batch), BATCH_MAX) : 300,
      template_header: draft.template_header, template_item: draft.template_item, enabled: draft.enabled,
    }
    if (draft.url) input.url = draft.url
    void onSubmit(input)
  }

  return (
    <Card ref={card} padding="none" className="min-w-0 scroll-mt-4">
      <CardHeader title={editing ? <>채널 수정 · <UntrustedText value={initial.name} max={120} /></> : '채널 추가'} aside={<Button size="sm" onClick={onCancel} disabled={busy}>닫기</Button>} />
      <form className="grid gap-4 p-4 xl:grid-cols-2" onSubmit={submit} aria-label={editing ? '채널 수정 양식' : '채널 추가 양식'}>
        <div className="grid content-start gap-4">
          <FormField label="이름" required>{(f) => <Input {...f} ref={nameInput} value={draft.name} maxLength={64} placeholder="SOC Teams" disabled={busy} onChange={(e) => patch({ name: e.target.value })} />}</FormField>
          <FormField label="종류" hint={URL_HINT[draft.kind]}>{(f) => <Select {...f} value={draft.kind} disabled={busy} onChange={(e) => patch({ kind: e.target.value as NotifyKind })}>{NOTIFY_KINDS.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}</Select>}</FormField>
          <FormField label="주소" required={!editing} hint={editing ? `비워 두면 기존 주소(${initial.url_host} …${initial.url_tail})를 유지합니다. 저장 뒤에는 원문을 다시 볼 수 없습니다.` : '저장 뒤에는 호스트와 끝 4자만 보입니다.'}>
            {(f) => <Input {...f} type="password" autoComplete="new-password" spellCheck={false} value={draft.url} maxLength={2048} placeholder="https://" disabled={busy} onChange={(e) => patch({ url: e.target.value })} />}
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="등급" hint={immediate ? '사건이 생기면 묶음 시간이 지난 뒤 보냅니다.' : '매일 09:00 KST 에 미판정 요약을 한 번 보냅니다.'}>{(f) => <Select {...f} value={draft.grade} disabled={busy} onChange={(e) => patch({ grade: e.target.value as NotifyGrade })}>{NOTIFY_GRADES.map((g) => <option key={g} value={g}>{GRADE_LABEL[g]}</option>)}</Select>}</FormField>
            {immediate && <FormField label="최소 심각도" hint="이 심각도 이상인 사건만 보냅니다.">{(f) => <Select {...f} value={draft.min_severity} disabled={busy} onChange={(e) => patch({ min_severity: e.target.value as Severity })}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</Select>}</FormField>}
          </div>
          {immediate ? <>
            <fieldset disabled={busy} className="m-0 grid gap-2 border-0 p-0 text-sm"><legend className="mb-1 text-sm font-medium">사건 종류</legend>
              <div className="flex flex-wrap gap-4">{NOTIFY_EVENTS.map((event) => <label key={event} className="flex items-center gap-2"><input type="checkbox" checked={draft.events.includes(event)} onChange={(e) => patch({ events: e.target.checked ? [...draft.events, event] : draft.events.filter((v) => v !== event) })} />{EVENT_LABEL[event]}</label>)}</div>
            </fieldset>
            <FormField label="묶음 시간(초)" hint="같은 종류의 첫 사건부터 이 시간 동안 들어온 사건을 모아 한 메시지로 보냅니다. 0 이면 바로 보냅니다.">{(f) => <Input {...f} inputMode="numeric" value={draft.batch} maxLength={5} disabled={busy} onChange={(e) => patch({ batch: e.target.value })} className="sm:w-40" />}</FormField>
          </> : <p className="m-0 rounded-panel bg-canvas px-3 py-2 text-xs leading-5 text-ink-muted">일일 요약은 사건 종류 · 최소 심각도 · 묶음 시간을 쓰지 않습니다. 매일 09:00 KST 에 미판정 수 · 최고 경과 · 목표 초과 수 · 최근 24시간 사건 수를 한 번 보냅니다.</p>}
          <Switch label="사용" checked={draft.enabled} disabled={busy} onChange={(e) => patch({ enabled: e.target.checked })} />
        </div>
        <div className="grid content-start gap-4">
          <FormField label="메시지 틀 · 머리말" hint={immediate ? '채널 · 사건 종류당 한 번 들어갑니다.' : '요약 메시지의 첫 줄입니다. {count} 는 미판정 수입니다.'}>{(f) => <Input {...f} value={draft.template_header} maxLength={TEMPLATE_MAX} disabled={busy} onChange={(e) => patch({ template_header: e.target.value })} />}</FormField>
          {immediate && <FormField label="메시지 틀 · 항목 한 줄" hint="사건마다 한 줄(최대 20건, 넘으면 '외 n건').">{(f) => <Input {...f} value={draft.template_item} maxLength={TEMPLATE_MAX} disabled={busy} onChange={(e) => patch({ template_item: e.target.value })} />}</FormField>}
          <div className="flex flex-wrap items-center gap-2"><Button size="sm" disabled={busy} onClick={() => patch({ template_header: DEFAULT_TEMPLATE_HEADER, template_item: DEFAULT_TEMPLATE_ITEM })}>기본값으로</Button><span className="text-xs text-ink-muted">모르는 자리표시자는 그대로 남고, 값이 없으면 '-' 로 나갑니다.</span></div>
          <details className="text-xs"><summary className="cursor-pointer">자리표시자 도움말</summary>
            <dl className="m-0 mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">{PLACEHOLDERS.map(([key, label]) => <div key={key} className="contents"><dt className="font-mono">{`{${key}}`}</dt><dd className="m-0 text-ink-muted">{label}</dd></div>)}</dl>
          </details>
          <div className="grid gap-1.5"><span className="text-sm font-medium">예시 미리보기</span>
            <div aria-label="메시지 미리보기" role="group" className="grid gap-2">{sections.map((section) => <div key={section.title} className="grid gap-1">
              <span className="text-xs text-ink-muted">{section.title}</span>
              <pre className="m-0 overflow-x-auto rounded-panel bg-canvas p-3 text-xs leading-5 whitespace-pre-wrap">{section.lines.join('\n')}</pre>
            </div>)}</div>
            <p className="m-0 text-xs text-ink-muted">예시 값으로 그린 화면용 미리보기입니다. 실제 발송은 사건 값으로 채웁니다.</p>
          </div>
        </div>
        {error && <Banner tone="danger" title={error} className="xl:col-span-2" />}
        <div className="flex flex-wrap gap-2 xl:col-span-2"><Button type="submit" variant="primary" loading={busy}>{editing ? '변경 저장' : '채널 추가'}</Button><Button onClick={onCancel} disabled={busy}>취소</Button></div>
      </form>
    </Card>
  )
}
