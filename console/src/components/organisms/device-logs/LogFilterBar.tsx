import { useId, useState, type FormEvent } from 'react'
import { LOG_KIND_LABEL, LOG_KINDS, type DeviceLogFilters, type LogKind } from '@/api/device-logs'
import { cn } from '@/lib/cn'
import { Button } from '../../atoms/Button'
import { Input } from '../../atoms/Input'
import { Label } from '../../atoms/Label'
import { SegmentedControl, type SegmentOption } from '../../molecules/SegmentedControl'
import { parseStatus } from './log-format'

export interface LogFilterBarProps {
  /** 적용된 조건(주소 검색 인자에서 읽은 값) */
  value: DeviceLogFilters
  onChange: (next: DeviceLogFilters) => void
  className?: string
}

type KindChoice = LogKind | 'all'

const KIND_OPTIONS: readonly SegmentOption<KindChoice>[] = [
  { value: 'all', label: '전체' },
  ...LOG_KINDS.map((kind) => ({ value: kind, label: LOG_KIND_LABEL[kind] })),
]

const STATUS_HINT = '응답 코드는 100~599 사이 세 자리 숫자입니다'

/**
 * 로그 조건 띠(#73): 로그 종류(바로 적용) · 출발지 · 응답 코드('적용' 으로 적용, '초기화' 로 두 칸을 비운다).
 * 응답 코드는 100..599 만 보낸다(그 밖은 서버가 영어 검증 문장으로 답한다). 출발지는 서버가 검사해 한국어 한 문장으로 답한다.
 * 입력 칸은 적용된 값이 바뀌면(주소 · 조건 초기화) 그 값으로 다시 채운다.
 */
export function LogFilterBar({ value, onChange, className }: LogFilterBarProps) {
  const id = useId()
  const applied = `${value.src_ip ?? ''}\n${value.status ?? ''}`
  const [seen, setSeen] = useState(applied)
  const [src, setSrc] = useState(value.src_ip ?? '')
  const [status, setStatus] = useState(value.status === undefined ? '' : String(value.status))
  const [badStatus, setBadStatus] = useState(false)
  if (seen !== applied) {
    setSeen(applied)
    setSrc(value.src_ip ?? '')
    setStatus(value.status === undefined ? '' : String(value.status))
    setBadStatus(false)
  }

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const code = status.trim()
    const parsed = parseStatus(code)
    if (code && parsed === undefined) {
      setBadStatus(true)
      return
    }
    setBadStatus(false)
    onChange({ ...value, src_ip: src.trim() || undefined, status: parsed })
  }

  function reset() {
    setSrc('')
    setStatus('')
    setBadStatus(false)
    onChange({ ...value, src_ip: undefined, status: undefined })
  }

  return (
    <div role="group" aria-label="로그 조건" className={cn('flex flex-wrap items-center gap-x-4 gap-y-2', className)}>
      <SegmentedControl<KindChoice>
        aria-label="로그 종류"
        options={KIND_OPTIONS}
        value={value.kind ?? 'all'}
        onChange={(kind) => onChange({ ...value, kind: kind === 'all' ? undefined : kind })}
      />
      <form onSubmit={apply} noValidate className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="flex items-center gap-1.5">
          <Label htmlFor={`${id}-src`} className="text-xs font-normal text-ink-muted">
            출발지
          </Label>
          <Input id={`${id}-src`} fieldSize="sm" className="w-44 font-mono" value={src} maxLength={64} autoComplete="off" spellCheck={false} onChange={(event) => setSrc(event.target.value)} />
        </span>
        <span className="flex items-center gap-1.5">
          <Label htmlFor={`${id}-status`} className="text-xs font-normal text-ink-muted">
            응답 코드
          </Label>
          <Input
            id={`${id}-status`}
            fieldSize="sm"
            className="w-16 font-mono"
            value={status}
            inputMode="numeric"
            maxLength={3}
            autoComplete="off"
            aria-invalid={badStatus || undefined}
            aria-describedby={badStatus ? `${id}-status-hint` : undefined}
            onChange={(event) => {
              setStatus(event.target.value)
              setBadStatus(false)
            }}
          />
        </span>
        <span className="flex items-center gap-1.5">
          <Button type="submit" size="md">
            적용
          </Button>
          <Button variant="ghost" size="md" onClick={reset}>
            초기화
          </Button>
        </span>
        {badStatus && (
          <span id={`${id}-status-hint`} role="alert" className="basis-full text-2xs text-danger">
            {STATUS_HINT}
          </span>
        )}
      </form>
    </div>
  )
}
