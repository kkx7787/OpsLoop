import { useId, type ReactNode } from 'react'
import type { IncidentSort } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { INCIDENT_STATUS_LABEL, INCIDENT_STATUSES, isSeverity, SEVERITIES } from '@/lib/domain'
import { revealHidden } from '@/lib/untrusted'
import { Button } from '../../atoms/Button'
import { Chip } from '../../atoms/Chip'
import { Label } from '../../atoms/Label'
import { Select } from '../../atoms/Select'
import { isDeviceId } from '../../molecules/device-format'
import { SegmentedControl, type SegmentOption } from '../../molecules/SegmentedControl'
import { clearFilters, countFilters, DEFAULT_SORT, SORT_LABEL, SORTS, type DeviceChoice, type ListFilters, type RuleOption } from './filters'
import { isIncidentStatus } from './model'

export interface IncidentFilterBarProps {
  value: ListFilters
  onChange: (next: ListFilters) => void
  /** 규칙 선택지. 주소에 있는 규칙이 여기 없어도 고른 값은 보인다 */
  rules?: readonly RuleOption[]
  /** 장비 선택지(deviceOptionsOf: 서버 선택지 · 장비 미확인 · 주소의 값) */
  devices?: readonly DeviceChoice[]
  className?: string
}

const SORT_OPTIONS: readonly SegmentOption<IncidentSort>[] = SORTS.map((sort) => ({ value: sort, label: SORT_LABEL[sort] }))

/** 이름표 + 선택. 조건 띠는 한 줄이라 양식 칸(FormField)보다 작게 둔다 */
function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div className="flex items-center gap-1.5">
      <Label htmlFor={id} className="text-xs font-normal text-ink-muted">
        {label}
      </Label>
      {children}
    </div>
  )
}

/** 판정 칸 값. 미결(#83)은 판정 여부가 아니라 최신 판정이 사람이 남긴 미결인 사건이다 */
function judgedValue(value: ListFilters): string {
  if (value.undetermined) return 'undetermined'
  return value.judged === undefined ? '' : String(value.judged)
}

/**
 * 조건 띠: 상태 · 심각도 · 규칙 · 장비 · 판정 여부(미결 포함). 값은 부르는 쪽이 주소에 둔다.
 * 출발지(actor_ip)는 고르는 칸 없이 출발지 분석(S-09)에서 넘어오므로 칩으로만 보이고 × 로 뺀다.
 */
export function IncidentFilterBar({ value, onChange, rules = [], devices = [], className }: IncidentFilterBarProps) {
  const id = useId()
  const active = countFilters(value)
  const ruleOptions =
    value.rule_id && !rules.some((rule) => rule.id === value.rule_id) ? [{ id: value.rule_id }, ...rules] : rules

  function patch(next: Partial<ListFilters>) {
    onChange({ ...value, ...next })
  }

  return (
    <div role="group" aria-label="목록 조건" className={cn('flex flex-wrap items-center gap-x-3 gap-y-2', className)}>
      <Field id={`${id}-status`} label="상태">
        <Select
          id={`${id}-status`}
          fieldSize="sm"
          className="w-auto"
          value={value.status ?? ''}
          onChange={(event) => {
            const next = event.target.value
            patch({ status: isIncidentStatus(next) ? next : undefined })
          }}
        >
          <option value="">전체</option>
          {INCIDENT_STATUSES.map((status) => (
            <option key={status} value={status}>
              {INCIDENT_STATUS_LABEL[status]}
            </option>
          ))}
        </Select>
      </Field>

      <Field id={`${id}-severity`} label="심각도">
        <Select
          id={`${id}-severity`}
          fieldSize="sm"
          className="w-auto"
          value={value.severity ?? ''}
          onChange={(event) => {
            const next = event.target.value
            patch({ severity: isSeverity(next) ? next : undefined })
          }}
        >
          <option value="">전체</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </Select>
      </Field>

      <Field id={`${id}-rule`} label="규칙">
        <Select
          id={`${id}-rule`}
          fieldSize="sm"
          className="w-auto max-w-[240px]"
          value={value.rule_id ?? ''}
          onChange={(event) => patch({ rule_id: event.target.value || undefined })}
        >
          <option value="">전체</option>
          {ruleOptions.map((rule) => (
            <option key={rule.id} value={rule.id}>
              {/* 규칙 값은 주소(?rule_id=)에서 올 수 있다. <option> 은 글자만 받으므로 문자열로 바꿔 넣는다 */}
              {revealHidden(rule.name ? `${rule.id} ${rule.name}` : rule.id)}
            </option>
          ))}
        </Select>
      </Field>

      <Field id={`${id}-device`} label="장비">
        <Select
          id={`${id}-device`}
          fieldSize="sm"
          className="w-auto max-w-[200px]"
          value={value.device ?? ''}
          onChange={(event) => {
            const next = event.target.value
            patch({ device: isDeviceId(next) ? next : undefined })
          }}
        >
          <option value="">전체</option>
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {/* 등록 노드 이름은 hostname(비신뢰)이다. <option> 은 글자만 받으므로 문자열로 바꿔 넣는다 */}
              {revealHidden(device.label)}
            </option>
          ))}
        </Select>
      </Field>

      <Field id={`${id}-assignment`} label="담당">
        <Select id={`${id}-assignment`} fieldSize="sm" className="w-auto" value={value.assignment ?? ''}
          onChange={event => patch({ assignment: event.target.value === 'mine' || event.target.value === 'unassigned' ? event.target.value : undefined })}>
          <option value="">전체</option><option value="mine">내 담당</option><option value="unassigned">미배정</option>
        </Select>
      </Field>
      <Field id={`${id}-judged`} label="판정">
        <Select
          id={`${id}-judged`}
          fieldSize="sm"
          className="w-auto"
          value={judgedValue(value)}
          onChange={(event) => {
            const next = event.target.value
            patch({ judged: next === 'true' ? true : next === 'false' ? false : undefined, undetermined: next === 'undetermined' ? true : undefined })
          }}
        >
          <option value="">전체</option>
          <option value="false">미판정</option>
          <option value="true">판정됨</option>
          <option value="undetermined">미결</option>
        </Select>
      </Field>

      {value.actor_ip && (
        // IPv6 는 39자(주소창에서 손으로 쓰면 45자)까지 길어 좁은 화면에서 칩이 띠 밖으로 나가지 않게 주소 안에서 줄을 바꾼다
        <Chip onRemove={() => patch({ actor_ip: undefined })} removeLabel="출발지 조건 빼기" className="h-auto min-h-7 max-w-full py-0.5">
          <span className="shrink-0">출발지</span> <span className="min-w-0 font-mono break-all">{value.actor_ip}</span>
        </Chip>
      )}

      {active > 0 && (
        <Button variant="ghost" size="sm" onClick={() => onChange(clearFilters(value))}>
          조건 초기화
        </Button>
      )}

    </div>
  )
}

/** 정렬은 빠른 보기 옆에 배치해 필터가 한 줄 더 밀리지 않게 한다. */
export function IncidentSortControl({ value, onChange }: Pick<IncidentFilterBarProps, 'value' | 'onChange'>) {
  return <SegmentedControl aria-label="정렬" options={SORT_OPTIONS} value={value.sort ?? DEFAULT_SORT}
    onChange={(sort) => onChange({ ...value, sort: sort === DEFAULT_SORT ? undefined : sort })} />
}
