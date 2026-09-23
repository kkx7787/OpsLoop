import { useId, type ReactNode } from 'react'
import type { IncidentSort } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { INCIDENT_STATUS_LABEL, INCIDENT_STATUSES, isSeverity, SEVERITIES } from '@/lib/domain'
import { Button } from '../../atoms/Button'
import { Label } from '../../atoms/Label'
import { Select } from '../../atoms/Select'
import { SegmentedControl, type SegmentOption } from '../../molecules/SegmentedControl'
import { clearFilters, countFilters, DEFAULT_SORT, SORT_LABEL, SORTS, type ListFilters, type RuleOption } from './filters'
import { isIncidentStatus } from './model'

export interface IncidentFilterBarProps {
  value: ListFilters
  onChange: (next: ListFilters) => void
  /** 규칙 선택지. 주소에 있는 규칙이 여기 없어도 고른 값은 보인다 */
  rules?: readonly RuleOption[]
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

/** 조건 띠: 상태 · 심각도 · 규칙 · 판정 여부. 값은 부르는 쪽이 주소에 둔다. */
export function IncidentFilterBar({ value, onChange, rules = [], className }: IncidentFilterBarProps) {
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
              {rule.name ? `${rule.id} ${rule.name}` : rule.id}
            </option>
          ))}
        </Select>
      </Field>

      <Field id={`${id}-judged`} label="판정">
        <Select
          id={`${id}-judged`}
          fieldSize="sm"
          className="w-auto"
          value={value.judged === undefined ? '' : String(value.judged)}
          onChange={(event) => {
            const next = event.target.value
            patch({ judged: next === 'true' ? true : next === 'false' ? false : undefined })
          }}
        >
          <option value="">전체</option>
          <option value="false">미판정</option>
          <option value="true">판정됨</option>
        </Select>
      </Field>

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
