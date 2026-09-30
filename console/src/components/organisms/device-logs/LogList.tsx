import { Fragment, useId, useState } from 'react'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { TABLE } from '../incident-detail/table-styles'
import { useIsDesktop } from '../incidents/useIsDesktop'
import { cardTime, GAP_TEXT, kindLabel, lineCode, lineSummary, requestText, sshResult, type LogRow } from './log-format'

export interface LogListProps {
  lines: readonly LogRow[]
  /** 이 줄 아래에 사이 끊김 구분선 */
  gaps: readonly string[]
  /** 받은 뒤 갱신이 실패했다. 이전 줄을 흐리게 남긴다 */
  stale: boolean
  className?: string
}

/** 긴 값은 이만큼만 보이고 펼치기로 본다(전체는 말풍선) */
const URL_MAX = 160
const TEXT_MAX = 160

const CAPTION = '최근 로그, 최신 순'

/**
 * 최근 로그 줄(#73). 넓은 폭(md 이상)은 표, 좁은 폭은 접은 카드다(한 가지만 그린다).
 * 모든 글자는 서버가 가린 비신뢰 값이라 UntrustedText 로 그리고, 말풍선(title)은 revealHidden 으로 드러낸다.
 * 줄은 5초마다 늘어나지만 aria-live 는 두지 않는다(낭독이 끊임없이 이어지지 않게).
 */
export function LogList({ lines, gaps, stale, className }: LogListProps) {
  const desktop = useIsDesktop()
  const gapSet = new Set(gaps)
  return (
    <div data-stale={stale ? '' : undefined} className={cn('min-w-0 transition-opacity', stale && 'opacity-50', className)}>
      {desktop ? <LogTable lines={lines} gaps={gapSet} /> : <LogCards lines={lines} gaps={gapSet} />}
    </div>
  )
}

function Gap() {
  return <span className="text-2xs font-medium text-warning">{GAP_TEXT}</span>
}

function PasswordBadge({ line }: { line: LogRow }) {
  if (!line.has_password) return null
  return (
    <Badge tone="neutral" className="ml-1.5" data-has-password="">
      비밀번호 기록 있음
    </Badge>
  )
}

/** 요청 칸: 웹은 '메서드 경로(가림) → 코드', SSH 는 '결과 · 사용자' */
function RequestCell({ line }: { line: LogRow }) {
  if (line.kind === 'web') {
    return (
      <>
        <span className="font-mono">
          <UntrustedText value={line.http_method} max={16} fallback="—" /> <UntrustedText value={line.url} max={URL_MAX} fallback="—" />
        </span>
        <span className="whitespace-nowrap tabular-nums"> → {lineCode(line)}</span>
        <PasswordBadge line={line} />
      </>
    )
  }
  return (
    <>
      <span className="font-medium">
        <UntrustedText value={sshResult(line.eventid)} max={64} />
      </span>
      {' · '}
      <span className="font-mono">
        <UntrustedText value={line.username} max={64} fallback="사용자 없음" />
      </span>
      <PasswordBadge line={line} />
    </>
  )
}

function LogTable({ lines, gaps }: { lines: readonly LogRow[]; gaps: ReadonlySet<string> }) {
  return (
    <div className={TABLE.wrap}>
      <table className={TABLE.table}>
        <caption className="sr-only">{CAPTION}</caption>
        <thead>
          <tr>
            <th scope="col" className={TABLE.th}>시각 · KST</th>
            <th scope="col" className={TABLE.th}>종류</th>
            <th scope="col" className={TABLE.th}>출발지</th>
            <th scope="col" className={TABLE.th}>요청 · SSH</th>
            <th scope="col" className={TABLE.th}>요약</th>
          </tr>
        </thead>
        <tbody>
          {lines.map((line) => {
            const summary = lineSummary(line)
            return (
              <Fragment key={line.id}>
                <tr data-line={line.id} data-fresh={line.fresh ? '' : undefined} className={cn(line.fresh && 'bg-primary-soft/60')}>
                  <td className={cn(TABLE.td, TABLE.mono)}>
                    <Time value={line.ts} format="datetime" />
                  </td>
                  <td className={cn(TABLE.td, 'whitespace-nowrap')}>
                    <UntrustedText value={kindLabel(line.kind)} max={32} />
                  </td>
                  <td className={cn(TABLE.td, 'font-mono whitespace-nowrap')}>
                    <UntrustedText value={line.src_ip} max={64} fallback="—" />
                  </td>
                  <td className={cn(TABLE.td, 'min-w-60 break-all')} title={revealHidden(requestText(line))}>
                    <RequestCell line={line} />
                  </td>
                  <td className={cn(TABLE.td, 'min-w-48 break-all text-ink-muted')} title={summary ? revealHidden(summary) : undefined}>
                    <UntrustedText value={summary} max={TEXT_MAX} fallback="—" />
                  </td>
                </tr>
                {gaps.has(line.id) && (
                  <tr data-gap="">
                    <td colSpan={5} className={cn(TABLE.td, 'bg-warning-soft text-center')}>
                      <Gap />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/**
 * 좁은 폭(390): 머리(시각 월-일 · 종류 · 출발지 · 코드/결과)만 보이는 접은 카드. 펼친 줄은 id 로 기억해 갱신에 접히지 않는다.
 * 머리의 출발지는 잘리므로(IPv6) 펼친 칸 맨 앞에 줄바꿈해 다시 둔다
 */
function LogCards({ lines, gaps }: { lines: readonly LogRow[]; gaps: ReadonlySet<string> }) {
  const baseId = useId()
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set())
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  return (
    <ul aria-label={CAPTION} className="m-0 flex list-none flex-col divide-y divide-line p-0">
      {lines.map((line, index) => {
        const expanded = open.has(line.id)
        // 요소 id 에는 순번을 쓴다. 갱신으로 순번이 바뀌어도 펼침은 줄 id 로 기억한다
        const panelId = `${baseId}-${index}`
        const date = toDate(line.ts)
        return (
          <Fragment key={line.id}>
            <li data-line={line.id} data-fresh={line.fresh ? '' : undefined} className={cn(line.fresh && 'bg-primary-soft/60')}>
              <button
                type="button"
                aria-expanded={expanded}
                aria-controls={panelId}
                onClick={() => toggle(line.id)}
                className="flex min-h-11 w-full cursor-pointer items-center gap-2 border-0 bg-transparent px-3 py-2 text-left text-xs text-ink"
              >
                <span aria-hidden="true" className="inline-block w-3 shrink-0 text-ink-muted">
                  {expanded ? '▾' : '▸'}
                </span>
                <time dateTime={date?.toISOString()} className="shrink-0 font-mono tabular-nums">
                  {cardTime(line.ts)}
                </time>
                <span className="shrink-0 text-ink-muted">
                  <UntrustedText value={kindLabel(line.kind)} max={32} clip />
                </span>
                <span className="min-w-0 flex-1 truncate font-mono" title={line.src_ip ? revealHidden(line.src_ip) : undefined}>
                  <UntrustedText value={line.src_ip} max={45} clip fallback="—" />
                </span>
                <span className="max-w-24 shrink-0 truncate font-medium tabular-nums">
                  <UntrustedText value={lineCode(line)} max={32} clip />
                </span>
              </button>
              {expanded && (
                <dl id={panelId} className="m-0 grid grid-cols-[4rem_minmax(0,1fr)] gap-x-2 gap-y-1 px-3 pb-2 text-xs">
                  <dt className="text-ink-muted">출발지</dt>
                  <dd className="m-0 font-mono break-all">
                    <UntrustedText value={line.src_ip} max={64} fallback="—" />
                  </dd>
                  {line.kind === 'web' ? (
                    <>
                      <dt className="text-ink-muted">경로</dt>
                      <dd className="m-0 font-mono break-all">
                        <UntrustedText value={line.http_method} max={16} fallback="—" /> <UntrustedText value={line.url} max={URL_MAX} fallback="—" />
                        <PasswordBadge line={line} />
                      </dd>
                      <dt className="text-ink-muted">UA</dt>
                      <dd className="m-0 break-all">
                        <UntrustedText value={line.user_agent} max={TEXT_MAX} fallback="—" />
                      </dd>
                    </>
                  ) : (
                    <>
                      <dt className="text-ink-muted">사용자</dt>
                      <dd className="m-0 font-mono break-all">
                        <UntrustedText value={line.username} max={64} fallback="사용자 없음" />
                        <PasswordBadge line={line} />
                      </dd>
                      <dt className="text-ink-muted">요약</dt>
                      <dd className="m-0 break-all">
                        <UntrustedText value={line.message} max={TEXT_MAX} fallback="—" />
                      </dd>
                    </>
                  )}
                  <dt className="text-ink-muted">포트</dt>
                  <dd className="m-0 font-mono tabular-nums">{typeof line.src_port === 'number' ? line.src_port : '—'}</dd>
                </dl>
              )}
            </li>
            {gaps.has(line.id) && (
              <li data-gap="" className="bg-warning-soft px-3 py-1 text-center">
                <Gap />
              </li>
            )}
          </Fragment>
        )
      })}
    </ul>
  )
}
