import type { ReactNode } from 'react'
import type { DeviceLogsResult } from '@/api/device-logs'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'
import { lineTimeText, missingTimeText } from './log-format'

export interface LogTimesProps {
  data: Pick<DeviceLogsResult, 'as_of' | 'times' | 'window_days' | 'limit'>
  /** 일시정지 중이면 화면 갱신 칸에 '5초마다' 대신 '일시정지' */
  paused: boolean
  className?: string
}

/** 상대 시각(기준 as_of)과 KST 시:분:초. 값이 없으면 대신 보일 글 */
function At({ value, asOf, empty }: { value: string | null | undefined; asOf: number | undefined; empty: string }) {
  if (!value) return <span className="text-ink-muted">{empty}</span>
  return (
    <span>
      <Time value={value} format="relative" now={asOf} className="font-medium" />
      <span className="text-ink-muted">
        {' · '}
        <Time value={value} format="time" />
      </span>
    </span>
  )
}

function Cell({ name, title, children }: { name: string; title: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5" data-time={name}>
      <dt className="text-2xs font-medium text-ink-muted">{title}</dt>
      <dd className="m-0 flex min-w-0 flex-col gap-0.5">{children}</dd>
    </div>
  )
}

/**
 * 시각(#73)을 따로 둔다: 마지막 적재(nodes.last_loaded_at) · 로그 종류별 마지막 줄(receipt) · 마지막 탐지(이 장비 규칙 버전) · 화면 갱신 주기.
 * '화면 5초 갱신' 이 '로그 5초 도착' 으로 읽히지 않게 화면 갱신은 적재와 다른 칸에 두고, 계산 기준은 ⓘ 에 접는다(#65).
 * 화면 기준 시각(as_of)은 여기 두지 않고 제목 줄 새로고침 옆 하나만 둔다(#79). 이 칸은 주기(5초마다 · 일시정지)만 보인다.
 * 탐지 멈춤은 본문(배지 · 서버 까닭)에 둔다. 서버 까닭에는 규칙 버전 이름(DB 값)이 들어가 비신뢰 문자열로 그린다.
 */
export function LogTimes({ data, paused, className }: LogTimesProps) {
  const { times } = data
  // 상대 시각의 기준은 DB 시각(as_of)이다. 해석할 수 없으면 Time 이 브라우저 시각으로 센다
  const asOf = toDate(data.as_of)?.getTime()
  const detect = times.detect
  const versions = Array.isArray(detect.versions) ? detect.versions : []
  return (
    <InfoTip
      label="시각 기준"
      panelAs="div"
      render={({ button, panel }) => (
        <section aria-label="시각" className={cn('flex min-w-0 flex-col gap-2 rounded-card bg-surface px-3 py-2 shadow-card', className)}>
          <h2 className="m-0 text-xs font-medium text-ink-muted">시각 {button}</h2>
          <dl className="m-0 grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 xl:grid-cols-4">
            <Cell name="loaded" title="마지막 적재">
              <At value={times.loaded_at} asOf={asOf} empty={missingTimeText(times.state)} />
            </Cell>
            <Cell name="lines" title="마지막 원본 줄">
              {times.lines.map((line) => {
                const text = lineTimeText(times.state, line)
                return (
                  <span key={line.key} data-time-line={line.key}>
                    {line.label}{' '}
                    {text === null ? <At value={line.last_line_at} asOf={asOf} empty="기록 없음" /> : <span className="text-ink-muted">{text}</span>}
                  </span>
                )
              })}
            </Cell>
            <Cell name="detect" title="마지막 탐지">
              <span>
                <At value={detect.last_at} asOf={asOf} empty="기록 없음" />
                {detect.stale && (
                  <Badge tone="warning" className="ml-1.5" data-detect-stale="">
                    멈춤
                  </Badge>
                )}
              </span>
              {detect.stale && detect.reason && (
                <span className="text-2xs text-ink-muted" data-detect-reason="">
                  <UntrustedText value={detect.reason} max={200} />
                </span>
              )}
            </Cell>
            <Cell name="refreshed" title="화면 갱신">
              <span className="font-medium">{paused ? '일시정지' : '5초마다'}</span>
            </Cell>
          </dl>
          <p className="m-0 mt-2 text-xs text-ink-muted">원본 줄은 에이전트가 읽은 기록 기준입니다. 아래 목록에서 제외되는 기록도 포함합니다.</p>
          {panel}
        </section>
      )}
    >
      <ul className="m-0 flex list-disc flex-col gap-0.5 pl-4">
        <li>마지막 적재: 1분 적재 회차가 이 장비의 새 줄을 넣은 시각입니다.</li>
        <li>
          마지막 탐지: 적재 뒤 탐지 회차의 실행 시각으로, 이 장비 규칙 버전 중 가장 오래된 것이 기준입니다
          {versions.length > 0 && (
            <>
              {' ('}
              {versions.map((v, i) => (
                <span key={`${v.rule_version ?? ''}-${i}`} data-detect-version={v.rule_version ?? ''}>
                  {i > 0 && ' · '}
                  <UntrustedText value={v.rule_version} max={40} fallback="버전 없음" />{' '}
                  {v.last_at ? <Time value={v.last_at} format="relative" now={asOf} /> : '기록 없음'}
                </span>
              ))}
              {')'}
            </>
          )}
          .
        </li>
        <li>화면 갱신: 5초마다 다시 받는 주기이며 새 줄 도착 주기가 아닙니다.</li>
        <li>목록 시각은 장비가 적은 요청 시각, 마지막 줄은 에이전트가 읽은 시각입니다(목록에 없는 시험 · 형식 밖 · sshd 외 줄도 셉니다).</li>
        <li>
          한 번에 최근 {data.window_days.toLocaleString('ko-KR')}일 안 최신 {data.limit.toLocaleString('ko-KR')}줄을 받습니다.
        </li>
      </ul>
    </InfoTip>
  )
}
