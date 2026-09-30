import type { Ref } from 'react'
import type { DeviceLogLine } from '@/api/device-logs'
import { cn } from '@/lib/cn'
import { formatKst, toDate } from '@/lib/time'
import { revealHidden } from '@/lib/untrusted'
import { Skeleton } from '../../atoms/Skeleton'
import { UntrustedText } from '../../atoms/UntrustedText'
import { futureText, kindLabel, kindShort, lineCode, logTime, requestText } from '../device-logs/log-format'

/**
 * 상자 안 상태.
 *  lines    줄(0줄이면 '최근 n일 로그 없음')
 *  loading  첫 조회 중(뼈대 10줄)
 *  message  줄 대신 한 줄 글(조회 실패 · 없는 장비 · 배포 전 · 장비 로그 대상 아님)
 */
export type CardLogBoxView =
  | { kind: 'lines'; lines: readonly DeviceLogLine[]; future: number; windowDays: number; asOf: string; stale: boolean }
  | { kind: 'loading' }
  | { kind: 'message'; text: string; tone?: 'muted' | 'warning' }

export interface CardLogBoxProps {
  view: CardLogBoxView
  /** 상자 이름이 될 요소 id 들(카드 제목 · 로그 머리 → '{이름} 최근 로그'). 노드 이름(비신뢰)을 aria-label 문자열에 넣지 않는다 */
  labelledBy: string
  /** 화면에 보이는지 재는 자리(자동 갱신은 이 상자가 보일 때만) */
  boxRef?: Ref<HTMLDivElement>
}

/** 카드에 보이는 최대 줄 수. 서버에 10줄만 묻지만 더 와도 자른다 */
export const CARD_LOG_ROWS = 10

/** 열 이름 칸. 24px(글 16 + 위아래 4) */
const TH = 'sticky top-0 z-[1] bg-surface px-1.5 py-1 text-left text-2xs font-medium whitespace-nowrap text-ink-muted shadow-hairline first:pl-3 last:pr-3'
/** 줄 칸. 22px(글 18 + 위아래 2). 칸 안 값은 block truncate span 하나 · 한 글꼴(섞으면 22.5px 가 되어 상자에 스크롤이 생긴다) */
const TD = 'px-1.5 py-0.5 align-middle shadow-hairline first:pl-3 last:pr-3'

/**
 * 보호 대상 카드의 최근 로그 상자(#83). 높이 244px(열 이름 24 + 22×10) 고정 · 안쪽 세로 스크롤 · 키보드 초점.
 * 받는 중 · 0줄 · 실패도 같은 높이라 장비가 늘거나 상태가 바뀌어도 카드 높이가 같다. 앞선 시각 줄 안내는 상자 안 첫 줄이다(그때만 스크롤).
 * 열은 카드 폭(컨테이너 28rem)으로만 바꾼다: 넓으면 '웹 접근' · 요청 한 줄, 좁으면 '웹' · 결과만. 전체 요청은 칸 말풍선과 '로그 더 보기' 로 본다.
 * 줄 글자(출발지 · 경로)는 서버가 가린 비신뢰 값이라 UntrustedText 로 그린다. 줄이 늘어나도 낭독 알림(aria-live)은 두지 않는다.
 */
export function CardLogBox({ view, labelledBy, boxRef }: CardLogBoxProps) {
  return (
    <div
      ref={boxRef}
      role="region"
      aria-labelledby={labelledBy}
      // 키보드로도 상자 안을 스크롤할 수 있게 초점을 준다(사건 목록 스크롤 영역과 같다)
      // oxlint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={0}
      data-log-box=""
      data-stale={view.kind === 'lines' && view.stale ? '' : undefined}
      className="h-61 min-w-0 overflow-y-auto focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-primary print:h-auto print:overflow-visible"
    >
      {view.kind === 'lines' ? (
        view.lines.length || view.future > 0 ? (
          <LogTable {...view} />
        ) : (
          <p className="m-0 flex h-full items-center justify-center px-3 text-xs text-ink-muted" data-log-empty="">
            최근 {view.windowDays.toLocaleString('ko-KR')}일 로그 없음
          </p>
        )
      ) : view.kind === 'loading' ? (
        <div className="flex flex-col gap-2.5 px-3 py-3" data-log-loading="">
          <span className="sr-only">최근 로그를 불러오는 중</span>
          {Array.from({ length: CARD_LOG_ROWS }, (_, i) => (
            <Skeleton key={i} className={i % 3 === 2 ? 'w-2/3' : 'w-full'} />
          ))}
        </div>
      ) : (
        <p className={cn('m-0 flex h-full items-center justify-center px-3 text-center text-xs', view.tone === 'warning' ? 'text-warning' : 'text-ink-muted')} data-log-message="">
          {view.text}
        </p>
      )}
    </div>
  )
}

function LogTable({ lines, future, asOf, stale }: Extract<CardLogBoxView, { kind: 'lines' }>) {
  return (
    <table className={cn('w-full table-fixed border-collapse text-xs transition-opacity', stale && 'opacity-50')}>
      <caption className="sr-only">최근 로그 {CARD_LOG_ROWS}줄, 최신 순</caption>
      <colgroup>
        <col className="w-25" />
        <col className="w-10 @md:w-16" />
        <col className="@md:w-36" />
        <col className="w-19 @md:w-auto" />
      </colgroup>
      <thead>
        <tr>
          <th scope="col" className={TH}>
            시각
          </th>
          <th scope="col" className={TH}>
            종류
          </th>
          <th scope="col" className={TH}>
            출발지
          </th>
          <th scope="col" className={TH}>
            <span className="@md:hidden">결과</span>
            <span className="hidden @md:inline">요청 · 결과</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {future > 0 && (
          <tr data-log-future="">
            <td colSpan={4} className="bg-warning-soft px-3 py-0.5 text-2xs text-warning">
              <span className="block truncate" title={futureText(future)}>
                {futureText(future)}
              </span>
            </td>
          </tr>
        )}
        {lines.slice(0, CARD_LOG_ROWS).map((line) => (
          <LogRow key={line.id} line={line} asOf={asOf} />
        ))}
      </tbody>
    </table>
  )
}

/**
 * 넓은 카드의 요청 칸. 웹 줄은 경로만 말줄임하고 끝의 '→ 결과' 는 늘 보인다(긴 경로에 결과 코드가 잘려 숨지 않게).
 * 두 칸 모두 font-mono 한 글꼴이라 줄 높이 22px 를 지킨다. SSH 줄은 결과가 앞이라 한 칸 그대로다
 */
function RequestWide({ line, request }: { line: DeviceLogLine; request: string }) {
  if (line.kind !== 'web') {
    return (
      <span className="hidden truncate font-mono @md:block">
        <UntrustedText value={request} max={200} clip />
      </span>
    )
  }
  return (
    <span className="hidden min-w-0 font-mono @md:flex" data-request="">
      <span className="block min-w-0 truncate">
        <UntrustedText value={`${line.http_method ?? '—'} ${line.url ?? ''}`} max={200} clip />
      </span>
      <span className="block shrink-0 whitespace-pre" data-request-code="">
        {` → ${lineCode(line)}`}
      </span>
    </span>
  )
}

function LogRow({ line, asOf }: { line: DeviceLogLine; asOf: string }) {
  const request = requestText(line)
  const date = toDate(line.ts)
  return (
    <tr data-line={line.id}>
      <td className={TD}>
        <span className="block truncate tabular-nums">
          {date ? (
            <time dateTime={date.toISOString()} title={`${formatKst(date, 'datetime')} KST`}>
              {logTime(line.ts, asOf)}
            </time>
          ) : (
            '—'
          )}
        </span>
      </td>
      <td className={TD}>
        {/* 좁으면 짧은 표기(눈), 전체 이름은 낭독용. 넓으면 전체 이름을 보인다 */}
        <span aria-hidden="true" className="block truncate @md:hidden">
          <UntrustedText value={kindShort(line.kind)} max={16} clip />
        </span>
        <span className="sr-only @md:not-sr-only @md:block @md:truncate">
          <UntrustedText value={kindLabel(line.kind)} max={32} clip />
        </span>
      </td>
      <td className={TD} title={line.src_ip ? revealHidden(line.src_ip) : undefined}>
        <span className="block truncate font-mono">
          <UntrustedText value={line.src_ip} max={45} clip fallback="—" />
        </span>
      </td>
      <td className={TD} title={revealHidden(request)}>
        <span className="block truncate tabular-nums @md:hidden">
          <UntrustedText value={lineCode(line)} max={32} clip />
        </span>
        <RequestWide line={line} request={request} />
      </td>
    </tr>
  )
}
