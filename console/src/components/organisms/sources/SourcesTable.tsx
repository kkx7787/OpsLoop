import { Fragment, type MouseEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import type { BlockCheckers, SourceSummary } from '@/api/sources'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { ColumnHeader } from './ColumnHeader'
import { SourceBlockCell } from './SourceBlock'
import { SourceMarks, TargetNames, VerdictMix } from './SourceBadges'
import { sourceHref } from './model'
import { useReturnTo } from '@/lib/returnTo'

const cell = 'px-4 py-2.5 align-top'
/** 열 이름과 계산 기준(열 머리 ⓘ) */
const HEADERS: ReadonlyArray<readonly [string, string?]> = [
  ['주소'],
  ['사건 · 미판정'],
  ['최고 심각도'],
  ['규칙 · 대상'],
  ['판정 분포', '사건마다 마지막 판정입니다. 같은 페이로드 흡수로 지워진 사건은 세지 않습니다.'],
  ['차단 상태', '지금 차단 목록 행 기준입니다.'],
  ['마지막 사건 (KST)'],
]
/** 규칙 칸에 이름을 늘어놓는 수. 넘는 것은 개수만 */
const RULES_SHOWN = 4

export interface SourcesTableProps {
  items: readonly SourceSummary[]
  /** 서버 기준 시각(as_of, ms). 차단 만료를 이 시각으로 가른다 */
  now: number
  checkers: BlockCheckers | undefined
}

/**
 * 출발지 목록 한 쪽. 행 어디를 눌러도 상세로 간다. 키보드 초점은 주소 링크에 있다.
 * 링크 · 펼치기 단추 · 도움말(ⓘ 단추와 펼친 설명)을 누른 것과 보조키(새 탭) · 글자 드래그는 행 누름으로 보지 않는다.
 * 좁은 화면에서는 responsive-table 이 행을 칸 이름(data-label)과 함께 쌓는다.
 */
export function SourcesTable({ items, now, checkers }: SourcesTableProps) {
  const navigate = useNavigate()
  const origin = useReturnTo('/sources')

  function open(event: MouseEvent<HTMLTableRowElement>, ip: string) {
    if (event.defaultPrevented) return
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    if (event.target instanceof Element && event.target.closest('a, button, summary, [data-infotip]')) return
    if (window.getSelection()?.toString()) return
    void navigate(sourceHref(ip), { state: { returnTo: origin.href } })
  }

  return (
    <table className="responsive-table w-full text-left text-sm" aria-label="출발지 목록">
      <thead className="sticky top-0 z-10 border-b border-line bg-surface text-xs text-ink-muted">
        <tr>
          {HEADERS.map(([label, tip]) => (
            <ColumnHeader key={label} label={label} tip={tip} className={`${cell} font-medium break-keep`} />
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {items.map((item) => (
          // 키보드 · 낭독기의 진입점은 안쪽 주소 링크다(행마다 초점 하나). 행의 onClick 은 마우스 편의라 키 처리기를 두지 않는다
          // oxlint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions
          <tr key={item.ip} data-source-ip={item.ip} onClick={(event) => open(event, item.ip)} className="cursor-pointer hover:bg-primary-soft/60">
            <td className={cell}>
              <Link to={sourceHref(item.ip)} state={{ returnTo: origin.href }} className="font-mono font-semibold break-all">
                {item.ip}
              </Link>
              <div className="mt-1">
                <SourceMarks testSource={item.test_source} exempt={item.exempt} />
              </div>
            </td>
            <td data-label="사건 · 미판정" className={`${cell} whitespace-nowrap tabular-nums`}>
              {item.incidents.toLocaleString('ko-KR')}건
              <div className={item.unjudged > 0 ? 'text-xs font-medium text-warning' : 'text-xs text-ink-muted'}>미판정 {item.unjudged.toLocaleString('ko-KR')}</div>
            </td>
            <td data-label="최고 심각도" className={cell}>
              <SeverityBadge severity={item.severity} />
            </td>
            <td data-label="규칙 · 대상" className={cell}>
              {/* 좁은 칸에서도 규칙 번호 사이에서만 줄을 바꾼다 */}
              <div className="font-mono text-xs">
                {item.rules.slice(0, RULES_SHOWN).map((rule, i) => (
                  <Fragment key={rule}>{i > 0 && ' · '}<span className="whitespace-nowrap">{rule}</span></Fragment>
                ))}
                {item.rules.length > RULES_SHOWN && <span className="font-sans whitespace-nowrap text-ink-muted"> 외 {item.rules.length - RULES_SHOWN}개</span>}
              </div>
              <div className="mt-0.5 text-xs text-ink-muted">
                <TargetNames targets={item.targets} />
              </div>
            </td>
            <td data-label="판정 분포" className={cell}>
              <VerdictMix verdicts={item.verdicts} />
            </td>
            <td data-label="차단 상태" className={cell}>
              <SourceBlockCell block={item.block} checkers={checkers} now={now} />
            </td>
            {/* 사건 시각과 마지막 관측(이벤트)을 따로 적는다. 차단 뒤에도 두드리면 관측이 사건보다 늦다 */}
            <td data-label="마지막 사건 (KST)" className={`${cell} whitespace-nowrap`}>
              <Time value={item.last_ts} format="short" />
              <div className="text-xs text-ink-muted" data-last-seen>
                마지막 관측 <Time value={item.last_seen} format="short" />
              </div>
              <div className="text-xs text-ink-muted">
                첫 사건 <Time value={item.first_ts} format="short" />
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
