import type { ReactNode } from 'react'
import type { ActorBlock, BlockExempt } from '@/api/incidents'
import type { BlockCheckers } from '@/api/sources'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { Banner } from '../../molecules/Banner'
import { EnforcePointList } from '../incident-detail/EnforcePointList'
import { BLOCK_STATE_TONE, blockState, blockStateHint, blockStateLabel, enforceRecord, gatewayCheckedAt, LIVE_BLOCK_STATES } from '../incident-detail/format'
import { CHECKER_UNKNOWN_NOTE, checkedPoints, checkersUnknown } from './model'

/**
 * 집행기 확인 멈춤 띠(목록 · 상세). 집행 미확인 경고라 멈춘 지점과 사실만 본문에 한 줄로 둔다.
 * 적용 확인을 '확인 지연'으로 바꾼 까닭은 지점 행 배지 옆 ⓘ(model.CHECKER_STALE_NOTE · EnforcePointList)에 있다
 */
export function CheckerStaleBanner({ points }: { points: readonly string[] }) {
  if (!points.length) return null
  return (
    <Banner tone="warning" title="집행기 확인이 멈췄습니다">
      {points.join(' · ')} · 10분 넘게 확인 없음
    </Banner>
  )
}

/**
 * 출발지의 지금 차단 상태(차단 목록 행 하나). 상태 나눔은 사건 상세 · 차단 목록과 같다(format.blockState · blockStateLabel).
 * now 는 서버 기준 시각(as_of)이다. 브라우저 시계가 달라도 만료를 서버와 같게 가른다.
 * 지점 칸(요청하지 않은 지점은 '미요청'이고 관문 빼기 뒤 확인 전이면 '빠짐 확인 전', 해제 · 만료는 '빠짐 확인 전' · '빠짐')을 붙이되,
 * 집행기 확인이 멈춘 지점의 '적용 확인'은
 * '확인 지연'으로 보인다(model.checkedPoints)
 */
export function SourceBlockCell({ block, checkers, now }: { block: ActorBlock | null; checkers: BlockCheckers | undefined; now: number }) {
  if (!block) return <span className="text-xs text-ink-muted">차단 없음</span>
  const state = blockState(block, now)
  const live = LIVE_BLOCK_STATES.includes(state)
  return (
    <div data-block-state={state} className="flex min-w-0 flex-col gap-1">
      <Badge tone={BLOCK_STATE_TONE[state]} className="self-start">{blockStateLabel(block, state)}</Badge>
      <EnforcePointList compact points={checkedPoints(block, checkers, now)} />
      {live && (
        <span className="text-xs text-ink-muted">
          {block.expires_at ? <>만료 <Time value={block.expires_at} format="short" className="whitespace-nowrap" /></> : '만료 없음'}
        </span>
      )}
    </div>
  )
}

export interface SourceBlockDetailProps {
  block: ActorBlock | null
  checkers: BlockCheckers | undefined
  now: number
  /** 금지 대역에 드는가(목록과 같은 판단: 코드 상수 + block_exempt · model.sourceExempt). 표를 읽을 수 없으면 null */
  exempt: boolean | null
  /** 드는 금지 대역(block_exempt 표의 행) */
  exemptRange: BlockExempt | null
}

/** 상세의 차단 상태: 요청 · 집행 확인 · 만료(해제) · 사유 · 방식 · 집행 메모 · 지점별 결과 · 금지 대역 */
export function SourceBlockDetail({ block, checkers, now, exempt, exemptRange }: SourceBlockDetailProps) {
  const state = block ? blockState(block, now) : null
  const checkedAt = block && state ? gatewayCheckedAt(block, state) : null
  // 관문을 요청하지 않은 행에 남은 관문 방식 · 메모는 보이지 않는다(관문 칸이 대신한다, 이슈 #77)
  const record = block ? enforceRecord(block) : null
  return (
    <div className="flex flex-col gap-3">
      {block && state ? (
        <>
          <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-2 text-sm" data-block-state={state}>
            <Fact label="상태" value={<Badge tone={BLOCK_STATE_TONE[state]}>{blockStateLabel(block, state)}</Badge>} />
            <Fact label="요청" value={<Time value={block.created_at} format="datetime" />} />
            <Fact
              label={checkedAt && state === 'mismatch' ? '마지막 집행 확인' : '집행 확인'}
              value={checkedAt ? <Time value={checkedAt} format="datetime" /> : blockStateHint(block, state)}
            />
            <Fact
              label={block.released_at ? '해제' : '만료'}
              value={block.released_at ? <Time value={block.released_at} format="datetime" /> : block.expires_at ? <Time value={block.expires_at} format="datetime" /> : '만료 없음'}
            />
            <Fact label="사유" value={<UntrustedText value={block.reason} fallback="—" />} />
            <Fact label="방식" value={<UntrustedText value={record?.method} max={64} fallback="—" />} />
            <Fact label="요청자" value={<UntrustedText value={block.requested_by} max={64} fallback="미기록" />} />
          </dl>
          {record?.note && (
            <p className="m-0 text-xs break-words text-ink-muted">
              집행 메모 <UntrustedText value={record.note} />
            </p>
          )}
          <EnforcePointList points={checkedPoints(block, checkers, now)} />
        </>
      ) : (
        <span className="text-sm text-ink-muted">차단한 적 없음</span>
      )}
      {/* 금지 대역이면 어느 대역인지만 적는다('차단하지 않음'은 이름과 같은 말). 표를 읽을 수 없으면 머리 표지('금지 대역 확인 불가')가 알린다 */}
      {(exempt === true || exemptRange) && (
        <p className="m-0 text-xs break-words text-ink-muted" data-block-exempt>
          차단 금지 대역
          {exemptRange && (
            <>
              {' '}
              <span className="font-mono">{exemptRange.cidr}</span>(<UntrustedText value={exemptRange.note} max={64} />)
            </>
          )}
        </p>
      )}
      {checkersUnknown(checkers) && <p className="m-0 text-xs text-ink-muted">{CHECKER_UNKNOWN_NOTE}</p>}
    </div>
  )
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-ink-muted">{label}</dt>
      <dd className="m-0 min-w-0 font-medium break-words tabular-nums">{value}</dd>
    </div>
  )
}
