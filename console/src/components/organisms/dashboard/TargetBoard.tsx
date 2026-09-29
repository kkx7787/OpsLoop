import { useId, useState, useSyncExternalStore } from 'react'
import { useCtiBadges, type CtiBadge } from '@/api/cti'
import { describeError } from '@/api/errors'
import { isTargetsNotDeployed, targetKind, type Target, type TargetId, type TargetsResult } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import { Button } from '../../atoms/Button'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'
import { ApiErrorState } from '../states/ApiErrorState'
import { LoadingState } from '../states/LoadingState'
import { COLLECTION_LABEL, COLLECTION_TONE, collectionState, LABEL_MAX, orderTargets, pendingText } from './target-format'
import { TargetCard } from './TargetCard'

export interface TargetBoardProps {
  /** GET /api/dashboard/targets 응답. 없으면 첫 조회 중이거나 실패다 */
  data: TargetsResult | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  /** 마지막 성공 조회 시각(ms) */
  updatedAt: number
  onRetry: () => void
  className?: string
}

/** Tailwind 의 sm 과 같다. 이보다 좁으면 카드를 접힌 요약으로 보인다 */
const WIDE_QUERY = '(min-width: 640px)'

function subscribe(onChange: () => void): () => void {
  if (typeof window.matchMedia !== 'function') return () => undefined
  const mq = window.matchMedia(WIDE_QUERY)
  mq.addEventListener('change', onChange)
  return () => mq.removeEventListener('change', onChange)
}

/** 대상 카드 격자. 열 수 계산은 아래 body 주석. gap-3(0.75rem) 이 식의 틈과 같아야 한다 */
const TARGET_GRID =
  'grid gap-3 grid-cols-[repeat(auto-fill,minmax(max(15rem,min(18.75rem,calc((100%_-_0.75rem)/2)),calc((100%_-_2.25rem)/4)),1fr))]'

/** matchMedia 가 없는 환경(시험)은 넓은 화면으로 본다(useIsDesktop 과 같은 기준) */
function snapshot(): boolean {
  if (typeof window.matchMedia !== 'function') return true
  return window.matchMedia(WIDE_QUERY).matches
}

/** 카드 · 접힌 요약 가운데 하나만 그린다(둘 다 DOM 에 두면 낭독 순서가 겹친다) */
function useWide(): boolean {
  return useSyncExternalStore(subscribe, snapshot, () => true)
}

/**
 * 관제 대상 상태판(#52). 대시보드 맨 위에 고정 대상 네 곳(AWS 센서 · web-01 · 관제 콘솔 · 데이터 노드)과
 * 그 뒤에 등록 노드 카드(#64, 수집 노드 표에 등록한 노드)를 둔다.
 * 데스크톱은 카드 그리드(sm 이상 두 개 · 2xl 이상 네 개씩, 카드가 늘면 다음 줄로), 모바일은 대상마다 한 줄(이름 · 수집 상태 · 미판정)로
 * 접어 두고 누르면 카드를 펼친다. 등록 노드가 늘어도 접힌 줄만 늘어 가장 오래된 미판정이 첫 화면 가까이에 남는다.
 * 조회 실패는 이 자리만 오류로 보인다. 아래 수치 · 판정 대기열은 따로 조회하므로 막지 않는다.
 * 카드 합이 전체와 다른 까닭은 제목 옆 도움말(ⓘ)에 둔다(카드를 받았을 때만).
 * 최근 사건의 CVE 배지는 목록과 같은 조회(useCtiBadges)로 카드마다의 최근 사건을 한 번에 받는다.
 */
export function TargetBoard({ data, pending, fetching, error, updatedAt, onRetry, className }: TargetBoardProps) {
  const titleId = useId()
  const wide = useWide()
  const targets = orderTargets(data?.targets ?? [])
  const latestKeys = targets.flatMap((t) => (t.security?.latest ? [t.security.latest.incident_key] : []))
  const badges = useCtiBadges(latestKeys).data?.badges
  const asOf = toDate(data?.as_of)?.getTime() ?? updatedAt

  let body
  if (!data) {
    body = pending ? (
      <LoadingState title="관제 대상을 불러오는 중입니다" lines={2} />
    ) : isTargetsNotDeployed(error) ? (
      <p className="m-0 rounded-card bg-surface px-4 py-3 text-xs text-ink-muted shadow-card" data-targets-missing="">
        {describeError(error)}
      </p>
    ) : (
      <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} titleAs="h3" />
    )
  } else if (wide) {
    body = (
      // 카드 열 수는 화면 폭 구간이 아니라 이 격자의 실제 폭(사이드바를 뺀 본문)으로 정한다. 카드 최소 폭 300px(18.75rem) —
      //   이보다 좁으면 줄바꿈이 늘어 카드가 급히 길어진다(실측). 한 줄에 최대 4개(각 칸이 격자의 1/4 이상), 카드가 보이는 폭에서는
      //   최소 2개(사이드바가 생기는 768 ~ 880 에서만 240px 까지 내려간다). 넓을수록 4 → 3 → 2 개, 640px 미만은 접힌 목록이다
      <div className={TARGET_GRID}>
        {targets.map((target) => (
          <TargetCard key={target.id} target={target} asOf={asOf} cti={badgeOf(badges, target)} />
        ))}
      </div>
    )
  } else {
    body = <FoldedTargets targets={targets} asOf={asOf} badges={badges} />
  }

  return (
    <section aria-labelledby={titleId} className={cn('flex min-w-0 flex-col gap-2', className)}>
      {data ? (
        <InfoTip
          label="관제 대상"
          render={({ button, panel }) => (
            <>
              <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
                <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
                  관제 대상
                </h2>
                {button}
              </div>
              {panel}
            </>
          )}
        >
          카드 수치는 대상별입니다. 한 사건이 여러 대상에 걸칠 수 있어 합이 전체와 다릅니다.
        </InfoTip>
      ) : (
        <h2 id={titleId} className="m-0 text-sm font-semibold tracking-heading">
          관제 대상
        </h2>
      )}
      {data && error ? (
        <div role="status" className="flex flex-wrap items-center gap-2 rounded-panel bg-warning-soft px-3 py-2 text-xs text-warning">
          <span className="min-w-0 flex-1">
            <strong className="font-semibold">대상 카드를 갱신하지 못했습니다</strong> · {describeError(error)} · 이전 결과 유지
            {updatedAt > 0 && (
              <>
                {' '}
                · 마지막 조회 <Time value={updatedAt} format="time" zone />
              </>
            )}
          </span>
          <Button size="sm" onClick={onRetry} loading={fetching}>
            다시 조회
          </Button>
        </div>
      ) : null}
      {body}
      {/* 기준 시각은 페이지 머리 하나만 둔다 */}
      {data && (data.unmapped.incidents_1h > 0 || data.unmapped.pending > 0) && (
        <p className="m-0 text-xs font-medium text-ink" data-unmapped="">
          대상 미분류 사건: 최근 1시간 {data.unmapped.incidents_1h.toLocaleString('ko-KR')} · 미판정 {data.unmapped.pending.toLocaleString('ko-KR')}
        </p>
      )}
    </section>
  )
}

/** 모바일: 대상마다 한 줄(이름 · 수집 상태 · 미판정). 누르면 그 자리에 카드를 펼친다. 여러 개를 함께 펼칠 수 있다 */
function FoldedTargets({ targets, asOf, badges }: { targets: Target[]; asOf: number; badges: Readonly<Record<string, CtiBadge>> | undefined }) {
  const [open, setOpen] = useState<ReadonlySet<TargetId>>(() => new Set())
  const baseId = useId()
  const toggle = (id: TargetId) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  return (
    <ul aria-label="관제 대상 요약" className="m-0 flex list-none flex-col divide-y divide-line rounded-card bg-surface p-0 shadow-card">
      {targets.map((target, index) => {
        const state = collectionState(target.collection.state)
        const expanded = open.has(target.id)
        // id 속성에는 순번을 쓴다(등록 노드 id 를 요소 id 에 넣지 않는다)
        const panelId = `${baseId}-${index}`
        return (
          <li key={target.id} data-target-summary={target.id}>
            <button
              type="button"
              aria-expanded={expanded}
              aria-controls={panelId}
              onClick={() => toggle(target.id)}
              className="flex min-h-11 w-full cursor-pointer items-center gap-2 border-0 bg-transparent px-3 py-2 text-left text-sm text-ink"
            >
              <span aria-hidden="true" className="inline-block w-3 shrink-0 text-ink-muted">
                {expanded ? '▾' : '▸'}
              </span>
              <span className="min-w-0 flex-1 truncate font-medium" title={targetKind(target) === 'node' ? revealHidden(target.label) : undefined}>
                <UntrustedText value={target.label} max={LABEL_MAX} clip />
              </span>
              <Badge tone={COLLECTION_TONE[state]} className="shrink-0">
                {COLLECTION_LABEL[state]}
              </Badge>
              <span className="shrink-0 text-xs tabular-nums text-ink-muted">{pendingText(target)}</span>
            </button>
            {expanded && (
              <div id={panelId} className="pb-1">
                <TargetCard target={target} asOf={asOf} cti={badgeOf(badges, target)} variant="inline" />
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}

/** 최근 사건의 배지. 자기 속성만 본다 */
function badgeOf(badges: Readonly<Record<string, CtiBadge>> | undefined, target: Target) {
  const key = target.security?.latest?.incident_key
  return key && badges && Object.hasOwn(badges, key) ? badges[key] : undefined
}
