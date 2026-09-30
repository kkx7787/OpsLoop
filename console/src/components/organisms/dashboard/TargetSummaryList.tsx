import { useId, useState } from 'react'
import type { CtiBadge } from '@/api/cti'
import { targetKind, type Target, type TargetId } from '@/api/targets'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import { UntrustedText } from '../../atoms/UntrustedText'
import { badgeOf } from './dashboard-layout'
import { ProtectedCard } from './ProtectedCard'
import { headBadge, LABEL_MAX, pendingText, protectedHeadBadge, summaryFlags } from './target-format'
import { TargetCard } from './TargetCard'

export interface TargetSummaryListProps {
  /** 무리 이름(보호 대상 · 관측 센서 · 관제 시스템). 목록 이름은 '{title} 요약' 이다 */
  title: string
  targets: readonly Target[]
  /** 상대 시각의 기준(ms, 응답의 as_of) */
  asOf: number
  /** 페이지가 한 번 받은 최근 사건 CVE 배지 */
  badges: Readonly<Record<string, CtiBadge>> | undefined
  /**
   * 펼칠 카드(#83). protected: 보호 대상 카드(ProtectedCard, 머리 배지 '수집 정상') · full: 관측 센서 · 관제 시스템(TargetCard). 기본 full
   */
  card?: 'protected' | 'full'
  /** 상태판 갱신이 실패해 이전 결과를 보이는 중. 줄마다 배지 끝에 '이전 결과'(접힌 줄이 카드 머리 역할이다) */
  stale?: boolean
  className?: string
}

/**
 * 대상마다 한 줄(이름 · 머리 배지 · 경고 배지 · 미판정)로 접은 목록(#72). 누르면 그 자리에 카드를 펼친다. 여러 개를 함께 펼칠 수 있다.
 * 보호 대상은 새 카드(ProtectedCard inline, #83)를 펼치고, 접혀 있는 동안은 로그를 묻지 않는다.
 * 줄 전체가 단추라 그 안에 링크를 두지 않는다. 링크(미판정 · 최근 사건 · 차단 목록)는 펼친 카드 안에만 있다.
 * 모바일의 보호 대상과, 모든 폭의 관측 센서 · 관제 시스템이 쓴다.
 */
export function TargetSummaryList({ title, targets, asOf, badges, card = 'full', stale = false, className }: TargetSummaryListProps) {
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
    <ul aria-label={`${title} 요약`} className={cn('m-0 flex list-none flex-col divide-y divide-line rounded-card bg-surface p-0 shadow-card', className)}>
      {targets.map((target, index) => {
        const head = card === 'protected' ? protectedHeadBadge(target) : headBadge(target)
        const flags = summaryFlags(target)
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
              <span className="flex min-w-0 flex-wrap items-center justify-end gap-1">
                <Badge tone={head.tone} className="shrink-0" data-head-badge="">
                  {head.label}
                </Badge>
                {flags.map((flag) => (
                  <Badge key={flag.key} tone={flag.tone} className="shrink-0" data-summary-flag={flag.key}>
                    {flag.text}
                  </Badge>
                ))}
                {stale && (
                  <Badge tone="warning" className="shrink-0" data-stale-badge="">
                    이전 결과
                  </Badge>
                )}
              </span>
              <span className="shrink-0 text-xs tabular-nums text-ink-muted">{pendingText(target)}</span>
            </button>
            {expanded && (
              <div id={panelId} className="pb-1">
                {card === 'protected' ? (
                  <ProtectedCard target={target} asOf={asOf} stale={stale} variant="inline" />
                ) : (
                  <TargetCard target={target} asOf={asOf} cti={badgeOf(badges, target)} variant="inline" />
                )}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
