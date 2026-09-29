import { Link } from 'react-router'
import type { ControlHealthView, MonitorItem } from '@/api/health'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { StatusDot, type Signal } from '../../atoms/StatusDot'

/** 사이드바 · 상단바가 그릴 관제 상태. api/health 의 controlHealthView 결과(띠와 같은 판정)다 */
export type OpsView = ControlHealthView

export interface OpsSummaryProps {
  view: OpsView
  /** 모바일 상단바용 짧은 표기('이상 2') */
  compact?: boolean
  /** 누름(서랍은 닫고 메뉴 단추로 초점을 돌린다. Brand · NavMenu 와 같다) */
  onClick?: () => void
  className?: string
}

/** 항목 이름. 서버 글자라 말풍선에는 revealHidden 으로 넣는다 */
function itemName(item: MonitorItem): string {
  return typeof item.label === 'string' && item.label !== '' ? item.label : item.key
}

function summaryOf(view: OpsView, compact: boolean): { kind: string; signal: Signal; text: string; title?: string } {
  if (view.state === 'pending') return { kind: 'pending', signal: 'idle', text: compact ? '관제 —' : '관제 상태 조회 전' }
  if (view.state === 'error') return { kind: 'error', signal: 'warn', text: compact ? '확인 불가' : '관제 상태 확인 불가' }
  const n = view.alerts.length
  if (n > 0) {
    return { kind: 'alert', signal: 'warn', text: compact ? `이상 ${n}` : `관제 이상 ${n}`, title: revealHidden(view.alerts.map(itemName).join(' · ')) }
  }
  if (view.unknowns.length > 0) return { kind: 'unknown', signal: 'idle', text: compact ? '일부 미확인' : '관제 상태 일부 미확인' }
  return { kind: 'ok', signal: 'idle', text: compact ? '이상 없음' : '관제 이상 없음' }
}

/**
 * 관제 이상 요약(#72). 사이드바 · 서랍 아래와 모바일 상단바에 둔다. 누르면 대시보드(관제 이상 띠)로 간다.
 * 판정은 대시보드 띠와 같다(GET /api/dashboard/monitor · 조회 실패면 이전 값 대신 '확인 불가').
 * 모든 화면에 늘 있는 조각이라 role status · alert · aria-live 를 두지 않는다(본문 상태 화면과 섞이지 않게).
 */
export function OpsSummary({ view, compact = false, onClick, className }: OpsSummaryProps) {
  const { kind, signal, text, title } = summaryOf(view, compact)
  return (
    <Link
      to="/"
      onClick={onClick}
      data-ops={kind}
      data-signal={signal}
      title={title}
      className={cn('inline-flex min-w-0 items-center gap-2 text-xs text-ink-muted hover:text-ink', className)}
    >
      <StatusDot signal={signal} />
      <span className="truncate">{text}</span>
    </Link>
  )
}
