import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { BlockCounts, PointCounts, Summary } from '@/api/monitoring'
import { cn } from '@/lib/cn'
import { formatDuration } from '@/lib/time'
import { Badge } from '../../atoms/Badge'
import { Card } from '../../atoms/Card'
import { InfoTip } from '../../molecules/InfoTip'
import { undeterminedHref } from './target-format'

export interface DashboardMetricsProps {
  summary: Summary
  /** 요약 갱신이 실패해 이전 결과를 보이는 중(오른쪽 위에 '이전 결과') */
  stale?: boolean
  className?: string
}

/**
 * 미판정 수치 네 칸(가장 오래된 미판정 · 미판정 · 판정 목표 초과 · 활성 차단 요청).
 * 활성 차단 칸은 지점별(AWS 관문 · 내부 방화벽) 적용 · 실패 · 미확인 두 줄이다(#72). 칸 이름의 요청 수에는 집행 제외가 들어 있어
 * 두 줄 합과 다르므로, 아래 줄 맨 앞에 집행 제외 수를 둔다. 집행기 확인이 멈춘 지점은 그 줄 끝에 멈춤을 붙인다(서버가 적용 · 실패를 미확인에 합쳤다).
 * 생존 신호 표를 읽을 수 없어 합친 것(unreadable)은 멈춤이 아니라 '집행 확인 불가' 다(#82). 서버 까닭은 말풍선으로 본다.
 * 이전 서버(지점별 없음)는 집행 확인 · 대기 · 제외 한 줄, 그보다 앞선 서버는 요청 수와 '집행 상태 미확인' 이다.
 * 계산 기준(판정 목표 · 첫 사건)은 값 옆 도움말(ⓘ)에 둔다.
 * 좁으면(md 미만) 2열이고 가장 오래된 미판정 · 활성 차단 칸은 두 열 폭이다(빈 칸이 생기지 않게).
 * 미판정 칸 아래 줄의 '미결 N건'(#83)은 최신 판정이 사람이 남긴 미결인 사건이고 미결 목록으로 잇는다. 0 이면 적지 않는다.
 */
export function DashboardMetrics({ summary: data, stale = false, className }: DashboardMetricsProps) {
  const points = Array.isArray(data.blocks_by_point) && data.blocks_by_point.length > 0 ? data.blocks_by_point : null
  const note = [points ? excludedNote(data.blocks) : undefined, mismatchNote(data.blocks), absorbedNote(data.absorbed_unblocked)].filter(Boolean).join(' · ') || undefined
  return (
    <Card padding="none" className={cn('relative', className)} data-stale={stale ? '' : undefined}>
      {stale && (
        <Badge tone="warning" className="absolute top-2 right-2" data-stale-badge="">
          이전 결과
        </Badge>
      )}
      {/* 칸 사이 세로선: 넓으면 칸마다, 좁으면(2열) 미판정 · 판정 목표 초과 사이에만(카드 가장자리에 선이 붙지 않게) */}
      <dl className="m-0 grid grid-cols-2 divide-line md:grid-cols-[1fr_1fr_1fr_1.5fr] md:divide-x">
        <Metric label="가장 오래된 미판정" value={data.pending.total ? formatDuration(data.pending.oldest_seconds * 1000) : '없음'} warn={data.pending.overdue > 0} className="col-span-2 md:col-span-1" />
        <Metric label="미판정" value={`${data.pending.total.toLocaleString()}건`} href="/incidents?judged=false" className="max-md:border-r max-md:border-line"
          note={undeterminedNote(data.pending.undetermined)} tip={data.pending.undetermined ? { at: 'note', label: '미결', content: UNDETERMINED_NOTE } : undefined} />
        <Metric label="판정 목표 초과" value={`${data.pending.overdue.toLocaleString()}건`} note={`목표 임박 ${data.pending.warning.toLocaleString()}건`} warn={data.pending.overdue > 0}
          tip={{ at: 'label', label: '판정 목표', content: VERDICT_TARGET_NOTE }} />
        <Metric label={`활성 차단 요청 ${data.blocked_ips.toLocaleString()}건`} value={points ? <PointLines points={points} /> : blocksValue(data.blocks, data.blocked_ips)} href="/blocklist"
          size={points ? 'sm' : data.blocks ? 'base' : 'xl'} note={note}
          tip={absorbedNote(data.absorbed_unblocked) ? { at: 'note', label: '첫 사건', content: FIRST_INCIDENT_NOTE } : undefined}
          warn={!!data.absorbed_unblocked?.sources || !!data.blocks?.mismatch} className="col-span-2 md:col-span-1" />
      </dl>
    </Card>
  )
}

/** 지점별 두 줄(관문 · 내부 방화벽, 서버 순서). 0 도 적는다(적용 · 실패 · 미확인의 합이 요청 수를 설명한다) */
function PointLines({ points }: { points: readonly PointCounts[] }) {
  const n = (v: number) => (Number.isFinite(v) ? v : 0).toLocaleString('ko-KR')
  return (
    <>
      {points.map((p) => (
        // 좁은 칸에서도 낱말 가운데서 끊지 않는다(멈춤 표지는 통째로 다음 줄로 간다)
        <span key={p.point} className="block break-keep" data-block-point={p.point}>
          {`${p.label || p.point} 적용 ${n(p.applied)} · 실패 ${n(p.failed)} · 미확인 ${n(p.unverified)}`}
          {p.stalled && (
            <>
              {' '}
              <span className={cn('whitespace-nowrap', p.unreadable === true ? 'text-ink-muted' : 'text-warning')} data-block-stalled={p.unreadable === true ? 'unreadable' : ''} title={p.stalled}>
                {p.unreadable === true ? '· 집행 확인 불가' : '· 집행기 멈춤'}
              </span>
            </>
          )}
        </span>
      ))}
    </>
  )
}

/**
 * 활성 차단 요청을 집행 상태로 나눈 값(이슈 #47). 요청 수 하나만 크게 보이면 실제로 막은 수로 읽힌다.
 * 관문이 반영한 것은 집행 확인뿐이다. 이전 서버(집행 상태 없음)는 요청 수와 '집행 상태 미확인' 을 보인다
 */
function blocksValue(blocks: BlockCounts | undefined, total: number): string {
  if (!blocks) return `${total.toLocaleString()}건 · 집행 상태 미확인`
  return `집행 확인 ${blocks.enforced.toLocaleString()} · 대기 ${blocks.pending.toLocaleString()} · 제외 ${blocks.excluded.toLocaleString()}`
}

/** 집행 제외(차단 금지 대역 등). 요청 수에는 들고 지점별 두 줄에는 없다. 0 이면 적지 않는다 */
function excludedNote(blocks: BlockCounts | undefined): string | undefined {
  return blocks?.excluded ? `집행 제외 ${blocks.excluded.toLocaleString()}건` : undefined
}

/** 관문 불일치. 요청과 관문 상태가 5분 넘게 다르다(집행기 · 관문 동기화 확인) */
function mismatchNote(blocks: BlockCounts | undefined): string | undefined {
  return blocks?.mismatch ? `관문 불일치 ${blocks.mismatch.toLocaleString()}건` : undefined
}

/** 판정 뒤에 흡수됐는데 차단이 없는 출발지. 첫 사건 상세의 함께 차단(후속 차단)으로 막는다 */
function absorbedNote(unblocked: { sources: number; incidents: number } | undefined): string | undefined {
  if (!unblocked?.sources) return undefined
  return `판정 뒤 흡수 미차단 ${unblocked.sources.toLocaleString()}곳 · 첫 사건 ${unblocked.incidents.toLocaleString()}건`
}

/** 미결(#83): 판정 없음과 따로 센다. 숫자는 미결 사건 목록으로 잇는다 */
function undeterminedNote(n: number | undefined): ReactNode {
  if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) return undefined
  return (
    <Link to={undeterminedHref()} data-undetermined-link="">
      미결 {n.toLocaleString()}건
    </Link>
  )
}

const UNDETERMINED_NOTE = '최신 판정이 사람이 남긴 미결인 사건입니다. 시스템 전환 처리 제외.'

/** 판정 목표 초과 · 목표 임박의 기준(lib/domain verdictTargetSeconds · WARN_RATIO, app/dashboard.py PENDING 과 같다) */
const VERDICT_TARGET_NOTE = '판정 목표는 critical 1시간 · high 4시간 · medium 12시간 · low 24시간이고, 관제 자기 탐지(R2xx) 사건은 1시간입니다. 목표 임박은 목표 시간의 2/3 를 넘긴 사건입니다.'
const FIRST_INCIDENT_NOTE = '첫 사건은 같은 페이로드의 출발지를 흡수한 사건입니다. 그 사건 상세의 함께 차단으로 막습니다.'

/** 값 옆 도움말(ⓘ). label: 수치 이름 옆 · note: 아래 한 줄 끝. 설명은 칸 맨 아래에 펼친다 */
interface MetricTip {
  at: 'label' | 'note'
  label: string
  content: ReactNode
}

const VALUE_SIZE = { xl: 'text-xl', base: 'text-base', sm: 'text-sm' } as const

function Metric({ label, value, note, href, warn, size = 'xl', tip, className }: { label: string; value: ReactNode; note?: ReactNode; href?: string; warn?: boolean; size?: keyof typeof VALUE_SIZE; tip?: MetricTip; className?: string }) {
  const cell = (button?: ReactNode, panel?: ReactNode) => <div className={cn('min-w-0 px-4 py-4', className)}>
    <dt className="text-xs text-ink-muted">{label}{tip?.at === 'label' && <> {button}</>}</dt>
    <dd className={cn('m-0 mt-1.5 break-words font-semibold tracking-heading tabular-nums', VALUE_SIZE[size], warn && 'text-warning')}>{href ? <Link to={href}>{value}</Link> : value}</dd>
    {note && <div className="mt-1 text-xs text-ink-muted">{note}{tip?.at === 'note' && <> {button}</>}</div>}
    {panel}
  </div>
  if (!tip) return cell()
  return <InfoTip label={tip.label} render={({ button, panel }) => cell(button, panel)}>{tip.content}</InfoTip>
}
