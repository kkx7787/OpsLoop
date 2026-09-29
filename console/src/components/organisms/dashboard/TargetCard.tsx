import { useId, type ReactNode } from 'react'
import { Link } from 'react-router'
import type { CtiBadge as CtiBadgeValue } from '@/api/cti'
import { useLiveState } from '@/api/live-context'
import { consoleLabel } from '@/api/live'
import { targetKind, type Target, type TargetCollection, type TargetLatest, type TargetResponse, type TargetSystem, type TargetVulns } from '@/api/targets'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { CtiBadge } from '../../molecules/CtiBadge'
import { InfoTip } from '../../molecules/InfoTip'
import { incidentHref } from '../incidents/model'
import { assetHref, COLLECTION_LABEL, COLLECTION_TONE, collectionState, LABEL_MAX, latestLog, responseParts, systemText, vulnText } from './target-format'

export interface TargetCardProps {
  target: Target
  /** 상대 시각의 기준(ms). 응답의 as_of(DB 시각)라 브라우저 시계가 어긋나도 같은 값을 보인다 */
  asOf: number
  /** 최근 사건의 CVE 배지(목록과 같은 useCtiBadges 값). 서명 규칙 사건이 아니거나 조회 전이면 없다 */
  cti?: CtiBadgeValue
  /**
   * card   카드 한 장(데스크톱 그리드)
   * inline 모바일 접힌 요약을 펼친 자리. 이름 · 상태는 요약 줄에 있으므로 겉틀과 머리를 빼고 역할만 적는다
   */
  variant?: 'card' | 'inline'
  className?: string
}

/**
 * 관제 대상 카드 한 장(#52): 머리(이름 · 역할 · 수집 상태) 아래에 수집 · 보안 · 최근 사건 · 시스템 · 대응 · 취약점을 한 줄 요약으로 쌓는다.
 * 수집 상태는 서버가 생존 신호로 정한다. 신호가 없는 대상은 마지막 로그 시각을 보이되 색을 입히지 않는다('생존 상태 미확인' 은 배지가 말한다).
 * 판정 근거(수신 없음 기준 · 정상일 때 서버의 까닭 · 정상 보고 시각)는 구역 제목 옆 도움말(ⓘ)에 두고,
 * 수신 없음 · 미확인의 까닭과 보고 문제 · 집행기 멈춤은 본문에 둔다.
 * 콘솔 카드의 현재 콘솔은 실시간 연결(hello)의 이름이다. REST 요청은 콘솔 두 대에 번갈아 가므로 응답의 콘솔 이름은 쓰지 않는다.
 * 등록 노드 카드(#64)는 web-01 카드와 같은 틀이다. 이름(hostname)은 노드가 적어 낸 값이라 비신뢰 문자열로 그리고,
 * 이름이 node_id 와 다르면 역할 옆에 node_id 를 붙여 수집 노드 화면과 맞춰 보게 한다.
 */
export function TargetCard({ target, asOf, cti, variant = 'card', className }: TargetCardProps) {
  const titleId = useId()
  const state = collectionState(target.collection.state)
  const inline = variant === 'inline'
  const kind = targetKind(target)
  return (
    <div
      role="region"
      aria-labelledby={titleId}
      data-target={target.id}
      data-target-kind={kind}
      data-collection={state}
      className={cn('flex min-w-0 flex-col', !inline && 'rounded-card bg-surface shadow-card', className)}
    >
      <div className={cn('flex min-w-0 items-start justify-between gap-2', inline ? 'px-3 pt-1' : 'rounded-t-card border-b border-line bg-canvas/60 px-3 py-2')}>
        <div className="min-w-0">
          <h3 id={titleId} className={cn('m-0 truncate text-md font-semibold tracking-heading', inline && 'sr-only')} title={kind === 'node' ? revealHidden(target.label) : undefined}>
            <UntrustedText value={target.label} max={LABEL_MAX} clip />
          </h3>
          <p className="m-0 break-words text-xs text-ink-muted">
            {target.role}
            {kind === 'node' && target.label !== target.id && (
              <>
                {' · '}
                <span className="font-mono" data-node-id="">
                  <UntrustedText value={target.id} max={64} clip />
                </span>
              </>
            )}
          </p>
        </div>
        {!inline && (
          <Badge tone={COLLECTION_TONE[state]} className="shrink-0" data-collection-badge="">
            {COLLECTION_LABEL[state]}
          </Badge>
        )}
      </div>
      <dl className="m-0 flex min-w-0 flex-col divide-y divide-line">
        <Row title="수집" tip={collectionTip(target.collection)}>
          <CollectionFacts target={target} collection={target.collection} asOf={asOf} />
        </Row>
        <Row title="보안">
          <SecurityFacts target={target} />
        </Row>
        <Row title="최근 사건">
          <LatestLine latest={target.security.latest} asOf={asOf} cti={cti} />
        </Row>
        <Row title="시스템">
          <SystemFacts system={target.system} asOf={asOf} />
        </Row>
        <Row title="대응" tip={responseTip(target.response, asOf)}>
          <ResponseFacts response={target.response} />
        </Row>
        <Row title="취약점">
          <VulnFacts vulns={target.vulns} asOf={asOf} />
        </Row>
      </dl>
    </div>
  )
}

interface RowTip {
  /** 단추 낭독 이름('{label} 설명') */
  label: string
  content: ReactNode
}

/** 구역 한 칸: 왼쪽 작은 제목 · 오른쪽 한 줄 요약. 도움말(ⓘ)은 제목 옆에 두고 설명은 요약 아래에 펼친다 */
function Row({ title, tip, children }: { title: string; tip?: RowTip | null; children: ReactNode }) {
  const cells = (button?: ReactNode, panel?: ReactNode) => (
    <div className="grid min-w-0 grid-cols-[3.25rem_minmax(0,1fr)] gap-x-2 px-3 py-1.5">
      <dt className="pt-px text-2xs font-medium text-ink-muted">
        {title}
        {button && <> {button}</>}
      </dt>
      <dd className="m-0 flex min-w-0 flex-col gap-0.5 text-xs">
        {children}
        {panel}
      </dd>
    </div>
  )
  if (!tip) return cells()
  return <InfoTip label={tip.label} render={({ button, panel }) => cells(button, panel)}>{tip.content}</InfoTip>
}

/** 서버가 정상 · 요청 없음으로 판정했다(까닭이 배지 · 신호 줄과 같은 말이라 도움말로 보낸다) */
function settled(collection: TargetCollection): boolean {
  const state = collectionState(collection.state)
  return state === 'ok' || state === 'quiet'
}

/** 수집 구역 도움말: 수신 없음 기준과, 정상 · 요청 없음일 때의 서버 까닭. 둘 다 없으면 단추를 두지 않는다 */
function collectionTip(collection: TargetCollection): RowTip | null {
  const signal = collection.signal
  const reason = settled(collection) && collection.reason ? collection.reason : null
  if (!signal && !reason) return null
  return {
    label: '수집 상태',
    content: (
      <>
        {signal && <span className="block">{Math.round(signal.stale_after_seconds / 60)}분 넘게 새 신호가 없으면 수신 없음입니다.</span>}
        {signal && reason && ' '}
        {/* 까닭에는 기록한 쪽이 남긴 읽기 문제가 섞일 수 있어 비신뢰 문자열로 그린다 */}
        {reason && (
          <span className="block" data-collection-reason="">
            <UntrustedText value={reason} max={200} />
          </span>
        )}
      </>
    ),
  }
}

/** 대응 구역 도움말: 집행 지점이 문제없이 보고한 시각. 보고 문제 · 기록 없음은 본문에 남는다 */
function responseTip(response: TargetResponse, asOf: number): RowTip | null {
  const report = response.report
  if (!response.point || !report || report.problem || !report.seen_at) return null
  return {
    label: '집행 지점 보고',
    content: (
      <span data-report="">
        {response.point_label ?? response.point} 보고 <Time value={report.seen_at} format="relative" now={asOf} />
      </span>
    ),
  }
}

/** 상대 시각(기준 as_of) · 없으면 대신 보일 글 */
function Ago({ value, asOf, empty = '기록 없음' }: { value: string | null | undefined; asOf: number; empty?: string }) {
  if (!value) return <span className="text-ink-muted">{empty}</span>
  return <Time value={value} format="relative" now={asOf} />
}

function CollectionFacts({ target, collection, asOf }: { target: Target; collection: TargetCollection; asOf: number }) {
  const live = useLiveState()
  const signal = collection.signal
  const last = latestLog(collection.logs)
  const logs = signal?.seen_at || collection.logs.length > 1 ? collection.logs : []
  // 신호 없이 마지막 로그만 보일 때 정상으로 읽히지 않게 미확인을 붙인다. 배지가 이미 미확인 · 수신 없음이면 되풀이하지 않는다
  const mark = settled(collection)
  return (
    <>
      {signal?.seen_at ? (
        <span data-signal="">
          {signal.label} <Time value={signal.seen_at} format="relative" now={asOf} className="font-medium" />
          <span className="text-ink-muted"> · <Time value={signal.seen_at} format="short" /></span>
        </span>
      ) : (
        <>
          {signal && (
            <span data-signal={collection.logs.length ? undefined : 'none'}>
              {signal.label} 기록 없음
              {!collection.logs.length && mark && <span className="text-ink-muted"> · 생존 상태 미확인</span>}
            </span>
          )}
          {/* 생존 신호가 없으면 마지막 로그 시각을 보인다. 로그가 없는 대상(데이터 노드)은 줄을 두지 않는다 */}
          {(!signal || collection.logs.length > 0) && (
            <span data-signal="none" title={last ? `${revealHidden(last.label)} 기준` : undefined}>
              {last?.last_at ? <>마지막 로그 <Time value={last.last_at} format="relative" now={asOf} /></> : '로그 기록 없음'}
              {mark && <span className="text-ink-muted"> · 생존 상태 미확인</span>}
            </span>
          )}
        </>
      )}
      {signal?.problem && (
        <span className="break-words text-ink-muted">
          읽기 문제: <UntrustedText value={signal.problem} max={160} />
        </span>
      )}
      {targetKind(target) === 'fixed' && target.id === 'console' && <ConsoleLine name={live.console} connected={live.status === 'connected'} />}
      {/* 등록 노드의 로그 이름은 노드 이름(hostname)에서 온다. 비신뢰 문자열로 그린다 */}
      {logs.length > 0 && (
        <span className="text-ink-muted">
          {logs.map((log, i) => (
            <span key={log.key}>
              {i > 0 && ' · '}
              <UntrustedText value={log.label} max={80} clip /> <Ago value={log.last_at} asOf={asOf} empty="없음" />
            </span>
          ))}
        </span>
      )}
      {collection.extra.length > 0 && (
        <span className="text-ink-muted">
          {collection.extra.map((item, i) => (
            <span key={item.label}>
              {i > 0 && ' · '}
              {item.label} <Ago value={item.at} asOf={asOf} />
              {item.note && <> (<UntrustedText value={item.note} max={80} />)</>}
            </span>
          ))}
        </span>
      )}
      {/* 까닭에는 기록한 쪽이 남긴 읽기 문제가 섞일 수 있어 비신뢰 문자열로 그린다. 정상 · 요청 없음의 까닭은 도움말에 있다 */}
      {collection.reason && !settled(collection) && (
        <span className="text-2xs text-ink-muted">
          <UntrustedText value={collection.reason} max={200} />
        </span>
      )}
    </>
  )
}

/** 실시간 연결의 콘솔 이름. 정해 둔 두 대는 '콘솔 A' · '콘솔 B', 그 밖은 원문을 비신뢰 문자열로 그린다 */
function ConsoleLine({ name, connected }: { name: string | undefined; connected: boolean }) {
  if (name === undefined) return <span data-live-console="">실시간 연결 없음</span>
  const known = consoleLabel(name)
  return (
    <span data-live-console={known ?? ''} title={known ? undefined : revealHidden(name)}>
      실시간 연결: <span className="font-medium">{known ?? <UntrustedText value={name} max={64} clip />}</span>
      {!connected && <span className="text-ink-muted"> (끊김 · 마지막 연결)</span>}
    </span>
  )
}

function SecurityFacts({ target }: { target: Target }) {
  const s = target.security
  return (
    <>
      <span className="tabular-nums">
        최근 1시간 신규 <strong className="font-semibold">{s.incidents_1h.toLocaleString('ko-KR')}</strong> · 높음 이상{' '}
        <strong className="font-semibold">{s.high_1h.toLocaleString('ko-KR')}</strong> · 미판정 <strong className="font-semibold">{s.pending.toLocaleString('ko-KR')}</strong>
      </span>
      {s.parts.length > 0 && (
        <span className="text-ink-muted tabular-nums" title={s.parts.map((p) => `${p.label} 미판정 ${p.pending.toLocaleString('ko-KR')}`).join(' · ')}>
          {s.parts.map((p) => `${p.label} ${p.incidents_1h.toLocaleString('ko-KR')}`).join(' · ')}
        </span>
      )}
    </>
  )
}

/** 최근 중요 탐지 한 줄. 누르면 상세로 간다. 링크 안에는 단추를 두지 않는다(비신뢰 문자열은 clip) */
function LatestLine({ latest, asOf, cti }: { latest: TargetLatest | null; asOf: number; cti?: CtiBadgeValue }) {
  if (!latest) return <span className="text-ink-muted">최근 24시간 사건 없음</span>
  const source = latest.actor_ip ?? latest.target
  return (
    <Link to={incidentHref(latest.incident_key)} className="-mx-1 flex min-w-0 flex-col gap-0.5 rounded-control px-1 py-0.5 text-ink hover:bg-canvas hover:text-ink" data-latest-key={latest.incident_key}>
      <span className="flex min-w-0 items-center gap-1.5">
        <SeverityBadge severity={latest.severity} className="shrink-0" />
        <span className="shrink-0 font-mono font-medium text-primary">{latest.rule_id}</span>
        <span className="truncate" title={revealHidden(latest.rule_name)}>
          <UntrustedText value={latest.rule_name} clip />
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-ink-muted">
        <span className="max-w-full truncate font-mono" title={revealHidden(source ?? '') || undefined}>
          <UntrustedText value={source} fallback="출발지 없음" clip max={80} />
        </span>
        {/* 낭독 · 복사 때도 끊어 읽히게 가운뎃점 앞뒤 공백을 글에 둔다(칸 사이는 gap 이 띄운다) */}
        <span>
          {' · '}
          <Time value={latest.last_ts} format="relative" now={asOf} />
        </span>
        <span className={latest.judged ? undefined : 'font-medium text-primary'}>{` · ${latest.judged ? '판정됨' : '미판정'}`}</span>
        {cti && (
          <>
            {' '}
            <CtiBadge badge={cti} />
          </>
        )}
      </span>
    </Link>
  )
}

function SystemFacts({ system, asOf }: { system: TargetSystem; asOf: number }) {
  const text = systemText(system.state, system.metrics)
  const metrics = system.state === 'ok' || system.state === 'stale' ? system.metrics : null
  const load = metrics && typeof metrics.load1 === 'number' ? `load1 ${metrics.load1}` : undefined
  return (
    <span data-system={system.state} className={metrics ? 'tabular-nums' : 'text-ink-muted'} title={load}>
      {text}
      {metrics && (
        <span className="text-ink-muted">
          {' · '}
          <Time value={metrics.ts} format="relative" now={asOf} />
        </span>
      )}
      {system.state === 'stale' && (
        <>
          {' '}
          <Badge tone="warning" className="ml-1">
            오래됨
          </Badge>
        </>
      )}
    </span>
  )
}

/** 대응 구역. 숫자 0 을 그리지 않는다(responseParts). 차단 목록으로 잇는다. 정상 보고 시각은 도움말(responseTip)에 있다 */
function ResponseFacts({ response }: { response: TargetResponse }) {
  const parts = responseParts(response)
  const report = response.report
  const pointLabel = response.point_label ?? response.point ?? ''
  return (
    <>
      <Link to="/blocklist" className="flex min-w-0 flex-wrap items-center gap-1.5 text-ink hover:text-ink" data-response="">
        {parts.map((part) =>
          part.tone ? (
            <Badge key={part.key} tone={part.tone} data-response-part={part.key}>
              {part.text}
            </Badge>
          ) : (
            // 집행기 확인 멈춤은 적용 확인을 믿지 못하는 까닭이라 주의색 글로 보인다(서버가 시각으로 만든 문장)
            <span key={part.key} className={part.key === 'stalled' ? 'text-2xs text-warning' : 'text-ink-muted'} data-response-part={part.key}>
              {part.text}
            </span>
          ),
        )}
        <span className="text-primary" aria-hidden="true">
          →
        </span>
      </Link>
      {report && response.point && (report.problem || !report.seen_at) && (
        <span className="text-2xs text-ink-muted" data-report="">
          {report.problem ? (
            <>
              {pointLabel} 보고: <UntrustedText value={report.problem} max={120} />
            </>
          ) : (
            `${pointLabel} 보고 기록 없음`
          )}
        </span>
      )}
    </>
  )
}

function VulnFacts({ vulns, asOf }: { vulns: TargetVulns; asOf: number }) {
  if (!vulns.available) return <span className="text-ink-muted">취약점 정보 없음</span>
  if (!vulns.assets.length) return <span className="text-ink-muted">연결된 자산 없음</span>
  return (
    <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
      {vulns.assets.map((asset) => (
        <li key={asset.asset_id} className="min-w-0" data-asset={asset.asset_id}>
          <Link to={assetHref(asset.asset_id)} className="break-words">
            <span className="font-mono font-medium">
              <UntrustedText value={asset.asset_id} max={64} clip />
            </span>{' '}
            <span className={cn('tabular-nums', (asset.missing || !asset.collected_at || !asset.checked_at) && 'text-ink-muted')}>{vulnText(asset)}</span>
            {!asset.missing && asset.collected_at && (
              <span className="text-ink-muted">
                {' · 조사 '}
                <Time value={asset.collected_at} format="relative" now={asOf} />
              </span>
            )}
          </Link>
          {asset.stale && !asset.missing && (
            <>
              {' '}
              <Badge tone="warning" className="ml-1">
                오래됨
              </Badge>
            </>
          )}
        </li>
      ))}
    </ul>
  )
}
