import { Fragment, useEffect, useId, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { CARD_LOGS_INTERVAL, DEVICE_NOT_FOUND, isDeviceNotFound, isLogsNotDeployed, LOGS_NOT_DEPLOYED, useCardLogs } from '@/api/device-logs'
import { targetKind, type Target, type TargetCollection, type TargetSystem } from '@/api/targets'
import { cn } from '@/lib/cn'
import { toDate } from '@/lib/time'
import { useInView } from '@/lib/useInView'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import { Button } from '../../atoms/Button'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { deviceIncidentsHref, deviceLogsHref } from '../../molecules/device-format'
import { InfoTip } from '../../molecules/InfoTip'
import { CardLogBox, type CardLogBoxView } from './CardLogBox'
import {
  collectionState,
  isLogDevice,
  LABEL_MAX,
  latestLog,
  pendingHref,
  protectedHeadBadge,
  summaryFlags,
  systemText,
  undeterminedHref,
  vulnSummary,
} from './target-format'

export interface ProtectedCardProps {
  target: Target
  /** 상대 시각의 기준(ms). 상태판 응답의 as_of(DB 시각)라 브라우저 시계가 어긋나도 같은 값을 보인다 */
  asOf: number
  /** 상태판 갱신이 실패해 이전 결과를 보이는 중이다(머리에 '이전 결과', 취약점 줄에 '조회 실패'. inline 은 요약 줄이 '이전 결과' 를 단다) */
  stale?: boolean
  /**
   * card   카드 한 장(sm 이상 격자)
   * inline 모바일 접힌 요약을 펼친 자리. 이름 · 수집 상태 · 경고 배지는 요약 줄에 있으므로 겉틀과 이름 줄을 뺀다
   */
  variant?: 'card' | 'inline'
  className?: string
}

/** 로그 머리 ⓘ: 장비 로그 화면 설명과 같은 뜻(자동 갱신 주기를 '도착 시간' 으로 설명하지 않는다) */
const LOG_NOTE = '로그는 1분 적재 회차로 들어오고, 사건은 그 뒤 탐지 회차에서 생깁니다.'

/**
 * 보호 대상 카드(#83, web-01 · 등록 노드). 위에서부터:
 *  머리    이름 · 역할 · 수집 상태('수집 정상' 등) / '마지막 수신 n분 전'(에이전트 신호) · 경고 배지(적용 실패 · 집행기 멈춤 · 이전 결과)
 *  경고    웹 로그 도착 · 적재 없음(#82) · 읽기 문제 · 수신 없음 까닭. 있을 때만 본문 줄이라 높이가 늘어도 된다
 *  성능    CPU · 메모리 · 디스크(오래되면 '오래됨')
 *  최근 로그 '마지막 로그 n분 전'(로그 시각) · 자동 갱신 정지 / 10줄 상자(높이 고정 · 안쪽 스크롤)
 *  취약점  '수정판 있음 N · KEV N · 수정 여부 미확인 N →' 한 줄(상태 글은 수 옆에, 미확인의 뜻은 말풍선)
 *  동선    '미판정 N건 → · 미결 N건 → · 사건 보기 → · 로그 더 보기 →'
 * 보안 · 최근 사건 · 대응 구역은 없다(판정 대기 구역 · 차단 화면에 있다). 정상 상태의 줄은 모두 한 줄이라 장비가 늘어도 카드 높이가 같다.
 * 로그는 카드가 보이고 탭이 앞일 때만 10초마다 받는다. 정지는 로그만 멈추고, 상단 새로고침은 정지 중에도 한 번 받는다(정지는 그대로).
 */
export function ProtectedCard({ target, asOf, stale = false, variant = 'card', className }: ProtectedCardProps) {
  const titleId = useId()
  const inline = variant === 'inline'
  const kind = targetKind(target)
  const state = collectionState(target.collection.state)
  const head = protectedHeadBadge(target)
  // 웹 로그 적재 없음은 아래 경고 줄이 마지막 도착 시각과 함께 말한다
  const flags = summaryFlags(target).filter((flag) => flag.key !== 'parse')
  const title = (
    <h3 id={titleId} className={cn('m-0 min-w-0 truncate text-md font-semibold tracking-heading', inline && 'sr-only')} title={kind === 'node' ? revealHidden(target.label) : undefined}>
      <UntrustedText value={target.label} max={LABEL_MAX} clip />
    </h3>
  )
  return (
    <div
      role="region"
      aria-labelledby={titleId}
      data-target={target.id}
      data-target-kind={kind}
      data-collection={state}
      data-stale={stale ? '' : undefined}
      className={cn('@container flex min-w-0 flex-col print:[container-type:normal]', !inline && 'rounded-card bg-surface shadow-card', className)}
    >
      <div className={cn('flex min-w-0 flex-col', inline ? 'px-3 pt-1' : 'rounded-t-card border-b border-line bg-canvas/60 px-3 py-2')}>
        {inline ? (
          title
        ) : (
          <div className="flex h-[22px] min-w-0 items-center gap-2">
            {title}
            <span className="min-w-0 truncate text-xs text-ink-muted">
              {target.role}
              {kind === 'node' && target.label !== target.id && (
                <>
                  {' · '}
                  <span className="font-mono" data-node-id="">
                    <UntrustedText value={target.id} max={64} clip />
                  </span>
                </>
              )}
            </span>
            <Badge tone={head.tone} className="ml-auto shrink-0" data-collection-badge="">
              {head.label}
            </Badge>
          </div>
        )}
        <div className="flex h-5 min-w-0 items-center gap-2 text-xs">
          <SignalLine collection={target.collection} asOf={asOf} />
          {!inline && (flags.length > 0 || stale) ? (
            <span className="ml-auto flex shrink-0 items-center gap-1">
              {flags.map((flag) => (
                <Badge key={flag.key} tone={flag.tone} data-summary-flag={flag.key}>
                  {flag.text}
                </Badge>
              ))}
              {stale && (
                <Badge tone="warning" data-stale-badge="">
                  이전 결과
                </Badge>
              )}
            </span>
          ) : null}
        </div>
      </div>
      <Alerts collection={target.collection} asOf={asOf} />
      <SystemLine system={target.system} />
      {isLogDevice(target) ? <CardLogs target={target} titleId={titleId} asOf={asOf} /> : <NoLogs titleId={titleId} />}
      <VulnLine target={target} stale={stale} />
      <p className="m-0 flex min-w-0 flex-nowrap items-center gap-x-3 overflow-hidden border-t border-line px-3 py-1.5 text-xs whitespace-nowrap print:hidden" data-device-links="">
        <PendingLink target={target} />
        {(target.security.undetermined ?? 0) > 0 && (
          <Link to={undeterminedHref(target.id)} data-undetermined-link="">
            미결 {count(target.security.undetermined ?? 0)}건
            <Arrow />
          </Link>
        )}
        <Link to={deviceIncidentsHref(target.id)}>
          사건 보기
          <Arrow />
        </Link>
        {isLogDevice(target) && (
          <Link to={deviceLogsHref(target.id)} className="ml-auto">
            로그 더 보기
            <Arrow />
          </Link>
        )}
      </p>
    </div>
  )
}

const count = (n: number) => n.toLocaleString('ko-KR')

function Arrow() {
  return (
    <span aria-hidden="true" className="text-primary">
      {' →'}
    </span>
  )
}

/** 서버가 정상 · 요청 없음으로 판정했다(까닭이 배지와 같은 말이라 ⓘ 로 보낸다) */
function settled(collection: TargetCollection): boolean {
  const state = collectionState(collection.state)
  return state === 'ok' || state === 'quiet'
}

/** '마지막 수신 n분 전'(에이전트 신호 기준). 수신 없음 기준과 정상일 때의 서버 까닭은 ⓘ 에 둔다 */
function SignalLine({ collection, asOf }: { collection: TargetCollection; asOf: number }) {
  const signal = collection.signal
  const reason = settled(collection) && collection.reason ? collection.reason : null
  const text = signal?.seen_at ? (
    <span className="min-w-0 truncate" data-signal="">
      마지막 수신 <Time value={signal.seen_at} format="relative" now={asOf} className="font-medium" />
    </span>
  ) : (
    <span className="min-w-0 truncate text-ink-muted" data-signal="none">
      {signal ? '수신 기록 없음' : '생존 신호 없음'}
    </span>
  )
  if (!signal && !reason) return text
  return (
    <span className="flex min-w-0 items-center gap-1">
      {text}
      <InfoTip label="수집 상태">
        {signal && <span className="block">{`${Math.round(signal.stale_after_seconds / 60)}분 넘게 새 신호가 없으면 수신 없음입니다.`}</span>}
        {signal && reason && ' '}
        {/* 까닭에는 기록한 쪽이 남긴 읽기 문제가 섞일 수 있어 비신뢰 문자열로 그린다 */}
        {reason && (
          <span className="block" data-collection-reason="">
            <UntrustedText value={reason} max={200} />
          </span>
        )}
      </InfoTip>
    </span>
  )
}

/** 이상 상태의 경고 본문 줄(#82 웹 로그 적재 없음 · 읽기 문제 · 수신 없음 까닭). 있을 때만 그리고, 줄이 늘면 카드도 높아진다 */
function Alerts({ collection, asOf }: { collection: TargetCollection; asOf: number }) {
  const warnings = Array.isArray(collection.warnings) ? collection.warnings : []
  const problem = collection.signal?.problem
  const reason = !settled(collection) && collection.reason ? collection.reason : null
  if (!warnings.length && !problem && !reason) return null
  return (
    <div className="flex min-w-0 flex-col gap-0.5 px-3 pt-1.5 text-xs break-words" data-card-alerts="">
      {warnings.map((warning) => (
        <span key={warning.key} className="text-warning" data-collection-warning={warning.key}>
          {warning.label}
          {warning.at && (
            <>
              {' · 마지막 도착 '}
              <Time value={warning.at} format="relative" now={asOf} />
            </>
          )}
        </span>
      ))}
      {problem && (
        <span className="text-warning" data-signal-problem="">
          읽기 문제: <UntrustedText value={problem} max={160} />
        </span>
      )}
      {reason && (
        <span className="text-2xs text-ink-muted" data-collection-reason="">
          <UntrustedText value={reason} max={200} />
        </span>
      )}
    </div>
  )
}

/** 성능 한 줄. 수치 시각은 적지 않고 오래됐을 때만 '오래됨'(주의색)을 붙인다. load1 은 말풍선 */
function SystemLine({ system }: { system: TargetSystem }) {
  const metrics = system.state === 'ok' || system.state === 'stale' ? system.metrics : null
  const load = metrics && typeof metrics.load1 === 'number' ? `load1 ${metrics.load1}` : undefined
  return (
    <p className={cn('m-0 min-w-0 truncate px-3 py-1.5 text-xs', metrics ? 'tabular-nums' : 'text-ink-muted')} data-system={system.state} title={load}>
      {systemText(system.state, system.metrics)}
      {system.state === 'stale' && (
        <>
          {' · '}
          <span className="font-medium text-warning" data-system-stale="">
            오래됨
          </span>
        </>
      )}
    </p>
  )
}

/** 로그 머리 한 줄(36px): 제목 · 마지막 로그 · 이전 결과 · ⓘ(1분 적재) | 오른쪽 단추 */
function LogHead({ headId, children, action, note = true }: { headId: string; children?: ReactNode; action?: ReactNode; note?: boolean }) {
  return (
    <div className="flex h-9 min-w-0 items-center justify-between gap-2 border-t border-line px-3 text-xs">
      <span className="flex min-w-0 items-center gap-1">
        <span className="min-w-0 truncate">
          <span id={headId} className="font-medium">
            최근 로그
          </span>
          {children}
        </span>
        {note && <InfoTip label="최근 로그">{LOG_NOTE}</InfoTip>}
      </span>
      {action}
    </div>
  )
}

/** 로그 없는 보호 대상(장비 로그 화면이 없는 id): 조회하지 않고 같은 높이 */
function NoLogs({ titleId }: { titleId: string }) {
  const headId = useId()
  return (
    <>
      <LogHead headId={headId} note={false} />
      <CardLogBox labelledBy={`${titleId} ${headId}`} view={{ kind: 'message', text: '최근 로그 없음(장비 로그 대상 아님)' }} />
    </>
  )
}

/**
 * 카드의 최근 로그. 보일 때(상자가 뷰포트 안) · 탭이 앞일 때 10초마다 받는다. 정지는 이 카드의 로그만 멈춘다(요약 · 상태판 · 관제 이상은 계속).
 * 다시 보이게 됐을 때 정지가 아니고 마지막으로 받은 지 10초가 넘었으면 한 번 받는다
 */
function CardLogs({ target, titleId, asOf }: { target: Target; titleId: string; asOf: number }) {
  const headId = useId()
  const [paused, setPaused] = useState(false)
  const [boxRef, inView] = useInView<HTMLDivElement>()
  const query = useCardLogs(target.id, paused, inView)
  const { data, refetch, dataUpdatedAt } = query
  const failed = query.isError || query.errorUpdatedAt > query.dataUpdatedAt
  const error = useLastError(query.error, failed)

  useEffect(() => {
    if (inView && !paused && dataUpdatedAt > 0 && Date.now() - dataUpdatedAt > CARD_LOGS_INTERVAL) void refetch()
  }, [inView, paused, dataUpdatedAt, refetch])

  // 마지막 로그: 상태판의 마지막 로그와 받은 첫 줄 가운데 늦은 것(둘 다 앞선 시각 줄을 뺀 값). 기준은 두 응답 가운데 늦은 as_of
  const now = Math.max(asOf, toDate(data?.as_of)?.getTime() ?? 0)
  const last = Math.max(toDate(latestLog(target.collection.logs)?.last_at)?.getTime() ?? -Infinity, toDate(data?.items[0]?.ts)?.getTime() ?? -Infinity)

  let view: CardLogBoxView
  if (data) view = { kind: 'lines', lines: data.items, future: data.future, windowDays: data.window_days, asOf: data.as_of, stale: failed }
  else if (!failed || !error) view = { kind: 'loading' }
  else if (isDeviceNotFound(error)) view = { kind: 'message', text: DEVICE_NOT_FOUND }
  else if (isLogsNotDeployed(error)) view = { kind: 'message', text: LOGS_NOT_DEPLOYED }
  else view = { kind: 'message', text: '최근 로그를 불러오지 못함', tone: 'warning' }

  return (
    <>
      <LogHead
        headId={headId}
        action={
          <Button
            size="sm"
            aria-pressed={paused}
            aria-label="로그 자동 갱신 정지"
            onClick={() => setPaused((p) => !p)}
            className="aria-pressed:bg-primary-soft aria-pressed:font-medium aria-pressed:text-primary aria-pressed:shadow-none print:hidden"
          >
            자동 갱신 정지
          </Button>
        }
      >
        <span className="text-ink-muted" data-last-log="">
          {' · '}
          {Number.isFinite(last) ? (
            <>
              마지막 로그 <Time value={Math.min(last, now)} format="relative" now={now} />
            </>
          ) : (
            '로그 기록 없음'
          )}
        </span>
        {data && failed && (
          <span className="font-medium text-warning" data-logs-stale="">
            {' · 이전 결과'}
          </span>
        )}
      </LogHead>
      <CardLogBox labelledBy={`${titleId} ${headId}`} view={view} boxRef={boxRef} />
    </>
  )
}

/**
 * 마지막 오류. 받은 적 없는 조회를 다시 보내는 동안 react-query 는 error 를 비우고 받는 중으로 돌아간다.
 * 마지막으로 끝난 조회가 실패였으면(failed) 그 오류를 계속 보여 10초마다 '불러오는 중' 으로 깜빡이지 않게 한다(장비 로그 화면과 같다)
 */
function useLastError(error: unknown, failed: boolean): unknown {
  const [last, setLast] = useState<unknown>(null)
  if (error && error !== last) setLast(error)
  return error ?? (failed ? last : null)
}

/** 미판정 N건: N>0 이면 그 장비의 미판정 목록으로 잇고 0 은 글만 둔다(Q18) */
function PendingLink({ target }: { target: Target }) {
  const n = target.security.pending
  if (n <= 0) return <span className="text-ink-muted">미판정 0건</span>
  return (
    <Link to={pendingHref(target.id)} data-pending-link="">
      미판정 {count(n)}건
      <Arrow />
    </Link>
  )
}

/**
 * 취약점 한 줄. 수는 숨기거나 0 으로 바꾸지 않고, 조사 오래됨 · 대조 실패 · 대조 오래됨 · 조회 실패는 수 옆에 주의색 글로 둔다.
 * 수정 여부 미확인의 뜻은 말풍선(title)으로 단다. 링크 안이라 도움말 단추는 두지 않는다(#94)
 */
function VulnLine({ target, stale }: { target: Target; stale: boolean }) {
  const vuln = vulnSummary(target.vulns)
  const flags = stale ? [...vuln.flags, '조회 실패'] : vuln.flags
  const body = (
    <>
      <span className={cn('tabular-nums', vuln.muted && 'text-ink-muted')}>취약점 {vuln.main}</span>
      {vuln.unknown && (
        <>
          {' · '}
          <span className="text-ink-muted tabular-nums" title={vuln.unknownNote}>
            {vuln.unknown}
          </span>
        </>
      )}
    </>
  )
  return (
    // 정상이면 한 줄(말줄임). 상태 글이 붙으면 좁은 카드에서 잘려 숨지 않게 줄을 바꾼다(경고는 본문, 높이가 늘어도 된다).
    // mt-auto: 나란한 카드 중 옆 카드가 높아져 이 카드가 늘어나면 취약점 · 동선 두 줄을 바닥에 붙인다(빈칸은 로그 상자 아래 한 곳)
    <p className={cn('m-0 mt-auto min-w-0 border-t border-line px-3 py-1.5 text-xs', flags.length ? 'break-words' : 'truncate')} data-vulns="">
      {vuln.href ? (
        <Link to={vuln.href} className="text-ink hover:text-ink" data-vuln-link="">
          {body}
          <Arrow />
        </Link>
      ) : (
        body
      )}
      {flags.map((flag) => (
        <Fragment key={flag}>
          {' '}
          {/* 상태 글은 낱말 가운데서 끊지 않는다(줄이 바뀌면 통째로 다음 줄) */}
          <span className="font-medium whitespace-nowrap text-warning" data-vuln-flag={flag}>
            {`· ${flag}`}
          </span>
        </Fragment>
      ))}
    </p>
  )
}
