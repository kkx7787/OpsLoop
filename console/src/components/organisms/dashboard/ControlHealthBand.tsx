import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { loginHref } from '@/api/client'
import { useControlHealthView, monitorItemHref, monitorItemText, type ControlHealthQuery, type MonitorItem } from '@/api/health'
import type { LiveStatus } from '@/api/live'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'

export interface ControlHealthBandProps {
  /** useControlHealth() 결과 */
  health: ControlHealthQuery
  /**
   * 실시간 연결 상태(대시보드만, #84). 끊김(reconnecting) · 종료(closed)면 띠 끝에 한 항목으로 싣는다(공통 끊김 띠와 둘이 되지 않게).
   * 없으면 싣지 않는다. 사이드바 관제 이상 수에는 넣지 않는다
   */
  live?: LiveStatus
  className?: string
}

/** 멈춤 기준(app/targets.py CHECKER_STALE · BLOCK_CHECKER_STALE · HEARTBEAT_STALE · 노드 수신 판정). 센서는 적재기 확인 때 신호가 멈춘 시간이다 */
const STALE_NOTE = '적재기 30분 · 집행기 10분 · 센서 15분 · 탐지 15분 · 노드 10분 넘게 확인이 없으면 멈춤입니다.'
/** 실시간 끊김(다시 연결 중) 동안의 주기 조회(공통 끊김 띠 MonitoringStatus 와 같은 원문. 세션 종료에는 붙이지 않는다) */
const LIVE_NOTE = '현재 화면은 30초마다 별도로 조회합니다.'

/** 실시간 연결 끊김 · 종료. 그 밖(연결 중 · 연결됨 · 없음)은 null */
function liveState(live: LiveStatus | undefined): 'reconnecting' | 'closed' | null {
  return live === 'reconnecting' || live === 'closed' ? live : null
}

/**
 * 관제 이상 띠(#72 · #82). 적재기 · 집행기 확인 멈춤, 센서 · 관문 기록 수신 끊김, 탐지 경로 멈춤, 지점별 적용 실패 · 불일치 · 보고 멈춤 · 확인 지연,
 * 활성 노드 수신 끊김(한 대라도) · 노드별 웹 로그 적재 없음 · 자원 지표 오래됨과 읽을 수 없는 표(모름)를 한 줄씩 보인다.
 * 대상 카드가 이상 · 확인 불가로 보이는 수집 · 탐지 · 집행 상태는 여기에도 있다. 이상이 없거나 받는 중이면 보이는 것이 없다.
 * 조회가 실패하면(재시도 뒤) 이전 항목 대신 '관제 상태 확인 불가' 한 줄이다(사이드바 요약과 같은 판정, controlHealthView).
 * 대시보드(#84)는 실시간 연결 끊김 · 종료를 끝 항목 하나로 싣는다(띠는 하나). 확인 불가와 함께면 그 줄 뒤에 붙인다.
 * 낭독 칸(role=status)은 첫 section 의 하나뿐이다. 비어 있어도(보이지 않고 이름 없음) 늘 두고 글만 바꾼다(새로 끼우면 낭독되지 않을 수 있다).
 * 확인 불가 · 실시간 끊김을 그 칸이 알리고, 이상 항목 띠는 주기 조회마다 다시 읽히지 않게 역할을 두지 않는다.
 * 항목은 볼 화면으로 잇는다(monitorItemHref: 차단 집행 쪽은 차단 목록, 센서 · 탐지 · 노드 · 자원 지표는 수집 · 관제 상태, 웹 로그 적재는
 * 장비 최근 로그). 기준은 ⓘ 하나에 둔다.
 */
export function ControlHealthBand({ health, live, className }: ControlHealthBandProps) {
  const view = useControlHealthView(health)
  const error = view.state === 'error' || view.state === 'stale'
  const items = view.state === 'ok' ? [...view.alerts, ...view.unknowns] : []
  const link = liveState(live)
  const status = error
    ? `${view.state === 'stale' ? '관제 상태 갱신 지연 · 최신 상태 확인 필요' : '관제 상태 확인 불가'}${link ? ` · 실시간 연결 ${link === 'closed' ? '종료' : '끊김'}` : ''}`
    : link === 'closed'
      ? '실시간 연결 종료 · 다시 로그인 필요'
      : link
        ? '실시간 연결 끊김 · 다시 연결 중'
        : ''
  return (
    <>
      <section
        aria-label={error ? '관제 이상' : undefined}
        className={error ? cn('rounded-panel bg-warning-soft px-4 py-2.5 text-sm text-warning', className) : 'sr-only'}
      >
        <div className="flex min-w-0 items-start gap-2">
          <p role="status" className="m-0 min-w-0 flex-1 font-semibold">
            {status}
          </p>
          {error && link === 'closed' && (
            <a href={loginHref()} className="shrink-0 text-current underline underline-offset-2 hover:text-current">
              다시 로그인
            </a>
          )}
          {error && link === 'reconnecting' && <InfoTip label="실시간 연결 끊김">{LIVE_NOTE}</InfoTip>}
        </div>
      </section>
      {!error && (items.length > 0 || link) && (
        <ItemsBand items={items} live={link} alert={(view.state === 'ok' && view.alerts.length > 0) || !!link} className={className} />
      )}
    </>
  )
}

/**
 * 이상 · 모름 항목 띠(끝에 실시간 끊김). 주기 조회마다 다시 읽히지 않게 status · alert 역할은 두지 않는다. 기준 ⓘ 는 쓸 글이 있을 때만이고,
 * 실시간 끊김만 있으면 단추 이름도 그 항목이다(확인 불가 띠와 같다)
 */
function ItemsBand({ items, live, alert, className }: { items: MonitorItem[]; live: 'reconnecting' | 'closed' | null; alert: boolean; className?: string }) {
  const note = [items.length > 0 ? STALE_NOTE : null, live === 'reconnecting' ? LIVE_NOTE : null].filter(Boolean).join(' ')
  const band = (button?: ReactNode, panel?: ReactNode) => (
    <section aria-label="관제 이상" className={cn('rounded-panel px-4 py-2.5 text-sm', alert ? 'bg-warning-soft text-warning' : 'bg-muted-soft text-ink', className)} data-control-health={alert ? 'alert' : 'unknown'}>
      <div className="flex min-w-0 items-start gap-2">
        <ul className="m-0 flex min-w-0 flex-1 list-none flex-col gap-1 p-0 md:flex-row md:flex-wrap md:gap-x-4">
          {items.map((item) => (
            <Item key={item.key} item={item} />
          ))}
          {live && <LiveItem state={live} />}
        </ul>
        {button && <span className="shrink-0 pt-0.5">{button}</span>}
      </div>
      {panel}
    </section>
  )
  if (!note) return band()
  return (
    <InfoTip label={items.length > 0 ? '관제 이상 기준' : '실시간 연결 끊김'} render={({ button, panel }) => band(button, panel)}>
      {note}
    </InfoTip>
  )
}

/** 실시간 연결 항목(#84). 다시 연결 중은 링크 없음(새로고침은 제목 줄), 종료는 다시 로그인 링크 */
function LiveItem({ state }: { state: 'reconnecting' | 'closed' }) {
  return (
    <li className="min-w-0 break-words" data-monitor-item="live" data-monitor-level="alert">
      <span className="font-semibold">실시간 연결</span>
      {state === 'closed' ? (
        <>
          {' · 종료 · '}
          <a href={loginHref()} className="text-current underline underline-offset-2 hover:text-current">
            다시 로그인
          </a>
        </>
      ) : (
        ' · 끊김 · 다시 연결 중'
      )}
    </li>
  )
}

/**
 * 항목 한 줄: '{이름} · {까닭 또는 건수}'. 까닭에는 탐지 버전 · 노드 이름 · 지점 보고 문제가 섞일 수 있어 비신뢰 문자열로 그린다.
 * 링크 안에 펼치기 단추를 두지 않도록 자르기(clip)만 쓰고 전체는 말풍선으로 본다
 */
function Item({ item }: { item: MonitorItem }) {
  const text = monitorItemText(item)
  const href = monitorItemHref(item.key)
  const body = (
    <>
      <span className="font-semibold">
        <UntrustedText value={item.label} max={80} clip fallback={item.key} />
      </span>
      {text && (
        <>
          {' · '}
          <span title={revealHidden(text)}>
            <UntrustedText value={text} clip />
          </span>
        </>
      )}
    </>
  )
  return (
    <li className={cn('min-w-0 break-words', item.level !== 'alert' && 'text-ink-muted')} data-monitor-item={item.key} data-monitor-level={item.level === 'alert' ? 'alert' : 'unknown'}>
      {href ? (
        <Link to={href} className="text-current underline underline-offset-2 hover:text-current">
          {body}
        </Link>
      ) : (
        body
      )}
    </li>
  )
}
