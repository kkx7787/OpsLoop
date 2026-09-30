import { Link } from 'react-router'
import { controlHealthView, monitorItemHref, monitorItemText, type ControlHealthQuery, type MonitorItem } from '@/api/health'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'

export interface ControlHealthBandProps {
  /** useControlHealth() 결과 */
  health: ControlHealthQuery
  className?: string
}

/** 멈춤 기준(app/targets.py CHECKER_STALE · BLOCK_CHECKER_STALE · HEARTBEAT_STALE · 노드 수신 판정). 센서는 적재기 확인 때 신호가 멈춘 시간이다 */
const STALE_NOTE = '적재기 30분 · 집행기 10분 · 센서 15분 · 탐지 15분 · 노드 10분 넘게 확인이 없으면 멈춤입니다.'

/**
 * 관제 이상 띠(#72 · #82). 적재기 · 집행기 확인 멈춤, 센서 · 관문 기록 수신 끊김, 탐지 경로 멈춤, 지점별 적용 실패 · 불일치 · 보고 멈춤,
 * 활성 노드 수신 끊김(한 대라도) · 노드별 웹 로그 적재 없음 · 자원 지표 오래됨과 읽을 수 없는 표(모름)를 한 줄씩 보인다.
 * 대상 카드가 이상 · 확인 불가로 보이는 수집 · 탐지 · 집행 상태는 여기에도 있다. 이상이 없거나 받는 중이면 보이는 것이 없다.
 * 조회가 실패하면(재시도 뒤) 이전 항목 대신 '관제 상태 확인 불가' 한 줄이다(사이드바 요약과 같은 판정, controlHealthView).
 * 그 status 자리는 비어 있어도(보이지 않고 이름 없음) 늘 두고 글만 바꾼다. 글과 함께 새로 끼우면 낭독되지 않을 수 있다.
 * 항목은 볼 화면으로 잇는다(monitorItemHref: 차단 집행 쪽은 차단 목록, 노드 수신 · 자원 지표는 수집 노드, 웹 로그 적재는 장비 최근 로그).
 * 기준은 ⓘ 하나에 둔다.
 */
export function ControlHealthBand({ health, className }: ControlHealthBandProps) {
  const view = controlHealthView(health)
  const error = view.state === 'error'
  const items = view.state === 'ok' ? [...view.alerts, ...view.unknowns] : []
  return (
    <>
      <section
        aria-label={error ? '관제 이상' : undefined}
        className={error ? cn('rounded-panel bg-warning-soft px-4 py-2.5 text-sm text-warning', className) : 'sr-only'}
      >
        <p role="status" className="m-0 font-semibold">
          {error ? '관제 상태 확인 불가' : ''}
        </p>
      </section>
      {items.length > 0 && <ItemsBand items={items} alert={view.state === 'ok' && view.alerts.length > 0} className={className} />}
    </>
  )
}

/** 이상 · 모름 항목 띠. 주기 조회마다 다시 읽히지 않게 status · alert 역할은 두지 않는다 */
function ItemsBand({ items, alert, className }: { items: MonitorItem[]; alert: boolean; className?: string }) {
  return (
    <InfoTip
      label="관제 이상 기준"
      render={({ button, panel }) => (
        <section aria-label="관제 이상" className={cn('rounded-panel px-4 py-2.5 text-sm', alert ? 'bg-warning-soft text-warning' : 'bg-muted-soft text-ink', className)} data-control-health={alert ? 'alert' : 'unknown'}>
          <div className="flex min-w-0 items-start gap-2">
            <ul className="m-0 flex min-w-0 flex-1 list-none flex-col gap-1 p-0 md:flex-row md:flex-wrap md:gap-x-4">
              {items.map((item) => (
                <Item key={item.key} item={item} />
              ))}
            </ul>
            <span className="shrink-0 pt-0.5">{button}</span>
          </div>
          {panel}
        </section>
      )}
    >
      {STALE_NOTE}
    </InfoTip>
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
