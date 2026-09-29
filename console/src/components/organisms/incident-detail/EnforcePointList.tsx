import type { ReactNode } from 'react'
import { Badge } from '../../atoms/Badge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'
import { POINT_STATE_LABEL, POINT_STATE_TONE, type PointRow } from './format'

/**
 * 집행 지점별 결과 목록(이슈 #51). 지점 · 상태 · 그 상태가 된 시각 · 방식, 실패 · 확인 지연이면 까닭.
 * 지점이 보낸 실패 · 확인 지연 까닭은 오류 안내라 본문 줄로 둔다. 화면이 덧붙인 판단 근거(noteTip · 집행기 멈춤)만
 * 배지 옆 도움말(ⓘ)로 접는다. 그때는 '확인 지연' 배지와 멈춤 띠가 경고를 맡는다.
 * 방식 · 까닭은 지점이 보낸 값이라 글자로만 그린다. 지점이 없으면 아무것도 그리지 않는다(이전 서버 · 집행기)
 */
export function EnforcePointList({ points, className, compact = false }: { points: PointRow[]; className?: string; compact?: boolean }) {
  if (!points.length) return null
  return (
    <ul className={['m-0 flex list-none flex-col gap-1 p-0 text-xs', className].filter(Boolean).join(' ')} aria-label="집행 지점별 결과">
      {points.map(({ key, label, point, noteTip }) => {
        const tip = !!point.note && point.state === 'stale' && noteTip === true
        const row = (button?: ReactNode, panel?: ReactNode) => (
          <li key={key} data-enforce-point={key} data-point-state={point.state} className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5">
            <span className="text-ink-muted">{label}</span>
            <Badge tone={POINT_STATE_TONE[point.state]}>{POINT_STATE_LABEL[point.state]}</Badge>
            {button}
            {!compact && point.since && <Time value={point.since} format="short" />}
            {!compact && point.mode && <span className="text-ink-muted">· <UntrustedText value={point.mode} max={16} /></span>}
            {point.note && (point.state === 'failed' || point.state === 'stale') && !tip && <span className="basis-full break-words text-ink-muted"><UntrustedText value={point.note} max={160} /></span>}
            {panel}
          </li>
        )
        if (!tip) return row()
        return (
          <InfoTip key={key} label={`${label} ${POINT_STATE_LABEL[point.state]}`} panelClassName="basis-full break-words" render={({ button, panel }) => row(button, panel)}>
            <UntrustedText value={point.note} max={160} />
          </InfoTip>
        )
      })}
    </ul>
  )
}
