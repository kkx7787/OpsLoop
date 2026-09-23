import type { IncidentDetail } from '@/api/incidents'
import { sensorOf, type Sensor } from '@/lib/domain'
import { Badge } from '../../atoms/Badge'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { PageHeader } from '../../molecules/PageHeader'
import { ElapsedClock } from './ElapsedClock'
import { StatusBadge } from './StatusBadge'

export interface IncidentHeaderProps {
  detail: IncidentDetail
  className?: string
}

/** 발생원 배지의 설명. 허니팟 · 디코이 건은 신고 대상이 아니고, 콘솔 건은 신고 기한이 걸린다(화면 설계 3장) */
const SENSOR_NOTE: Partial<Record<Sensor, string>> = {
  허니팟: '노출을 의도한 자산에서 발생한 건 · 침해사고 신고 대상이 아니다',
  '콘솔 · 감사': '콘솔에서 발생한 건 · 침해사고 신고 기한이 걸려 critical 목표를 따른다',
}

/** 상세 머리글: 규칙 · 심각도 · 상태 · 발생원 · 출발지 · 구간 · 경과(판정 목표 대비) */
export function IncidentHeader({ detail, className }: IncidentHeaderProps) {
  const sensor = sensorOf(detail.rule_id)
  const last = detail.verdicts[detail.verdicts.length - 1]
  return (
    <PageHeader
      className={className}
      title={
        <>
          <span className="font-mono">{detail.rule_id}</span> {detail.rule_name}
        </>
      }
      badges={
        <>
          <SeverityBadge severity={detail.severity} />
          <StatusBadge status={detail.status} />
          <Badge tone="info">{detail.rule_version}</Badge>
          <Badge title={SENSOR_NOTE[sensor]} data-sensor={sensor}>
            발생원 {sensor}
          </Badge>
          {last && <VerdictBadge verdict={last.verdict} title="최근 판정" />}
        </>
      }
      description={
        <>
          {detail.actor_ip ? (
            <>
              출발지 <span className="font-mono text-ink">{detail.actor_ip}</span>
            </>
          ) : !detail.target ? '출발지 없음' : null}
          {detail.target && (
            <>
              {detail.actor_ip && ' · '}
              대상 <span className="font-mono text-ink">{detail.target}</span>
            </>
          )}
          {' · '}
          발생 <Time value={detail.first_ts} format="datetime" className="text-ink" /> ~ <Time value={detail.last_ts} format="time" className="text-ink" /> KST
          {' · '}
          신호 {detail.signal_count}건 · 세션 {detail.session_count}개
          {' · '}
          키 <span className="font-mono text-2xs break-all">{detail.incident_key}</span>
        </>
      }
      aside={<ElapsedClock severity={detail.severity} ruleId={detail.rule_id} firstTs={detail.first_ts} judgedAt={last?.created_at ?? null} />}
    />
  )
}
