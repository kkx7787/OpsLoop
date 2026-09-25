import type { IncidentDetail } from '@/api/incidents'
import { cn } from '@/lib/cn'
import { sensorOf, type Sensor } from '@/lib/domain'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'
import { PageHeader } from '../../molecules/PageHeader'
import { ElapsedClock } from './ElapsedClock'
import { StatusBadge } from './StatusBadge'

export interface IncidentHeaderProps {
  detail: IncidentDetail
  className?: string
}

/** 발생원에 따른 기존 목표 시간의 설명. */
const SENSOR_NOTE: Partial<Record<Sensor, string>> = {
  허니팟: '노출을 의도한 자산에서 발생한 건 · 침해사고 신고 대상이 아니다',
  '콘솔 · 감사': '콘솔에서 발생한 건 · 침해사고 신고 기한이 걸려 critical 목표를 따른다',
}

/** 규칙·심각도를 먼저 읽고, 대상·발생 구간을 별도 줄에서 확인한다. 긴 사건 키는 펼쳐 본다. */
export function IncidentHeader({ detail, className }: IncidentHeaderProps) {
  const sensor = sensorOf(detail.rule_id)
  const last = detail.verdicts[detail.verdicts.length - 1]
  return (
    <div className={cn('flex min-w-0 flex-col gap-3', className)}>
      <PageHeader
        title={<><span className="font-mono text-ink-muted">{detail.rule_id}</span> <UntrustedText value={detail.rule_name} /></>}
        badges={<>
          <SeverityBadge severity={detail.severity} />
          <StatusBadge status={detail.status} />
          {last && <VerdictBadge verdict={last.verdict} title="최근 판정" />}
        </>}
        aside={<ElapsedClock severity={detail.severity} ruleId={detail.rule_id} firstTs={detail.first_ts} judgedAt={last?.created_at ?? null} />}
      />
      <div className="flex flex-col gap-2 border-y border-line py-3">
        <dl className="m-0 flex flex-wrap gap-x-8 gap-y-2 text-xs">
          <div className="flex flex-col gap-1">
            <dt className="text-ink-muted">출발지</dt>
            <dd className="m-0 font-mono text-sm font-medium">{detail.actor_ip ?? '출발지 없음'}</dd>
          </div>
          {detail.target && <div className="flex min-w-0 flex-col gap-1">
            <dt className="text-ink-muted">대상</dt>
            <dd className="m-0 break-all font-mono text-sm font-medium">
              <UntrustedText value={detail.target} />
            </dd>
          </div>}
          <div className="flex flex-col gap-1">
            <dt className="text-ink-muted">발생 구간 · KST</dt>
            <dd className="m-0"><Time value={detail.first_ts} format="datetime" /> ~ <Time value={detail.last_ts} format="time" /></dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt className="text-ink-muted">관측</dt>
            <dd className="m-0 tabular-nums">신호 {detail.signal_count}건 · 세션 {detail.session_count}개</dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt className="text-ink-muted">수집 정보</dt>
            <dd className="m-0"><span title={SENSOR_NOTE[sensor]} data-sensor={sensor}>발생원 {sensor}</span> · {detail.rule_version}</dd>
          </div>
        </dl>
        <details className="text-xs text-ink-muted">
          <summary className="w-fit cursor-pointer py-1">사건 키</summary>
          <code className="block break-all pb-1 font-mono">
            <UntrustedText value={detail.incident_key} />
          </code>
        </details>
      </div>
    </div>
  )
}
