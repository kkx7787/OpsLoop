import type { IncidentDetail } from '@/api/incidents'
import { Divider } from '../../atoms/Divider'
import { ActionBar } from './ActionBar'
import { DetailSection } from './DetailSection'
import { HistoryList } from './HistoryList'
import { StatusBadge } from './StatusBadge'
import { VerdictPanel } from './VerdictPanel'

export interface ResponseSectionProps {
  detail: IncidentDetail
  /** 이 사건 화면을 연 시각(ms) */
  openedAt: number
  blocked?: boolean
  className?: string
}

/** ⑤ 조치와 판정: 조치 바 · 판정 패널(S-05) · 판정 · 조치 이력 */
export function ResponseSection({ detail, openedAt, blocked = false, className }: ResponseSectionProps) {
  return (
    <DetailSection id="incident-response" tabIndex={-1} number="⑤" title="조치와 판정" aside={<StatusBadge status={detail.status} />} className={`scroll-mt-16 ${className ?? ''}`}>
      {blocked && <p className="m-0 text-sm text-warning">최신 사건 상태를 확인하지 못했습니다. 입력은 유지되며, 조회가 복구되면 조치·판정을 저장할 수 있습니다.</p>}
      <fieldset disabled={blocked} className="m-0 flex min-w-0 flex-col gap-3 border-0 p-0">
        <ActionBar detail={detail} blocked={blocked} />
        <Divider />
        <VerdictPanel detail={detail} openedAt={openedAt} blocked={blocked} />
      </fieldset>
      <Divider />
      <div className="flex flex-col gap-2">
        <h3 className="m-0 text-base font-semibold tracking-heading">이력</h3>
        <HistoryList detail={detail} />
      </div>
    </DetailSection>
  )
}
