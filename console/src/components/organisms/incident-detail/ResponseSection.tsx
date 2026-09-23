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
  className?: string
}

/** ⑤ 조치와 판정: 조치 바 · 판정 패널(S-05) · 판정 · 조치 이력 */
export function ResponseSection({ detail, openedAt, className }: ResponseSectionProps) {
  return (
    <DetailSection number="⑤" title="조치와 판정" aside={<StatusBadge status={detail.status} />} className={className}>
      <ActionBar detail={detail} />
      <Divider />
      <VerdictPanel detail={detail} openedAt={openedAt} />
      <Divider />
      <div className="flex flex-col gap-2">
        <h3 className="m-0 text-base font-semibold tracking-heading">이력</h3>
        <HistoryList detail={detail} />
      </div>
    </DetailSection>
  )
}
