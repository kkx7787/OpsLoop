/**
 * 인시던트 상세(S-04) · 판정 패널(S-05)의 구역 컴포넌트. 페이지(pages/incident-detail)가 조립한다.
 *  머리글  IncidentHeader(규칙 · 심각도 · 상태 · 발생원 · 출발지 · 경과) · ElapsedClock · StatusBadge
 *  구역    ① RuleEvidenceSection · ② BehaviorSection · ③ ActorSection · ④ RawLogSection · ⑤ ResponseSection
 *          ⑥ VulnLinkPanel(취약점 연계 · #39, 서명 규칙 사건만)
 *  ⑤ 안   ActionBar(조치) · VerdictPanel(판정) · HistoryList(이력)
 */
export { ActionBar } from './ActionBar'
export type { ActionBarProps } from './ActionBar'
export { ActorSection } from './ActorSection'
export type { ActorSectionProps } from './ActorSection'
export { BehaviorSection } from './BehaviorSection'
export type { BehaviorSectionProps } from './BehaviorSection'
export { DetailSection } from './DetailSection'
export type { DetailSectionProps } from './DetailSection'
export { ElapsedClock } from './ElapsedClock'
export type { ElapsedClockProps } from './ElapsedClock'
export {
  BLOCK_HOURS,
  BLOCK_STATE_LABEL,
  BLOCK_STATE_TONE,
  blockState,
  decisionSeconds,
  DEFAULT_BLOCK_HOURS,
  formatRawLine,
  formatValue,
  hoursLabel,
  incidentHref,
  isActiveBlock,
  isSampleObject,
  MAX_DECISION_SECONDS,
  MAX_ROWS,
  mergeHistory,
  sampleColumns,
  STATUS_TONE,
  summarizeBehavior,
} from './format'
export type { BlockState, HistoryEntry } from './format'
export { HistoryList } from './HistoryList'
export type { HistoryListProps } from './HistoryList'
export { IncidentHeader } from './IncidentHeader'
export type { IncidentHeaderProps } from './IncidentHeader'
export { ackPermission } from './permissions'
export { RawLogSection } from './RawLogSection'
export type { RawLogSectionProps } from './RawLogSection'
export { ResponseSection } from './ResponseSection'
export type { ResponseSectionProps } from './ResponseSection'
export { RuleEvidenceSection } from './RuleEvidenceSection'
export type { RuleEvidenceSectionProps } from './RuleEvidenceSection'
export { StatusBadge } from './StatusBadge'
export type { StatusBadgeProps } from './StatusBadge'
export { VerdictPanel } from './VerdictPanel'
export type { VerdictPanelProps } from './VerdictPanel'
export { VulnLinkPanel } from './VulnLinkPanel'
export type { VulnLinkPanelProps } from './VulnLinkPanel'
