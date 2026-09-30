/**
 * 관제 현황(대시보드) 조각(#52 · #72). 페이지(pages/dashboard)가 조립만 한다.
 *  ControlHealthBand(관제 이상 띠: 멈춤 · 센서 · 탐지 경로 · 적용 실패 · 불일치 · 지점 보고 · 노드 수신 · 웹 로그 적재 · 자원 지표, 조회 실패는 '관제 상태 확인 불가')
 *  TargetBoard(보호 대상: 넓으면 두 열 카드 격자 · 좁으면 접힌 요약) · ProtectedCard(보호 대상 카드 #83) · CardLogBox(카드 최근 로그 10줄 상자)
 *  TargetCard(관측 센서 · 관제 시스템 카드) · TargetSummaryList(대상마다 한 줄로 접은 목록)
 *  SupportTargets(관측 센서 · 관제 시스템 접힌 줄) · DashboardMetrics(수치 네 칸 · 지점별 차단 · 미결) · PendingQueue(판정 대기 사건) · AgeDistribution(경과 분포)
 *  target-format(수집 상태 · 머리 배지 · 경고 배지 · 대응 문구(숫자 0 없음) · 자원 지표 · 취약점 한 줄 · 무리 나누기 · 카드 순서 · 미판정 · 미결 목록 주소)
 *  dashboard-layout(카드 · 접힌 요약 폭 판정 · 최근 사건 CVE 배지 고르기)
 */
export { AgeDistribution } from './AgeDistribution'
export type { AgeDistributionProps } from './AgeDistribution'
export { ControlHealthBand } from './ControlHealthBand'
export type { ControlHealthBandProps } from './ControlHealthBand'
export { DashboardMetrics } from './DashboardMetrics'
export type { DashboardMetricsProps } from './DashboardMetrics'
export { CardLogBox, CARD_LOG_ROWS } from './CardLogBox'
export type { CardLogBoxProps, CardLogBoxView } from './CardLogBox'
export { PendingQueue } from './PendingQueue'
export type { PendingQueueProps } from './PendingQueue'
export { ProtectedCard } from './ProtectedCard'
export type { ProtectedCardProps } from './ProtectedCard'
export { SupportTargets } from './SupportTargets'
export type { SupportTargetsProps } from './SupportTargets'
export { TargetBoard } from './TargetBoard'
export type { TargetBoardProps } from './TargetBoard'
export { TargetCard } from './TargetCard'
export type { TargetCardProps } from './TargetCard'
export { TargetSummaryList } from './TargetSummaryList'
export type { TargetSummaryListProps } from './TargetSummaryList'
export { badgeOf, latestKeys, useWide } from './dashboard-layout'
export {
  assetHref,
  COLLECTION_LABEL,
  COLLECTION_TONE,
  collectionState,
  formatPct,
  groupTargets,
  headBadge,
  LABEL_MAX,
  latestJudgedText,
  latestLog,
  metricsText,
  orderTargets,
  pendingHref,
  pendingText,
  PROTECTED_OK_LABEL,
  protectedHeadBadge,
  responseParts,
  summaryFlags,
  SYSTEM_TEXT,
  systemText,
  undeterminedHref,
  vulnSummary,
  vulnText,
} from './target-format'
export type { ResponsePart, SummaryFlag, TargetGroups, VulnSummary } from './target-format'
