/**
 * 관제 현황(대시보드) 조각(#52). 페이지(pages/dashboard)가 조립한다.
 *  TargetBoard(관제 대상 상태판: 데스크톱 카드 그리드 · 모바일 접힌 요약) · TargetCard(대상 한 장)
 *  target-format(수집 상태 표기 · 대응 문구(숫자 0 없음) · 자원 지표 · 취약점 한 줄 · 카드 순서(고정 대상 뒤 등록 노드))
 */
export { TargetBoard } from './TargetBoard'
export type { TargetBoardProps } from './TargetBoard'
export { TargetCard } from './TargetCard'
export type { TargetCardProps } from './TargetCard'
export {
  assetHref,
  COLLECTION_LABEL,
  COLLECTION_TONE,
  collectionState,
  formatPct,
  LABEL_MAX,
  latestLog,
  metricsText,
  orderTargets,
  pendingText,
  responseParts,
  SYSTEM_TEXT,
  systemText,
  vulnText,
} from './target-format'
export type { ResponsePart } from './target-format'
