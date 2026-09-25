/**
 * 자산 · 취약점(#39) 조각. 페이지(pages/assets)가 조립하고, 신선도 · 표기 함수는 사건 상세의 ⑥ 취약점 연계도 쓴다.
 *  WatchCard(주목 CVE: 정해 둔 CVE 의 자산별 배포판 수정판 대조) · AssetTable(자산 표) · AssetDetailSection(자산 한 대: 주요 패키지 · 이미지 · 배포판 취약점) · CtiFreshnessFacts(공개 정보 신선도)
 *  cti-format(적용 판정 · 수정 상태 색, CVSS · EPSS · 랜섬웨어 · Ubuntu 등급 표기)
 */
export { AssetDetailSection } from './AssetDetailSection'
export type { AssetDetailSectionProps } from './AssetDetailSection'
export { AssetTable } from './AssetTable'
export type { AssetTableProps } from './AssetTable'
export { CtiFreshnessFacts } from './CtiFreshnessFacts'
export type { CtiFreshnessFactsProps } from './CtiFreshnessFacts'
export { WatchCard } from './WatchCard'
export type { WatchCardProps } from './WatchCard'
export {
  APPLICABILITY_TONE,
  cvssTone,
  FIX_STATE_TONE,
  formatCvss,
  formatPercentile,
  formatProbability,
  ransomwareLabel,
  staleSources,
  truncate,
  ubuntuPriorityLabel,
  ubuntuPriorityTone,
} from './cti-format'
