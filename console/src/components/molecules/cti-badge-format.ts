import { APPLICABILITY_LABEL, type CtiBadge } from '@/api/cti'

/**
 * CVE 배지(#52)의 글. 목록 · 대상 카드 · 상세 머리가 같은 함수로 그려 세 곳의 글이 같다.
 *  'CVE 2 · KEV 1 · 해당'  KEV 가 0 이면 KEV 칸을 뺀다('CVE 2 · 비해당')
 *  'CVE 없음 · 미확인'     이어진 CVE 가 없다(제품 식별 서명 R105 등)
 * 적용 요약은 서버가 정한다. 공개 정보가 오래되면 서버가 비해당을 미확인으로 올려 보낸다
 */
export function ctiBadgeText(badge: CtiBadge): string {
  const applicability = APPLICABILITY_LABEL[badge.applicability] ?? '미확인'
  if (badge.cves <= 0 && badge.kev <= 0) return `CVE 없음 · ${applicability}`
  return [`CVE ${badge.cves.toLocaleString('ko-KR')}`, badge.kev > 0 && `KEV ${badge.kev.toLocaleString('ko-KR')}`, applicability].filter(Boolean).join(' · ')
}

/** 오래된 공개 정보의 말풍선. 비해당으로 읽지 않는다 */
export const CTI_BADGE_STALE_TITLE = '공개 정보 48시간 넘음 · 비해당으로 읽지 않음'

/** 말풍선. 판정값이 아니라 조사 우선순위 정보임을 밝힌다 */
export function ctiBadgeTitle(badge: CtiBadge): string {
  return badge.stale ? CTI_BADGE_STALE_TITLE : '공개 취약점 정보(CVE · KEV · 자산 해당 여부) · 판정값이 아니라 조사 우선순위 참고'
}
