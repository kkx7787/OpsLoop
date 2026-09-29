import type { CtiBadge } from '@/api/cti'

/**
 * CVE 배지(#52)의 글. 목록 · 대상 카드 · 상세 머리가 같은 함수로 그려 세 곳의 글이 같다.
 *  'CVE 2 · KEV 1 · 자산 해당'  KEV 가 0 이면 KEV 칸을 뺀다. 우리 자산에 해당하지 않으면(비해당) 해당 칸을 뺀다('CVE 2 · KEV 1')
 *  'CVE 없음 · 자산 미확인'     이어진 CVE 가 없다(제품 식별 서명 R105 등)
 * 적용 요약은 서버가 정한다. 공개 정보가 오래되면 서버가 비해당을 미확인으로 올려 보낸다. 해당 여부 풀이는 말풍선에 둔다
 */
export function ctiBadgeText(badge: CtiBadge): string {
  // 비해당(우리 자산에 없는 제품의 CVE)은 배지에서 뺀다. 처음 보는 사람이 '무엇이 비해당인지' 헷갈리고, 조사 순서를 올릴 까닭도 없다.
  // 해당 · 미확인은 무엇에 대한 판단인지 알 수 있게 '자산' 을 붙인다. 모르는 값은 미확인으로 적는다(비해당으로 꾸미지 않는다)
  const applicability = badge.applicability === 'not_affected' ? null : `자산 ${badge.applicability === 'affected' ? '해당' : '미확인'}`
  if (badge.cves <= 0 && badge.kev <= 0) return ['CVE 없음', applicability].filter(Boolean).join(' · ')
  return [`CVE ${badge.cves.toLocaleString('ko-KR')}`, badge.kev > 0 && `KEV ${badge.kev.toLocaleString('ko-KR')}`, applicability].filter(Boolean).join(' · ')
}

/** 오래된 공개 정보의 말풍선. 해당 여부를 확정하지 않는다(서버가 비해당을 미확인으로 올린다) */
export const CTI_BADGE_STALE_TITLE = '공개 정보 48시간 넘음 · 우리 자산 해당 여부를 확정하지 않음'

const APPLICABILITY_TITLE: Record<string, string> = {
  affected: '우리 자산에 해당하는 CVE 가 있음',
  not_affected: '우리 자산(제품 · 판)에는 해당하지 않음',
}

/** 말풍선. 해당 여부를 풀어 쓰고, 판정값이 아니라 조사 우선순위 정보임을 밝힌다 */
export function ctiBadgeTitle(badge: CtiBadge): string {
  if (badge.stale) return CTI_BADGE_STALE_TITLE
  return `${APPLICABILITY_TITLE[badge.applicability] ?? '우리 자산 해당 여부 미확인'} · 공개 취약점 정보(CVE · KEV)는 판정값이 아니라 조사 우선순위 참고`
}
