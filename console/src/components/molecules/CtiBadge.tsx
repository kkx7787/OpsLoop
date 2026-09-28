import type { CtiBadge as CtiBadgeValue } from '@/api/cti'
import { cn } from '@/lib/cn'
import { Badge, type BadgeProps } from '../atoms/Badge'
import { ctiBadgeText, ctiBadgeTitle } from './cti-badge-format'

export interface CtiBadgeProps extends Omit<BadgeProps, 'tone' | 'children' | 'title'> {
  badge: CtiBadgeValue
}

/**
 * 사건의 CVE 배지(#52): 'CVE n · KEV m · 해당|비해당|미확인'. 목록 행 · 모바일 카드 · 대상 카드의 최근 사건 · 상세 머리에 같은 컴포넌트를 쓴다.
 * 정보 색(info)에 둥근 테두리를 둘러 판정값 · 심각도 배지(각진 칠 배지)와 색 · 모양이 섞이지 않게 한다.
 * 공개 정보가 오래됐으면 말풍선과 낭독 글로 알린다(보이는 글은 서버가 올린 '미확인' 이다)
 */
export function CtiBadge({ badge, className, ...rest }: CtiBadgeProps) {
  return (
    <Badge
      tone="info"
      data-cti-badge=""
      data-applicability={badge.applicability}
      data-stale={badge.stale || undefined}
      title={ctiBadgeTitle(badge)}
      className={cn('rounded-full px-2 font-normal ring-1 ring-primary/30 ring-inset', className)}
      {...rest}
    >
      {ctiBadgeText(badge)}
      {badge.stale && <span className="sr-only"> · 공개 정보 48시간 넘음</span>}
    </Badge>
  )
}
