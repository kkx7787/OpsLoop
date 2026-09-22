import { Card } from '@/components/atoms/Card'

export interface PendingCardProps {
  /** 채우는 WBS 항목('3.6.4') */
  wbs: string
  /** 화면 설계 번호('S-02') */
  code: string
}

/** 아직 만들지 않은 화면의 자리. 골격(3.6.1)만 있음을 밝힌다. */
export function PendingCard({ wbs, code }: PendingCardProps) {
  return (
    <Card padding="lg" className="flex flex-col gap-1.5 border border-dashed border-line shadow-none">
      <span className="text-2xs font-semibold text-ink-muted">구현 예정</span>
      <span className="text-lg font-semibold tracking-heading">WBS {wbs}</span>
      <p className="m-0 text-xs text-ink-muted">골격(3.6.1)만 있는 자리다. 화면 설계 {code} 를 따라 이 단계에서 채운다.</p>
    </Card>
  )
}
