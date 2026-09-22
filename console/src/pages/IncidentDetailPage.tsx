import { useParams } from 'react-router'
import { Badge } from '@/components/atoms/Badge'
import { PageHeader } from '@/components/molecules/PageHeader'
import { PendingCard } from './PendingCard'

/** 인시던트 상세(S-04) · 판정 패널(S-05) 자리. 키는 경로에서 받는다(라우터가 풀어 준다). */
export function IncidentDetailPage() {
  const { key = '' } = useParams()
  return (
    <div className="flex flex-col gap-[18px]">
      <PageHeader
        title={<span className="font-mono">{key}</span>}
        badges={<Badge tone="info">S-04 · S-05</Badge>}
        description="증거 집약 · 담당 표시 · 판정 패널. 목록에서 고른 인시던트 한 건."
      />
      <PendingCard wbs="3.6.2 · 3.6.3" code="S-04 · S-05" />
    </div>
  )
}
