import type { ReactNode } from 'react'
import type { IncidentAi } from '@/api/ai'
import { cn } from '@/lib/cn'
import type { Verdict } from '@/lib/domain'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { VerdictBadge } from '../../atoms/VerdictBadge'

export interface AiRecommendationBoxProps {
  ai: IncidentAi
  /** 관제자가 지금 고른 판정값. 고르면 추천과 같은지 다른지 한 줄로 보인다 */
  chosen: Verdict | null
  className?: string
}

/**
 * AI 판정 추천(이슈 #120). 판정 패널의 도구 제안 아래에 둔다. 추천은 판정이 아니다. 관제자가 직접 고르고, 저장할 때 본 추천이 함께 남는다.
 * 근거 세 줄은 공격자 기록을 읽은 모델의 글이라 UntrustedText 로 보인다. 확신도는 보이지 않는다(평가에서 틀린 추천 4건이 모두 high).
 * 사람 확인이 필요하면 안전장치가 붙인 까닭(SSH 규칙 밖 사건 · 차단 금지 대역 출발지 · 미결 추천)을 함께 적는다.
 * 추천이 없으면 까닭을 한 줄로 적는다. AI 서버에 닿지 않는 것(학교 밖)은 장애가 아니라 판정은 평소대로 한다.
 */
export function AiRecommendationBox({ ai, chosen, className }: AiRecommendationBoxProps) {
  const rec = ai.recommendation
  return (
    <div className={cn('border-l-2 border-primary/40 bg-canvas px-3 py-2 text-sm', className)} aria-label="AI 추천" data-ai-recommendation="">
      <p className="m-0 font-medium">
        AI 추천 · {rec ? <VerdictBadge verdict={rec.recommendation} /> : '추천 없음'}
        {rec?.needs_human && <span className="ml-1.5 text-xs font-normal text-warning">사람 확인 필요</span>}
      </p>
      {rec ? (
        <>
          <ul className="mb-0 mt-2 list-disc space-y-1 pl-4 text-xs text-ink-muted">
            {rec.reasons.map((line, i) => (
              <li key={`${i}-${line}`}>
                <UntrustedText value={line} max={200} />
              </li>
            ))}
          </ul>
          <p className="mb-0 mt-2 text-xs text-ink-muted" data-ai-meta="">
            {rec.block_hours > 0 ? `차단 제안 ${rec.block_hours}시간` : '차단 제안 없음'}
            {rec.guard.length > 0 && ` · ${rec.guard.join(', ')}`}
            {' · '}
            <UntrustedText value={rec.model} max={60} /> · <Time value={rec.created_at} format="short" />
          </p>
          {chosen && (
            <p role="status" className="mb-0 mt-2 font-medium">
              {chosen === rec.recommendation ? 'AI 추천과 같음' : 'AI 추천과 다름'}
            </p>
          )}
        </>
      ) : (
        <p className="mb-0 mt-2 text-xs text-ink-muted">{emptyReason(ai)}</p>
      )}
    </div>
  )
}

/** 추천이 없는 까닭. 닿지 않음이 먼저다(그때는 실패 횟수가 늘지 않는다) */
function emptyReason(ai: IncidentAi): ReactNode {
  const st = ai.status
  if (st && !st.reachable) {
    return (
      <>
        AI 서버에 연결되지 않아 추천을 만들지 못했습니다
        {st.last_ok_at && (
          <>
            {' '}(마지막 연결 <Time value={st.last_ok_at} format="relative" />)
          </>
        )}
        . 판정은 평소대로 할 수 있습니다.
      </>
    )
  }
  if (ai.failed > 0) return `추천을 ${ai.failed}번 만들지 못했습니다. 판정은 평소대로 할 수 있습니다.`
  return '아직 추천이 없습니다. 판정 대기 사건에는 5분 안팎으로 붙습니다.'
}
