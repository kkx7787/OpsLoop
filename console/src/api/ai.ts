import type { Verdict } from '@/lib/domain'

/** AI 판정 추천값(이슈 #120). 오탐 · 양성 정탐은 사람만 판정하므로 추천값이 아니다(판정 기준 §6) */
export type AiRecommendationValue = Extract<Verdict, 'threat' | 'non_actionable' | 'undetermined'>

/** 사건의 최신 정상 추천(app/ai_recommend.py LATEST_SQL). 추천은 판정이 아니다. 확신도는 서버가 보내지 않는다 */
export interface AiRecommendation {
  id: number
  created_at: string
  model: string
  prompt_version: string
  recommendation: AiRecommendationValue
  /** 사람 확인 필요. 모델이 요청했거나 안전장치(guard)가 붙였다 */
  needs_human: boolean
  /** 안전장치가 사람 확인을 붙인 까닭(SSH 규칙 밖 사건 · 차단 금지 대역 출발지 · 미결 추천) */
  guard: string[]
  /** 관제자가 읽을 근거 세 줄. 공격자 기록을 읽은 모델의 글이다 */
  reasons: string[]
  /** 차단 제안 시간. 위협이고 차단 금지 대역이 아닐 때만 24, 아니면 0 */
  block_hours: number
  seconds: number | null
}

/** 데이터 노드 추천 작업기의 최근 상태 한 행(ai_status). 학교 밖에서는 AI 서버에 닿지 않는 것이 정상이다 */
export interface AiStatus {
  checked_at: string
  reachable: boolean
  last_ok_at: string | null
  model: string | null
  pending: number | null
  error: string | null
}

/** 사건 상세의 AI 구역. 서버가 추천 표를 읽을 수 없으면(마이그레이션 전) 생략 · null 이고 화면은 그리지 않는다 */
export interface IncidentAi {
  recommendation: AiRecommendation | null
  /** 이 사건에 추천을 만들지 못한 횟수(작업기는 세 번까지 묻는다) */
  failed: number
  status: AiStatus | null
}

/** 대시보드 한 줄: 관제자가 추천을 보고 남긴 판정 중 판정값이 추천과 같은 수 */
export interface AiSummary {
  agreed: number
  judged: number
  status: AiStatus | null
}
