import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AiRecommendation, IncidentAi } from '@/api/ai'
import { expectInertDom, MIXED } from '@/test/hostile-fixtures'
import { AiRecommendationBox } from './AiRecommendationBox'

const REC: AiRecommendation = {
  id: 7,
  created_at: '2026-10-06T06:00:00+00:00',
  model: 'gpt-oss:20b',
  prompt_version: 'p3-1006',
  recommendation: 'threat',
  needs_human: false,
  guard: [],
  reasons: ['출발지가 로그인 뒤 uname -a 를 실행했습니다.', '로그인 성공 뒤 명령 실행은 위협 조건입니다.', '출발지 차단을 검토하십시오.'],
  block_hours: 24,
  seconds: 5.3,
}
const UP = { checked_at: '2026-10-06T06:05:00+00:00', reachable: true, last_ok_at: '2026-10-06T06:05:00+00:00', model: 'gpt-oss:20b', pending: 0, error: null }

function ai(extra: Partial<IncidentAi> = {}): IncidentAi {
  return { recommendation: REC, failed: 0, status: UP, ...extra }
}

describe('AiRecommendationBox', () => {
  it('추천값 · 근거 세 줄 · 차단 제안 · 모델을 보이고 확신도는 없다', () => {
    render(<AiRecommendationBox ai={ai()} chosen={null} />)
    const box = screen.getByLabelText('AI 추천')
    expect(box).toHaveTextContent('AI 추천 · 실제 위협')
    for (const line of REC.reasons) expect(box).toHaveTextContent(line)
    expect(box).toHaveTextContent('차단 제안 24시간')
    expect(box).toHaveTextContent('gpt-oss:20b')
    expect(box).not.toHaveTextContent('사람 확인 필요')
    expect(box.textContent).not.toMatch(/확신|high|confidence/)
    expect(screen.queryByRole('status')).toBeNull()
  })

  it('사람 확인이면 안전장치 까닭을 함께 적고 차단 제안은 없다', () => {
    render(<AiRecommendationBox ai={ai({ recommendation: { ...REC, recommendation: 'non_actionable', needs_human: true,
      guard: ['SSH 규칙 밖 사건', '차단 금지 대역 출발지'], block_hours: 0 } })} chosen={null} />)
    const box = screen.getByLabelText('AI 추천')
    expect(box).toHaveTextContent('AI 추천 · 무시 가능')
    expect(box).toHaveTextContent('사람 확인 필요')
    expect(box).toHaveTextContent('차단 제안 없음 · SSH 규칙 밖 사건, 차단 금지 대역 출발지')
  })

  it.each([
    ['threat', 'AI 추천과 같음'],
    ['false_positive', 'AI 추천과 다름'],
  ] as const)('%s 를 고르면 %s', (chosen, text) => {
    render(<AiRecommendationBox ai={ai()} chosen={chosen} />)
    expect(screen.getByRole('status')).toHaveTextContent(text)
  })

  it('근거는 공격자 기록을 읽은 모델의 글이라 실행되지 않는 글자로 보인다', () => {
    const { container } = render(<AiRecommendationBox ai={ai({ recommendation: { ...REC, reasons: [MIXED, MIXED, MIXED] } })} chosen={null} />)
    expect(screen.getByLabelText('AI 추천').querySelectorAll('li')).toHaveLength(3)
    expectInertDom(container)
  })

  it('AI 서버에 닿지 않으면 마지막 연결과 함께 판정은 평소대로라고 적는다', () => {
    render(<AiRecommendationBox ai={ai({ recommendation: null, failed: 0,
      status: { ...UP, reachable: false, error: 'AI 서버에 닿지 않음: timed out', last_ok_at: '2026-10-06T04:00:00+00:00' } })} chosen={null} />)
    const box = screen.getByLabelText('AI 추천')
    expect(box).toHaveTextContent('AI 추천 · 추천 없음')
    expect(box).toHaveTextContent('AI 서버에 연결되지 않아 추천을 만들지 못했습니다')
    expect(box).toHaveTextContent('마지막 연결')
    expect(box).toHaveTextContent('판정은 평소대로 할 수 있습니다.')
    expect(box).not.toHaveTextContent('timed out')            // 서버 오류 문장은 화면에 내지 않는다
  })

  it.each([
    [2, '추천을 2번 만들지 못했습니다.'],
    [0, '아직 추천이 없습니다.'],
  ])('추천이 없고 실패 %i 번이면 까닭을 한 줄로', (failed, text) => {
    render(<AiRecommendationBox ai={ai({ recommendation: null, failed })} chosen="threat" />)
    expect(screen.getByLabelText('AI 추천')).toHaveTextContent(text)
    expect(screen.queryByRole('status')).toBeNull()
  })
})
