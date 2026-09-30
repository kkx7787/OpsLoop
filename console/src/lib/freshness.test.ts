import { describe, expect, it } from 'vitest'
import { failureWarning, freshnessPart, freshnessWarning, pageFreshness, STALE_MS, type FreshnessPart } from './freshness'

const NOW = Date.parse('2026-09-30T05:00:00Z')

function part(over: Partial<FreshnessPart> = {}): FreshnessPart {
  return { dataUpdatedAt: NOW - 10_000, errorUpdatedAt: 0, isError: false, asOf: '2026-09-30T04:59:50Z', ...over }
}

describe('pageFreshness', () => {
  it('모두 성공: 가장 오래전에 성공한 조회의 as_of 가 기준 시각이고 경고가 없다', () => {
    const f = pageFreshness([part({ dataUpdatedAt: NOW - 5_000, asOf: 'new' }), part({ dataUpdatedAt: NOW - 20_000, asOf: 'old' })], NOW)
    expect(f).toEqual({ state: 'ok', asOf: 'old', since: NOW - 20_000 })
    expect(freshnessWarning(f, NOW)).toBeNull()
  })

  it('하나 실패: 이전 값을 가진 쪽의 시각을 남기고 일부 갱신 실패', () => {
    // 요약은 방금 받았고, 상태판은 1분 전 값을 둔 채 실패했다 → 기준 시각은 상태판(오래된 쪽)
    const f = pageFreshness(
      [part({ dataUpdatedAt: NOW - 1_000, asOf: 'summary' }), part({ dataUpdatedAt: NOW - 60_000, errorUpdatedAt: NOW - 2_000, asOf: 'targets' })],
      NOW,
    )
    expect(f).toEqual({ state: 'partial', asOf: 'targets', since: NOW - 60_000 })
    expect(freshnessWarning(f, NOW)).toBe('일부 갱신 실패')
  })

  it('모두 실패: 갱신 실패. 다시 받는 중이어도(isError 꺼짐) 마지막으로 끝난 조회가 실패면 실패다', () => {
    const f = pageFreshness([part({ isError: true, errorUpdatedAt: NOW - 1_000 }), part({ isError: false, errorUpdatedAt: NOW - 500 })], NOW)
    expect(f.state).toBe('failed')
    expect(f.asOf).toBe('2026-09-30T04:59:50Z')
    expect(freshnessWarning(f, NOW)).toBe('갱신 실패')
  })

  it('조회 하나뿐인 화면(장비 로그)은 실패가 곧 갱신 실패다', () => {
    expect(pageFreshness([part({ errorUpdatedAt: NOW - 1_000 })], NOW).state).toBe('failed')
  })

  it('90초를 넘기면 n분 전 기준, 넘기지 않으면 시각만', () => {
    expect(pageFreshness([part({ dataUpdatedAt: NOW - STALE_MS })], NOW).state).toBe('ok')
    const stale = pageFreshness([part({ dataUpdatedAt: NOW - STALE_MS - 1 })], NOW)
    expect(stale.state).toBe('stale')
    expect(freshnessWarning(stale, NOW)).toBe('1분 전 기준')
    expect(freshnessWarning(pageFreshness([part({ dataUpdatedAt: NOW - 7_300_000 })], NOW), NOW)).toBe('2시간 전 기준')
    // 기준을 바꿀 수 있다
    expect(pageFreshness([part({ dataUpdatedAt: NOW - 20_000 })], NOW, 10_000).state).toBe('stale')
  })

  it('첫 조회 전 · 첫 조회 실패로 자료가 없으면 시각이 없다', () => {
    expect(pageFreshness([part({ dataUpdatedAt: 0, asOf: null })], NOW)).toEqual({ state: 'pending', asOf: null, since: null })
    expect(pageFreshness([], NOW).state).toBe('pending')
    const failed = pageFreshness([part({ dataUpdatedAt: 0, asOf: null, isError: true, errorUpdatedAt: NOW })], NOW)
    expect(failed).toEqual({ state: 'failed', asOf: null, since: null })
    // 한쪽은 받았고 다른 쪽은 첫 조회부터 실패 → 받은 쪽 시각 · 일부 갱신 실패
    const mixed = pageFreshness([part({ asOf: 'summary' }), part({ dataUpdatedAt: 0, asOf: null, isError: true, errorUpdatedAt: NOW })], NOW)
    expect(mixed).toMatchObject({ state: 'partial', asOf: 'summary' })
  })

  it('실패만 알리는 조회(카드 로그)는 시각을 정하지 않고, 실패하면 일부 갱신 실패다', () => {
    const logs = part({ dataUpdatedAt: NOW - 600_000, asOf: 'logs', failureOnly: true })
    // 오래된 로그 조회가 기준 시각을 끌어내리지 않는다
    expect(pageFreshness([part({ asOf: 'summary' }), logs], NOW)).toMatchObject({ state: 'ok', asOf: 'summary' })
    expect(pageFreshness([part({ asOf: 'summary' }), { ...logs, isError: true }], NOW)).toMatchObject({ state: 'partial', asOf: 'summary' })
    // 시각을 정하는 조회가 모두 실패면 로그 조회가 성공해도 갱신 실패다
    expect(pageFreshness([part({ isError: true }), logs], NOW).state).toBe('failed')
  })
})

describe('failureWarning', () => {
  it('낭독할 글은 갱신 실패 · 일부 갱신 실패뿐이다(정상 · 받는 중 · n분 전 기준은 비움)', () => {
    expect(failureWarning([part(), part({ errorUpdatedAt: NOW })])).toBe('일부 갱신 실패')
    expect(failureWarning([part({ isError: true })])).toBe('갱신 실패')
    expect(failureWarning([part()])).toBeNull()
    expect(failureWarning([part({ dataUpdatedAt: NOW - STALE_MS * 10 })])).toBeNull()
    expect(failureWarning([part({ dataUpdatedAt: 0, asOf: null })])).toBeNull()
    expect(failureWarning([])).toBeNull()
  })
})

describe('freshnessPart', () => {
  it('조회 결과의 세 칸과 as_of 만 옮긴다', () => {
    const query = { dataUpdatedAt: 5, errorUpdatedAt: 3, isError: false, data: { big: true }, status: 'success' }
    expect(freshnessPart(query, 'as-of')).toEqual({ dataUpdatedAt: 5, errorUpdatedAt: 3, isError: false, asOf: 'as-of', failureOnly: false })
    expect(freshnessPart(query, undefined, true)).toMatchObject({ asOf: null, failureOnly: true })
  })
})
