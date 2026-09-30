import { act, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { FreshnessPart } from '@/lib/freshness'
import { AsOfStatus } from './AsOfStatus'

const NOW = Date.parse('2026-09-30T05:00:10Z')
const AS_OF = '2026-09-30T05:00:05Z' // 14:00:05 KST

function part(over: Partial<FreshnessPart> = {}): FreshnessPart {
  return { dataUpdatedAt: NOW - 5_000, errorUpdatedAt: 0, isError: false, asOf: AS_OF, ...over }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('AsOfStatus(#79)', () => {
  it('정상이면 기준 시각만 보인다(현재 시계 · 경고 없음)', () => {
    const { container } = render(<AsOfStatus parts={[part()]} now={NOW} />)
    expect(container).toHaveTextContent(/^기준 14:00:05$/)
    expect(container.querySelector('[data-as-of-warning]')).toBeNull()
    expect(container.querySelector('[data-as-of]')).toHaveAttribute('data-as-of', 'ok')
    // 마우스를 올리면 날짜까지 보인다
    expect(screen.getByText('14:00:05')).toHaveAttribute('title', '2026-09-30 14:00:05 KST')
  })

  it('일부 조회가 실패하면 오래된 쪽 시각에 일부 갱신 실패, 모두 실패면 갱신 실패를 주의색으로 붙인다', () => {
    const { container, rerender } = render(
      <AsOfStatus parts={[part({ dataUpdatedAt: NOW - 1_000, asOf: '2026-09-30T05:00:09Z' }), part({ errorUpdatedAt: NOW - 500 })]} now={NOW} />,
    )
    expect(container).toHaveTextContent(/^기준 14:00:05 · 일부 갱신 실패$/)
    expect(container.querySelector('[data-as-of-warning]')).toHaveClass('text-warning')
    rerender(<AsOfStatus parts={[part({ isError: true, errorUpdatedAt: NOW - 500 })]} now={NOW} />)
    expect(container).toHaveTextContent(/^기준 14:00:05 · 갱신 실패$/)
  })

  it('받은 적 없이 실패하면 시각 없이 갱신 실패, 받는 중이면 아무것도 그리지 않는다', () => {
    const { container, rerender } = render(<AsOfStatus parts={[part({ dataUpdatedAt: 0, asOf: null, isError: true, errorUpdatedAt: NOW })]} now={NOW} />)
    expect(container).toHaveTextContent(/^갱신 실패$/)
    rerender(<AsOfStatus parts={[part({ dataUpdatedAt: 0, asOf: null })]} now={NOW} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('조회 이벤트가 없어도 15초마다 다시 재서 90초가 지나면 n분 전 기준을 붙인다', () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    const parts = [part({ dataUpdatedAt: NOW })]
    const { container } = render(<AsOfStatus parts={parts} />)
    expect(container).toHaveTextContent(/^기준 14:00:05$/)
    act(() => void vi.advanceTimersByTime(90_000))
    expect(container).toHaveTextContent(/^기준 14:00:05$/)
    act(() => void vi.advanceTimersByTime(15_000))
    expect(container).toHaveTextContent(/^기준 14:00:05 · 1분 전 기준$/)
    act(() => void vi.advanceTimersByTime(60_000))
    expect(container).toHaveTextContent(/^기준 14:00:05 · 2분 전 기준$/)
  })
})
