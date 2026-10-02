import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useNow } from './useNow'

afterEach(() => vi.useRealTimers())

it('잠든 탭에서 돌아오면 시계가 즉시 갱신되고 판정 시작 시각은 그대로다', () => {
  vi.useFakeTimers()
  vi.setSystemTime(1000)
  const live = renderHook(() => useNow(15_000))
  const fixed = renderHook(() => useNow(0))
  vi.setSystemTime(200_000)
  act(() => window.dispatchEvent(new Event('focus')))
  expect(live.result.current).toBe(200_000)
  expect(fixed.result.current).toBe(1000)
  live.unmount()
  fixed.unmount()
  expect(vi.getTimerCount()).toBe(0)
})
