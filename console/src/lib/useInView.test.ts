import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useInView } from './useInView'

/** 가짜 IntersectionObserver. 만든 관찰자를 모아 두고 들어옴 · 나감을 흉내 낸다 */
function stubObserver() {
  const made: Array<{ callback: IntersectionObserverCallback; targets: Element[]; disconnected: boolean }> = []
  class FakeObserver {
    entry: (typeof made)[number]
    constructor(callback: IntersectionObserverCallback) {
      this.entry = { callback, targets: [], disconnected: false }
      made.push(this.entry)
    }
    observe(target: Element) {
      this.entry.targets.push(target)
    }
    disconnect() {
      this.entry.disconnected = true
    }
  }
  vi.stubGlobal('IntersectionObserver', FakeObserver)
  const fire = (isIntersecting: boolean) =>
    act(() => {
      const last = made[made.length - 1]
      last.callback([{ isIntersecting, target: last.targets[0] } as IntersectionObserverEntry], {} as IntersectionObserver)
    })
  return { made, fire }
}

afterEach(() => vi.unstubAllGlobals())

describe('useInView(#83)', () => {
  it('요소를 관찰해 들어옴 · 나감을 돌려주고, 떼면 관찰을 끊는다', () => {
    const { made, fire } = stubObserver()
    const { result, unmount } = renderHook(() => useInView<HTMLDivElement>())
    expect(result.current[1]).toBe(true)
    const el = document.createElement('div')
    act(() => result.current[0](el))
    expect(made).toHaveLength(1)
    expect(made[0].targets).toEqual([el])
    fire(false)
    expect(result.current[1]).toBe(false)
    fire(true)
    expect(result.current[1]).toBe(true)
    unmount()
    expect(made[0].disconnected).toBe(true)
  })

  it('IntersectionObserver 가 없으면 늘 보인다고 본다', () => {
    vi.stubGlobal('IntersectionObserver', undefined)
    const { result } = renderHook(() => useInView<HTMLDivElement>())
    act(() => result.current[0](document.createElement('div')))
    expect(result.current[1]).toBe(true)
  })
})
