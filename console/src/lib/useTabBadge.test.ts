import { act, renderHook } from '@testing-library/react'
import { StrictMode, createElement, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { tabTitle, useTabBadge } from './useTabBadge'

const BASE = 'OpsLoop 관제'

/** 문서 가시성을 바꾸고 visibilitychange 를 보낸다 */
function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  document.dispatchEvent(new Event('visibilitychange'))
}

describe('tabTitle', () => {
  it('0 이하는 기준 그대로, 99 까지는 수, 100 부터는 (99+)', () => {
    expect(tabTitle(BASE, 0)).toBe(BASE)
    expect(tabTitle(BASE, -1)).toBe(BASE)
    expect(tabTitle(BASE, 1)).toBe(`(1) ${BASE}`)
    expect(tabTitle(BASE, 99)).toBe(`(99) ${BASE}`)
    expect(tabTitle(BASE, 100)).toBe(`(99+) ${BASE}`)
    expect(tabTitle(BASE, 12_345)).toBe(`(99+) ${BASE}`)
  })
})

describe('useTabBadge', () => {
  beforeEach(() => {
    document.title = BASE
    setVisibility('visible')
  })

  afterEach(() => {
    Reflect.deleteProperty(document, 'visibilityState')
    document.title = ''
  })

  it('보이는 동안은 세지 않고, 숨은 동안만 늘며, 다시 보이면 0 이다', () => {
    const { result } = renderHook(() => useTabBadge())
    act(() => result.current(2))
    expect(document.title).toBe(BASE)

    setVisibility('hidden')
    act(() => result.current(2))
    expect(document.title).toBe(`(2) ${BASE}`)
    act(() => result.current(1))
    act(() => result.current(0))
    expect(document.title).toBe(`(3) ${BASE}`)

    act(() => setVisibility('visible'))
    expect(document.title).toBe(BASE)

    // 다시 숨으면 0 부터 센다
    setVisibility('hidden')
    act(() => result.current(1))
    expect(document.title).toBe(`(1) ${BASE}`)
  })

  it('100 건부터는 (99+) 로 숫자만 넣는다', () => {
    const { result } = renderHook(() => useTabBadge())
    setVisibility('hidden')
    act(() => result.current(99))
    expect(document.title).toBe(`(99) ${BASE}`)
    act(() => result.current(1))
    expect(document.title).toBe(`(99+) ${BASE}`)
  })

  it('내려가면 원래 제목으로 돌리고, 더 세지 않는다', () => {
    const { result, unmount } = renderHook(() => useTabBadge())
    setVisibility('hidden')
    act(() => result.current(5))
    expect(document.title).toBe(`(5) ${BASE}`)
    unmount()
    expect(document.title).toBe(BASE)
    act(() => setVisibility('visible'))
    expect(document.title).toBe(BASE)
  })

  it('StrictMode 의 두 번 실행에도 기준 제목이 수로 오염되지 않는다', () => {
    const wrapper = ({ children }: { children: ReactNode }) => createElement(StrictMode, null, children)
    const { result, unmount } = renderHook(() => useTabBadge(), { wrapper })
    setVisibility('hidden')
    act(() => result.current(3))
    expect(document.title).toBe(`(3) ${BASE}`)
    unmount()
    expect(document.title).toBe(BASE)
  })
})
