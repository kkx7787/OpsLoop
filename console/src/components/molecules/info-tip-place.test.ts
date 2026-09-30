import { describe, expect, it } from 'vitest'
import { placeTip, TIP_GAP, TIP_GUTTER } from './info-tip-place'

const button = (left: number, top: number) => ({ left, top, bottom: top + 16 })

describe('placeTip', () => {
  it('자리가 있으면 단추 아래 왼쪽 끝에 맞춘다', () => {
    expect(placeTip(button(200, 100), { width: 300, height: 80 }, { width: 1440, height: 800 })).toEqual({ x: 200, y: 116 + TIP_GAP, side: 'below' })
  })

  it('1440 오른쪽 끝: 오른쪽 여백 16px 안으로 당긴다', () => {
    const spot = placeTip(button(1420, 60), { width: 352, height: 80 }, { width: 1440, height: 800 })
    expect(spot.x).toBe(1440 - TIP_GUTTER - 352)
    expect(spot.x + 352).toBeLessThanOrEqual(1440 - TIP_GUTTER)
  })

  it('390 가장자리: 좌우 16px 안에 들어온다', () => {
    const size = { width: 358, height: 120 }
    const viewport = { width: 390, height: 844 }
    for (const left of [0, 4, 180, 370, 386]) {
      const spot = placeTip(button(left, 300), size, viewport)
      expect(spot.x).toBeGreaterThanOrEqual(TIP_GUTTER)
      expect(spot.x + size.width).toBeLessThanOrEqual(390 - TIP_GUTTER)
    }
  })

  it('화면보다 넓은 상자는 왼쪽 여백에 붙인다', () => {
    expect(placeTip(button(300, 100), { width: 500, height: 80 }, { width: 390, height: 844 }).x).toBe(TIP_GUTTER)
  })

  it('아래 자리가 없으면 위로 뒤집는다', () => {
    expect(placeTip(button(40, 760), { width: 200, height: 100 }, { width: 1440, height: 800 })).toEqual({ x: 40, y: 760 - TIP_GAP - 100, side: 'above' })
  })

  it('위아래 어디에도 다 들어가지 않으면 넓은 쪽에 두고 화면 안으로 당긴다', () => {
    const below = placeTip(button(40, 100), { width: 200, height: 400 }, { width: 390, height: 300 })
    expect(below).toEqual({ x: 40, y: 8, side: 'below' })
    const above = placeTip(button(40, 250), { width: 200, height: 400 }, { width: 390, height: 300 })
    expect(above.side).toBe('above')
    expect(above.y).toBe(8)
  })
})
