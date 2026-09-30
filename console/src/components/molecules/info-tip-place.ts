/**
 * 도움말 말풍선 위치(#79). 단추 아래에 두고, 아래 자리가 모자라면 위로 뒤집는다.
 * 좌우는 화면 가장자리에서 gutter(모바일 본문 여백 16px) 안쪽으로 당긴다. 값은 뷰포트 기준(position: fixed) px 이다.
 */

/** 좌우 가장자리 여백. 모바일(390) 본문 여백과 같다 */
export const TIP_GUTTER = 16
/** 단추와 말풍선 사이 */
export const TIP_GAP = 4
/** 위아래 가장자리 여백 */
const EDGE_Y = 8

export interface TipAnchor {
  left: number
  top: number
  bottom: number
}

export interface TipSize {
  width: number
  height: number
}

export interface TipViewport {
  width: number
  height: number
}

export interface TipSpot {
  x: number
  y: number
  side: 'below' | 'above'
}

export function placeTip(anchor: TipAnchor, size: TipSize, viewport: TipViewport, gutter = TIP_GUTTER): TipSpot {
  // 단추 왼쪽 끝에 맞추되 오른쪽이 넘치면 당기고, 그래도 넓으면 왼쪽 여백에 붙인다
  const x = Math.max(gutter, Math.min(anchor.left, viewport.width - gutter - size.width))
  const below = anchor.bottom + TIP_GAP
  const above = anchor.top - TIP_GAP - size.height
  const floor = viewport.height - EDGE_Y
  if (below + size.height <= floor) return { x, y: below, side: 'below' }
  if (above >= EDGE_Y) return { x, y: above, side: 'above' }
  // 어느 쪽에도 다 들어가지 않으면(아주 긴 설명 · 낮은 창) 넓은 쪽에 두고 화면 안으로 당긴다
  const side = anchor.top > viewport.height - anchor.bottom ? 'above' : 'below'
  const y = Math.max(EDGE_Y, Math.min(side === 'below' ? below : above, floor - size.height))
  return { x, y, side }
}
