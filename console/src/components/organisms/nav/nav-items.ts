import type { ComponentType } from 'react'
import type { Action } from '@/auth/roles'
import type { IconProps } from '../../atoms/icons'

/** 메뉴 항목 하나. 경로 정의(src/app/nav.ts)가 채운다. */
export interface NavItem {
  /** 경로. '/' 는 정확히 같을 때만 현재 위치다. 그 밖은 하위 경로(/incidents/…)도 현재 위치로 친다. */
  to: string
  label: string
  icon: ComponentType<IconProps>
  /** 이 권한이 없으면 흐리게 보인다(관리 묶음 · 화면 설계 15장). 숨기지 않는다. */
  action?: Action
}

/** 메뉴 묶음(관제 · 대응 · 분석 · 수집 · 관리) */
export interface NavGroup {
  label: string
  items: readonly NavItem[]
}

export interface NavHit {
  group: NavGroup
  item: NavItem
}

/** 경로에 맞는 메뉴 항목. 가장 긴 경로가 이긴다. 없는 주소 · 개발용 경로는 undefined. */
export function findNavItem(groups: readonly NavGroup[], pathname: string): NavHit | undefined {
  let best: NavHit | undefined
  for (const group of groups) {
    for (const item of group.items) {
      const hit = item.to === '/' ? pathname === '/' : pathname === item.to || pathname.startsWith(`${item.to}/`)
      if (hit && (!best || item.to.length > best.item.to.length)) best = { group, item }
    }
  }
  return best
}
