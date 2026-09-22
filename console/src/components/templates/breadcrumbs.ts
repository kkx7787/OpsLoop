import type { Params } from 'react-router'
import { findNavItem, type NavGroup } from '../organisms/nav/nav-items'

/** 경로 정의의 handle. 상단바 경로 표시에 칸을 더한다(인시던트 키 등). */
export interface RouteHandle {
  crumb?: string | ((params: Params) => string)
}

export interface CrumbMatch {
  handle?: unknown
  params: Params
}

/** 상단바 경로 표시: 묶음 › 항목 › (handle.crumb …). 메뉴에 없는 경로는 빈 배열. */
export function breadcrumbsFor(groups: readonly NavGroup[], pathname: string, matches: readonly CrumbMatch[] = []): string[] {
  const hit = findNavItem(groups, pathname)
  const crumbs = hit ? [hit.group.label, hit.item.label] : []
  for (const match of matches) {
    const crumb = (match.handle as RouteHandle | undefined)?.crumb
    if (crumb === undefined) continue
    crumbs.push(typeof crumb === 'function' ? crumb(match.params) : crumb)
  }
  return crumbs
}
