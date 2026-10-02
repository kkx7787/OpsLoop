import { useLocation } from 'react-router'

const LABELS: Record<string, string> = {
  '/incidents': '인시던트 목록으로',
  '/sources': '출발지 목록으로',
  '/': '대시보드로',
}

export interface ReturnTo { href: string; label: string }

/** 목록 조건은 라우터 상태로 전달한다. 외부 주소·상세 주소는 복귀 대상으로 받지 않는다. */
export function readReturnTo(state: unknown, fallback = '/incidents'): ReturnTo {
  const href = state && typeof state === 'object' && 'returnTo' in state ? state.returnTo : undefined
  if (typeof href === 'string' && !href.includes('#') && !href.includes('\\')) {
    const path = href.split('?')[0]
    if (Object.hasOwn(LABELS, path)) return { href, label: LABELS[path] }
  }
  return { href: fallback, label: LABELS[fallback] }
}

/** 목록 진입 때는 그 조건, 관련 사건으로 옮길 때는 원래 목록을 이어 받는다. */
export function useReturnTo(fallback = '/incidents'): ReturnTo {
  const location = useLocation()
  if (Object.hasOwn(LABELS, location.pathname)) {
    return { href: location.pathname + location.search, label: LABELS[location.pathname] }
  }
  return readReturnTo(location.state, fallback)
}
