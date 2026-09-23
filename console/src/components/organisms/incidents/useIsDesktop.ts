import { useSyncExternalStore } from 'react'

/** Tailwind 의 md 와 같다. 표 ↔ 카드 전환 기준. */
const DESKTOP_QUERY = '(min-width: 768px)'

function subscribe(onChange: () => void): () => void {
  if (typeof window.matchMedia !== 'function') return () => undefined
  const mq = window.matchMedia(DESKTOP_QUERY)
  mq.addEventListener('change', onChange)
  return () => mq.removeEventListener('change', onChange)
}

/** matchMedia 가 없는 환경(시험)은 데스크톱으로 본다. */
function snapshot(): boolean {
  if (typeof window.matchMedia !== 'function') return true
  return window.matchMedia(DESKTOP_QUERY).matches
}

function serverSnapshot(): boolean {
  return true
}

/**
 * 화면 폭이 md 이상인가. CSS 로만 가르면 표와 카드가 둘 다 DOM 에 남아 가상화 높이 · 낭독 순서가 꼬이므로
 * 하나만 그린다(MobileNav 의 matchMedia 처리와 같은 기준).
 */
export function useIsDesktop(): boolean {
  return useSyncExternalStore(subscribe, snapshot, serverSnapshot)
}
