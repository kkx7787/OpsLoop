import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * 탭 제목의 새 사건 수(#72). 문서가 숨은 동안 띄운 새 사건 알림 수를 '(3) OpsLoop 관제' 처럼 앞에 붙인다.
 * 숫자만 넣는다(사건 글자는 제목에 넣지 않는다). 다시 보이면 0 으로 돌아가고, 내려가면 원래 제목으로 돌려놓는다.
 */

/** 이보다 많으면 '(99+)' */
export const TAB_BADGE_MAX = 99

/** 기준 제목에 수를 붙인 제목. 0 이하면 기준 그대로 */
export function tabTitle(base: string, count: number): string {
  if (!(count > 0)) return base
  const shown = count > TAB_BADGE_MAX ? `${TAB_BADGE_MAX}+` : String(Math.floor(count))
  return `(${shown}) ${base}`
}

function isHidden(): boolean {
  return document.visibilityState === 'hidden'
}

/**
 * 돌려주는 함수로 띄운 사건 수를 더한다. 문서가 보이는 동안은 세지 않는다.
 * 기준 제목은 마운트 때 잡고(index.html 'OpsLoop 관제'), 정리 때(언마운트 · StrictMode 두 번 실행) 되돌린다.
 */
export function useTabBadge(): (count: number) => void {
  const [count, setCount] = useState(0)
  const baseRef = useRef<string | null>(null)

  useEffect(() => {
    const base = document.title
    baseRef.current = base
    function onVisibility() {
      if (!isHidden()) setCount(0)
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      baseRef.current = null
      document.title = base
    }
  }, [])

  useEffect(() => {
    if (baseRef.current !== null) document.title = tabTitle(baseRef.current, count)
  }, [count])

  return useCallback((n: number) => {
    if (n > 0 && isHidden()) setCount((c) => c + n)
  }, [])
}
