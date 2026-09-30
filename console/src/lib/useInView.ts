import { useEffect, useState, type RefCallback } from 'react'

/**
 * 요소가 화면(뷰포트)에 조금이라도 보이는가(#83 카드 로그 자동 갱신). IntersectionObserver 로 들어옴 · 나감을 받는다.
 * IntersectionObserver 가 없는 환경(옛 브라우저 · 시험)은 늘 보인다고 본다(useWide 와 같은 대비). 요소를 붙이기 전에도 보인다고 둔다.
 * ref 는 콜백 ref 다: 요소가 바뀌면(모바일 펼침) 다시 관찰한다.
 */
export function useInView<T extends Element>(): [RefCallback<T>, boolean] {
  const [element, setElement] = useState<T | null>(null)
  const [inView, setInView] = useState(true)
  useEffect(() => {
    if (!element || typeof IntersectionObserver !== 'function') return
    const observer = new IntersectionObserver((entries) => {
      const entry = entries[entries.length - 1]
      if (entry) setInView(entry.isIntersecting)
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [element])
  return [setElement, inView]
}
