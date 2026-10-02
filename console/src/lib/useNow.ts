import { useEffect, useState } from 'react'

/** 지금 시각(ms). intervalMs 마다 다시 읽는다. 0 이하면 처음 값에서 멈춘다(고정 표시 · 시험). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (intervalMs <= 0) return
    const update = () => setNow(Date.now())
    const visible = () => { if (document.visibilityState === 'visible') update() }
    const id = window.setInterval(update, intervalMs)
    window.addEventListener('focus', update)
    document.addEventListener('visibilitychange', visible)
    return () => {
      window.clearInterval(id)
      window.removeEventListener('focus', update)
      document.removeEventListener('visibilitychange', visible)
    }
  }, [intervalMs])
  return now
}
