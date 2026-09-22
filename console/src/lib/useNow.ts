import { useEffect, useState } from 'react'

/** 지금 시각(ms). intervalMs 마다 다시 읽는다. 0 이하면 처음 값에서 멈춘다(고정 표시 · 시험). */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (intervalMs <= 0) return
    const id = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}
