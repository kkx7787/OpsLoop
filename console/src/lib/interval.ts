/** datetime-local 입력은 브라우저 지역 설정과 무관하게 화면에 명시한 KST로 읽는다. */
export function readInterval(start: string, end: string): { since?: string; until?: string } {
  if (!start && !end) return {}
  const since = new Date(`${start}+09:00`), until = new Date(`${end}+09:00`)
  if (!start || !end || !Number.isFinite(+since) || !Number.isFinite(+until) || since >= until) {
    throw new Error('시작과 종료 시각을 함께 입력하고 시작을 종료보다 앞서 지정해 주세요.')
  }
  return { since: since.toISOString(), until: until.toISOString() }
}
