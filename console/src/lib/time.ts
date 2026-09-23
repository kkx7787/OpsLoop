/**
 * 시각 표시. 저장 · 전송은 UTC(ISO 8601), 화면은 KST 로 보인다.
 * 사용자 PC 의 시간대 설정과 무관하게 같은 값을 보이려고 시간대를 못 박는다.
 */

export type TimeInput = string | number | Date

/** 날짜 · 시각 표시 형식 */
export type TimeFormat =
  | 'datetime' // 2026-09-18 15:20:04
  | 'minute' // 2026-09-18 15:20
  | 'date' // 2026-09-18
  | 'time' // 15:20:04
  | 'short' // 09-18 15:20 (목록 · 이력)

const KST = new Intl.DateTimeFormat('en-CA', {
  timeZone: 'Asia/Seoul',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
})

/** 해석할 수 없는 값은 null. */
export function toDate(value: TimeInput | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function kstParts(date: Date): Record<string, string> {
  const parts: Record<string, string> = {}
  for (const p of KST.formatToParts(date)) parts[p.type] = p.value
  return parts
}

/** KST 로 맞춘 문자열. 해석할 수 없으면 '—'. */
export function formatKst(value: TimeInput | null | undefined, format: TimeFormat = 'datetime'): string {
  const date = toDate(value)
  if (!date) return '—'
  const { year, month, day, hour, minute, second } = kstParts(date)
  switch (format) {
    case 'date':
      return `${year}-${month}-${day}`
    case 'time':
      return `${hour}:${minute}:${second}`
    case 'minute':
      return `${year}-${month}-${day} ${hour}:${minute}`
    case 'short':
      return `${month}-${day} ${hour}:${minute}`
    case 'datetime':
      return `${year}-${month}-${day} ${hour}:${minute}:${second}`
  }
}

/**
 * 경과 시간. 큰 단위 두 개까지만 보인다.
 *  long    '6시간 12분' · '2분 10초' · '3일 4시간' (상세 · 수치 타일)
 *  compact '6h 12m' · '4h 05m' · '52m' (목록의 좁은 칸)
 */
export function formatDuration(ms: number, style: 'long' | 'compact' = 'long'): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const d = Math.floor(total / 86_400)
  const h = Math.floor((total % 86_400) / 3_600)
  const m = Math.floor((total % 3_600) / 60)
  const s = total % 60

  if (style === 'compact') {
    if (d > 0) return `${d}d ${h}h`
    if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
    if (m > 0) return `${m}m`
    return `${s}s`
  }

  const units: Array<[number, string]> = [
    [d, '일'],
    [h, '시간'],
    [m, '분'],
    [s, '초'],
  ]
  const first = units.findIndex(([n]) => n > 0)
  if (first === -1) return '0초'
  return units
    .slice(first, first + 2)
    .filter(([n]) => n > 0)
    .map(([n, u]) => `${n}${u}`)
    .join(' ')
}

/** '12초 전' · '3분 전' · '2시간 전' · '3일 전'. 미래 시각은 '… 후'. */
export function formatRelative(value: TimeInput | null | undefined, now: number = Date.now()): string {
  const date = toDate(value)
  if (!date) return '—'
  const diff = now - date.getTime()
  const abs = Math.abs(diff)
  const suffix = diff >= 0 ? '전' : '후'
  if (abs < 5_000) return '방금'
  if (abs < 60_000) return `${Math.floor(abs / 1000)}초 ${suffix}`
  if (abs < 3_600_000) return `${Math.floor(abs / 60_000)}분 ${suffix}`
  if (abs < 86_400_000) return `${Math.floor(abs / 3_600_000)}시간 ${suffix}`
  return `${Math.floor(abs / 86_400_000)}일 ${suffix}`
}

/** 어떤 시각부터 지금까지 지난 초. 해석할 수 없거나 미래면 0. 상세 응답에는 pending_seconds 가 없어 first_ts 로 센다. */
export function secondsSince(value: TimeInput | null | undefined, now: number = Date.now()): number {
  const date = toDate(value)
  if (!date) return 0
  return Math.max(0, Math.floor((now - date.getTime()) / 1000))
}
