import { describe, expect, it } from 'vitest'
import { formatDuration, formatKst, formatRelative, toDate } from './time'

describe('formatKst', () => {
  const iso = '2026-09-18T06:20:04Z'

  it('UTC 를 KST 로 바꿔 형식대로 보인다', () => {
    expect(formatKst(iso)).toBe('2026-09-18 15:20:04')
    expect(formatKst(iso, 'minute')).toBe('2026-09-18 15:20')
    expect(formatKst(iso, 'date')).toBe('2026-09-18')
    expect(formatKst(iso, 'time')).toBe('15:20:04')
    expect(formatKst(iso, 'short')).toBe('09-18 15:20')
  })

  it('자정은 24시가 아니라 00시다', () => {
    expect(formatKst('2026-09-17T15:00:00Z')).toBe('2026-09-18 00:00:00')
  })

  it('해석할 수 없는 값은 대시', () => {
    expect(formatKst('아님')).toBe('—')
    expect(formatKst(null)).toBe('—')
    expect(toDate('')).toBeNull()
  })
})

describe('formatDuration', () => {
  const min = 60_000
  it('큰 단위 두 개까지 보인다', () => {
    expect(formatDuration((6 * 60 + 12) * min)).toBe('6시간 12분')
    expect(formatDuration(2 * min + 10_000)).toBe('2분 10초')
    expect(formatDuration(3 * 86_400_000 + 4 * 3_600_000 + 5 * min)).toBe('3일 4시간')
    expect(formatDuration(60 * min)).toBe('1시간')
    expect(formatDuration(0)).toBe('0초')
  })

  it('compact 는 목록 칸 모양(6h 12m · 4h 05m · 52m)', () => {
    expect(formatDuration((6 * 60 + 12) * min, 'compact')).toBe('6h 12m')
    expect(formatDuration((4 * 60 + 5) * min, 'compact')).toBe('4h 05m')
    expect(formatDuration(52 * min, 'compact')).toBe('52m')
  })
})

describe('formatRelative', () => {
  const now = Date.parse('2026-09-18T06:20:04Z')
  it('지난 시각 · 앞으로의 시각', () => {
    expect(formatRelative(now - 2_000, now)).toBe('방금')
    expect(formatRelative(now - 12_000, now)).toBe('12초 전')
    expect(formatRelative(now - 3 * 60_000, now)).toBe('3분 전')
    expect(formatRelative(now - 2 * 3_600_000, now)).toBe('2시간 전')
    expect(formatRelative(now - 3 * 86_400_000, now)).toBe('3일 전')
    expect(formatRelative(now + 10 * 60_000, now)).toBe('10분 후')
  })
})
