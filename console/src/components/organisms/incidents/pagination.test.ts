import { describe, expect, it } from 'vitest'
import { paginationFromSearch, pageNumbers } from './pagination'

describe('페이지 URL', () => {
  it.each(['-1', '0', '2.5', 'no', '1e3', '99999999999999999'])('잘못된 페이지 %s는 첫 쪽으로 제한한다', (page) => {
    expect(paginationFromSearch(new URLSearchParams({ page, page_size: '5000' }))).toEqual({ page: 1, pageSize: 25 })
  })
  it('지원하는 페이지 크기와 번호를 복원한다', () => {
    expect(paginationFromSearch(new URLSearchParams('page=3&page_size=100'))).toEqual({ page: 3, pageSize: 100 })
  })
  it.each([1, 2, 50, 99, 100])('100쪽 중 %i쪽에서도 현재·처음·끝을 보존한다', (page) => {
    const numbers = pageNumbers(page, 100)
    expect(numbers).toContain(page)
    expect(numbers[0]).toBe(1)
    expect(numbers.at(-1)).toBe(100)
    expect(numbers.length).toBeLessThanOrEqual(7)
    expect(new Set(numbers).size).toBe(numbers.length)
  })
})
