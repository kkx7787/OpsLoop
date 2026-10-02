import { describe, expect, it } from 'vitest'
import { readReturnTo } from './returnTo'

describe('목록 복귀 경로', () => {
  it('장비·정렬·쪽 조건을 바꾸지 않는다', () => {
    const href = '/incidents?device=web-01&sort=severity&page=3'
    expect(readReturnTo({ returnTo: href })).toEqual({ href, label: '인시던트 목록으로' })
    expect(readReturnTo({ returnTo: '/sources?blocked=true' }).label).toBe('출발지 목록으로')
    expect(readReturnTo({ returnTo: '/' }).label).toBe('대시보드로')
  })
  it.each(['//other.test', 'https://other.test', 'javascript:alert(1)', '/incidents/anything', '/incidents#other', '/\\other.test', null, 42])('목록 이외의 복귀 값 %s를 거부한다', (returnTo) => {
    expect(readReturnTo({ returnTo }, '/sources')).toEqual({ href: '/sources', label: '출발지 목록으로' })
  })
})
