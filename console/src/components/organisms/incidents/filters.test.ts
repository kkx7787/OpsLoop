import { describe, expect, it } from 'vitest'
import type { Incident, RuleQuality } from '@/api/incidents'
import { clearFilters, countFilters, filtersFromSearch, ruleOptionsOf, searchFromFilters } from './filters'

describe('filtersFromSearch', () => {
  it('주소의 조건 칸을 읽는다', () => {
    const params = new URLSearchParams('status=open&severity=critical&rule_id=R003&judged=false&sort=recent')
    expect(filtersFromSearch(params)).toEqual({
      status: 'open',
      severity: 'critical',
      rule_id: 'R003',
      judged: false,
      sort: 'recent',
    })
  })

  it('모르는 값 · 빈 값 · 기본 정렬은 뺀다', () => {
    const params = new URLSearchParams('status=nope&severity=&rule_id=%20&judged=maybe&sort=pending&other=1')
    expect(filtersFromSearch(params)).toEqual({})
    expect(filtersFromSearch(new URLSearchParams('judged=true'))).toEqual({ judged: true })
  })
})

describe('searchFromFilters', () => {
  it('조건 → 주소. 기본 정렬은 붙이지 않고 다른 칸은 그대로 둔다', () => {
    const base = new URLSearchParams('other=1&status=open&sort=recent')
    const next = searchFromFilters({ severity: 'high', judged: true, sort: 'pending' }, base)
    expect(next.toString()).toBe('other=1&severity=high&judged=true')
    expect(searchFromFilters({}).toString()).toBe('')
    expect(searchFromFilters({ sort: 'severity', rule_id: 'R101' }).toString()).toBe('rule_id=R101&sort=severity')
  })

  it('주소 → 조건 → 주소가 같다', () => {
    const search = 'status=acknowledged&severity=low&rule_id=R201&judged=false&sort=severity'
    expect(searchFromFilters(filtersFromSearch(new URLSearchParams(search))).toString()).toBe(search)
  })
})

describe('countFilters · clearFilters', () => {
  it('정렬은 조건으로 세지 않고, 초기화해도 정렬은 남는다', () => {
    expect(countFilters({})).toBe(0)
    expect(countFilters({ sort: 'recent' })).toBe(0)
    expect(countFilters({ status: 'open', judged: false, sort: 'recent' })).toBe(2)
    expect(clearFilters({ status: 'open', judged: false, sort: 'recent' })).toEqual({ sort: 'recent' })
    expect(clearFilters({ status: 'open' })).toEqual({})
  })
})

describe('ruleOptionsOf', () => {
  it('품질 목록의 규칙(회차 중복 제거)에 목록에서 본 이름을 붙이고 번호순으로 늘어놓는다', () => {
    const quality = [{ rule_id: 'R101' }, { rule_id: 'R003' }, { rule_id: 'R003' }] as RuleQuality[]
    const items = [
      { rule_id: 'R003', rule_name: '악성코드 투하' },
      { rule_id: 'R201', rule_name: '콘솔 로그인 실패' },
    ] as Incident[]
    expect(ruleOptionsOf(quality, items)).toEqual([
      { id: 'R003', name: '악성코드 투하' },
      { id: 'R101', name: undefined },
      { id: 'R201', name: '콘솔 로그인 실패' },
    ])
    expect(ruleOptionsOf(undefined, undefined)).toEqual([])
  })
})
