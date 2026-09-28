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

  it('출발지(actor_ip)는 주소 하나일 때만 읽고, 틀린 값은 서버에 넘기지 않게 버린다', () => {
    expect(filtersFromSearch(new URLSearchParams('actor_ip=203.0.113.5'))).toEqual({ actor_ip: '203.0.113.5' })
    expect(filtersFromSearch(new URLSearchParams('actor_ip=%202001:db8::1%20'))).toEqual({ actor_ip: '2001:db8::1' })
    expect(filtersFromSearch(new URLSearchParams('actor_ip=::ffff:198.51.100.7'))).toEqual({ actor_ip: '::ffff:198.51.100.7' })
    for (const bad of ['abc', '1.2.3', '256.1.1.1', '01.2.3.4', '203.0.113.0/24', 'fe80::1%25eth0', '1:::2', '1:2:3:4:5:6:7:8:9', "1.2.3.4'--", '']) {
      expect(filtersFromSearch(new URLSearchParams({ actor_ip: bad }))).toEqual({})
    }
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
    const withActor = 'judged=false&actor_ip=2001%3Adb8%3A%3A1&sort=recent'
    expect(searchFromFilters(filtersFromSearch(new URLSearchParams(withActor))).toString()).toBe(withActor)
  })

  it('출발지 조건을 빼면 주소에서도 빠진다', () => {
    const base = new URLSearchParams('actor_ip=203.0.113.5&page=2')
    expect(searchFromFilters({}, base).toString()).toBe('page=2')
    expect(searchFromFilters({ actor_ip: '203.0.113.5', judged: false }).toString()).toBe('judged=false&actor_ip=203.0.113.5')
  })
})

describe('countFilters · clearFilters', () => {
  it('정렬은 조건으로 세지 않고, 초기화해도 정렬은 남는다', () => {
    expect(countFilters({})).toBe(0)
    expect(countFilters({ sort: 'recent' })).toBe(0)
    expect(countFilters({ status: 'open', judged: false, sort: 'recent' })).toBe(2)
    expect(clearFilters({ status: 'open', judged: false, sort: 'recent' })).toEqual({ sort: 'recent' })
    expect(clearFilters({ status: 'open' })).toEqual({})
    expect(countFilters({ actor_ip: '203.0.113.5' })).toBe(1)
    expect(clearFilters({ actor_ip: '203.0.113.5', sort: 'severity' })).toEqual({ sort: 'severity' })
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
