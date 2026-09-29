import { describe, expect, it } from 'vitest'
import { LIVE_BLOCK, sourceSummary } from '@/test/sources-fixtures'
import {
  CHECKER_STALE_NOTE,
  checkedPoints,
  conditionsFromSearch,
  countConditions,
  fingerprintHref,
  incidentsOfHref,
  kindFromSearch,
  requestPage,
  searchFromConditions,
  sourceExempt,
  sourceHref,
  staleCheckers,
  tabFromSearch,
  targetLabel,
} from './model'

describe('주소창 조건', () => {
  it('조건 칸을 읽고 모르는 값 · 기본 정렬 · 한쪽만 있는 지문은 뺀다', () => {
    expect(conditionsFromSearch(new URLSearchParams('q=203.0.113.&sort=severity&include_test=true&fp_kind=hassh&fp=abc'))).toEqual({
      q: '203.0.113.', sort: 'severity', include_test: true, fp: { kind: 'hassh', value: 'abc' },
    })
    expect(conditionsFromSearch(new URLSearchParams('q=%20&sort=recent&include_test=1&fp_kind=ja3&fp=abc'))).toEqual({})
    expect(conditionsFromSearch(new URLSearchParams('q=10.0.0.0/8&fp_kind=hassh'))).toEqual({})
    // 서버가 422 를 주는 지문 값(NUL · 512자 초과)은 보내지 않는다. 512자(코드 포인트)까지는 받는다
    expect(conditionsFromSearch(new URLSearchParams('fp_kind=user_agent&fp=a%00b'))).toEqual({})
    expect(conditionsFromSearch(new URLSearchParams({ fp_kind: 'user_agent', fp: 'a'.repeat(513) }))).toEqual({})
    expect(conditionsFromSearch(new URLSearchParams({ fp_kind: 'user_agent', fp: '\u{E0041}'.repeat(512) })).fp?.value).toHaveLength(1024)
  })

  it('조건 → 주소는 다른 칸(탭 · 쪽)을 두고 조건 칸만 다시 쓴다. 주소 → 조건 → 주소가 같다', () => {
    const base = new URLSearchParams('page=3&q=1.&tab=fingerprints')
    expect(searchFromConditions({ sort: 'incidents' }, base).toString()).toBe('page=3&tab=fingerprints&sort=incidents')
    const search = 'q=2001%3Adb8%3A&sort=severity&include_test=true&fp_kind=user_agent&fp=Mozilla%2F5.0+%28x%29'
    expect(searchFromConditions(conditionsFromSearch(new URLSearchParams(search))).toString()).toBe(search)
  })

  it('좁히는 조건만 센다(정렬 · 시험 대역 포함은 보기 방식)', () => {
    expect(countConditions({ sort: 'severity', include_test: true })).toBe(0)
    expect(countConditions({ q: '1.', fp: { kind: 'hassh', value: 'x' } })).toBe(2)
  })

  it('탭 · 지문 종류는 모르는 값이면 기본으로', () => {
    expect(tabFromSearch(new URLSearchParams('tab=fingerprints'))).toBe('fingerprints')
    expect(tabFromSearch(new URLSearchParams('tab=x'))).toBe('sources')
    expect(kindFromSearch(new URLSearchParams('kind=ssh_version'))).toBe('ssh_version')
    expect(kindFromSearch(new URLSearchParams('kind=__proto__'))).toBe('hassh')
  })
})

describe('경로', () => {
  it('주소 · 지문 값은 쿼리로 부호화한다', () => {
    expect(sourceHref('2001:db8::1')).toBe('/sources/detail?ip=2001%3Adb8%3A%3A1')
    expect(incidentsOfHref('203.0.113.5')).toBe('/incidents?actor_ip=203.0.113.5')
    expect(fingerprintHref('user_agent', 'a&b=c #')).toBe('/sources?include_test=true&fp_kind=user_agent&fp=a%26b%3Dc+%23')
  })

  it('대상 이름은 정해 둔 것만, 원형의 값은 읽지 않는다', () => {
    expect(targetLabel('aws-sensor')).toBe('AWS 센서')
    expect(targetLabel('toString')).toBeNull()
    // 등록 노드(#64)는 정해 둔 이름이 없어 원문(node_id)으로 그린다
    expect(targetLabel('web-02')).toBeNull()
  })
})

describe('집행기 확인', () => {
  it('멈춘 지점의 적용 확인만 확인 지연으로 바꾸고, 모르면(null) 그대로 둔다', () => {
    expect(checkedPoints(LIVE_BLOCK, { gateway_stale: true, fw_stale: true }).map((row) => [row.key, row.point.state, row.point.note])).toEqual([
      ['gateway', 'stale', CHECKER_STALE_NOTE],
      ['fw', 'pending', null],
    ])
    // 화면이 덧붙인 까닭(판단 근거)만 ⓘ 로 접는다. 지점 결과 그대로인 행은 표시가 없다
    expect(checkedPoints(LIVE_BLOCK, { gateway_stale: true, fw_stale: true }).map((row) => row.noteTip ?? false)).toEqual([true, false])
    expect(checkedPoints(LIVE_BLOCK, { gateway_stale: null, fw_stale: null }).map((row) => row.point.state)).toEqual(['confirmed', 'pending'])
    expect(checkedPoints(null, undefined)).toEqual([])
    expect(staleCheckers({ gateway_stale: true, fw_stale: null })).toEqual(['AWS 관문'])
  })
})

describe('쪽 번호 상한', () => {
  it('offset 이 서버 상한(1,000,000)을 넘지 않는 쪽까지만 묻는다', () => {
    for (const size of [25, 50, 100]) {
      const last = requestPage(1_000_000, size)
      expect((last - 1) * size).toBe(1_000_000)
      expect(requestPage(last + 1, size)).toBe(last)
    }
    expect(requestPage(40_002, 25)).toBe(40_001)
    expect(requestPage(3, 25)).toBe(3)
  })
})

describe('금지 대역 판단', () => {
  it('요약이 있으면 요약의 판단, 사건 없는 출발지는 exempt_flag(모르면 null)', () => {
    expect(sourceExempt({ summary: sourceSummary({ exempt: null }), exempt_flag: null })).toBeNull()
    expect(sourceExempt({ summary: sourceSummary({ exempt: true }), exempt_flag: true })).toBe(true)
    expect(sourceExempt({ summary: sourceSummary({ exempt: false }), exempt_flag: false })).toBe(false)
    expect(sourceExempt({ summary: null, exempt_flag: null })).toBeNull()
    expect(sourceExempt({ summary: null, exempt_flag: true })).toBe(true)
    expect(sourceExempt({ summary: null, exempt_flag: false })).toBe(false)
  })
})
