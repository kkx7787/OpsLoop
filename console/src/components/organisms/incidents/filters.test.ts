import { describe, expect, it } from 'vitest'
import type { DeviceOption, Incident, RuleQuality } from '@/api/incidents'
import { clearFilters, countFilters, deviceOptionsOf, filtersFromSearch, ruleOptionsOf, searchFromFilters } from './filters'

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

  it('장비(device)는 장비 id 또는 장비 미확인일 때만 읽고, 틀린 값은 서버에 넘기지 않게 버린다(#72)', () => {
    expect(filtersFromSearch(new URLSearchParams('device=web-01'))).toEqual({ device: 'web-01' })
    expect(filtersFromSearch(new URLSearchParams('device=%20aws-sensor%20'))).toEqual({ device: 'aws-sensor' })
    expect(filtersFromSearch(new URLSearchParams('device=_unconfirmed'))).toEqual({ device: '_unconfirmed' })
    for (const bad of ['', 'Web-01', '-web', '_x', '../x', 'web_01', 'a'.repeat(64), 'web\u0000', 'web-01;drop']) {
      expect(filtersFromSearch(new URLSearchParams({ device: bad }))).toEqual({})
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
    // 대시보드 카드 '미판정 N' 링크
    const pending = 'judged=false&device=web-01'
    expect(searchFromFilters(filtersFromSearch(new URLSearchParams(pending))).toString()).toBe(pending)
    expect(searchFromFilters({ sort: 'recent', device: '_unconfirmed', actor_ip: '203.0.113.5' }).toString()).toBe('actor_ip=203.0.113.5&device=_unconfirmed&sort=recent')
  })

  it('장비 조건을 빼면 주소에서도 빠진다', () => {
    expect(searchFromFilters({ judged: false }, new URLSearchParams('device=web-01&judged=false&page=2')).toString()).toBe('page=2&judged=false')
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
    expect(countFilters({ judged: false, device: 'web-01' })).toBe(2)
    expect(clearFilters({ device: '_unconfirmed', sort: 'recent' })).toEqual({ sort: 'recent' })
  })
})

describe('deviceOptionsOf (#72)', () => {
  const OPTIONS: DeviceOption[] = [
    { id: 'web-01', label: 'web-01', group: 'protected' },
    { id: 'web-02', label: 'web02.lab', group: 'protected' },
    { id: 'aws-sensor', label: '허니팟 센서', group: 'sensor' },
  ]

  it('서버 선택지(서버 순서) 뒤에 장비 미확인을 둔다', () => {
    expect(deviceOptionsOf(OPTIONS)).toEqual([
      { id: 'web-01', label: 'web-01' },
      { id: 'web-02', label: 'web02.lab' },
      { id: 'aws-sensor', label: '허니팟 센서' },
      { id: '_unconfirmed', label: '장비 미확인' },
    ])
    expect(deviceOptionsOf(OPTIONS, 'web-02')).toHaveLength(4)
    expect(deviceOptionsOf(OPTIONS, '_unconfirmed')).toHaveLength(4)
  })

  it('주소의 장비가 선택지에 없으면(이전 서버 · 폐기된 노드) id 를 이름으로 앞에 붙인다', () => {
    expect(deviceOptionsOf(undefined, 'web-09')).toEqual([{ id: 'web-09', label: 'web-09' }, { id: '_unconfirmed', label: '장비 미확인' }])
    expect(deviceOptionsOf(OPTIONS, 'web-09')[0]).toEqual({ id: 'web-09', label: 'web-09' })
  })

  it('형식 밖 id 는 버리고 이름이 비면 id 를 쓴다', () => {
    const bad = [{ id: 'Bad Id', label: 'x', group: 'protected' }, { id: 'web-03', label: '', group: 'protected' }, null, { id: '_unconfirmed', label: '가짜', group: 'monitor' }]
    expect(deviceOptionsOf(bad as never)).toEqual([{ id: 'web-03', label: 'web-03' }, { id: '_unconfirmed', label: '장비 미확인' }])
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

describe('미결 조건(#83)', () => {
  it('undetermined=true 만 읽고(다른 값은 버린다) 판정 칸 뒤에 붙이며 조건 하나로 센다', () => {
    expect(filtersFromSearch(new URLSearchParams('undetermined=true'))).toEqual({ undetermined: true })
    expect(filtersFromSearch(new URLSearchParams('undetermined=false'))).toEqual({})
    expect(filtersFromSearch(new URLSearchParams('undetermined=1'))).toEqual({})
    // 대시보드 카드 링크: 장비 조건과 함께
    const card = filtersFromSearch(new URLSearchParams('undetermined=true&device=web-02'))
    expect(card).toEqual({ undetermined: true, device: 'web-02' })
    expect(searchFromFilters(card).toString()).toBe('undetermined=true&device=web-02')
    expect(searchFromFilters({ judged: true, undetermined: true }).toString()).toBe('judged=true&undetermined=true')
    expect(searchFromFilters({ undetermined: false }).toString()).toBe('')
    expect(countFilters({ undetermined: true, device: 'web-02' })).toBe(2)
    expect(clearFilters({ undetermined: true, sort: 'recent' })).toEqual({ sort: 'recent' })
  })
})
