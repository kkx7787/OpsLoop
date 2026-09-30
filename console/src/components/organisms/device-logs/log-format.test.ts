import { describe, expect, it } from 'vitest'
import { awsSensor, consoleTarget, dataNode, nodeTarget, web01 } from '@/test/targets-fixtures'
import { lineId, secondsAgo, sshLine, webLine } from '@/test/device-logs-fixtures'
import { deviceIncidentsHref, deviceLogsHref, isLogDeviceId } from '../../molecules/device-format'
import { isLogDevice } from '../dashboard/target-format'
import {
  cardTime,
  compareLines,
  countLogFilters,
  filterScope,
  futureText,
  GAP_TEXT,
  kindLabel,
  lineCode,
  lineSummary,
  lineTimeText,
  logFiltersFromSearch,
  MERGE_CAP,
  mergeLines,
  missingTimeText,
  parseStatus,
  requestText,
  searchFromLogFilters,
  sshResult,
  type LogBuffer,
} from './log-format'

const ids = (buffer: LogBuffer) => buffer.lines.map((line) => line.id)
const fresh = (buffer: LogBuffer) => buffer.lines.filter((line) => line.fresh).map((line) => line.id)
/** n 번 줄(클수록 최신)을 new → old 로 */
const range = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => webLine(to - i))

describe('mergeLines(#73)', () => {
  it('첫 적재: 시각 · id 내림차순이고 fresh 를 달지 않는다', () => {
    const same = secondsAgo(10)
    const buffer = mergeLines(null, [webLine(1), webLine(3, { ts: same }), webLine(2, { ts: same })], 100)
    expect(ids(buffer)).toEqual([lineId(3), lineId(2), lineId(1)])
    expect(fresh(buffer)).toEqual([])
    expect(buffer.gaps).toEqual([])
  })

  it('같은 id 는 한 줄이고 새 값으로 바꾼다. 처음 본 줄만 fresh 이고, 늦게 온 옛 줄도 제자리에 들어간다', () => {
    const first = mergeLines(null, [webLine(5), webLine(3)], 100)
    const second = mergeLines(first, [webLine(6), webLine(5, { url: '/새 값' }), webLine(4)], 100)
    expect(ids(second)).toEqual([6, 5, 4, 3].map(lineId))
    expect(fresh(second)).toEqual([lineId(6), lineId(4)])
    expect(second.lines[1].url).toBe('/새 값')
    // 다음 회차에 새 줄이 없으면 fresh 가 풀린다
    const third = mergeLines(second, [webLine(6), webLine(5)], 100)
    expect(fresh(third)).toEqual([])
    expect(ids(third)).toEqual([6, 5, 4, 3].map(lineId))
  })

  it('이전 목록이 비어 있어도 첫 적재 뒤에 온 줄은 fresh 다', () => {
    const empty = mergeLines(null, [], 100)
    expect(fresh(mergeLines(empty, [webLine(1)], 100))).toEqual([lineId(1)])
  })

  it('상한(기본 500)을 넘으면 오래된 줄부터 버린다', () => {
    expect(MERGE_CAP).toBe(500)
    let buffer = mergeLines(null, range(1, 200), 200)
    buffer = mergeLines(buffer, range(201, 400), 200)
    buffer = mergeLines(buffer, range(401, 600), 200)
    expect(buffer.lines).toHaveLength(500)
    expect(buffer.lines[0].id).toBe(lineId(600))
    expect(buffer.lines[499].id).toBe(lineId(101))
    expect(ids(mergeLines(null, range(1, 5), 100, 3))).toEqual([5, 4, 3].map(lineId))
  })

  it('초기화: 이전 목록 없이(null) 합치면 새 조건의 줄만 남고 fresh · 구분선이 없다', () => {
    const before = mergeLines(mergeLines(null, range(1, 3), 3), range(10, 12), 3)
    expect(before.gaps).toHaveLength(1)
    const reset = mergeLines(null, [sshLine(20)], 100)
    expect(ids(reset)).toEqual([lineId(20)])
    expect(fresh(reset)).toEqual([])
    expect(reset.gaps).toEqual([])
  })

  it('사이 끊김: 이전 줄이 있고 받은 줄이 limit 만큼이며 가장 오래된 받은 줄을 전에 본 적이 없으면 그 아래에 구분선', () => {
    const first = mergeLines(null, range(1, 3), 3)
    const jumped = mergeLines(first, range(10, 12), 3)
    expect(ids(jumped)).toEqual([12, 11, 10, 3, 2, 1].map(lineId))
    expect(jumped.gaps).toEqual([lineId(10)])
    expect(GAP_TEXT).toBe('이 사이 줄이 빠졌을 수 있음')
    // 구분선은 그 줄이 남아 있는 동안 이어진다
    expect(mergeLines(jumped, range(11, 13), 3).gaps).toEqual([lineId(10)])
  })

  it('사이 끊김: 시각이 앞선 줄이 맨 위에 남아 있어도 꽉 찬 회차가 이미 가진 줄까지 닿지 않으면 구분선', () => {
    // 1회: 평소 줄 50개와 기준 시각보다 앞선 줄 하나(서버는 as_of + 5분까지 목록에 넣는다). 다음 회차: 그 줄과 새 줄 99개로 꽉 찬다
    const ahead = webLine(999, { ts: secondsAgo(-200) })
    const first = mergeLines(null, [ahead, ...range(1, 50)], 100)
    expect(first.lines[0].id).toBe(lineId(999))
    const next = mergeLines(first, [ahead, ...range(151, 249)], 100)
    expect(next.gaps).toEqual([lineId(151)])
    // 앞선 줄이 없어도 같다
    expect(mergeLines(mergeLines(null, range(1, 50), 100), range(151, 250), 100).gaps).toEqual([lineId(151)])
  })

  it('사이 끊김이 아닌 경우: 받은 줄이 limit 보다 적음 · 겹침 · 첫 적재', () => {
    const first = mergeLines(null, range(1, 3), 3)
    expect(mergeLines(first, range(10, 11), 3).gaps).toEqual([])
    expect(mergeLines(first, range(3, 5), 3).gaps).toEqual([])
    expect(mergeLines(null, range(10, 12), 3).gaps).toEqual([])
  })

  it('구분선이 붙은 줄이 상한으로 버려지거나 맨 아래가 되면 구분선도 없앤다', () => {
    const jumped = mergeLines(mergeLines(null, range(1, 3), 3), range(10, 12), 3)
    expect(mergeLines(jumped, [], 3, 3).gaps).toEqual([])
    expect(mergeLines(jumped, [], 3, 2).gaps).toEqual([])
  })

  it('compareLines: 최신 먼저, 같은 시각은 id 내림차순', () => {
    const t = secondsAgo(5)
    expect(compareLines({ ts: t, id: lineId(2) }, { ts: t, id: lineId(1) })).toBeLessThan(0)
    expect(compareLines({ ts: secondsAgo(6), id: lineId(9) }, { ts: t, id: lineId(1) })).toBeGreaterThan(0)
    expect(compareLines({ ts: t, id: lineId(1) }, { ts: t, id: lineId(1) })).toBe(0)
  })
})

describe('줄 글', () => {
  it('SSH 결과 · 종류 라벨. 모르는 값은 그대로', () => {
    expect(['sshd.login.failed', 'sshd.login.invalid_user', 'sshd.login.success', 'sshd.other', 'toString'].map(sshResult)).toEqual(['실패', '없는 사용자', '성공', 'sshd.other', 'toString'])
    expect(['web', 'ssh', 'odd'].map(kindLabel)).toEqual(['웹 접근', 'SSH 인증', 'odd'])
  })

  it('요약은 웹이면 UA, SSH 면 메시지. 코드 칸은 응답 코드 · SSH 결과', () => {
    expect(lineSummary(webLine(1))).toBe('curl/8.5.0')
    expect(lineSummary(sshLine(1))).toBe('Failed password for root from 198.51.100.9 port 40022 ssh2')
    expect(lineCode(webLine(1, { http_status: 404 }))).toBe('404')
    expect(lineCode(webLine(1, { http_status: null }))).toBe('—')
    expect(lineCode(sshLine(1, { eventid: 'sshd.login.invalid_user' }))).toBe('없는 사용자')
    expect(requestText(webLine(1))).toBe('GET /search?q=…&page=… → 200')
    expect(requestText(sshLine(1))).toBe('실패 root')
    expect(requestText(sshLine(1, { username: null }))).toBe('실패')
  })

  it('좁은 폭 카드 시각은 KST 월-일 시:분:초', () => {
    expect(cardTime('2026-09-30T04:59:29.871000+00:00')).toBe('09-30 13:59:29')
    expect(cardTime('2026-09-30T15:00:01.000000+00:00')).toBe('10-01 00:00:01')
    expect(cardTime('틀림')).toBe('—')
  })
})

describe('시각 칸 · 경고 글', () => {
  it('값이 없을 때: 노드 표를 읽을 수 없으면 그 사실, 아니면 기록 없음', () => {
    expect(missingTimeText('unreadable')).toBe('노드 표를 읽을 수 없음')
    expect(missingTimeText('no_node')).toBe('기록 없음')
    expect(missingTimeText('ok')).toBe('기록 없음')
  })

  it('로그 종류별 마지막 줄: 선언 안 함은 수집 안 함, 선언했는데 값 없음은 기록 없음, 값이 있으면 시각', () => {
    expect(lineTimeText('ok', { declared: false, last_line_at: '2026-09-30T04:59:30+00:00' })).toBe('수집 안 함')
    expect(lineTimeText('ok', { declared: true, last_line_at: null })).toBe('기록 없음')
    expect(lineTimeText('ok', { declared: true, last_line_at: '2026-09-30T04:59:30+00:00' })).toBeNull()
    expect(lineTimeText('unreadable', { declared: null, last_line_at: null })).toBe('노드 표를 읽을 수 없음')
    expect(lineTimeText('no_node', { declared: null, last_line_at: null })).toBe('기록 없음')
  })

  it('앞선 시각 경고: 1,001(서버 상한)이면 1,000건 넘게', () => {
    expect(futureText(1)).toBe('시각이 5분 넘게 앞선 줄 1건은 목록에서 뺐습니다')
    expect(futureText(1000)).toBe('시각이 5분 넘게 앞선 줄 1,000건은 목록에서 뺐습니다')
    expect(futureText(1001)).toBe('시각이 5분 넘게 앞선 줄 1,000건 넘게는 목록에서 뺐습니다')
  })
})

describe('주소 조건', () => {
  it('모르는 종류 · 100..599 밖 응답 코드는 버린다', () => {
    const read = (qs: string) => logFiltersFromSearch(new URLSearchParams(qs))
    expect(read('kind=web&src_ip=%20203.0.113.7%20&status=404')).toEqual({ kind: 'web', src_ip: '203.0.113.7', status: 404 })
    expect(read('kind=all&status=000')).toEqual({})
    expect(['000', '99', '099', '600', '1a', '4040', '', ' ', '2e2'].map((status) => read(`status=${status}`))).toEqual(Array(9).fill({}))
    expect(read('status=100')).toEqual({ status: 100 })
    expect(read('status=599')).toEqual({ status: 599 })
    expect(read('kind=SSH&src_ip=')).toEqual({})
    expect(parseStatus(' 200 ')).toBe(200)
    expect(parseStatus(null)).toBeUndefined()
  })

  it('조건을 주소에 쓰면 값 없는 조건은 빼고 다른 인자는 남긴다', () => {
    const base = new URLSearchParams('x=1&kind=ssh&status=500')
    expect(searchFromLogFilters({ kind: 'web', src_ip: '::1' }, base).toString()).toBe('x=1&kind=web&src_ip=%3A%3A1')
    expect(searchFromLogFilters({}, base).toString()).toBe('x=1')
    expect(countLogFilters({ kind: 'web', src_ip: '1.2.3.4', status: 200 })).toBe(3)
    expect(countLogFilters({})).toBe(0)
  })

  it('조건 · 장비가 다르면 합친 목록의 키가 다르다', () => {
    expect(filterScope('web-01', {})).not.toBe(filterScope('web-01', { kind: 'web' }))
    expect(filterScope('web-01', {})).not.toBe(filterScope('web-02', {}))
    expect(filterScope('web-01', { status: 200 })).toBe(filterScope('web-01', { status: 200 }))
  })
})

describe('링크 · 대상(#73)', () => {
  it('최근 로그 · 사건 보기 주소. 장비 id 는 부호화한다', () => {
    expect(deviceLogsHref('web-01')).toBe('/devices/web-01/logs')
    expect(deviceLogsHref('a b/c?d')).toBe('/devices/a%20b%2Fc%3Fd/logs')
    expect(deviceIncidentsHref('web-01')).toBe('/incidents?device=web-01')
    expect(deviceIncidentsHref('a&b=c')).toBe('/incidents?device=a%26b%3Dc')
  })

  it('로그 화면이 있는 대상은 web-01 과 등록 노드뿐이다', () => {
    expect(isLogDevice(web01())).toBe(true)
    expect(isLogDevice(nodeTarget('web-02'))).toBe(true)
    expect(isLogDevice({ id: 'web-03' })).toBe(true)
    expect([awsSensor(), consoleTarget(), dataNode(), { id: 'mystery', kind: 'fixed' as const }].map(isLogDevice)).toEqual([false, false, false, false])
  })

  it('로그 화면 id: 장비 id 형식이고 장비 미확인 예약값이 아니다', () => {
    expect(['web-01', 'n-7', 'a'].map(isLogDeviceId)).toEqual([true, true, true])
    expect(['_unconfirmed', 'Web-01', '-a', '', 'a'.repeat(64), 'a b', 'a\u0000', 42].map(isLogDeviceId)).toEqual([false, false, false, false, false, false, false, false])
  })
})
