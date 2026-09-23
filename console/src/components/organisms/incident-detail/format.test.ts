import { describe, expect, it } from 'vitest'
import type { ActorBlock, BehaviorRow, RawLine } from '@/api/incidents'
import { blockState, decisionSeconds, formatRawLine, formatValue, isActiveBlock, mergeHistory, sampleColumns, summarizeBehavior } from './format'

function row(extra: Partial<BehaviorRow> = {}): BehaviorRow {
  return { ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'x', session: null, username: null, input: null, url: null, shasum: null, http_method: null, http_status: null, ...extra }
}

function block(extra: Partial<ActorBlock> = {}): ActorBlock {
  return { reason: 'console', method: 'nft', created_at: '2026-09-18T07:00:00+00:00', expires_at: '2026-09-19T07:00:00+00:00', released_at: null, enforced_at: '2026-09-18T07:00:10+00:00', ...extra }
}

describe('summarizeBehavior', () => {
  it('명령 → 요청 → 파일 → 계정 순으로 있는 것 하나', () => {
    expect(summarizeBehavior(row({ input: 'wget x', url: '/a' }))).toBe('wget x')
    expect(summarizeBehavior(row({ url: '/admin', http_method: 'POST', http_status: 403 }))).toBe('POST /admin → 403')
    expect(summarizeBehavior(row({ url: '/admin' }))).toBe('/admin')
    expect(summarizeBehavior(row({ shasum: 'abc' }))).toBe('파일 abc')
    expect(summarizeBehavior(row({ username: 'root' }))).toBe('계정 root')
    expect(summarizeBehavior(row())).toBe('—')
  })
})

describe('formatRawLine', () => {
  it('KST 시각 · 센서 · 이벤트 뒤에 있는 필드만 붙이고 비밀번호는 있었는지만', () => {
    const line: RawLine = { ...row({ session: 's1', username: 'root', input: 'id' }), has_password: true, user_agent: null, message: null }
    expect(formatRawLine(line)).toBe('2026-09-18 15:00:30  hp-01  x  session=s1  user=root  password=[있음]  input=id')
  })
})

describe('formatValue · sampleColumns', () => {
  it('시각 열은 KST 로, 객체는 JSON 으로, 빈 값은 —', () => {
    expect(formatValue('2026-09-18T06:00:00+00:00', 'ts')).toBe('2026-09-18 15:00:00')
    expect(formatValue('2026-09-18T06:00:00+00:00', 'url')).toBe('2026-09-18T06:00:00+00:00')
    expect(formatValue({ a: 1 })).toBe('{"a":1}')
    expect(formatValue(null)).toBe('—')
    expect(formatValue(3)).toBe('3')
  })

  it('객체 표본의 열을 처음 나온 순서로 모은다', () => {
    expect(sampleColumns([{ b: 1, a: 2 }, 'x', { c: 3, a: 4 }])).toEqual(['b', 'a', 'c'])
  })
})

describe('blockState · isActiveBlock', () => {
  const now = Date.parse('2026-09-18T12:00:00+00:00')

  it('해제 > 만료 > 집행 여부 순으로 판단한다', () => {
    expect(blockState(block(), now)).toBe('active')
    expect(blockState(block({ enforced_at: null }), now)).toBe('pending')
    expect(blockState(block({ released_at: '2026-09-18T08:00:00+00:00' }), now)).toBe('released')
    expect(blockState(block({ expires_at: '2026-09-18T11:00:00+00:00' }), now)).toBe('expired')
    expect(blockState(block({ expires_at: null }), now)).toBe('active')
  })

  it('풀 수 있는 차단은 살아 있거나 집행 대기인 것', () => {
    expect(isActiveBlock(null, now)).toBe(false)
    expect(isActiveBlock(block(), now)).toBe(true)
    expect(isActiveBlock(block({ enforced_at: null }), now)).toBe(true)
    expect(isActiveBlock(block({ released_at: '2026-09-18T08:00:00+00:00' }), now)).toBe(false)
  })
})

describe('decisionSeconds', () => {
  it('연 시각부터의 초. 음수와 하루 넘김은 자른다', () => {
    expect(decisionSeconds(1_000, 4_500)).toBe(3)
    expect(decisionSeconds(5_000, 4_000)).toBe(0)
    expect(decisionSeconds(0, 100 * 86_400_000)).toBe(86_400)
  })
})

describe('mergeHistory', () => {
  it('판정과 조치를 최근 순으로 섞고 같은 시각이면 판정이 위', () => {
    const merged = mergeHistory({
      verdicts: [{ id: 1, verdict: 'threat', reason: '근거', observed_value: 3, operator: 'han', created_at: '2026-09-18T08:00:00+00:00' }],
      actions: [
        { id: 1, action: 'acknowledge', operator: 'han', note: null, created_at: '2026-09-18T07:00:00+00:00' },
        { id: 2, action: 'block_ip', operator: 'han', note: '메모', created_at: '2026-09-18T08:00:00+00:00' },
        { id: 3, action: 'escalate', operator: 'han', note: null, created_at: '2026-09-18T09:00:00+00:00' },
      ],
    })
    expect(merged.map((e) => `${e.kind}:${e.label}`)).toEqual(['action:escalate', 'verdict:실제 위협', 'action:차단', 'action:확인'])
    expect(merged[1]).toMatchObject({ verdict: 'threat', note: '근거', observed_value: 3 })
  })
})
