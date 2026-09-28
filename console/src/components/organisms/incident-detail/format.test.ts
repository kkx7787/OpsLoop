import { describe, expect, it } from 'vitest'
import type { ActorBlock, BehaviorRow, RawLine } from '@/api/incidents'
import { BLOCK_STATE_LABEL, blockState, blockStateHint, decisionSeconds, enforcementPoints, formatRawLine, formatValue, isActiveBlock, mergeHistory, sampleColumns, summarizeBehavior } from './format'

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

  it('해제 > 만료 > 집행 제외 > 관문 불일치 > 집행 확인 > 집행 대기 순으로 판단한다(이슈 #47)', () => {
    expect(blockState(block(), now)).toBe('enforced')
    expect(blockState(block({ enforced_at: null }), now)).toBe('pending')
    expect(blockState(block({ released_at: '2026-09-18T08:00:00+00:00' }), now)).toBe('released')
    expect(blockState(block({ expires_at: '2026-09-18T11:00:00+00:00' }), now)).toBe('expired')
    // 만료 없는 옛 차단은 집행기가 메모를 쓰기 전에도 제외다(관문에 넘기지 않는다)
    expect(blockState(block({ expires_at: null }), now)).toBe('excluded')
    expect(blockState(block({ enforced_at: null, enforce_note: '집행 제외 · 금지 대역' }), now)).toBe('excluded')
    // 불일치는 옛 enforced_at 이 남아 있어도 불일치다
    expect(blockState(block({ enforce_note: '관문 불일치 · 관문 상태가 7분 전' }), now)).toBe('mismatch')
    expect(blockState(block({ enforce_note: '관문 반영 · abcd1234 · 2026-09-18T07:00:10Z' }), now)).toBe('enforced')
    // 해제 · 만료가 메모보다 앞선다
    expect(blockState(block({ expires_at: null, released_at: '2026-09-18T08:00:00+00:00' }), now)).toBe('released')
    expect(blockState(block({ enforce_note: '관문 불일치 · x', expires_at: '2026-09-18T11:00:00+00:00' }), now)).toBe('expired')
  })

  it('다섯 상태의 이름과 설명', () => {
    expect(BLOCK_STATE_LABEL).toMatchObject({ enforced: '집행 확인', pending: '집행 대기', excluded: '집행 제외', mismatch: '관문 불일치', released: '해제됨', expired: '만료됨' })
    expect(blockStateHint(block({ expires_at: null, enforced_at: null }), 'excluded')).toBe('만료 없는 차단 · 관문에 넘기지 않음')
    expect(blockStateHint(block(), 'mismatch')).toBe('관문 상태가 목록과 다름 · 마지막 확인')
    expect(blockStateHint(block({ enforced_at: null }), 'pending')).toBe('관문 반영 확인 전')
  })

  it('해제 · 만료 · 제외인데 관문이 뺀 것을 아직 확인하지 못했으면(enforced_at 이 남음) 빠졌다고 적지 않는다', () => {
    const released = '2026-09-18T08:00:00+00:00'
    expect(blockStateHint(block({ released_at: released, enforced_at: null }), 'released')).toBe('사람이 풂 · 관문 목록에서 빠짐')
    expect(blockStateHint(block({ released_at: released }), 'released')).toBe('사람이 풂 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ expires_at: '2026-09-18T11:00:00+00:00', enforced_at: null }), 'expired')).toBe('만료가 지남 · 관문 목록에서 빠짐')
    expect(blockStateHint(block({ expires_at: '2026-09-18T11:00:00+00:00' }), 'expired')).toBe('만료가 지남 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ enforce_note: '집행 제외 · 금지 대역' }), 'excluded')).toBe('관문에 넘기지 않음 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ enforce_note: '집행 제외 · 금지 대역', enforced_at: null }), 'excluded')).toBe('관문에 넘기지 않음')
  })

  it('풀 수 있는 차단은 살아 있는 것(집행 확인 · 대기 · 제외 · 불일치)', () => {
    expect(isActiveBlock(null, now)).toBe(false)
    expect(isActiveBlock(block(), now)).toBe(true)
    expect(isActiveBlock(block({ enforced_at: null }), now)).toBe(true)
    expect(isActiveBlock(block({ expires_at: null }), now)).toBe(true)
    expect(isActiveBlock(block({ enforce_note: '관문 불일치 · x' }), now)).toBe(true)
    expect(isActiveBlock(block({ released_at: '2026-09-18T08:00:00+00:00' }), now)).toBe(false)
    expect(isActiveBlock(block({ expires_at: '2026-09-18T11:00:00+00:00' }), now)).toBe(false)
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

describe('enforcementPoints (이슈 #51)', () => {
  it('관문 → 내부 방화벽 순으로 알려진 지점 · 상태만 돌려준다', () => {
    const rows = enforcementPoints({ enforcement: {
      fw: { state: 'stale', since: '2026-09-29T01:05:00Z', mode: 'nft', note: '내부 방화벽 보고가 5분 넘게 멈춤' },
      gateway: { state: 'confirmed', since: '2026-09-29T01:00:30Z', mode: 'fail2ban', note: null },
    } })
    expect(rows.map(r => [r.key, r.label, r.point.state])).toEqual([['gateway', 'AWS 관문', 'confirmed'], ['fw', '내부 방화벽', 'stale']])
    expect(rows[1].point.note).toBe('내부 방화벽 보고가 5분 넘게 멈춤')
  })

  it('없거나 모양이 틀리면 빈 목록 · 모르는 상태와 글자가 아닌 값은 버린다', () => {
    expect(enforcementPoints(null)).toEqual([])
    expect(enforcementPoints({})).toEqual([])
    expect(enforcementPoints({ enforcement: null })).toEqual([])
    const bad = { enforcement: { gateway: { state: 'hacked' }, fw: { state: 'pending', since: 7, mode: ['nft'], note: {} }, other: { state: 'confirmed' } } }
    expect(enforcementPoints(bad as never)).toEqual([{ key: 'fw', label: '내부 방화벽', point: { state: 'pending', since: null, mode: null, note: null } }])
    expect(enforcementPoints({ enforcement: [] as never })).toEqual([])
  })
})
