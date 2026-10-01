import { describe, expect, it } from 'vitest'
import type { ActorBlock, BehaviorRow, BlockEnforcement, BlockPoint, EnforcePointState, RawLine } from '@/api/incidents'
import {
  BLOCK_STATE_LABEL, BLOCK_STATE_TONE, blockState, blockStateHint, blockStateLabel, decisionSeconds, enforcementPoints, enforceRecord, formatRawLine, formatValue,
  gatewayCheckedAt, isActiveBlock, mergeHistory, POINT_STATE_LABEL, POINT_STATE_TONE, pointCounts, pointRows, requestedPoints, sampleColumns, summarizeBehavior,
  type BlockState,
} from './format'

function row(extra: Partial<BehaviorRow> = {}): BehaviorRow {
  return { ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'x', session: null, username: null, input: null, url: null, shasum: null, http_method: null, http_status: null, ...extra }
}

/** 지점 결과 하나(시각 · 방식 · 까닭 없음) */
const point = (state: EnforcePointState, since: string | null = null) => ({ state, since, mode: null, note: null })

/** 두 지점 요청(이전 서버처럼 points 없음) · 관문 반영(enforced_at) · 내부 방화벽 적용 확인. 요청한 지점이 모두 확인이라 집행 확인이다 */
function block(extra: Partial<ActorBlock> = {}): ActorBlock {
  return { reason: 'console', method: 'nft', created_at: '2026-09-18T07:00:00+00:00', expires_at: '2026-09-19T07:00:00+00:00', released_at: null, enforced_at: '2026-09-18T07:00:10+00:00', enforcement: { fw: point('confirmed', '2026-09-18T07:00:20+00:00') }, ...extra }
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

  it('해제 > 만료 > 집행 제외 > 실패 > 불일치 > 집행 대기 > 집행 확인 순으로 판단한다(이슈 #47 · #77)', () => {
    expect(blockState(block(), now)).toBe('enforced')
    expect(blockState(block({ enforced_at: null }), now)).toBe('pending')
    // 요청한 지점이 모두 확인이어야 집행 확인이다(결정 b). 관문만 확인이고 내부 방화벽 기록이 없으면 대기
    expect(blockState(block({ enforcement: null }), now)).toBe('pending')
    expect(blockState(block({ enforcement: { fw: point('failed') } }), now)).toBe('failed')
    expect(blockState(block({ enforcement: { fw: point('stale') } }), now)).toBe('mismatch')
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

  it('합친 수의 이름에는 지점이 없고, 행의 불일치 이름 · 설명은 그 지점 이름이다(이슈 #77)', () => {
    expect(BLOCK_STATE_LABEL).toEqual({ enforced: '집행 확인', pending: '집행 대기', excluded: '집행 제외', failed: '집행 실패', mismatch: '불일치', released: '해제됨', expired: '만료됨' })
    const gatewayOff = block({ enforce_note: '관문 불일치 · 관문 상태가 7분 전' })
    const fwStale = block({ enforcement: { fw: point('stale') } })
    const both = block({ enforce_note: '관문 불일치 · x', enforcement: { fw: point('stale') } })
    expect([gatewayOff, fwStale, both].map((b) => blockStateLabel(b, blockState(b, now)))).toEqual(['관문 불일치', '내부 방화벽 불일치', '관문 · 내부 방화벽 불일치'])
    // 불일치가 아니면 합친 이름 그대로
    expect(blockStateLabel(block(), 'enforced')).toBe('집행 확인')
    expect(blockStateLabel(block({ enforcement: { fw: point('failed') } }), 'failed')).toBe('집행 실패')
    // 설명: 관문 확인 시각(마지막 확인)은 관문 불일치일 때만 잇는다
    expect(blockStateHint(gatewayOff, 'mismatch')).toBe('관문 상태가 목록과 다름 · 마지막 확인')
    expect(blockStateHint(fwStale, 'mismatch')).toBe('내부 방화벽 상태가 목록과 다름')
    expect(blockStateHint(block({ enforced_at: null, enforce_note: '관문 불일치 · x' }), 'mismatch')).toBe('관문 상태가 목록과 다름')
    // 대기 · 실패는 확인하지 못한 · 실패한 지점만, 집행 확인 · 제외는 요청 지점 모두
    expect(blockStateHint(block({ enforced_at: null }), 'pending')).toBe('관문 반영 확인 전')
    expect(blockStateHint(block({ enforcement: null }), 'pending')).toBe('내부 방화벽 반영 확인 전')
    expect(blockStateHint(block({ enforced_at: null, enforcement: null }), 'pending')).toBe('관문 · 내부 방화벽 반영 확인 전')
    expect(blockStateHint(block({ enforcement: { fw: point('failed') } }), 'failed')).toBe('내부 방화벽 적용 실패')
    expect(blockStateHint(block(), 'enforced')).toBe('관문 · 내부 방화벽 반영 확인')
    const fwOnly = block({ points: ['fw'], method: null, enforced_at: null })
    expect(blockState(fwOnly, now)).toBe('enforced')
    expect(blockStateHint(fwOnly, 'enforced')).toBe('내부 방화벽 반영 확인')
    expect(blockStateHint(block({ expires_at: null, enforced_at: null, enforcement: null }), 'excluded')).toBe('만료 없는 차단 · 관문 · 내부 방화벽에 넘기지 않음')
    expect(blockStateHint(block({ points: ['fw'], expires_at: null, enforced_at: null, enforcement: null }), 'excluded')).toBe('만료 없는 차단 · 내부 방화벽에 넘기지 않음')
    // 관리자 관문 빼기 뒤(결정 14): 관문이 뺐다고 확인될 때까지 관문 세 열 · 관문 결과가 남아 설명에 덧붙인다(관문 시각은 보이지 않는다)
    const narrowed = block({ points: ['fw'], enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('removing'), fw: point('confirmed') } })
    expect(blockState(narrowed, now)).toBe('enforced')
    expect(blockStateHint(narrowed, 'enforced')).toBe('내부 방화벽 반영 확인 · 관문에서 빠졌는지 확인 전')
    expect(gatewayCheckedAt(narrowed, 'enforced')).toBeNull()
    expect(blockStateHint(block({ points: ['fw'], enforced_at: null, enforcement: { gateway: point('removing'), fw: point('stale') } }), 'mismatch')).toBe('내부 방화벽 상태가 목록과 다름 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ points: ['fw'], released_at: '2026-09-18T08:00:00+00:00', enforced_at: null, enforcement: { gateway: point('removing') } }), 'released')).toBe('사람이 풂 · 관문에서 빠졌는지 확인 전')
    // 빠짐 확인 전에 관문을 다시 요청(집행기 다음 회차 전): 남은 확인 시각이 있어도 관문 칸 '대기' 와 같이 집행 대기다(관문 시각은 보이지 않는다)
    const rewidened = block({ points: ['gateway', 'fw'], enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('removing'), fw: point('confirmed') } })
    expect(blockState(rewidened, now)).toBe('pending')
    expect(blockStateLabel(rewidened, 'pending')).toBe('집행 대기')
    expect(blockStateHint(rewidened, 'pending')).toBe('관문 반영 확인 전')
    expect(gatewayCheckedAt(rewidened, 'pending')).toBeNull()
    expect(pointRows(rewidened, now).map((r) => [r.key, r.point.state])).toEqual([['gateway', 'pending'], ['fw', 'confirmed']])
    // 해제 · 만료 행을 관문을 포함해 다시 건 뒤(결정 2): 세 열은 요청 시각에 비지 않는다. 새 목록을 확인하기 전(관문 결과 대기)은 남은
    // 확인 시각이 있어도 집행 대기이고(관문 시각은 보이지 않는다), 확인되면 쪽지 끝에 '기존 차단 유지' · '연속성 확인 불가'(결정 3)가
    // 붙은 채 집행 확인이다
    const rearmed = block({ points: ['gateway', 'fw'], enforce_note: '관문 반영 · abcd1234 · x', enforcement: { gateway: point('pending'), fw: point('confirmed') } })
    expect(blockState(rearmed, now)).toBe('pending')
    expect(blockStateHint(rearmed, 'pending')).toBe('관문 반영 확인 전')
    expect(gatewayCheckedAt(rearmed, 'pending')).toBeNull()
    expect(pointRows(rearmed, now).map((r) => [r.key, r.point.state])).toEqual([['gateway', 'pending'], ['fw', 'confirmed']])
    const kept = block({ points: ['gateway', 'fw'], enforce_note: '관문 반영 · abcd1234 · x · 기존 차단 유지', enforcement: { gateway: point('confirmed'), fw: point('confirmed') } })
    expect(blockState(kept, now)).toBe('enforced')
    expect(gatewayCheckedAt(kept, 'enforced')).toBe(kept.enforced_at)
    expect(enforceRecord(kept)).toEqual({ method: 'nft', note: '관문 반영 · abcd1234 · x · 기존 차단 유지' })
    const uncertain = block({ points: ['gateway', 'fw'], enforce_note: '관문 반영 · abcd1234 · x · 연속성 확인 불가', enforcement: { gateway: point('confirmed'), fw: point('confirmed') } })
    expect(blockState(uncertain, now)).toBe('enforced')
    expect(gatewayCheckedAt(uncertain, 'enforced')).toBe(uncertain.enforced_at)
    expect(enforceRecord(uncertain)).toEqual({ method: 'nft', note: '관문 반영 · abcd1234 · x · 연속성 확인 불가' })
  })

  it('방식 · 집행 메모는 관문을 요청한 행만 보이고, 관문을 뺀 행에 남은 관문 기록은 보이지 않는다(집행 제외 쪽지는 보인다)', () => {
    const applied = '관문 반영 · abcd1234 · x'
    expect(enforceRecord(block({ enforce_note: applied }))).toEqual({ method: 'nft', note: applied })
    expect(enforceRecord(block({ points: ['gateway', 'fw'], method: 'fail2ban', enforce_note: '관문 불일치 · x' }))).toEqual({ method: 'fail2ban', note: '관문 불일치 · x' })
    expect(enforceRecord(block({ points: ['fw'], method: 'fail2ban', enforce_note: '관문 불일치 · 5분 넘게 반영되지 않음' }))).toEqual({ method: null, note: null })
    expect(enforceRecord(block({ points: ['fw'], enforce_note: applied }))).toEqual({ method: null, note: null })
    expect(enforceRecord(block({ points: ['fw'], method: null, enforced_at: null, enforce_note: '집행 제외 · 금지 대역' }))).toEqual({ method: null, note: '집행 제외 · 금지 대역' })
    expect(enforceRecord(block({ method: null, enforce_note: null }))).toEqual({ method: null, note: null })
  })

  it('상태 칸의 관문 확인 시각은 관문을 요청한 행의 집행 확인 · 관문 불일치일 때만', () => {
    const at = '2026-09-18T07:00:10+00:00'
    expect(gatewayCheckedAt(block(), 'enforced')).toBe(at)
    expect(gatewayCheckedAt(block({ enforce_note: '관문 불일치 · x' }), 'mismatch')).toBe(at)
    expect(gatewayCheckedAt(block({ enforcement: { fw: point('stale') } }), 'mismatch')).toBeNull()
    expect(gatewayCheckedAt(block({ enforcement: null }), 'pending')).toBeNull()
    // 옛 집행기 시절 관문 세 열이 남은 내부 방화벽 전용 행은 관문 시각을 보이지 않는다
    expect(gatewayCheckedAt(block({ points: ['fw'] }), 'enforced')).toBeNull()
  })

  it('해제 · 만료 · 제외인데 요청 지점이 뺀 것을 아직 확인하지 못했으면(결과 기록 · 관문 enforced_at 이 남음) 빠졌다고 적지 않는다', () => {
    const released = '2026-09-18T08:00:00+00:00'
    const past = '2026-09-18T11:00:00+00:00'
    expect(blockStateHint(block({ released_at: released, enforced_at: null, enforcement: null }), 'released')).toBe('사람이 풂 · 관문 · 내부 방화벽 목록에서 빠짐')
    expect(blockStateHint(block({ released_at: released, enforcement: { gateway: point('removing'), fw: point('removing') } }), 'released')).toBe('사람이 풂 · 관문 · 내부 방화벽에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ released_at: released, enforcement: null }), 'released')).toBe('사람이 풂 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ released_at: released, enforced_at: null, enforcement: { fw: point('removing') } }), 'released')).toBe('사람이 풂 · 내부 방화벽에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ expires_at: past, enforced_at: null, enforcement: null }), 'expired')).toBe('만료가 지남 · 관문 · 내부 방화벽 목록에서 빠짐')
    expect(blockStateHint(block({ expires_at: past, enforcement: null }), 'expired')).toBe('만료가 지남 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ points: ['fw'], expires_at: past, enforced_at: null, enforcement: null }), 'expired')).toBe('만료가 지남 · 내부 방화벽 목록에서 빠짐')
    expect(blockStateHint(block({ enforce_note: '집행 제외 · 금지 대역', enforcement: null }), 'excluded')).toBe('관문 · 내부 방화벽에 넘기지 않음 · 관문에서 빠졌는지 확인 전')
    expect(blockStateHint(block({ enforce_note: '집행 제외 · 금지 대역', enforced_at: null, enforcement: null }), 'excluded')).toBe('관문 · 내부 방화벽에 넘기지 않음')
  })

  it('풀 수 있는 차단은 살아 있는 것(집행 확인 · 대기 · 실패 · 제외 · 불일치)', () => {
    expect(isActiveBlock(null, now)).toBe(false)
    expect(isActiveBlock(block(), now)).toBe(true)
    expect(isActiveBlock(block({ enforcement: { fw: point('failed') } }), now)).toBe(true)
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
    expect(rows.map(r => [r.key, r.label, r.point.state])).toEqual([['gateway', '허니팟 관문', 'confirmed'], ['fw', '내부 방화벽', 'stale']])
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

  it('빠짐 확인 전(removing, 이슈 #77)은 아는 상태다', () => {
    expect(enforcementPoints({ enforcement: { fw: point('removing', '2026-09-29T01:05:00Z') } }).map((r) => [r.key, r.point.state, r.point.since])).toEqual([['fw', 'removing', '2026-09-29T01:05:00Z']])
  })
})

/**
 * 종합 상태 경우 표(결정 b). 서버 app/test_block_points.py 의 STATE_CASES 를 이름 · 순서 그대로 옮긴 것이다(서버 block_points.STATE_CASE 와
 * 같은 경우). (이름, 요청 지점, 만료 있음, 관문 확인 시각 있음, enforce_note, enforcement, 기대 상태)
 */
const GF: BlockPoint[] = ['gateway', 'fw']
const F: BlockPoint[] = ['fw']
const [C, P, S, X, R] = (['confirmed', 'pending', 'stale', 'failed', 'removing'] as const).map((state) => point(state))
const APPLIED = '관문 반영 · abcd1234 · x'
const KEPT = `${APPLIED} · 기존 차단 유지`
const UNCERTAIN = `${APPLIED} · 연속성 확인 불가`
const MISMATCH = '관문 불일치 · 5분 넘게 반영되지 않음'
const EXCLUDED = '집행 제외 · 금지 대역'
const STATE_CASES: Array<[string, BlockPoint[], boolean, boolean, string | null, BlockEnforcement | null, BlockState]> = [
  ['두 지점 · 모두 확인', GF, true, true, APPLIED, { gateway: C, fw: C }, 'enforced'],
  ['두 지점 · 관문 확인 · 내부 방화벽 대기', GF, true, true, APPLIED, { gateway: C, fw: P }, 'pending'],
  ['두 지점 · 관문 확인 · 내부 방화벽 기록 없음', GF, true, true, APPLIED, null, 'pending'],
  ['두 지점 · 내부 방화벽 확인 · 관문 확인 전', GF, true, false, null, { fw: C }, 'pending'],
  ['두 지점 · 다시 건 직후 남은 빠짐 확인 전', GF, true, false, null, { gateway: R, fw: R }, 'pending'],
  ['두 지점 · 관문 빼기 뒤 다시 요청(집행기 회차 전)', GF, true, true, APPLIED, { gateway: R, fw: C }, 'pending'],
  ['두 지점 · 다시 건 뒤 관문 새 목록 확인 전(남은 확인 시각)', GF, true, true, APPLIED, { gateway: P, fw: C }, 'pending'],
  ['두 지점 · 관문이 뺀 뒤 다시 건 행(확인 시각 없이 남은 쪽지)', GF, true, false, APPLIED, { gateway: P, fw: C }, 'pending'],
  ['두 지점 · 기존 차단 유지로 다시 확인', GF, true, true, KEPT, { gateway: C, fw: C }, 'enforced'],
  ['두 지점 · 연속성 확인 불가로 다시 확인', GF, true, true, UNCERTAIN, { gateway: C, fw: C }, 'enforced'],
  ['두 지점 · 내부 방화벽 지연', GF, true, true, APPLIED, { gateway: C, fw: S }, 'mismatch'],
  ['두 지점 · 관문 불일치 쪽지', GF, true, false, MISMATCH, { gateway: S, fw: C }, 'mismatch'],
  ['두 지점 · 관문 지연(쪽지 전)', GF, true, true, APPLIED, { gateway: S, fw: C }, 'mismatch'],
  ['두 지점 · 내부 방화벽 실패', GF, true, true, APPLIED, { gateway: C, fw: X }, 'failed'],
  ['두 지점 · 관문 실패가 불일치 쪽지보다 먼저', GF, true, false, '관문 불일치 · 관문 거부 · x', { gateway: X, fw: S }, 'failed'],
  ['내부 방화벽만 · 확인(관문 열 없음)', F, true, false, null, { fw: C }, 'enforced'],
  ['내부 방화벽만 · 대기', F, true, false, null, { fw: P }, 'pending'],
  ['내부 방화벽만 · 기록 없음', F, true, false, null, null, 'pending'],
  ['내부 방화벽만 · 지연', F, true, false, null, { fw: S }, 'mismatch'],
  ['내부 방화벽만 · 실패', F, true, false, null, { fw: X }, 'failed'],
  ['내부 방화벽만 · 남은 관문 쪽지 · 관문 실패는 보지 않음', F, true, true, MISMATCH, { gateway: X, fw: C }, 'enforced'],
  ['내부 방화벽만 · 관문 빠짐 확인 전은 보지 않음', F, true, true, APPLIED, { gateway: R, fw: C }, 'enforced'],
  ['내부 방화벽만 · 관문 빠짐 확인 전 · 내부 방화벽 대기', F, true, true, APPLIED, { gateway: R, fw: P }, 'pending'],
  ['두 지점 · 만료 없음', GF, false, true, APPLIED, { gateway: C, fw: C }, 'excluded'],
  ['내부 방화벽만 · 집행 제외 쪽지가 실패보다 먼저', F, true, false, EXCLUDED, { fw: X }, 'excluded'],
]

describe('종합 상태 경우 표 (서버 STATE_CASE 와 같다 · 결정 b)', () => {
  const now = Date.parse('2026-09-18T12:00:00+00:00')

  it.each(STATE_CASES)('%s', (_name, points, expires, enforced, note, enforcement, want) => {
    const row = block({ points, expires_at: expires ? '2026-09-18T13:00:00+00:00' : null, enforced_at: enforced ? '2026-09-18T11:00:00+00:00' : null, enforce_note: note, enforcement })
    expect(blockState(row, now)).toBe(want)
  })

  it('표는 24건이고 살아 있는 다섯 상태를 모두 덮는다', () => {
    expect(STATE_CASES).toHaveLength(25)
    expect(new Set(STATE_CASES.map((c) => c[6]))).toEqual(new Set(['enforced', 'pending', 'excluded', 'mismatch', 'failed']))
  })
})

/**
 * 지점 칸 경우 표(결정 14). 서버 app/test_block_points.py 의 POINT_CASES 를 이름 · 순서 그대로 옮긴 것이다(targets.BLOCKS_SQL 과 같은 경우).
 * (이름, 요청 지점, 관문 확인 시각 있음, enforcement, 관문 칸, 내부 방화벽 칸). 칸은 pointCounts 의 적용 · 실패 · 미확인 · 미요청 · 빠짐 확인 전
 */
type Cell = 'applied' | 'failed' | 'unverified' | 'unrequested' | 'removing'
const POINT_CASES: Array<[string, BlockPoint[], boolean, BlockEnforcement, Cell, Cell]> = [
  ['두 지점 · 모두 확인', GF, true, { gateway: C, fw: C }, 'applied', 'applied'],
  ['두 지점 · 관문 실패 · 내부 방화벽 대기', GF, false, { gateway: X, fw: P }, 'failed', 'unverified'],
  ['두 지점 · 다시 건 직후 남은 빠짐 확인 전', GF, false, { gateway: R, fw: R }, 'unverified', 'unverified'],
  ['두 지점 · 관문 빼기 뒤 다시 요청(집행기 회차 전)', GF, true, { gateway: R, fw: C }, 'unverified', 'applied'],
  ['두 지점 · 다시 건 뒤 관문 새 목록 확인 전(남은 확인 시각)', GF, true, { gateway: P, fw: C }, 'unverified', 'applied'],
  ['내부 방화벽만 · 관문 기록 없음', F, false, { fw: C }, 'unrequested', 'applied'],
  ['내부 방화벽만 · 관문 기록의 state 가 글자가 아님', F, false, { gateway: { state: 1 }, fw: C } as never, 'unrequested', 'applied'],
  ['내부 방화벽만 · 관문 빼기 직후(관문 세 열 · 관문 결과 남음)', F, true, { gateway: C, fw: C }, 'removing', 'applied'],
  ['내부 방화벽만 · 관문 빠짐 확인 전', F, true, { gateway: R, fw: C }, 'removing', 'applied'],
  ['내부 방화벽만 · 관문 확인 전에 뺌(결과만 남음)', F, false, { gateway: R, fw: X }, 'removing', 'failed'],
  ['내부 방화벽만 · 관문 확인 시각만 남음(옛 집행기)', F, true, { fw: S }, 'removing', 'unverified'],
  ['내부 방화벽만 · 남은 관문 실패 기록', F, false, { gateway: X }, 'removing', 'unverified'],
]

describe('지점 칸 경우 표 (서버 BLOCKS_SQL 과 같다 · 결정 14)', () => {
  const now = Date.parse('2026-09-18T12:00:00+00:00')
  const cells: Cell[] = ['applied', 'failed', 'unverified', 'unrequested', 'removing']

  it.each(POINT_CASES)('%s', (_name, points, enforced, enforcement, gateway, fw) => {
    const row = block({ points, expires_at: '2026-09-18T13:00:00+00:00', enforced_at: enforced ? '2026-09-18T11:00:00+00:00' : null, enforce_note: enforced ? APPLIED : null, enforcement })
    for (const [p, want] of [['gateway', gateway], ['fw', fw]] as const) {
      const tally = pointCounts([row], now, p)
      expect(cells.filter((c) => tally[c] === 1)).toEqual([want])
      expect(cells.reduce((sum, c) => sum + tally[c], 0)).toBe(1)
    }
    // 지점 칸도 같다: 요청하지 않은 지점은 기록이 남았으면 빠짐 확인 전, 아니면 미요청
    const cell = pointRows(row, now).find((r) => r.key === 'gateway')?.point.state
    expect(gateway === 'removing' || gateway === 'unrequested' ? cell : gateway).toBe(gateway)
  })

  it('표는 다섯 칸을 모두 덮는다', () => {
    expect(new Set(POINT_CASES.flatMap((c) => [c[4], c[5]]))).toEqual(new Set(cells))
  })
})

describe('requestedPoints · pointRows (이슈 #77)', () => {
  const now = Date.parse('2026-09-18T12:00:00+00:00')
  const released = '2026-09-18T08:00:00+00:00'
  const cells = (b: ActorBlock) => pointRows(b, now).map((r) => [r.key, r.point.state])

  it('요청 지점은 정규 순서이고, 없거나 모양이 틀리면 두 지점이다(이전 서버)', () => {
    expect(requestedPoints(null)).toEqual(['gateway', 'fw'])
    expect(requestedPoints({})).toEqual(['gateway', 'fw'])
    expect(requestedPoints({ points: null })).toEqual(['gateway', 'fw'])
    expect(requestedPoints({ points: ['fw'] })).toEqual(['fw'])
    expect(requestedPoints({ points: ['fw', 'gateway'] })).toEqual(['gateway', 'fw'])
    expect(requestedPoints({ points: [] })).toEqual(['gateway', 'fw'])
    expect(requestedPoints({ points: ['x'] as never })).toEqual(['gateway', 'fw'])
    expect(requestedPoints({ points: 'fw' as never })).toEqual(['gateway', 'fw'])
  })

  it('내부 방화벽만 요청한 행의 관문 칸은 미요청(중립색)이고 미확인 · 실패가 아니다', () => {
    expect(cells(block({ points: ['fw'], method: null, enforced_at: null }))).toEqual([['gateway', 'unrequested'], ['fw', 'confirmed']])
    expect(cells(block({ points: ['fw'], enforced_at: null, enforcement: null }))).toEqual([['gateway', 'unrequested']])
    expect([POINT_STATE_LABEL.unrequested, POINT_STATE_TONE.unrequested]).toEqual(['미요청', 'neutral'])
    expect(pointRows(block({ points: ['fw'], enforced_at: null }), now)[0].point).toEqual({ state: 'unrequested', since: null, mode: null, note: null })
  })

  it('관문을 뺀 행의 관문 칸은 관문이 뺐다고 확인될 때까지 빠짐 확인 전이다(결정 14 · 결과 기록이나 관문 enforced_at 이 남음)', () => {
    const since = '2026-09-18T08:00:30+00:00'
    // 집행기가 removing 으로 바꾼 뒤: 시각 · 방식을 싣는다. 결과는 실패 · 미확인이 아니다
    const narrowed = block({ points: ['fw'], enforcement: { gateway: { state: 'removing', since, mode: 'nft', note: null }, fw: point('confirmed') } })
    expect(pointRows(narrowed, now).map((r) => [r.key, r.point.state, r.point.since, r.point.mode])).toEqual([['gateway', 'removing', since, 'nft'], ['fw', 'confirmed', null, null]])
    // 관문 빼기 직후(집행기 회차 전): 옛 관문 결과 · 관문 세 열이 남아 있어도 빠짐 확인 전(시각은 싣지 않는다)
    expect(cells(block({ points: ['fw'], enforcement: { gateway: point('failed'), fw: point('pending') } }))).toEqual([['gateway', 'removing'], ['fw', 'pending']])
    expect(pointRows(block({ points: ['fw'] }), now)[0].point).toEqual({ state: 'removing', since: null, mode: null, note: null })
    // 관문이 뺐다고 확인되면 집행기가 결과 · 세 열을 비워 미요청이다
    expect(cells(block({ points: ['fw'], enforced_at: null, enforcement: { fw: point('confirmed') } }))).toEqual([['gateway', 'unrequested'], ['fw', 'confirmed']])
    // 해제 · 만료돼도 관문 기록이 남았으면 빠짐 확인 전이다
    expect(cells(block({ points: ['fw'], released_at: '2026-09-18T08:00:00+00:00', enforced_at: null, enforcement: { gateway: point('removing'), fw: point('removing') } }))).toEqual([['gateway', 'removing'], ['fw', 'removing']])
  })

  it('살아 있는 행의 요청 지점은 결과 기록 그대로이고, 기록이 없으면 줄이 없다(이전 서버 · 집행기). points 가 없으면 두 지점이다', () => {
    expect(cells(block())).toEqual([['fw', 'confirmed']])
    expect(cells(block({ enforcement: null }))).toEqual([])
    expect(cells(block({ enforcement: { gateway: point('confirmed'), fw: point('stale') } }))).toEqual([['gateway', 'confirmed'], ['fw', 'stale']])
    // 집행 제외 행은 집행기가 요청 지점마다 빠짐 확인 전을 둔다
    expect(cells(block({ enforce_note: '집행 제외 · 금지 대역', enforcement: { gateway: point('removing'), fw: point('removing') } }))).toEqual([['gateway', 'removing'], ['fw', 'removing']])
    // 빠짐 확인 전에 다시 건 목록 행(해제 → removing → 재차단): 집행기 다음 회차 전까지 남은 removing 은 요청 지점이라 대기다
    const rearmed = { enforced_at: null, method: null, enforce_note: null, enforcement: { gateway: point('removing'), fw: point('removing') } }
    // 관문 없이 다시 건 행: 관문은 요청했던 지점이라 뺐다고 확인될 때까지 빠짐 확인 전이다(결정 14)
    expect(pointRows(block({ ...rearmed, points: ['fw'] }), now).map((r) => [r.key, r.point.state, r.point.since])).toEqual([['gateway', 'removing', null], ['fw', 'pending', null]])
    expect(cells(block(rearmed))).toEqual([['gateway', 'pending'], ['fw', 'pending']])
    expect(blockState(block(rearmed), now)).toBe('pending')
    expect(pointRows(null, now)).toEqual([])
  })

  it('해제 · 만료 행은 요청 지점마다 빠짐 확인 전(결과 기록 · 관문 enforced_at 이 남음) · 빠짐이다', () => {
    const since = '2026-09-18T08:00:30+00:00'
    const rows = pointRows(block({ released_at: released, enforcement: { gateway: point('removing', since), fw: point('removing', since) } }), now)
    expect(rows.map((r) => [r.key, r.point.state, r.point.since])).toEqual([['gateway', 'removing', since], ['fw', 'removing', since]])
    expect(cells(block({ released_at: released, enforced_at: null, enforcement: { fw: point('removing') } }))).toEqual([['gateway', 'gone'], ['fw', 'removing']])
    // 관문은 enforced_at 이 남아 있으면 빠짐 확인 전이다. 집행기가 아직 removing 으로 바꾸지 않은 기록도 빠짐 확인 전(시각은 싣지 않는다)
    expect(pointRows(block({ released_at: released }), now).map((r) => [r.key, r.point.state, r.point.since])).toEqual([['gateway', 'removing', null], ['fw', 'removing', null]])
    expect(cells(block({ released_at: released, enforced_at: null, enforcement: null }))).toEqual([['gateway', 'gone'], ['fw', 'gone']])
    expect(cells(block({ points: ['fw'], expires_at: '2026-09-18T11:00:00+00:00', enforced_at: null, enforcement: { fw: point('removing') } }))).toEqual([['gateway', 'unrequested'], ['fw', 'removing']])
    expect(cells(block({ points: ['fw'], expires_at: '2026-09-18T11:00:00+00:00', enforced_at: null, enforcement: null }))).toEqual([['gateway', 'unrequested'], ['fw', 'gone']])
    expect([POINT_STATE_LABEL.removing, POINT_STATE_LABEL.gone]).toEqual(['빠짐 확인 전', '빠짐'])
  })
})

describe('pointCounts (#72 · #77)', () => {
  const now = Date.parse('2026-09-18T08:00:00+00:00')
  const raw = (state: string) => ({ state, since: null, mode: null, note: null }) as never

  it('집행 확인 · 대기 · 실패 · 불일치 행만 지점 결과로 적용 · 실패 · 미확인을 센다(서버 BLOCKS_SQL 과 같은 정의)', () => {
    const rows = [
      block({ enforcement: { gateway: raw('confirmed'), fw: raw('failed') } }),
      block({ enforced_at: null, enforcement: { gateway: raw('pending'), fw: raw('confirmed') } }),
      block({ enforce_note: '관문 불일치 · x', enforcement: { fw: raw('stale') } }),
      // 기록 없음 · 모르는 값 · 모양이 틀린 값은 미확인
      block({ enforcement: null }),
      block({ enforcement: { fw: raw('hacked') } }),
      block({ enforcement: [] as never }),
      // 해제 · 만료 · 만료 없음 · 집행 제외는 세지 않는다
      block({ released_at: '2026-09-18T07:30:00+00:00', enforcement: { fw: raw('confirmed') } }),
      block({ expires_at: '2026-09-18T07:59:00+00:00', enforcement: { fw: raw('failed') } }),
      block({ expires_at: null, enforcement: { fw: raw('failed') } }),
      block({ enforce_note: '집행 제외 · 금지 대역', enforcement: { fw: raw('confirmed') } }),
    ]
    expect(pointCounts(rows, now, 'fw')).toEqual({ applied: 1, failed: 1, unverified: 4, unrequested: 0, removing: 0 })
    expect(pointCounts(rows, now, 'gateway')).toEqual({ applied: 1, failed: 0, unverified: 5, unrequested: 0, removing: 0 })
    expect(pointCounts([], now, 'fw')).toEqual({ applied: 0, failed: 0, unverified: 0, unrequested: 0, removing: 0 })
  })

  it('그 지점을 요청한 행만 센다. 내부 방화벽만 요청한 행은 관문 미요청이고 관문 미확인 · 실패가 아니다(이슈 #77)', () => {
    const rows = [
      block({ points: ['fw'], method: null, enforced_at: null, enforcement: { fw: raw('confirmed') } }),
      // 남은 관문 결과(관문 빼기 뒤 관문이 뺐다고 확인하기 전)는 관문 수 · 미요청이 아니라 빠짐 확인 전이다(결정 14)
      block({ points: ['fw'], enforced_at: null, enforcement: { gateway: raw('failed'), fw: raw('failed') } }),
      block({ points: ['fw'], enforced_at: null, enforcement: null }),
      block({ enforcement: { gateway: raw('confirmed'), fw: raw('confirmed') } }),
      // 제외 · 해제는 미요청으로도 세지 않는다
      block({ points: ['fw'], expires_at: null }),
      block({ points: ['fw'], released_at: '2026-09-18T07:30:00+00:00' }),
    ]
    const gateway = pointCounts(rows, now, 'gateway')
    expect(gateway).toEqual({ applied: 1, failed: 0, unverified: 0, unrequested: 2, removing: 1 })
    expect(pointCounts(rows, now, 'fw')).toEqual({ applied: 2, failed: 1, unverified: 1, unrequested: 0, removing: 0 })
    // 지점별 합 = 살아 있는 요청 − 제외 − 그 지점 미요청 − 그 지점 빠짐 확인 전
    expect(gateway.applied + gateway.failed + gateway.unverified).toBe(4 - gateway.unrequested - gateway.removing)
  })
})

describe('BLOCK_STATE_TONE', () => {
  it('집행 확인은 정상 적용 결과라 초록이고 지점별 적용 확인과 같다', () => {
    expect(BLOCK_STATE_TONE.enforced).toBe('success')
    expect([BLOCK_STATE_TONE.pending, BLOCK_STATE_TONE.mismatch, BLOCK_STATE_TONE.failed]).toEqual(['warning', 'orange', 'danger'])
  })
})
