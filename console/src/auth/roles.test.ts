import { describe, expect, it } from 'vitest'
import { ACTION_LABEL, can, permission, PERMISSIONS, type Action } from './roles'

const ALL = Object.keys(ACTION_LABEL) as Action[]
const OPERATE: Action[] = ['incident.verdict', 'block.request']

describe('권한표(화면 설계 15장)', () => {
  it('viewer 는 아무 동작도 못 한다', () => {
    for (const action of ALL) expect(can('viewer', action)).toBe(false)
  })

  it('operator 는 판정 · 차단 요청만 한다', () => {
    for (const action of ALL) expect(can('operator', action)).toBe(OPERATE.includes(action))
  })

  it('admin 은 모두 한다', () => {
    for (const action of ALL) expect(can('admin', action)).toBe(true)
  })

  it('되돌리는 행위와 기준을 바꾸는 행위는 admin 만', () => {
    for (const action of ['block.release', 'block.extend', 'rule.suppress', 'rule.approve'] as const) {
      expect(PERMISSIONS[action]).toEqual(['admin'])
    }
  })

  it('로그인 전 · 모르는 역할은 막는다', () => {
    expect(can(undefined, 'incident.verdict')).toBe(false)
    expect(can('root', 'incident.verdict')).toBe(false)
  })
})

describe('permission', () => {
  it('허용이면 이유가 비어 있다', () => {
    expect(permission('admin', 'audit.read')).toEqual({ allowed: true, reason: '' })
  })

  it('막히면 누가 할 수 있는지와 현재 역할을 알린다', () => {
    expect(permission('viewer', 'incident.verdict')).toEqual({
      allowed: false,
      reason: '이 동작(판정)은 operator · admin 만 할 수 있습니다 · 현재 역할 viewer',
    })
  })

  it('역할을 모르는 동안은 확인 중으로 막는다', () => {
    expect(permission(undefined, 'block.request')).toEqual({ allowed: false, reason: '권한을 확인하는 중입니다 (차단 요청)' })
  })
})
