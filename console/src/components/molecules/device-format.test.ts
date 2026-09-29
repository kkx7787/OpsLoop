import { describe, expect, it } from 'vitest'
import type { DeviceBasis, DeviceGroup, IncidentDevice } from '@/api/incidents'
import { DEVICE_BASIS_LABEL, deviceKey, deviceText, deviceView, hasConfirmedProtected, isDeviceId } from './device-format'

function device(id: string, extra: Partial<IncidentDevice> = {}): IncidentDevice {
  return { id, part: null, label: id, group: 'protected', logs: [], basis: 'confirmed', ...extra }
}

const WEB = device('web-01', { logs: ['웹 접근'] })
const DECOY = device('aws-sensor', { part: 'decoy', label: '웹 디코이', group: 'sensor', logs: ['웹 요청'] })
const COWRIE_GUESS = device('aws-sensor', { part: 'cowrie', label: 'Cowrie', group: 'sensor', logs: ['SSH 세션'], basis: 'fallback' })
const DATA_NODE = device('data-node', { label: '데이터 노드', group: 'monitor', logs: ['수집 관문', '원장 가져오기'], basis: 'rule_scope' })

const ids = (list: IncidentDevice[]) => list.map(deviceKey)

describe('deviceView', () => {
  it('devices 가 없으면 이전 서버 응답이라 legacy 이고 미확인이 아니다', () => {
    expect(deviceView({})).toEqual({ legacy: true, known: [], unknown: false, fallback: [] })
    expect(deviceView({ device_fallback: [COWRIE_GUESS] })).toMatchObject({ legacy: true, unknown: false })
  })

  it('빈 devices 는 장비 미확인이다', () => {
    expect(deviceView({ devices: [], device_state: 'unconfirmed', device_fallback: [] })).toEqual({ legacy: false, known: [], unknown: true, fallback: [] })
  })

  it('대체 추정은 known 에 들지 않고 fallback 으로 간다(서버가 devices 에 잘못 넣어도)', () => {
    const view = deviceView({ devices: [COWRIE_GUESS], device_fallback: [COWRIE_GUESS, device('web-01', { basis: 'fallback' })] })
    expect(view.known).toEqual([])
    expect(view.unknown).toBe(true)
    // 같은 장비(id + 나눔)는 한 번만
    expect(ids(view.fallback)).toEqual(['aws-sensor|cowrie', 'web-01|'])
  })

  it('모르는 근거 값은 known 에 들지 않는다(화이트리스트)', () => {
    const guess = device('web-01', { basis: 'guess' as DeviceBasis })
    const view = deviceView({ devices: [guess] })
    expect(view.known).toEqual([])
    expect(view.unknown).toBe(true)
  })

  it('보호 대상 먼저 → 확인 먼저 → 서버 순서', () => {
    const node = device('n-7', { label: 'web02.lab', basis: 'rule_scope' })
    const console_ = device('console', { label: '관제 콘솔', group: 'monitor', logs: ['감사 기록'] })
    const view = deviceView({ devices: [DATA_NODE, DECOY, node, console_, WEB] })
    expect(ids(view.known)).toEqual(['web-01|', 'n-7|', 'aws-sensor|decoy', 'console|', 'data-node|'])
    expect(view.unknown).toBe(false)
  })

  it('같은 장비(id + 나눔)가 두 번 오면 앞선 것(확인 먼저) 하나만 남긴다', () => {
    const view = deviceView({ devices: [device('web-01', { basis: 'rule_scope' }), WEB, DECOY, device('aws-sensor', { part: 'cowrie', group: 'sensor' })] })
    expect(ids(view.known)).toEqual(['web-01|', 'aws-sensor|decoy', 'aws-sensor|cowrie'])
    expect(view.known[0]).toBe(WEB)
  })

  it('모르는 무리는 보호 대상으로 올리지 않는다', () => {
    const odd = device('odd', { group: 'other' as DeviceGroup })
    const view = deviceView({ devices: [odd, device('web-01', { basis: 'rule_scope' })] })
    expect(ids(view.known)).toEqual(['web-01|', 'odd|'])
  })

  it('규칙 범위와 대체 추정이 함께 오면(세션을 못 고른 R002) 규칙 범위만 known', () => {
    const aws = device('aws-sensor', { label: 'AWS 센서', group: 'sensor', logs: ['세션 기록'], basis: 'rule_scope' })
    const view = deviceView({ devices: [aws], device_state: 'rule_scope', device_fallback: [COWRIE_GUESS] })
    expect(view.known).toEqual([aws])
    expect(view.unknown).toBe(false)
    expect(view.fallback).toEqual([COWRIE_GUESS])
  })
})

describe('deviceText', () => {
  it('장비 이름 뒤에 로그 종류를 잇는다', () => {
    expect(deviceText(WEB)).toBe('web-01 · 웹 접근')
    expect(deviceText(DATA_NODE)).toBe('데이터 노드 · 수집 관문 · 원장 가져오기')
    expect(deviceText(device('web-01'))).toBe('web-01')
  })
})

describe('hasConfirmedProtected', () => {
  it('보호 대상이 확인된 것만 참이다', () => {
    expect(hasConfirmedProtected([DECOY, WEB])).toBe(true)
    expect(hasConfirmedProtected([device('web-01', { basis: 'rule_scope' })])).toBe(false)
    expect(hasConfirmedProtected([device('web-01', { basis: 'fallback' })])).toBe(false)
    expect(hasConfirmedProtected([DECOY])).toBe(false)
    expect(hasConfirmedProtected([])).toBe(false)
    expect(hasConfirmedProtected(undefined)).toBe(false)
  })
})

describe('isDeviceId', () => {
  it('장비 id 형식과 장비 미확인 예약값만 받는다', () => {
    const ok = ['web-01', 'aws-sensor', 'a', '0', `a${'b'.repeat(62)}`, '_unconfirmed']
    const bad = ['', 'Web-01', '-a', '_x', '../x', 'a/b', ' web-01', 'web-01\n', 'a\u0000', `a${'b'.repeat(63)}`, '_unconfirmed2']
    expect(ok.filter((v) => !isDeviceId(v))).toEqual([])
    expect(bad.filter((v) => isDeviceId(v))).toEqual([])
    expect(isDeviceId(undefined)).toBe(false)
    expect(isDeviceId(1)).toBe(false)
  })
})

describe('DEVICE_BASIS_LABEL', () => {
  it('근거 글자는 확인 · 규칙 범위 둘뿐이다', () => {
    expect(DEVICE_BASIS_LABEL).toEqual({ confirmed: '확인', rule_scope: '규칙 범위' })
  })
})
