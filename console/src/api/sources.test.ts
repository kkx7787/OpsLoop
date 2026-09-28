import { describe, expect, it } from 'vitest'
import { isAddressPrefix, isIpAddress, sourceKeys } from './sources'

describe('isIpAddress', () => {
  it('서버(ipaddress)가 받는 주소 하나만 참이다', () => {
    const good = ['203.0.113.5', '0.0.0.0', '255.255.255.255', '2001:db8::1', '::', '::1', '1::', 'fe80::1', '::ffff:198.51.100.7',
      '2001:0db8:0000:0000:0000:ff00:0042:8329', '1:2:3:4:5:6:7::', '1:2:3:4:5:6:1.2.3.4', 'ABCD:EF01::']
    expect(good.filter((value) => !isIpAddress(value))).toEqual([])
  })

  it('대역 · 영역 표기 · 앞자리 0 · 모자라거나 넘치는 묶음 · 다른 글자는 거짓이다', () => {
    const bad = ['', 'abc', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1.2.3.04', '203.0.113.0/24', 'fe80::1%eth0',
      '1:::2', '1::2::3', ':1', '1:', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8::', '12345::', 'g::1',
      '1.2.3.4::', '::1.2.3', ' 1.2.3.4', "1.2.3.4'--", '1:2:3:4:5:6:7:1.2.3.4']
    expect(bad.filter((value) => isIpAddress(value))).toEqual([])
  })
})

describe('isAddressPrefix', () => {
  it('16진 숫자 · 콜론 · 점 1~45자', () => {
    expect(isAddressPrefix('203.0.113.')).toBe(true)
    expect(isAddressPrefix('2001:DB8:')).toBe(true)
    expect(isAddressPrefix('a'.repeat(45))).toBe(true)
    expect(isAddressPrefix('a'.repeat(46))).toBe(false)
    expect(isAddressPrefix('')).toBe(false)
    expect(isAddressPrefix('10.0.0.0/8')).toBe(false)
    expect(isAddressPrefix('g')).toBe(false)
  })
})

describe('sourceKeys', () => {
  it('목록 · 상세 · 지문이 모두 sources 아래에 있다(한 번에 무효화)', () => {
    const query = { limit: 25, offset: 0 }
    expect(sourceKeys.list(query).slice(0, 2)).toEqual(['sources', 'list'])
    expect(sourceKeys.detail('::1')).toEqual(['sources', 'detail', '::1'])
    expect(sourceKeys.fingerprints({ kind: 'hassh', ...query })[0]).toBe('sources')
  })
})
