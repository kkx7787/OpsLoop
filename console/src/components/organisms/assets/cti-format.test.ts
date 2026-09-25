import { describe, expect, it } from 'vitest'
import { freshness } from '@/test/cti-fixtures'
import { cvssTone, formatCvss, formatPercentile, formatProbability, ransomwareLabel, staleSources, truncate, ubuntuPriorityLabel, ubuntuPriorityTone } from './cti-format'

describe('formatCvss · cvssTone', () => {
  it('점수는 소수 한 자리, 등급은 NVD 대문자 그대로 붙인다', () => {
    expect(formatCvss(9.8, 'CRITICAL')).toBe('9.8 CRITICAL')
    expect(formatCvss(7, 'high')).toBe('7.0 HIGH')
    expect(formatCvss('5.3', null)).toBe('5.3')
    expect(formatCvss(null, 'HIGH')).toBe('—')
    expect(formatCvss('x')).toBe('—')
  })

  it('등급 색은 심각도 색 체계를 따르고 모르는 등급은 중립', () => {
    expect(cvssTone('CRITICAL')).toBe('danger')
    expect(cvssTone('HIGH')).toBe('orange')
    expect(cvssTone('medium')).toBe('warning')
    expect(cvssTone('LOW')).toBe('neutral')
    expect(cvssTone(null)).toBe('neutral')
  })
})

describe('formatProbability · formatPercentile', () => {
  it('EPSS 를 백분율로 보이고 작은 값도 0 으로 뭉개지 않는다', () => {
    expect(formatProbability(0.99506)).toBe('99.5%')
    expect(formatProbability(0.0431)).toBe('4.3%')
    expect(formatProbability(0.00043)).toBe('0.04%')
    expect(formatProbability(0.0000004)).toBe('<0.01%')
    expect(formatProbability(0)).toBe('0%')
    expect(formatProbability(null)).toBe('—')
  })

  it('백분위는 한 자리 소수', () => {
    expect(formatPercentile(0.99944)).toBe('백분위 99.9')
    expect(formatPercentile(undefined)).toBe('—')
  })
})

describe('ransomwareLabel · Ubuntu 등급', () => {
  it('KEV 랜섬웨어 표기를 한국어로', () => {
    expect(ransomwareLabel('Known')).toBe('사용 확인')
    expect(ransomwareLabel('Unknown')).toBe('알려지지 않음')
    expect(ransomwareLabel(null)).toBe('—')
    expect(ransomwareLabel('Other')).toBe('Other')
  })

  it('Ubuntu 등급 원문(소문자)을 그대로 보이지 않는다', () => {
    expect(ubuntuPriorityLabel('critical')).toBe('긴급')
    expect(ubuntuPriorityLabel('negligible')).toBe('무시 가능')
    expect(ubuntuPriorityLabel(null)).toBe('—')
    expect(ubuntuPriorityTone('high')).toBe('orange')
    expect(ubuntuPriorityTone('low')).toBe('neutral')
  })
})

describe('staleSources', () => {
  it('오래된 출처를 KEV · EPSS · 배포판 대조 순으로 모은다(NVD 는 넣지 않는다)', () => {
    expect(staleSources(undefined)).toEqual([])
    expect(staleSources(freshness())).toEqual([])
    const f = freshness()
    expect(staleSources({ ...f, osv: { ...f.osv, stale: true }, kev: { ...f.kev, stale: true }, nvd: { ...f.nvd, stale: true } })).toEqual(['KEV', '배포판 대조'])
  })
})

describe('truncate', () => {
  it('긴 글은 줄임표로 자르고 빈 값은 —', () => {
    expect(truncate('가'.repeat(200), 10)).toBe(`${'가'.repeat(9)}…`)
    expect(truncate('짧다')).toBe('짧다')
    expect(truncate(null)).toBe('—')
  })
})
