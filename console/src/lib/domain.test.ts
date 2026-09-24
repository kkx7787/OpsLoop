import { describe, expect, it } from 'vitest'
import {
  ACK_TARGET_SECONDS,
  ACTION_LABEL,
  ACTION_STATUS,
  actionLabel,
  elapsedTone,
  INCIDENT_ACTIONS,
  isCircularRule,
  sensorOf,
  VERDICT_DESCRIPTION,
  VERDICT_TARGET_SECONDS,
  VERDICTS,
  verdictTargetSeconds,
} from './domain'

describe('sensorOf', () => {
  it('규칙 번호대로 발생원을 가른다', () => {
    expect(sensorOf('R001')).toBe('허니팟')
    expect(sensorOf('R005')).toBe('허니팟')
    expect(sensorOf('R101')).toBe('웹 노드')
    expect(sensorOf('R201')).toBe('콘솔 · 감사')
    expect(sensorOf('R301')).toBe('인프라')
  })

  it('모르는 번호대 · 모양이 다른 값 · 빈 값은 기타', () => {
    expect(sensorOf('R901')).toBe('기타')
    expect(sensorOf('R1001')).toBe('기타')
    expect(sensorOf('X001')).toBe('기타')
    expect(sensorOf('')).toBe('기타')
    expect(sensorOf(null)).toBe('기타')
    expect(sensorOf(undefined)).toBe('기타')
  })
})

describe('판정 목표', () => {
  it('화면 설계 3장 표: critical 1시간 · high 4시간 · medium 12시간 · low 24시간', () => {
    expect(VERDICT_TARGET_SECONDS).toEqual({ critical: 3_600, high: 14_400, medium: 43_200, low: 86_400 })
    expect(ACK_TARGET_SECONDS).toEqual({ critical: 900, high: 3_600, medium: 14_400, low: null })
  })

  it('콘솔 발생 건(R2xx)은 심각도와 관계없이 critical 목표, 모르는 심각도는 low', () => {
    expect(verdictTargetSeconds('low', 'R201')).toBe(3_600)
    expect(verdictTargetSeconds('low', 'R001')).toBe(86_400)
    expect(verdictTargetSeconds('unknown')).toBe(86_400)
  })
})

describe('elapsedTone', () => {
  it('목표의 2/3 전은 ok, 2/3 부터 warn, 목표부터 over', () => {
    // high: 4시간 = 14400초. 2/3 는 9600초
    expect(elapsedTone('high', 0)).toBe('ok')
    expect(elapsedTone('high', 9_599)).toBe('ok')
    expect(elapsedTone('high', 9_600)).toBe('warn')
    expect(elapsedTone('high', 14_399)).toBe('warn')
    expect(elapsedTone('high', 14_400)).toBe('over')
    expect(elapsedTone('critical', 3_601)).toBe('over')
    expect(elapsedTone('low', 50_000)).toBe('ok')
  })

  it('콘솔 발생 건은 critical 목표로 본다', () => {
    expect(elapsedTone('low', 3_000, 'R201')).toBe('warn')
    expect(elapsedTone('low', 3_000, 'R001')).toBe('ok')
  })

  it('음수 · NaN 은 ok', () => {
    expect(elapsedTone('critical', -5)).toBe('ok')
    expect(elapsedTone('critical', Number.NaN)).toBe('ok')
  })
})

describe('조치 표기', () => {
  it('네 조치의 표기와 상태 전이', () => {
    expect(INCIDENT_ACTIONS).toEqual(['acknowledge', 'block_ip', 'unblock_ip', 'suppress_rule'])
    expect(ACTION_LABEL).toEqual({ acknowledge: '확인', block_ip: '차단', unblock_ip: '차단 해제', suppress_rule: '규칙 억제' })
    expect(ACTION_STATUS).toEqual({ acknowledge: 'acknowledged', block_ip: 'in_progress', suppress_rule: 'suppressed' })
    expect(ACTION_STATUS.unblock_ip).toBeUndefined()
  })

  it('actionLabel 은 모르는 조치를 값 그대로 보인다', () => {
    expect(actionLabel('block_ip')).toBe('차단')
    expect(actionLabel('escalate')).toBe('escalate')
  })
})

describe('VERDICT_DESCRIPTION', () => {
  it('판정값 다섯 개 모두 한 줄 설명이 있다', () => {
    for (const v of VERDICTS) {
      expect(VERDICT_DESCRIPTION[v]).toBeTruthy()
      expect(VERDICT_DESCRIPTION[v]).not.toContain('\n')
    }
    expect(VERDICT_DESCRIPTION.benign_positive).toContain('오탐으로 세지 않는다')
    expect(VERDICT_DESCRIPTION.undetermined).toContain('지표에서는 뺀다')
  })
})

describe('isCircularRule', () => {
  it('규칙 조건과 판정 근거가 겹치는 규칙(판정 기준 §6)만 순환이다. R006(키 심기) 포함', () => {
    for (const rule of ['R002', 'R003', 'R004', 'R006']) expect(isCircularRule(rule)).toBe(true)
    for (const rule of ['R001', 'R005', 'R101', 'R201', '', null, undefined]) expect(isCircularRule(rule)).toBe(false)
  })
})
