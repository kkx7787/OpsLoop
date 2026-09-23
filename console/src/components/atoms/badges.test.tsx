import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { Badge } from './Badge'
import { SeverityBadge } from './SeverityBadge'
import { Time } from './Time'
import { VerdictBadge } from './VerdictBadge'

describe('Badge', () => {
  it('색조에 맞는 바탕 · 글자 색', () => {
    render(<Badge tone="info">규칙 v2 기준</Badge>)
    expect(screen.getByText('규칙 v2 기준')).toHaveClass('bg-primary-soft', 'text-primary', 'rounded-sm')
  })
})

describe('SeverityBadge', () => {
  it.each(['critical', 'high', 'medium', 'low'] as const)('%s 는 심각도 토큰 색을 쓴다', (severity) => {
    render(<SeverityBadge severity={severity} />)
    const badge = screen.getByText(severity)
    expect(badge).toHaveClass(`bg-severity-${severity}-soft`, `text-severity-${severity}`)
    expect(badge).not.toHaveClass('bg-muted-soft')
  })

  it('모르는 값은 회색으로 그대로 보인다', () => {
    render(<SeverityBadge severity="info" />)
    expect(screen.getByText('info')).toHaveClass('bg-muted-soft', 'text-muted')
  })
})

describe('VerdictBadge', () => {
  it.each([
    ['threat', '실제 위협'],
    ['non_actionable', '무시 가능'],
    ['false_positive', '오탐'],
    ['benign_positive', '양성 정탐'],
    ['undetermined', '미결'],
  ] as const)('%s → %s', (verdict, label) => {
    render(<VerdictBadge verdict={verdict} />)
    const badge = screen.getByText(label)
    expect(badge).toHaveClass(`text-verdict-${verdict.replace('_', '-')}`)
    expect(badge).toHaveAttribute('data-verdict', verdict)
  })
})

describe('Time', () => {
  it('KST 로 보이고 dateTime 에 UTC ISO 를 둔다', () => {
    render(<Time value="2026-09-18T06:20:04Z" zone />)
    const time = screen.getByText('2026-09-18 15:20:04 KST')
    expect(time.tagName).toBe('TIME')
    expect(time).toHaveAttribute('datetime', '2026-09-18T06:20:04.000Z')
  })

  it('relative 는 마우스 오버로 전체 시각을 보인다', () => {
    const now = Date.parse('2026-09-18T06:20:04Z')
    render(<Time value={now - 180_000} format="relative" now={now} />)
    expect(screen.getByText('3분 전')).toHaveAttribute('title', '2026-09-18 15:17:04 KST')
  })

  it('값이 없으면 대시', () => {
    render(<Time value={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })
})
