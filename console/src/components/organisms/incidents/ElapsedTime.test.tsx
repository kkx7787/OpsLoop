import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ElapsedTime } from './ElapsedTime'

describe('ElapsedTime', () => {
  it('목표를 넘긴 건은 빨강 · 낭독기에는 글로 알린다', () => {
    render(<ElapsedTime seconds={22_320} severity="critical" since="2026-09-18T06:00:00+00:00" />)
    const el = screen.getByText('6h 12m')
    expect(el).toHaveAttribute('data-tone', 'over')
    expect(el).toHaveClass('text-danger')
    expect(el).toHaveTextContent('(목표 초과)')
    expect(el).toHaveAttribute('title', '발생 2026-09-18 15:00:00 KST · 경과 6시간 12분 · 판정 목표 1시간')
  })

  it('목표의 2/3 를 지나면 주황, 그 전은 색이 없다', () => {
    const { rerender } = render(<ElapsedTime seconds={3 * 3600} severity="high" />)
    expect(screen.getByText('3h 00m')).toHaveAttribute('data-tone', 'warn')
    expect(screen.getByText('3h 00m')).toHaveTextContent('(목표 임박)')
    rerender(<ElapsedTime seconds={600} severity="high" />)
    expect(screen.getByText('10m')).toHaveAttribute('data-tone', 'ok')
    expect(screen.getByText('10m')).not.toHaveTextContent('목표')
  })

  it('콘솔 발생 건(R2xx)은 심각도가 낮아도 critical 목표를 따른다', () => {
    render(<ElapsedTime seconds={3_000} severity="low" ruleId="R201" />)
    expect(screen.getByText('50m')).toHaveAttribute('data-tone', 'warn')
  })

  it('판정된 건은 회색이고 목표를 말하지 않는다. long 은 한글 표기', () => {
    render(<ElapsedTime seconds={90_000} severity="critical" pending={false} format="long" />)
    const el = screen.getByText('1일 1시간')
    expect(el).not.toHaveAttribute('data-tone')
    expect(el).toHaveClass('text-ink-muted')
    expect(el).toHaveAttribute('title', '경과 1일 1시간')
  })
})
