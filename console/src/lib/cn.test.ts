import { describe, expect, it } from 'vitest'
import { cn } from './cn'

describe('cn', () => {
  it('조건부 클래스를 모으고 거짓 값은 뺀다', () => {
    const off = false as boolean
    expect(cn('a', off && 'b', null, undefined, { c: true, d: false }, ['e'])).toBe('a c e')
  })

  it('겹치는 Tailwind 클래스는 뒤의 것이 이긴다', () => {
    expect(cn('px-3 py-2', 'px-8')).toBe('py-2 px-8')
    expect(cn('bg-primary', 'bg-danger')).toBe('bg-danger')
  })

  it('글자 크기와 글자 색은 서로 지우지 않는다', () => {
    expect(cn('text-sm text-ink', 'text-danger')).toBe('text-sm text-danger')
    expect(cn('text-ink-muted', 'text-2xs')).toBe('text-ink-muted text-2xs')
  })

  it('디자인 토큰 이름(모서리 · 그림자 · 자간)도 병합한다', () => {
    expect(cn('rounded-card', 'rounded-none')).toBe('rounded-none')
    expect(cn('rounded-control', 'rounded-full')).toBe('rounded-full')
    expect(cn('shadow-card', 'shadow-none')).toBe('shadow-none')
    expect(cn('shadow-control', 'shadow-field')).toBe('shadow-field')
    expect(cn('tracking-heading', 'tracking-display')).toBe('tracking-display')
  })

  it('심각도 · 판정 색 토큰은 기본 배지 색을 덮는다', () => {
    expect(cn('bg-muted-soft text-muted', 'bg-severity-critical-soft text-severity-critical')).toBe(
      'bg-severity-critical-soft text-severity-critical',
    )
  })
})
