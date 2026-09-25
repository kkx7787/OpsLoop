import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { hasHidden } from '@/lib/untrusted'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, LONG_MORE, MIXED } from '@/test/hostile-fixtures'
import { EXPAND_MAX, UntrustedText } from './UntrustedText'

describe('UntrustedText', () => {
  it('숨은 문자는 경고색 표식 배지로, 원문 문자는 DOM 에 남기지 않는다', () => {
    const { container } = render(<UntrustedText value={HOSTILE.rlo} />)
    const mark = screen.getByText('⟨U+202E⟩')
    expect(mark).toHaveClass('bg-warning-soft', 'text-warning')
    expect(mark).toHaveAttribute('data-hidden-char', 'U+202E')
    expect(container.textContent).toBe('admin⟨U+202E⟩gnp.exe')
    expect(hasHidden(container.textContent ?? '')).toBe(false)
  })

  it('결과 전체를 방향 격리한다(<bdi dir="ltr">)', () => {
    const { container } = render(<p>앞 <UntrustedText value={HOSTILE.rlo} /> 뒤</p>)
    const bdi = container.querySelector('bdi')
    expect(bdi).not.toBeNull()
    expect(bdi).toHaveAttribute('dir', 'ltr')
    expect(bdi?.textContent).toBe('admin⟨U+202E⟩gnp.exe')
  })

  it('줄바꿈은 ↵ 배지로 보여 한 값이 가짜 줄을 만들지 못한다 · 탭은 공백', () => {
    const { container } = render(<UntrustedText value={`${HOSTILE.decoy}\tx${HOSTILE.crlf}`} />)
    expect(container.textContent).toBe('줄1↵2026-09-18 15:00:00 decoy login.success x⟨U+000D⟩↵')
    expect(container.textContent).not.toContain('\n')
    expect(screen.getAllByText('↵')).toHaveLength(2)
  })

  it('악성 표본 전체를 글자로만 그린다', () => {
    const { container } = render(<UntrustedText value={MIXED} />)
    expectInertDom(container)
    expectMixedRevealed(container)
    expect(screen.getByText('⟨U+FEFF⟩')).toBeInTheDocument()
    expect(screen.getByText('⟨U+001B⟩')).toBeInTheDocument()
    expect(screen.getByText('⟨U+009B⟩')).toBeInTheDocument()
  })

  it('2만 자는 앞 500자만 보이고 펼치기 · 접기로 오간다', () => {
    const { container } = render(<UntrustedText value={LONG} />)
    expect(container.textContent).toBe(`${'L'.repeat(500)}${LONG_MORE}`)
    const more = screen.getByRole('button', { name: LONG_MORE })
    expect(more).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(more)
    expect(container.textContent).toBe(`${LONG}접기`)
    fireEvent.click(screen.getByRole('button', { name: '접기' }))
    expect(screen.getByRole('button', { name: LONG_MORE })).toBeInTheDocument()
  })

  it('같은 자리에 다른 값이 오면 펼침이 풀려 다시 접힌다', () => {
    const { container, rerender } = render(<UntrustedText value={LONG} />)
    fireEvent.click(screen.getByRole('button', { name: LONG_MORE }))
    expect(container.textContent).toBe(`${LONG}접기`)
    const next = `${'M'.repeat(19_995)}TAIL!`
    rerender(<UntrustedText value={next} />)
    expect(container.textContent).toBe(`${'M'.repeat(500)}${LONG_MORE}`)
    expect(screen.getByRole('button', { name: LONG_MORE })).toHaveAttribute('aria-expanded', 'false')
  })

  it('펼쳐도 2만 자까지만 그리고 나머지는 단추 없이 개수만 적는다', () => {
    const huge = `${'H'.repeat(EXPAND_MAX)}${'X'.repeat(30_000)}`
    const { container } = render(<UntrustedText value={huge} />)
    fireEvent.click(screen.getByRole('button', { name: '… 49,500자 더 · 펼치기' }))
    expect(container.textContent).toBe(`${'H'.repeat(EXPAND_MAX)}… 30,000자 더는 화면에 그리지 않음접기`)
    expect(container.textContent).not.toContain('X')
    expect(screen.getAllByRole('button')).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '접기' }))
    expect(container.textContent).toBe(`${'H'.repeat(500)}… 49,500자 더 · 펼치기`)
  })

  it('글자 수는 표식으로 바꾸기 전 원문(코드 포인트) 기준이다', () => {
    render(<UntrustedText value={'\u{202E}'.repeat(12)} max={10} />)
    expect(screen.getAllByText('⟨U+202E⟩')).toHaveLength(10)
    expect(screen.getByRole('button', { name: '… 2자 더 · 펼치기' })).toBeInTheDocument()
    render(<UntrustedText value={'\u{E0041}'.repeat(3)} max={3} />)
    expect(screen.getAllByText('⟨U+E0041⟩')).toHaveLength(3)
  })

  it('한 줄 말줄임 자리(clip)는 단추 없이 잘라 … 만 붙인다', () => {
    const { container } = render(<UntrustedText value={LONG} max={40} clip />)
    expect(container.textContent).toBe(`${'L'.repeat(40)}…`)
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('값이 없으면 fallback 을 보인다', () => {
    const { container, rerender } = render(<UntrustedText value={null} fallback="—" />)
    expect(container.textContent).toBe('—')
    rerender(<UntrustedText value="" fallback="미기록" />)
    expect(container.textContent).toBe('미기록')
    rerender(<UntrustedText value={undefined} />)
    expect(container.textContent).toBe('')
  })
})
