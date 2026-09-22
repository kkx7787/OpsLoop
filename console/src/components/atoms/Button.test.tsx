import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Button } from './Button'
import { buttonClasses } from './button-styles'

describe('Button', () => {
  it('기본은 type="button" · secondary · md', () => {
    render(<Button>조건 초기화</Button>)
    const button = screen.getByRole('button', { name: '조건 초기화' })
    expect(button).toHaveAttribute('type', 'button')
    expect(button).toHaveClass('bg-surface', 'shadow-control', 'h-8', 'text-sm')
  })

  it.each([
    ['primary', 'bg-primary'],
    ['secondary', 'bg-surface'],
    ['ghost', 'bg-transparent'],
    ['danger', 'bg-danger'],
  ] as const)('변형 %s', (variant, cls) => {
    render(<Button variant={variant}>단추</Button>)
    expect(screen.getByRole('button')).toHaveClass(cls)
  })

  it('크기와 className 을 합치고, 겹치면 className 이 이긴다', () => {
    render(
      <Button size="lg" className="px-8 w-full">
        다시 연결
      </Button>,
    )
    const button = screen.getByRole('button')
    expect(button).toHaveClass('h-10', 'rounded-panel', 'px-8', 'w-full')
    expect(button).not.toHaveClass('px-5')
  })

  it('누르면 onClick', () => {
    const onClick = vi.fn<() => void>()
    render(<Button onClick={onClick}>판정 기록</Button>)
    fireEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('이유 없는 disabled 는 네이티브로 끈다', () => {
    render(<Button disabled>저장</Button>)
    expect(screen.getByRole('button')).toBeDisabled()
  })

  it('비활성 사유가 있으면 초점은 남기고 이유를 title · 설명으로 알리며 누름을 막는다', () => {
    const onClick = vi.fn<() => void>()
    const reason = '이 동작(차단 해제)은 admin 만 할 수 있습니다 · 현재 역할 operator'
    render(
      <Button variant="danger" disabled disabledReason={reason} onClick={onClick}>
        차단 해제
      </Button>,
    )
    const button = screen.getByRole('button', { name: '차단 해제' })
    expect(button).not.toBeDisabled()
    expect(button).toHaveAttribute('aria-disabled', 'true')
    expect(button).toHaveAttribute('title', reason)
    expect(button).toHaveAccessibleDescription(reason)
    expect(button).toHaveClass('opacity-50', 'cursor-not-allowed')
    expect(button).not.toHaveClass('hover:bg-danger-strong')

    button.focus()
    expect(button).toHaveFocus()
    fireEvent.click(button)
    expect(onClick).not.toHaveBeenCalled()
  })

  it('비활성 사유가 있는 제출 단추는 양식을 제출하지 않는다', () => {
    const onSubmit = vi.fn<(e: { preventDefault: () => void }) => void>((e) => e.preventDefault())
    render(
      <form onSubmit={onSubmit}>
        <Button type="submit" disabled disabledReason="판정 근거를 적어 주세요">
          판정 기록
        </Button>
      </form>,
    )
    fireEvent.click(screen.getByRole('button'))
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('처리 중에는 돌림표를 보이고 누름을 막는다', () => {
    const onClick = vi.fn<() => void>()
    render(
      <Button variant="primary" loading onClick={onClick}>
        저장
      </Button>,
    )
    const button = screen.getByRole('button', { name: '저장' })
    expect(button).toHaveAttribute('aria-busy', 'true')
    expect(button).toHaveAttribute('aria-disabled', 'true')
    expect(button.querySelector('svg.animate-spin')).not.toBeNull()
    fireEvent.click(button)
    expect(onClick).not.toHaveBeenCalled()
  })
})

describe('buttonClasses', () => {
  it('링크를 단추 모양으로 만든다', () => {
    expect(buttonClasses({ variant: 'primary', size: 'sm' })).toContain('bg-primary')
    expect(buttonClasses({ variant: 'primary', size: 'sm' })).toContain('h-[30px]')
    expect(buttonClasses({ inactive: true })).toContain('opacity-50')
  })
})
