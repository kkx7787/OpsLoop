import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { permission } from '@/auth/roles'
import { Button } from '../atoms/Button'
import { Gated } from './Gated'

describe('Gated', () => {
  it('허용이면 아무것도 덧씌우지 않는다', () => {
    const onClick = vi.fn<() => void>()
    const { container } = render(
      <Gated {...permission('operator', 'incident.verdict')}>
        <Button onClick={onClick}>판정 기록</Button>
      </Gated>,
    )
    expect(container.querySelector('[data-gated]')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '판정 기록' }))
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('권한 밖이면 숨기지 않고 흐리게 보이며 누를 수 없다', () => {
    const onClick = vi.fn<() => void>()
    const gate = permission('operator', 'block.release')
    const { container } = render(
      <Gated {...gate}>
        <Button onClick={onClick}>차단 해제</Button>
      </Gated>,
    )

    const wrapper = container.querySelector('[data-gated="denied"]')
    expect(wrapper).not.toBeNull()
    expect(wrapper).toHaveAttribute('title', gate.reason)

    // 단추는 화면에 남아 있다(숨기지 않는다). inert 라 접근성 트리에서는 빠진다.
    const button = container.querySelector('button')
    expect(button).toHaveTextContent('차단 해제')
    const inner = button?.closest('[inert]')
    expect(inner).not.toBeNull()
    expect(inner).toHaveClass('opacity-45')

    fireEvent.click(button!)
    expect(onClick).not.toHaveBeenCalled()

    // 이유는 화면 낭독기로 읽힌다
    expect(screen.getByText(gate.reason)).toHaveClass('sr-only')
    expect(gate.reason).toBe('이 동작(차단 해제)은 admin 만 할 수 있습니다 · 현재 역할 operator')
  })

  it('showReason 이면 이유를 글로도 보인다', () => {
    render(
      <Gated allowed={false} reason="이 동작(계정 관리)은 admin 만 할 수 있습니다" showReason>
        <Button>계정</Button>
      </Gated>,
    )
    const reason = screen.getByText('이 동작(계정 관리)은 admin 만 할 수 있습니다')
    expect(reason).not.toHaveClass('sr-only')
    expect(reason).toHaveClass('text-xs')
  })
})
