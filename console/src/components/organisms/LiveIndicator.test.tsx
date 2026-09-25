import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { expectInertDom, HOSTILE } from '@/test/hostile-fixtures'
import { LiveIndicator } from './LiveIndicator'

/** 콘솔 표시 조각. 없으면 null */
function consoleTag(root: HTMLElement): HTMLElement | null {
  return root.querySelector('[data-console]')
}

describe('LiveIndicator', () => {
  it('연결 상태를 점과 글로 보이고, 콘솔 이름이 없으면(옛 서버 · hello 전) 콘솔 표시를 그리지 않는다', () => {
    const { container } = render(<LiveIndicator live={{ status: 'connected', retries: 0 }} />)
    const root = container.firstElementChild as HTMLElement
    expect(root).toHaveAttribute('data-live', 'connected')
    expect(root).toHaveAttribute('title', '실시간 수신 중')
    expect(root).toHaveTextContent('실시간 수신 중')
    expect(consoleTag(root)).toBeNull()
  })

  it('opsloop-console-a · b 는 콘솔 A · B 로 보인다', () => {
    const { container, rerender } = render(<LiveIndicator live={{ status: 'connected', retries: 0, console: 'opsloop-console-a' }} />)
    const root = () => container.firstElementChild as HTMLElement
    expect(consoleTag(root())).toHaveTextContent('콘솔 A')
    expect(consoleTag(root())).toHaveAttribute('data-console', '콘솔 A')
    expect(consoleTag(root())).not.toHaveAttribute('data-stale')
    expect(consoleTag(root())).not.toHaveClass('opacity-45')
    expect(root()).toHaveAttribute('title', '실시간 수신 중 · 콘솔 A')
    expect(root().textContent).not.toContain('opsloop-console-a')

    rerender(<LiveIndicator live={{ status: 'connected', retries: 0, console: 'opsloop-console-b' }} />)
    expect(consoleTag(root())).toHaveTextContent('콘솔 B')
    expect(root()).toHaveAttribute('title', '실시간 수신 중 · 콘솔 B')
  })

  it('끊기면 마지막 콘솔을 흐리게 남기고 낭독에는 마지막 연결이라 알린다', () => {
    const { container, rerender } = render(<LiveIndicator live={{ status: 'reconnecting', retries: 2, console: 'opsloop-console-a' }} />)
    const root = () => container.firstElementChild as HTMLElement
    expect(consoleTag(root())).toHaveAttribute('data-stale', 'true')
    expect(consoleTag(root())).toHaveClass('opacity-45')
    expect(consoleTag(root())).toHaveTextContent('마지막 연결 콘솔 A')
    expect(root()).toHaveAttribute('title', '실시간 끊김 · 다시 연결 중 · 마지막 연결 콘솔 A')

    rerender(<LiveIndicator live={{ status: 'closed', retries: 0, console: 'opsloop-console-a' }} />)
    expect(consoleTag(root())).toHaveAttribute('data-stale', 'true')
    expect(root()).toHaveAttribute('title', '실시간 끊김 · 다시 로그인 필요 · 마지막 연결 콘솔 A')
  })

  it('정해 두지 않은 이름(호스트 이름 등)은 원문을 비신뢰 문자열로 그린다', () => {
    const { container } = render(<LiveIndicator live={{ status: 'connected', retries: 0, console: '3f2a9c1b7d4e' }} />)
    const root = container.firstElementChild as HTMLElement
    expect(consoleTag(root)).toHaveAttribute('data-console', '')
    expect(consoleTag(root)?.querySelector('[data-untrusted]')).toHaveTextContent('3f2a9c1b7d4e')
    expect(root).toHaveAttribute('title', '실시간 수신 중 · 3f2a9c1b7d4e')
  })

  it('악성 이름도 글자로만 그리고 숨은 문자는 표식으로, 긴 값은 64자에서 자른다', () => {
    const name = `${HOSTILE.rlo} ${HOSTILE.img} ${HOSTILE.decoy}`
    const { container, rerender } = render(<LiveIndicator live={{ status: 'connected', retries: 0, console: name }} />)
    const root = () => container.firstElementChild as HTMLElement
    // 말풍선(title)은 겉 span 자체에 있다. expectInertDom 은 넘긴 요소의 자손만 보므로 container 를 넘겨 겉 span 의 속성까지 본다
    expectInertDom(container)
    expect(root().textContent).toContain('admin⟨U+202E⟩gnp.exe')
    expect(root().getAttribute('title')).toContain('⟨U+202E⟩')
    expect(root().getAttribute('title')).toContain('줄1↵2026')

    // 끊겨 흐리게 남을 때도 같다(낭독 '마지막 연결' · 말풍선)
    rerender(<LiveIndicator live={{ status: 'reconnecting', retries: 1, console: name }} />)
    expectInertDom(container)
    expect(root().getAttribute('title')).toContain('마지막 연결 admin⟨U+202E⟩gnp.exe')

    rerender(<LiveIndicator live={{ status: 'connected', retries: 0, console: 'x'.repeat(200) }} />)
    expect(root().textContent).toContain(`${'x'.repeat(64)}…`)
    expect(root().textContent).not.toContain('x'.repeat(65))
    expect(root().querySelector('button')).toBeNull()
  })
})
