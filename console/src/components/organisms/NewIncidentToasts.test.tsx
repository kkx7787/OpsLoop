import { act, fireEvent, render, screen, within } from '@testing-library/react'
import { useState } from 'react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TOAST_MS, type NewIncidentToast } from '@/api/new-incidents'
import { expectInertDom, expectMixedRevealed, HOSTILE, MIXED } from '@/test/hostile-fixtures'
import { DECOY, device } from '@/test/targets-fixtures'
import { NewIncidentToasts } from './NewIncidentToasts'

function toast(extra: Partial<NewIncidentToast> = {}): NewIncidentToast {
  return {
    id: 'R101|w2|198.51.100.7|2026-09-30T00:00:00+00:00',
    group: 'R101|198.51.100.7',
    openedAt: 0,
    version: 0,
    keys: ['R101|w2|198.51.100.7|2026-09-30T00:00:00+00:00'],
    rule_id: 'R101',
    rule_name: 'SSH 무차별 대입',
    severity: 'high',
    actor_ip: '198.51.100.7',
    target: null,
    devices: [device(), DECOY],
    ...extra,
  }
}

function renderToasts(toasts: NewIncidentToast[], onDismiss = vi.fn<(id: string) => void>()) {
  const result = render(
    <MemoryRouter>
      <NewIncidentToasts toasts={toasts} onDismiss={onDismiss} />
    </MemoryRouter>,
  )
  const rerender = (next: NewIncidentToast[]) =>
    result.rerender(
      <MemoryRouter>
        <NewIncidentToasts toasts={next} onDismiss={onDismiss} />
      </MemoryRouter>,
    )
  return { ...result, rerender, onDismiss }
}

/** 닫으면 목록에서 빼는 부모(AppLayout 의 useNewIncidentToasts 와 같다). 마지막 장을 닫을 때 초점이 갈 본문(#main)도 둔다 */
function Stack({ initial }: { initial: NewIncidentToast[] }) {
  const [toasts, setToasts] = useState(initial)
  return (
    <MemoryRouter>
      <main id="main" tabIndex={-1} />
      <NewIncidentToasts toasts={toasts} onDismiss={(id) => setToasts((all) => all.filter((t) => t.id !== id))} />
    </MemoryRouter>
  )
}

const closeButtons = () => screen.queryAllByRole('button', { name: '알림 닫기' })

function setVisibility(state: 'visible' | 'hidden') {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  document.dispatchEvent(new Event('visibilitychange'))
}

describe('NewIncidentToasts', () => {
  afterEach(() => {
    vi.useRealTimers()
    Reflect.deleteProperty(document, 'visibilityState')
  })

  it('비면 카드 · 이름 · 포인터가 없고 live 목록만 미리 있다(첫 알림과 함께 끼운 목록은 낭독되지 않는다)', () => {
    const { container, rerender } = renderToasts([])
    expect(screen.queryByRole('region', { name: '새 사건 알림' })).toBeNull()
    expect(screen.queryByRole('listitem')).toBeNull()
    const section = container.querySelector('section')
    expect(section).toHaveClass('pointer-events-none')
    const live = section?.querySelector('ol[aria-live="polite"]')
    expect(live).toBeEmptyDOMElement()

    rerender([toast()])
    const region = screen.getByRole('region', { name: '새 사건 알림' })
    expect(region.querySelector('ol')).toBe(live)
    expect(region).not.toHaveClass('pointer-events-none')
    expect(within(region).getAllByRole('listitem')).toHaveLength(1)
  })

  it('한 장: 심각도 · 장비(보호 대상 먼저) · 규칙 번호와 이름 · 출발지 · 건수. 겉은 section, 목록만 aria-live, status · alert 는 없다', () => {
    const { container } = renderToasts([toast()])
    const region = screen.getByRole('region', { name: '새 사건 알림' })
    expect(region.tagName).toBe('SECTION')
    expect(region).toHaveClass('fixed', 'bottom-4', 'right-4', 'left-4', 'z-30', 'print:hidden')
    expect(region.querySelector('ol')).toHaveAttribute('aria-live', 'polite')
    expect(region).not.toHaveAttribute('aria-live')
    expect(container.querySelector('[role="status"], [role="alert"]')).toBeNull()

    const card = within(region).getByRole('listitem')
    expect(card.querySelector('[data-severity]')).toHaveTextContent('high')
    const badges = [...card.querySelectorAll('[data-device]')].map((el) => el.getAttribute('data-device'))
    expect(badges).toEqual(['web-01', 'aws-sensor'])
    expect(card.querySelector('[data-device="web-01"]')).toHaveTextContent('web-01 · 웹 접근')
    expect(card).toHaveTextContent('R101')
    expect(card).toHaveTextContent('SSH 무차별 대입')
    expect(card).toHaveTextContent('198.51.100.7')
    expect(card.querySelector('[data-toast-count]')).toHaveTextContent('1건')
  })

  it('링크는 글 부분만 감싸고 닫기 단추는 링크 밖 형제다. 한 건은 상세, 묶음은 규칙 · 출발지 목록, 출발지 없는 묶음은 마지막 사건', () => {
    const key = 'R101|w2|198.51.100.7|2026-09-30T00:00:00+00:00'
    const { rerender } = renderToasts([toast()])
    const link = screen.getByRole('link')
    expect(link).toHaveAttribute('href', `/incidents/${encodeURIComponent(key)}`)
    const close = screen.getByRole('button', { name: '알림 닫기' })
    expect(link).not.toContainElement(close)
    expect(link.querySelector('button')).toBeNull()
    expect(close.parentElement).toBe(link.parentElement)

    rerender([toast({ keys: [key, 'k2', 'k3'] })])
    expect(screen.getByRole('link')).toHaveAttribute('href', '/incidents?rule_id=R101&actor_ip=198.51.100.7')
    expect(screen.getByRole('listitem').querySelector('[data-toast-count]')).toHaveTextContent('3건')

    rerender([toast({ id: 'n1', keys: ['n1', 'n2|x'], rule_id: 'R301', actor_ip: null, target: 'node:web-01' })])
    expect(screen.getByRole('link')).toHaveAttribute('href', `/incidents/${encodeURIComponent('n2|x')}`)
    expect(screen.getByRole('listitem')).toHaveTextContent('node:web-01')
  })

  it('닫기 단추는 그 장의 id 로 onDismiss 를 부른다', () => {
    const { onDismiss } = renderToasts([toast({ id: 'a', keys: ['a'] }), toast({ id: 'b', keys: ['b'] })])
    const cards = screen.getAllByRole('listitem')
    fireEvent.click(within(cards[1]).getByRole('button', { name: '알림 닫기' }))
    expect(onDismiss).toHaveBeenCalledWith('b')
  })

  it('키보드로 닫으면 초점이 남은 장의 닫기 단추로, 마지막 장이면 본문으로 간다. 마우스로 닫으면 옮기지 않는다', () => {
    const { unmount } = render(<Stack initial={['a', 'b', 'c'].map((id) => toast({ id, keys: [id] }))} />)
    closeButtons()[0].focus()
    fireEvent.click(closeButtons()[0], { detail: 0 })       // Enter · Space 로 누른 click 은 detail 0 이다
    expect(closeButtons()).toHaveLength(2)
    expect(closeButtons()[0]).toHaveFocus()                  // 다음 장(b)
    closeButtons()[1].focus()
    fireEvent.click(closeButtons()[1], { detail: 0 })       // 끝 장(c)이면 앞 장(b)으로
    expect(closeButtons()).toHaveLength(1)
    expect(closeButtons()[0]).toHaveFocus()
    fireEvent.click(closeButtons()[0], { detail: 0 })       // 남은 장이 없으면 본문
    expect(closeButtons()).toHaveLength(0)
    expect(screen.getByRole('main')).toHaveFocus()
    unmount()

    render(<Stack initial={['a', 'b'].map((id) => toast({ id, keys: [id] }))} />)
    closeButtons()[0].focus()
    fireEvent.click(closeButtons()[0], { detail: 1 })
    expect(closeButtons()).toHaveLength(1)
    expect(closeButtons()[0]).not.toHaveFocus()
  })

  it('초점이 있던 장이 blur 없이 빠져도(새 알림에 밀려남) 남은 장은 60초 뒤 닫힌다', () => {
    vi.useFakeTimers()
    const first = ['a', 'b', 'c'].map((id) => toast({ id, keys: [id] }))
    const { rerender, onDismiss } = renderToasts(first)
    act(() => closeButtons()[2].focus())
    const region = screen.getByRole('region', { name: '새 사건 알림' })
    expect(region).toHaveAttribute('data-paused')
    rerender([toast({ id: 'n', keys: ['n'] }), ...first])   // 초점이 있던 c 가 3장 밖으로 빠진다
    expect(document.activeElement).toBe(document.body)
    expect(region).not.toHaveAttribute('data-paused')
    act(() => void vi.advanceTimersByTime(TOAST_MS))
    expect(onDismiss.mock.calls.map(([id]) => id)).toEqual(['n', 'a', 'b'])
  })

  it('최대 3장까지만 그린다', () => {
    renderToasts(['a', 'b', 'c', 'd'].map((id) => toast({ id, keys: [id] })))
    expect(screen.getAllByRole('listitem')).toHaveLength(3)
  })

  it('악성 규칙 이름 · 대상 · 장비 이름(hostname)도 글자로만 그리고, 링크는 같은 출처 경로다', () => {
    const { container } = renderToasts([
      toast({
        id: `${HOSTILE.jsUrl}|${HOSTILE.rlo}`,
        keys: [`${HOSTILE.jsUrl}|${HOSTILE.rlo}`],
        rule_name: MIXED,
        actor_ip: null,
        target: `node:${HOSTILE.img}`,
        devices: [device({ id: 'web-02', label: MIXED })],
      }),
    ])
    expectInertDom(container)
    expectMixedRevealed(screen.getByRole('listitem'))
    const href = screen.getByRole('link').getAttribute('href') ?? ''
    expect(href.startsWith('/incidents/')).toBe(true)
    expect(href).not.toContain('javascript:')
    expect(href).not.toContain('\u{202E}')
  })

  it('60초 뒤 닫힌다. 마우스가 올라가 있거나 초점이 있거나 탭이 숨은 동안은 멈춘다', () => {
    vi.useFakeTimers()
    const { onDismiss } = renderToasts([toast({ id: 'a', keys: ['a'] })])
    const region = screen.getByRole('region', { name: '새 사건 알림' })

    act(() => void vi.advanceTimersByTime(20_000))
    fireEvent.pointerEnter(region, { pointerType: 'mouse' })
    act(() => void vi.advanceTimersByTime(120_000))
    expect(onDismiss).not.toHaveBeenCalled()
    fireEvent.pointerLeave(region, { pointerType: 'mouse' })

    act(() => void vi.advanceTimersByTime(10_000))
    fireEvent.focus(screen.getByRole('button', { name: '알림 닫기' }))
    act(() => void vi.advanceTimersByTime(120_000))
    expect(onDismiss).not.toHaveBeenCalled()
    fireEvent.blur(screen.getByRole('button', { name: '알림 닫기' }), { relatedTarget: null })

    act(() => setVisibility('hidden'))
    act(() => void vi.advanceTimersByTime(120_000))
    expect(onDismiss).not.toHaveBeenCalled()
    act(() => setVisibility('visible'))

    // 떠 있던 시간은 20 + 10 = 30초. 남은 30초가 지나면 닫힌다
    act(() => void vi.advanceTimersByTime(TOAST_MS - 30_001))
    expect(onDismiss).not.toHaveBeenCalled()
    act(() => void vi.advanceTimersByTime(1))
    expect(onDismiss).toHaveBeenCalledWith('a')
  })

  it('링크로 사건을 열면 그 장이 닫히고 초점은 본문으로 간다. 남은 장은 60초 뒤 닫힌다', () => {
    vi.useFakeTimers()
    render(<Stack initial={[toast({ id: 'a', keys: ['a'] }), toast({ id: 'b', keys: ['b'] })]} />)
    const [first] = screen.getAllByRole('link')
    act(() => first.focus())
    fireEvent.click(first)
    expect(screen.getAllByRole('link')).toHaveLength(1)
    expect(document.activeElement).toBe(document.getElementById('main'))
    act(() => void vi.advanceTimersByTime(TOAST_MS))
    expect(screen.queryAllByRole('link')).toHaveLength(0)
  })

  it('터치로 올라간 포인터는 알림을 멈추지 않는다(떠날 때 leave 가 오지 않는다)', () => {
    vi.useFakeTimers()
    const { onDismiss } = renderToasts([toast({ id: 'a', keys: ['a'] })])
    fireEvent.pointerEnter(screen.getByRole('region', { name: '새 사건 알림' }), { pointerType: 'touch' })
    act(() => void vi.advanceTimersByTime(TOAST_MS))
    expect(onDismiss).toHaveBeenCalledWith('a')
  })

  it('묶여 새 사건이 붙으면(version) 다시 60초를 잰다', () => {
    vi.useFakeTimers()
    const first = toast({ id: 'a', keys: ['a'] })
    const { rerender, onDismiss } = renderToasts([first])
    act(() => void vi.advanceTimersByTime(50_000))
    rerender([{ ...first, version: 1, keys: ['a', 'b'] }])
    act(() => void vi.advanceTimersByTime(TOAST_MS - 1))
    expect(onDismiss).not.toHaveBeenCalled()
    act(() => void vi.advanceTimersByTime(1))
    expect(onDismiss).toHaveBeenCalledWith('a')
  })
})
