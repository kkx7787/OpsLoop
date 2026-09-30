import { useId } from 'react'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { expectInertDom, expectMixedRevealed, HOSTILE, MIXED } from '@/test/hostile-fixtures'
import { UntrustedText } from '../atoms/UntrustedText'
import { InfoTip } from './InfoTip'

const RATE = '최근 30일 판정 가운데 위협으로 판정한 비율'

/**
 * jsdom 은 단추의 키 활성화(Enter 는 keydown, Space 는 keyup 에서 click)를 하지 않는다. 브라우저처럼 흉내 낸다.
 * 부품이 키의 기본 동작을 막으면(preventDefault) click 이 나지 않아 시험이 실패한다.
 */
function press(el: HTMLElement, key: 'Enter' | ' ') {
  const down = fireEvent.keyDown(el, { key })
  if (key === 'Enter' && down) fireEvent.click(el)
  const up = fireEvent.keyUp(el, { key })
  if (key === ' ' && down && up) fireEvent.click(el)
}

function panelOf(button: HTMLElement): HTMLElement {
  const id = button.getAttribute('aria-controls')
  expect(id).toBeTruthy()
  const panel = document.getElementById(id ?? '')
  expect(panel).not.toBeNull()
  return panel as HTMLElement
}

function Header({ tip }: { tip?: Partial<Parameters<typeof InfoTip>[0]> }) {
  const id = useId()
  return (
    <table>
      <thead>
        <tr>
          <th scope="col" aria-describedby={id}>
            정탐률{' '}
            <InfoTip label="정탐률" id={id} {...tip}>
              {RATE}
            </InfoTip>
          </th>
        </tr>
      </thead>
    </table>
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('InfoTip', () => {
  it('닫힌 채로 시작하고, 설명은 DOM 에 남아 단추 · 대상의 설명으로 읽힌다', () => {
    render(<Header />)
    const button = screen.getByRole('button', { name: '정탐률 설명' })
    expect(button).toHaveAttribute('type', 'button')
    expect(button).toHaveAttribute('aria-expanded', 'false')
    const panel = panelOf(button)
    expect(panel).toHaveTextContent(RATE)
    // hidden 속성이 아니라 클래스로 닫는다(print:block 이 먹게)
    expect(panel).not.toHaveAttribute('hidden')
    expect(panel).toHaveClass('hidden')
    expect(button).toHaveAccessibleDescription(RATE)
    expect(screen.getByRole('columnheader', { name: /정탐률/ })).toHaveAccessibleDescription(RATE)
    // 기존 시험의 getByText 가 닫힌 설명도 찾는다
    expect(screen.getByText(RATE)).toBe(panel)
  })

  it('누르면 단추 가까이 겹쳐 뜨고(흐름 밖 · 본문을 밀지 않음) 다시 누르면 닫힌다', () => {
    render(<Header />)
    const button = screen.getByRole('button', { name: '정탐률 설명' })
    const panel = panelOf(button)
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    expect(panel).not.toHaveClass('hidden')
    // 흐름 밖(fixed)에 뜨고 자리는 CSS 변수로 받는다. popover 의 가운데 정렬 기본값은 되돌린다
    expect(panel).toHaveClass('block', 'fixed', 'inset-auto', 'm-0', 'z-50', 'left-(--tip-x)', 'top-(--tip-y)')
    expect(panel.style.getPropertyValue('--tip-x')).toMatch(/^\d+px$/)
    expect(panel.style.getPropertyValue('--tip-y')).toMatch(/^\d+px$/)
    // DOM 자리는 그대로(단추 바로 뒤)라 설명 연결 · 인쇄 순서가 유지된다
    expect(button.nextElementSibling).toBe(panel)
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(panel).toHaveClass('hidden')
  })

  it('한 번에 하나만 열린다', () => {
    render(
      <p>
        <InfoTip label="가">가 설명</InfoTip>
        <InfoTip label="나">나 설명</InfoTip>
      </p>,
    )
    const a = screen.getByRole('button', { name: '가 설명' })
    const b = screen.getByRole('button', { name: '나 설명' })
    fireEvent.click(a)
    expect(a).toHaveAttribute('aria-expanded', 'true')
    fireEvent.pointerDown(b)
    fireEvent.click(b)
    expect(a).toHaveAttribute('aria-expanded', 'false')
    expect(panelOf(a)).toHaveClass('hidden')
    expect(b).toHaveAttribute('aria-expanded', 'true')
    // 바깥 누르기 없이 열어도(키보드) 앞의 것이 닫힌다
    fireEvent.click(a)
    expect(a).toHaveAttribute('aria-expanded', 'true')
    expect(b).toHaveAttribute('aria-expanded', 'false')
  })

  it('바깥을 누르면 닫히고 초점은 옮기지 않는다. 단추 · 설명 안을 누르면 열린 채다', () => {
    render(
      <div>
        <input aria-label="검색" />
        <InfoTip label="첫 사건">
          같은 페이로드 · <a href="/incidents">목록</a>
        </InfoTip>
      </div>,
    )
    const button = screen.getByRole('button', { name: '첫 사건 설명' })
    fireEvent.click(button)
    fireEvent.pointerDown(screen.getByRole('link', { name: '목록' }))
    expect(button).toHaveAttribute('aria-expanded', 'true')
    fireEvent.pointerDown(button)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    const input = screen.getByRole('textbox', { name: '검색' })
    input.focus()
    fireEvent.pointerDown(input)
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(input).toHaveFocus()
    fireEvent.click(button)
    fireEvent.pointerDown(document.body)
    expect(button).toHaveAttribute('aria-expanded', 'false')
  })

  it('Esc 는 문서 캡처 단계에서 먼저 받는다: 열려 있으면 감싼 서랍의 Esc 가 먹지 않고, 닫혀 있으면 그대로 간다', () => {
    const drawer = vi.fn<(event: KeyboardEvent) => void>()
    // MobileNav 처럼 문서에서 Esc 를 듣는 서랍
    document.addEventListener('keydown', drawer)
    try {
      render(<InfoTip label="판정 목표">critical 1시간</InfoTip>)
      const button = screen.getByRole('button', { name: '판정 목표 설명' })
      fireEvent.click(button)
      button.focus()
      fireEvent.keyDown(button, { key: 'Escape' })
      expect(button).toHaveAttribute('aria-expanded', 'false')
      expect(drawer).not.toHaveBeenCalled()
      fireEvent.keyDown(button, { key: 'Escape' })
      expect(drawer).toHaveBeenCalledTimes(1)
    } finally {
      document.removeEventListener('keydown', drawer)
    }
  })

  it('다른 입력 칸에 초점이 있으면 Esc 로 닫아도 초점을 빼앗지 않는다', () => {
    render(
      <div>
        <input aria-label="검색" />
        <InfoTip label="판정 목표">critical 1시간</InfoTip>
      </div>,
    )
    const button = screen.getByRole('button', { name: '판정 목표 설명' })
    fireEvent.click(button)
    const input = screen.getByRole('textbox', { name: '검색' })
    input.focus()
    fireEvent.keyDown(input, { key: 'Escape' })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(input).toHaveFocus()
  })

  it('화면 가장자리 안에 자리를 잡고, 스크롤 · 창 크기가 바뀌면 다시 잡는다', () => {
    render(<InfoTip label="표본">표본 설명</InfoTip>)
    const button = screen.getByRole('button', { name: '표본 설명' })
    const panel = panelOf(button)
    // jsdom 은 배치를 계산하지 않는다. 단추 자리 · 상자 크기를 정해 준다(창 1024×768)
    let rect = { left: 1000, top: 100, bottom: 116, right: 1016, width: 16, height: 16, x: 1000, y: 100 }
    vi.spyOn(button, 'getBoundingClientRect').mockImplementation(() => ({ ...rect, toJSON: () => rect }) as DOMRect)
    Object.defineProperty(panel, 'offsetWidth', { configurable: true, value: 300 })
    Object.defineProperty(panel, 'offsetHeight', { configurable: true, value: 100 })
    fireEvent.click(button)
    // 오른쪽이 넘치니 가장자리 16px 안으로 당기고, 아래에 자리가 있으니 단추 아래 4px
    expect(panel.style.getPropertyValue('--tip-x')).toBe(`${1024 - 16 - 300}px`)
    expect(panel.style.getPropertyValue('--tip-y')).toBe('120px')
    expect(panel.style.getPropertyValue('--tip-max')).toBe(`${1024 - 32}px`)
    // 아래 자리가 없으면 위로 뒤집는다
    rect = { ...rect, left: 40, top: 700, bottom: 716, y: 700, x: 40 }
    act(() => void window.dispatchEvent(new Event('scroll')))
    expect(panel.style.getPropertyValue('--tip-x')).toBe('40px')
    expect(panel.style.getPropertyValue('--tip-y')).toBe(`${700 - 4 - 100}px`)
    rect = { ...rect, left: 4, top: 10, bottom: 26, y: 10, x: 4 }
    act(() => void window.dispatchEvent(new Event('resize')))
    expect(panel.style.getPropertyValue('--tip-x')).toBe('16px')
    expect(panel.style.getPropertyValue('--tip-y')).toBe('30px')
  })

  it('popover 를 쓸 수 있으면 top layer 로 올리고(overflow · 카드에 잘리지 않음), 닫으면 내린다', () => {
    const show = vi.fn<() => void>()
    const hide = vi.fn<() => void>()
    const proto = HTMLElement.prototype as Partial<Pick<HTMLElement, 'showPopover' | 'hidePopover'>>
    const saved = { show: proto.showPopover, hide: proto.hidePopover }
    proto.showPopover = show
    proto.hidePopover = hide
    try {
      render(<Header />)
      const button = screen.getByRole('button', { name: '정탐률 설명' })
      const panel = panelOf(button)
      expect(panel).toHaveAttribute('popover', 'manual')
      fireEvent.click(button)
      expect(show).toHaveBeenCalledTimes(1)
      expect(show.mock.contexts[0]).toBe(panel)
      fireEvent.click(button)
      expect(hide).toHaveBeenCalledTimes(1)
    } finally {
      proto.showPopover = saved.show
      proto.hidePopover = saved.hide
    }
  })

  it('못 쓰면(옛 브라우저) popover 속성 없이 fixed 로만 띄운다', () => {
    render(<Header />)
    expect(panelOf(screen.getByRole('button', { name: '정탐률 설명' }))).not.toHaveAttribute('popover')
  })

  it('인쇄 직전에 떠 있던 말풍선을 닫는다(제자리 펼침만 찍힌다)', () => {
    render(<Header />)
    const button = screen.getByRole('button', { name: '정탐률 설명' })
    fireEvent.click(button)
    act(() => void window.dispatchEvent(new Event('beforeprint')))
    expect(button).toHaveAttribute('aria-expanded', 'false')
  })

  it('열린 채 사라지면 열림을 비운다(다시 그리면 닫혀 있다)', () => {
    const { unmount } = render(<Header />)
    fireEvent.click(screen.getByRole('button', { name: '정탐률 설명' }))
    unmount()
    render(<Header />)
    expect(screen.getByRole('button', { name: '정탐률 설명' })).toHaveAttribute('aria-expanded', 'false')
  })

  it.each([
    ['Enter', 'Enter'],
    ['Space', ' '],
  ] as const)('%s 로 열고 닫는다', (_name, key) => {
    render(<Header />)
    const button = screen.getByRole('button', { name: '정탐률 설명' })
    button.focus()
    press(button, key)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    press(button, key)
    expect(button).toHaveAttribute('aria-expanded', 'false')
  })

  it('Esc 로 닫고 초점을 단추로 돌린다(설명 안에 초점이 있을 때도)', () => {
    render(
      <InfoTip label="첫 사건">
        같은 페이로드를 처음 흡수한 사건 · <a href="/incidents">목록</a>
      </InfoTip>,
    )
    const button = screen.getByRole('button', { name: '첫 사건 설명' })
    fireEvent.click(button)
    button.focus()
    fireEvent.keyDown(button, { key: 'Escape' })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(button).toHaveFocus()

    fireEvent.click(button)
    const link = screen.getByRole('link', { name: '목록' })
    link.focus()
    fireEvent.keyDown(link, { key: 'Escape' })
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(button).toHaveFocus()
  })

  it('열려 있을 때만 Esc 를 가로챈다(닫혀 있으면 감싸는 쪽이 받는다)', () => {
    const outer = vi.fn<() => void>()
    render(
      // oxlint-disable-next-line jsx-a11y/no-static-element-interactions
      <div onKeyDown={outer}>
        <InfoTip label="판정 목표">critical 1시간 · high 4시간</InfoTip>
      </div>,
    )
    const button = screen.getByRole('button', { name: '판정 목표 설명' })
    fireEvent.keyDown(button, { key: 'Escape' })
    expect(outer).toHaveBeenCalledTimes(1)
    fireEvent.click(button)
    fireEvent.keyDown(button, { key: 'Escape' })
    expect(outer).toHaveBeenCalledTimes(1)
  })

  it('마우스 올림 · 초점만으로는 열지 않는다', () => {
    render(<Header />)
    const button = screen.getByRole('button', { name: '정탐률 설명' })
    fireEvent.mouseEnter(button)
    fireEvent.mouseOver(button)
    fireEvent.focus(button)
    expect(button).toHaveAttribute('aria-expanded', 'false')
    expect(button).not.toHaveAttribute('title')
  })

  it('누름이 감싸는 행의 이동으로 번지지 않게 기본 동작을 막는다', () => {
    let prevented: boolean | null = null
    render(
      // oxlint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
      <div onClick={(e) => (prevented = e.defaultPrevented)}>
        <InfoTip label="노출 자산">노출을 의도한 자산</InfoTip>
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: '노출 자산 설명' }))
    expect(prevented).toBe(true)
  })

  it('인쇄: 기본은 단추 · 설명 모두 빼고, expand 는 설명만 펼쳐 찍는다', () => {
    const { unmount } = render(<InfoTip label="수신 없음">3분 넘게 새 신호가 없으면 수신 없음</InfoTip>)
    let button = screen.getByRole('button', { name: '수신 없음 설명' })
    let panel = panelOf(button)
    expect(button).toHaveClass('print:hidden')
    expect(panel).toHaveClass('hidden', 'print:hidden')
    expect(panel).not.toHaveClass('print:block')
    fireEvent.click(button)
    expect(panel).toHaveClass('block', 'print:hidden')
    unmount()

    render(
      <InfoTip label="판정 품질" print="expand">
        제안이 없던 판정은 뒤집힘으로 세지 않는다
      </InfoTip>,
    )
    button = screen.getByRole('button', { name: '판정 품질 설명' })
    panel = panelOf(button)
    expect(button).toHaveClass('print:hidden')
    // 종이에는 말풍선이 아니라 제자리(흐름 안)에 보통 글로 찍는다
    expect(panel).toHaveClass('hidden', 'print:block', 'print:static', 'print:max-w-none', 'print:max-h-none', 'print:shadow-none', 'print:border-0', 'print:p-0')
    expect(panel).not.toHaveClass('print:hidden')
    expect(panel).not.toHaveAttribute('hidden')
  })

  it("text 변형: '기준 보기' 글자 단추 · div 상자에 목록 · 펼치기 전에는 단추 설명을 붙이지 않는다", () => {
    render(
      <InfoTip variant="text" label="판정 품질" print="expand" panelAs="div">
        <ul>
          <li>분모는 기간 안 판정 수</li>
          <li>제안이 없던 판정은 세지 않는다</li>
        </ul>
      </InfoTip>,
    )
    const button = screen.getByRole('button', { name: '판정 품질 기준 보기' })
    expect(button).toHaveTextContent('기준 보기')
    expect(button).not.toHaveAttribute('aria-describedby')
    const panel = panelOf(button)
    expect(panel.tagName).toBe('DIV')
    expect(panel).toHaveClass('hidden', 'print:block')
    expect(panel.querySelectorAll('li')).toHaveLength(2)
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-expanded', 'true')
    expect(panel).not.toHaveClass('hidden')
  })

  it('render 로 단추와 설명을 떨어뜨려 두고 id 로 대상을 잇는다', () => {
    render(
      <InfoTip
        label="관제 대상"
        render={({ button, panel, id, open }) => (
          <section>
            <div className="flex items-center gap-1.5">
              <h2 aria-describedby={id}>관제 대상</h2>
              {button}
            </div>
            <p data-open={String(open)}>상태판</p>
            {panel}
          </section>
        )}
      >
        카드 수치는 대상별이다
      </InfoTip>,
    )
    const heading = screen.getByRole('heading', { name: '관제 대상' })
    expect(heading).toHaveAccessibleDescription('카드 수치는 대상별이다')
    const button = screen.getByRole('button', { name: '관제 대상 설명' })
    expect(panelOf(button).parentElement?.tagName).toBe('SECTION')
    fireEvent.click(button)
    expect(screen.getByText('상태판')).toHaveAttribute('data-open', 'true')
    // 떨어진 자리에 두어도 같은 말풍선이다(단추 가까이 겹쳐 뜬다)
    expect(panelOf(button)).toHaveClass('fixed', 'left-(--tip-x)', 'top-(--tip-y)')
  })

  it('설명 상자 클래스가 display 를 바꿔도 닫힘이 이긴다', () => {
    render(
      <InfoTip label="표본" panelClassName="flex gap-2">
        표본 설명
      </InfoTip>,
    )
    const button = screen.getByRole('button', { name: '표본 설명' })
    const panel = panelOf(button)
    expect(panel).toHaveClass('hidden')
    expect(panel).not.toHaveClass('flex')
    fireEvent.click(button)
    expect(panel).toHaveClass('flex', 'gap-2')
    expect(panel).not.toHaveClass('hidden')
  })

  it('악성 문자열: 이름 · 설명 모두 글자로만 남는다', () => {
    const { container } = render(
      <p>
        대상{' '}
        <InfoTip label={MIXED}>
          <UntrustedText value={MIXED} />
        </InfoTip>
      </p>,
    )
    fireEvent.click(screen.getByRole('button'))
    expectInertDom(container)
    expectMixedRevealed(container)
    const button = screen.getByRole('button')
    expect(button.getAttribute('aria-label')).toContain('⟨U+202E⟩')
    expect(button.getAttribute('aria-label')).toContain(HOSTILE.img)
    expect(button.getAttribute('aria-label')?.endsWith(' 설명')).toBe(true)
  })

  it('악성 문자열: 문자열 설명 · text 단추 글자도 태그가 되지 않는다', () => {
    const raw = `${HOSTILE.img} ${HOSTILE.svg} ${HOSTILE.style} ${HOSTILE.prefetch}`
    const { container } = render(
      <InfoTip variant="text" label="출처" text={HOSTILE.rlo} print="expand">
        {raw}
      </InfoTip>,
    )
    expect(container.querySelectorAll('img, style, link, script, [src], svg:not([aria-hidden="true"])')).toHaveLength(0)
    expect(container.textContent).toContain(raw)
    const button = screen.getByRole('button')
    expect(button).toHaveTextContent('admin⟨U+202E⟩gnp.exe')
    expect(button).toHaveAccessibleName('출처 admin⟨U+202E⟩gnp.exe')
    expect(container.querySelectorAll('[style]')).toHaveLength(0)
  })
})
