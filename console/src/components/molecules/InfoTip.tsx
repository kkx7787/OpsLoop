import { useId, useRef, useState, type KeyboardEvent, type MouseEvent, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'

/** icon: 열 머리 · 배지 · 소제목 옆 ⓘ · text: 구역 끝 글자 단추('기준 보기') */
export type InfoTipVariant = 'icon' | 'text'
/** hide: 종이에 단추 · 설명 모두 빼기(기본) · expand: 단추만 빼고 설명은 늘 펼쳐 찍기 */
export type InfoTipPrint = 'hide' | 'expand'

/** render 에 넘기는 조각. 단추와 설명 상자를 떨어진 자리에 둘 때 쓴다 */
export interface InfoTipParts {
  /** 여닫는 단추 */
  button: ReactNode
  /** 설명 상자. 닫혀 있어도 DOM 에 있다 */
  panel: ReactNode
  /** 설명 상자 id. 대상 요소(열 머리 · 배지 · 입력)의 aria-describedby 에 준다 */
  id: string
  open: boolean
}

export interface InfoTipProps {
  /**
   * 무엇의 설명인지(열 머리 · 배지 · 소제목 이름). 단추의 낭독 이름이 된다.
   * icon 은 '{label} 설명', text 는 '{label} {text}'. 숨은 문자는 revealHidden 으로 표식이 된다
   */
  label: string
  /** 설명 내용(계산 기준 · 판단 근거 · 예외). 비신뢰 값은 UntrustedText 로 감싸 넣는다 */
  children: ReactNode
  variant?: InfoTipVariant
  /** text 단추의 글자. 기본 '기준 보기' */
  text?: string
  print?: InfoTipPrint
  /** 설명 상자 id. 대상 요소가 aria-describedby 로 이을 때 useId 로 만들어 같은 값을 준다. 없으면 스스로 만든다 */
  id?: string
  /** 설명 상자 태그. 목록(ul) · 여러 문단을 담으면 div. 기본 span(표 머리 · 문단 · 배지 옆에 둘 수 있게) */
  panelAs?: 'span' | 'div'
  /** 단추 클래스 */
  className?: string
  /** 설명 상자 클래스. 열림 · 닫힘 · 인쇄 클래스는 뒤에 붙어 이긴다 */
  panelClassName?: string
  /** 단추와 설명 상자를 직접 배치한다. 없으면 단추 바로 뒤에 설명 상자를 둔다(블록이라 다음 줄에 펼쳐진다) */
  render?: (parts: InfoTipParts) => ReactNode
}

const ICON_BUTTON =
  // 보이는 원은 16px, 누를 자리는 after 로 24px 까지 넓힌다(터치 · WCAG 2.5.8)
  'relative inline-flex size-4 shrink-0 cursor-pointer items-center justify-center rounded-full border-0 bg-transparent p-0 ' +
  "align-[-0.2em] text-ink-muted hover:text-primary after:absolute after:-inset-1 after:content-['']"
const TEXT_BUTTON =
  'inline-flex cursor-pointer items-center gap-0.5 rounded-sm border-0 bg-transparent p-0 font-sans text-xs font-medium text-primary hover:underline'

// 표 머리(굵게 · 한 줄 · 대문자)에 들어가도 설명은 보통 글로 보이게 되돌린다
const ICON_PANEL =
  'mt-1 block max-w-prose rounded-control bg-canvas px-2.5 py-1.5 text-left text-xs leading-5 font-normal tracking-normal normal-case whitespace-normal text-ink shadow-control'
const TEXT_PANEL = 'mt-1.5 block text-left text-xs leading-5 font-normal text-ink-muted'

function InfoIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5M12 7.6h.01" />
    </svg>
  )
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      width={14}
      height={14}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={cn('transition-transform', open && 'rotate-180')}
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  )
}

/**
 * 도움말(ⓘ). 계산 기준 · 판단 근거 · 예외처럼 늘 볼 필요 없는 설명을 접어 둔다. 안전 · 판정 경고는 넣지 않는다(본문에 둔다).
 *  떠 있는 말풍선이 아니다. 누르면 바로 아래(다음 줄)에 펼쳐진다. 표가 overflow-x-auto 상자 안에 있어도 잘리지 않는다
 *  클릭 · 탭 · Enter · Space(네이티브 button)로 여닫고, Esc 로 닫으면 초점이 단추로 돌아온다. 마우스 올림으로는 열지 않는다
 *  설명 상자는 닫혀 있어도 DOM 에 있다. 닫힘은 hidden 속성이 아니라 'hidden' 클래스다
 *   (Tailwind 4 기본 스타일의 [hidden]{display:none !important} 가 print:block 을 이기기 때문)
 *  낭독: icon 단추는 설명 상자를 aria-describedby 로 읽는다(닫혀 있어도). 대상 요소도 id 로 이을 수 있다
 *   text 단추(긴 기준)는 이름만 읽고, 펼치면 내용을 읽는다
 *  인쇄: 단추는 늘 빠진다. 설명은 print="expand" 일 때만 펼쳐 찍힌다
 *  단추 누름은 기본 동작을 막아(preventDefault) 누르면 이동하는 행(IncidentRow)으로 번지지 않는다
 *  CSP(style-src 'self'): style 속성 · 인라인 <style> 을 쓰지 않는다. Tailwind 클래스만 쓴다
 */
export function InfoTip({
  label,
  children,
  variant = 'icon',
  text = '기준 보기',
  print = 'hide',
  id,
  panelAs: Panel = 'span',
  className,
  panelClassName,
  render,
}: InfoTipProps) {
  const autoId = useId()
  const panelId = id ?? autoId
  const [open, setOpen] = useState(false)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const icon = variant === 'icon'

  function toggle(event: MouseEvent<HTMLButtonElement>) {
    event.preventDefault()
    setOpen((v) => !v)
  }

  // 열려 있을 때만 Esc 를 가로챈다. 닫혀 있으면 감싸는 쪽(서랍 · 양식)의 Esc 가 그대로 먹는다
  function closeOnEscape(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== 'Escape' || !open) return
    event.preventDefault()
    event.stopPropagation()
    setOpen(false)
    buttonRef.current?.focus()
  }

  const button = (
    <button
      ref={buttonRef}
      type="button"
      aria-expanded={open}
      aria-controls={panelId}
      aria-label={revealHidden(icon ? `${label} 설명` : `${label} ${text}`)}
      aria-describedby={icon ? panelId : undefined}
      onClick={toggle}
      onKeyDown={closeOnEscape}
      className={cn(icon ? ICON_BUTTON : TEXT_BUTTON, icon && open && 'text-primary', className, 'print:hidden')}
    >
      {icon ? (
        <InfoIcon />
      ) : (
        <>
          {revealHidden(text)}
          <Chevron open={open} />
        </>
      )}
    </button>
  )

  const panel = (
    // 설명 상자 안(링크 등)에 초점이 있을 때도 Esc 로 닫고 단추로 돌아간다
    <Panel
      id={panelId}
      data-infotip=""
      onKeyDown={closeOnEscape}
      className={cn(icon ? ICON_PANEL : TEXT_PANEL, panelClassName, !open && 'hidden', print === 'expand' ? 'print:block' : 'print:hidden')}
    >
      {children}
    </Panel>
  )

  if (render) return <>{render({ button, panel, id: panelId, open })}</>
  return (
    <>
      {button}
      {panel}
    </>
  )
}
