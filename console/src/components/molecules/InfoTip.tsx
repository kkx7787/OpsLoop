import { useCallback, useEffect, useId, useLayoutEffect, useRef, useSyncExternalStore, type MouseEvent, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { placeTip, TIP_GUTTER } from './info-tip-place'

/** icon: 열 머리 · 배지 · 소제목 옆 ⓘ · text: 구역 끝 글자 단추('기준 보기') */
export type InfoTipVariant = 'icon' | 'text'
/** hide: 종이에 단추 · 설명 모두 빼기(기본) · expand: 단추만 빼고 설명은 늘 펼쳐 찍기 */
export type InfoTipPrint = 'hide' | 'expand'

/** render 에 넘기는 조각. 단추와 설명 상자를 떨어진 자리에 둘 때 쓴다 */
export interface InfoTipParts {
  /** 여닫는 단추 */
  button: ReactNode
  /** 설명 상자. 닫혀 있어도 DOM 에 있다. 열리면 단추 가까이에 겹쳐 뜨므로 놓는 자리는 낭독 · 인쇄 순서만 정한다 */
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
  /** 설명 상자 클래스(내용 글꼴 · 줄 배치 · 인쇄 여백). 위치 · 열림 · 닫힘 클래스는 뒤에 붙어 이긴다 */
  panelClassName?: string
  /** 단추와 설명 상자를 직접 배치한다. 없으면 단추 바로 뒤에 설명 상자를 둔다 */
  render?: (parts: InfoTipParts) => ReactNode
}

/*
 * 한 번에 하나만 연다. 열린 설명 상자 id 하나를 모듈에 두고(useSyncExternalStore), 다른 것을 열면 앞의 것이 닫힌다.
 * 각 InfoTip 은 '내가 열렸는가' 만 구독해 여닫힌 둘만 다시 그린다.
 */
let openPanel: string | null = null
const listeners = new Set<() => void>()

function setOpenPanel(next: string | null) {
  if (openPanel === next) return
  openPanel = next
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/**
 * popover(top layer)를 쓸 수 있는가. 못 쓰면(옛 브라우저 · jsdom) popover 속성을 달지 않고 fixed 만으로 겹쳐 띄운다.
 * jsdom 은 showPopover 없이 UA 규칙([popover]:not(:popover-open) → display:none)만 있어, 속성을 달면 열어도 보이지 않는다
 */
function canPopover(): boolean {
  return typeof HTMLElement !== 'undefined' && typeof HTMLElement.prototype.showPopover === 'function' && typeof HTMLElement.prototype.hidePopover === 'function'
}

function showLayer(el: HTMLElement) {
  try {
    el.showPopover()
  } catch {
    // 이미 떠 있거나 문서에서 떨어진 경우. fixed 로도 겹쳐 뜬다
  }
}

function hideLayer(el: HTMLElement) {
  try {
    el.hidePopover()
  } catch {
    // 이미 닫혔다
  }
}

const ICON_BUTTON =
  // 보이는 원은 16px, 누를 자리는 after 로 24px 까지 넓힌다(터치 · WCAG 2.5.8)
  'relative inline-flex size-4 shrink-0 cursor-pointer items-center justify-center rounded-full border-0 bg-transparent p-0 ' +
  "align-[-0.2em] text-ink-muted hover:text-primary after:absolute after:-inset-1 after:content-['']"
const TEXT_BUTTON =
  'inline-flex cursor-pointer items-center gap-0.5 rounded-sm border-0 bg-transparent p-0 font-sans text-xs font-medium text-primary hover:underline'

// 말풍선 모양. 표 머리(굵게 · 한 줄 · 대문자) 안에 있어도 보통 글로 되돌린다.
// 폭은 22rem 과 화면 폭 - 좌우 여백(--tip-max, 스크롤바를 뺀 값) 가운데 작은 쪽, 긴 목록은 안에서 스크롤한다
const PANEL =
  'block w-max max-w-[min(22rem,var(--tip-max,calc(100vw-2rem)))] max-h-[60vh] overflow-y-auto ' +
  'rounded-control border border-line bg-surface px-2.5 py-1.5 text-left text-xs leading-5 font-normal tracking-normal normal-case whitespace-normal text-ink shadow-raised'
// 겹쳐 띄우기: 흐름 밖(fixed)이라 본문을 밀지 않는다. 위치는 CSSOM 으로 넣은 --tip-x/--tip-y(CSP style-src 'self' 에 걸리지 않는다).
// popover 의 UA 기본값(inset 0 · margin auto → 가운데 정렬)은 inset-auto · m-0 으로 되돌린다
const PLACE = 'fixed inset-auto m-0 left-(--tip-x) top-(--tip-y) z-50'
// 인쇄 펼침: 제자리(흐름 안)에 보통 글로 찍는다
const PRINT_EXPAND =
  'print:static print:mt-1 print:block print:w-auto print:max-w-none print:max-h-none print:overflow-visible ' +
  'print:rounded-none print:border-0 print:bg-transparent print:p-0 print:shadow-none'

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
 * 도움말(ⓘ) 말풍선(#79). 계산 기준 · 판단 근거 · 예외처럼 늘 볼 필요 없는 설명을 접어 둔다. 안전 · 판정 경고는 넣지 않는다(본문에 둔다).
 *  누르면 단추 가까이(아래, 자리가 없으면 위)에 겹쳐 뜨고 본문 배치를 밀지 않는다. popover(top layer)라 overflow 상자 ·
 *   @container 카드 · z-index 에 잘리지 않고, DOM 자리는 그대로라 설명 연결(aria-describedby)과 인쇄가 유지된다.
 *   좌우는 화면 가장자리 16px 안쪽에 들어오고(390 포함), 스크롤 · 창 크기가 바뀌면 다시 자리를 잡는다
 *  다시 누르기 · 바깥 누르기 · Esc 로 닫힌다. 한 번에 하나만 열린다
 *  클릭 · 탭 · Enter · Space(네이티브 button)로 여닫는다. 마우스 올림으로는 열지 않는다
 *  Esc 는 문서 캡처 단계에서 먼저 받아 전파를 막는다(감싼 서랍 · 양식의 Esc 보다 먼저 닫힌다). 닫혀 있으면 가로채지 않는다.
 *   초점이 단추나 설명 안에 있을 때만 단추로 돌린다(다른 입력 칸의 초점은 빼앗지 않는다). 바깥 누르기는 초점을 옮기지 않는다
 *  설명 상자는 닫혀 있어도 DOM 에 있다. 닫힘은 hidden 속성이 아니라 'hidden' 클래스다
 *   (Tailwind 4 기본 스타일의 [hidden]{display:none !important} 가 print:block 을 이기기 때문)
 *  낭독: icon 단추는 설명 상자를 aria-describedby 로 읽는다(닫혀 있어도). 대상 요소도 id 로 이을 수 있다
 *   text 단추(긴 기준)는 이름만 읽고, 펼치면 내용을 읽는다
 *  인쇄: 단추는 늘 빠진다. 설명은 print="expand" 일 때만 제자리에 펼쳐 찍힌다(인쇄 직전에 떠 있던 말풍선은 닫는다)
 *  단추 누름은 기본 동작을 막아(preventDefault) 누르면 이동하는 행(IncidentRow)으로 번지지 않는다
 *  CSP(style-src 'self'): style 속성 · 인라인 <style> 을 쓰지 않는다. 위치만 CSSOM(style.setProperty)으로 넣는다
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
  const open = useSyncExternalStore(
    subscribe,
    () => openPanel === panelId,
    () => false,
  )
  const buttonRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLElement | null>(null)
  // span · div 어느 쪽이든 받도록 콜백으로 잇는다
  const setPanel = useCallback((el: HTMLElement | null) => {
    panelRef.current = el
  }, [])
  const icon = variant === 'icon'
  const layer = canPopover()

  // 열린 채 사라지면 닫힌 것으로 돌린다
  useEffect(
    () => () => {
      if (openPanel === panelId) setOpenPanel(null)
    },
    [panelId],
  )

  // 열리면 top layer 에 올리고 단추 가까이에 자리를 잡는다(그리기 전에)
  useLayoutEffect(() => {
    const panel = panelRef.current
    const button = buttonRef.current
    if (!open || !panel || !button) return
    if (layer) showLayer(panel)
    function place() {
      if (!panel || !button) return
      const root = document.documentElement
      const viewport = { width: root.clientWidth || window.innerWidth, height: root.clientHeight || window.innerHeight }
      panel.style.setProperty('--tip-max', `${Math.max(0, viewport.width - 2 * TIP_GUTTER)}px`)
      const spot = placeTip(button.getBoundingClientRect(), { width: panel.offsetWidth, height: panel.offsetHeight }, viewport)
      panel.style.setProperty('--tip-x', `${Math.round(spot.x)}px`)
      panel.style.setProperty('--tip-y', `${Math.round(spot.y)}px`)
    }
    place()
    // 안쪽 스크롤 상자(표 · 서랍)도 잡도록 캡처로 듣는다
    window.addEventListener('scroll', place, true)
    window.addEventListener('resize', place)
    return () => {
      window.removeEventListener('scroll', place, true)
      window.removeEventListener('resize', place)
      if (layer) hideLayer(panel)
    }
  }, [open, layer])

  // 열려 있는 동안만 문서의 바깥 누르기 · Esc · 인쇄 직전을 듣는다
  useEffect(() => {
    if (!open) return
    const close = () => {
      if (openPanel === panelId) setOpenPanel(null)
    }
    const inside = (node: unknown) =>
      node instanceof Node && (!!buttonRef.current?.contains(node) || !!panelRef.current?.contains(node))
    function onPointerDown(event: PointerEvent) {
      if (!inside(event.target)) close()
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== 'Escape') return
      event.preventDefault()
      event.stopImmediatePropagation()
      const back = inside(document.activeElement)
      close()
      if (back) buttonRef.current?.focus()
    }
    // 떠 있는 말풍선은 top layer 라 제자리에 찍히지 않는다. 인쇄 직전에 바로 내린다
    function onBeforePrint() {
      if (layer && panelRef.current) hideLayer(panelRef.current)
      close()
    }
    document.addEventListener('pointerdown', onPointerDown, true)
    document.addEventListener('keydown', onKeyDown, true)
    window.addEventListener('beforeprint', onBeforePrint)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true)
      document.removeEventListener('keydown', onKeyDown, true)
      window.removeEventListener('beforeprint', onBeforePrint)
    }
  }, [open, panelId, layer])

  function toggle(event: MouseEvent<HTMLButtonElement>) {
    event.preventDefault()
    setOpenPanel(open ? null : panelId)
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
    <Panel
      ref={setPanel}
      id={panelId}
      data-infotip=""
      popover={layer ? 'manual' : undefined}
      className={cn(
        PANEL,
        print === 'expand' ? cn(PRINT_EXPAND, !icon && 'print:text-ink-muted') : 'print:hidden',
        panelClassName,
        PLACE,
        !open && 'hidden',
      )}
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
