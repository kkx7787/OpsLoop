import { useEffect, useRef, useState, type FocusEvent, type MouseEvent, type PointerEvent } from 'react'
import { Link } from 'react-router'
import { MAX_TOASTS, TOAST_MS, toastHref, type NewIncidentToast } from '@/api/new-incidents'
import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Button } from '../atoms/Button'
import { IconClose } from '../atoms/icons'
import { SeverityBadge } from '../atoms/SeverityBadge'
import { UntrustedText } from '../atoms/UntrustedText'
import { DeviceBadges } from '../molecules/DeviceBadges'
import { sourceOf } from './incidents/model'

export interface NewIncidentToastsProps {
  /** useNewIncidentToasts 의 알림(새 것 먼저) */
  toasts: readonly NewIncidentToast[]
  onDismiss: (id: string) => void
  className?: string
}

/** 문서가 숨었는가(다른 탭 · 창을 내림). 숨은 동안은 알림 시간을 멈춘다 */
function useDocumentHidden(): boolean {
  const [hidden, setHidden] = useState(() => document.visibilityState === 'hidden')
  useEffect(() => {
    const update = () => setHidden(document.visibilityState === 'hidden')
    document.addEventListener('visibilitychange', update)
    return () => document.removeEventListener('visibilitychange', update)
  }, [])
  return hidden
}

interface ToastCardProps {
  toast: NewIncidentToast
  paused: boolean
  onDismiss: (id: string) => void
  /** 닫기 단추로 닫음(초점 옮기기는 스택이 한다) */
  onClose: (id: string, event: MouseEvent<HTMLButtonElement>) => void
  /** 링크로 사건을 엶(그 장은 할 일을 다 했다) */
  onOpen: (id: string) => void
}

/** 알림 한 장. 글 부분만 링크이고 닫기 단추는 링크 밖 형제다(링크 안에 단추를 두지 않는다 #41) */
function ToastCard({ toast, paused, onDismiss, onClose, onOpen }: ToastCardProps) {
  // 남은 시간. 묶여 새 사건이 붙으면(version) 다시 60초다
  const clock = useRef({ version: toast.version, left: TOAST_MS })

  useEffect(() => {
    const current = clock.current.version === toast.version ? clock.current : { version: toast.version, left: TOAST_MS }
    clock.current = current
    if (paused) return
    const started = Date.now()
    const timer = setTimeout(() => onDismiss(toast.id), current.left)
    return () => {
      clearTimeout(timer)
      current.left = Math.max(0, current.left - (Date.now() - started))
    }
  }, [paused, toast.id, toast.version, onDismiss])

  const source = sourceOf(toast)
  return (
    <li data-toast={toast.id} className="flex items-start gap-1 rounded-card bg-surface p-3 shadow-card">
      <Link to={toastHref(toast)} onClick={() => onOpen(toast.id)} className="flex min-w-0 flex-1 flex-col gap-1 text-ink hover:text-ink">
        <span className="flex min-w-0 items-center gap-1.5">
          <SeverityBadge severity={toast.severity} className="shrink-0" />
          <DeviceBadges source={toast} mode="compact" />
        </span>
        <span className="flex min-w-0 items-baseline gap-1.5 text-sm">
          <span className="shrink-0 font-mono font-medium">{toast.rule_id}</span>
          <span className="truncate text-ink-muted" title={revealHidden(toast.rule_name)}>
            <UntrustedText value={toast.rule_name} clip max={80} />
          </span>
        </span>
        <span className="flex min-w-0 items-baseline gap-1.5 text-xs text-ink-muted">
          <span className="truncate font-mono" title={revealHidden(source)}>
            <UntrustedText value={source} clip />
          </span>
          <span className="shrink-0" data-toast-count="">
            · {toast.keys.length.toLocaleString('ko-KR')}건
          </span>
        </span>
      </Link>
      <Button size="icon" aria-label="알림 닫기" onClick={(event) => onClose(toast.id, event)} className="shrink-0 shadow-none">
        <IconClose size={14} />
      </Button>
    </li>
  )
}

/**
 * 새 사건 알림(#72): 보호 대상 장비가 확인된 사건. 오른쪽 아래(모바일은 좌우 16px 전체 폭)에 최대 3장, 비면 보이지 않는다.
 * 한 장 = 심각도 · 장비 · 규칙 번호와 이름 · 출발지 또는 대상 · 건수 · 닫기. 60초 뒤 닫히고 마우스 · 초점 · 숨은 탭 동안은 멈춘다.
 * 링크로 사건을 열면 그 장을 닫고, 초점이 알림 안에 있었으면 본문으로 옮긴다(초점이 남아 남은 알림이 멈추지 않게).
 * 상단바(z-20)보다 위, 모바일 서랍(z-40)보다 아래다. 알림 목록만 aria-live polite 이고 status · alert 역할은 쓰지 않는다.
 * 목록(live)은 비어 있어도 늘 둔다. 첫 알림과 함께 새로 끼우면 낭독되지 않아서다. 비면 이름 · 크기 · 포인터가 없다.
 */
export function NewIncidentToasts({ toasts, onDismiss, className }: NewIncidentToastsProps) {
  const [hovered, setHovered] = useState(false)
  const [focused, setFocused] = useState(false)
  const hidden = useDocumentHidden()
  const paused = hovered || focused || hidden
  const sectionRef = useRef<HTMLElement>(null)
  const shown = toasts.slice(0, MAX_TOASTS)
  const shownIds = shown.map((toast) => toast.id).join('\n')

  // 초점이 있던 장이 빠지면 blur 없이 초점이 문서로 떨어질 수 있다(명세 · Firefox). 장이 바뀔 때마다 초점 위치로 다시 정한다
  useEffect(() => {
    setFocused(sectionRef.current?.contains(document.activeElement) ?? false)
    if (!shownIds) setHovered(false)
  }, [shownIds])

  function onBlur(event: FocusEvent<HTMLElement>) {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setFocused(false)
  }

  // 키보드로 닫으면(click detail 0) 초점을 다음 장(없으면 앞 장)의 닫기 단추, 남은 장이 없으면 본문으로 옮긴 뒤 닫는다.
  // 마우스로 닫을 때는 옮기지 않는다(초점이 스택에 남아 남은 알림이 멈추지 않게)
  function onClose(id: string, event: MouseEvent<HTMLButtonElement>) {
    if (event.detail === 0) {
      const card = event.currentTarget.closest('li')
      const next = (card?.nextElementSibling ?? card?.previousElementSibling)?.querySelector<HTMLElement>('button')
      ;(next ?? document.getElementById('main'))?.focus()
    }
    onDismiss(id)
  }

  function onOpen(id: string) {
    if (sectionRef.current?.contains(document.activeElement)) document.getElementById('main')?.focus()
    onDismiss(id)
  }

  // 멈춤은 마우스 포인터만 본다. 터치는 떠날 때 leave 가 오지 않아 남은 알림이 멈춘 채 남는다
  function onPointer(event: PointerEvent<HTMLElement>, over: boolean) {
    if (event.pointerType === 'mouse') setHovered(over)
  }

  return (
    // 마우스를 올린 동안은 닫힘 시간만 멈춘다(동작이 아니다). 키보드는 onFocus · onBlur 로 같게 멈춘다
    // oxlint-disable-next-line jsx-a11y/no-noninteractive-element-interactions
    <section
      ref={sectionRef}
      aria-label={shown.length ? '새 사건 알림' : undefined}
      data-paused={paused || undefined}
      onPointerEnter={(event) => onPointer(event, true)}
      onPointerLeave={(event) => onPointer(event, false)}
      onFocus={() => setFocused(true)}
      onBlur={onBlur}
      className={cn('fixed right-4 bottom-4 left-4 z-30 sm:left-auto sm:w-96 print:hidden', !shown.length && 'pointer-events-none', className)}
    >
      <ol aria-live="polite" className="m-0 flex list-none flex-col gap-2 p-0">
        {shown.map((toast) => (
          <ToastCard key={toast.id} toast={toast} paused={paused} onDismiss={onDismiss} onClose={onClose} onOpen={onOpen} />
        ))}
      </ol>
    </section>
  )
}
