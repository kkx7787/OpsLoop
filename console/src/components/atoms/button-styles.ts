import { cn } from '@/lib/cn'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
/** sm 30px(상태 카드) · md 32px(필터 · 도구 막대) · lg 40px(상태 화면 · 판정 기록) · icon 28px */
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon'

const BASE =
  'inline-flex shrink-0 cursor-pointer select-none items-center justify-center gap-1.5 whitespace-nowrap ' +
  'transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary'

const VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-primary font-medium text-white',
  secondary: 'bg-surface text-ink shadow-control',
  ghost: 'bg-transparent text-primary',
  danger: 'bg-danger font-medium text-white',
}

// 누를 수 없을 때는 마우스를 올려도 색이 바뀌지 않게 따로 둔다.
const HOVER: Record<ButtonVariant, string> = {
  primary: 'hover:bg-primary-strong',
  secondary: 'hover:bg-canvas',
  ghost: 'hover:bg-black/5 hover:text-primary-strong',
  danger: 'hover:bg-danger-strong',
}

const SIZE: Record<ButtonSize, string> = {
  sm: 'h-[30px] rounded-control px-3 text-xs',
  md: 'h-8 rounded-control px-3 text-sm',
  lg: 'h-10 rounded-panel px-5 text-base font-medium',
  icon: 'size-7 rounded-control p-0 text-sm',
}

export interface ButtonClassOptions {
  variant?: ButtonVariant
  size?: ButtonSize
  /** 비활성 · 처리 중. 흐리게 하고 마우스 반응을 뺀다. */
  inactive?: boolean
  className?: string
}

/**
 * 버튼 모양 클래스. <a> · 라우터 Link 를 버튼처럼 보일 때도 쓴다.
 *   <Link to="/nodes" className={buttonClasses({ variant: 'secondary' })}>수집 노드 보기</Link>
 */
export function buttonClasses({
  variant = 'secondary',
  size = 'md',
  inactive = false,
  className,
}: ButtonClassOptions = {}): string {
  return cn(BASE, VARIANT[variant], SIZE[size], inactive ? 'cursor-not-allowed opacity-50' : HOVER[variant], className)
}
