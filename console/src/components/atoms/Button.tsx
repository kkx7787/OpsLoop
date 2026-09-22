import { useId, type ComponentProps, type MouseEvent } from 'react'
import { buttonClasses, type ButtonSize, type ButtonVariant } from './button-styles'
import { Spinner } from './Spinner'

export interface ButtonProps extends ComponentProps<'button'> {
  variant?: ButtonVariant
  size?: ButtonSize
  /** 처리 중. 누를 수 없고 돌림표를 보인다. */
  loading?: boolean
  /**
   * 누를 수 없는 이유(권한 밖 · 조건 부족). disabled 와 함께 준다.
   * 이유가 있으면 네이티브 disabled 대신 aria-disabled 로 둔다. 초점과 마우스 오버가 살아 있어야
   * 이유(title · 설명)를 읽을 수 있기 때문이다. 누름은 여기서 막는다.
   */
  disabledReason?: string
}

export function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  disabled = false,
  disabledReason,
  type = 'button',
  className,
  children,
  onClick,
  title,
  'aria-describedby': describedBy,
  ...rest
}: ButtonProps) {
  const reasonId = useId()
  const showReason = disabled && !!disabledReason
  const blocked = disabled || loading
  // 이유 없는 disabled 만 네이티브로 끈다. 처리 중에는 초점이 사라지지 않도록 aria-disabled 로 둔다.
  const nativeDisabled = disabled && !disabledReason && !loading

  function handleClick(event: MouseEvent<HTMLButtonElement>) {
    if (blocked) {
      event.preventDefault()
      return
    }
    onClick?.(event)
  }

  return (
    <>
      <button
        type={type}
        disabled={nativeDisabled || undefined}
        aria-disabled={blocked || undefined}
        aria-busy={loading || undefined}
        aria-describedby={[describedBy, showReason ? reasonId : undefined].filter(Boolean).join(' ') || undefined}
        title={showReason ? disabledReason : title}
        onClick={handleClick}
        className={buttonClasses({ variant, size, inactive: blocked, className })}
        {...rest}
      >
        {loading && <Spinner size="sm" decorative />}
        {children}
      </button>
      {showReason && (
        <span id={reasonId} hidden>
          {disabledReason}
        </span>
      )}
    </>
  )
}
