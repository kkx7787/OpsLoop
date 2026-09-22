import { useId, type ComponentProps, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { SOFT_TONE, TEXT_TONE } from '../../atoms/tones'

export type StateTone = 'info' | 'warning' | 'danger'

export interface StateViewProps extends Omit<ComponentProps<'section'>, 'title'> {
  tone?: StateTone
  /** 머리말(S-03 · 결과 0건 / 공통 · 403) */
  eyebrow?: ReactNode
  title: ReactNode
  description?: ReactNode
  /** page 크기에서만 보이는 아이콘 칸 */
  icon?: ReactNode
  /** 단추 · 링크 */
  actions?: ReactNode
  /** 맨 아래 작은 글 */
  footnote?: ReactNode
  /**
   * compact: 목록 · 카드 자리를 대신하는 작은 카드(States.dc.html)
   * page: 본문 전체를 대신하는 큰 카드(Error.dc.html)
   */
  size?: 'compact' | 'page'
  titleAs?: 'h1' | 'h2' | 'h3'
}

/** 상태 화면들의 공통 틀. 정상 화면만 그리면 빠지는 상태를 모든 화면이 같은 모양으로 보인다. */
export function StateView({
  tone = 'info',
  eyebrow,
  title,
  description,
  icon,
  actions,
  footnote,
  size = 'compact',
  titleAs: Heading = 'h2',
  className,
  children,
  ...rest
}: StateViewProps) {
  const titleId = useId()
  const page = size === 'page'
  return (
    <section
      aria-labelledby={titleId}
      data-state-tone={tone}
      className={cn(
        'flex flex-col items-start rounded-card bg-surface shadow-card',
        page ? 'gap-4 px-6 py-10 md:px-11 md:py-12' : 'gap-2.5 p-5',
        className,
      )}
      {...rest}
    >
      {page && icon && (
        <span className={cn('flex size-14 items-center justify-center rounded-tile', SOFT_TONE[tone])} aria-hidden="true">
          {icon}
        </span>
      )}
      {eyebrow && <span className={cn('text-2xs font-semibold', TEXT_TONE[tone])}>{eyebrow}</span>}
      <Heading
        id={titleId}
        className={cn('m-0', page ? 'text-2xl font-bold tracking-display' : 'text-lg font-semibold tracking-heading')}
      >
        {title}
      </Heading>
      {description && (
        <div className={cn('text-ink-muted', page ? 'max-w-prose text-base' : 'text-xs')}>{description}</div>
      )}
      {children}
      {actions && <div className={cn('flex flex-wrap gap-2', page ? 'mt-2 gap-2.5' : 'mt-auto pt-1')}>{actions}</div>}
      {footnote && <p className={cn('m-0 text-xs text-ink-muted', page && 'mt-2')}>{footnote}</p>}
    </section>
  )
}
