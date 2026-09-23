import { Link } from 'react-router'
import { cn } from '@/lib/cn'
import { IconLogo } from '../../atoms/icons'

export interface BrandProps {
  className?: string
  onClick?: () => void
}

/** 제품 표지: 파란 순환 화살표 + OpsLoop. 누르면 대시보드로 간다. */
export function Brand({ className, onClick }: BrandProps) {
  return (
    <Link to="/" onClick={onClick} className={cn('flex h-[68px] items-center gap-2.5 px-2 text-ink hover:text-ink', className)}>
      <span aria-hidden="true" className="flex size-7 items-center justify-center text-primary">
        <IconLogo size={26} />
      </span>
      <span className="text-[19px] font-semibold tracking-heading">OpsLoop</span>
    </Link>
  )
}
