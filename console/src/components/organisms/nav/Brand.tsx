import { Link } from 'react-router'
import { cn } from '@/lib/cn'
import { IconLogo } from '../../atoms/icons'

export interface BrandProps {
  className?: string
  onClick?: () => void
}

/** 제품 표지: 검은 칸의 순환 화살표 + OpsLoop(17px 600). 누르면 대시보드로 간다. */
export function Brand({ className, onClick }: BrandProps) {
  return (
    <Link to="/" onClick={onClick} className={cn('flex h-16 items-center gap-2.5 px-2 text-ink hover:text-ink', className)}>
      <span aria-hidden="true" className="flex size-7 items-center justify-center rounded-panel bg-ink text-white">
        <IconLogo size={16} />
      </span>
      <span className="text-lg font-semibold tracking-heading">OpsLoop</span>
    </Link>
  )
}
