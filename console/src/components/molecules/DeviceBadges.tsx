import { cn } from '@/lib/cn'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../atoms/Badge'
import { UntrustedText } from '../atoms/UntrustedText'
import { DEVICE_BASIS_LABEL, DEVICE_UNKNOWN_LABEL, deviceKey, deviceText, deviceView, type DeviceSource, type KnownDevice } from './device-format'

export interface DeviceBadgesProps {
  source: DeviceSource
  /** compact: 목록 행 · 카드 · 대기열 · 알림(앞 max 개와 '+n') · full: 상세 머리(전부와 근거 글자) */
  mode: 'compact' | 'full'
  /** compact 에서 보일 장비 수. 기본 2 */
  max?: number
  className?: string
}

function DeviceBadge({ device }: { device: KnownDevice }) {
  const logs = Array.isArray(device.logs) ? device.logs : []
  return (
    <Badge
      tone="neutral"
      data-device={device.id}
      data-device-part={device.part ?? undefined}
      data-device-basis={device.basis}
      title={revealHidden(deviceText(device))}
      className={cn('max-w-full min-w-0', device.group === 'protected' ? 'font-medium text-ink' : 'font-normal')}
    >
      <span className="min-w-0 truncate">
        <UntrustedText value={device.label} clip fallback={device.id} />
        {logs.length > 0 && ` · ${logs.join(' · ')}`}
      </span>
    </Badge>
  )
}

/**
 * 사건의 관련 장비(#72): '장비 · 로그 종류' 배지, 보호 대상 먼저. 이전 서버(devices 없음)면 그리지 않는다.
 * 확인 · 규칙 범위만 그리고, 없으면 점선 '장비 미확인' 하나다. 대체 추정 장비 이름은 이 배지에 쓰지 않는다(상세 ⓘ 만).
 * compact 는 목록 행 · 카드가 통째로 링크라 단추 · ⓘ 를 두지 않고, 확인과 규칙 범위를 같은 모양으로 그린다.
 * full 은 배지 뒤에 근거 글자(확인 · 규칙 범위)를 붙인다.
 */
export function DeviceBadges({ source, mode, max = 2, className }: DeviceBadgesProps) {
  const view = deviceView(source)
  if (view.legacy) return null
  const wrap = cn('flex min-w-0 items-center gap-1', mode === 'full' && 'flex-wrap', className)

  if (view.unknown) {
    return (
      <span className={wrap}>
        <Badge tone="neutral" data-device-unknown="" className="border border-dashed border-line bg-transparent font-normal text-ink-muted">
          {DEVICE_UNKNOWN_LABEL}
        </Badge>
      </span>
    )
  }

  if (mode === 'full') {
    return (
      <span className={wrap}>
        {view.known.map((d) => (
          <span key={deviceKey(d)} className="inline-flex max-w-full min-w-0 items-baseline gap-1">
            <DeviceBadge device={d} />
            <span className="shrink-0 text-xs text-ink-muted">{DEVICE_BASIS_LABEL[d.basis]}</span>
          </span>
        ))}
      </span>
    )
  }

  const shown = view.known.slice(0, Math.max(1, max))
  const rest = view.known.slice(shown.length)
  return (
    <span className={wrap}>
      {shown.map((d) => (
        <DeviceBadge key={deviceKey(d)} device={d} />
      ))}
      {rest.length > 0 && (
        <Badge tone="neutral" data-device-more="" title={revealHidden(rest.map(deviceText).join(', '))} className="shrink-0 font-normal">
          <span aria-hidden="true">+{rest.length}</span>
          <span className="sr-only">외 {rest.length}대</span>
        </Badge>
      )}
    </span>
  )
}
