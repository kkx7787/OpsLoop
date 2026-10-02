import { Link } from 'react-router'
import type { Delivery } from '@/api/notify'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { isLogDeviceId, statusHref } from '@/components/molecules/device-format'
import { incidentHref } from '../incidents/model'

/** 저장된 대상 키는 보존하되, 확인 가능한 사건·노드만 내부 경로로 연결한다. */
export function DeliverySubject({ delivery }: { delivery: Pick<Delivery, 'event' | 'subject_key'> }) {
  const { event, subject_key: key } = delivery
  const parts = key.split('|')
  if ((event === 'incident.created' || event === 'pending.overdue') && parts.length >= 4 && /^R\d+$/.test(parts[0])) {
    return <div className="flex flex-col gap-1">
      <Link to={incidentHref(key)} className="font-medium">{parts[0]} · 사건 보기 →</Link>
      <span className="font-mono text-xs text-ink-muted"><UntrustedText value={parts[2]} /></span>
      <details className="text-xs text-ink-muted"><summary className="cursor-pointer">대상 키</summary><UntrustedText value={key} className="break-all font-mono" /></details>
    </div>
  }
  if (event === 'node.silent' && key.startsWith('node:')) {
    const node = key.slice(5).split('@')[0]
    if (isLogDeviceId(node)) return <div className="flex flex-col gap-1">
      <Link to={statusHref()} className="font-medium"><UntrustedText value={node} /> · 수신 상태 →</Link>
      <details className="text-xs text-ink-muted"><summary className="cursor-pointer">대상 키</summary><UntrustedText value={key} className="break-all font-mono" /></details>
    </div>
  }
  return <UntrustedText value={key} className="break-all font-mono text-xs" />
}
