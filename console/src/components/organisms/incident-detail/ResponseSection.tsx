import { useState } from 'react'
import type { IncidentDetail } from '@/api/incidents'
import { Button } from '../../atoms/Button'
import { Divider } from '../../atoms/Divider'
import { ActionBar } from './ActionBar'
import { DetailSection } from './DetailSection'
import { HistoryList } from './HistoryList'
import { StatusBadge } from './StatusBadge'
import { VerdictPanel } from './VerdictPanel'

export interface ResponseSectionProps {
  detail: IncidentDetail
  /** 이 사건 화면을 연 시각(ms) */
  openedAt: number
  blocked?: boolean
  className?: string
}

/** ⑤ 조치와 판정: 조치 바 · 판정 패널(S-05) · 판정 · 조치 이력 */
export function ResponseSection({ detail, openedAt, blocked = false, className }: ResponseSectionProps) {
  // 다른 관제자의 재조회 결과가 입력 중인 제출 기준을 자동 교체하면 충돌 검사가 무력해진다.
  const [expectedVersion, setExpectedVersion] = useState(detail.workflow_version)
  const changed = expectedVersion !== detail.workflow_version
  const unavailable = !detail.workflow_version
  const cannotSave = blocked || changed || unavailable
  function saved(version?: string) { if (version) setExpectedVersion(version) }
  return (
    <DetailSection id="incident-response" tabIndex={-1} number="⑤" title="조치와 판정" aside={<StatusBadge status={detail.status} />} className={`scroll-mt-16 ${className ?? ''}`}>
      {blocked && <p className="m-0 text-sm text-warning">최신 사건 상태를 확인하지 못했습니다. 입력은 유지되며, 조회가 복구되면 조치·판정을 저장할 수 있습니다.</p>}
      {unavailable && <p role="alert" className="m-0 text-sm text-warning">서버의 변경 확인 정보가 없습니다. 화면을 새로고침해 주세요. 계속되면 콘솔 배포 상태를 확인해야 합니다.</p>}
      {changed && <div role="alert" className="rounded-panel border border-warning/40 bg-warning/5 p-3 text-sm">
        <p className="mt-0">다른 변경이 저장됐습니다. 작성한 내용은 유지됩니다. 아래 이력과 현재 상태를 확인해 주세요.</p>
        <Button size="sm" disabled={blocked || unavailable} onClick={() => setExpectedVersion(detail.workflow_version)}>최신 이력 확인 후 계속</Button>
      </div>}
      <fieldset disabled={cannotSave} className="m-0 flex min-w-0 flex-col gap-3 border-0 p-0">
        <p className="m-0 text-xs text-ink-muted">판정과 조치는 현재 로그인한 계정과 저장 시각으로 이력에 남습니다.</p>
        <ActionBar detail={detail} blocked={cannotSave} expectedVersion={expectedVersion} onSaved={saved} />
        <Divider />
        <VerdictPanel detail={detail} openedAt={openedAt} blocked={cannotSave} expectedVersion={expectedVersion} onSaved={saved} />
      </fieldset>
      <Divider />
      <div className="flex flex-col gap-2">
        <h3 className="m-0 text-base font-semibold tracking-heading">이력</h3>
        <HistoryList detail={detail} />
      </div>
    </DetailSection>
  )
}
