import { useId, useState } from 'react'
import type { RawLine } from '@/api/incidents'
import { Button } from '../../atoms/Button'
import { DetailSection } from './DetailSection'
import { formatRawLine, MAX_ROWS } from './format'

export interface RawLogSectionProps {
  raw: RawLine[]
  /** 처음부터 펼쳐 둘지. 기본은 접힘 — 원문은 길고, 판정에는 ① ② 가 먼저다 */
  defaultOpen?: boolean
  className?: string
}

/** ④ 원문 로그: 판단 근거가 된 원본 줄. 요약이 아니라 원문이다. 비밀번호 원문은 서버가 주지 않는다 */
export function RawLogSection({ raw, defaultOpen = false, className }: RawLogSectionProps) {
  const [open, setOpen] = useState(defaultOpen)
  const listId = useId()
  const shown = raw.slice(0, MAX_ROWS)
  return (
    <DetailSection
      number="④"
      title="원문 로그"
      aside={
        <>
          <span>{raw.length}줄</span>
          {raw.length > 0 && (
            <Button size="sm" aria-expanded={open} aria-controls={listId} onClick={() => setOpen((v) => !v)}>
              {open ? '접기' : '펼치기'}
            </Button>
          )}
        </>
      }
      padding={open && shown.length > 0 ? 'none' : 'md'}
      className={className}
    >
      {raw.length === 0 ? (
        <p className="m-0 text-xs text-ink-muted">이 구간에 이 출발지의 원문 줄이 없습니다.</p>
      ) : !open ? (
        <p className="m-0 text-xs text-ink-muted">접혀 있습니다. 펼치면 시각 · 센서 · 이벤트 · 필드가 한 줄씩 보입니다.</p>
      ) : (
        <>
          <ol id={listId} className="m-0 max-h-[480px] list-none overflow-auto bg-canvas p-3 font-mono text-2xs leading-4 text-ink" aria-label="원문 로그 줄">
            {shown.map((row, i) => (
              <li key={i} className="whitespace-pre-wrap break-all">
                {formatRawLine(row)}
              </li>
            ))}
          </ol>
          {raw.length > MAX_ROWS && (
            <p className="m-0 px-4 py-2 text-xs text-ink-muted">처음 {MAX_ROWS}줄만 보입니다 (전체 {raw.length}줄).</p>
          )}
        </>
      )}
    </DetailSection>
  )
}
