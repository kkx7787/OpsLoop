import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { CtiBadge as CtiBadgeValue } from '@/api/cti'
import { SeverityBadge } from '../atoms/SeverityBadge'
import { VerdictBadge } from '../atoms/VerdictBadge'
import { CTI_BADGE_STALE_TITLE, ctiBadgeText } from './cti-badge-format'
import { CtiBadge } from './CtiBadge'

const badge = (extra: Partial<CtiBadgeValue> = {}): CtiBadgeValue => ({ cves: 2, kev: 1, applicability: 'affected', stale: false, ...extra })

describe('CVE 배지 글(#52)', () => {
  it('CVE · KEV · 적용 요약을 한 줄로, KEV 0 은 뺀다', () => {
    expect(ctiBadgeText(badge())).toBe('CVE 2 · KEV 1 · 자산 해당')
    expect(ctiBadgeText(badge({ kev: 0, applicability: 'not_affected' }))).toBe('CVE 2')
    expect(ctiBadgeText(badge({ cves: 1200, kev: 3, applicability: 'unknown' }))).toBe('CVE 1,200 · KEV 3 · 자산 미확인')
  })

  it('CVE 가 없으면 0 대신 없음이라 적는다', () => {
    expect(ctiBadgeText(badge({ cves: 0, kev: 0, applicability: 'unknown' }))).toBe('CVE 없음 · 자산 미확인')
  })

  it('모르는 적용 값은 미확인으로 적는다(비해당으로 꾸미지 않는다)', () => {
    expect(ctiBadgeText(badge({ applicability: 'maybe' as CtiBadgeValue['applicability'] }))).toBe('CVE 2 · KEV 1 · 자산 미확인')
  })
})

describe('CtiBadge', () => {
  it('정보 색 · 둥근 테두리로 판정값 · 심각도 배지와 색 · 모양이 다르다', () => {
    render(
      <>
        <CtiBadge badge={badge()} />
        <SeverityBadge severity="high" />
        <VerdictBadge verdict="threat" />
      </>,
    )
    const el = screen.getByText('CVE 2 · KEV 1 · 자산 해당')
    expect(el).toHaveAttribute('data-cti-badge')
    expect(el).toHaveAttribute('data-applicability', 'affected')
    expect(el).toHaveClass('bg-primary-soft', 'text-primary', 'rounded-full')
    for (const other of [screen.getByText('high'), screen.getByText('실제 위협')]) {
      expect(other).not.toHaveClass('bg-primary-soft')
      expect(other).not.toHaveClass('rounded-full')
    }
  })

  it('오래된 공개 정보는 말풍선과 낭독 글로 알린다', () => {
    render(<CtiBadge badge={badge({ applicability: 'unknown', stale: true })} />)
    const el = screen.getByTitle(CTI_BADGE_STALE_TITLE)
    expect(CTI_BADGE_STALE_TITLE).toBe('공개 정보 48시간 넘음 · 우리 자산 해당 여부를 확정하지 않음')
    expect(el).toHaveTextContent('CVE 2 · KEV 1 · 자산 미확인 · 공개 정보 48시간 넘음')
    expect(el).toHaveAttribute('data-stale', 'true')
  })

  it('비해당은 배지 글에서 빼고 말풍선으로 풀어 쓴다', () => {
    render(<CtiBadge badge={badge({ applicability: 'not_affected' })} />)
    const el = screen.getByText('CVE 2 · KEV 1')
    expect(el.getAttribute('title')).toMatch(/^우리 자산\(제품 · 판\)에는 해당하지 않음 · /)
    expect(el).toHaveAttribute('data-applicability', 'not_affected')
  })

  it('신선하면 오래됨 글이 없다', () => {
    render(<CtiBadge badge={badge()} />)
    expect(screen.getByText('CVE 2 · KEV 1 · 자산 해당')).not.toHaveAttribute('data-stale')
    expect(screen.queryByTitle(CTI_BADGE_STALE_TITLE)).toBeNull()
  })
})
