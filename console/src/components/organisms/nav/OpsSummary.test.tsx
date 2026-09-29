import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import type { MonitorItem } from '@/api/health'
import { expectInertDom, HOSTILE } from '@/test/hostile-fixtures'
import { MONITOR, monitorItem } from '@/test/monitoring-fixtures'
import { OpsSummary, type OpsView } from './OpsSummary'

function renderView(view: OpsView, compact = false) {
  const result = render(
    <MemoryRouter>
      <OpsSummary view={view} compact={compact} />
    </MemoryRouter>,
  )
  return { ...result, link: result.container.querySelector('a') as HTMLAnchorElement }
}

const ok = (alerts: MonitorItem[] = [], unknowns: MonitorItem[] = []): OpsView => ({ state: 'ok', alerts, unknowns })

describe('OpsSummary', () => {
  it.each<[string, OpsView, string, string, string]>([
    ['조회 전', { state: 'pending' }, '관제 상태 조회 전', '관제 —', 'idle'],
    ['조회 실패', { state: 'error' }, '관제 상태 확인 불가', '확인 불가', 'warn'],
    ['이상 있음', ok([MONITOR.loader, MONITOR.mismatch], [MONITOR.nodes]), '관제 이상 2', '이상 2', 'warn'],
    ['모름만', ok([], [MONITOR.heartbeats, MONITOR.nodes]), '관제 상태 일부 미확인', '일부 미확인', 'idle'],
    ['이상 없음', ok(), '관제 이상 없음', '이상 없음', 'idle'],
  ])('%s: 보통 · 짧은 글과 점 색', (_name, view, text, compactText, signal) => {
    const full = renderView(view)
    expect(full.link).toHaveTextContent(text)
    expect(full.link).toHaveAttribute('data-signal', signal)
    expect(full.link.querySelector('[data-signal]')).toHaveAttribute('data-signal', signal)
    full.unmount()

    const compact = renderView(view, true)
    expect(compact.link).toHaveTextContent(compactText)
    expect(compact.link).toHaveAttribute('data-signal', signal)
    compact.unmount()
  })

  it('대시보드로 가는 링크 하나이고, 낭독 이름은 글이다', () => {
    renderView(ok([MONITOR.loader]))
    expect(screen.getByRole('link', { name: '관제 이상 1' })).toHaveAttribute('href', '/')
  })

  it('이상이 있으면 말풍선에 이상 항목 이름을 잇는다. 모름 항목은 넣지 않는다', () => {
    const { link } = renderView(ok([MONITOR.loader, MONITOR.enforcerFw, MONITOR.mismatch], [MONITOR.nodes]))
    expect(link).toHaveAttribute('title', '적재기 · 내부 방화벽 집행기 · 관문 불일치')
    for (const view of [{ state: 'pending' } as const, { state: 'error' } as const, ok(), ok([], [MONITOR.nodes])]) {
      const other = renderView(view)
      expect(other.link).not.toHaveAttribute('title')
      other.unmount()
    }
  })

  it('항목 이름은 서버 글자라 말풍선에서 숨은 문자를 표식으로 바꾼다', () => {
    const { container, link } = renderView(ok([monitorItem({ key: 'loader', label: `${HOSTILE.rlo} ${HOSTILE.decoy}` }), monitorItem({ key: 'x', label: '' })]))
    expectInertDom(container)
    expect(link.getAttribute('title')).toContain('admin⟨U+202E⟩gnp.exe')
    expect(link.getAttribute('title')).toContain('줄1↵2026')
    // 이름이 비면 key 로 대신한다
    expect(link.getAttribute('title')?.endsWith(' · x')).toBe(true)
  })

  it('늘 있는 조각이라 status · alert · aria-live 를 두지 않고, 글 조각이 정확히 "확인 중" 이 되지 않는다', () => {
    const views: OpsView[] = [{ state: 'pending' }, { state: 'error' }, ok([MONITOR.loader]), ok([], [MONITOR.nodes]), ok()]
    for (const view of views) {
      for (const compact of [false, true]) {
        const { container, unmount } = renderView(view, compact)
        expect(container.querySelector('[role], [aria-live]')).toBeNull()
        expect(screen.queryByText('확인 중')).toBeNull()
        unmount()
      }
    }
  })
})
