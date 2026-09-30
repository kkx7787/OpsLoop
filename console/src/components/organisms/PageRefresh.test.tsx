import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { PageRefreshContext, type PageRefreshSlot } from '@/api/page-refresh'
import { PageHeader } from '../molecules/PageHeader'
import { PageRefresh } from './PageRefresh'

const NOW = Date.parse('2026-09-30T05:00:10Z')
const part = { dataUpdatedAt: NOW - 5_000, errorUpdatedAt: 0, isError: false, asOf: '2026-09-30T05:00:05Z' }

function wrap(client: QueryClient, slot: PageRefreshSlot | null = null) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <PageRefreshContext.Provider value={slot}>{children}</PageRefreshContext.Provider>
    </QueryClientProvider>
  )
}

describe('PageRefresh(#79)', () => {
  it('제목 줄 오른쪽 끝에 기준 시각 + 새로고침. 누르면 모든 조회를 무효로 하고 끝날 때까지 잠근다', async () => {
    const client = new QueryClient()
    let finish: () => void = () => {}
    const invalidate = vi.spyOn(client, 'invalidateQueries').mockImplementation(() => new Promise<void>((resolve) => (finish = resolve)))
    render(<PageHeader title="관제 현황" aside={<button type="button">일시정지</button>} status={<PageRefresh parts={[part]} now={NOW} />} />, {
      wrapper: wrap(client),
    })
    const status = document.querySelector('[data-page-status]') as HTMLElement
    expect(status).toHaveTextContent(/^기준 14:00:05$/)
    // 좁은 폭에서도 제목 줄(첫 줄)에 남고, 넓은 폭에서는 aside 뒤 맨 오른쪽이다
    expect(status).toHaveClass('row-start-1', 'col-start-2', 'md:col-start-3')
    const button = screen.getByRole('button', { name: '새로고침' })
    expect(status).toContainElement(button)
    // Tab 순서는 넓은 폭에서 보이는 순서와 같다: aside 단추 → 새로고침(맨 오른쪽)
    expect(screen.getByRole('button', { name: '일시정지' }).compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // 낭독 칸은 켠 화면(대시보드)만 둔다
    expect(document.querySelector('[aria-live]')).toBeNull()
    fireEvent.click(button)
    expect(invalidate).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenCalledWith()
    expect(button).toHaveAttribute('aria-disabled', 'true')
    await act(async () => finish())
    expect(button).not.toHaveAttribute('aria-disabled', 'true')
  })

  it('announce 면 낭독 칸을 늘 두고 갱신 실패 · 일부 갱신 실패일 때만 글을 넣는다(기준 시각 · 나이는 넣지 않는다)', () => {
    const client = new QueryClient()
    const { rerender } = render(<PageRefresh parts={[part]} now={NOW} announce />, { wrapper: wrap(client) })
    const live = screen.getByRole('status')
    expect(live).toHaveAttribute('aria-live', 'polite')
    expect(live).toHaveClass('sr-only')
    expect(live).toBeEmptyDOMElement()
    rerender(<PageRefresh parts={[part, { ...part, errorUpdatedAt: NOW }]} now={NOW} announce />)
    expect(screen.getByRole('status')).toBe(live)
    expect(live).toHaveTextContent(/^일부 갱신 실패$/)
    rerender(<PageRefresh parts={[{ ...part, isError: true }]} now={NOW} announce />)
    expect(live).toHaveTextContent(/^갱신 실패$/)
    // 오래되기만 한 것(n분 전 기준)은 읽지 않는다
    rerender(<PageRefresh parts={[{ ...part, dataUpdatedAt: NOW - 600_000 }]} now={NOW} announce />)
    expect(document.querySelector('[data-as-of-warning]')).toHaveTextContent('10분 전 기준')
    expect(live).toBeEmptyDOMElement()
  })

  it('그려져 있는 동안 틀에 알려 상단바 새로고침을 숨기게 하고, 사라지면 돌려준다', () => {
    const release = vi.fn<() => void>()
    const claim = vi.fn<() => () => void>(() => release)
    const { unmount } = render(<PageRefresh parts={[part]} now={NOW} />, { wrapper: wrap(new QueryClient(), { claim }) })
    expect(claim).toHaveBeenCalledTimes(1)
    expect(release).not.toHaveBeenCalled()
    unmount()
    expect(release).toHaveBeenCalledTimes(1)
  })
})
