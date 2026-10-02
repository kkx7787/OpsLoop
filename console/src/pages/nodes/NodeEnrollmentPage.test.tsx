import { screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NodeEnrollmentPage } from './NodeEnrollmentPage'
import { noRetryClient, renderRoutes } from '@/test/render'
import { json } from '@/test/monitoring-fixtures'
import { nodeEntry } from '@/test/operations-fixtures'

function setup(path: string) {
  const rows = [nodeEntry()]
  vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'tester', role: 'admin' })
    if (url.pathname === '/api/nodes') return json({ as_of: rows[0].checked_at, rows })
    return json({}, 404)
  }))
  return renderRoutes([{ path: '/nodes/new', element: <NodeEnrollmentPage /> }], path, noRetryClient())
}
afterEach(() => vi.unstubAllGlobals())

describe('노드 추가', () => {
  it.each(['/nodes/new', '/nodes/new?node=web-01'])('%s 는 발급 전에 내부 방화벽 수집 허용 안내를 접지 않고 보인다(이슈 #94)', async path => {
    setup(path)
    const note = await screen.findByText(/^설치 전에 내부 방화벽의 수집 허용\(이 노드 → 192\.168\.60\.11:3101\)이 먼저 있어야 합니다\./)
    expect(note.textContent).toContain("운영 문서(infra/vmware/README.md)의 '방화벽 설정 올리기 · 되돌리기' 절")
    expect(note.closest('details')).toBeNull()
    expect(note.closest('form')).toContainElement(screen.getByRole('button', { name: /^등록 토큰 (다시 )?발급$/ }))
  })
})
