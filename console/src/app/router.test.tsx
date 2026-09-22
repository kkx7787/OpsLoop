import { screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderRoutes, stubMe } from '@/test/render'
import { routes } from './router'

describe('경로표', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('없는 주소는 틀 안에서 404 화면: 주소 표시 · 대시보드 링크', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/nowhere?x=1')
    expect(await screen.findByRole('heading', { level: 1, name: '페이지를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByText('/nowhere?x=1')).toBeInTheDocument()
    expect(within(screen.getByRole('main')).getByRole('link', { name: '대시보드로' })).toHaveAttribute('href', '/')
    // 메뉴는 그대로 있어 바로 옮겨 갈 수 있다
    expect(screen.getByRole('navigation', { name: '주 메뉴' })).toBeInTheDocument()
  })

  it('대시보드는 / 에 있고 자리 페이지는 제목 · 화면 번호 · 구현 예정 WBS 를 보인다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/')
    expect(await screen.findByRole('heading', { level: 1, name: '미판정 현황' })).toBeInTheDocument()
    expect(screen.getByText('S-02')).toBeInTheDocument()
    expect(screen.getByText('구현 예정')).toBeInTheDocument()
    expect(screen.getByText('WBS 3.6.4')).toBeInTheDocument()
  })

  it.each([
    ['/incidents', '인시던트', 'S-03'],
    ['/blocklist', '차단 목록', 'S-06'],
    ['/rules', '규칙과 리플레이', 'S-07'],
    ['/sources', '출발지 분석', 'S-09'],
    ['/reports', '보고서', 'S-11'],
    ['/nodes', '수집 노드', 'S-08 · S-13'],
  ])('%s → %s (%s)', async (path, title, code) => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, path)
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.getByText(code)).toBeInTheDocument()
    expect(screen.getByText('구현 예정')).toBeInTheDocument()
  })

  it('인시던트 상세는 키를 제목과 상단바 경로 표시에 보인다', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/incidents/R003%7Cv2%7C1.2.3.4')
    expect(await screen.findByRole('heading', { level: 1, name: 'R003|v2|1.2.3.4' })).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: '현재 위치' })).toHaveTextContent('관제›인시던트›R003|v2|1.2.3.4')
    expect(screen.getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page')
  })

  it('관리 화면은 admin 이 아니면 403 안내(숨기지 않고 이유를 보인다)', async () => {
    stubMe({ username: 'han', role: 'operator' })
    renderRoutes(routes, '/audit')
    expect(await screen.findByRole('heading', { level: 1, name: '감사 기록' })).toBeInTheDocument()
    const main = screen.getByRole('main')
    expect(await within(main).findByRole('heading', { name: '이 화면은 admin 만 볼 수 있습니다' })).toBeInTheDocument()
    expect(within(main).getByText(/현재 역할 operator/)).toBeInTheDocument()
    expect(screen.queryByText('구현 예정')).toBeNull()
  })

  it('admin 은 관리 화면 자리를 본다', async () => {
    stubMe({ username: 'root', role: 'admin' })
    renderRoutes(routes, '/accounts')
    expect(await screen.findByRole('heading', { level: 1, name: '계정' })).toBeInTheDocument()
    expect(await screen.findByText('구현 예정')).toBeInTheDocument()
    expect(screen.getByText('WBS 3.6.8')).toBeInTheDocument()
  })
})
