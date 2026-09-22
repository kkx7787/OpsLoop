import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { NAV_GROUPS } from '@/app/nav'
import { SideNav, type SideNavProps } from './SideNav'

function renderAt(path: string, props: Partial<SideNavProps> = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SideNav groups={NAV_GROUPS} userRole="operator" user={{ username: 'han', role: 'operator' }} {...props} />
    </MemoryRouter>,
  )
}

describe('SideNav', () => {
  it('현재 위치만 aria-current=page 로 강조한다(하위 경로 포함)', () => {
    renderAt('/incidents/R003%7Cv2')
    expect(screen.getByRole('link', { name: '인시던트' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: '대시보드' })).not.toHaveAttribute('aria-current')
    expect(screen.getByRole('link', { name: '차단' })).not.toHaveAttribute('aria-current')
  })

  it('대시보드는 / 에서만 현재 위치다', () => {
    renderAt('/')
    expect(screen.getByRole('link', { name: '대시보드' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: '인시던트' })).not.toHaveAttribute('aria-current')
  })

  it('메뉴 묶음은 와이어프레임 순서로 이름이 붙는다', () => {
    renderAt('/')
    const nav = screen.getByRole('navigation', { name: '주 메뉴' })
    expect(within(nav).getAllByRole('group').map((g) => g.getAttribute('aria-labelledby') && within(g).getByText(/^(관제|대응|분석|수집|관리)$/).textContent)).toEqual([
      '관제',
      '대응',
      '분석',
      '수집',
      '관리',
    ])
  })

  it('관리 묶음은 admin 이 아니면 흐리게 두고 누를 수 없다. 숨기지 않는다', () => {
    const { container } = renderAt('/', { userRole: 'operator' })
    const gated = container.querySelectorAll('[data-gated="denied"]')
    expect(gated).toHaveLength(3)
    expect(gated[0]).toHaveAttribute('title', '이 동작(알림 설정)은 admin 만 할 수 있습니다 · 현재 역할 operator')
    expect(gated[2]).toHaveAttribute('title', '이 동작(계정 관리)은 admin 만 할 수 있습니다 · 현재 역할 operator')
    // 링크는 남아 있되 inert 안에 있다
    const accounts = screen.getByRole('link', { name: '계정' })
    expect(accounts.closest('[inert]')).not.toBeNull()
    expect(screen.getByRole('link', { name: '수집 노드' }).closest('[inert]')).toBeNull()
  })

  it('역할을 모르는 동안(불러오는 중)에도 관리 묶음은 막혀 있다', () => {
    const { container } = renderAt('/', { userRole: undefined, user: null })
    expect(container.querySelectorAll('[data-gated="denied"]')).toHaveLength(3)
    expect(screen.getByText('확인 중')).toBeInTheDocument()
  })

  it('admin 이면 관리 묶음도 누를 수 있고 현재 위치가 된다', () => {
    const { container } = renderAt('/accounts', { userRole: 'admin', user: { username: 'root', role: 'admin' } })
    expect(container.querySelector('[data-gated="denied"]')).toBeNull()
    expect(screen.getByRole('link', { name: '계정' })).toHaveAttribute('aria-current', 'page')
  })

  it('아래 칸: 센서 수신 자리 · 사용자 · 역할 · 로그아웃 폼(POST /logout)', () => {
    const { container } = renderAt('/')
    expect(screen.getByText('센서 수신 · 확인 전')).toBeInTheDocument()
    expect(screen.getByText('han')).toBeInTheDocument()
    expect(screen.getByText('operator')).toHaveAttribute('title', '관제사')
    const form = container.querySelector('form[action="/logout"]')
    expect(form).not.toBeNull()
    expect(form).toHaveAttribute('method', 'post')
    expect(within(form as HTMLElement).getByRole('button', { name: '로그아웃' })).toHaveAttribute('type', 'submit')
  })
})
