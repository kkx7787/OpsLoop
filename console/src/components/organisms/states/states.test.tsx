import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/api/errors'
import { ApiErrorState } from './ApiErrorState'
import { EmptyState } from './EmptyState'
import { ForbiddenState } from './ForbiddenState'
import { LoadingState } from './LoadingState'
import { NotFoundState } from './NotFoundState'
import { SessionExpiredState } from './SessionExpiredState'

describe('상태 화면', () => {
  it('404: 제목 · 찾지 못한 주소 · 대시보드 링크', () => {
    render(<NotFoundState path="/nowhere" />)
    expect(screen.getByRole('heading', { name: '페이지를 찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByText('/nowhere')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '대시보드로' })).toHaveAttribute('href', '/')
  })

  it('page 크기는 제목을 크게 · 아이콘 칸을 보인다', () => {
    const { container } = render(<NotFoundState size="page" titleAs="h1" />)
    expect(screen.getByRole('heading', { level: 1 })).toHaveClass('text-2xl')
    expect(container.querySelector('svg')).not.toBeNull()
  })

  it('403: 필요한 역할과 현재 역할 · 돌아가기', () => {
    const onBack = vi.fn<() => void>()
    render(<ForbiddenState requiredRoles="admin" currentRole="operator" onBack={onBack} />)
    expect(screen.getByRole('heading', { name: '이 동작은 admin 만 할 수 있습니다' })).toBeInTheDocument()
    expect(screen.getByText(/현재 역할 operator/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '돌아가기' }))
    expect(onBack).toHaveBeenCalledTimes(1)
  })

  it('세션 만료: 지금 경로를 next 로 붙인 로그인 링크', () => {
    window.history.replaceState(null, '', '/audit')
    render(<SessionExpiredState />)
    expect(screen.getByRole('link', { name: '로그인' })).toHaveAttribute('href', '/login?next=%2Faudit')
    window.history.replaceState(null, '', '/')
  })

  it('불러오는 중은 status 로 알린다', () => {
    render(<LoadingState title="이전 결과를 유지한 채 조회합니다" />)
    const status = screen.getByRole('status')
    expect(status).toHaveAttribute('aria-busy', 'true')
    expect(status).toHaveAccessibleName('이전 결과를 유지한 채 조회합니다')
  })

  it('0건: 동작 단추를 함께 보인다', () => {
    render(<EmptyState title="조건에 맞는 인시던트가 없습니다" actions={<button type="button">조건 초기화</button>} />)
    expect(screen.getByRole('heading', { name: '조건에 맞는 인시던트가 없습니다' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '조건 초기화' })).toBeInTheDocument()
  })
})

describe('ApiErrorState', () => {
  it('401 → 세션 만료', () => {
    render(<ApiErrorState error={new ApiError({ status: 401, detail: '인증이 필요합니다' })} />)
    expect(screen.getByRole('heading', { name: '다시 로그인해 주세요' })).toBeInTheDocument()
  })

  it('403 → 권한 밖(서버 설명 포함)', () => {
    render(<ApiErrorState error={new ApiError({ status: 403, detail: '권한이 없습니다 (viewer)' })} />)
    expect(screen.getByRole('heading', { name: '이 화면을 볼 권한이 없습니다' })).toBeInTheDocument()
    expect(screen.getByText(/권한이 없습니다 \(viewer\)/)).toBeInTheDocument()
  })

  it('404 → 없음', () => {
    render(<ApiErrorState error={new ApiError({ status: 404, detail: '인시던트를 찾을 수 없습니다' })} />)
    expect(screen.getByRole('heading', { name: '찾을 수 없습니다' })).toBeInTheDocument()
    expect(screen.getByText('인시던트를 찾을 수 없습니다')).toBeInTheDocument()
  })

  it('5xx · 네트워크 → 오류와 다시 시도', () => {
    const onRetry = vi.fn<() => void>()
    render(<ApiErrorState error={new ApiError({ status: 503, detail: '데이터베이스에 연결할 수 없습니다' })} onRetry={onRetry} />)
    expect(screen.getByRole('alert')).toHaveTextContent('데이터베이스에 연결할 수 없습니다 (HTTP 503)')
    fireEvent.click(screen.getByRole('button', { name: '다시 시도' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('ApiError 가 아니어도 오류 화면', () => {
    render(<ApiErrorState error={new Error('렌더 실패')} />)
    expect(screen.getByRole('heading', { name: '데이터를 불러오지 못했습니다' })).toBeInTheDocument()
    expect(screen.getByText('렌더 실패')).toBeInTheDocument()
  })
})
