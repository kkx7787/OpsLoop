import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { expect, it } from 'vitest'
import { expectInertDom, HOSTILE } from '@/test/hostile-fixtures'
import { DeliverySubject } from './DeliverySubject'

it('사건 통보를 원 사건에 연결하고 원래 키도 확인할 수 있다', () => {
  const key = 'R102|w2|203.0.113.10|2026-10-03T00:00:00+00:00'
  render(<MemoryRouter><DeliverySubject delivery={{ event: 'incident.created', subject_key: key }} /></MemoryRouter>)
  expect(screen.getByRole('link', { name: 'R102 · 사건 보기 →' })).toHaveAttribute('href', `/incidents/${encodeURIComponent(key)}`)
  expect(screen.getByText(key)).toBeInTheDocument()
})

it('노드 경고는 수집 상태로 연결하고 원래 키를 남긴다', () => {
  const key = 'node:web-01@2026-10-03T00:00:00Z'
  render(<MemoryRouter><DeliverySubject delivery={{ event: 'node.silent', subject_key: key }} /></MemoryRouter>)
  expect(screen.getByRole('link')).toHaveAttribute('href', '/nodes')
  expect(screen.getByText(key)).toBeInTheDocument()
})

it('모르는 키나 악성 문자열은 링크로 추측하지 않는다', () => {
  const { container } = render(<MemoryRouter><DeliverySubject delivery={{ event: 'node.silent', subject_key: `node:${HOSTILE.img}@now` }} /></MemoryRouter>)
  expect(screen.queryByRole('link')).toBeNull()
  expectInertDom(container)
})
