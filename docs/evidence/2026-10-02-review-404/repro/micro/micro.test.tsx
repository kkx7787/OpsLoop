/**
 * 404 시험(router.test.tsx 38-46행)을 쪼개 잰다. 코드 저장소 밖에서 돌리는 조사용 시험이다.
 * findByRole 은 waitFor(getByRole) 이므로 같은 waitFor 에 계측을 끼워 확인 시각 · 확인 1회 비용 · 그때 본문 h1 을 적는다.
 * 첫 시험(냉시동)과 같은 파일의 뒤 시험(데운 뒤)을 같은 방법으로 잰다. 결과는 MICRO_OUT(JSON 줄)에 덧붙인다.
 * MICRO_MODE 로 확인 방법을 바꾼다: role-name(기본, 원래 시험과 같다) · role-noname(이름 조건 없이 역할만) ·
 * role-hidden(hidden: true, 숨김 판정의 계산된 스타일 조회를 건너뛴다) · text(getByText, h1 만)
 */
import { appendFileSync } from 'node:fs'
import { screen, waitFor } from '@testing-library/react'
import { afterEach, it, vi } from 'vitest'
import { routes } from '@/app/router'
import { renderRoutes, stubMe } from '@/test/render'

const TITLE = '페이지를 찾을 수 없습니다'
const OUT = process.env.MICRO_OUT
const MODE = process.env.MICRO_MODE ?? 'role-name'

function find(): HTMLElement {
  if (MODE === 'role-noname') {
    const h = screen.getAllByRole('heading', { level: 1 }).find((e) => e.textContent === TITLE)
    if (!h) throw new Error('없음')
    return h
  }
  if (MODE === 'role-hidden') return screen.getByRole('heading', { level: 1, name: TITLE, hidden: true })
  if (MODE === 'text') return screen.getByText(TITLE, { selector: 'h1' })
  return screen.getByRole('heading', { level: 1, name: TITLE })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

async function measure(label: string) {
  stubMe({ username: 'han', role: 'operator' })
  const checks: { at: number; cost: number; h1: string | null }[] = []
  let headingAt = -1
  const t0 = performance.now()
  renderRoutes(routes, '/nowhere?x=1')
  const renderMs = performance.now() - t0
  const h1AtRender = document.querySelector('main h1')?.textContent ?? null
  // 404 제목이 DOM 에 처음 생긴 시각(싼 조회)
  const mo = new MutationObserver(() => {
    if (headingAt < 0 && document.querySelector('main h1')?.textContent === TITLE) headingAt = performance.now() - t0
  })
  mo.observe(document.body, { subtree: true, childList: true, characterData: true })
  let failed = false
  const w0 = performance.now()
  try {
    await waitFor(() => {
      const s = performance.now()
      const h1 = document.querySelector('main h1')?.textContent ?? null
      try {
        return find()
      } finally {
        checks.push({ at: Math.round(s - t0), cost: +(performance.now() - s).toFixed(1), h1 })
      }
    })
  } catch {
    failed = true
  }
  const waitMs = performance.now() - w0
  mo.disconnect()
  const elements = document.querySelectorAll('*').length
  // 다 그려진 뒤 조회 1회 비용: 역할 + 이름(getByRole) · 글자(getByText)
  const r0 = performance.now()
  if (!failed) screen.getByRole('heading', { level: 1, name: TITLE })
  const roleMs = performance.now() - r0
  const x0 = performance.now()
  if (!failed) screen.getByText(TITLE)
  const textMs = performance.now() - x0
  const row = {
    label,
    mode: MODE,
    pid: process.pid,
    failed,
    render_ms: +renderMs.toFixed(1),
    h1_at_render: h1AtRender,
    heading_in_dom_ms: +headingAt.toFixed(1),
    wait_ms: +waitMs.toFixed(1),
    total_ms: +(performance.now() - t0).toFixed(1),
    checks: checks.length,
    check_cost_sum_ms: +checks.reduce((a, c) => a + c.cost, 0).toFixed(1),
    check_cost_max_ms: Math.max(...checks.map((c) => c.cost)),
    check_log: checks,
    elements,
    getByRole_after_ms: +roleMs.toFixed(1),
    getByText_after_ms: +textMs.toFixed(1),
  }
  if (OUT) appendFileSync(OUT, JSON.stringify(row) + '\n')
}

it('첫 시험(냉시동)', async () => {
  await measure('cold')
})

it('두 번째(데운 뒤)', async () => {
  await measure('warm1')
})

it('세 번째(데운 뒤)', async () => {
  await measure('warm2')
})
