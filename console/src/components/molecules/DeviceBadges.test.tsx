import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import type { DeviceBasis, IncidentDevice } from '@/api/incidents'
import { expectInertDom, expectMixedRevealed, MIXED } from '@/test/hostile-fixtures'
import { revealHidden } from '@/lib/untrusted'
import { DeviceBadges } from './DeviceBadges'

function device(id: string, extra: Partial<IncidentDevice> = {}): IncidentDevice {
  return { id, part: null, label: id, group: 'protected', logs: [], basis: 'confirmed', ...extra }
}

const WEB = device('web-01', { logs: ['웹 접근'] })
const DECOY = device('aws-sensor', { part: 'decoy', label: '웹 디코이', group: 'sensor', logs: ['웹 요청'] })
const COWRIE_GUESS = device('aws-sensor', { part: 'cowrie', label: 'SSH 허니팟(Cowrie)', group: 'sensor', logs: ['SSH 세션'], basis: 'fallback' })
const DATA_NODE = device('data-node', { label: '데이터 노드', group: 'monitor', logs: ['수집 관문', '원장 가져오기'], basis: 'rule_scope' })
const NODE = device('n-7', { label: 'web02.lab', logs: ['SSH 인증'], basis: 'rule_scope' })

function badgeOf(container: HTMLElement, id: string): HTMLElement {
  const el = container.querySelector<HTMLElement>(`[data-device="${id}"]`)
  if (!el) throw new Error(`${id} 배지 없음`)
  return el
}

describe('DeviceBadges', () => {
  it('이전 서버(devices 없음)면 그리지 않는다', () => {
    const { container } = render(<DeviceBadges source={{}} mode="compact" />)
    expect(container).toBeEmptyDOMElement()
    const full = render(<DeviceBadges source={{ device_fallback: [COWRIE_GUESS] }} mode="full" />)
    expect(full.container).toBeEmptyDOMElement()
  })

  it('compact: 보호 대상 먼저 앞 두 개와 +n, +n 은 낭독 글 외 n대', () => {
    const { container } = render(<DeviceBadges source={{ devices: [DECOY, DATA_NODE, WEB], device_state: 'confirmed' }} mode="compact" />)
    const shown = [...container.querySelectorAll<HTMLElement>('[data-device]')]
    expect(shown.map((el) => el.dataset.device)).toEqual(['web-01', 'aws-sensor'])
    expect(shown[0]).toHaveTextContent('web-01 · 웹 접근')
    expect(shown[0]).toHaveAttribute('data-device-basis', 'confirmed')
    expect(shown[0]).toHaveAttribute('title', 'web-01 · 웹 접근')
    expect(shown[1]).toHaveTextContent('웹 디코이 · 웹 요청')
    expect(shown[1]).toHaveAttribute('data-device-part', 'decoy')
    const more = container.querySelector<HTMLElement>('[data-device-more]')
    expect(more).toHaveTextContent('+1외 1대')
    expect(screen.getByText('+1')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByText('외 1대')).toHaveClass('sr-only')
    expect(more).toHaveAttribute('title', '데이터 노드 · 수집 관문 · 원장 가져오기')
    // 목록 행 · 카드가 통째로 링크라 단추 · ⓘ 가 없다
    expect(container.querySelectorAll('button, a')).toHaveLength(0)
  })

  it('compact: max 만큼 보이고, 넘지 않으면 +n 이 없다', () => {
    const three = render(<DeviceBadges source={{ devices: [WEB, DECOY, DATA_NODE] }} mode="compact" max={1} />)
    expect(three.container.querySelectorAll('[data-device]')).toHaveLength(1)
    expect(three.container.querySelector('[data-device-more]')).toHaveTextContent('+2외 2대')
    three.unmount()
    const two = render(<DeviceBadges source={{ devices: [WEB, DECOY] }} mode="compact" />)
    expect(two.container.querySelectorAll('[data-device]')).toHaveLength(2)
    expect(two.container.querySelector('[data-device-more]')).toBeNull()
  })

  it('보호 대상은 진한 글, 나머지는 흐린 글이다', () => {
    const { container } = render(<DeviceBadges source={{ devices: [WEB, DECOY] }} mode="compact" />)
    expect(badgeOf(container, 'web-01')).toHaveClass('text-ink', 'font-medium')
    expect(badgeOf(container, 'web-01')).not.toHaveClass('text-muted')
    const sensor = badgeOf(container, 'aws-sensor')
    expect(sensor).toHaveClass('text-muted', 'font-normal')
    expect(sensor).not.toHaveClass('text-ink')
  })

  it('compact: 확인과 규칙 범위는 같은 모양이고 근거 글자가 없다', () => {
    const scoped = device('web-01', { logs: ['웹 접근'], basis: 'rule_scope' })
    const a = render(<DeviceBadges source={{ devices: [WEB] }} mode="compact" />)
    const b = render(<DeviceBadges source={{ devices: [scoped] }} mode="compact" />)
    expect(badgeOf(a.container, 'web-01').className).toBe(badgeOf(b.container, 'web-01').className)
    expect(b.container).toHaveTextContent(/^web-01 · 웹 접근$/)
  })

  it('full: 전부 보이고 배지 뒤에 근거 글자를 붙인다', () => {
    const { container } = render(<DeviceBadges source={{ devices: [DATA_NODE, DECOY, NODE, WEB], device_state: 'confirmed' }} mode="full" />)
    expect([...container.querySelectorAll<HTMLElement>('[data-device]')].map((el) => el.dataset.device)).toEqual(['web-01', 'n-7', 'aws-sensor', 'data-node'])
    expect(container.querySelector('[data-device-more]')).toBeNull()
    expect(badgeOf(container, 'web-01').nextElementSibling).toHaveTextContent('확인')
    expect(badgeOf(container, 'n-7').nextElementSibling).toHaveTextContent('규칙 범위')
    expect(badgeOf(container, 'data-node').nextElementSibling).toHaveTextContent('규칙 범위')
    expect(badgeOf(container, 'n-7')).toHaveClass('text-ink')
    expect(container.querySelectorAll('button, a')).toHaveLength(0)
  })

  it('확인 · 규칙 범위가 없으면 점선 장비 미확인 하나이고, 추정 장비 이름은 쓰지 않는다', () => {
    for (const mode of ['compact', 'full'] as const) {
      const { container, unmount } = render(
        <DeviceBadges source={{ devices: [], device_state: 'unconfirmed', device_fallback: [COWRIE_GUESS, device('web-01', { basis: 'fallback' })] }} mode={mode} />,
      )
      const unknown = container.querySelector<HTMLElement>('[data-device-unknown]')
      expect(unknown).toHaveTextContent(/^장비 미확인$/)
      expect(unknown).toHaveClass('border-dashed', 'border-line', 'bg-transparent', 'text-ink-muted')
      expect(unknown).not.toHaveClass('bg-muted-soft')
      expect(container.querySelectorAll('[data-device]')).toHaveLength(0)
      expect(container.querySelector('[data-device-basis="fallback"]')).toBeNull()
      expect(container.innerHTML).not.toContain('Cowrie')
      expect(container.innerHTML).not.toContain('web-01')
      unmount()
    }
  })

  it('서버가 대체 추정이나 모르는 근거를 devices 에 넣어도 확정으로 그리지 않는다', () => {
    const guess = device('web-01', { basis: 'guess' as DeviceBasis })
    const { container } = render(<DeviceBadges source={{ devices: [COWRIE_GUESS, guess] }} mode="compact" />)
    expect(container.querySelector('[data-device-unknown]')).toHaveTextContent('장비 미확인')
    expect(container.querySelectorAll('[data-device]')).toHaveLength(0)
  })

  it('규칙 범위와 대체 추정이 함께면 규칙 범위만 그린다', () => {
    const aws = device('aws-sensor', { label: '허니팟 센서', group: 'sensor', logs: ['세션 기록'], basis: 'rule_scope' })
    const { container } = render(<DeviceBadges source={{ devices: [aws], device_state: 'rule_scope', device_fallback: [COWRIE_GUESS] }} mode="full" />)
    expect(badgeOf(container, 'aws-sensor')).toHaveTextContent('허니팟 센서 · 세션 기록')
    expect(container.querySelector('[data-device-unknown]')).toBeNull()
    expect(container.innerHTML).not.toContain('Cowrie')
  })

  it('비신뢰 hostname 은 글자로만 그리고 숨은 문자를 드러낸다', () => {
    const hostile = device('n-9', { label: MIXED, logs: ['SSH 인증'] })
    for (const mode of ['compact', 'full'] as const) {
      const { container, unmount } = render(<DeviceBadges source={{ devices: [hostile, WEB, DECOY] }} mode={mode} max={1} />)
      expectInertDom(container)
      expectMixedRevealed(container)
      expect(badgeOf(container, 'n-9')).toHaveAttribute('title', revealHidden(`${MIXED} · SSH 인증`))
      unmount()
    }
    // 가려진 장비의 이름은 +n 말풍선에 드러낸 채로 둔다
    const { container } = render(<DeviceBadges source={{ devices: [WEB, hostile, DECOY] }} mode="compact" max={1} />)
    expectInertDom(container)
    expect(container.querySelector('[data-device-more]')).toHaveAttribute('title', `${revealHidden(`${MIXED} · SSH 인증`)}, 웹 디코이 · 웹 요청`)
  })

  it('full · logLinks: 확인된 보호 대상 뒤에만 최근 로그(새 탭) 링크가 있고 인쇄에는 빠진다(#73)', () => {
    const confirmedNode = device('web-02', { label: 'web02.lab', logs: ['SSH 인증'] })
    const scopedWeb = device('web-01', { logs: ['웹 접근'], basis: 'rule_scope' })
    const monitor = device('console', { label: '관제 콘솔', group: 'monitor', logs: ['감사 기록'] })
    const { container } = render(
      <MemoryRouter>
        <DeviceBadges source={{ devices: [DECOY, WEB, NODE, confirmedNode, monitor, device('_unconfirmed', { label: '이상한 값' })] }} mode="full" logLinks />
      </MemoryRouter>,
    )
    const links = screen.getAllByRole('link', { name: '최근 로그 (새 탭)' })
    expect(links.map((a) => a.getAttribute('data-device-logs'))).toEqual(['web-01', 'web-02'])
    expect(links.map((a) => a.getAttribute('href'))).toEqual(['/devices/web-01/logs', '/devices/web-02/logs'])
    for (const link of links) {
      expect(link).toHaveAttribute('target', '_blank')
      expect(link).toHaveAttribute('rel', 'noopener noreferrer')
      expect(link).toHaveClass('print:hidden')
      expect(link.querySelector('.sr-only')).toHaveTextContent('(새 탭)')
    }
    // 링크는 배지 · 근거 글자 뒤에 붙는다
    expect(badgeOf(container, 'web-01').nextElementSibling?.nextElementSibling).toBe(links[0])
    // 규칙 범위 · 센서 · 관제 시스템 · 형식 밖 id 에는 없다
    expect(container.querySelectorAll('[data-device-logs]')).toHaveLength(2)

    // 규칙 범위만 있으면 링크가 없다. compact 는 logLinks 를 줘도 링크를 두지 않는다(행 · 카드가 통째로 링크)
    const scoped = render(
      <MemoryRouter>
        <DeviceBadges source={{ devices: [scopedWeb] }} mode="full" logLinks />
        <DeviceBadges source={{ devices: [WEB] }} mode="compact" logLinks />
      </MemoryRouter>,
    )
    expect(scoped.container.querySelectorAll('a')).toHaveLength(0)
  })

  it('className 을 겉에 합친다', () => {
    const { container } = render(<DeviceBadges source={{ devices: [WEB] }} mode="compact" className="flex-wrap" />)
    expect(container.firstElementChild).toHaveClass('flex', 'flex-wrap', 'min-w-0')
  })
})
