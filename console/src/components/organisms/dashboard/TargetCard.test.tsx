import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import type { LiveState } from '@/api/live'
import { LiveContext } from '@/api/live-context'
import type { Target } from '@/api/targets'
import { expectInertDom, expectMixedRevealed, HOSTILE, MIXED } from '@/test/hostile-fixtures'
import { hasHidden, revealHidden } from '@/lib/untrusted'
import { awsSensor, consoleTarget, dataNode, dataNodeStopped, LATEST_KEY, minutesAgo, nodeTarget, TARGETS_AS_OF, web01 } from '@/test/targets-fixtures'
import { LABEL_MAX } from './target-format'
import { TargetCard } from './TargetCard'

const AS_OF = Date.parse(TARGETS_AS_OF)
const CONNECTED: LiveState = { status: 'connected', retries: 0, console: 'opsloop-console-a' }

function renderCard(target: Target, options: { live?: LiveState; cti?: Parameters<typeof TargetCard>[0]['cti'] } = {}) {
  const view = render(
    <MemoryRouter>
      <LiveContext.Provider value={options.live ?? CONNECTED}>
        <TargetCard target={target} asOf={AS_OF} cti={options.cti} />
      </LiveContext.Provider>
    </MemoryRouter>,
  )
  // 구역 이름은 대상 이름이다. 표식 · 말줄임이 붙는 악성 이름은 이름 대신 하나뿐인 구역으로 찾는다
  const plain = !hasHidden(target.label) && !target.label.includes('\n') && target.label.length <= LABEL_MAX
  const card = screen.getByRole('region', plain ? { name: target.label } : {})
  /** 구역 한 칸(dt 제목 옆 dd) */
  const row = (title: string) => within(card).getByText(title, { selector: 'dt' }).nextElementSibling as HTMLElement
  return { ...view, card, row }
}

/** 도움말(ⓘ) 단추가 여닫는 설명 상자 */
function tipPanel(button: HTMLElement): HTMLElement {
  const panel = document.getElementById(button.getAttribute('aria-controls') ?? '')
  expect(panel).not.toBeNull()
  return panel as HTMLElement
}

/** 홀로 선 숫자 0. '10분' · '2026' 의 0 은 아니다 */
const ZERO = /(^|[^\d.,:-])0(?![\d.,:%-])/

describe('TargetCard(#52)', () => {
  it.each([
    [awsSensor(), '정상', 'bg-success-soft'],
    [web01(), '요청 없음', 'bg-muted-soft'],
    [consoleTarget(), '생존 상태 미확인', 'bg-muted-soft'],
    [dataNode(), '수신 없음', 'bg-warning-soft'],
  ])('%#: 수집 상태는 글자 배지로 보인다(색만 쓰지 않는다)', (target, label, tone) => {
    const { card } = renderCard(target)
    const badge = within(card).getByText(label)
    expect(badge).toHaveClass(tone)
    expect(card).toHaveAttribute('data-collection', target.collection.state)
    expect(card).toHaveTextContent(target.role)
  })

  it('생존 신호가 있으면 신호 시각을 상대 표기와 기준 시각으로, 로그는 색 없이 옆에 적는다', () => {
    const { card, row } = renderCard(awsSensor())
    const collect = row('수집')
    expect(collect).toHaveTextContent('업로더 생존 신호 3분 전 · 09-28 18:57')
    expect(collect).toHaveTextContent('Cowrie 2분 전 · 웹 디코이 1시간 전 · AWS 관문 기록 없음')
    expect(collect).not.toHaveTextContent('생존 상태 미확인')
    // 정상 판정의 까닭(서버)은 신호 줄 · 배지와 같은 말이라 '수집' 옆 도움말(ⓘ)에만 있고, 수신 없음 기준도 거기 있다
    const tip = within(card).getByRole('button', { name: '수집 상태 설명' })
    expect(tip).toHaveAttribute('aria-expanded', 'false')
    const panel = tipPanel(tip)
    expect(collect).toContainElement(panel)
    expect(panel).toHaveTextContent('15분 넘게 새 신호가 없으면 수신 없음입니다. 업로더 생존 신호 3분 전 · 최근 1시간 로그 있음')
    expect(panel).toContainElement(within(collect).getByText(/최근 1시간 로그 있음/))
    expect(collect.querySelector('[data-signal]')).not.toHaveAttribute('title')
  })

  it('생존 신호가 없는 대상은 마지막 로그 시각을 보이고, 미확인은 배지 한 곳에만 둔다', () => {
    const { card, row } = renderCard(consoleTarget())
    expect(within(card).getByText('생존 상태 미확인')).toHaveAttribute('data-collection-badge')
    expect(row('수집')).toHaveTextContent('마지막 로그 12분 전')
    expect(row('수집')).not.toHaveTextContent('생존 상태 미확인')
    // 미확인의 까닭은 본문에 남는다(도움말로 숨기지 않는다). 신호가 없는 대상이라 도움말 단추도 없다
    expect(row('수집')).toHaveTextContent('생존 신호를 보내지 않음')
    expect(within(card).queryByRole('button', { name: '수집 상태 설명' })).toBeNull()
  })

  it('서버가 정상이라 했는데 생존 신호가 없으면 마지막 로그에 미확인을 붙인다(정상으로 읽히지 않게)', () => {
    const target = awsSensor({ collection: { ...awsSensor().collection, state: 'ok', signal: null } })
    const { card, row } = renderCard(target)
    expect(within(card).getByText('정상')).toHaveAttribute('data-collection-badge')
    expect(row('수집')).toHaveTextContent('마지막 로그 2분 전 · 생존 상태 미확인')
  })

  it('신호 표에 기록이 없으면 신호 없음과 마지막 로그를 함께 보인다', () => {
    const target = awsSensor({ collection: { ...awsSensor().collection, state: 'unknown', reason: '생존 신호 미기록', signal: { label: '업로더 생존 신호', seen_at: null, checked_at: null, stale_after_seconds: 900, problem: '없음' } } })
    const { card, row } = renderCard(target)
    expect(within(card).getByText('생존 상태 미확인')).toHaveAttribute('data-collection-badge')
    expect(row('수집')).toHaveTextContent('업로더 생존 신호 기록 없음')
    expect(row('수집')).toHaveTextContent('마지막 로그 2분 전')
    expect(row('수집')).not.toHaveTextContent('생존 상태 미확인')
    expect(row('수집')).toHaveTextContent('읽기 문제: 없음')
    // 미확인의 까닭은 본문, 도움말에는 수신 없음 기준만 있다
    const panel = tipPanel(within(card).getByRole('button', { name: '수집 상태 설명' }))
    expect(panel).toHaveTextContent('15분 넘게 새 신호가 없으면 수신 없음입니다.')
    expect(panel).not.toHaveTextContent('생존 신호 미기록')
    expect(row('수집')).toHaveTextContent('생존 신호 미기록')
  })

  it('로그가 없는 대상(데이터 노드)은 신호 기록 없음을 적고 로그 줄을 두지 않는다', () => {
    const base = dataNode()
    const target = dataNode({ collection: { ...base.collection, state: 'unknown', reason: '탐지 실행 기록 없음', signal: { ...base.collection.signal!, seen_at: null } } })
    const { card, row } = renderCard(target)
    expect(within(card).getByText('생존 상태 미확인')).toHaveAttribute('data-collection-badge')
    expect(row('수집')).toHaveTextContent('마지막 탐지 실행 기록 없음')
    expect(row('수집')).not.toHaveTextContent('생존 상태 미확인')
    expect(row('수집')).not.toHaveTextContent('로그 기록 없음')
    expect(row('수집')).toHaveTextContent('적재기 확인 1분 전 · 집행기 확인 기록 없음')
  })

  it('데이터 노드가 정상이어도 집행기 확인이 멈췄으면 멈춤은 본문에 남는다(까닭 줄만 도움말로 간다)', () => {
    const base = dataNode()
    const target = dataNode({
      collection: {
        ...base.collection,
        state: 'ok',
        reason: '마지막 탐지 실행 1분 전 · 집행기 확인 중단 · 마지막 12분 전',
        signal: { ...base.collection.signal!, seen_at: minutesAgo(1) },
        extra: [
          { label: '적재기 확인', at: minutesAgo(1), note: null },
          { label: '집행기 확인', at: minutesAgo(12), note: '멈춤' },
        ],
      },
    })
    const { card, row } = renderCard(target)
    const panel = tipPanel(within(card).getByRole('button', { name: '수집 상태 설명' }))
    expect(panel).toHaveTextContent('집행기 확인 중단 · 마지막 12분 전')
    // 도움말 상자는 수집 칸 안에 있으므로, 상자에 없는 '(멈춤)' 이 칸에 보이면 본문이다
    expect(row('수집')).toHaveTextContent('적재기 확인 1분 전 · 집행기 확인 12분 전 (멈춤)')
    expect(panel).not.toHaveTextContent('(멈춤)')
  })

  it('서버가 수신 없음으로 판정한 대상에는 미확인을 덧붙이지 않고 까닭은 본문에 둔다', () => {
    const base = awsSensor()
    const target = awsSensor({ collection: { ...base.collection, state: 'no_signal', reason: '업로더 생존 신호 없음', signal: { ...base.collection.signal!, seen_at: null } } })
    const { card, row } = renderCard(target)
    expect(within(card).getByText('수신 없음')).toHaveClass('bg-warning-soft')
    expect(row('수집')).toHaveTextContent('업로더 생존 신호 기록 없음')
    expect(row('수집')).toHaveTextContent('마지막 로그 2분 전')
    expect(row('수집')).not.toHaveTextContent('생존 상태 미확인')
    expect(tipPanel(within(card).getByRole('button', { name: '수집 상태 설명' }))).not.toHaveTextContent('업로더 생존 신호 없음')
    expect(row('수집')).toHaveTextContent('업로더 생존 신호 없음')
  })

  it('콘솔 카드의 현재 콘솔은 실시간 연결(hello)의 이름이다', () => {
    const { row, unmount } = renderCard(consoleTarget(), { live: { status: 'connected', retries: 0, console: 'opsloop-console-b' } })
    expect(row('수집')).toHaveTextContent('실시간 연결: 콘솔 B')
    unmount()

    const again = renderCard(consoleTarget(), { live: { status: 'reconnecting', retries: 1, console: 'opsloop-console-a' } })
    expect(again.row('수집')).toHaveTextContent('실시간 연결: 콘솔 A (끊김 · 마지막 연결)')
    again.unmount()

    const none = renderCard(consoleTarget(), { live: { status: 'connecting', retries: 0 } })
    expect(none.row('수집')).toHaveTextContent('실시간 연결 없음')
  })

  it('정해 두지 않은 콘솔 이름은 원문을 표식으로 보인다', () => {
    const { row } = renderCard(consoleTarget(), { live: { status: 'connected', retries: 0, console: HOSTILE.rlo } })
    expect(row('수집')).toHaveTextContent('실시간 연결: admin⟨U+202E⟩gnp.exe')
  })

  it('콘솔이 아닌 카드에는 실시간 연결 줄이 없다', () => {
    const { card } = renderCard(web01())
    expect(card).not.toHaveTextContent('실시간 연결')
  })

  it('보안은 최근 1시간 신규 · 높음 이상 · 미판정, AWS 센서는 발생원별 수를 붙인다', () => {
    const { row } = renderCard(awsSensor())
    expect(row('보안')).toHaveTextContent('최근 1시간 신규 4 · 높음 이상 1 · 미판정 12')
    expect(row('보안')).toHaveTextContent('Cowrie 3 · 웹 디코이 1 · AWS 관문 0')
    expect(within(row('보안')).getByTitle('Cowrie 미판정 10 · 웹 디코이 미판정 2 · AWS 관문 미판정 0')).toBeInTheDocument()
  })

  it('미판정 N 은 그 장비의 미판정 목록(판정 전 · 장비 조건, 기간 없음)으로 잇고 글자는 그대로다(#72)', () => {
    const { row } = renderCard(awsSensor())
    const link = within(row('보안')).getByRole('link', { name: '미판정 12' })
    expect(link).toHaveAttribute('href', '/incidents?judged=false&device=aws-sensor')
    expect(row('보안').firstElementChild).toHaveTextContent(/^최근 1시간 신규 4 · 높음 이상 1 · 미판정 12$/)
  })

  it('미판정 0 은 링크 없이 글만(Q18), 등록 노드는 자기 id 로 잇는다', () => {
    const web = renderCard(web01())
    expect(within(web.row('보안')).queryByRole('link')).toBeNull()
    expect(web.row('보안')).toHaveTextContent('최근 1시간 신규 0 · 높음 이상 0 · 미판정 0')
    web.unmount()
    const node = renderCard(nodeTarget('web-02'))
    expect(within(node.row('보안')).getByRole('link', { name: '미판정 3' })).toHaveAttribute('href', '/incidents?judged=false&device=web-02')
  })

  it('보호 대상(web-01 · 등록 노드) 카드에만 맨 아래 사건 보기 · 최근 로그 한 줄이 있고 인쇄에는 빠진다(#73)', () => {
    for (const [target, id] of [[web01(), 'web-01'], [nodeTarget('web-02'), 'web-02']] as const) {
      const { card, unmount } = renderCard(target)
      const links = card.querySelector<HTMLElement>('[data-device-links]') as HTMLElement
      expect(links).toHaveClass('print:hidden')
      expect(card.lastElementChild).toBe(links)
      expect(within(links).getByRole('link', { name: '사건 보기' })).toHaveAttribute('href', `/incidents?device=${id}`)
      expect(within(links).getByRole('link', { name: '최근 로그' })).toHaveAttribute('href', `/devices/${id}/logs`)
      expect(within(links).getByRole('link', { name: '최근 로그' })).not.toHaveAttribute('target')
      unmount()
    }
    for (const target of [awsSensor(), consoleTarget(), dataNode()]) {
      const { card, unmount } = renderCard(target)
      expect(card.querySelector('[data-device-links]')).toBeNull()
      expect(within(card).queryByRole('link', { name: '최근 로그' })).toBeNull()
      unmount()
    }
    // 모바일에서 펼친 카드(inline)에도 같은 줄이 있다
    render(
      <MemoryRouter>
        <LiveContext.Provider value={CONNECTED}>
          <TargetCard target={web01()} asOf={AS_OF} variant="inline" />
        </LiveContext.Provider>
      </MemoryRouter>,
    )
    expect(screen.getByRole('link', { name: '최근 로그' })).toHaveAttribute('href', '/devices/web-01/logs')
  })

  it('데이터 노드 확인이 멈추면 머리 배지는 주의(주의색)이고 data-collection 은 서버 값(ok) 그대로다(#72)', () => {
    const { card } = renderCard(dataNodeStopped())
    const badge = card.querySelector('[data-collection-badge]')
    expect(badge).toHaveTextContent('주의')
    expect(badge).toHaveClass('bg-warning-soft')
    expect(card).toHaveAttribute('data-collection', 'ok')
    expect(within(card).queryByText('정상')).toBeNull()
  })

  it('넓은 카드(컨테이너 56rem 이상)는 두 단(수집 · 보안 · 최근 사건 | 시스템 · 대응 · 취약점)이고 인쇄는 한 단이다', () => {
    const { card, row } = renderCard(web01())
    expect(card).toHaveClass('@container', 'print:[container-type:normal]')
    const dl = card.querySelector('dl') as HTMLElement
    expect(dl).toHaveClass('flex', 'flex-col', '@4xl:grid', '@4xl:grid-flow-col', '@4xl:grid-cols-2', '@4xl:grid-rows-[repeat(3,auto)]')
    const cells = ['수집', '보안', '최근 사건', '시스템', '대응', '취약점'].map((title) => row(title).parentElement as HTMLElement)
    expect(cells.every((cell) => cell.parentElement === dl)).toBe(true)
    // 둘째 단 첫 칸(시스템)은 위 선 대신 왼쪽 선이다
    expect(cells[0]).not.toHaveClass('border-t')
    expect(cells[3]).toHaveClass('border-t', '@4xl:border-t-0', '@4xl:border-l')
    expect(cells[5]).toHaveClass('@4xl:border-l')
    expect(cells[2]).not.toHaveClass('@4xl:border-l')
  })

  it('최근 사건 한 줄은 상세로 잇고 심각도 · 규칙 · 출발지 · 시각 · CVE 배지를 보인다', () => {
    const { row } = renderCard(awsSensor(), { cti: { cves: 3, kev: 1, applicability: 'unknown', stale: false } })
    const link = within(row('최근 사건')).getByRole('link')
    expect(link).toHaveAttribute('href', `/incidents/${encodeURIComponent(LATEST_KEY)}`)
    expect(link).toHaveTextContent('high')
    expect(link).toHaveTextContent('R105')
    expect(link).toHaveTextContent('제품 식별 탐색')
    expect(link).toHaveTextContent('203.0.113.7 · 20분 전 · 미판정 CVE 3 · KEV 1 · 자산 미확인')
    expect(within(link).getByText('CVE 3 · KEV 1 · 자산 미확인')).toHaveAttribute('data-cti-badge')
  })

  it('최근 사건이 없으면 그렇게 적는다', () => {
    const { row } = renderCard(web01())
    expect(row('최근 사건')).toHaveTextContent('최근 24시간 사건 없음')
  })

  it('시스템: web-01 만 수치, 나머지는 미수집 · 권한 없음 · 없음을 글로', () => {
    expect(renderCard(web01()).row('시스템')).toHaveTextContent('CPU 12% · 메모리 42% · 디스크 63% · 1분 전')
  })

  it.each([
    ['not_collected', '자원 지표 미수집'],
    ['no_privilege', '자원 지표 읽기 권한 없음'],
    ['no_data', '자원 지표 없음'],
  ] as const)('시스템 %s → %s', (state, text) => {
    const { row } = renderCard(awsSensor({ system: { state, metrics: null } }))
    expect(row('시스템')).toHaveTextContent(text)
    expect(row('시스템')).not.toHaveTextContent('%')
  })

  it('오래된 자원 지표는 수치에 오래됨을 붙인다', () => {
    const { row } = renderCard(web01({ system: { state: 'stale', metrics: { ts: minutesAgo(30), cpu_pct: 5, mem_used_pct: 10, disk_root_pct: 20, load1: null } } }))
    expect(row('시스템')).toHaveTextContent('CPU 5% · 메모리 10% · 디스크 20% · 30분 전 오래됨')
  })

  it('대응: 적용 확인(초록) · 미확인 · 정책상 제외, 차단 목록으로 잇고 정상 보고 시각은 도움말에 둔다', () => {
    const { card, row } = renderCard(awsSensor())
    const response = row('대응')
    expect(within(response).getByText('차단 적용 2 (AWS 관문)')).toHaveClass('bg-success-soft')
    expect(within(response).getByText('차단 적용 여부 미확인 1')).toHaveClass('bg-warning-soft')
    expect(within(response).getByText('정책상 차단 제외 3')).toBeInTheDocument()
    expect(within(response).getByRole('link')).toHaveAttribute('href', '/blocklist')
    const panel = tipPanel(within(card).getByRole('button', { name: '집행 지점 보고 설명' }))
    expect(response).toContainElement(panel)
    expect(panel).toHaveTextContent('AWS 관문 보고 2분 전')
    expect(panel).toContainElement(response.querySelector('[data-report]') as HTMLElement)
  })

  it('대응: 지점 보고 문제는 본문 줄로 남고 도움말 단추는 두지 않는다', () => {
    const { card, row } = renderCard(web01())
    expect(row('대응').querySelector('[data-report]')).toHaveTextContent('내부 방화벽 보고: 보고 파일 없음')
    expect(within(card).queryByRole('button', { name: '집행 지점 보고 설명' })).toBeNull()
  })

  it('대응: 지점이 거부한 차단은 빨간 실패, 집행기 확인이 멈추면 초록 대신 미확인과 까닭(주의색)', () => {
    const failed = renderCard(web01({ response: { ...web01().response, applied: 1, failed: 2 } }))
    expect(within(failed.row('대응')).getByText('차단 적용 실패 2 (내부 방화벽)')).toHaveClass('bg-danger-soft')
    failed.unmount()
    const { card, row } = renderCard(awsSensor({ response: { ...awsSensor().response, applied: 0, failed: 0, unverified: 3, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' } }))
    const response = row('대응')
    expect(within(response).queryByText(/차단 적용 \d+ \(/)).not.toBeInTheDocument()
    expect(within(response).getByText('차단 적용 여부 미확인 3')).toHaveClass('bg-warning-soft')
    expect(within(response).getByText('집행기 확인 중단 · 마지막 확인 12분 전')).toHaveClass('text-warning')
    // 멈춤 경고는 도움말(정상 보고 시각) 뒤로 숨지 않는다
    expect(tipPanel(within(card).getByRole('button', { name: '집행 지점 보고 설명' }))).not.toHaveTextContent('집행기 확인 중단')
  })

  it.each([
    ['web-01(모두 0)', web01(), ['내부 방화벽 집행 대상 차단 없음', '내부 방화벽 보고: 보고 파일 없음']],
    ['콘솔(지점 없음)', consoleTarget(), ['차단 적용 여부 미확인']],
    ['데이터 노드(지점 없음 · 제외 있음)', dataNode({ response: { ...dataNode().response, exempt: 2 } }), ['차단 적용 여부 미확인', '정책상 차단 제외 2']],
  ])('대응 구역에 숫자 0 을 그리지 않는다: %s', (_name, target, expected) => {
    const { row } = renderCard(target)
    const response = row('대응')
    for (const text of expected) expect(response).toHaveTextContent(text)
    expect(response.textContent ?? '').not.toMatch(ZERO)
  })

  it('취약점: 자산마다 수 · KEV · 조사 시각을 자산 화면으로 잇고, 없음 · 대조 전 · 오래됨을 0 으로 꾸미지 않는다', () => {
    const aws = renderCard(awsSensor())
    const vulns = aws.row('취약점')
    expect(within(vulns).getByRole('link', { name: /honeypot-dmz/ })).toHaveAttribute('href', '/inventory?asset=honeypot-dmz')
    expect(vulns).toHaveTextContent('honeypot-dmz 수정판 있음 6 · 재부팅 대기 1 · 수정 여부 미확인 3 · KEV 1 · 조사 3시간 전')
    expect(vulns).toHaveTextContent('gateway 자산 정보 없음')
    aws.unmount()

    const console = renderCard(consoleTarget()).row('취약점')
    expect(console).toHaveTextContent('console-b 취약점 대조 전')
    expect(console).not.toHaveTextContent('console-b 취약점 0')

    const web = renderCard(web01()).row('취약점')
    expect(web).toHaveTextContent('web-01 수정판 있음 12 · 재부팅 대기 0 · 수정 여부 미확인 4 · KEV 0')
    expect(within(web).getByText('오래됨')).toHaveClass('bg-warning-soft')
  })

  it('CTI 표가 없으면 취약점 정보 없음', () => {
    const { row } = renderCard(dataNode({ vulns: { available: false, assets: [] } }))
    expect(row('취약점')).toHaveTextContent('취약점 정보 없음')
  })

  it('비신뢰 문자열(규칙 이름 · 대상 · 읽기 문제)은 표식으로 보이고 링크 안에 단추를 두지 않는다', () => {
    const base = awsSensor()
    const target = awsSensor({
      collection: { ...base.collection, reason: `까닭 ${MIXED}`, signal: { ...base.collection.signal!, problem: MIXED } },
      security: { ...base.security, latest: { ...base.security.latest!, rule_name: MIXED, actor_ip: null, target: `user:${MIXED}` } },
    })
    const { container, row } = renderCard(target)
    expectInertDom(container)
    expectMixedRevealed(container)
    expect(within(row('최근 사건')).getByRole('link').querySelector('button')).toBeNull()
  })
})

describe('TargetCard · 등록 노드(#64)', () => {
  it('web-01 카드와 같은 틀: 이름(hostname) · 역할 옆 node_id · 노드 수신 · 보안 · 최근 사건', () => {
    const { card, row } = renderCard(nodeTarget('web-02'), { cti: { cves: 1, kev: 0, applicability: 'unknown', stale: false } })
    expect(card).toHaveAttribute('data-target', 'web-02')
    expect(card).toHaveAttribute('data-target-kind', 'node')
    expect(within(card).getByRole('heading', { level: 3 })).toHaveTextContent('opsloop-web-02')
    expect(within(card).getByText('등록 노드', { exact: false })).toHaveTextContent('등록 노드 · web-02')
    expect(within(card).getByText('정상')).toHaveClass('bg-success-soft')
    expect(row('수집')).toHaveTextContent('노드 수신 2분 전')
    expect(row('수집')).toHaveTextContent('opsloop-web-02 로그 3분 전')
    expect(row('수집')).toHaveTextContent('마지막 적재 2분 전')
    expect(row('보안')).toHaveTextContent('최근 1시간 신규 2 · 높음 이상 1 · 미판정 3')
    const link = within(row('최근 사건')).getByRole('link')
    expect(link).toHaveAttribute('href', `/incidents/${encodeURIComponent('R101|v3|198.51.100.9|web-02')}`)
    expect(link).toHaveTextContent('198.51.100.9 · 5분 전 · 미판정 CVE 1 · 자산 미확인')
    // 콘솔 카드만 실시간 연결 줄을 둔다
    expect(card).not.toHaveTextContent('실시간 연결')
  })

  it('실시간 연결 줄은 고정 콘솔 카드에만 둔다(같은 id 의 등록 노드가 와도)', () => {
    const { card } = renderCard(nodeTarget('console'))
    expect(card).toHaveAttribute('data-target-kind', 'node')
    expect(card).not.toHaveTextContent('실시간 연결')
  })

  it('지표가 없으면 미수집, 집행 지점이 없으면 숫자 없는 미확인, 같은 이름의 자산이 없으면 연결된 자산 없음', () => {
    // targets.py vulns_block: 등록 노드는 asset_id = node_id 인 자산이 있을 때만 잇고 없으면 assets 가 빈 목록이다(표본 기본값)
    const { row } = renderCard(nodeTarget('web-02'))
    expect(row('시스템')).toHaveTextContent('자원 지표 미수집')
    expect(row('대응')).toHaveTextContent('차단 적용 여부 미확인')
    expect(row('대응').textContent ?? '').not.toMatch(ZERO)
    expect(row('대응').querySelector('[data-report]')).toBeNull()
    expect(row('취약점')).toHaveTextContent('연결된 자산 없음')
    expect(row('취약점').textContent ?? '').not.toMatch(ZERO)
    expect(within(row('취약점')).queryByRole('link')).toBeNull()
  })

  it('같은 이름의 자산이 있으면 web-01 처럼 수 · KEV 를 자산 화면으로 잇는다', () => {
    const asset = { asset_id: 'web-07', vuln_total: 4, vuln_kev: 1, collected_at: minutesAgo(60), checked_at: minutesAgo(50), stale: false, missing: false }
    const { row } = renderCard(nodeTarget('web-07', { vulns: { available: true, assets: [asset] } }))
    expect(row('취약점')).toHaveTextContent('web-07 취약점 4 · KEV 1 · 조사 1시간 전')
    expect(within(row('취약점')).getByRole('link', { name: /web-07/ })).toHaveAttribute('href', '/inventory?asset=web-07')
  })

  it('수신 전 등록 노드: 마지막 로그 말풍선의 로그 이름(hostname 에서 온다)도 표식으로 보인다', () => {
    const label = `${HOSTILE.rlo}${HOSTILE.zwsp}`
    const base = nodeTarget('web-08', { label })
    const signal = { label: '노드 수신', seen_at: null, checked_at: null, stale_after_seconds: 600, problem: null }
    const logs = [{ key: 'web-08', label: `${label} 로그`, last_at: minutesAgo(30) }]
    const { container, row } = renderCard({ ...base, collection: { ...base.collection, state: 'no_signal', reason: '노드 수신 기록 없음 · 등록 뒤 10분 넘게 수신 없음', signal, logs } })
    expectInertDom(container)
    const line = row('수집').querySelector('[data-signal="none"][title]')
    expect(line).toHaveTextContent('마지막 로그 30분 전')
    expect(line).toHaveAttribute('title', `${revealHidden(label)} 로그 기준`)
    expect(line?.getAttribute('title')).not.toMatch(/[\u202E\u200B]/u)
  })

  it('지표를 보내는 노드는 web-01 처럼 수치 한 줄', () => {
    const { row } = renderCard(nodeTarget('web-03', { system: { state: 'ok', metrics: { ts: minutesAgo(1), cpu_pct: 7, mem_used_pct: 33.4, disk_root_pct: 51, load1: 0.1 } } }))
    expect(row('시스템')).toHaveTextContent('CPU 7% · 메모리 33% · 디스크 51% · 1분 전')
  })

  it('hostname 이 없어 이름이 node_id 면 역할 옆에 다시 적지 않는다', () => {
    const { card } = renderCard(nodeTarget('web-04', { label: 'web-04' }))
    expect(card.querySelector('[data-node-id]')).toBeNull()
    expect(within(card).getByText('등록 노드')).toBeInTheDocument()
  })

  it('kind 가 없는 응답도 고정 네 값이 아닌 id 는 등록 노드로 읽는다', () => {
    const { card } = renderCard(nodeTarget('web-05', { kind: undefined }))
    expect(card).toHaveAttribute('data-target-kind', 'node')
    expect(card.querySelector('[data-node-id]')).toHaveTextContent('web-05')
    const fixed = renderCard(web01())
    expect(fixed.card).toHaveAttribute('data-target-kind', 'fixed')
    expect(fixed.card.querySelector('[data-node-id]')).toBeNull()
    expect(fixed.card.querySelector('h3')).not.toHaveAttribute('title')
  })

  it('악성 hostname · node_id 는 표식으로 보이고 이름 · 말풍선에 숨은 문자가 원문으로 남지 않는다', () => {
    const label = `${HOSTILE.rlo} ${HOSTILE.img} ${HOSTILE.decoy} ${HOSTILE.isolate}`
    const { container, card } = renderCard(nodeTarget(HOSTILE.zwsp, { label }))
    expectInertDom(container)
    const title = within(card).getByRole('heading', { level: 3 })
    expect(title).toHaveTextContent('admin⟨U+202E⟩gnp.exe <img src=//a.attacker.test/p.png onerror=alert(1)> 줄1↵2026-09-18')
    expect(title).toHaveAttribute('title', revealHidden(label))
    expect(title.querySelector('button')).toBeNull()
    expect(card.querySelector('[data-node-id]')).toHaveTextContent('ad⟨U+200B⟩min')
    // 로그 이름도 노드가 적어 낸 값에서 온다
    expect(card).toHaveTextContent('opsloop-ad⟨U+200B⟩min 로그 3분 전')
  })

  it('긴 악성 이름은 253자에서 자르고(펼치기 단추 없음) 전체는 말풍선으로 본다', () => {
    const { container, card } = renderCard(nodeTarget('web-06', { label: MIXED }))
    expectInertDom(container)
    const title = within(card).getByRole('heading', { level: 3 })
    expect(title).toHaveClass('truncate')
    expect(title).toHaveAttribute('title', revealHidden(MIXED))
    expect(title.textContent?.endsWith('…')).toBe(true)
    expect(title.querySelector('button')).toBeNull()
  })
})
