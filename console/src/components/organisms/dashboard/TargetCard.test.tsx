import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import type { LiveState } from '@/api/live'
import { LiveContext } from '@/api/live-context'
import type { Target } from '@/api/targets'
import { expectInertDom, expectMixedRevealed, HOSTILE, MIXED } from '@/test/hostile-fixtures'
import { awsSensor, consoleTarget, dataNode, LATEST_KEY, minutesAgo, TARGETS_AS_OF, web01 } from '@/test/targets-fixtures'
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
  const card = screen.getByRole('region', { name: target.label })
  /** 구역 한 칸(dt 제목 옆 dd) */
  const row = (title: string) => within(card).getByText(title, { selector: 'dt' }).nextElementSibling as HTMLElement
  return { ...view, card, row }
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
    const { row } = renderCard(awsSensor())
    const collect = row('수집')
    expect(collect).toHaveTextContent('업로더 생존 신호 3분 전 · 09-28 18:57')
    expect(collect).toHaveTextContent('Cowrie 2분 전 · 웹 디코이 1시간 전 · AWS 관문 기록 없음')
    expect(collect).toHaveTextContent('업로더 생존 신호 3분 전 · 최근 1시간 로그 있음')
    expect(collect).not.toHaveTextContent('생존 상태 미확인')
  })

  it('생존 신호가 없는 대상은 마지막 로그 시각에 생존 상태 미확인을 붙인다', () => {
    const { row } = renderCard(consoleTarget())
    expect(row('수집')).toHaveTextContent('마지막 로그 12분 전 · 생존 상태 미확인')
  })

  it('신호 표에 기록이 없으면 신호 없음과 마지막 로그를 함께 보인다', () => {
    const target = awsSensor({ collection: { ...awsSensor().collection, state: 'unknown', reason: '생존 신호 미기록', signal: { label: '업로더 생존 신호', seen_at: null, checked_at: null, stale_after_seconds: 900, problem: '없음' } } })
    const { row } = renderCard(target)
    expect(row('수집')).toHaveTextContent('업로더 생존 신호 기록 없음')
    expect(row('수집')).toHaveTextContent('마지막 로그 2분 전 · 생존 상태 미확인')
    expect(row('수집')).toHaveTextContent('읽기 문제: 없음')
  })

  it('로그가 없는 대상(데이터 노드)은 신호 기록 없음에 미확인을 붙이고 로그 줄을 두지 않는다', () => {
    const base = dataNode()
    const target = dataNode({ collection: { ...base.collection, state: 'unknown', reason: '탐지 실행 기록 없음', signal: { ...base.collection.signal!, seen_at: null } } })
    const { row } = renderCard(target)
    expect(row('수집')).toHaveTextContent('마지막 탐지 실행 기록 없음 · 생존 상태 미확인')
    expect(row('수집')).not.toHaveTextContent('로그 기록 없음')
    expect(row('수집')).toHaveTextContent('적재기 확인 1분 전 · 집행기 확인 기록 없음')
  })

  it('서버가 수신 없음으로 판정한 대상에는 미확인을 덧붙이지 않는다', () => {
    const base = awsSensor()
    const target = awsSensor({ collection: { ...base.collection, state: 'no_signal', reason: '업로더 생존 신호 없음', signal: { ...base.collection.signal!, seen_at: null } } })
    const { card, row } = renderCard(target)
    expect(within(card).getByText('수신 없음')).toHaveClass('bg-warning-soft')
    expect(row('수집')).toHaveTextContent('업로더 생존 신호 기록 없음')
    expect(row('수집')).toHaveTextContent('마지막 로그 2분 전')
    expect(row('수집')).not.toHaveTextContent('생존 상태 미확인')
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

  it('대응: 적용 확인(초록) · 미확인 · 정책상 제외와 지점 보고 시각, 차단 목록으로 잇는다', () => {
    const { row } = renderCard(awsSensor())
    const response = row('대응')
    expect(within(response).getByText('차단 적용 2 (AWS 관문)')).toHaveClass('bg-success-soft')
    expect(within(response).getByText('차단 적용 여부 미확인 1')).toHaveClass('bg-warning-soft')
    expect(within(response).getByText('정책상 차단 제외 3')).toBeInTheDocument()
    expect(response).toHaveTextContent('AWS 관문 보고 2분 전')
    expect(within(response).getByRole('link')).toHaveAttribute('href', '/blocklist')
  })

  it('대응: 지점이 거부한 차단은 빨간 실패, 집행기 확인이 멈추면 초록 대신 미확인과 까닭(주의색)', () => {
    const failed = renderCard(web01({ response: { ...web01().response, applied: 1, failed: 2 } }))
    expect(within(failed.row('대응')).getByText('차단 적용 실패 2 (내부 방화벽)')).toHaveClass('bg-danger-soft')
    failed.unmount()
    const { row } = renderCard(awsSensor({ response: { ...awsSensor().response, applied: 0, failed: 0, unverified: 3, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' } }))
    const response = row('대응')
    expect(within(response).queryByText(/차단 적용 \d+ \(/)).not.toBeInTheDocument()
    expect(within(response).getByText('차단 적용 여부 미확인 3')).toHaveClass('bg-warning-soft')
    expect(within(response).getByText('집행기 확인 중단 · 마지막 확인 12분 전')).toHaveClass('text-warning')
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
    expect(vulns).toHaveTextContent('honeypot-dmz 취약점 12 · KEV 1 · 조사 3시간 전')
    expect(vulns).toHaveTextContent('gateway 자산 정보 없음')
    aws.unmount()

    const console = renderCard(consoleTarget()).row('취약점')
    expect(console).toHaveTextContent('console-b 취약점 대조 전')
    expect(console).not.toHaveTextContent('console-b 취약점 0')

    const web = renderCard(web01()).row('취약점')
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
