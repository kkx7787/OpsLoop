import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { PeriodReport } from '@/api/reports'
import { sensorOf } from '@/lib/domain'
import { json } from '@/test/monitoring-fixtures'
import { noRetryClient, renderRoutes } from '@/test/render'
import { expectInertDom, expectMixedRevealed, HOSTILE, LONG, LONG_MORE, MIXED } from '@/test/hostile-fixtures'
import { BLOCKS_SECTION, CTI_SECTION, OPS_SECTION, OVERVIEW_SECTION, periodReport, RULES_SECTION, TARGETS_SECTION } from '@/test/reports-fixtures'
import { ReportsPage } from './ReportsPage'

/** 보고서 API 가짜. 서버처럼 요청한 구역만 돌려준다(sections 가 없으면 전부) */
function setup(path = '/reports', { role = 'admin', report = periodReport(), status = 200 }: { role?: string; report?: PeriodReport; status?: number } = {}) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'tester', role })
    if (url.pathname === '/api/reports/period') {
      if (status !== 200) return json({ detail: status === 403 ? '운영 기록은 admin 만 볼 수 있습니다' : '일시 오류' }, status)
      const wanted = url.searchParams.getAll('sections')
      return json({ ...report, sections: Object.fromEntries(Object.entries(report.sections).filter(([name]) => !wanted.length || wanted.includes(name))) })
    }
    return json({}, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return { fetch, ...renderRoutes([{ path: '/reports', element: <ReportsPage /> }], path, noRetryClient()) }
}
const reportCalls = (fetch: ReturnType<typeof setup>['fetch']) =>
  fetch.mock.calls.map(([input]) => new URL(String(input), 'http://localhost')).filter((url) => url.pathname === '/api/reports/period')
/** 표에서 label 칸이 든 행의 칸 글 */
const cells = (table: HTMLElement, label: string) => within(within(table).getByText(label).closest('tr')!).getAllByRole('cell').map((cell) => cell.textContent)
/** 한 줄 수치 표의 값 */
const rowOf = (table: HTMLElement) => within(table).getAllByRole('cell').map((cell) => cell.textContent)
const sectionTitles = () => screen.getAllByRole('region').map((region) => region.getAttribute('aria-label')).filter((name) => name !== '보고서 머리')

afterEach(() => vi.unstubAllGlobals())

describe('보고서 조건', () => {
  it('만들기 전에는 조회하지 않고, 고른 기간 · 구역을 주소창과 요청 인자로 남긴다', async () => {
    const { fetch, router } = setup()
    const form = await screen.findByRole('form', { name: '보고서 조건' })
    expect(within(form).getByRole('radio', { name: '최근 7일' })).toBeChecked()
    expect(within(form).getAllByRole('checkbox').every((box) => (box as HTMLInputElement).checked)).toBe(true)
    expect(reportCalls(fetch)).toEqual([])
    // 기간 끝 기준 · 다시 만들기 동작은 본문 대신 ⓘ
    expect(within(form).getByRole('button', { name: '기간 설명' })).toHaveAccessibleDescription(/기간 끝은 보고서를 만든 시각\(출력 시각\)입니다/)
    expect(within(form).getByRole('button', { name: '보고서 만들기 설명' })).toHaveAccessibleDescription(/저절로 다시 조회하지 않습니다/)
    fireEvent.click(within(form).getByRole('radio', { name: '최근 14일' }))
    for (const name of ['규칙별 판정 · 비조치율', '차단 · 집행', '관제 대상 · 수집', '운영 기록']) fireEvent.click(within(form).getByRole('checkbox', { name }))
    fireEvent.click(within(form).getByRole('button', { name: '보고서 만들기' }))
    await waitFor(() => expect(router.state.location.search).toBe('?period=14d&s=overview&s=cti'))
    await waitFor(() => expect(reportCalls(fetch)).toHaveLength(1))
    expect(reportCalls(fetch)[0].searchParams.get('period')).toBe('14d')
    expect(reportCalls(fetch)[0].searchParams.getAll('sections')).toEqual(['overview', 'cti'])
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expect(sectionTitles()).toEqual(['요약 · 운영 부담', '취약점 · CVE'])
  })

  it('구역을 하나도 고르지 않으면 만들지 않는다', async () => {
    const { fetch, router } = setup()
    const form = await screen.findByRole('form', { name: '보고서 조건' })
    for (const box of within(form).getAllByRole('checkbox')) fireEvent.click(box)
    const button = within(form).getByRole('button', { name: '보고서 만들기' })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(button)
    expect(router.state.location.search).toBe('')
    expect(reportCalls(fetch)).toEqual([])
  })

  it('주소창의 조건으로 바로 만들고 구역은 주소 순서와 관계없이 계약 순서로 싣는다', async () => {
    const { fetch } = setup('/reports?period=30d&s=cti&s=rules&s=overview')
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expect(reportCalls(fetch)[0].searchParams.getAll('sections')).toEqual(['overview', 'rules', 'cti'])
    expect(sectionTitles()).toEqual(['요약 · 운영 부담', '규칙별 판정 · 비조치율', '취약점 · CVE'])
    // 양식도 주소의 조건으로 채운다
    expect(screen.getByRole('radio', { name: '최근 30일' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: '차단 · 집행' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: '규칙별 판정 · 비조치율' })).toBeChecked()
  })

  it('같은 조건으로 다시 누르면 새로 만든다', async () => {
    const { fetch } = setup('/reports?period=7d&s=overview')
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    fireEvent.click(screen.getByRole('button', { name: '보고서 만들기' }))
    await waitFor(() => expect(reportCalls(fetch)).toHaveLength(2))
  })

  // 주소 글자는 달라도(구역 없음 · 순서 다름 · 뺀 운영 기록) 조건이 같으면 조회 키가 같아 주소만 바꿔서는 다시 묻지 않는다
  it.each([
    ['구역을 고르지 않은 주소', '/reports?period=7d', 'admin'],
    ['구역 순서가 다른 주소', '/reports?period=7d&s=cti&s=overview', 'admin'],
    ['운영 기록을 뺀 비관리자 주소', '/reports?period=7d&s=overview&s=ops', 'viewer'],
  ])('%s에서 같은 조건으로 다시 눌러도 새로 만든다', async (_, path, role) => {
    const { fetch } = setup(path, { role })
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    fireEvent.click(screen.getByRole('button', { name: '보고서 만들기' }))
    await waitFor(() => expect(reportCalls(fetch)).toHaveLength(2))
    expect(reportCalls(fetch)[1].searchParams.getAll('sections')).toEqual(reportCalls(fetch)[0].searchParams.getAll('sections'))
  })

  it('관리자는 운영 기록까지 여섯 구역을 고른다', async () => {
    setup('/reports?period=7d')
    await screen.findByRole('region', { name: '운영 기록' })
    expect(screen.getAllByRole('checkbox')).toHaveLength(6)
    expect(sectionTitles()).toEqual(['요약 · 운영 부담', '규칙별 판정 · 비조치율', '차단 · 집행', '관제 대상 · 수집', '취약점 · CVE', '운영 기록'])
  })

  it.each(['viewer', 'operator'])('%s 는 운영 기록 체크가 없고 주소에 있어도 요청하지 않는다', async (role) => {
    const { fetch } = setup('/reports?period=24h&s=overview&s=ops', { role })
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expect(screen.queryByRole('checkbox', { name: '운영 기록' })).toBeNull()
    expect(screen.getAllByRole('checkbox')).toHaveLength(5)
    // 권한 안내는 도움말(ⓘ) 안이 아니라 본문
    expect(screen.getByText('운영 기록은 관리자만 실을 수 있습니다.').closest('[data-infotip]')).toBeNull()
    expect(screen.getByText('운영 기록은 관리자만 실을 수 있어 뺐습니다')).toBeInTheDocument()
    expect(reportCalls(fetch).map((url) => url.searchParams.getAll('sections'))).toEqual([['overview']])
    expect(screen.queryByRole('region', { name: '운영 기록' })).toBeNull()
  })

  it('비관리자가 구역을 고르지 않은 주소를 열면 볼 수 있는 다섯 구역을 묻는다', async () => {
    const { fetch } = setup('/reports?period=7d', { role: 'viewer' })
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expect(reportCalls(fetch)[0].searchParams.getAll('sections')).toEqual(['overview', 'rules', 'blocks', 'targets', 'cti'])
  })
})

describe('인쇄', () => {
  it('보고서를 만든 뒤에만 인쇄 버튼이 window.print 를 부른다', async () => {
    const print = vi.spyOn(window, 'print').mockImplementation(() => undefined)
    setup()
    const generate = await screen.findByRole('button', { name: '보고서 만들기' })
    const button = screen.getByRole('button', { name: '인쇄 · PDF 저장' })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(button)
    expect(print).not.toHaveBeenCalled()
    fireEvent.click(generate)
    await screen.findByRole('region', { name: '요약 · 운영 부담' })
    fireEvent.click(screen.getByRole('button', { name: '인쇄 · PDF 저장' }))
    expect(print).toHaveBeenCalledTimes(1)
  })

  it('보고서 머리에 기간(KST) · 출력 시각 · 출력자 · 구역별 기준을 적는다', async () => {
    setup('/reports?period=7d')
    const head = await screen.findByRole('region', { name: '보고서 머리' })
    expect(within(head).getByRole('heading', { name: 'OpsLoop 기간 보고서 · 최근 7일' })).toBeInTheDocument()
    // since 08:00Z · until 08:00Z → KST 17:00. 끝 시각은 기간에 들지 않는다
    expect(head.textContent).toContain('2026-09-22 17:00:00 ~ 2026-09-29 17:00:00 KST · 최근 7일 · 끝 시각 제외')
    expect(within(head).getByText('출력 시각').nextElementSibling).toHaveTextContent('2026-09-29 17:00:00 KST')
    expect(within(head).getByText('출력자').nextElementSibling).toHaveTextContent('tester')
    const basis = within(head).getAllByRole('listitem').map((item) => item.textContent)
    expect(basis).toEqual([
      '요약 · 운영 부담 · 기간 집계 · 출력 시점 값', '규칙별 판정 · 비조치율 · 기간 집계', '차단 · 집행 · 기간 집계 · 출력 시점 값',
      '관제 대상 · 수집 · 기간 집계 · 출력 시점 값', '취약점 · CVE · 기간 집계 · 출력 시점 값', '운영 기록 · 기간 집계',
    ])
  })
})

describe('구역', () => {
  it('숫자 표는 빈 값을 — 로 적고 상위 출발지는 "상위 N · 전체 M곳 중" 으로 적는다', async () => {
    setup('/reports?period=7d')
    const overview = await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expect(within(overview).getByText('기간 집계 · 출력 시점 값')).toBeInTheDocument()
    expect(within(overview).getByText('상위 2 · 전체 41곳 중 · 시험 대역 제외')).toBeInTheDocument()
    const burden = within(overview).getByRole('table', { name: '운영 부담' })
    expect(cells(burden, '판정 대기 (사건 생성 → 첫 판정)')).toEqual(['판정 대기 (사건 생성 → 첫 판정)', '68생성 90건 중 판정', '1시간 30분', '1일'])
    expect(cells(burden, '판정 소요 (화면 열기 → 판정 저장)')).toEqual(['판정 소요 (화면 열기 → 판정 저장)', '0', '—', '—'])
    expect(rowOf(within(overview).getByRole('table', { name: '기간 사건 (발생 시각 기준)' }))).toEqual(['120', '3', '20', '60', '37', '4'])
    // 발생원 이름은 사건 목록 · 상세와 같은 말이다(sensorOf). R202 도 R2xx 관제 자기 탐지로 센다
    const origins = within(overview).getByRole('table', { name: '발생원별 사건' })
    expect(within(origins).getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['R0xx 허니팟', 'R1xx 웹 노드', `R2xx ${sensorOf('R202')}`, 'R3xx 인프라', '기타'])
    expect(rowOf(origins)).toEqual(['90', '25', '5', '0', '0'])
    expect(rowOf(within(overview).getByRole('table', { name: '미판정 잔량 (출력 시점)' }))).toEqual(['40', '12', '7', '2', '1일 2시간'])
    const top = within(overview).getByRole('table', { name: '상위 출발지' })
    expect(within(top).getByRole('link', { name: '198.51.100.7' })).toHaveAttribute('href', '/sources/detail?ip=198.51.100.7')
    expect(cells(top, '198.51.100.9')).toEqual(['198.51.100.9', '12', 'medium', '—'])
    // 구역 끝의 기준 설명(notes)은 화면에서 '기준 보기'로 접고, 종이에는 늘 펼쳐 찍는다(단추는 찍지 않는다)
    const basis = within(overview).getByRole('button', { name: '요약 · 운영 부담 기준 보기' })
    const notes = within(overview).getByText('잔량 · 목표 초과: 출력 시각 기준. 목표 시간은 발생 시각부터 잰다').closest('[data-infotip]')!
    expect(basis).toHaveAttribute('aria-expanded', 'false')
    expect(basis).toHaveAttribute('aria-controls', notes.id)
    expect(basis).toHaveClass('print:hidden')
    expect(notes).toHaveClass('hidden', 'print:block')
    fireEvent.click(basis)
    expect(basis).toHaveAttribute('aria-expanded', 'true')
    expect(notes).not.toHaveClass('hidden')
    expect(notes).toHaveClass('print:block')
    // 구역마다 하나씩
    expect(screen.getAllByRole('button', { name: / 기준 보기$/ })).toHaveLength(6)
  })

  it('규칙 · 차단 · 대상 · 취약점 · 운영 기록 구역을 표로 싣는다', async () => {
    setup('/reports?period=7d')
    const rules = await screen.findByRole('region', { name: '규칙별 판정 · 비조치율' })
    const quality = within(rules).getByRole('table', { name: '규칙별 판정 (사건별 마지막 판정)' })
    expect(within(within(quality).getByText('R003').closest('tr')!).getByText('순환 규칙')).toBeInTheDocument()
    expect(within(quality).getByText('비조치 26 / 유효 판정 28')).toBeInTheDocument()
    // 흡수 · 억제는 규칙별(없으면 0) · 합계
    expect(within(quality).getByText('R001').closest('tr')!.lastElementChild).toHaveTextContent('12 · 3')
    expect(within(quality).getByText('R003').closest('tr')!.lastElementChild).toHaveTextContent('0 · 0')
    expect(rowOf(within(rules).getByRole('table', { name: '흡수 · 억제 (사건 수에 없음)' }))).toEqual(['12', '3'])

    const blocks = screen.getByRole('region', { name: '차단 · 집행' })
    expect(rowOf(within(blocks).getByRole('table', { name: '새 차단 요청의 요청자 (감사 기록)' }))).toEqual(['9', '6', '3', '0', '0'])
    expect(within(within(blocks).getByRole('table', { name: '기간 차단 감사 이벤트' })).getByText('차단 연장')).toBeInTheDocument()
    expect(rowOf(within(blocks).getByRole('table', { name: '집행 지연 (요청 → 관문 반영)' }))).toEqual(['9', '8', '42초', '5분 10초'])

    const targets = screen.getByRole('region', { name: '관제 대상 · 수집' })
    expect(within(targets).getByText('AWS 센서').closest('tr')).toHaveTextContent('차단 적용 3 (수집 관문) · 차단 적용 여부 미확인 1')
    expect(within(targets).getByText('관제 콘솔').closest('tr')).toHaveTextContent('생존 상태 미확인')
    expect(within(targets).getByText('관제 콘솔').closest('tr')!.lastElementChild).toHaveTextContent(/^차단 적용 여부 미확인$/)
    expect(rowOf(within(targets).getByRole('table', { name: 'web-01 자원 (기간 최대)' }))).toEqual(['88%', '61%', '—', '10,000', '2분'])

    const cti = screen.getByRole('region', { name: '취약점 · CVE' })
    expect(rowOf(within(cti).getByRole('table', { name: '주목 CVE (출력 시점)' }))).toEqual(['3', '1', '1', '1'])
    expect(within(cti).getByText('기간 등재 4건 중 1건')).toBeInTheDocument()
    expect(within(cti).queryByText('해당 없음')).toBeNull()

    const ops = screen.getByRole('region', { name: '운영 기록' })
    expect(cells(within(ops).getByRole('table', { name: '알림 발송 (기간 · 시험 발송 제외)' }), '판정 지연')).toEqual(['판정 지연', '실패', '2'])
  })

  it('표를 읽을 수 없어 빠진 부분은 0 이 아니라 빠졌다고 적는다', async () => {
    const report = periodReport({ sections: {
      rules: { ...RULES_SECTION, absorbed: null }, targets: { ...TARGETS_SECTION, web: null },
      cti: { ...CTI_SECTION, watch: null }, ops: { ...OPS_SECTION, notify: null },
    } })
    setup('/reports?period=7d', { report })
    const rules = await screen.findByRole('region', { name: '규칙별 판정 · 비조치율' })
    expect(within(rules).getByText('흡수 기록을 읽을 수 없어 흡수 · 억제 수를 싣지 않았습니다.')).toBeInTheDocument()
    expect(within(rules).getByText('R001').closest('tr')!.lastElementChild).toHaveTextContent('—')
    expect(screen.getByText('자원 지표를 읽을 수 없어 web-01 자원을 싣지 않았습니다.')).toBeInTheDocument()
    expect(screen.getByText('주목 CVE 표를 읽을 수 없어 주목 CVE 를 싣지 않았습니다.')).toBeInTheDocument()
    const ops = screen.getByRole('region', { name: '운영 기록' })
    expect(within(ops).getByText('알림 발송 기록을 읽을 수 없어 알림 발송을 싣지 않았습니다.')).toBeInTheDocument()
    expect(rowOf(within(ops).getByRole('table', { name: '로그인 · 알림 발송 (기간)' }))).toEqual(['9', '—', '—', '—'])
  })

  it('기간 중 KEV 등재가 우리 자산에 걸리지 않았으면 해당 없음으로 적는다', async () => {
    setup('/reports?period=7d&s=cti', { report: periodReport({ sections: { cti: { ...CTI_SECTION, kev_added: { total: 4, ours: [] } } } }) })
    const cti = await screen.findByRole('region', { name: '취약점 · CVE' })
    expect(within(cti).getByText('기간 등재 4건 중 0건')).toBeInTheDocument()
    expect(within(cti).getByText('해당 없음')).toBeInTheDocument()
  })

  it('만들지 못한 구역은 사유를 한 줄로 보이고 다른 구역은 그대로 싣는다', async () => {
    const report = periodReport()
    setup('/reports?period=7d', { report: { ...report, sections: { ...report.sections, cti: { available: false, reason: 'CTI 표를 읽을 권한이 없습니다' } } } })
    const cti = await screen.findByRole('region', { name: '취약점 · CVE' })
    // '만들지 못함'은 머리 오른쪽에 한 번, 본문은 사유만
    expect(within(cti).getByText('CTI 표를 읽을 권한이 없습니다')).toBeInTheDocument()
    expect(within(cti).getByText('만들지 못함')).toBeInTheDocument()
    expect(within(cti).queryByRole('button', { name: /기준 보기/ })).toBeNull()
    expect(within(cti).queryByRole('table')).toBeNull()
    expect(within(screen.getByRole('region', { name: '보고서 머리' })).getByText('취약점 · CVE · 만들지 못함')).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: '요약 · 운영 부담' })).getAllByRole('table').length).toBeGreaterThan(0)
  })

  it('조회 실패는 빈 보고서로 숨기지 않고 인쇄를 막는다', async () => {
    setup('/reports?period=7d', { status: 503 })
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '보고서 머리' })).toBeNull()
    expect(screen.getByRole('button', { name: '인쇄 · PDF 저장' })).toHaveAttribute('aria-disabled', 'true')
  })

  it('서버가 403 을 주면 권한 안내를 보인다', async () => {
    setup('/reports?period=7d', { status: 403 })
    expect(await screen.findByText(/운영 기록은 admin 만 볼 수 있습니다/)).toBeInTheDocument()
  })
})

describe('보고서 · 비신뢰 문자열(#41)', () => {
  it('출발지 · 규칙 버전 · 사유 · 센서 · 수집 사유 · 자산 · CVE · 출력자를 글자로만 그리고 펼치기 단추 없이 앞부분만 싣는다', async () => {
    const report = periodReport({
      generated_by: HOSTILE.rlo,
      sections: {
        overview: { ...OVERVIEW_SECTION, top_sources: { total: 2, items: [{ ip: MIXED, incidents: 3, severity: 'high', last_ts: null }, { ip: LONG, incidents: 1, severity: null, last_ts: null }] } },
        rules: { ...RULES_SECTION, versions: [{ rule_version: HOSTILE.zwsp, created_at: '2026-09-24T01:00:00Z', reason: LONG, rules: [MIXED] }] },
        blocks: { ...BLOCKS_SECTION, audit: [{ eventid: HOSTILE.svg, count: 1 }] },
        // 수집 사유에는 업로더가 보고한 문제(problem) 원문이 붙는다(targets.py sensor_collection)
        targets: { ...TARGETS_SECTION, sensors: [{ sensor: HOSTILE.img, events: 1 }], targets: [{ ...TARGETS_SECTION.targets[0], collection: { state: 'no_signal', reason: `업로더 생존 신호 없음 · ${MIXED}` } }, { ...TARGETS_SECTION.targets[0], id: 'web-02', label: HOSTILE.rlo }] },
        cti: { ...CTI_SECTION, assets: [{ ...CTI_SECTION.assets[0], asset_id: HOSTILE.jsUrl }], kev_added: { total: 1, ours: [{ cve_id: HOSTILE.mdLink, name: MIXED, date_added: HOSTILE.decoy, assets: [HOSTILE.style] }] } },
        ops: { ...OPS_SECTION, notify: { ...OPS_SECTION.notify!, rows: [{ event: HOSTILE.prefetch, status: HOSTILE.ansi, count: 1 }] } },
      },
    })
    const { container } = setup('/reports?period=7d', { report })
    const overview = await screen.findByRole('region', { name: '요약 · 운영 부담' })
    expectInertDom(container)
    expectMixedRevealed(within(overview).getByRole('table', { name: '상위 출발지' }))
    expectMixedRevealed(within(screen.getByRole('region', { name: '규칙별 판정 · 비조치율' })).getByRole('table', { name: '기간 중 만든 규칙 버전' }))
    expectMixedRevealed(within(screen.getByRole('region', { name: '취약점 · CVE' })).getByRole('table', { name: '기간 중 KEV 등재 · 우리 자산 해당' }))
    expectMixedRevealed(within(screen.getByRole('region', { name: '관제 대상 · 수집' })).getByRole('table', { name: '대상 상태 (출력 시점)' }))
    expect(within(screen.getByRole('region', { name: '보고서 머리' })).getByText('출력자').nextElementSibling?.textContent).toBe('admin⟨U+202E⟩gnp.exe')
    // 등록 노드(#64) 이름은 노드 hostname 이다
    expect(within(screen.getByRole('table', { name: '대상 상태 (출력 시점)' })).getAllByRole('row').at(-1)?.firstElementChild?.textContent).toBe('admin⟨U+202E⟩gnp.exe')
    // 2만 자는 앞부분만 싣고 펼치기 단추를 두지 않는다(종이에 단추가 찍히거나 접힌 채 잘리지 않게)
    expect(container.textContent).not.toContain(LONG)
    expect(container.textContent).toContain(`${'L'.repeat(500)}…`)
    expect(screen.queryAllByRole('button', { name: LONG_MORE })).toEqual([])
    // 출발지 링크는 같은 출처 경로 하나뿐이다
    for (const link of within(overview).getAllByRole('link')) expect(link.getAttribute('href')).toMatch(/^\/sources\/detail\?ip=/)
  })
})
