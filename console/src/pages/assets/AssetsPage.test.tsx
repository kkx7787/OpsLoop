import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ctiKeys, type AssetDetailAvailable, type AssetsResult, type VulnFilter, type WatchResult } from '@/api/cti'
import { assetDetailResult, assetsResult, freshness, watchResult } from '@/test/cti-fixtures'
import { json } from '@/test/monitoring-fixtures'
import { noRetryClient, renderRoutes } from '@/test/render'
import { AssetsPage } from './AssetsPage'

interface SetupOptions {
  list?: AssetsResult | { detail: string }
  listStatus?: number
  /** 고정 응답(받은 거르기 · 쪽을 그대로 돌려준다) 또는 요청 주소마다 응답을 만드는 함수 */
  detail?: AssetDetailAvailable | ((url: URL) => AssetDetailAvailable)
  detailStatus?: number
  watch?: WatchResult | { detail: string }
  watchStatus?: number
}

/** /api/cti/watch · /api/assets · /api/assets/{id} 에 답하는 fetch. 상세는 받은 거르기 · 쪽을 그대로 돌려준다 */
function setup(path = '/inventory', { list = assetsResult(), listStatus = 200, detail = assetDetailResult(), detailStatus = 200, watch = watchResult(), watchStatus = 200 }: SetupOptions = {}) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), 'http://localhost')
    if (url.pathname === '/api/me') return json({ username: 'han', role: 'viewer' })
    if (url.pathname === '/api/cti/watch') return json(watch, watchStatus)
    if (url.pathname === '/api/assets') return json(list, listStatus)
    if (url.pathname.startsWith('/api/assets/')) {
      if (detailStatus !== 200) return json({ detail: '자산 조회 실패' }, detailStatus)
      if (typeof detail === 'function') return json(detail(url))
      const filter = url.searchParams.get('filter') as VulnFilter
      const offset = Number(url.searchParams.get('offset'))
      return json({ ...detail, vulnerabilities: { ...detail.vulnerabilities, filter, offset } })
    }
    return json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  const client = noRetryClient()
  const view = renderRoutes([{ path: '/inventory', element: <AssetsPage /> }], path, client)
  const detailUrls = () => fetch.mock.calls.map(([input]) => String(input)).filter((u) => u.startsWith('/api/assets/'))
  return { fetch, detailUrls, client, ...view }
}

/** 총수를 바꿀 수 있는 상세 응답. offset 이 총수를 넘은 쪽은 행이 비어 온다(서버와 같다) */
function shrinkingDetail(initialTotal: number) {
  const base = assetDetailResult()
  const state = { total: initialTotal }
  const detail = (url: URL): AssetDetailAvailable => {
    const offset = Number(url.searchParams.get('offset'))
    const filter = url.searchParams.get('filter') as VulnFilter
    const rows = offset < state.total ? base.vulnerabilities.rows : []
    return { ...base, vulnerabilities: { ...base.vulnerabilities, rows, total: state.total, offset, filter } }
  }
  return { state, detail }
}

afterEach(() => vi.unstubAllGlobals())

describe('자산 · 취약점', () => {
  it('자산 표에 역할 · 수집 · 재부팅 대기 · KEV · 수집 오류를 보이고 신선도를 요약한다', async () => {
    setup()
    expect(await screen.findByRole('heading', { level: 1, name: '자산 · 취약점' })).toBeInTheDocument()
    const table = await screen.findByRole('region', { name: '자산 표' })
    const row = (id: string) => table.querySelector(`[data-asset="${id}"]`) as HTMLElement

    expect(within(row('web-01')).getByText('대상')).toBeInTheDocument()
    expect(within(row('web-01')).getByText('SSH')).toBeInTheDocument()
    expect(within(row('web-01')).getByText('12건')).toBeInTheDocument()
    expect(within(row('web-01')).getByText('0.43%')).toBeInTheDocument()
    expect(within(row('fw')).getByText('재부팅 대기')).toHaveAttribute('title', '설치된 최신 커널 6.8.0-142.142')
    expect(within(row('fw')).getByText('2건')).toBeInTheDocument()
    expect(within(row('fw')).getByText(/재부팅 25건/)).toBeInTheDocument()
    expect(within(row('fw')).getByText('99.5%')).toBeInTheDocument()
    // 수집 실패 · 대조 전: 0건으로 보이지 않는다
    expect(within(row('console-b')).getByText('미수집')).toBeInTheDocument()
    expect(within(row('console-b')).getByText('오래됨')).toBeInTheDocument()
    expect(within(row('console-b')).getByText('대조 전')).toBeInTheDocument()
    expect(within(row('console-b')).getByText(/수집 · 연결 실패/)).toBeInTheDocument()

    expect(screen.getByText('KEV 수집')).toBeInTheDocument()
    expect(screen.queryByText(/공개 정보가 오래됐습니다/)).toBeNull()
    expect(screen.getByRole('link', { name: '수집 노드' })).toHaveAttribute('href', '/nodes')
    expect(screen.queryByRole('region', { name: /자산 상세$/ })).toBeNull()
  })

  it('자산을 누르면 주소에 남고 상세(주요 패키지 · 이미지 · 배포판 취약점)가 열린다', async () => {
    const { detailUrls, router } = setup()
    fireEvent.click(await screen.findByRole('button', { name: 'fw' }))
    expect(router.state.location.search).toBe('?asset=fw')
    expect(screen.getByRole('button', { name: 'fw' })).toHaveAttribute('aria-pressed', 'true')

    const region = await screen.findByRole('region', { name: 'fw 자산 상세' })
    const detail = within(region)
    expect(await detail.findByText('openssh-server')).toBeInTheDocument()
    expect(detail.getByText('1:9.6p1-3ubuntu13.19')).toBeInTheDocument()
    expect(detail.getByText('opsloop-console:5adc7de')).toBeInTheDocument()
    expect(detail.getByText(/이미지 안의 패키지는 조사하지 않아 취약점 대조에 들어가지 않습니다/)).toBeInTheDocument()
    expect(detailUrls()).toEqual(['/api/assets/fw?filter=all&limit=50&offset=0'])

    const rows = within(detail.getByRole('region', { name: '배포판 취약점 표' })).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText('CVE-2024-1086')).toBeInTheDocument()
    expect(within(rows[0]).getByText('재부팅하면 해소')).toBeInTheDocument()
    expect(rows[0]).toHaveTextContent('설치된 커널 6.8.0-142.142')
    expect(within(rows[0]).getByText('KEV')).toBeInTheDocument()
    expect(within(rows[0]).getByText('랜섬웨어 사용 확인')).toBeInTheDocument()
    expect(within(rows[0]).getByText('7.8 HIGH')).toBeInTheDocument()
    expect(within(rows[0]).getByText('높음')).toBeInTheDocument()
    expect(within(rows[1]).getByText('배포판 수정판 없음')).toBeInTheDocument()
    expect(detail.getByText('1–2 / 120건')).toBeInTheDocument()
  })

  it('거르기 · 쪽 넘김은 질의로 보내고, 거르기를 바꾸면 첫 쪽부터 본다', async () => {
    const { detailUrls } = setup('/inventory?asset=fw')
    const region = await screen.findByRole('region', { name: 'fw 자산 상세' })
    const detail = within(region)
    await detail.findByText('1–2 / 120건')

    fireEvent.click(detail.getByRole('button', { name: '다음' }))
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=all&limit=50&offset=50'))
    expect(await detail.findByText('51–52 / 120건')).toBeInTheDocument()

    const filters = detail.getByRole('group', { name: '취약점 거르기' })
    fireEvent.click(within(filters).getByRole('button', { name: 'KEV' }))
    expect(within(filters).getByRole('button', { name: 'KEV' })).toHaveAttribute('aria-pressed', 'true')
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=kev&limit=50&offset=0'))
    fireEvent.click(within(filters).getByRole('button', { name: '수정 가능' }))
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=fix&limit=50&offset=0'))
  })

  it('뒤쪽을 보는 동안 재조회로 총수가 줄면 없음으로 적지 않고 유효한 마지막 쪽으로 옮긴다', async () => {
    const { state, detail: respond } = shrinkingDetail(120)
    const { detailUrls, client } = setup('/inventory?asset=fw', { detail: respond })
    const detail = within(await screen.findByRole('region', { name: 'fw 자산 상세' }))
    await detail.findByText('1–2 / 120건')
    fireEvent.click(detail.getByRole('button', { name: '다음' }))
    await detail.findByText('51–52 / 120건')
    fireEvent.click(detail.getByRole('button', { name: '다음' }))
    await detail.findByText('101–102 / 120건')

    // 패치 뒤 대조로 60건이 되고 재접속 무효화(ctiKeys.all)로 다시 받는다: 셋째 쪽은 비고 마지막 쪽은 둘째 쪽이다
    state.total = 60
    await act(async () => { await client.invalidateQueries({ queryKey: ctiKeys.all }) })
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=all&limit=50&offset=50'))
    expect(await detail.findByText('51–52 / 60건')).toBeInTheDocument()
    expect(detail.queryByText('배포판 기준으로 알려진 취약점이 없습니다.')).toBeNull()

    // 30건으로 더 줄면 첫 쪽이 마지막 쪽이다
    state.total = 30
    await act(async () => { await client.invalidateQueries({ queryKey: ctiKeys.all }) })
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=all&limit=50&offset=0'))
    expect(await detail.findByText('1–2 / 30건')).toBeInTheDocument()
    expect(detail.queryByText('배포판 기준으로 알려진 취약점이 없습니다.')).toBeNull()
  })

  it('총수가 있는데 행이 비어 오면 없음이 아니라 이 쪽이 비었다고 적는다', async () => {
    const base = assetDetailResult()
    setup('/inventory?asset=fw', { detail: { ...base, vulnerabilities: { ...base.vulnerabilities, rows: [], total: 30 } } })
    const detail = within(await screen.findByRole('region', { name: 'fw 자산 상세' }))
    expect(await detail.findByText(/이 쪽에는 행이 없습니다/)).toHaveTextContent('전체 30건')
    expect(detail.queryByText('배포판 기준으로 알려진 취약점이 없습니다.')).toBeNull()
    expect(detail.getByText('— / 30건')).toBeInTheDocument()
  })

  it('다른 자산을 고르면 거르기가 처음으로 돌아가고, 닫으면 주소에서도 빠진다', async () => {
    const { detailUrls, router } = setup('/inventory?asset=fw')
    const detail = within(await screen.findByRole('region', { name: 'fw 자산 상세' }))
    await detail.findByText('1–2 / 120건')
    fireEvent.click(within(detail.getByRole('group', { name: '취약점 거르기' })).getByRole('button', { name: 'KEV' }))
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/fw?filter=kev&limit=50&offset=0'))

    fireEvent.click(screen.getByRole('button', { name: 'web-01' }))
    await waitFor(() => expect(detailUrls().at(-1)).toBe('/api/assets/web-01?filter=all&limit=50&offset=0'))
    const next = within(await screen.findByRole('region', { name: 'web-01 자산 상세' }))
    fireEvent.click(next.getByRole('button', { name: '닫기' }))
    expect(screen.queryByRole('region', { name: 'web-01 자산 상세' })).toBeNull()
    expect(router.state.location.search).toBe('')
  })

  it('주소의 자산 값이 형식에 맞지 않으면 상세를 묻지 않는다', async () => {
    const { detailUrls } = setup('/inventory?asset=..%2Fetc')
    await screen.findByRole('region', { name: '자산 표' })
    expect(screen.queryByRole('region', { name: /자산 상세$/ })).toBeNull()
    expect(detailUrls()).toEqual([])
  })

  it('목록 조회 실패(503)를 빈 목록으로 숨기지 않고 다시 시도를 둔다', async () => {
    setup('/inventory', { list: { detail: '일시 오류' }, listStatus: 503 })
    expect(await screen.findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '자산 표' })).toBeNull()
  })

  it('상세 조회가 실패해도 자산 표는 그대로이고 상세 구역 안에만 오류가 보인다', async () => {
    setup('/inventory?asset=fw', { detailStatus: 503 })
    const region = await screen.findByRole('region', { name: 'fw 자산 상세' })
    expect(await within(region).findByText('자산 조회 실패 (HTTP 503)')).toBeInTheDocument()
    expect(within(region).getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '자산 표' })).toBeInTheDocument()
  })

  it('없는 자산(404)은 상세 구역 안에 찾을 수 없음으로 보인다', async () => {
    setup('/inventory?asset=ghost', { detailStatus: 404 })
    const region = await screen.findByRole('region', { name: 'ghost 자산 상세' })
    expect(await within(region).findByText('찾을 수 없습니다')).toBeInTheDocument()
  })

  it('자산 정보 · 공개 정보가 오래되면 비해당으로 읽지 말라는 띠를 보인다', async () => {
    const f = freshness()
    const base = assetDetailResult()
    setup('/inventory?asset=fw', {
      list: assetsResult({ freshness: { ...f, osv: { ...f.osv, stale: true } } }),
      detail: { ...base, asset: { ...base.asset, stale: true, last_error: '연결 실패: 시간 초과', check_error: '지원하지 않는 배포판' } },
    })
    expect(await screen.findByText(/공개 정보가 오래됐습니다\. 비해당으로 읽지 않습니다\. 오래된 출처: 배포판 대조/)).toBeInTheDocument()
    const detail = within(await screen.findByRole('region', { name: 'fw 자산 상세' }))
    expect(await detail.findByText(/자산 정보가 오래됐습니다/)).toHaveTextContent('비해당으로 읽지 않습니다')
    expect(detail.getByText('마지막 수집 실패')).toBeInTheDocument()
    expect(detail.getByText('배포판 대조 실패')).toBeInTheDocument()
  })

  it('대조 전 자산의 빈 취약점 표는 없음이 아니라 대조 전으로 적는다', async () => {
    const base = assetDetailResult()
    setup('/inventory?asset=fw', { detail: { ...base, asset: { ...base.asset, checked_at: null }, vulnerabilities: { rows: [], total: 0, limit: 50, offset: 0, filter: 'all' } } })
    const detail = within(await screen.findByRole('region', { name: 'fw 자산 상세' }))
    expect(await detail.findByText('배포판 취약점 대조 전입니다. 비해당으로 읽지 않습니다.')).toBeInTheDocument()
    expect(detail.queryByRole('navigation', { name: '배포판 취약점 쪽' })).toBeNull()
  })

  it('CTI 표가 없으면(available=false) 마이그레이션 안내를 보인다', async () => {
    setup('/inventory', { list: { as_of: '2026-09-25T03:00:00Z', available: false, freshness: null, rows: [] } })
    expect(await screen.findByRole('heading', { name: '공개 취약점 정보 표가 아직 없습니다' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: '자산 표' })).toBeNull()
  })
})

describe('주목 CVE', () => {
  it('맨 위 카드에 CVE · 주목 이유 · KEV · EPSS · 판정 요약 · 자산별 판정을 서버 순서대로 보인다', async () => {
    setup()
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    const table = await within(card).findByRole('region', { name: '주목 CVE 표' })
    // 자산 표보다 앞(맨 위)에 있다
    const assetTable = await screen.findByRole('region', { name: '자산 표' })
    expect(card.compareDocumentPosition(assetTable) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(within(card).getByText(/3건 · 해당 1건/)).toBeInTheDocument()
    expect(within(card).getByText(/판정 근거가 아닙니다/)).toBeInTheDocument()

    const rows = Array.from(table.querySelectorAll('tr[data-cve]')) as HTMLElement[]
    expect(rows.map((r) => r.dataset.cve)).toEqual(['CVE-2026-53266', 'CVE-2024-6387', 'CVE-2021-3156'])

    const [kernel, ssh, sudo] = rows
    expect(within(kernel).getByText('KEV')).toBeInTheDocument()
    expect(within(kernel).getByText('2026-09-18')).toBeInTheDocument()
    const summaryCell = (row: HTMLElement) => row.querySelectorAll('td')[3]
    expect(summaryCell(kernel)).toHaveTextContent(/^해당$/)
    expect(summaryCell(ssh)).toHaveTextContent(/^비해당$/)
    expect(summaryCell(sudo)).toHaveTextContent(/^미확인$/)
    expect(within(within(kernel).getByRole('list', { name: 'CVE-2026-53266 자산별 판정' })).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['web-01 해당', 'fw 해당', 'console-b 미확인'])

    // CVE-2024-6387: KEV 아님 · EPSS 99.5% (백분위 99.9) · 배포판 수정판 기준 비해당
    expect(within(ssh).getByText('OpenSSH regreSSHion · 인증 전 원격 코드 실행 · 모든 노드의 sshd')).toBeInTheDocument()
    expect(within(ssh).queryByText('KEV')).toBeNull()
    expect(ssh).toHaveTextContent('99.5% (백분위 99.9)')
    expect(within(within(ssh).getByRole('list', { name: 'CVE-2024-6387 자산별 판정' })).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['web-01 비해당', 'fw 비해당', 'console-b 미확인'])
    expect(within(ssh).getByText('web-01').closest('span[title]')).toHaveAttribute('title', 'openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3')

    // 배포판 기록이 없으면 비해당이 아니라 미확인이다
    expect(within(within(sudo).getByRole('list', { name: 'CVE-2021-3156 자산별 판정' })).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['web-01 미확인', 'fw 미확인'])
  })

  it('행을 펼치면 자산마다 패키지 · 설치 버전 · 수정판 · 이유를 보이고 다시 누르면 접힌다', async () => {
    setup()
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    const toggle = await within(card).findByRole('button', { name: 'CVE-2024-6387' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(within(card).queryByRole('table', { name: 'CVE-2024-6387 자산별 대조' })).toBeNull()

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const detail = within(card).getByRole('table', { name: 'CVE-2024-6387 자산별 대조' })
    expect(detail.closest('tr[data-detail]')).toHaveAttribute('id', toggle.getAttribute('aria-controls'))
    const web = detail.querySelector('tr[data-asset="web-01"]') as HTMLElement
    expect(within(web).getByText('비해당')).toBeInTheDocument()
    expect(within(web).getByText('openssh')).toBeInTheDocument()
    expect(within(web).getByText('1:9.6p1-3ubuntu13.19')).toBeInTheDocument()
    expect(within(web).getByText('1:9.6p1-3ubuntu13.3')).toBeInTheDocument()
    expect(web).toHaveTextContent('openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3')
    expect(within(detail.querySelector('tr[data-asset="console-b"]') as HTMLElement).getByText('자산 정보가 아직 없다')).toBeInTheDocument()
    expect(within(card).getByText('UBUNTU-CVE-2024-6387')).toBeInTheDocument()
    expect(within(card).getByRole('list', { name: 'CVE-2024-6387 영향 패키지' })).toHaveTextContent('openssh · 수정판 1:9.6p1-3ubuntu13.3')

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(within(card).queryByRole('table', { name: 'CVE-2024-6387 자산별 대조' })).toBeNull()
  })

  it('수정판이 없는 CVE 와 배포판 기록이 없는 CVE 를 펼치면 그렇게 적는다', async () => {
    setup()
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    fireEvent.click(await within(card).findByRole('button', { name: 'CVE-2026-53266' }))
    expect(within(card).getByRole('list', { name: 'CVE-2026-53266 영향 패키지' })).toHaveTextContent('linux · 배포판 수정판 없음')
    const kernel = within(card).getByRole('table', { name: 'CVE-2026-53266 자산별 대조' })
    expect(kernel.querySelector('tr[data-asset="fw"]')).toHaveTextContent('linux 6.8.0-139.139 · 배포판 수정판 없음')

    fireEvent.click(within(card).getByRole('button', { name: 'CVE-2021-3156' }))
    const sudo = within(card).getByRole('table', { name: 'CVE-2021-3156 자산별 대조' }).closest('td') as HTMLElement
    expect(within(sudo).getByText('기록 없음')).toBeInTheDocument()
    expect(within(sudo).getByText('배포판 기록이 없어 영향 패키지를 모릅니다.')).toBeInTheDocument()
  })

  it('공개 정보가 오래되면 카드 안에 비해당으로 읽지 말라는 띠를 보인다', async () => {
    const f = freshness()
    setup('/inventory', { watch: watchResult({ freshness: { ...f, osv: { ...f.osv, stale: true } } }) })
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    expect(await within(card).findByText(/이 표의 비해당도 비해당으로 읽지 않습니다\. 오래된 출처: 배포판 대조/)).toBeInTheDocument()
  })

  it('주목 CVE 조회가 실패해도 자산 표는 그대로이고 카드 안에만 오류 · 다시 시도가 보인다', async () => {
    setup('/inventory', { watch: { detail: '일시 오류' }, watchStatus: 503 })
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    expect(await within(card).findByText('일시 오류 (HTTP 503)')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: '다시 시도' })).toBeInTheDocument()
    expect(await screen.findByRole('region', { name: '자산 표' })).toBeInTheDocument()
  })

  it('이 기능을 모르는 서버(404)는 카드 안 안내 한 줄로 보인다', async () => {
    setup('/inventory', { watch: { detail: '없는 경로' }, watchStatus: 404 })
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    expect(await within(card).findByText(/주목 CVE 정보가 없습니다/)).toBeInTheDocument()
    expect(within(card).queryByRole('button', { name: '다시 시도' })).toBeNull()
  })

  it('표가 없거나(available=false) 목록이 비었으면 그렇게 적는다', async () => {
    setup('/inventory', { watch: { as_of: '2026-09-25T03:00:00Z', available: false, freshness: null, rows: [] } })
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    expect(await within(card).findByText(/주목 CVE 표가 아직 없습니다/)).toBeInTheDocument()
    vi.unstubAllGlobals()

    setup('/inventory', { watch: watchResult({ rows: [] }) })
    const cards = await screen.findAllByRole('region', { name: '주목 CVE' })
    expect(await within(cards.at(-1) as HTMLElement).findByText(/주목 CVE 목록이 비어 있습니다/)).toBeInTheDocument()
  })

  it('첫 조회 중에는 카드 안에 불러오는 중을 보인다', async () => {
    const pending = new Promise<Response>(() => undefined)
    const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
      const url = new URL(String(input), 'http://localhost')
      if (url.pathname === '/api/cti/watch') return pending
      if (url.pathname === '/api/assets') return json(assetsResult())
      return json({ detail: '없는 경로' }, 404)
    })
    vi.stubGlobal('fetch', fetch)
    renderRoutes([{ path: '/inventory', element: <AssetsPage /> }], '/inventory', noRetryClient())
    const card = await screen.findByRole('region', { name: '주목 CVE' })
    expect(within(card).getByRole('status')).toBeInTheDocument()
    expect(await screen.findByRole('region', { name: '자산 표' })).toBeInTheDocument()
  })
})
