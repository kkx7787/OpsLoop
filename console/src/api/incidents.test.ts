import { QueryClientProvider, type InfiniteData } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { noRetryClient } from '@/test/render'
import {
  applyAction,
  applyVerdict,
  flattenPages,
  incidentKeys,
  incidentPath,
  nextOffset,
  normalizeFilters,
  PAGE_SIZE,
  ruleKeys,
  useActionMutation,
  useIncident,
  useIncidentsInfinite,
  useVerdictMutation,
  type ActionCreated,
  type Incident,
  type IncidentDetail,
  type IncidentPage,
  type VerdictCreated,
} from './incidents'

// ---------------------------------------------------------------- 표본

function incident(n: number, extra: Partial<Incident> = {}): Incident {
  return {
    incident_key: `R003|v2|4.4.66.${n}|2026-09-18T06:00:00+00:00`,
    rule_id: 'R003',
    rule_version: 'v2',
    rule_name: '악성코드 투하',
    severity: 'critical',
    actor_ip: `4.4.66.${n}`,
    target: null,
    first_ts: '2026-09-18T06:00:00+00:00',
    last_ts: '2026-09-18T06:10:00+00:00',
    signal_count: 3,
    session_count: 1,
    status: 'open',
    created_at: '2026-09-18T06:10:05+00:00',
    verdict: null,
    pending_seconds: 22_320,
    ...extra,
  }
}

function page(offset: number, items: Incident[], total: number): IncidentPage {
  return { total, limit: PAGE_SIZE, offset, items }
}

const KEY = 'R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00'

function detail(extra: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    incident_key: KEY,
    rule_id: 'R003',
    rule_version: 'v2',
    rule_name: '악성코드 투하',
    severity: 'critical',
    actor_ip: '4.4.66.84',
    target: null,
    first_ts: '2026-09-18T06:00:00+00:00',
    last_ts: '2026-09-18T06:10:00+00:00',
    signal_count: 3,
    session_count: 1,
    status: 'open',
    created_at: '2026-09-18T06:10:05+00:00',
    evidence: { sample: [{ count: 3 }], sessions: ['abc'] },
    actions: [],
    verdicts: [],
    related: [],
    behavior: [],
    actor: { history: null, rules: [], blocked: null },
    raw: [],
    circular: '규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다',
    ...extra,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

/** 주소 · 방식별로 응답을 정한 fetch 를 전역에 끼운다(render.tsx 의 stubMe 와 같은 방식) */
function stubFetch(route: (url: string, init?: RequestInit) => Response | undefined) {
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    return route(url, init) ?? json({ detail: '없는 경로' }, 404)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function calledUrls(fetch: ReturnType<typeof stubFetch>): string[] {
  return fetch.mock.calls.map(([input]) => (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url))
}

function withClient() {
  const client = noRetryClient()
  const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
  return { client, wrapper }
}

// ---------------------------------------------------------------- 순수 함수

describe('쿼리 키', () => {
  it('비어 있는 필터 칸은 키에서 빠져 같은 뜻이면 같은 키가 된다', () => {
    expect(normalizeFilters({ status: 'open', severity: undefined, rule_id: '', judged: false })).toEqual({ status: 'open', judged: false })
    expect(incidentKeys.list({ status: 'open', rule_id: '' })).toEqual(incidentKeys.list({ status: 'open' }))
    expect(incidentKeys.list()).toEqual(['incidents', 'list', {}])
  })

  it('목록 · 상세 키는 incidents 밑에 있어 한 번에 무효화할 수 있다', () => {
    expect(incidentKeys.detail(KEY)).toEqual(['incidents', 'detail', KEY])
    expect(incidentKeys.lists()).toEqual(['incidents', 'list'])
    expect(incidentKeys.details()).toEqual(['incidents', 'detail'])
    expect(ruleKeys.quality()).toEqual(['rules', 'quality'])
  })

  it('사건 키는 경로에 넣기 전에 부호화한다', () => {
    expect(incidentPath('R003|v2')).toBe('/api/incidents/R003%7Cv2')
  })
})

describe('nextOffset', () => {
  it('받은 만큼 더한 값이 total 보다 작을 때만 다음 쪽이 있다', () => {
    const items = Array.from({ length: PAGE_SIZE }, (_, i) => incident(i))
    expect(nextOffset(page(0, items, 120))).toBe(50)
    expect(nextOffset(page(50, items, 120))).toBe(100)
    expect(nextOffset(page(100, items.slice(0, 20), 120))).toBeUndefined()
    expect(nextOffset(page(0, items, 50))).toBeUndefined()
  })

  it('빈 쪽이 오면 끝이다(total 이 커도 무한히 묻지 않는다)', () => {
    expect(nextOffset(page(0, [], 10))).toBeUndefined()
  })
})

describe('flattenPages', () => {
  it('쪽을 한 배열로 펴고 total 은 마지막 쪽 값', () => {
    const data: InfiniteData<IncidentPage, number> = {
      pages: [page(0, [incident(1), incident(2)], 3), page(2, [incident(3)], 4)],
      pageParams: [0, 2],
    }
    const out = flattenPages(data)
    expect(out.items.map((i) => i.actor_ip)).toEqual(['4.4.66.1', '4.4.66.2', '4.4.66.3'])
    expect(out.total).toBe(4)
  })

  it('쪽 사이에 끼어든 사건으로 겹친 행은 키로 거른다', () => {
    const data: InfiniteData<IncidentPage, number> = {
      pages: [page(0, [incident(1), incident(2)], 3), page(2, [incident(2), incident(3)], 4)],
      pageParams: [0, 2],
    }
    expect(flattenPages(data).items.map((i) => i.actor_ip)).toEqual(['4.4.66.1', '4.4.66.2', '4.4.66.3'])
  })

  it('쪽이 없으면 빈 목록', () => {
    expect(flattenPages({ pages: [], pageParams: [] })).toEqual({ items: [], total: 0 })
  })
})

describe('applyVerdict · applyAction', () => {
  const verdict: VerdictCreated = {
    id: 7,
    verdict: 'threat',
    reason: '명령 실행',
    observed_value: 3,
    operator: 'han',
    proposed: 'threat',
    decision_seconds: 40,
    created_at: '2026-09-18T12:00:00+00:00',
    incident_key: KEY,
  }
  const action = (kind: string): ActionCreated => ({ id: 9, action: kind, operator: 'han', note: null, created_at: '2026-09-18T12:00:00+00:00', incident_key: KEY })

  it('판정은 이력 끝에 붙고 사건은 종결', () => {
    const next = applyVerdict(detail(), verdict)
    expect(next.status).toBe('resolved')
    expect(next.verdicts).toEqual([verdict])
  })

  it('조치는 이력 끝에 붙고 상태는 조치 종류대로', () => {
    expect(applyAction(detail(), action('acknowledge')).status).toBe('acknowledged')
    expect(applyAction(detail(), action('block_ip')).status).toBe('in_progress')
    expect(applyAction(detail(), action('suppress_rule')).status).toBe('suppressed')
    expect(applyAction(detail({ status: 'in_progress' }), action('unblock_ip')).status).toBe('in_progress')
    expect(applyAction(detail(), action('note')).actions).toHaveLength(1)
  })

  it('원본을 바꾸지 않는다', () => {
    const before = detail()
    applyVerdict(before, verdict)
    expect(before.status).toBe('open')
    expect(before.verdicts).toEqual([])
  })
})

// ---------------------------------------------------------------- 훅

describe('useIncidentsInfinite', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('필터를 쿼리로 붙여 50건씩 묻고, 다음 쪽은 offset 으로 이어 받는다', async () => {
    const first = Array.from({ length: PAGE_SIZE }, (_, i) => incident(i))
    const second = [incident(60)]
    const fetch = stubFetch((url) => {
      if (!url.startsWith('/api/incidents?')) return undefined
      const q = new URL(url, 'http://x').searchParams
      return json(q.get('offset') === '0' ? page(0, first, 51) : page(50, second, 51))
    })
    const { wrapper } = withClient()
    const { result } = renderHook(() => useIncidentsInfinite({ status: 'open', judged: false, rule_id: '' }), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(calledUrls(fetch)[0]).toBe('/api/incidents?status=open&judged=false&limit=50&offset=0')
    expect(result.current.data).toMatchObject({ total: 51 })
    expect(result.current.data?.items).toHaveLength(50)
    expect(result.current.hasNextPage).toBe(true)

    await result.current.fetchNextPage()
    await waitFor(() => expect(result.current.data?.items).toHaveLength(51))
    expect(calledUrls(fetch)[1]).toBe('/api/incidents?status=open&judged=false&limit=50&offset=50')
    expect(result.current.hasNextPage).toBe(false)
  })
})

describe('useIncident', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('부호화한 키로 상세를 받는다', async () => {
    const fetch = stubFetch((url) => (url === `/api/incidents/${encodeURIComponent(KEY)}` ? json(detail()) : undefined))
    const { wrapper } = withClient()
    const { result } = renderHook(() => useIncident(KEY), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.circular).toContain('파일 이동')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('키가 비어 있으면 묻지 않는다', () => {
    const fetch = stubFetch(() => undefined)
    const { wrapper } = withClient()
    const { result } = renderHook(() => useIncident(''), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(fetch).not.toHaveBeenCalled()
  })
})

describe('useVerdictMutation · useActionMutation', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('판정이 등록되면 상세 캐시를 바로 고치고 목록 · 규칙 품질을 무효화한다', async () => {
    const created: VerdictCreated = {
      id: 1,
      verdict: 'threat',
      reason: null,
      observed_value: null,
      operator: 'han',
      proposed: null,
      decision_seconds: 12,
      created_at: '2026-09-18T12:00:00+00:00',
      incident_key: KEY,
    }
    const fetch = stubFetch((url, init) => (init?.method === 'POST' && url.endsWith('/verdict') ? json(created, 201) : undefined))
    const { client, wrapper } = withClient()
    client.setQueryData(incidentKeys.detail(KEY), detail())
    const invalidate = vi.spyOn(client, 'invalidateQueries')

    const { result } = renderHook(() => useVerdictMutation(KEY), { wrapper })
    await result.current.mutateAsync({ verdict: 'threat', decision_seconds: 12 })

    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe(`/api/incidents/${encodeURIComponent(KEY)}/verdict`)
    expect(init?.body).toBe('{"verdict":"threat","decision_seconds":12}')
    expect(client.getQueryData<IncidentDetail>(incidentKeys.detail(KEY))).toMatchObject({ status: 'resolved', verdicts: [created] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ruleKeys.quality() })
  })

  it('조치가 등록되면 상세 캐시의 상태를 바꾸고 목록을 무효화한다. 차단은 상세도 다시 받는다', async () => {
    const created: ActionCreated = { id: 2, action: 'block_ip', operator: 'han', note: '차단', created_at: '2026-09-18T12:00:00+00:00', incident_key: KEY }
    stubFetch((url, init) => (init?.method === 'POST' && url.endsWith('/actions') ? json(created, 201) : undefined))
    const { client, wrapper } = withClient()
    client.setQueryData(incidentKeys.detail(KEY), detail())
    const invalidate = vi.spyOn(client, 'invalidateQueries')

    const { result } = renderHook(() => useActionMutation(KEY), { wrapper })
    await result.current.mutateAsync({ action: 'block_ip', note: '차단', expires_hours: 48 })

    expect(client.getQueryData<IncidentDetail>(incidentKeys.detail(KEY))).toMatchObject({ status: 'in_progress', actions: [created] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.lists() })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: incidentKeys.detail(KEY) })
  })

  it('상세 캐시가 없으면 만들지 않는다(빈 상세가 그려지지 않게)', async () => {
    const created: ActionCreated = { id: 3, action: 'acknowledge', operator: 'han', note: null, created_at: '2026-09-18T12:00:00+00:00', incident_key: KEY }
    stubFetch((url, init) => (init?.method === 'POST' && url.endsWith('/actions') ? json(created, 201) : undefined))
    const { client, wrapper } = withClient()
    const { result } = renderHook(() => useActionMutation(KEY), { wrapper })
    await result.current.mutateAsync({ action: 'acknowledge' })
    expect(client.getQueryData(incidentKeys.detail(KEY))).toBeUndefined()
  })

  it('403 은 ApiError 로 돌아오고 캐시는 그대로다', async () => {
    stubFetch((_url, init) => (init?.method === 'POST' ? json({ detail: '권한이 없습니다 (viewer)' }, 403) : undefined))
    const { client, wrapper } = withClient()
    client.setQueryData(incidentKeys.detail(KEY), detail())
    const { result } = renderHook(() => useVerdictMutation(KEY), { wrapper })
    await expect(result.current.mutateAsync({ verdict: 'threat' })).rejects.toMatchObject({ status: 403, detail: '권한이 없습니다 (viewer)' })
    expect(client.getQueryData<IncidentDetail>(incidentKeys.detail(KEY))?.status).toBe('open')
  })
})
