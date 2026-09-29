import { useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useRef, useState } from 'react'
import { deviceKey, hasConfirmedProtected } from '@/components/molecules/device-format'
import { SEVERITIES } from '@/lib/domain'
import { isApiError } from './errors'
import { fetchIncident, fetchIncidents, incidentKeys, type IncidentBase, type IncidentDevice, type IncidentPage } from './incidents'
import type { LiveMessage } from './live'

/**
 * 새 사건 알림(#72). 보호 대상 장비가 확인(confirmed)된 사건만 띄운다. 규칙 번호로 가르지 않는다.
 *  받기   incident.created 의 incident_key(1~1024자)만 쓴다. 통보는 비신뢰이고 장비도 없어 다른 값(rule_name 등)은 쓰지 않는다
 *  모으기 마지막 통보 2초 뒤, 늦어도 첫 통보 5초 안에 한 번에 확인한다
 *  확인   목록(최근순 50건)을 한 번 받아 키를 대조하고(캐시에 넣지 않음), 목록에 없는 키는 3건까지 상세로 받는다.
 *         상한을 넘은 키와 5xx · 네트워크로 실패한 키는 다음 회차로 넘긴다(키마다 최대 2회, 그 뒤 본 것)
 *  거르기 hasConfirmedProtected(devices) 만 띄운다. 규칙 범위 · 대체 추정 · devices 없음(이전 서버)은 띄우지 않고 본 것으로 둔다
 *  묶기   `${rule_id}|${actor_ip ?? target ?? ''}` 가 같으면 묶음을 연 때부터 60초 동안 한 장에 붙인다(건수 · 장비 합집합)
 *  중복   본 키는 삽입 순서 Map(1000개, 오래된 것부터 지움)에 둔다. 틀이 살아 있는 동안 남고 재접속 · resync 로 지우지 않는다.
 *         resync · 재접속만으로는 띄우지 않는다(incident.created 만 받는다)
 * 확인 · 묶기는 React 없는 createNewIncidentWatcher 가 하고, 훅 useNewIncidentToasts 가 틀(AppLayout)에 잇는다.
 */

/** 마지막 통보 뒤 기다리는 시간 */
export const QUIET_MS = 2_000
/** 첫 통보부터 늦어도 확인하는 시간 */
export const MAX_WAIT_MS = 5_000
/** 대조할 최근 목록 크기 */
export const LIST_SIZE = 50
/** 한 회차에 상세로 받는 키 수 */
export const DETAIL_LIMIT = 3
/** 키마다 확인하는 회차 수. 넘으면 본 것으로 둔다 */
export const MAX_ATTEMPTS = 2
/** 묶음 창(묶음을 연 때부터 고정) */
export const GROUP_MS = 60_000
/** 한꺼번에 두는 알림 장 수 */
export const MAX_TOASTS = 3
/** 본 키 상한 */
export const SEEN_LIMIT = 1_000
/** 받는 사건 키 길이 상한 */
export const KEY_MAX = 1_024
/** 알림이 떠 있는 시간(마우스 · 초점 · 숨은 탭 동안은 멈춘다) */
export const TOAST_MS = 60_000

/** 알림 한 장. 글자는 모두 REST 값이다(통보 값이 아니다) */
export interface NewIncidentToast {
  /** 묶음을 연 사건 키 */
  id: string
  /** 묶음 키 `${rule_id}|${actor_ip ?? target ?? ''}` */
  group: string
  /** 묶음을 연 시각(ms). 이때부터 GROUP_MS 동안 같은 묶음이 붙는다 */
  openedAt: number
  /** 붙을 때마다 1 늘어난다. 화면은 이 값이 바뀌면 떠 있는 시간을 다시 잰다 */
  version: number
  /** 묶인 사건 키(받은 순서). 건수는 길이다 */
  keys: string[]
  rule_id: string
  rule_name: string
  /** 묶인 사건 가운데 가장 높은 심각도 */
  severity: string
  actor_ip: string | null
  target: string | null
  /** 장비 합집합(id + 나눔), 보호 대상 먼저 */
  devices: IncidentDevice[]
}

export interface WatcherDeps {
  fetchList: (signal: AbortSignal) => Promise<Pick<IncidentPage, 'items'>>
  fetchDetail: (key: string, signal: AbortSignal) => Promise<IncidentBase>
  /** 알림 목록이 바뀌면 부른다(새 배열) */
  onChange: (toasts: NewIncidentToast[]) => void
  /** 새로 띄운 사건 수(묶여 들어간 사건 포함). 탭 제목 수에 쓴다 */
  onShown?: (count: number) => void
  /** 본 키. 훅이 ref 로 들고 넘긴다(감시기를 다시 만들어도 남는다) */
  seen?: Map<string, true>
  now?: () => number
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>
  clearTimer?: (id: ReturnType<typeof setTimeout>) => void
}

export interface NewIncidentWatcher {
  /** 실시간 통보 하나. incident.created 만 받는다 */
  receive: (message: LiveMessage) => void
  /** 알림 한 장을 닫는다 */
  dismiss: (id: string) => void
  /** 타이머를 지우고 진행 중인 확인을 버린다 */
  stop: () => void
}

/** 통보에서 받을 사건 키. incident.created 이고 1~1024자 문자열일 때만 */
export function incidentKeyOf(message: LiveMessage): string | null {
  if (message.type !== 'incident.created') return null
  const key = message.data?.incident_key
  return typeof key === 'string' && key.length >= 1 && key.length <= KEY_MAX ? key : null
}

export function groupKey(item: Pick<IncidentBase, 'rule_id' | 'actor_ip' | 'target'>): string {
  return `${item.rule_id}|${item.actor_ip ?? item.target ?? ''}`
}

/** 한 건은 그 사건, 묶음은 출발지가 있으면 규칙 · 출발지 목록, 없으면 마지막 사건 */
export function toastHref(toast: Pick<NewIncidentToast, 'keys' | 'rule_id' | 'actor_ip'>): string {
  if (toast.keys.length > 1 && toast.actor_ip) return `/incidents?${new URLSearchParams({ rule_id: toast.rule_id, actor_ip: toast.actor_ip })}`
  return `/incidents/${encodeURIComponent(toast.keys[toast.keys.length - 1] ?? '')}`
}

function textOr(v: unknown, fallback: string): string {
  return typeof v === 'string' ? v : fallback
}

function orNull(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null
}

/** 모르는 심각도는 가장 낮게 본다 */
function severityRank(s: string): number {
  const i = (SEVERITIES as readonly string[]).indexOf(s)
  return i < 0 ? SEVERITIES.length : i
}

/** 같은 장비(id + 나눔)는 앞의 것만 두고, 보호 대상을 앞으로(안정 정렬) */
function unionDevices(a: readonly IncidentDevice[], b: unknown): IncidentDevice[] {
  const out: IncidentDevice[] = []
  const keys = new Set<string>()
  for (const d of [...a, ...(Array.isArray(b) ? b : [])] as unknown[]) {
    if (typeof d !== 'object' || d === null) continue
    const device = d as IncidentDevice
    const key = deviceKey(device)
    if (keys.has(key)) continue
    keys.add(key)
    out.push(device)
  }
  return out.sort((x, y) => Number(y.group === 'protected') - Number(x.group === 'protected'))
}

function isIncident(v: unknown): v is IncidentBase {
  return typeof v === 'object' && v !== null && typeof (v as IncidentBase).incident_key === 'string' && typeof (v as IncidentBase).rule_id === 'string'
}

/** 다음 회차에 다시 볼 실패: 5xx · 네트워크 · 시간 초과. 4xx(없음 · 권한)는 다시 봐도 같다 */
function worthRetry(error: unknown): boolean {
  return isApiError(error) && (error.retryable || error.kind === 'timeout')
}

export function createNewIncidentWatcher(deps: WatcherDeps): NewIncidentWatcher {
  const now = deps.now ?? (() => Date.now())
  const setTimer = deps.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms))
  const clearTimer = deps.clearTimer ?? ((id: ReturnType<typeof setTimeout>) => clearTimeout(id))
  const seen = deps.seen ?? new Map<string, true>()
  /** 확인을 기다리는 키 → 지난 회차 수 */
  const pending = new Map<string, number>()
  let toasts: NewIncidentToast[] = []
  let timer: ReturnType<typeof setTimeout> | undefined
  let firstAt: number | undefined
  let lastAt = 0
  let running = false
  let stopped = false
  let controller: AbortController | undefined

  function settle(key: string) {
    pending.delete(key)
    seen.set(key, true)
    for (const oldest of seen.keys()) {
      if (seen.size <= SEEN_LIMIT) break
      seen.delete(oldest)
    }
  }

  function defer(key: string) {
    const attempts = (pending.get(key) ?? 0) + 1
    if (attempts >= MAX_ATTEMPTS) settle(key)
    else pending.set(key, attempts)
  }

  function schedule() {
    if (stopped || running || pending.size === 0) return
    if (timer !== undefined) clearTimer(timer)
    const at = Math.min(lastAt + QUIET_MS, (firstAt ?? lastAt) + MAX_WAIT_MS)
    timer = setTimer(() => void run(), Math.max(0, at - now()))
  }

  function fresh(item: IncidentBase, at: number): NewIncidentToast {
    return {
      id: item.incident_key,
      group: groupKey(item),
      openedAt: at,
      version: 0,
      keys: [item.incident_key],
      rule_id: item.rule_id,
      rule_name: textOr(item.rule_name, ''),
      severity: textOr(item.severity, ''),
      actor_ip: orNull(item.actor_ip),
      target: orNull(item.target),
      devices: unionDevices([], item.devices),
    }
  }

  function merge(toast: NewIncidentToast, item: IncidentBase): NewIncidentToast {
    const severity = textOr(item.severity, '')
    return {
      ...toast,
      version: toast.version + 1,
      keys: [...toast.keys, item.incident_key],
      severity: severityRank(severity) < severityRank(toast.severity) ? severity : toast.severity,
      devices: unionDevices(toast.devices, item.devices),
    }
  }

  function show(items: readonly IncidentBase[]) {
    let next = toasts
    let shown = 0
    for (const item of items) {
      if (!hasConfirmedProtected(item.devices)) continue
      shown += 1
      const at = now()
      const group = groupKey(item)
      const open = next.find((t) => t.group === group && at - t.openedAt < GROUP_MS)
      next = open ? next.map((t) => (t === open ? merge(t, item) : t)) : [fresh(item, at), ...next].slice(0, MAX_TOASTS)
    }
    if (shown === 0) return
    toasts = next
    deps.onChange(toasts)
    deps.onShown?.(shown)
  }

  async function run() {
    timer = undefined
    if (stopped || running || pending.size === 0) return
    running = true
    firstAt = undefined
    const batch = [...pending.keys()]
    const ctrl = new AbortController()
    controller = ctrl
    try {
      let items: IncidentBase[] | null = null
      let listError: unknown
      try {
        const page = await deps.fetchList(ctrl.signal)
        items = Array.isArray(page?.items) ? page.items.filter(isIncident) : []
      } catch (error) {
        listError = error
      }
      if (stopped) return

      const found: IncidentBase[] = []
      const outside: string[] = []
      const byKey = new Map((items ?? []).map((item) => [item.incident_key, item]))
      for (const key of batch) {
        const item = byKey.get(key)
        if (item) {
          found.push(item)
          settle(key)
        } else if (items) outside.push(key)
        else if (worthRetry(listError)) defer(key)
        else settle(key)
      }

      const tried = outside.slice(0, DETAIL_LIMIT)
      const results = await Promise.allSettled(tried.map((key) => deps.fetchDetail(key, ctrl.signal)))
      if (stopped) return
      results.forEach((result, i) => {
        const key = tried[i]
        if (result.status === 'fulfilled') {
          if (isIncident(result.value) && result.value.incident_key === key) found.push(result.value)
          settle(key)
        } else if (worthRetry(result.reason)) defer(key)
        else settle(key)
      })
      for (const key of outside.slice(DETAIL_LIMIT)) defer(key)

      // 받은 순서(통보 순서)로 띄운다
      const order = new Map(batch.map((key, i) => [key, i]))
      show(found.sort((a, b) => (order.get(a.incident_key) ?? 0) - (order.get(b.incident_key) ?? 0)))
    } finally {
      running = false
      if (controller === ctrl) controller = undefined
      if (!stopped && pending.size > 0) {
        // 넘긴 키만 남았으면 지금부터 다시 기다린다(곧바로 되풀이하지 않는다)
        if (firstAt === undefined) firstAt = lastAt = now()
        schedule()
      }
    }
  }

  return {
    receive(message) {
      if (stopped) return
      const key = incidentKeyOf(message)
      if (key === null || seen.has(key) || pending.has(key)) return
      pending.set(key, 0)
      const at = now()
      firstAt ??= at
      lastAt = at
      schedule()
    },
    dismiss(id) {
      const next = toasts.filter((t) => t.id !== id)
      if (next.length === toasts.length) return
      toasts = next
      deps.onChange(toasts)
    },
    stop() {
      stopped = true
      if (timer !== undefined) clearTimer(timer)
      timer = undefined
      controller?.abort()
    },
  }
}

export interface NewIncidentToastsOptions {
  /** 새로 띄운 사건 수(탭 제목 수) */
  onShown?: (count: number) => void
  /** 시험에서 바꿔 끼우는 조회 · 시각 · 타이머 */
  deps?: Partial<Pick<WatcherDeps, 'fetchList' | 'fetchDetail' | 'now' | 'setTimer' | 'clearTimer'>>
}

export interface NewIncidentToastsState {
  toasts: NewIncidentToast[]
  /** useLiveUpdates 의 onMessage 로 넘긴다 */
  onLiveMessage: (message: LiveMessage) => void
  dismiss: (id: string) => void
}

/** 확인 목록. 대조만 하고 캐시에는 넣지 않는다 */
function fetchRecent(signal: AbortSignal): Promise<IncidentPage> {
  return fetchIncidents({ sort: 'recent' }, 0, signal, LIST_SIZE)
}

/**
 * 새 사건 알림 훅. 틀(AppLayout)이 로그인을 확인한 뒤(enabled) 한 번 부르고, onLiveMessage 를 useLiveUpdates 에 넘긴다.
 * 상세는 상세 화면과 같은 캐시 키로 받는다(열면 다시 받지 않는다).
 */
export function useNewIncidentToasts(enabled: boolean, options: NewIncidentToastsOptions = {}): NewIncidentToastsState {
  const queryClient = useQueryClient()
  const [toasts, setToasts] = useState<NewIncidentToast[]>([])
  const seenRef = useRef<Map<string, true> | null>(null)
  const watcherRef = useRef<NewIncidentWatcher | null>(null)
  const optionsRef = useRef(options)

  useEffect(() => {
    optionsRef.current = options
  })

  useEffect(() => {
    if (!enabled) return
    seenRef.current ??= new Map()
    const deps = optionsRef.current.deps ?? {}
    const watcher = createNewIncidentWatcher({
      fetchList: deps.fetchList ?? fetchRecent,
      fetchDetail:
        deps.fetchDetail ??
        ((key) => queryClient.fetchQuery({ queryKey: incidentKeys.detail(key), queryFn: ({ signal }) => fetchIncident(key, signal), staleTime: 60_000 })),
      onChange: setToasts,
      onShown: (count) => optionsRef.current.onShown?.(count),
      seen: seenRef.current,
      now: deps.now,
      setTimer: deps.setTimer,
      clearTimer: deps.clearTimer,
    })
    watcherRef.current = watcher
    return () => {
      watcher.stop()
      if (watcherRef.current === watcher) watcherRef.current = null
      setToasts([])
    }
  }, [enabled, queryClient])

  const onLiveMessage = useCallback((message: LiveMessage) => watcherRef.current?.receive(message), [])
  const dismiss = useCallback((id: string) => watcherRef.current?.dismiss(id), [])
  return { toasts, onLiveMessage, dismiss }
}
