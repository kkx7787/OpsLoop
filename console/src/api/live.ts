import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { ctiKeys } from './cti'
import { incidentKeys, ruleKeys } from './incidents'
import { nodeKey, auditKey } from './operations'
import { monitoringKeys } from './monitoring-keys'

/**
 * 실시간 통보(WS /ws). 서버는 접속하면 {type:'hello', data:{channel, console}} 을 보내고, 그 뒤로 사건 · 판정 · 조치가 생길 때마다 알린다.
 * 화면은 통보의 내용을 그리지 않고, 해당 쿼리를 무효화해 REST 로 다시 받는다(통보는 식별자와 요약뿐이다).
 *  incident.created                → 목록
 *  verdict.created · action.created → 그 사건의 상세 + 목록 (판정은 규칙 품질도). 키가 없으면(서버가 8000 바이트를 넘겨 뺐다) 목록만
 *  resync                          → 전부 다시 조회(서버의 DB 통보 연결이 끊겼다 다시 붙었다. 끊긴 동안의 통보는 오지 않는다)
 * 판정 · 조치 통보는 DB(pg_notify)를 거쳐 모든 콘솔이 보낸다. 어느 콘솔에 붙어도 같은 통보를 받는다.
 * 같은 출처 쿠키로 인증한다. 끊기면 지수 백오프(1초 → 2배 → 최대 30초)로 다시 잇고, 다시 이어지면 resync 와 같이 전부 다시 조회한다.
 * 세션이 없으면 서버가 연결을 받은 뒤 1008 로 닫는다. 다시 잇지 않고 /api/me 를 다시 물어 401 이면 로그인으로 보낸다.
 */

export interface LiveMessage {
  type: string
  data?: Record<string, unknown>
}

export type LiveStatus =
  | 'connecting' // 처음 잇는 중
  | 'connected'
  | 'reconnecting' // 끊겨서 기다리는 중 · 다시 잇는 중
  | 'closed' // 서버가 거부해(1008) 더 잇지 않는다

export interface LiveState {
  status: LiveStatus
  /** 마지막 연결 뒤 다시 이은 횟수. 이어지면 0 */
  retries: number
  /**
   * 마지막으로 hello 를 보낸 콘솔 이름(서버 OPSLOOP_WORKER · 없으면 호스트 이름). 서버가 주는 원문 그대로다.
   * 끊겨도 남겨 두어 표시가 흐리게 보이고, 새 연결이 열리면 지웠다가 그 연결의 hello 로 다시 채운다.
   * REST 요청은 콘솔 두 대에 번갈아 가므로 /api/me 의 console 이 아니라 이 값이 '실시간을 받는 콘솔'이다.
   */
  console?: string
}

/** 시험에서 바꿔 끼우려고 WebSocket 에서 쓰는 만큼만 잘랐다 */
export interface LiveSocket {
  addEventListener(type: 'open' | 'message' | 'close' | 'error', listener: (ev: Event) => void): void
  close(code?: number, reason?: string): void
}

export type LiveSocketFactory = (url: string) => LiveSocket

export interface LiveOptions {
  /** 기본은 같은 출처의 /ws */
  url?: string
  socket?: LiveSocketFactory
  onState?: (state: LiveState) => void
  baseDelayMs?: number
  maxDelayMs?: number
}

export const BASE_DELAY_MS = 1_000
export const MAX_DELAY_MS = 30_000

/** 세션 없음(정책 위반). 서버(ws_endpoint)가 쿠키가 없거나 만료됐을 때 연결을 받은 뒤 이 코드로 닫는다 */
export const CLOSE_UNAUTHORIZED = 1008

/** auth/useMe 의 meQueryKey 와 같다(api 가 auth 를 가져오지 않게 따로 적는다) */
const ME_KEY = ['me'] as const

/**
 * 재접속 · resync 때 다시 조회하는 쿼리. 끊긴 동안의 통보는 다시 오지 않으므로 현재 상태를 통째로 다시 받는다.
 * CVE · KEV 연계(ctiKeys)는 통보가 없고 하루 단위로 바뀌지만, 오래 끊겼다 이어진 뒤에는 신선도를 다시 맞춘다.
 * /api/me 는 끊긴 동안 세션이 끝났으면 401 을 받아 로그인으로 보내려고 넣는다.
 */
export const RESYNC_KEYS = [
  incidentKeys.all,
  ruleKeys.all,
  monitoringKeys.summary,
  monitoringKeys.blocklist,
  nodeKey,
  auditKey,
  ctiKeys.all,
  ME_KEY,
] as const

/** 콘솔 이름의 화면 표기. 정해 둔 두 대만 '콘솔 A' · '콘솔 B' 로 바꾸고, 그 밖은 null(원문을 비신뢰 문자열로 그린다) */
export function consoleLabel(name: string): string | null {
  const match = /^opsloop-console-([ab])$/.exec(name)
  return match ? `콘솔 ${match[1].toUpperCase()}` : null
}

/** 같은 출처의 /ws. https 면 wss */
export function wsUrl(location: Pick<Location, 'protocol' | 'host'> = window.location): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${location.host}/ws`
}

/** n 번째 재시도까지의 대기(ms): base · 2^n, 최대 max */
export function backoffMs(attempt: number, base = BASE_DELAY_MS, max = MAX_DELAY_MS): number {
  return Math.min(max, base * 2 ** Math.max(0, attempt))
}

export function parseLiveMessage(raw: unknown): LiveMessage | null {
  if (typeof raw !== 'string') return null
  try {
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object' || typeof (parsed as { type?: unknown }).type !== 'string') return null
    const data = (parsed as { data?: unknown }).data
    return { type: (parsed as { type: string }).type, data: data && typeof data === 'object' ? (data as Record<string, unknown>) : undefined }
  } catch {
    return null
  }
}

/** 끊긴 동안 놓쳤을 수 있는 것을 전부 다시 조회한다(재접속 · resync) */
export function resyncAll(queryClient: QueryClient): void {
  for (const queryKey of RESYNC_KEYS) void queryClient.invalidateQueries({ queryKey })
}

/** hello 의 콘솔 이름. 문자열이 아니거나 비었으면 없는 것으로 본다 */
export function helloConsole(message: LiveMessage): string | undefined {
  if (message.type !== 'hello') return undefined
  const name = message.data?.console
  return typeof name === 'string' && name !== '' ? name : undefined
}

/** 통보 하나를 쿼리 무효화로 옮긴다. 모르는 종류(hello 포함)는 지나친다 */
export function applyLiveMessage(queryClient: QueryClient, message: LiveMessage): void {
  const key = message.data?.incident_key
  switch (message.type) {
    case 'resync':
      resyncAll(queryClient)
      return
    case 'incident.created':
      void queryClient.invalidateQueries({ queryKey: incidentKeys.lists() })
      void queryClient.invalidateQueries({ queryKey: monitoringKeys.summary })
      return
    case 'verdict.created':
    case 'action.created':
      if (typeof key === 'string' && key) void queryClient.invalidateQueries({ queryKey: incidentKeys.detail(key) })
      void queryClient.invalidateQueries({ queryKey: incidentKeys.lists() })
      if (message.type === 'verdict.created') void queryClient.invalidateQueries({ queryKey: ruleKeys.quality() })
      void queryClient.invalidateQueries({ queryKey: monitoringKeys.summary })
      if (message.type === 'action.created') {
        void queryClient.invalidateQueries({ queryKey: monitoringKeys.blocklist })
        void queryClient.invalidateQueries({ queryKey: auditKey })
      }
      return
    default:
      return
  }
}

/**
 * 연결을 열고 끊기면 다시 잇는다. 돌려주는 함수를 부르면 멈춘다(타이머 취소 · 소켓 닫기, 다시 잇지 않음).
 * React 밖에서도 쓸 수 있게 훅과 떼어 둔다(시험 · 다른 진입점).
 */
export function connectLive(queryClient: QueryClient, options: LiveOptions = {}): () => void {
  const url = options.url ?? wsUrl()
  const makeSocket: LiveSocketFactory = options.socket ?? ((u) => new WebSocket(u))
  const base = options.baseDelayMs ?? BASE_DELAY_MS
  const max = options.maxDelayMs ?? MAX_DELAY_MS

  let socket: LiveSocket | null = null
  let timer: ReturnType<typeof setTimeout> | undefined
  let retries = 0
  let stopped = false
  let connectedBefore = false
  let status: LiveStatus = 'connecting'
  let consoleName: string | undefined

  const emit = (next: LiveStatus) => {
    status = next
    options.onState?.(consoleName === undefined ? { status, retries } : { status, retries, console: consoleName })
  }

  function schedule() {
    emit('reconnecting')
    const delay = backoffMs(retries, base, max)
    retries += 1
    timer = setTimeout(open, delay)
  }

  function open() {
    if (stopped) return
    const current = makeSocket(url)
    socket = current
    // 닫힌 옛 소켓의 늦은 이벤트가 새 연결의 상태를 덮지 않게 지금 소켓인지 본다.
    const mine = () => socket === current && !stopped

    current.addEventListener('open', () => {
      if (!mine()) return
      // 끊긴 동안의 통보는 다시 오지 않으므로 재접속 때 현재 상태를 재조회한다(RESYNC_KEYS)
      if (connectedBefore) resyncAll(queryClient)
      connectedBefore = true
      retries = 0
      // 다른 콘솔에 붙었을 수 있다. 이 연결의 hello 가 올 때까지 이름을 비운다
      consoleName = undefined
      emit('connected')
    })
    current.addEventListener('message', (ev) => {
      if (!mine()) return
      const message = parseLiveMessage((ev as MessageEvent).data)
      if (!message) return
      if (message.type === 'hello') {
        consoleName = helloConsole(message)
        emit(status)
        return
      }
      applyLiveMessage(queryClient, message)
    })
    current.addEventListener('close', (ev) => {
      if (!mine()) return
      socket = null
      const code = typeof (ev as CloseEvent).code === 'number' ? (ev as CloseEvent).code : 0
      if (code === CLOSE_UNAUTHORIZED) {
        // 세션이 끝났다. /api/me 를 다시 물어 401 이면 API 클라이언트가 로그인으로 보낸다
        emit('closed')
        void queryClient.invalidateQueries({ queryKey: ME_KEY })
        return
      }
      schedule()
    })
    // 오류 뒤에는 close 가 따라오므로 여기서 따로 하지 않는다.
    current.addEventListener('error', () => undefined)
  }

  emit('connecting')
  open()

  return () => {
    stopped = true
    if (timer !== undefined) clearTimeout(timer)
    const current = socket
    socket = null
    current?.close()
  }
}

/**
 * 실시간 통보를 한 번 연결해 쿼리를 무효화한다. 화면 틀(AppLayout)이 한 번 부른다.
 * 돌려주는 상태로 상단바가 연결 표시(끊김 배지 · S-10 · 붙은 콘솔)를 그린다.
 */
export function useLiveUpdates(options: Pick<LiveOptions, 'url' | 'socket'> = {}): LiveState {
  const queryClient = useQueryClient()
  const { url, socket } = options
  const [state, setState] = useState<LiveState>({ status: 'connecting', retries: 0 })

  useEffect(() => connectLive(queryClient, { url, socket, onState: setState }), [queryClient, url, socket])

  return state
}
