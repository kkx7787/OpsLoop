import { notifyManager, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { useCallback, useSyncExternalStore } from 'react'
import { api } from './client'
import { ApiError, isApiError } from './errors'
import type { DetectPathVersion } from './health'
import { shouldRetry } from './queryClient'

/**
 * 보호 대상 장비의 최근 로그(#73). 서버 계약은 app/node_logs.py.
 *  GET /api/devices/{id}/logs?kind=&src_ip=&status=&limit= → DeviceLogsResult
 * 대상은 web-01 과 등록 노드뿐이다(그 밖은 404 '보호 대상 장비를 찾을 수 없습니다'). 발생원은 관문이 인증한 node_id 다.
 * 글자 칸(url · user_agent · message · username · http_method)은 서버가 이미 가려서 보낸다. 비밀번호는 있었는지만 온다.
 * 화면은 5초마다 최근 창을 다시 받아 줄 id 로 합친다(log-format.ts mergeLines). 새 줄은 1분 적재 회차로 들어온다.
 * 대시보드 보호 대상 카드(#83)는 같은 경로에서 최근 10줄을 10초마다 받는다(조회 키에 줄 수를 넣어 로그 화면과 캐시를 나눈다).
 */

export const LOG_KINDS = ['web', 'ssh'] as const
export type LogKind = (typeof LOG_KINDS)[number]

/** 서버 KIND_LABEL 과 같다(targets.PREFIX_KIND) */
export const LOG_KIND_LABEL: Readonly<Record<LogKind, string>> = { web: '웹 접근', ssh: 'SSH 인증' }
/** 좁은 카드 로그 칸(#83)의 짧은 표기. 전체 이름은 낭독용으로 함께 둔다 */
export const LOG_KIND_SHORT: Readonly<Record<LogKind, string>> = { web: '웹', ssh: 'SSH' }

export function isLogKind(v: unknown): v is LogKind {
  return v === 'web' || v === 'ssh'
}

/** 줄 한 행. 글자 칸은 가린 값이고 비신뢰다. 해당 없는 칸은 null */
export interface DeviceLogLine {
  /** 줄 해시에서 만든 HMAC 32자. 같은 줄은 같은 id 다 */
  id: string
  /** 장비가 줄에 적은 요청 시각. 마이크로초까지 고정 자릿수(UTC)라 글자로 견준다 */
  ts: string
  kind: LogKind
  eventid: string
  src_ip: string | null
  src_port: number | null
  http_method: string | null
  url: string | null
  http_status: number | null
  user_agent: string | null
  username: string | null
  /** 비밀번호 열에 값이 있었는가(원문은 오지 않는다) */
  has_password: boolean
  message: string | null
}

/** 로그 종류별 마지막 줄. state 가 ok 가 아니면 declared · last_line_at 이 null 이다 */
export interface DeviceLogTimeLine {
  key: LogKind
  job: string
  label: string
  /** job ∈ nodes.logs */
  declared: boolean | null
  /** nodes.receipt[job].last_line_at: 에이전트가 읽은 시각. 목록에 없는 줄(시험 · 형식 밖 · sshd 외)도 올린다 */
  last_line_at: string | null
}

/** 이 장비 탐지 경로(1분 다리)의 마지막 탐지. last_at 은 관련 버전 가운데 가장 오래된 값이다 */
export interface DeviceLogDetect {
  last_at: string | null
  stale: boolean
  /** 멈췄을 때의 글(관제 이상 항목과 같다). 멈춤이 아니면 null */
  reason: string | null
  versions: DetectPathVersion[]
}

export type DeviceLogTimesState = 'ok' | 'no_node' | 'unreadable'

/** 시각 네 가지 가운데 셋(화면 갱신은 as_of) */
export interface DeviceLogTimes {
  state: DeviceLogTimesState
  /** nodes.last_loaded_at: 다리가 이 노드에서 새 줄을 넣은 마지막 회차 */
  loaded_at: string | null
  lines: DeviceLogTimeLine[]
  detect: DeviceLogDetect
}

export interface DeviceLogsResult {
  /** DB now(). 화면 갱신 시각 · 상대 시각의 기준 */
  as_of: string
  /** label 은 등록 노드의 hostname 이라 비신뢰다 */
  device: { id: string; label: string; kind: 'fixed' | 'node' }
  limit: number
  window_days: number
  filters: { kind: LogKind | null; src_ip: string | null; status: number | null }
  kinds: Array<{ key: LogKind; label: string }>
  times: DeviceLogTimes
  /** 5분 넘게 앞선 시각이라 목록에서 뺀 줄 수. 1,001 에서 멈춘다(FUTURE_CAP) */
  future: number
  /** (ts, id) 내림차순 */
  items: DeviceLogLine[]
}

/** 화면이 보내는 조건. 값이 없으면 조건 없음 */
export interface DeviceLogFilters {
  kind?: LogKind
  src_ip?: string
  status?: number
}

/** 한 번에 받는 최신 줄 수(화면은 고정) */
export const DEVICE_LOGS_LIMIT = 100
/** 서버가 앞선 시각 줄을 세다 멈추는 값. 이 값이면 '1,000건 넘게' 다 */
export const FUTURE_CAP = 1001
/** 서버의 404 문장(node_logs.NOT_FOUND). 이 문장이면 보호 대상이 아니거나 폐기된 장비다 */
export const DEVICE_NOT_FOUND = '보호 대상 장비를 찾을 수 없습니다'
/** 이 경로를 모르는 서버(FastAPI 기본 404)의 안내. TARGETS_NOT_DEPLOYED 와 같은 꼴이다 */
export const LOGS_NOT_DEPLOYED = '장비 로그 API 가 없습니다. 콘솔 API 배포 전일 수 있습니다.'

export function deviceLogsPath(id: string): string {
  return `/api/devices/${encodeURIComponent(id)}/logs`
}

/** 응답 코드 조건은 100..599 정수만 보낸다(그 밖은 서버가 영어 검증 문장으로 답한다) */
export function isHttpStatus(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 599
}

/** 보낼 쿼리. 모르는 종류 · 범위 밖 코드 · 빈 출발지는 빼고, limit 은 로그 화면 100 · 대시보드 카드 10 이다 */
export function deviceLogsQuery(filters: DeviceLogFilters, limit: number = DEVICE_LOGS_LIMIT): Record<string, string | number> {
  const query: Record<string, string | number> = {}
  if (isLogKind(filters.kind)) query.kind = filters.kind
  const src = filters.src_ip?.trim()
  if (src) query.src_ip = src
  if (isHttpStatus(filters.status)) query.status = filters.status
  query.limit = limit
  return query
}

/** 받은 뒤에 와도 그 장비는 보호 대상이 아니다(폐기 · 발생원 겹침) */
export function isDeviceNotFound(error: unknown): boolean {
  return isApiError(error) && error.status === 404 && error.detail === DEVICE_NOT_FOUND
}

/** 서버 문장이 아닌 404 는 이 경로가 없는 서버다(fetchDeviceLogs 가 LOGS_NOT_DEPLOYED 로 바꿔 던진다) */
export function isLogsNotDeployed(error: unknown): boolean {
  return isApiError(error) && error.status === 404 && error.detail !== DEVICE_NOT_FOUND
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** 합치기 · 시각 칸이 기대는 칸만 본다. 모양이 다른 응답을 빈 목록으로 꾸미지 않는다 */
function isResult(data: unknown): data is DeviceLogsResult {
  if (!isRecord(data) || typeof data.as_of !== 'string' || !isRecord(data.device) || typeof data.device.id !== 'string' || typeof data.device.label !== 'string') return false
  if (typeof data.limit !== 'number' || typeof data.window_days !== 'number' || typeof data.future !== 'number' || !Array.isArray(data.items)) return false
  const times = data.times
  if (!isRecord(times) || !Array.isArray(times.lines) || !isRecord(times.detect)) return false
  return data.items.every((item) => isRecord(item) && typeof item.id === 'string' && typeof item.ts === 'string')
}

export async function fetchDeviceLogs(id: string, filters: DeviceLogFilters, signal?: AbortSignal, limit: number = DEVICE_LOGS_LIMIT): Promise<DeviceLogsResult> {
  let data: unknown
  try {
    data = await api.get<unknown>(deviceLogsPath(id), { signal, query: deviceLogsQuery(filters, limit) })
  } catch (error) {
    // 서버 문장이 아닌 404 는 이 경로를 모르는 이전 서버다. '찾을 수 없음' 대신 배포 전으로 읽히게 한다
    if (isLogsNotDeployed(error)) throw new ApiError({ status: 404, detail: LOGS_NOT_DEPLOYED, body: (error as ApiError).body, cause: error })
    throw error
  }
  if (!isResult(data)) {
    throw new ApiError({ status: 0, kind: 'parse', detail: '서버의 장비 로그 응답을 해석할 수 없습니다. 콘솔 API 배포를 확인해 주세요.' })
  }
  return data
}

/** 다시 보내도 같은 답인 오류(HTTP 4xx: 없는 장비 · 배포 전 · 입력 오류 · 권한). 주기 · 초점 조회를 멈춘다('다시 시도' 는 된다) */
export function isFinalError(error: unknown): boolean {
  return isApiError(error) && error.kind === 'http' && error.status >= 400 && error.status < 500
}

/** 조회 키. 줄 수를 넣어 로그 화면(100)과 대시보드 카드(10)의 캐시를 나눈다 */
export function deviceLogsKey(id: string, filters: DeviceLogFilters, limit: number = DEVICE_LOGS_LIMIT) {
  return ['device-logs', id, { kind: filters.kind ?? null, src_ip: filters.src_ip ?? null, status: filters.status ?? null }, limit] as const
}

/** 주기 조회 간격 */
export const DEVICE_LOGS_INTERVAL = 5_000
/** 대시보드 보호 대상 카드(#83)의 최근 로그: 10줄 · 카드가 보이고 탭이 앞일 때 10초마다 */
export const CARD_LOGS_LIMIT = 10
export const CARD_LOGS_INTERVAL = 10_000

export interface DeviceLogsOptions {
  /** 받을 줄 수. 기본 100(로그 화면) */
  limit?: number
  /** 주기 조회 간격. 기본 5초(로그 화면) */
  interval?: number
  /** 화면에 보이는가(카드가 스크롤 밖이면 false). 안 보이면 주기 · 초점 · 재연결 조회를 끈다. 기본 true */
  visible?: boolean
}

/** 주기 · 초점 · 재연결 조회 설정이 보는 조회 상태 */
interface QueryLike {
  state: { error: unknown }
}

/**
 * 조회 설정. 5초마다 다시 받되 숨은 탭에서는 멈춘다(돌아오면 초점 조회가 한 번 돈다).
 * 일시정지면 주기 · 초점 · 재연결 조회를 모두 끈다. 조건이 바뀌면(새 key) 한 번은 받는다.
 * 마지막 조회가 4xx 면 주기 · 초점 · 재연결 조회도 멈춘다: 받은 적 없는 조회를 다시 보내면 react-query 가 오류를 비우고 받는 중으로 돌아가
 * '찾을 수 없음' 화면이 5초마다 깜빡이고, 같은 404 · 422 를 계속 보내게 된다.
 * 브라우저가 오프라인이어도 보낸다(networkMode 'always'). 기본('online')은 조회를 오류 없이 멈춰(paused) 갱신 실패 경고 · 흐림이 켜지지 않고
 * 화면 갱신 칸이 '5초마다' 로 남는다. 보내면 네트워크 오류가 되어 갱신 실패로 보인다.
 * 이전 조건의 줄이 새 조건 아래에 보이지 않도록 placeholderData 는 쓰지 않는다.
 * 켜짐(enabled)은 두지 않아 늘 켜져 있다. 그래서 새로고침(전체 invalidate)은 일시정지 · 안 보이는 카드의 로그도 한 번 받고,
 * 멈춤은 주기 조회만 끄므로 그대로 남는다(#83)
 */
export function deviceLogsQueryOptions(id: string, filters: DeviceLogFilters, paused: boolean, { limit = DEVICE_LOGS_LIMIT, interval = DEVICE_LOGS_INTERVAL, visible = true }: DeviceLogsOptions = {}) {
  const auto = !paused && visible
  return {
    queryKey: deviceLogsKey(id, filters, limit),
    queryFn: ({ signal }: { signal?: AbortSignal }) => fetchDeviceLogs(id, filters, signal, limit),
    refetchInterval: (query: QueryLike) => (!auto || isFinalError(query.state.error) ? false : interval),
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: (query: QueryLike) => auto && !isFinalError(query.state.error),
    refetchOnReconnect: (query: QueryLike) => auto && !isFinalError(query.state.error),
    networkMode: 'always' as const,
    staleTime: 4_000,
    retry: shouldRetry,
  }
}

export function useDeviceLogs(id: string, filters: DeviceLogFilters, paused: boolean, options?: DeviceLogsOptions) {
  return useQuery(deviceLogsQueryOptions(id, filters, paused, options))
}

/** 대시보드 카드 로그 조회(#83): 조건 없이 최근 10줄 · 10초 */
export function useCardLogs(id: string, paused: boolean, visible: boolean) {
  return useDeviceLogs(id, {}, paused, { limit: CARD_LOGS_LIMIT, interval: CARD_LOGS_INTERVAL, visible })
}

/**
 * 지금 화면에 걸린(활성) 카드 로그 조회 가운데 마지막 조회가 실패한 것이 있는가(#83 상단 '일부 갱신 실패').
 * 떠난 화면 · 접힌 카드의 남은 캐시(비활성)는 세지 않는다. 다시 보내도 같은 답인 4xx(없는 장비 · 배포 전)는 카드 안 글로만 보이고 세지 않는다
 */
export function cardLogsFailed(client: QueryClient): boolean {
  return client
    .getQueryCache()
    .findAll({ queryKey: ['device-logs'] })
    .some((query) => {
      const { error, status, errorUpdatedAt, dataUpdatedAt } = query.state
      if (query.queryKey[3] !== CARD_LOGS_LIMIT || !query.isActive() || isFinalError(error)) return false
      return status === 'error' || errorUpdatedAt > dataUpdatedAt
    })
}

/** cardLogsFailed 를 조회 캐시 변화마다 다시 잰다(useIsFetching 과 같은 구독) */
export function useCardLogsFailed(): boolean {
  const client = useQueryClient()
  const subscribe = useCallback((onChange: () => void) => client.getQueryCache().subscribe(notifyManager.batchCalls(onChange)), [client])
  const snapshot = useCallback(() => cardLogsFailed(client), [client])
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}
