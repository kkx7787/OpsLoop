import type { DeviceLogLine, DeviceLogsResult } from '@/api/device-logs'

/**
 * 장비 최근 로그(#73) 픽스처. 기준 시각은 LOGS_AS_OF(2026-09-30 14:00:05 KST).
 * 줄 시각은 서버처럼 마이크로초까지 고정 자릿수(UTC)다. 줄 글자는 서버가 이미 가린 값이다.
 */

export const LOGS_AS_OF = '2026-09-30T05:00:05.123456+00:00'

/** 기준 시각에서 초 단위로 앞선 줄 시각(고정 자릿수) */
export function secondsAgo(seconds: number): string {
  return new Date(Date.parse(LOGS_AS_OF) - seconds * 1000).toISOString().replace('Z', '000+00:00')
}

/** 32자 16진 줄 id. n 이 클수록 id 도 크다 */
export function lineId(n: number): string {
  return n.toString(16).padStart(32, '0')
}

export function webLine(n: number, extra: Partial<DeviceLogLine> = {}): DeviceLogLine {
  return {
    id: lineId(n),
    ts: secondsAgo(1000 - n),
    kind: 'web',
    eventid: 'nginx.request',
    src_ip: '203.0.113.7',
    src_port: 51234,
    http_method: 'GET',
    url: '/search?q=…&page=…',
    http_status: 200,
    user_agent: 'curl/8.5.0',
    username: null,
    has_password: false,
    message: null,
    ...extra,
  }
}

export function sshLine(n: number, extra: Partial<DeviceLogLine> = {}): DeviceLogLine {
  return {
    id: lineId(n),
    ts: secondsAgo(1000 - n),
    kind: 'ssh',
    eventid: 'sshd.login.failed',
    src_ip: '198.51.100.9',
    src_port: 40022,
    http_method: null,
    url: null,
    http_status: null,
    user_agent: null,
    username: 'root',
    has_password: false,
    message: 'Failed password for root from 198.51.100.9 port 40022 ssh2',
    ...extra,
  }
}

export function logsResult(extra: Partial<DeviceLogsResult> = {}): DeviceLogsResult {
  return {
    as_of: LOGS_AS_OF,
    device: { id: 'web-01', label: 'web-01', kind: 'fixed' },
    limit: 100,
    window_days: 7,
    filters: { kind: null, src_ip: null, status: null },
    kinds: [
      { key: 'web', label: '웹 접근' },
      { key: 'ssh', label: 'SSH 인증' },
    ],
    times: {
      state: 'ok',
      loaded_at: '2026-09-30T04:59:41.002311+00:00',
      lines: [
        { key: 'web', job: 'nginx', label: '웹 접근', declared: true, last_line_at: '2026-09-30T04:59:30.120000+00:00' },
        { key: 'ssh', job: 'auth', label: 'SSH 인증', declared: true, last_line_at: null },
      ],
      detect: {
        last_at: '2026-09-30T04:59:43.500000+00:00',
        stale: false,
        reason: null,
        versions: [
          { rule_version: 'c1', last_at: '2026-09-30T04:59:43.500000+00:00', stale: false },
          { rule_version: 'sg1', last_at: '2026-09-30T04:59:50.000000+00:00', stale: false },
          { rule_version: 'w2', last_at: '2026-09-30T04:59:55.000000+00:00', stale: false },
        ],
      },
    },
    future: 0,
    items: [webLine(3), sshLine(2), webLine(1, { http_status: 404, url: '/reset/…(가림)?…' })].sort((a, b) => (a.ts < b.ts ? 1 : -1)),
    ...extra,
  }
}
