import { describe, expect, it } from 'vitest'
import type { TargetResponse } from '@/api/targets'
import { awsSensor, consoleTarget, dataNode, dataNodeStopped, minutesAgo, nodeTarget, web01 } from '@/test/targets-fixtures'
import type { TargetAssetVulns } from '@/api/targets'
import {
  collectionState,
  formatPct,
  groupTargets,
  headBadge,
  latestJudgedText,
  latestLog,
  orderTargets,
  pendingHref,
  protectedHeadBadge,
  responseParts,
  summaryFlags,
  summaryHeadBadge,
  summaryLineFlags,
  systemText,
  undeterminedHref,
  vulnSummary,
  vulnText,
} from './target-format'

const response = (extra: Partial<TargetResponse>): TargetResponse => ({ point: 'gateway', point_label: '허니팟 관문', applied: 0, unverified: 0, exempt: 0, report: null, ...extra })
const texts = (r: TargetResponse) => responseParts(r).map((p) => p.text)

/** 글 안의 홀로 선 숫자 0(‘0’ · ‘0건’ 등). '10' · '2026' 의 0 은 아니다 */
const ZERO = /(^|[^\d.,])0(?![\d.,])/

describe('대응 문구(#52): 숫자 0 을 그리지 않는다', () => {
  it('집행 지점이 있으면 적용 확인 · 미확인 · 정책상 제외 중 0 이 아닌 것만', () => {
    expect(texts(response({ applied: 2, unverified: 1, exempt: 3 }))).toEqual(['차단 적용 2 (허니팟 관문)', '차단 적용 여부 미확인 1', '정책상 차단 제외 3'])
    expect(texts(response({ applied: 0, unverified: 4, exempt: 0 }))).toEqual(['차단 적용 여부 미확인 4'])
    expect(texts(response({ applied: 5, point: 'fw', point_label: '내부 방화벽' }))).toEqual(['차단 적용 5 (내부 방화벽)'])
  })

  it('모두 0 이면 그 지점의 집행 대상 차단 없음(집행 제외 차단만 있어도 거짓이 아닌 문구)', () => {
    expect(texts(response({}))).toEqual(['허니팟 관문 집행 대상 차단 없음'])
    expect(texts(response({ applied: null, unverified: null }))).toEqual(['허니팟 관문 집행 대상 차단 없음'])
    expect(texts(response({ point: 'fw', point_label: '내부 방화벽', failed: 0 }))).toEqual(['내부 방화벽 집행 대상 차단 없음'])
  })

  it('지점이 거부한 차단은 미확인에 섞지 않고 실패(빨강)로 보인다', () => {
    const parts = responseParts(response({ point: 'fw', point_label: '내부 방화벽', applied: 1, failed: 2, unverified: 1 }))
    expect(parts.map((p) => [p.text, p.tone])).toEqual([
      ['차단 적용 1 (내부 방화벽)', 'success'], ['차단 적용 실패 2 (내부 방화벽)', 'danger'], ['차단 적용 여부 미확인 1', 'warning']])
  })

  it('집행기 확인이 멈추면 서버가 합친 미확인과 그 까닭을 보인다(초록 배지 없음)', () => {
    const parts = responseParts(response({ applied: 0, failed: 0, unverified: 5, stalled: '집행기 확인 중단 · 마지막 확인 12분 전' }))
    expect(parts.map((p) => [p.key, p.text, p.tone])).toEqual([
      ['unverified', '차단 적용 여부 미확인 5', 'warning'], ['stalled', '집행기 확인 중단 · 마지막 확인 12분 전', undefined]])
    // 요청이 없어도 멈춤은 알린다
    expect(texts(response({ stalled: '집행기 확인 기록 없음' }))).toEqual(['허니팟 관문 집행 대상 차단 없음', '집행기 확인 기록 없음'])
  })

  it('미요청 · 빠짐 확인 전(#77)은 적용 · 실패 · 미확인과 따로 보이고, 그것만 있으면 집행 대상 차단 없음이 아니다', () => {
    const parts = responseParts(response({ applied: 1, unrequested: 3, removing: 1, exempt: 2 }))
    expect(parts.map((p) => [p.key, p.text, p.tone])).toEqual([
      ['applied', '차단 적용 1 (허니팟 관문)', 'success'], ['unrequested', '차단 미요청 3 (허니팟 관문)', 'neutral'],
      ['removing', '차단 빠짐 확인 전 1 (허니팟 관문)', 'warning'], ['exempt', '정책상 차단 제외 2', 'neutral']])
    expect(texts(response({ removing: 1 }))).toEqual(['차단 빠짐 확인 전 1 (허니팟 관문)'])
    expect(texts(response({ unrequested: 2 }))).toEqual(['차단 미요청 2 (허니팟 관문)'])
    expect(texts(response({ unrequested: 0, removing: 0 }))).toEqual(['허니팟 관문 집행 대상 차단 없음'])
    expect(texts(response({ unrequested: null, removing: null }))).toEqual(['허니팟 관문 집행 대상 차단 없음'])
  })

  it('이전 서버(failed · stalled 없음)도 그린다', () => {
    expect(texts({ point: 'gateway', point_label: '허니팟 관문', applied: 2, unverified: 0, exempt: 0, report: null })).toEqual(['차단 적용 2 (허니팟 관문)'])
  })

  it('집행 지점이 없는 대상은 숫자 없이 미확인, 정책상 제외만 수를 붙인다', () => {
    expect(texts(response({ point: null, point_label: null, applied: null, unverified: null, exempt: 0 }))).toEqual(['차단 적용 여부 미확인'])
    expect(texts(response({ point: null, point_label: null, applied: null, unverified: null, exempt: 2 }))).toEqual(['차단 적용 여부 미확인', '정책상 차단 제외 2'])
  })

  it('적용 확인은 초록(집행 확인과 같은 색), 미확인은 주의색이다', () => {
    const parts = responseParts(response({ applied: 1, unverified: 1, exempt: 1 }))
    expect(parts.map((p) => p.tone)).toEqual(['success', 'warning', 'neutral'])
  })

  it('어떤 조합에서도 0 이 글에 들어가지 않는다', () => {
    for (const point of ['gateway', 'fw', null] as const) {
      for (const applied of [0, 1, null]) {
        for (const unverified of [0, 3, null]) {
          for (const failed of [0, 2, null, undefined]) {
            for (const exempt of [0, 10]) {
              for (const text of texts(response({ point, point_label: point ? '지점' : null, applied, failed, unverified, exempt }))) expect(text).not.toMatch(ZERO)
            }
          }
        }
      }
    }
  })
})

describe('수집 · 시스템 · 취약점 표기', () => {
  it('모르는 수집 상태는 미확인으로 읽는다(콘솔 응답 중은 아는 값, #76)', () => {
    expect(collectionState('ok')).toBe('ok')
    expect(collectionState('quiet')).toBe('quiet')
    expect(collectionState('no_signal')).toBe('no_signal')
    expect(collectionState('responding')).toBe('responding')
    expect(collectionState('down')).toBe('unknown')
    expect(collectionState(undefined)).toBe('unknown')
  })

  it('가장 최근 로그를 고르고 기록 없는 로그는 건너뛴다', () => {
    expect(latestLog(awsSensor().collection.logs)?.key).toBe('cowrie')
    expect(latestLog([{ key: 'a', label: 'A', last_at: null }])).toBeNull()
    expect(latestLog([{ key: 'a', label: 'A', last_at: minutesAgo(9) }, { key: 'b', label: 'B', last_at: minutesAgo(3) }])?.key).toBe('b')
  })

  it('자원 지표는 web-01 수치 한 줄, 수집하지 않는 까닭은 글로', () => {
    const w = web01()
    expect(systemText(w.system.state, w.system.metrics)).toBe('CPU 12% · 메모리 42% · 디스크 63%')
    expect(systemText('stale', { ts: minutesAgo(30), cpu_pct: null, mem_used_pct: 50, disk_root_pct: 70, load1: null })).toBe('CPU — · 메모리 50% · 디스크 70%')
    expect(systemText('not_collected', null)).toBe('자원 지표 미수집')
    expect(systemText('no_privilege', null)).toBe('자원 지표 읽기 권한 없음')
    expect(systemText('no_data', null)).toBe('자원 지표 없음')
    expect(systemText('ok', null)).toBe('자원 지표 없음')
    expect(formatPct(undefined)).toBe('—')
  })

  it('자산이 없거나 조사 · 대조 전이면 0 건으로 적지 않는다', () => {
    const base = { asset_id: 'x', vuln_total: 0, vuln_kev: 0, collected_at: minutesAgo(10), checked_at: minutesAgo(5), stale: false, missing: false }
    expect(vulnText(base)).toBe('취약점 0 · KEV 0')
    expect(vulnText({ ...base, missing: true, stale: true, collected_at: null, checked_at: null })).toBe('자산 정보 없음')
    expect(vulnText({ ...base, collected_at: null, checked_at: null, stale: true })).toBe('조사 기록 없음')
    expect(vulnText({ ...base, checked_at: null })).toBe('취약점 대조 전')
    expect(vulnText({ ...base, vuln_total: 1234, vuln_kev: 5 })).toBe('취약점 1,234 · KEV 5')
  })

  it('수정 상태별 수(#72)가 모두 오면 수정판 있음 · 재부팅 대기 · 수정 여부 미확인 · KEV(0 도 적는다), 총수는 쓰지 않는다', () => {
    const base = { asset_id: 'x', vuln_total: 14, vuln_kev: 1, collected_at: minutesAgo(10), checked_at: minutesAgo(5), stale: false, missing: false }
    expect(vulnText({ ...base, vuln_fix_available: 6, vuln_reboot_pending: 1, vuln_fix_unknown: 3 })).toBe('수정판 있음 6 · 재부팅 대기 1 · 수정 여부 미확인 3 · KEV 1')
    expect(vulnText({ ...base, vuln_kev: 0, vuln_fix_available: 0, vuln_reboot_pending: 0, vuln_fix_unknown: 1200 })).toBe('수정판 있음 0 · 재부팅 대기 0 · 수정 여부 미확인 1,200 · KEV 0')
    // 셋 가운데 하나라도 없으면(이전 서버) 옛 표기
    expect(vulnText({ ...base, vuln_fix_available: 6, vuln_reboot_pending: 1 })).toBe('취약점 14 · KEV 1')
    expect(vulnText({ ...base, vuln_fix_available: 6, vuln_reboot_pending: 1, vuln_fix_unknown: null as never })).toBe('취약점 14 · KEV 1')
    // 없음 · 조사 전 · 대조 전은 새 칸이 있어도 그 글이 앞선다
    expect(vulnText({ ...base, missing: true, vuln_fix_available: 0, vuln_reboot_pending: 0, vuln_fix_unknown: 0 })).toBe('자산 정보 없음')
    expect(vulnText({ ...base, checked_at: null, vuln_fix_available: 0, vuln_reboot_pending: 0, vuln_fix_unknown: 0 })).toBe('취약점 대조 전')
  })
})

describe('무리 · 머리 배지 · 경고 배지 · 미판정 주소(#72)', () => {
  const ids = (targets: { id: string }[]) => targets.map((t) => t.id)

  it('보호 대상(web-01 · 등록 노드) · 관측 센서 · 관제 시스템으로 나누고 각 무리 안은 서버 순서다', () => {
    const groups = groupTargets([awsSensor(), web01(), consoleTarget(), dataNode(), nodeTarget('web-03'), nodeTarget('web-02')])
    expect(ids(groups.protected)).toEqual(['web-01', 'web-03', 'web-02'])
    expect(ids(groups.sensors)).toEqual(['aws-sensor'])
    expect(ids(groups.system)).toEqual(['console', 'data-node'])
    expect(groupTargets([])).toEqual({ protected: [], sensors: [], system: [] })
  })

  it('kind 가 없는 응답은 고정 네 id 인지로 가르고, 고정 id 와 같은 등록 노드는 보호 대상이다', () => {
    const groups = groupTargets([nodeTarget('web-05', { kind: undefined }), consoleTarget({ kind: undefined }), nodeTarget('console'), awsSensor({ kind: undefined })])
    expect(ids(groups.protected)).toEqual(['web-05', 'console'])
    expect(groups.protected[1].kind).toBe('node')
    expect(ids(groups.sensors)).toEqual(['aws-sensor'])
    expect(ids(groups.system)).toEqual(['console'])
  })

  it('머리 배지: 데이터 노드가 정상이어도 확인이 멈췄으면 주의, 아니면 수집 상태 그대로', () => {
    expect(headBadge(dataNodeStopped())).toEqual({ label: '주의', tone: 'warning' })
    expect(headBadge(dataNodeStopped(['enforcer']))).toEqual({ label: '주의', tone: 'warning' })
    expect(headBadge(dataNodeStopped([]))).toEqual({ label: '수집 정상', tone: 'success' })
    // 서버가 이미 수신 없음이면 그대로(멈춤은 경고 배지가 말한다)
    expect(headBadge(dataNode({ collection: { ...dataNode().collection, stopped: ['loader'] } }))).toEqual({ label: '수신 없음', tone: 'warning' })
    expect(headBadge(awsSensor())).toEqual({ label: '정상', tone: 'success' })
    // 콘솔은 응답 중(#76): 생존 확정이 아니라 정상 초록으로 꾸미지 않는다
    expect(headBadge(consoleTarget())).toEqual({ label: '응답 중', tone: 'neutral' })
    expect(headBadge({ collection: { state: 'down' as never } })).toEqual({ label: '생존 상태 미확인', tone: 'neutral' })
  })

  it('접힌 줄 머리 배지: 상태판 갱신 실패(이전 결과) 동안 콘솔 응답 중은 두지 않고, 다른 대상은 그대로다(#84 결정 5)', () => {
    expect(summaryHeadBadge(consoleTarget(), 'full', false)).toEqual({ label: '응답 중', tone: 'neutral' })
    expect(summaryHeadBadge(consoleTarget(), 'full', true)).toBeNull()
    expect(summaryHeadBadge(awsSensor(), 'full', true)).toEqual({ label: '정상', tone: 'success' })
    expect(summaryHeadBadge(nodeTarget(), 'protected', true)).toEqual({ label: '수집 정상', tone: 'success' })
    expect(summaryHeadBadge(dataNodeStopped(), 'full', true)).toEqual({ label: '주의', tone: 'warning' })
  })

  it('경고 배지: 적용 실패 n(빨강) · 집행기 멈춤 · 적재기 멈춤, 0 과 해당 없음은 만들지 않고 집행기 멈춤은 한 번만', () => {
    const flags = (t: Parameters<typeof summaryFlags>[0]) => summaryFlags(t).map((f) => [f.key, f.text, f.tone])
    expect(flags(awsSensor())).toEqual([])
    expect(flags(awsSensor({ response: { ...awsSensor().response, failed: 0, stalled: null } }))).toEqual([])
    expect(flags(web01({ response: { ...web01().response, failed: 1234, stalled: '집행기 확인 기록 없음' } }))).toEqual([
      ['failed', '적용 실패 1,234', 'danger'], ['enforcer', '집행기 멈춤', 'warning']])
    expect(flags(dataNodeStopped())).toEqual([['loader', '적재기 멈춤', 'warning'], ['enforcer', '집행기 멈춤', 'warning']])
    expect(flags({ response: { stalled: '멈춤' }, collection: { stopped: ['enforcer', 'loader', 'enforcer'] } })).toEqual([
      ['enforcer', '집행기 멈춤', 'warning'], ['loader', '적재기 멈춤', 'warning']])
    // 모르는 값 · 목록이 아닌 값은 무시한다
    expect(flags({ response: {}, collection: { stopped: ['other' as never] } })).toEqual([])
    expect(flags({ response: {}, collection: { stopped: 'loader' as never } })).toEqual([])
  })

  it('경고 배지(#82): 탐지 경로 멈춤 · 웹 로그 적재 없음은 주의색, 생존 신호 표를 읽을 수 없으면 집행기 멈춤이 아니라 집행 확인 불가(중립색)', () => {
    const flags = (t: Parameters<typeof summaryFlags>[0]) => summaryFlags(t).map((f) => [f.key, f.text, f.tone])
    expect(flags(dataNodeStopped(['loader', 'detect']))).toEqual([['loader', '적재기 멈춤', 'warning'], ['detect', '탐지 멈춤', 'warning']])
    expect(headBadge(dataNodeStopped(['detect']))).toEqual({ label: '주의', tone: 'warning' })
    const parse = { key: 'parse' as const, label: '웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖)', at: null }
    expect(flags(web01({ collection: { ...web01().collection, warnings: [parse, parse] } }))).toEqual([['parse', '웹 로그 적재 없음', 'warning']])
    expect(flags({ response: {}, collection: { warnings: [{ key: 'other' as never, label: '', at: null }] } })).toEqual([])
    const unread = { stalled: '집행 보고를 읽을 수 없음 · 적용 여부 확인 불가', unreadable: true }
    expect(flags({ response: unread, collection: {} })).toEqual([['unreadable', '집행 확인 불가', 'neutral']])
    expect(flags({ response: { ...unread, unreadable: false }, collection: {} })).toEqual([['enforcer', '집행기 멈춤', 'warning']])
    // 이전 서버(unreadable 없음)는 지금처럼 멈춤이다
    expect(flags({ response: { stalled: '집행기 확인 기록 없음' }, collection: {} })).toEqual([['enforcer', '집행기 멈춤', 'warning']])
  })

  describe('접힌 요약 줄 배지(#84 결정 1 · 3 · 6)', () => {
    const line = (t: Parameters<typeof summaryLineFlags>[0]) => summaryLineFlags(t).map((f) => [f.key, f.text, f.tone])
    const sensor = (extra: Partial<TargetResponse>) => awsSensor({ response: { ...awsSensor().response, checking: 0, delayed: 0, ...extra } })

    it('지점 적용은 지점마다 하나: 실패(빨강) > 확인 지연(주의) > 확인 중(중립)이고 수는 차단 건수, 해제 확인 중(중립)은 따로다', () => {
      expect(line(awsSensor())).toEqual([['checking', '적용 확인 중 1건', 'neutral']])
      expect(line(sensor({ delayed: 2, checking: 3 }))).toEqual([['delayed', '적용 확인 지연 2건', 'warning']])
      expect(line(sensor({ failed: 1, delayed: 2, checking: 3 }))).toEqual([['failed', '적용 실패 1건', 'danger']])
      expect(line(sensor({ removing: 1 }))).toEqual([['removing', '해제 확인 중 1건', 'neutral']])
      expect(line(sensor({ checking: 1, removing: 2 }))).toEqual([['checking', '적용 확인 중 1건', 'neutral'], ['removing', '해제 확인 중 2건', 'neutral']])
      // 미확인 수만으로는 만들지 않는다(이전 서버 · 확인 중 · 지연이 0)
      expect(line(sensor({ unverified: 4 }))).toEqual([])
      expect(line(awsSensor({ response: { ...awsSensor().response, checking: undefined, delayed: undefined } }))).toEqual([])
    })

    it('같은 지점의 집행기 멈춤 · 집행 확인 불가와 겹치면 그 경고 하나로 합친다(보고 문제 · 해제 확인 중도 뺀다)', () => {
      expect(line(sensor({ failed: 1, delayed: 2, removing: 1, report_issue: '마지막 보고 20분 전', stalled: '집행기 확인 중단 · 마지막 확인 12분 전' }))).toEqual([
        ['enforcer', '집행기 멈춤', 'warning']])
      expect(line(sensor({ checking: 1, stalled: '집행 보고를 읽을 수 없음 · 적용 여부 확인 불가', unreadable: true }))).toEqual([['unreadable', '집행 확인 불가', 'neutral']])
    })

    it('보고 문제는 서버 report_issue(띠 report:<지점> 과 같은 판정)가 있을 때만 주의색이다', () => {
      expect(line(web01())).toEqual([['report', '보고 문제', 'warning']])
      expect(line(web01({ response: { ...web01().response, report_issue: null } }))).toEqual([])
      // 이전 서버(report_issue 없음)는 보고 원자료만으로 판정하지 않는다
      expect(line(web01({ response: { ...web01().response, report_issue: undefined } }))).toEqual([])
    })

    it('지표 오래됨(주의)은 자원 지표가 오래된 대상만, 지점 없는 대상(콘솔 · 데이터 노드 · 등록 노드)에는 지점 배지가 없다', () => {
      const stale = { state: 'stale' as const, metrics: web01().system.metrics }
      expect(line(nodeTarget('web-02', { system: stale }))).toEqual([['metrics', '지표 오래됨', 'warning']])
      expect(line(web01({ system: stale }))).toEqual([['report', '보고 문제', 'warning'], ['metrics', '지표 오래됨', 'warning']])
      expect(line(consoleTarget())).toEqual([])
      expect(line(nodeTarget())).toEqual([])
      expect(line(dataNode({ response: { ...dataNode().response, checking: 3 } }))).toEqual([])
    })

    it('적재기 · 탐지 멈춤 · 웹 로그 적재 없음은 경고 배지와 같고 지점 배지 · 보고 뒤, 지표 오래됨 앞이다', () => {
      expect(line(dataNodeStopped(['loader', 'detect']))).toEqual([['loader', '적재기 멈춤', 'warning'], ['detect', '탐지 멈춤', 'warning']])
      const parse = { key: 'parse' as const, label: '웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖)', at: null }
      const busy = web01({
        collection: { ...web01().collection, warnings: [parse] },
        system: { state: 'stale', metrics: null },
        response: { ...web01().response, delayed: 1 },
      })
      expect(line(busy).map(([key]) => key)).toEqual(['delayed', 'report', 'parse', 'metrics'])
    })
  })

  it('미판정 주소는 판정 전 · 장비 조건만(기간 없음)이고 값을 인코딩한다', () => {
    expect(pendingHref('web-01')).toBe('/incidents?judged=false&device=web-01')
    expect(pendingHref('_unconfirmed')).toBe('/incidents?judged=false&device=_unconfirmed')
    expect(pendingHref('a&b=c d')).toBe('/incidents?judged=false&device=a%26b%3Dc+d')
    expect(pendingHref('web-01')).not.toMatch(/since|until/)
  })
})

describe('카드 순서(#64): 고정 대상 뒤 등록 노드', () => {
  const ids = (targets: { id: string }[]) => targets.map((t) => t.id)

  it('서버 순서를 지키고 등록 노드는 고정 네 대상 뒤에 둔다', () => {
    const fixed = [awsSensor(), web01(), consoleTarget(), dataNode()]
    expect(ids(orderTargets([...fixed, nodeTarget('web-02'), nodeTarget('web-03')]))).toEqual(['aws-sensor', 'web-01', 'console', 'data-node', 'web-02', 'web-03'])
    // 섞여 와도 고정 대상이 앞자리를 잃지 않고, 각 무리 안은 받은 순서 그대로다
    expect(ids(orderTargets([nodeTarget('web-03'), awsSensor(), nodeTarget('web-02'), web01()]))).toEqual(['aws-sensor', 'web-01', 'web-03', 'web-02'])
  })

  it('kind 가 없는 이전 응답은 id 로 가른다(고정 네 값이 아니면 등록 노드)', () => {
    const legacy = [nodeTarget('web-02', { kind: undefined }), consoleTarget({ kind: undefined })]
    expect(ids(orderTargets(legacy))).toEqual(['console', 'web-02'])
    expect(orderTargets([])).toEqual([])
  })
})

describe('보호 대상 카드 문구(#83)', () => {
  const asset = (extra: Partial<TargetAssetVulns> = {}): TargetAssetVulns => ({ ...web01().vulns.assets[0], stale: false, check_stale: false, ...extra })

  it('머리 배지는 정상이면 수집 정상, 그 밖은 headBadge 그대로(보고서 · 센서 · 관제 시스템은 정상)', () => {
    expect(protectedHeadBadge(nodeTarget())).toEqual({ label: '수집 정상', tone: 'success' })
    expect(protectedHeadBadge(web01())).toEqual(headBadge(web01()))
    expect(protectedHeadBadge(dataNodeStopped())).toEqual({ label: '주의', tone: 'warning' })
    expect(headBadge(nodeTarget()).label).toBe('정상')
  })

  it('취약점 한 줄: 수정판 있음 · KEV 나란히, 수정 여부 미확인은 따로(흐린 글 · 말풍선) · 자산 화면으로 잇는다', () => {
    expect(vulnSummary({ available: true, assets: [asset()] })).toMatchObject({ main: '수정판 있음 12 · KEV 0', muted: false, unknown: '수정 여부 미확인 4', flags: [], href: '/inventory?asset=web-01' })
    // 이전 서버(수정 상태별 수 없음)는 총수 · KEV
    expect(vulnSummary({ available: true, assets: [asset({ vuln_fix_available: undefined, vuln_fix_unknown: undefined })] }).main).toBe('취약점 30 · KEV 0')
  })

  it('조사 오래됨 · 대조 실패 · 대조 오래됨은 수를 바꾸지 않고 상태 글로 붙인다', () => {
    const v = vulnSummary({ available: true, assets: [asset({ stale: true, check_failed: true, check_stale: true })] })
    expect(v.main).toBe('수정판 있음 12 · KEV 0')
    expect(v.unknown).toBe('수정 여부 미확인 4')
    expect(v.flags).toEqual(['조사 오래됨', '대조 실패', '대조 오래됨'])
  })

  it('수가 없으면 까닭 글(0 으로 꾸미지 않는다): 정보 없음 · 자산 없음 · 자산 정보 없음 · 조사 기록 없음 · 대조 전', () => {
    expect(vulnSummary({ available: false, assets: [] })).toMatchObject({ main: '취약점 정보 없음', muted: true, href: null })
    expect(vulnSummary({ available: true, assets: [] })).toMatchObject({ main: '연결된 자산 없음', muted: true, href: null })
    expect(vulnSummary({ available: true, assets: [asset({ missing: true, collected_at: null, checked_at: null, stale: true })] })).toMatchObject({ main: '자산 정보 없음', flags: [] })
    expect(vulnSummary({ available: true, assets: [asset({ collected_at: null, checked_at: null })] }).main).toBe('조사 기록 없음')
    const before = vulnSummary({ available: true, assets: [asset({ checked_at: null, check_failed: true })] })
    expect(before).toMatchObject({ main: '취약점 대조 전', muted: true, unknown: null, flags: ['대조 실패'], href: '/inventory?asset=web-01' })
  })

  it('자산이 여럿이면 수를 더하고 자산 목록으로 잇는다', () => {
    const v = vulnSummary(awsSensor().vulns)
    expect(v).toMatchObject({ main: '수정판 있음 6 · KEV 1', unknown: '수정 여부 미확인 3', href: '/inventory' })
    // 말풍선의 수도 더한 값이다
    expect(v.unknownNote).toMatch(/^수정 여부 미확인 3건 — /)
  })

  it('수정 여부 미확인 말풍선(#94): 상세를 조회하지 않는 기록 포함 · 수정판 없음 아님 · 취약점 수 단위. 수를 사유별로 나누지 않는다', () => {
    expect(vulnSummary({ available: true, assets: [asset({ vuln_fix_unknown: 1200 })] }).unknownNote).toBe(
      '수정 여부 미확인 1,200건 — 현재 수집 정책에서 상세 정보를 조회하지 않는 기록(커널 질의에서만 나온 KEV 밖 기록)을 포함합니다. 수정판 없음이라는 뜻은 아닙니다. ' +
        '취약점 수는 패키지별 대조 행 수입니다. 같은 CVE 가 여러 패키지에 걸리면 여러 번 셉니다.',
    )
    // 0건이면 수 없이 뜻만 적는다
    expect(vulnSummary({ available: true, assets: [asset({ vuln_fix_unknown: 0 })] }).unknownNote).toMatch(/^수정 여부 미확인은 현재 수집 정책에서 /)
    // 수가 없으면(이전 서버 · 대조 전) 말풍선도 없다
    expect(vulnSummary({ available: true, assets: [asset({ vuln_fix_available: undefined, vuln_fix_unknown: undefined })] }).unknownNote).toBeUndefined()
    expect(vulnSummary({ available: true, assets: [asset({ checked_at: null })] }).unknownNote).toBeUndefined()
  })

  it('최근 사건 줄은 최신 판정이 미결이면 판정 기록이 있어도 미결이다', () => {
    const latest = awsSensor().security.latest!
    expect(latestJudgedText(latest)).toBe('미판정')
    expect(latestJudgedText({ ...latest, judged: true, verdict: 'threat' })).toBe('판정됨')
    expect(latestJudgedText({ ...latest, judged: true, verdict: 'undetermined' })).toBe('미결')
    expect(latestJudgedText({ ...latest, judged: true })).toBe('판정됨')
  })

  it('미결 목록 주소: 전체 · 장비별', () => {
    expect(undeterminedHref()).toBe('/incidents?undetermined=true')
    expect(undeterminedHref('web-02')).toBe('/incidents?undetermined=true&device=web-02')
  })
})

describe('데이터 노드 자원 요약(#109)', () => {
  it('측정 성공과 용량 정상은 별개이며, 부족과 일부 실패를 함께 표시한다', () => {
    const target = dataNode({ system: { state: 'ok', metrics: null, capacity: 'critical', problems: ['Loki 측정 실패'] } })
    expect(summaryLineFlags(target)).toEqual(expect.arrayContaining([
      { key: 'capacity', text: '디스크 용량 부족', tone: 'danger' },
      { key: 'metrics', text: '자원 확인 불가', tone: 'neutral' },
    ]))
  })
  it('미설치도 접힌 줄에서 보이고, 오래된 용량은 현재 부족으로 확정하지 않는다', () => {
    const target = dataNode({ system: { state: 'no_data', metrics: null, capacity: 'unknown', problems: ['미설치'] } })
    expect(summaryLineFlags(target)).toContainEqual({ key: 'metrics', text: '자원 확인 불가', tone: 'neutral' })
    target.system.state = 'stale'
    expect(summaryLineFlags(target)).toContainEqual({ key: 'metrics', text: '지표 오래됨', tone: 'warning' })
    expect(summaryLineFlags(target).some((x) => x.key === 'capacity')).toBe(false)
  })
})

it('데이터 노드의 정상 배지는 전체 자원 정상으로 읽히지 않게 수집 범위를 밝힌다', () => {
  const target = dataNode()
  target.collection.state = 'ok'
  expect(headBadge(target).label).toBe('수집 정상')
})
