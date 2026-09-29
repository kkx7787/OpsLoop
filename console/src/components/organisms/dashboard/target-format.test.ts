import { describe, expect, it } from 'vitest'
import type { TargetResponse } from '@/api/targets'
import { awsSensor, consoleTarget, dataNode, minutesAgo, nodeTarget, web01 } from '@/test/targets-fixtures'
import { collectionState, formatPct, latestLog, orderTargets, responseParts, systemText, vulnText } from './target-format'

const response = (extra: Partial<TargetResponse>): TargetResponse => ({ point: 'gateway', point_label: 'AWS 관문', applied: 0, unverified: 0, exempt: 0, report: null, ...extra })
const texts = (r: TargetResponse) => responseParts(r).map((p) => p.text)

/** 글 안의 홀로 선 숫자 0(‘0’ · ‘0건’ 등). '10' · '2026' 의 0 은 아니다 */
const ZERO = /(^|[^\d.,])0(?![\d.,])/

describe('대응 문구(#52): 숫자 0 을 그리지 않는다', () => {
  it('집행 지점이 있으면 적용 확인 · 미확인 · 정책상 제외 중 0 이 아닌 것만', () => {
    expect(texts(response({ applied: 2, unverified: 1, exempt: 3 }))).toEqual(['차단 적용 2 (AWS 관문)', '차단 적용 여부 미확인 1', '정책상 차단 제외 3'])
    expect(texts(response({ applied: 0, unverified: 4, exempt: 0 }))).toEqual(['차단 적용 여부 미확인 4'])
    expect(texts(response({ applied: 5, point: 'fw', point_label: '내부 방화벽' }))).toEqual(['차단 적용 5 (내부 방화벽)'])
  })

  it('모두 0 이면 그 지점의 집행 대상 차단 없음(집행 제외 차단만 있어도 거짓이 아닌 문구)', () => {
    expect(texts(response({}))).toEqual(['AWS 관문 집행 대상 차단 없음'])
    expect(texts(response({ applied: null, unverified: null }))).toEqual(['AWS 관문 집행 대상 차단 없음'])
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
    expect(texts(response({ stalled: '집행기 확인 기록 없음' }))).toEqual(['AWS 관문 집행 대상 차단 없음', '집행기 확인 기록 없음'])
  })

  it('이전 서버(failed · stalled 없음)도 그린다', () => {
    expect(texts({ point: 'gateway', point_label: 'AWS 관문', applied: 2, unverified: 0, exempt: 0, report: null })).toEqual(['차단 적용 2 (AWS 관문)'])
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
  it('모르는 수집 상태는 미확인으로 읽는다', () => {
    expect(collectionState('ok')).toBe('ok')
    expect(collectionState('quiet')).toBe('quiet')
    expect(collectionState('no_signal')).toBe('no_signal')
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
