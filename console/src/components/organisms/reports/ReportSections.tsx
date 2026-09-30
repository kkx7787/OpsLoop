import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { APPLICABILITY_LABEL, APPLICABILITY_STATUSES } from '@/api/cti'
import { DELIVERY_EVENT_LABEL, DELIVERY_STATUS_LABEL } from '@/api/notify'
import {
  BASIS_LABEL, SECTION_LABEL,
  type BlocksSection, type CtiSection, type OpsSection, type OverviewSection, type ReportSection, type ReportSectionMap,
  type RulesSection, type SectionUnavailable, type TargetsSection,
} from '@/api/reports'
import { isCircularRule, VERDICT_LABEL, VERDICTS } from '@/lib/domain'
import { formatDuration } from '@/lib/time'
import { cn } from '@/lib/cn'
import { Badge } from '../../atoms/Badge'
import { Card, CardHeader } from '../../atoms/Card'
import { SeverityBadge } from '../../atoms/SeverityBadge'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { InfoTip } from '../../molecules/InfoTip'
import { COLLECTION_LABEL, COLLECTION_TONE, collectionState, formatPct, responseParts } from '../dashboard/target-format'

/**
 * 기간 보고서의 구역(S-11 · #58). 페이지(pages/reports)가 계약 순서대로 조립한다.
 * 종이에 그대로 찍히도록 그래프 없이 표만 쓰고, 스크롤 상자 · details 접힘 · 펼치기 단추에 넣지 않는다.
 * 예외는 구역 끝 기준 설명(notes) 하나다. 화면에서는 '기준 보기'(InfoTip text)로 접고, 종이에는 늘 펼쳐 찍는다(print="expand").
 * 표 제목의 괄호는 짧은 정의만 둔다(기간 · 기록 출처 같은 긴 기준은 notes 에 있다).
 * 비신뢰 문자열(출발지 · 규칙 버전 사유 · 센서 · 수집 사유(업로더가 보고한 문제 포함) · 자산 · 외부 CVE 자료)은 UntrustedText clip 으로 앞 500자까지만 그린다(펼치기 단추가 인쇄되지 않게).
 * 빈 값은 '—'. 좁은 화면은 responsive-table 이 행을 쌓고, 인쇄는 index.css 의 @media print 가 표로 되돌린다.
 */

const cell = 'px-4 py-2 align-top'
const numCell = `${cell} tabular-nums`
// 표 칸의 시각(<Time>)은 종이에서 한 줄로 둔다(print:whitespace-nowrap). A4 세로 폭에는 좁은 화면 규칙(index.css)이 걸려
// 칸의 white-space 가 normal 이 되고, 긴 비신뢰 문자열 칸 옆에서 '2026-' 뒤로 줄이 갈린다. 좁은 화면에서는 전처럼 줄을 바꾼다

/** 수 한 칸. 값이 없으면 '—' */
function num(n: number | null | undefined): string {
  const v = Number(n)
  return n === null || n === undefined || !Number.isFinite(v) ? '—' : v.toLocaleString('ko-KR')
}
/** 초를 '6시간 12분' 으로. 표본이 없으면 '—' */
function seconds(s: number | null | undefined): string {
  const v = Number(s)
  return s === null || s === undefined || !Number.isFinite(v) ? '—' : formatDuration(v * 1000)
}
const percent = (n: number | null) => n === null ? '—' : `${Number(n).toFixed(1)}%`

/** 감사 화면(AuditPage EVENTS)과 같은 말. 모르는 이벤트는 원문을 글자로 보인다 */
const AUDIT_EVENT_LABEL: Record<string, string> = {
  'console.block.created': '차단 요청',
  'console.block.rearmed': '차단 재요청',
  'console.block.extended': '차단 연장',
  'console.block.shortened': '차단 만료 단축',
  'console.block.points': '차단 지점 넓힘',
  'console.block.released': '차단 해제',
  'console.block.enforced': '관문 집행 확인',
  'console.block.unenforced': '관문 집행 해제',
  'console.block.expired': '차단 만료',
  'console.node.token.issued': '등록 토큰 발급',
  'console.node.token.canceled': '등록 토큰 취소',
  'console.notify.channel.created': '알림 채널 추가',
  'console.notify.channel.changed': '알림 채널 변경',
}
const ORIGINS = [['R0xx', 'R0xx 허니팟'], ['R1xx', 'R1xx 웹 노드'], ['R2xx', 'R2xx 관제 자기 탐지'], ['R3xx', 'R3xx 인프라'], ['other', '기타']] as const

/** 구역 안 표 하나. 머리(h3)가 표의 이름이 된다 */
function SubTable({ title, aside, head, empty, children }: { title: string; aside?: ReactNode; head: readonly string[]; empty?: string | false; children: ReactNode }) {
  return <div className="min-w-0">
    <h3 className="m-0 flex flex-wrap items-baseline justify-between gap-x-3 px-4 pt-3 pb-1 text-sm font-semibold">{title}{aside && <span className="text-xs font-normal text-ink-muted">{aside}</span>}</h3>
    <table aria-label={title} className="responsive-table w-full text-left text-sm">
      <thead className="border-b border-line text-xs text-ink-muted"><tr>{head.map(t => <th key={t} scope="col" className={cell}>{t}</th>)}</tr></thead>
      <tbody className="divide-y divide-line">{children}</tbody>
    </table>
    {empty && <p className="m-0 px-4 py-2 text-sm text-ink-muted">{empty}</p>}
  </div>
}

/** 한 줄 수치 표(머리 = 항목, 한 행 = 값). 좁은 화면에서는 칸마다 항목 이름이 붙는다 */
function CountRow({ title, aside, cells }: { title: string; aside?: ReactNode; cells: ReadonlyArray<readonly [string, ReactNode]> }) {
  return <SubTable title={title} aside={aside} head={cells.map(([label]) => label)}>
    <tr>{cells.map(([label, value]) => <td key={label} data-label={label} className={numCell}>{value}</td>)}</tr>
  </SubTable>
}

/** 표를 읽을 수 없어 서버가 내지 않은 부분(구역의 나머지는 그대로 싣는다) */
function Missing({ children }: { children: ReactNode }) {
  return <p className="m-0 px-4 pt-3 text-sm text-ink-muted">{children}</p>
}

/** 보고서에서 미결이 처음 나오는 곳(기간 판정)은 화면 표기 '미결' 과 이슈 · 문서의 '판단 유보' 를 잇는다(#83) */
const FIRST_VERDICT_LABEL: Record<(typeof VERDICTS)[number], string> = { ...VERDICT_LABEL, undetermined: '미결(판단 유보)' }

function Overview({ s }: { s: OverviewSection }) {
  const { incidents: inc, verdicts, backlog, wait, decision } = s
  return <>
    <CountRow title="기간 사건 (발생 시각 기준)" cells={[['합계', num(inc.total)], ...(['critical', 'high', 'medium', 'low'] as const).map(sev => [sev, num(inc.by_severity[sev])] as const), ['시험 출발지 (따로)', num(inc.test_source)]]} />
    <CountRow title="발생원별 사건" cells={ORIGINS.map(([key, label]) => [label, num(inc.by_origin[key])] as const)} />
    <CountRow title="기간 판정 (판정 시각 기준)" cells={[['합계', num(verdicts.total)], ...VERDICTS.map(v => [FIRST_VERDICT_LABEL[v], num(verdicts.by_verdict[v])] as const), ['시험 출발지 (따로)', num(verdicts.test_source)]]} />
    <CountRow title="미판정 잔량 (출력 시점)" cells={[['판정 없음', num(backlog.unjudged)], ['미결(판단 유보)', num(backlog.undetermined)], ['판정 목표 초과', num(backlog.overdue)], ['목표 임박', num(backlog.warning)], ['가장 오래된 미판정', seconds(backlog.oldest_seconds)]]} />
    <SubTable title="운영 부담" head={['지표', '표본', '중앙값', '90분위']}>
      <tr><td className={cell}>판정 대기 (사건 생성 → 첫 판정)</td><td data-label="표본" className={numCell}>{num(wait.judged)}<div className="text-xs text-ink-muted">생성 {num(wait.incidents)}건 중 판정</div></td><td data-label="중앙값" className={numCell}>{seconds(wait.p50_seconds)}</td><td data-label="90분위" className={numCell}>{seconds(wait.p90_seconds)}</td></tr>
      <tr><td className={cell}>판정 소요 (화면 열기 → 판정 저장)</td><td data-label="표본" className={numCell}>{num(decision.n)}</td><td data-label="중앙값" className={numCell}>{seconds(decision.p50_seconds)}</td><td data-label="90분위" className={numCell}>{seconds(decision.p90_seconds)}</td></tr>
    </SubTable>
    <SubTable title="날짜별 생성 · 판정 (KST)" head={['날짜', '생성', '판정']} empty={!s.daily.length && '기간에 생성 · 판정된 사건이 없습니다.'}>
      {s.daily.map(d => <tr key={d.date}><td className={`${cell} tabular-nums`}>{d.date}</td><td data-label="생성" className={numCell}>{num(d.created)}</td><td data-label="판정" className={numCell}>{num(d.judged)}</td></tr>)}
    </SubTable>
    <SubTable title="상위 출발지" aside={`상위 ${s.top_sources.items.length} · 전체 ${num(s.top_sources.total)}곳 중 · 시험 대역 제외`} head={['출발지', '사건', '최고 심각도', '마지막 사건 (KST)']} empty={!s.top_sources.items.length && '기간에 출발지가 있는 사건이 없습니다.'}>
      {s.top_sources.items.map(src => <tr key={src.ip}>
        <td className={`${cell} font-mono`}><Link to={`/sources/detail?ip=${encodeURIComponent(src.ip)}`}><UntrustedText value={src.ip} clip /></Link></td>
        <td data-label="사건" className={numCell}>{num(src.incidents)}</td>
        <td data-label="최고 심각도" className={cell}>{src.severity ? <SeverityBadge severity={src.severity} /> : '—'}</td>
        <td data-label="마지막 사건 (KST)" className={cell}><Time value={src.last_ts} format="minute" className="print:whitespace-nowrap" /></td>
      </tr>)}
    </SubTable>
  </>
}

function Rules({ s }: { s: RulesSection }) {
  const absorbed = new Map(s.absorbed?.rules.map(r => [`${r.rule_id}:${r.rule_version}`, r]))
  return <>
    <SubTable title="규칙별 판정 (사건별 마지막 판정)" head={['규칙 · 버전', '사건', '판정', '판정 분포', '비조치율', '오탐률', '흡수 · 억제']} empty={!s.rows.length && '기간에 집계된 사건이 없습니다.'}>
      {s.rows.map(r => {
        const a = absorbed.get(`${r.rule_id}:${r.rule_version}`)
        return <tr key={`${r.rule_id}:${r.rule_version}`}>
          <td className={`${cell} whitespace-nowrap`}><span className="whitespace-nowrap"><span className="font-mono">{r.rule_id}</span> · {r.rule_version}</span></td>
          <td data-label="사건" className={numCell}>{num(r.incidents)}</td>
          <td data-label="판정" className={numCell}>{num(r.judged)}</td>
          <td data-label="판정 분포" className={`${cell} text-xs`}>{([['threat', r.threats], ['non_actionable', r.non_actionable], ['false_positive', r.false_positives], ['benign_positive', r.benign_positives], ['undetermined', r.undetermined]] as const).map(([v, n]) => `${VERDICT_LABEL[v]} ${num(n)}`).join(' · ')}</td>
          <td data-label="비조치율" className={numCell}>{percent(r.non_action_rate)}{r.judged_effective > 0 && <div className="text-xs text-ink-muted">비조치 {num(r.non_actionable + r.false_positives + r.benign_positives)} / 유효 판정 {num(r.judged_effective)}</div>}</td>
          <td data-label="오탐률" className={numCell}>{isCircularRule(r.rule_id) ? <span className="whitespace-nowrap">순환 규칙</span> : percent(r.false_positive_rate)}</td>
          <td data-label="흡수 · 억제" className={numCell}>{s.absorbed ? `${num(a?.absorbed ?? 0)} · ${num(a?.suppressed ?? 0)}` : '—'}</td>
        </tr>
      })}
    </SubTable>
    {s.absorbed ? <CountRow title="흡수 · 억제 (사건 수에 없음)" cells={[['흡수', num(s.absorbed.absorbed)], ['억제', num(s.absorbed.suppressed)]]} />
      : <Missing>흡수 기록을 읽을 수 없어 흡수 · 억제 수를 싣지 않았습니다.</Missing>}
    <SubTable title="기간 중 만든 규칙 버전" head={['버전', '만든 시각 (KST)', '규칙', '사유']} empty={!s.versions.length && '기간 중 새 규칙 버전이 없습니다.'}>
      {s.versions.map(v => <tr key={v.rule_version}>
        <td className={`${cell} font-mono`}><UntrustedText value={v.rule_version} clip /></td>
        <td data-label="만든 시각 (KST)" className={cell}><Time value={v.created_at} format="minute" className="print:whitespace-nowrap" /></td>
        <td data-label="규칙" className={`${cell} font-mono text-xs`}><UntrustedText value={v.rules.join(' ')} clip fallback="—" /></td>
        <td data-label="사유" className={cell}><UntrustedText value={v.reason} max={160} clip fallback="사유 미기록" /></td>
      </tr>)}
    </SubTable>
  </>
}

function Blocks({ s }: { s: BlocksSection }) {
  const { requests: r, enforcement: e, states } = s
  return <>
    <CountRow title="기간 조치 (사건 조치 기록)" cells={[['차단 요청', num(s.actions.block_ip)], ['차단 해제', num(s.actions.unblock_ip)]]} />
    <CountRow title="새 차단 요청의 요청자 (감사 기록)" cells={[['합계', num(r.total)], ['콘솔 사용자', num(r.console)], ['triage', num(r.triage)], ['system', num(r.system)], ['미기록', num(r.unknown)]]} />
    <SubTable title="기간 차단 감사 이벤트" aside="종류별 수" head={['종류', '건수']} empty={!s.audit.length && '기간에 차단 감사 기록이 없습니다.'}>
      {s.audit.map(a => <tr key={a.eventid}><td className={cell}>{AUDIT_EVENT_LABEL[a.eventid] ?? <UntrustedText value={a.eventid} clip />}</td><td data-label="건수" className={numCell}>{num(a.count)}</td></tr>)}
    </SubTable>
    {/* 관문을 요청한 새 요청만 센다(#77). 내부 방화벽 반영은 감사가 없어 싣지 않는다. 관문이 빼기 전에 다시 건 요청은 기존 차단 유지로 따로 세고 지연에서 뺀다(결정 2) */}
    <CountRow title="관문 반영 지연 (관문 요청 → 관문 반영)" cells={[['관문 요청', num(e.created)], ['관문 반영 확인', num(e.enforced)], ['기존 차단 유지', num(e.maintained)], ['중앙값', seconds(e.p50_seconds)], ['최대', seconds(e.max_seconds)]]} />
    {/* 종합 상태: 요청한 지점이 모두 확인해야 집행 확인(#77). 실패는 이전 서버에 없어 '—' */}
    <CountRow title="차단 집행 상태 (출력 시점)" cells={[['살아 있는 요청', num(states.total)], ['집행 확인', num(states.enforced)], ['집행 대기', num(states.pending)], ['집행 실패', num(states.failed)], ['불일치', num(states.mismatch)], ['집행 제외', num(states.excluded)]]} />
  </>
}

function Targets({ s }: { s: TargetsSection }) {
  const w = s.web
  return <>
    <SubTable title="대상 상태 (출력 시점)" head={['대상', '수집', '대응']}>
      {s.targets.map(t => {
        const state = collectionState(t.collection.state)
        // 서버는 지점 이름(point_label)만 싣는다. 상태판 문구(responseParts)는 지점이 있는지만 보고 이름을 쓰므로 있다는 표시만 채운다
        const response = { ...t.response, point: t.response.point_label ? ('gateway' as const) : null, report: null }
        return <tr key={t.id}>
          {/* 등록 노드(#64)의 이름은 노드 hostname 이라 비신뢰 문자열로 그린다 */}
          <td className={cell}><UntrustedText value={t.label} clip /></td>
          <td data-label="수집" className={cell}><Badge tone={COLLECTION_TONE[state]}>{COLLECTION_LABEL[state]}</Badge>{t.collection.reason && <div className="mt-1 text-xs text-ink-muted"><UntrustedText value={t.collection.reason} clip /></div>}</td>
          <td data-label="대응" className={cell}>{responseParts(response).map(p => p.text).join(' · ')}</td>
        </tr>
      })}
    </SubTable>
    <SubTable title="센서별 이벤트 (기간)" head={['센서', '이벤트']} empty={!s.sensors.length && '기간에 들어온 이벤트가 없습니다. 수집부터 확인해 주세요.'}>
      {s.sensors.map(e => <tr key={e.sensor}><td className={`${cell} font-mono`}><UntrustedText value={e.sensor} clip /></td><td data-label="이벤트" className={numCell}>{num(e.events)}</td></tr>)}
    </SubTable>
    <CountRow title="탐지 실행 (기간)" cells={[['실행', num(s.detector.runs)], ['실행 사이 최대 공백', seconds(s.detector.max_gap_seconds)]]} />
    {w ? <CountRow title="web-01 자원 (기간 최대)" cells={[['CPU', formatPct(w.cpu_pct)], ['메모리', formatPct(w.mem_used_pct)], ['디스크', formatPct(w.disk_root_pct)], ['표본', num(w.samples)], ['지표 최대 공백', seconds(w.max_gap_seconds)]]} />
      : <Missing>자원 지표를 읽을 수 없어 web-01 자원을 싣지 않았습니다.</Missing>}
  </>
}

function Cti({ s }: { s: CtiSection }) {
  const { freshness: f, watch, kev_added: kev } = s
  const sources = [['KEV', f.kev], ['EPSS', f.epss], ['배포판 대조 (OSV)', f.osv]] as const
  return <>
    <SubTable title="자산별 취약점 (출력 시점)" head={['자산', '취약점', 'KEV', '수정판 있음', '재부팅 대기', '자산 수집 (KST)']} empty={!s.assets.length && '수집된 자산이 없습니다.'}>
      {s.assets.map(a => <tr key={a.asset_id}>
        <td className={`${cell} font-mono`}><UntrustedText value={a.asset_id} clip /></td>
        <td data-label="취약점" className={numCell}>{num(a.vuln_total)}</td><td data-label="KEV" className={numCell}>{num(a.vuln_kev)}</td>
        <td data-label="수정판 있음" className={numCell}>{num(a.vuln_fix_available)}</td><td data-label="재부팅 대기" className={numCell}>{num(a.vuln_reboot_pending)}</td>
        <td data-label="자산 수집 (KST)" className={cell}><Time value={a.collected_at} format="minute" className="print:whitespace-nowrap" />{a.stale && <> <Badge tone="warning">오래됨</Badge></>}</td>
      </tr>)}
    </SubTable>
    {watch ? <CountRow title="주목 CVE (출력 시점)" aside={watch.affected_cves.length ? <UntrustedText value={`해당: ${watch.affected_cves.join(', ')}`} clip /> : undefined}
      cells={[['전체', num(watch.total)], ...APPLICABILITY_STATUSES.map(st => [APPLICABILITY_LABEL[st], num(watch[st])] as const)]} />
      : <Missing>주목 CVE 표를 읽을 수 없어 주목 CVE 를 싣지 않았습니다.</Missing>}
    <SubTable title="기간 중 KEV 등재 · 우리 자산 해당" aside={`기간 등재 ${num(kev.total)}건 중 ${num(kev.ours.length)}건`} head={['CVE', '이름', 'KEV 등재일', '해당 자산']} empty={!kev.ours.length && '해당 없음'}>
      {kev.ours.map(k => <tr key={k.cve_id}>
        <td className={`${cell} font-mono`}><UntrustedText value={k.cve_id} clip /></td>
        <td data-label="이름" className={cell}><UntrustedText value={k.name} clip fallback="—" /></td>
        <td data-label="KEV 등재일" className={`${cell} tabular-nums`}><UntrustedText value={k.date_added} clip /></td>
        <td data-label="해당 자산" className={`${cell} font-mono`}><UntrustedText value={k.assets.join(', ')} clip fallback="—" /></td>
      </tr>)}
    </SubTable>
    <SubTable title="신선도" head={['출처', '마지막 수집 (KST)', '상태']}>
      {sources.map(([label, src]) => <tr key={label}><td className={cell}>{label}</td><td data-label="마지막 수집 (KST)" className={cell}><Time value={src.fetched_at} format="minute" className="print:whitespace-nowrap" /></td><td data-label="상태" className={cell}>{src.stale ? <Badge tone="warning">오래됨</Badge> : '최신'}</td></tr>)}
      <tr><td className={cell}>자산 조사 (가장 오래된 수집)</td><td data-label="마지막 수집 (KST)" className={cell}><Time value={f.assets.oldest_collected_at} format="minute" className="print:whitespace-nowrap" /></td><td data-label="상태" className={cell}>{f.assets.stale_assets.length ? <><Badge tone="warning">오래됨</Badge> <UntrustedText value={f.assets.stale_assets.join(', ')} clip /></> : '최신'}</td></tr>
    </SubTable>
  </>
}

function Ops({ s }: { s: OpsSection }) {
  const n = s.notify
  return <>
    <SubTable title="감사 이벤트 (기간)" aside="종류별 수" head={['종류', '건수']} empty={!s.audit.length && '기간에 감사 기록이 없습니다.'}>
      {s.audit.map(a => <tr key={a.eventid}><td className={cell}>{AUDIT_EVENT_LABEL[a.eventid] ?? <UntrustedText value={a.eventid} clip />}</td><td data-label="건수" className={numCell}>{num(a.count)}</td></tr>)}
    </SubTable>
    <CountRow title="로그인 · 알림 발송 (기간)" cells={[['콘솔 로그인 실패', num(s.login_failed)], ['알림 발송', num(n?.total)], ['발송 실패', num(n?.failed)], ['발송 지연 중앙값', seconds(n?.p50_seconds)]]} />
    {n ? <SubTable title="알림 발송 (기간 · 시험 발송 제외)" head={['사건 종류', '상태', '건수']} empty={!n.rows.length && '기간에 알림 발송이 없습니다.'}>
      {n.rows.map(d => <tr key={`${d.event}:${d.status}`}>
        <td className={cell}>{DELIVERY_EVENT_LABEL[d.event] ?? <UntrustedText value={d.event} clip />}</td>
        <td data-label="상태" className={cell}>{(DELIVERY_STATUS_LABEL as Record<string, string>)[d.status] ?? <UntrustedText value={d.status} clip />}</td>
        <td data-label="건수" className={numCell}>{num(d.count)}</td>
      </tr>)}
    </SubTable> : <Missing>알림 발송 기록을 읽을 수 없어 알림 발송을 싣지 않았습니다.</Missing>}
  </>
}

type AnySection = ReportSectionMap[ReportSection]

function SectionBody({ name, section }: { name: ReportSection; section: AnySection }) {
  switch (name) {
    case 'overview': return <Overview s={section as OverviewSection} />
    case 'rules': return <Rules s={section as RulesSection} />
    case 'blocks': return <Blocks s={section as BlocksSection} />
    case 'targets': return <Targets s={section as TargetsSection} />
    case 'cti': return <Cti s={section as CtiSection} />
    default: return <Ops s={section as OpsSection} />
  }
}

export interface ReportSectionCardProps {
  name: ReportSection
  section: AnySection | SectionUnavailable
  className?: string
}

/**
 * 구역 한 장. 머리 오른쪽에 기준(기간 집계 · 출력 시점 값)을 적고, 끝에 기준 설명(notes)을 둔다.
 * notes 는 화면에서 '기준 보기'로 접고 종이에는 늘 펼쳐 찍는다(구역마다 2~8줄이라 화면에서는 표를 가린다).
 * 표 권한이 없어 만들지 못한 구역은 사유 한 줄만 보인다(머리 오른쪽 '만들지 못함'과 되풀이하지 않는다. 다른 구역은 그대로 나온다).
 */
export function ReportSectionCard({ name, section, className }: ReportSectionCardProps) {
  const title = SECTION_LABEL[name]
  return <Card padding="none" className={cn('min-w-0', className)}>
    <section aria-label={title}>
      <CardHeader title={title} aside={section.available ? BASIS_LABEL[section.basis] : '만들지 못함'} />
      {!section.available ? <p className="m-0 px-4 py-3 text-sm">{section.reason}</p> : <>
        <div className="flex flex-col gap-1 pb-3"><SectionBody name={name} section={section} /></div>
        {section.notes.length > 0 && <div className="border-t border-line px-4 py-2.5">
          <InfoTip variant="text" label={title} print="expand" panelAs="div" panelClassName="print:mt-0">
            <ul className="m-0 list-none space-y-0.5 p-0">{section.notes.map(note => <li key={note}>{note}</li>)}</ul>
          </InfoTip>
        </div>}
      </>}
    </section>
  </Card>
}
