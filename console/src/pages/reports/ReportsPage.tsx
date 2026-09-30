import { useState, type FormEvent, type ReactNode } from 'react'
import { useSearchParams } from 'react-router'
import { describeError } from '@/api/errors'
import {
  ADMIN_SECTIONS, BASIS_LABEL, isReportPeriod, isReportSection, PERIOD_LABEL, REPORT_PERIODS, REPORT_SECTIONS, SECTION_LABEL, usePeriodReport,
  type PeriodReport, type ReportPeriod, type ReportRequest, type ReportSection,
} from '@/api/reports'
import { can } from '@/auth/roles'
import { useMe } from '@/auth/useMe'
import { Button } from '@/components/atoms/Button'
import { Card } from '@/components/atoms/Card'
import { Time } from '@/components/atoms/Time'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { ReportSectionCard } from '@/components/organisms/reports/ReportSections'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'

const DEFAULT_PERIOD: ReportPeriod = '7d'

/**
 * 주소창(?period=7d&s=overview&s=rules)의 보고서 요청. period 가 없거나 모르는 값이면 아직 만들지 않은 것이다.
 * s 가 없으면 볼 수 있는 구역 전부. 구역은 주소의 순서와 관계없이 계약 순서로 묻는다.
 * 볼 수 없는 구역(비관리자의 운영 기록)은 뺀다. 서버가 403 으로 막아 보고서 전체가 실패하지 않게 한다.
 */
function requestFromSearch(search: URLSearchParams, visible: readonly ReportSection[]): { request: ReportRequest | null; dropped: boolean } {
  const period = search.get('period')
  const picked = search.getAll('s')
  const dropped = picked.some(name => isReportSection(name) && !visible.includes(name))
  if (!isReportPeriod(period)) return { request: null, dropped }
  const sections = picked.length ? visible.filter(name => picked.includes(name)) : [...visible]
  return { request: sections.length ? { period, sections } : null, dropped }
}

/**
 * 보고서(S-11 · #58). 기간과 실을 구역을 골라 '보고서 만들기' 를 누르면 조건을 주소창에 남기고 한 벌을 만든다.
 * 끝 = 출력 시각이라 기간 끝 시점 재계산이 없다. 스냅샷 · 정기 생성 · 회차 비교 · 그래프는 없다(범위 밖).
 * 인쇄는 지금 페이지를 window.print() 로 찍는다. CSP 가 iframe · 새 창 스타일 · data: 이미지를 막기 때문이다.
 * 종이에는 메뉴 · 상단바(AppLayout) · 조건 양식 · 이 머리가 빠지고 보고서 머리 · 구역만 나온다(index.css @media print).
 */
export function ReportsPage() {
  const me = useMe()
  const [searchParams, setSearchParams] = useSearchParams()
  // 운영 기록(감사 · 알림 발송)은 감사 기록 열람 권한(admin)과 같다
  const admin = can(me.data?.role, 'audit.read')
  const visible = REPORT_SECTIONS.filter(name => admin || !ADMIN_SECTIONS.has(name))
  const { request, dropped } = me.data ? requestFromSearch(searchParams, visible) : { request: null, dropped: false }
  const report = usePeriodReport(request)
  const data = report.data

  function generate(period: ReportPeriod, sections: readonly ReportSection[]) {
    // 같은 조건으로 다시 누르면 새로 만든다(출력 시각이 바뀐다). 주소 글자가 달라도(구역 없음 · 순서 · 뺀 운영 기록)
    // 조건이 같으면 조회 키가 같아 주소만 바꿔서는 다시 묻지 않으므로 글자가 아니라 조건을 견준다
    if (request && request.period === period && request.sections.join() === sections.join()) {
      void report.refetch()
      return
    }
    const next = new URLSearchParams({ period })
    for (const name of sections) next.append('s', name)
    setSearchParams(next)
  }

  let body: ReactNode
  if (!request) body = <Card className="print:hidden"><p className="m-0 text-sm text-ink-muted">기간과 실을 구역을 고른 뒤 '보고서 만들기' 를 누르세요.</p></Card>
  else if (report.isPending) body = <LoadingState title="보고서를 만드는 중입니다" lines={4} />
  else if (!data) body = <ApiErrorState error={report.error} onRetry={() => void report.refetch()} retrying={report.isFetching} />
  else body = <>
    {report.error && <Banner tone="danger" className="print:hidden" title="보고서를 다시 만들지 못했습니다">{describeError(report.error)} · 이전 보고서를 그대로 둡니다</Banner>}
    <ReportHead report={data} />
    {REPORT_SECTIONS.map(name => {
      const section = data.sections[name]
      return section && <ReportSectionCard key={name} name={name} section={section} />
    })}
  </>

  return <div className="flex min-w-0 flex-col gap-4 print:gap-3">
    <PageHeader className="print:hidden" title="보고서" description="기간과 구역을 골라 한 장으로 모으고 브라우저 인쇄로 PDF 를 저장합니다."
      aside={<Button onClick={() => window.print()} disabled={!data} disabledReason="보고서를 만든 뒤 인쇄할 수 있습니다">인쇄 · PDF 저장</Button>} />
    {me.isPending ? <LoadingState /> : <>
      <ReportForm key={searchParams.toString()} initial={request ?? { period: DEFAULT_PERIOD, sections: visible }} visible={visible} admin={admin} busy={report.isFetching} onSubmit={generate} />
      {dropped && <Banner tone="warning" className="print:hidden" title="운영 기록은 관리자만 실을 수 있어 뺐습니다" />}
      {body}
    </>}
  </div>
}

/** 조건 양식. 주소가 바뀌면(뒤로 가기 포함) 새로 그려 주소의 조건으로 돌아간다. 동작 · 계산 설명은 ⓘ(양식은 종이에 찍히지 않는다) */
function ReportForm({ initial, visible, admin, busy, onSubmit }: {
  initial: ReportRequest; visible: readonly ReportSection[]; admin: boolean; busy: boolean
  onSubmit: (period: ReportPeriod, sections: readonly ReportSection[]) => void
}) {
  const [period, setPeriod] = useState<ReportPeriod>(initial.period)
  const [sections, setSections] = useState<readonly ReportSection[]>(initial.sections)
  function submit(event: FormEvent) {
    event.preventDefault()
    if (sections.length) onSubmit(period, visible.filter(name => sections.includes(name)))
  }
  return <Card className="print:hidden"><form aria-label="보고서 조건" onSubmit={submit} className="flex flex-col gap-4">
    <fieldset className="m-0 border-0 p-0"><legend className="mb-2 p-0 text-sm font-medium">기간</legend>
      <InfoTip label="기간" render={({ button, panel }) => <>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">{REPORT_PERIODS.map(p => <label key={p} className="flex cursor-pointer items-center gap-2"><input type="radio" name="report-period" value={p} checked={period === p} onChange={() => setPeriod(p)} className="size-3.5 accent-primary" />{PERIOD_LABEL[p]}</label>)}{button}</div>
        {panel}
      </>}>기간 끝은 보고서를 만든 시각(출력 시각)입니다. 끝 시각은 기간에 들지 않습니다.</InfoTip>
    </fieldset>
    <fieldset className="m-0 border-0 p-0"><legend className="mb-2 p-0 text-sm font-medium">실을 구역</legend>
      <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm">{visible.map(name => <label key={name} className="flex cursor-pointer items-center gap-2"><input type="checkbox" checked={sections.includes(name)} onChange={e => setSections(e.target.checked ? [...sections, name] : sections.filter(v => v !== name))} className="size-3.5 accent-primary" />{SECTION_LABEL[name]}</label>)}</div>
      {!admin && <p className="m-0 mt-2 text-xs text-ink-muted">운영 기록은 관리자만 실을 수 있습니다.</p>}
    </fieldset>
    <InfoTip label="보고서 만들기" render={({ button, panel }) => <>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Button type="submit" variant="primary" loading={busy} disabled={!sections.length} disabledReason="구역을 하나 이상 고르세요">보고서 만들기</Button>
        {button}
      </div>
      {panel}
    </>}>만든 뒤에는 저절로 다시 조회하지 않습니다. 같은 조건으로 다시 누르면 새로 만듭니다.</InfoTip>
  </form></Card>
}

/**
 * 보고서 머리. 기간(KST) · 출력 시각 · 출력자는 화면과 종이에 함께 나온다.
 * 제목과 구역별 기준은 종이에만 싣는다(화면은 구역 머리 오른쪽에 기준이 있다).
 */
function ReportHead({ report }: { report: PeriodReport }) {
  const names = REPORT_SECTIONS.filter(name => report.sections[name])
  const term = 'text-ink-muted', value = 'm-0 min-w-0'
  return <Card>
    <section aria-label="보고서 머리" className="flex flex-col gap-3">
      <h2 className="m-0 hidden text-xl font-semibold tracking-tight print:block">OpsLoop 기간 보고서 · {PERIOD_LABEL[report.period] ?? report.period}</h2>
      <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-1 text-sm">
        <dt className={term}>기간 (KST)</dt>
        <dd className={value}><Time value={report.since} /> ~ <Time value={report.until} zone /> · {PERIOD_LABEL[report.period] ?? report.period} · 끝 시각 제외</dd>
        <dt className={term}>출력 시각</dt>
        <dd className={value}><Time value={report.as_of} zone /></dd>
        <dt className={term}>출력자</dt>
        <dd className={value}><UntrustedText value={report.generated_by} clip fallback="미기록" /></dd>
        <dt className={`${term} hidden print:block`}>구역별 기준</dt>
        <dd className={`${value} hidden print:block`}><ul className="m-0 list-none p-0">{names.map(name => {
          const section = report.sections[name]!
          return <li key={name}>{SECTION_LABEL[name]} · {section.available ? BASIS_LABEL[section.basis] : '만들지 못함'}</li>
        })}</ul></dd>
      </dl>
    </section>
  </Card>
}
