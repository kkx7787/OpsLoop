import { Link } from 'react-router'
import { useSummary } from '@/api/monitoring'
import { Card, CardHeader } from '@/components/atoms/Card'
import { SeverityBadge } from '@/components/atoms/SeverityBadge'
import { Time } from '@/components/atoms/Time'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { formatDuration } from '@/lib/time'
import { sensorOf } from '@/lib/domain'
import { cn } from '@/lib/cn'

const AGE_LABELS = ['1시간 미만', '1–4시간', '4–12시간', '12–24시간', '24시간 이상']

export function DashboardPage() {
  const query = useSummary()
  const data = query.data
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="미판정 현황" aside={data && <span className="text-xs text-ink-muted"><Time value={data.as_of} format="time" zone /> 기준</span>} />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
    {query.isPending ? <LoadingState title="대시보드를 불러오는 중입니다" /> : !data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} /> : <>
      <Card padding="none">
        <dl className="m-0 grid grid-cols-2 divide-x divide-line md:grid-cols-4">
          <Metric label="가장 오래된 미판정" value={data.pending.total ? formatDuration(data.pending.oldest_seconds * 1000) : '없음'} warn={data.pending.overdue > 0} />
          <Metric label="미판정" value={`${data.pending.total.toLocaleString()}건`} href="/incidents?judged=false" />
          <Metric label="판정 목표 초과" value={`${data.pending.overdue.toLocaleString()}건`} note={`목표 임박 ${data.pending.warning.toLocaleString()}건`} warn={data.pending.overdue > 0} />
          <Metric label="활성 차단 요청" value={`${data.blocked_ips.toLocaleString()}건`} href="/blocklist" />
        </dl>
      </Card>
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <Card padding="none" className="min-w-0">
          <CardHeader title="먼저 확인할 사건" aside={<Link to="/incidents?judged=false">미판정 전체 보기 →</Link>} />
          {data.oldest_pending.length ? <ol className="m-0 list-none divide-y divide-line p-0">
            {data.oldest_pending.map(item => <li key={item.incident_key}>
              <Link to={`/incidents/${encodeURIComponent(item.incident_key)}`} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-3 hover:bg-canvas sm:grid-cols-[110px_minmax(0,1fr)_auto]">
                <div className={cn('text-sm font-semibold tabular-nums', item.overdue ? 'text-warning' : 'text-ink')}>
                  {formatDuration(item.pending_seconds * 1000, 'compact')}
                  <div className="text-xs font-normal">{item.overdue ? '목표 초과' : `목표 ${formatDuration(item.target_seconds * 1000)}`}</div>
                </div>
                <div className="col-span-2 row-start-2 min-w-0 sm:col-span-1 sm:row-auto">
                  <div className="break-words text-sm text-ink"><span className="mr-2 font-mono text-primary">{item.rule_id}</span>{item.rule_name}</div>
                  <div className="mt-0.5 break-all text-xs text-ink-muted"><span className="font-mono">{item.actor_ip ?? item.target ?? '대상 없음'}</span> · {sensorOf(item.rule_id)}</div>
                </div>
                <SeverityBadge severity={item.severity} className="col-start-2 row-start-1 justify-self-end sm:col-start-3" />
              </Link>
            </li>)}
          </ol> : <p className="m-0 px-4 py-8 text-ink-muted">미판정 사건이 없습니다. 최근 수집 시각도 함께 확인해 주세요.</p>}
          <p className="m-0 border-t border-line px-4 py-2 text-xs text-ink-muted">오래된 순 · 최대 8건 · 전체 규칙 버전</p>
        </Card>
        <Card padding="none">
          <CardHeader title="미판정 경과 시간" />
          <ul className="m-0 flex list-none flex-col gap-4 p-4">
            {AGE_LABELS.map((label, index) => {
              const count = data.pending.age_distribution[index] ?? 0
              const percent = data.pending.total ? count / data.pending.total * 100 : 0
              return <li key={label}>
                <div className="mb-1.5 flex justify-between gap-2 text-xs"><span>{label}</span><span className="tabular-nums">{count.toLocaleString()}건</span></div>
                <div className="h-1.5 overflow-hidden rounded-sm bg-line" aria-hidden="true"><div className="h-full bg-primary" style={{ width: `${percent}%` }} /></div>
              </li>
            })}
          </ul>
          <div className="border-t border-line px-4 py-3 text-xs leading-5 text-ink-muted">판정 목표: critical 1시간 · high 4시간 · medium 12시간 · low 24시간. 콘솔·감사 사건은 1시간입니다.</div>
        </Card>
      </div>
      <Card padding="none" className="min-w-0">
        <CardHeader title="규칙별 비조치율" aside="사건별 마지막 판정 기준" />
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs text-ink-muted"><tr>{['규칙', '버전', '전체 사건', '유효 판정', '비조치', '비조치율'].map(label => <th key={label} className="px-4 py-2 font-medium whitespace-nowrap">{label}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{data.rule_quality.map(row => <tr key={`${row.rule_id}:${row.rule_version}`}>
              <td className="px-4 py-2.5 font-mono"><Link to={`/incidents?rule_id=${encodeURIComponent(row.rule_id)}`}>{row.rule_id}</Link></td>
              <td className="px-4 py-2.5">{row.rule_version}</td><td className="px-4 py-2.5 tabular-nums">{row.incidents}</td><td className="px-4 py-2.5 tabular-nums">{row.judged_effective}</td><td className="px-4 py-2.5 tabular-nums">{row.non_action}</td>
              <td className="px-4 py-2.5 font-medium tabular-nums">{row.non_action_rate === null ? <span className="text-xs text-ink-muted">판정 없음</span> : `${Number(row.non_action_rate).toFixed(1)}%`}</td>
            </tr>)}</tbody>
          </table>
        </div>
        {!data.rule_quality.length && <p className="px-4 text-ink-muted">집계할 사건이 없습니다.</p>}
        <p className="m-0 border-t border-line px-4 py-2 text-xs text-ink-muted">비조치 = 무시 가능 + 오탐 + 양성 정탐. 미결은 분모에서 제외합니다. 높은 비율만으로 규칙의 오류를 뜻하지 않습니다.</p>
      </Card>
      <p className="m-0 text-xs text-ink-muted">최근 원문 수집 <Time value={data.latest_event} format="short" zone /> · 웹소켓 통보 시 갱신 · 30초마다 재조회</p>
    </>}
  </div>
}

function Metric({ label, value, note, href, warn }: { label: string; value: string; note?: string; href?: string; warn?: boolean }) {
  return <div className="min-w-0 px-4 py-4"><dt className="text-xs text-ink-muted">{label}</dt><dd className={cn('m-0 mt-1.5 break-words text-xl font-semibold tracking-heading tabular-nums', warn && 'text-warning')}>{href ? <Link to={href}>{value}</Link> : value}</dd>{note && <div className="mt-1 text-xs text-ink-muted">{note}</div>}</div>
}
