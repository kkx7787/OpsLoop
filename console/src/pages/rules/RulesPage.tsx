/* oxlint-disable jsx-a11y/no-noninteractive-tabindex -- 가로 스크롤 표를 키보드로도 스크롤할 수 있게 한다. */
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { useRulesResult } from '@/api/operations'
import { Badge } from '@/components/atoms/Badge'
import { Button } from '@/components/atoms/Button'
import { Card, CardHeader } from '@/components/atoms/Card'
import { Input } from '@/components/atoms/Input'
import { Select } from '@/components/atoms/Select'
import { Time } from '@/components/atoms/Time'
import { Banner } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { readInterval } from '@/lib/interval'

const cell = 'px-4 py-2.5 whitespace-nowrap'
const percent = (n: number | null) => n === null ? '판정 없음' : `${Number(n).toFixed(1)}%`
export function RulesPage() {
  const [start, setStart] = useState(''), [end, setEnd] = useState('')
  const [period, setPeriod] = useState<{ since?: string; until?: string }>({})
  const [error, setError] = useState('')
  const [version, setVersion] = useState(''), [before, setBefore] = useState(''), [after, setAfter] = useState('')
  const query = useRulesResult(period.since, period.until)
  const data = query.data
  function filter(event: FormEvent) {
    event.preventDefault()
    try { setPeriod(readInterval(start, end)); setError('') } catch (e) { setError((e as Error).message) }
  }
  const versions = data?.versions ?? []
  const shown = data?.rows.filter(row => !version || row.rule_version === version) ?? []
  const names = new Map(versions.flatMap(v => v.rules.map(r => [`${v.version}:${r.id}`, r] as const)))
  const base = before || versions[0]?.version || '', compare = after || versions[1]?.version || ''
  const comparison = [...new Set(data?.rows.filter(r => [base, compare].includes(r.rule_version)).map(r => r.rule_id))].sort()
  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="규칙 · 리플레이" description="판정 결과와 규칙 버전별 저장 결과를 비교합니다." />
    <MonitoringStatus updatedAt={query.dataUpdatedAt} error={data ? query.error : null} onRetry={() => void query.refetch()} busy={query.isFetching} />
    <Card><form onSubmit={filter} className="grid gap-3 sm:flex sm:flex-wrap sm:items-end">
      <label htmlFor="rules-field-0" className="grid gap-1 text-xs">시작 (KST)<Input id="rules-field-0" type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
      <label htmlFor="rules-field-1" className="grid gap-1 text-xs">종료 (KST)<Input id="rules-field-1" type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
      <div className="flex gap-2"><Button type="submit" variant="primary">구간 조회</Button><Button onClick={() => { setStart(''); setEnd(''); setPeriod({}); setError('') }}>전체 기간</Button></div>
      <span className="text-xs text-ink-muted">{period.since ? '선택한 구간의 사건 시작 시각 기준' : '전체 기간 · 버전별 관측 구간이 다를 수 있음'}</span>
    </form></Card>
    {error && <Banner tone="danger" title={error} />}
    {query.isPending ? <LoadingState /> : !data ? <ApiErrorState error={query.error} onRetry={() => void query.refetch()} /> : <>
      <Card padding="none" className="min-w-0">
        <CardHeader title="규칙별 판정 집계" aside={<Select aria-label="규칙 버전" fieldSize="sm" value={version} onChange={e => setVersion(e.target.value)}><option value="">전체 버전</option>{versions.map(v => <option key={v.version}>{v.version}</option>)}</Select>} />
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="규칙별 판정 집계 표"><table className="w-full text-left text-sm">
          <thead className="border-b border-line text-xs text-ink-muted"><tr>{['규칙 · 버전', '사건', '판정', '실제 위협', '무시 가능', '오탐', '양성 정탐', '미결', '비조치율', '오탐률'].map(t => <th key={t} className={cell}>{t}</th>)}</tr></thead>
          <tbody className="divide-y divide-line">{shown.map(r => <tr key={`${r.rule_id}:${r.rule_version}`}><td className={cell}><Link title="이 규칙의 모든 버전 사건 보기" to={`/incidents?rule_id=${encodeURIComponent(r.rule_id)}`}><span className="font-mono">{r.rule_id}</span> · {r.rule_version}</Link><div className="text-xs text-ink-muted">{names.get(`${r.rule_version}:${r.rule_id}`)?.name ?? '이름 미기록'}</div></td>{[r.incidents,r.judged,r.threats,r.non_actionable,r.false_positives,r.benign_positives,r.undetermined].map((n,i) => <td key={i} className={`${cell} tabular-nums`}>{n}</td>)}<td className={cell}>{percent(r.non_action_rate)}</td><td className={cell}>{['R002','R003','R004'].includes(r.rule_id) ? <span title="규칙 조건과 판정 근거가 겹쳐 독립적인 정확도 지표로 사용하지 않습니다">순환 규칙</span> : percent(r.false_positive_rate)}</td></tr>)}</tbody>
        </table></div>
        {!shown.length && <p className="p-4 text-sm text-ink-muted">선택한 조건에 집계된 사건이 없습니다.</p>}
        <p className="m-0 border-t border-line px-4 py-3 text-xs text-ink-muted">사건별 마지막 판정 기준. 비조치 = 무시 가능 + 오탐 + 양성 정탐. 비율의 분모에서 미결은 제외합니다.</p>
      </Card>
      <Card padding="none"><CardHeader title="리플레이 결과 비교" aside="저장된 사건 기준" />
        <div className="flex flex-wrap items-end gap-3 p-4"><label className="grid gap-1 text-xs">기준 버전<Select value={base} onChange={e => setBefore(e.target.value)}>{versions.map(v => <option key={v.version}>{v.version}</option>)}</Select></label><span className="pb-2 text-ink-muted">→</span><label className="grid gap-1 text-xs">비교 버전<Select value={compare} onChange={e => setAfter(e.target.value)}>{versions.map(v => <option key={v.version}>{v.version}</option>)}</Select></label></div>
        {!period.since || base === compare ? <p className="m-0 px-4 pb-4 text-sm text-ink-muted">서로 다른 두 버전과 동일한 시작·종료 구간을 선택해 주세요.</p> : <>
          <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-y border-line text-xs text-ink-muted"><tr>{['규칙',base,compare,'증감'].map((t,i) => <th key={i} className={cell}>{t}</th>)}</tr></thead><tbody className="divide-y divide-line">{comparison.map(id => { const a=data.rows.find(r => r.rule_id===id && r.rule_version===base)?.incidents, b=data.rows.find(r => r.rule_id===id && r.rule_version===compare)?.incidents; return <tr key={id}><td className={`${cell} font-mono`}>{id}</td><td className={cell}>{a ?? '결과 없음'}</td><td className={cell}>{b ?? '결과 없음'}</td><td className={cell}>{a === undefined || b === undefined ? '—' : `${b-a > 0 ? '+' : ''}${b-a}`}</td></tr> })}</tbody></table></div>
          {!comparison.length && <p className="px-4 text-sm text-ink-muted">이 구간에 저장된 비교 결과가 없습니다.</p>}
          <p className="m-0 border-t border-line p-4 text-xs text-ink-muted">원문을 다시 실행하지 않습니다. 동일 입력으로 두 버전을 실행했는지는 실행 이력과 함께 확인해야 합니다. 사건 수 감소만으로 정확도나 재현율 개선을 뜻하지 않습니다.</p>
        </>}
      </Card>
      <Card padding="none"><CardHeader title="최근 탐지 실행" aside="최근 30회 · 신규 생성 수" /><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs text-ink-muted"><tr>{['버전','실행 시각 (KST)','입력 시작 (KST)','입력 종료 (KST)','신규 사건'].map(t => <th className={cell} key={t}>{t}</th>)}</tr></thead><tbody className="divide-y divide-line">{data.runs.map(r => <tr key={r.id}><td className={cell}>{r.rule_version}</td><td className={cell}><Time value={r.finished_at} format="short" /></td><td className={cell}>{r.since ? <Time value={r.since} format="short" /> : '전체'}</td><td className={cell}>{r.until ? <Time value={r.until} format="short" /> : '상한 없음'}</td><td className={cell}>{r.incidents}</td></tr>)}</tbody></table></div>{!data.runs.length && <p className="px-4 text-sm text-ink-muted">저장된 실행 기록이 없습니다.</p>}</Card>
      <Card padding="none"><CardHeader title="규칙 버전 · 변경 근거" /><div className="divide-y divide-line">{versions.map(v => <details key={v.version} className="p-4"><summary className="cursor-pointer text-sm font-semibold">{v.version} · <Time value={v.created_at} format="short" /> · {v.rules.length}개 규칙</summary><p className="text-sm leading-6">{v.reason || '변경 사유 미기록'}</p><ul className="list-none space-y-3 p-0">{v.rules.map(r => <li key={r.id} className="text-sm"><span className="font-mono">{r.id}</span> {r.name} <Badge tone="neutral">{r.enabled ? '정의상 활성' : '비활성'}</Badge>{(r.change || r.rationale) && <p className="m-0 mt-1 text-xs leading-5 text-ink-muted">{r.change || r.rationale}</p>}</li>)}</ul></details>)}</div><p className="m-0 border-t border-line p-4 text-xs text-ink-muted">규칙 정의의 활성 여부이며 현재 실행 중인 버전이라는 뜻은 아닙니다. 실제 실행은 위 이력을 확인하세요.</p></Card>
    </>}
  </div>
}
