import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ASSET_ID_PATTERN, lastVulnOffset, useAsset, useAssets, useWatch, type VulnFilter } from '@/api/cti'
import { describeError } from '@/api/errors'
import { Button } from '@/components/atoms/Button'
import { Time } from '@/components/atoms/Time'
import { buttonClasses } from '@/components/atoms/button-styles'
import { Banner } from '@/components/molecules/Banner'
import { InfoTip } from '@/components/molecules/InfoTip'
import { PageHeader } from '@/components/molecules/PageHeader'
import { AssetDetailSection, AssetTable, CtiFreshnessFacts, staleSources, WatchCard } from '@/components/organisms/assets'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { EmptyState } from '@/components/organisms/states/EmptyState'
import { LoadingState } from '@/components/organisms/states/LoadingState'

interface VulnView { asset: string; filter: VulnFilter; offset: number }

/**
 * 자산 · 취약점(#39). 자산 목록 · 선택한 자산 상세를 먼저, 주목 CVE 대조를 그 아래에 둔다. 노드마다 설치된 패키지 · 컨테이너와
 * 배포판 기준 취약점(OSV)에 KEV · EPSS 를 붙여 보인다.
 * 고른 자산은 주소(?asset=)에 두어 새로고침 · 공유에도 남는다. 거르기 · 쪽은 그 자산에만 붙고, 다른 자산을 고르면 처음부터 본다.
 * 세 조회(주목 CVE · 자산 목록 · 자산 상세)는 이 페이지가 갖고 카드 · 표 · 상세는 그리기만 한다. 원본이 하루 단위로 바뀌어 주기 재조회는 두지 않는다.
 * 주목 CVE 는 자산 목록과 따로 받아, 한쪽이 실패해도 다른 쪽은 그대로 보인다.
 */
export function AssetsPage() {
  const watch = useWatch()
  const assets = useAssets()
  const [params, setParams] = useSearchParams()
  const raw = params.get('asset') ?? ''
  const selected = ASSET_ID_PATTERN.test(raw) ? raw : ''
  const detailRef = useRef<HTMLDivElement>(null)
  const assetListRef = useRef<HTMLDivElement>(null)
  const previousAsset = useRef(selected)
  useEffect(() => {
    if (selected) { detailRef.current?.scrollIntoView?.({ block: 'start' }); detailRef.current?.focus({ preventScroll: true }) }
    else if (previousAsset.current) assetListRef.current?.querySelector<HTMLButtonElement>(`[data-asset="${previousAsset.current}"] button`)?.focus()
    previousAsset.current = selected
  }, [selected])
  const [view, setView] = useState<VulnView>({ asset: '', filter: 'all', offset: 0 })
  const filter = view.asset === selected ? view.filter : 'all'
  const offset = view.asset === selected ? view.offset : 0
  const detail = useAsset(selected, filter, offset)
  const vulns = detail.data?.available ? detail.data.vulnerabilities : null
  const lastOffset = vulns ? lastVulnOffset(vulns.total, vulns.limit) : 0
  // 자리표시(이전 쪽 결과)가 아니라 이 쪽의 답인데 offset 이 총수를 넘었다: 뒤쪽을 보는 동안 대조가 다시 돌아 총수가 줄었다
  const outOfRange = !!vulns && !detail.isPlaceholderData && !detail.isError && offset > 0 && offset >= vulns.total
  // 빈 쪽을 '취약점 없음'으로 읽지 않게 유효한 마지막 쪽으로 돌아간다. 그리는 도중에 상태를 맞춰(React 의 '이전 렌더 값으로 상태 조정')
  // 빈 쪽이 한 번도 화면에 나가지 않게 한다. 새 offset 은 늘 더 작아 되풀이되지 않고 0 에서 멈춘다
  if (outOfRange) setView({ asset: selected, filter, offset: lastOffset })

  const select = (assetId: string) => setParams(assetId ? { asset: assetId } : {}, { replace: true })
  const data = assets.data
  const stale = staleSources(data?.freshness)

  return <div className="flex min-w-0 flex-col gap-4">
    <InfoTip label="자산 · 취약점" render={({ button, panel }) => (
      <PageHeader title="자산 · 취약점" badges={button} description={<>자산별 취약점과 수정 상태를 확인합니다.{panel}</>} aside={<Link className={buttonClasses({})} to="/nodes">수집 노드</Link>} />
    )}>KEV · EPSS · 주목 CVE 는 조사 · 조치 우선순위 참고용이며 사건 판정의 근거가 아닙니다.</InfoTip>
    {data && assets.error ? <Banner tone="danger" title="데이터를 갱신하지 못했습니다" action={<Button onClick={() => void assets.refetch()} loading={assets.isFetching}>다시 조회</Button>}>
      {describeError(assets.error)} · 이전 결과 유지 · 마지막 조회 <Time value={assets.dataUpdatedAt} format="time" zone />
    </Banner> : null}
    {assets.isPending ? <LoadingState /> : !data ? <ApiErrorState error={assets.error} onRetry={() => void assets.refetch()} retrying={assets.isFetching} /> : !data.available ? (
      <EmptyState title="공개 취약점 정보 표가 아직 없습니다" description="수집 상태를 확인해 주세요." />
    ) : <>
      {stale.length > 0 && <Banner tone="warning">공개 정보가 오래됐습니다. 비해당으로 읽지 않습니다. 오래된 출처: {stale.join(' · ')}</Banner>}
      {data.freshness && <details className="rounded-panel border border-line px-3 py-2 text-xs text-ink-muted">
        <summary className="cursor-pointer">공개 정보 신선도 · <Time value={data.as_of} format="time" zone /> 조회 기준</summary>
        <div className="mt-3"><CtiFreshnessFacts freshness={data.freshness} /></div>
        <ul className="m-0 mt-3 list-none space-y-0.5 p-0 leading-5">
          <li>48시간 넘게 새로 받지 못하면 오래됨입니다.</li>
          <li>배포판 대조는 Ubuntu 보안 정보(OSV) 기준이며, 직접 설치한 프로그램은 대조하지 않습니다(미확인).</li>
        </ul>
      </details>}
      {selected && <div ref={detailRef} tabIndex={-1} className="scroll-mt-16 outline-none"><AssetDetailSection
        assetId={selected}
        data={detail.data}
        pending={detail.isPending}
        fetching={detail.isFetching}
        error={detail.error}
        onRetry={() => void detail.refetch()}
        filter={filter}
        offset={offset}
        onFilter={(next) => setView({ asset: selected, filter: next, offset: 0 })}
        onOffset={(next) => setView({ asset: selected, filter, offset: next })}
        onClose={() => select('')}
      /></div>}
      <div ref={assetListRef}><AssetTable rows={data.rows ?? []} selected={selected} onSelect={select} /></div>
    </>}
    <WatchCard data={watch.data} pending={watch.isPending} fetching={watch.isFetching} error={watch.error} onRetry={() => void watch.refetch()} />
  </div>
}
