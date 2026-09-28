import { Link, useSearchParams } from 'react-router'
import { isApiError } from '@/api/errors'
import { isIpAddress, useSourceDetail } from '@/api/sources'
import { buttonClasses } from '@/components/atoms/button-styles'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { SourceMarks } from '@/components/organisms/sources/SourceBadges'
import {
  SourceActionsSection,
  SourceBlockSection,
  SourceEventsSection,
  SourceFingerprintsSection,
  SourceIncidentsSection,
  SourceSummarySection,
} from '@/components/organisms/sources/SourceDetailSections'
import { incidentsOfHref, sourceExempt, staleCheckers } from '@/components/organisms/sources/model'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ErrorState } from '@/components/organisms/states/ErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { NotFoundState } from '@/components/organisms/states/NotFoundState'

/**
 * 출발지 한 곳(S-09 · /sources/detail?ip=). 요약 · 사건 흐름 · 이벤트 종류 · 도구 지문 · 차단 상태 · 조치 이력.
 * 주소는 주소창에서 오므로 IPv4 · IPv6 한 주소가 아니면 묻지 않는다(서버도 422). 사건도 이벤트도 없으면 서버가 404 를 준다.
 * 판정 · 조치는 사건 단위라 이 화면에서 하지 않는다. 사건 목록(actor_ip 조건)이나 사건 상세로 넘어가서 한다.
 */
export function SourceDetailPage() {
  const [searchParams] = useSearchParams()
  const raw = searchParams.get('ip')?.trim() ?? ''
  const valid = isIpAddress(raw)
  const query = useSourceDetail(valid ? raw : '')

  if (!valid) return <InvalidAddress value={raw} />
  if (query.isPending) {
    return <LoadingState size="page" titleAs="h1" title="출발지를 불러오는 중입니다" description={<span className="font-mono">{raw}</span>} lines={4} />
  }
  if (query.isError && !query.data) {
    const error = query.error
    if (isApiError(error) && error.status === 422) return <InvalidAddress value={raw} />
    if (isApiError(error) && error.status === 404) {
      return (
        <NotFoundState
          size="page"
          titleAs="h1"
          eyebrow="S-09 · 404"
          title="이 출발지의 기록이 없습니다"
          description={<>{error.detail}. <code className="font-mono text-xs break-all text-ink">{raw}</code></>}
          actions={<Link to="/sources" className={buttonClasses({ size: 'lg' })}>출발지 목록으로</Link>}
        />
      )
    }
    return <ApiErrorState size="page" titleAs="h1" error={error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
  }

  const detail = query.data
  const stale = staleCheckers(detail.checkers)
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <PageHeader
        title={<span className="font-mono break-all">{detail.ip}</span>}
        badges={<SourceMarks testSource={detail.summary?.test_source} exempt={sourceExempt(detail)} />}
        description="이 주소의 사건 흐름 · 이벤트 종류 · 도구 지문 · 차단 상태 · 조치 이력을 모아 봅니다. 판정 · 조치는 사건에서 합니다."
        aside={<>
          {detail.incidents_total > 0 && <Link to={incidentsOfHref(detail.ip)} className={buttonClasses({ variant: 'primary', size: 'sm' })}>사건 목록에서 보기</Link>}
          <Link to="/sources" className={buttonClasses({ size: 'sm' })}>출발지 목록</Link>
        </>}
      />
      <MonitoringStatus updatedAt={query.dataUpdatedAt} error={query.error} onRetry={() => void query.refetch()} busy={query.isFetching} />
      {stale.length > 0 && (
        <Banner tone="warning" title="집행기 확인이 멈췄습니다">
          {stale.join(' · ')} · 10분 넘게 확인이 없어 그 지점의 '적용 확인'을 '확인 지연'으로 보입니다
        </Banner>
      )}
      <SourceSummarySection detail={detail} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px] xl:items-start">
        <div className="flex min-w-0 flex-col gap-3">
          <SourceIncidentsSection detail={detail} />
          <SourceEventsSection detail={detail} />
          <SourceFingerprintsSection detail={detail} />
        </div>
        <div className="flex min-w-0 flex-col gap-3">
          <SourceBlockSection detail={detail} />
          <SourceActionsSection detail={detail} />
        </div>
      </div>
    </div>
  )
}

/** 주소가 없거나 한 주소(IPv4 · IPv6)가 아니다. 값은 주소창에서 온 글자라 글자로만 보인다 */
function InvalidAddress({ value }: { value: string }) {
  return (
    <ErrorState
      size="page"
      titleAs="h1"
      eyebrow="S-09 · 422"
      title="출발지 주소가 올바르지 않습니다"
      description={<>IPv4 · IPv6 주소 하나만 볼 수 있습니다. <code className="font-mono text-xs break-all text-ink"><UntrustedText value={value} max={64} fallback="주소 없음" /></code></>}
      actions={<Link to="/sources" className={buttonClasses({ size: 'lg' })}>출발지 목록으로</Link>}
    />
  )
}
