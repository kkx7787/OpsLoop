import { Link, useParams } from 'react-router'
import { useIncidentCti } from '@/api/cti'
import { isApiError } from '@/api/errors'
import { useIncident } from '@/api/incidents'
import { useNow } from '@/lib/useNow'
import { buttonClasses } from '@/components/atoms/button-styles'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { NotFoundState } from '@/components/organisms/states/NotFoundState'
import {
  ActorSection,
  BehaviorSection,
  IncidentHeader,
  RawLogSection,
  ResponseSection,
  RuleEvidenceSection,
  VulnLinkPanel,
} from '@/components/organisms/incident-detail'

/**
 * 인시던트 상세(S-04) + 판정 패널(S-05). 키는 경로에서 받는다(라우터가 부호화를 풀어 준다).
 * 사건이 바뀌면(관련 사건 링크) 안쪽을 새로 그려 판정 소요 시계가 다시 시작한다.
 */
export function IncidentDetailPage() {
  const { key = '' } = useParams()
  return <IncidentDetailView key={key} incidentKey={key} />
}

interface IncidentDetailViewProps {
  incidentKey: string
}

/**
 * 판정에 필요한 것을 한 화면에(화면 설계 5장). 왼쪽에 증거 ① ~ ④, 오른쪽에 조치와 판정 ⑤.
 * 서명 규칙 사건이면 왼쪽 끝에 ⑥ 취약점 연계(조사 우선순위 참고)가 붙는다. 판정 근거인 ① ~ ④ 보다 앞에 두지 않는다.
 * 좁은 화면에서는 왼쪽 열(① → ④ · ⑥) 다음에 ⑤ 가 세로로 쌓인다.
 */
function IncidentDetailView({ incidentKey }: IncidentDetailViewProps) {
  // 이 사건 화면을 연 시각. 판정 소요 시간(decision_seconds)의 시작점이다. 주기 0 이라 처음 값에서 멈춘다.
  const openedAt = useNow(0)
  const query = useIncident(incidentKey)
  // 상세와 함께(조기 반환 앞에서) 받는다. 구역은 그리기만 한다.
  const cti = useIncidentCti(incidentKey)

  if (query.isPending) {
    return <LoadingState size="page" titleAs="h1" title="인시던트를 불러오는 중입니다" description={<span className="font-mono">{incidentKey}</span>} lines={4} />
  }

  if (query.isError) {
    const error = query.error
    if (isApiError(error) && error.status === 404) {
      return (
        <NotFoundState
          size="page"
          titleAs="h1"
          eyebrow="S-04 · 404"
          title="인시던트를 찾을 수 없습니다"
          path={incidentKey}
          description={
            <>
              {error.detail}. 키가 바뀌었거나 다른 콘솔의 사건일 수 있습니다.{' '}
              <code className="font-mono text-xs break-all text-ink">{incidentKey}</code>
            </>
          }
          actions={
            <Link to="/incidents" className={buttonClasses({ size: 'lg' })}>
              인시던트 목록으로
            </Link>
          }
        />
      )
    }
    return <ApiErrorState size="page" titleAs="h1" error={error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
  }

  const detail = query.data
  return (
    <div className="flex flex-col gap-3">
      <IncidentHeader detail={detail} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px] xl:items-start">
        <div className="flex min-w-0 flex-col gap-3">
          <RuleEvidenceSection detail={detail} />
          <BehaviorSection rows={detail.behavior} actorIp={detail.actor_ip} />
          <ActorSection actor={detail.actor} related={detail.related} actorIp={detail.actor_ip} absorbed={detail.absorbed} />
          <RawLogSection raw={detail.raw} />
          <VulnLinkPanel data={cti.data} pending={cti.isPending} fetching={cti.isFetching} error={cti.error} onRetry={() => void cti.refetch()} />
        </div>
        <ResponseSection detail={detail} openedAt={openedAt} className="min-w-0" />
      </div>
    </div>
  )
}
