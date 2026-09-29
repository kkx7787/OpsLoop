import { useLiveState } from '@/api/live-context'
import { describeError } from '@/api/errors'
import { loginHref } from '@/api/client'
import { Button } from '../atoms/Button'
import { Time } from '../atoms/Time'
import { Banner } from '../molecules/Banner'
import { InfoTip } from '../molecules/InfoTip'

/**
 * 공통 조회 띠. 웹소켓 끊김과 조회 실패를 구별하며 DB나 센서 상태를 추측하지 않는다.
 * 끊긴 동안의 주기 조회(30초)는 판단 근거라 ⓘ 로 접는다. 주기 조회가 없는 화면(출발지 지문 탭)은 자기 띠를 쓴다.
 */
export function MonitoringStatus({ updatedAt, error, onRetry, busy }: {
  updatedAt: number; error: unknown; onRetry: () => void; busy: boolean
}) {
  const live = useLiveState()
  if (error) return <Banner tone="danger" title="데이터를 갱신하지 못했습니다" action={<Button onClick={onRetry} loading={busy}>다시 조회</Button>}>
    {describeError(error)}{updatedAt > 0 && <> · 이전 결과 유지 · 마지막 조회 <Time value={updatedAt} format="time" zone /></>}
  </Banner>
  if (live.status === 'closed') return <Banner tone="danger" title="실시간 연결이 종료됐습니다" action={<a href={loginHref()}>다시 로그인</a>} />
  if (live.status === 'reconnecting') return <Banner tone="warning" title="실시간 연결이 끊겼습니다" action={<Button onClick={onRetry} loading={busy}>지금 조회</Button>}>
    자동으로 다시 연결합니다. <InfoTip label="실시간 연결 끊김">현재 화면은 30초마다 별도로 조회합니다.</InfoTip>
  </Banner>
  return null
}
