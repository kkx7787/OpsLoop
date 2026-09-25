import { useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { createChannel, notifyKeys, testChannel, updateChannel, useChannels, useDeliveries, type ChannelInput, type DeliveryFilters, type NotifyChannel } from '@/api/notify'
import { describeError } from '@/api/errors'
import { useMe } from '@/auth/useMe'
import { Button } from '@/components/atoms/Button'
import { UntrustedText } from '@/components/atoms/UntrustedText'
import { Banner, type BannerTone } from '@/components/molecules/Banner'
import { PageHeader } from '@/components/molecules/PageHeader'
import { MonitoringStatus } from '@/components/organisms/MonitoringStatus'
import { ChannelForm } from '@/components/organisms/notify/ChannelForm'
import { ChannelTable } from '@/components/organisms/notify/ChannelTable'
import { DeliveryTable } from '@/components/organisms/notify/DeliveryTable'
import { deliveryProblem } from '@/components/organisms/notify/problem'
import { ApiErrorState } from '@/components/organisms/states/ApiErrorState'
import { ForbiddenState } from '@/components/organisms/states/ForbiddenState'
import { LoadingState } from '@/components/organisms/states/LoadingState'
import { revealHidden } from '@/lib/untrusted'

interface Notice { tone: BannerTone; title: string; body?: ReactNode }
type Editing = 'new' | NotifyChannel | null
const DELIVERY_DEFAULTS: DeliveryFilters = { limit: 25, offset: 0 }

/** 바꾸기 본문: 기존 값 그대로, url 은 빼서 서버가 유지하게 한다 */
function inputOf(c: NotifyChannel, enabled: boolean): ChannelInput {
  return { name: c.name, kind: c.kind, grade: c.grade, events: c.events, min_severity: c.min_severity, batch_seconds: c.batch_seconds, template_header: c.template_header, template_item: c.template_item, enabled }
}

/**
 * 알림 설정(S-12). admin 만 채널을 만들고 고치고 시험 발송하며 발송 이력을 본다.
 * 목록 · 이력은 30초마다 다시 조회하고, 만들기 · 바꾸기 · 시험 발송 뒤에는 바로 다시 조회한다.
 * 두 조회는 이 페이지가 갖고 표는 그리기만 한다. 어느 쪽이든 재조회가 실패하면 상단 띠로 알린다.
 */
export function AlertsPage() {
  const me = useMe(), client = useQueryClient()
  const allowed = me.data?.role === 'admin'
  const channels = useChannels(allowed)
  const [filters, setFilters] = useState<DeliveryFilters>(DELIVERY_DEFAULTS)
  const deliveries = useDeliveries(filters, allowed)
  // 이전 결과가 있는데 재조회가 실패한 쪽을 띠로 보인다(첫 조회 실패는 각 자리의 오류 화면). 갱신 시각은 오래된 쪽
  const staleError = (channels.data ? channels.error : null) ?? (deliveries.data ? deliveries.error : null)
  const stamps = [channels.dataUpdatedAt, deliveries.dataUpdatedAt].filter((t) => t > 0)
  const updatedAt = stamps.length ? Math.min(...stamps) : 0
  const [editing, setEditing] = useState<Editing>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [saving, setSaving] = useState(false), [busyId, setBusyId] = useState<number | null>(null)
  const pending = useRef(false)

  const refresh = () => client.invalidateQueries({ queryKey: notifyKeys.all })

  async function save(input: ChannelInput) {
    if (pending.current || !editing) return
    pending.current = true; setSaving(true); setNotice(null)
    try {
      const saved = editing === 'new' ? await createChannel(input) : await updateChannel(editing.id, input)
      setNotice({ tone: 'info', title: editing === 'new' ? `채널 ${revealHidden(saved.name)} 을(를) 추가했습니다.` : `채널 ${revealHidden(saved.name)} 을(를) 바꿨습니다.` })
      setEditing(null)
      await refresh()
    } catch (e) { setNotice({ tone: 'danger', title: describeError(e) }) }
    finally { pending.current = false; setSaving(false) }
  }
  async function toggle(c: NotifyChannel) {
    if (busyId !== null) return
    setBusyId(c.id); setNotice(null)
    try { await updateChannel(c.id, inputOf(c, !c.enabled)); setNotice({ tone: 'info', title: `채널 ${revealHidden(c.name)} 을(를) ${c.enabled ? '중지' : '사용'}했습니다.` }) }
    catch (e) { setNotice({ tone: 'danger', title: describeError(e) }) }
    finally { setBusyId(null); await refresh() }
  }
  async function test(c: NotifyChannel) {
    if (busyId !== null) return
    setBusyId(c.id); setNotice(null)
    try {
      const result = await testChannel(c.id)
      setNotice(result.status === 'sent'
        ? { tone: 'success', title: `시험 발송 성공 · ${revealHidden(c.name)}`, body: `응답 ${result.response_code ?? '-'} · 이력에 시험 발송으로 남았습니다.` }
        // 실패 원인은 받는 쪽(웹훅)이 준 글이라 비신뢰 원문으로 그린다
        : { tone: 'danger', title: `시험 발송 실패 · ${revealHidden(c.name)}`, body: <UntrustedText value={deliveryProblem(result.error, result.response_code)} fallback="응답 없음" /> })
    } catch (e) { setNotice({ tone: 'danger', title: `시험 발송 실패 · ${revealHidden(c.name)}`, body: describeError(e) }) }
    finally { setBusyId(null); await refresh() }
  }

  return <div className="flex min-w-0 flex-col gap-4">
    <PageHeader title="알림 설정" description="Teams · 웹훅 채널과 메시지 틀을 관리하고 발송 이력을 확인합니다." aside={allowed && <Button variant="primary" disabled={editing !== null} title={editing !== null ? '열린 양식을 저장하거나 닫은 뒤 추가할 수 있습니다' : undefined} onClick={() => { setEditing('new'); setNotice(null) }}>채널 추가</Button>} />
    {me.isPending ? <LoadingState /> : !allowed ? <ForbiddenState title="이 화면은 admin 만 볼 수 있습니다" requiredRoles="admin" currentRole={me.data?.role} /> : <>
      <MonitoringStatus updatedAt={updatedAt} error={staleError} onRetry={() => { void channels.refetch(); void deliveries.refetch() }} busy={channels.isFetching || deliveries.isFetching} />
      {notice && <Banner tone={notice.tone} title={notice.title} action={<Button size="sm" onClick={() => setNotice(null)}>닫기</Button>}>{notice.body}</Banner>}
      {editing && <ChannelForm key={editing === 'new' ? 'new' : editing.id} initial={editing === 'new' ? undefined : editing} busy={saving} onSubmit={save} onCancel={() => setEditing(null)} />}
      {channels.isPending ? <LoadingState /> : !channels.data ? <ApiErrorState error={channels.error} onRetry={() => void channels.refetch()} /> : <>
        <ChannelTable channels={channels.data} busyId={busyId} onEdit={(c) => { setEditing(c); setNotice(null) }} onToggle={(c) => void toggle(c)} onTest={(c) => void test(c)} />
        <DeliveryTable channels={channels.data} filters={filters} onFilters={setFilters} data={deliveries.data} pending={deliveries.isPending} fetching={deliveries.isFetching} error={deliveries.error} onRetry={() => void deliveries.refetch()} />
        <p className="m-0 text-xs leading-5 text-ink-muted">즉시 등급은 같은 종류의 첫 사건부터 묶음 시간 동안 모아 한 메시지로 보내고, 일일 요약은 매일 09:00 KST 에 미판정 현황을 보냅니다. 채널 주소는 저장 뒤 다시 볼 수 없으며 메시지에는 원문 로그 · 내부 주소를 넣지 않습니다. 30초마다 재조회</p>
      </>}
    </>}
  </div>
}
