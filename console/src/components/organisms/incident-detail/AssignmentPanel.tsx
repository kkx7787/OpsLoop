import { useId, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { describeError } from '@/api/errors'
import { incidentKeys, incidentPath, newerWorkflow, type IncidentDetail } from '@/api/incidents'
import { useMe } from '@/auth/useMe'
import { revealHidden } from '@/lib/untrusted'
import { Button } from '../../atoms/Button'
import { Select } from '../../atoms/Select'
import { UntrustedText } from '../../atoms/UntrustedText'

export function AssignmentPanel({ detail, expectedVersion, blocked, onSaved }: {
  detail: IncidentDetail; expectedVersion?: string; blocked: boolean; onSaved: (version?: string) => void
}) {
  const { data: me } = useMe()
  const client = useQueryClient()
  const id = useId()
  const [target, setTarget] = useState('')
  const admin = me?.role === 'admin'
  const allowed = admin || me?.role === 'operator'
  const candidates = useQuery({
    queryKey: ['incident-operators'], enabled: admin,
    queryFn: ({ signal }) => api.get<Array<{ username: string; role: string }>>('/api/incident-operators', { signal }),
    staleTime: 30_000,
  })
  const mutation = useMutation({
    mutationFn: (username: string | null) => api.post<{ assigned_to: string | null; workflow_version: string }>(`${incidentPath(detail.incident_key)}/assignment`, { username, expected_version: expectedVersion }),
    onSuccess: result => {
      client.setQueryData<IncidentDetail>(incidentKeys.detail(detail.incident_key), old => old && !newerWorkflow(old, result.workflow_version) ? { ...old, ...result, assignee_available: !!result.assigned_to } : old)
      onSaved(result.workflow_version)
      setTarget('')
      void client.invalidateQueries({ queryKey: incidentKeys.detail(detail.incident_key) })
      void client.invalidateQueries({ queryKey: incidentKeys.lists() })
    },
    onError: () => {
      void client.invalidateQueries({ queryKey: incidentKeys.detail(detail.incident_key) })
      void client.invalidateQueries({ queryKey: ['incident-operators'] })
    },
  })
  const mine = !!me && detail.assigned_to === me.username
  const unavailable = !!detail.assigned_to && detail.assignee_available === false
  return <div className="flex flex-col gap-2" aria-label="사건 담당">
    <p className="m-0 text-sm">담당 <strong><UntrustedText value={detail.assigned_to} fallback="미배정" /></strong>{mine && ' · 나'}{unavailable && <span className="text-warning"> · 담당 변경 필요</span>}</p>
    {unavailable && <p className="m-0 text-xs text-ink-muted">기존 담당 계정이 비활성 또는 조회 전용입니다. 다른 관제자가 인수할 수 있습니다.</p>}
    {allowed && <div className="flex flex-wrap items-center gap-2">
      {(!detail.assigned_to || unavailable || admin) && !mine && <Button size="sm" disabled={blocked || mutation.isPending} onClick={() => mutation.mutate(me!.username)}>내가 담당</Button>}
      {(mine || admin) && detail.assigned_to && <Button size="sm" disabled={blocked || mutation.isPending} onClick={() => mutation.mutate(null)}>담당 해제</Button>}
      {admin && <><label htmlFor={id} className="sr-only">담당자 선택</label><Select id={id} fieldSize="sm" className="min-w-0 max-w-full" value={target} onChange={e => setTarget(e.target.value)} disabled={blocked || mutation.isPending || candidates.isPending || candidates.isError}>
        <option value="">담당자 선택</option>{candidates.data?.map(user => <option key={user.username} value={user.username}>{revealHidden(user.username)}</option>)}
      </Select><Button size="sm" disabled={blocked || mutation.isPending || !target || candidates.isError} onClick={() => mutation.mutate(target)}>배정</Button></>}
    </div>}
    {allowed && <p className="m-0 text-xs text-ink-muted">담당 배정 후에도 다른 관제자의 조치 권한은 유지됩니다.</p>}
    {candidates.isError && admin && <p role="alert" className="m-0 text-sm text-danger">담당자 목록을 읽지 못했습니다. <Button size="sm" onClick={() => void candidates.refetch()}>다시 조회</Button></p>}
    {mutation.isError && <p role="alert" className="m-0 text-sm text-danger">{describeError(mutation.error)}</p>}
  </div>
}
