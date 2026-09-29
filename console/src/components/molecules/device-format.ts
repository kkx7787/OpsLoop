import type { DeviceBasis, IncidentBase, IncidentDevice } from '@/api/incidents'

/**
 * 관련 장비 표기(#72). 목록 행 · 카드 · 상세 머리 · 대시보드 대기열 · 새 사건 알림이 같은 함수로 가른다.
 * 대체 추정을 거르는 판단은 이 파일에만 둔다. 서버가 이미 뺐어도 한 번 더 거른다.
 *  legacy   devices 가 없는 이전 서버 응답. 화면은 옛 표기(발생원)를 쓴다
 *  known    근거가 확인 · 규칙 범위인 장비만(화이트리스트). 보호 대상 먼저 → 확인 먼저 → 서버 순서
 *  unknown  devices 는 왔는데 known 이 비었다('장비 미확인'). 추정 장비를 확정처럼 보이지 않는다
 *  fallback 대체 추정 장비(상세 ⓘ 에만 쓴다)
 */

export type DeviceSource = Pick<IncidentBase, 'devices' | 'device_state' | 'device_fallback'>
export type KnownBasis = Exclude<DeviceBasis, 'fallback'>
export type KnownDevice = IncidentDevice & { basis: KnownBasis }

export interface DeviceView {
  legacy: boolean
  known: KnownDevice[]
  unknown: boolean
  fallback: IncidentDevice[]
}

export const DEVICE_BASIS_LABEL: Readonly<Record<KnownBasis, string>> = { confirmed: '확인', rule_scope: '규칙 범위' }
export const DEVICE_UNKNOWN_LABEL = '장비 미확인'

const DEVICE_ID = /^(?:_unconfirmed|[a-z0-9][a-z0-9-]{0,62})$/

function isDevice(d: unknown): d is IncidentDevice {
  return typeof d === 'object' && d !== null
}

function isKnown(d: IncidentDevice): d is KnownDevice {
  return Object.hasOwn(DEVICE_BASIS_LABEL, d.basis)
}

function listOf(v: unknown): IncidentDevice[] {
  return Array.isArray(v) ? v.filter(isDevice) : []
}

/** 모르는 group 은 보호 대상으로, 모르는 basis 는 확인으로 보지 않는다 */
function rank(d: KnownDevice): number {
  return (d.group === 'protected' ? 0 : 2) + (d.basis === 'confirmed' ? 0 : 1)
}

/** 같은 장비(id + 나눔)를 가르는 키 */
export function deviceKey(d: Pick<IncidentDevice, 'id' | 'part'>): string {
  return `${d.id}|${d.part ?? ''}`
}

/** 같은 장비는 처음 것만 남긴다 */
function unique<T extends IncidentDevice>(list: T[]): T[] {
  const seen = new Set<string>()
  return list.filter((d) => {
    const key = deviceKey(d)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function deviceView(src: DeviceSource): DeviceView {
  const legacy = src.devices === undefined
  const devices = listOf(src.devices)
  // sort 는 안정 정렬이라 같은 순위 안에서는 서버 순서가 남는다
  const known = unique(devices.filter(isKnown).sort((a, b) => rank(a) - rank(b)))
  const fallback = unique([...listOf(src.device_fallback), ...devices.filter((d) => d.basis === 'fallback')])
  return { legacy, known, unknown: !legacy && known.length === 0, fallback }
}

/** '웹 디코이 · 웹 요청'. label 은 비신뢰(등록 노드 hostname)라 문자열 자리에서는 revealHidden 으로 감싼다 */
export function deviceText(d: Pick<IncidentDevice, 'label' | 'logs'>): string {
  return [d.label, ...(Array.isArray(d.logs) ? d.logs : [])].join(' · ')
}

/** 보호 대상 장비가 확인된 사건인가. 규칙 범위 · 대체 추정은 들지 않는다(새 사건 알림 · 대기열) */
export function hasConfirmedProtected(devices?: readonly IncidentDevice[] | null): boolean {
  return Array.isArray(devices) && devices.some((d) => isDevice(d) && d.basis === 'confirmed' && d.group === 'protected')
}

/** 목록 device 값(장비 id 또는 '_unconfirmed'). 서버 형식 검사와 같다 */
export function isDeviceId(v: unknown): v is string {
  return typeof v === 'string' && DEVICE_ID.test(v)
}
