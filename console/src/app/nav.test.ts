import { describe, expect, it } from 'vitest'
import { findNavItem } from '@/components/organisms/nav/nav-items'
import { NAV_GROUPS } from './nav'
import { SCREENS } from './screens'

describe('메뉴 정의', () => {
  it('묶음과 항목은 와이어프레임 순서다', () => {
    expect(NAV_GROUPS.map((g) => g.label)).toEqual(['관제', '대응', '분석', '수집', '관리'])
    expect(NAV_GROUPS.flatMap((g) => g.items.map((i) => i.label))).toEqual([
      '대시보드',
      '인시던트',
      '차단',
      '규칙 · 리플레이',
      '출발지 분석',
      '보고서',
      '수집 노드',
      '알림',
      '감사 기록',
      '계정',
    ])
  })

  it('관리 묶음만 권한을 따진다(화면 설계 15장)', () => {
    for (const group of NAV_GROUPS) {
      for (const item of group.items) {
        expect(item.action !== undefined, `${group.label} › ${item.label}`).toBe(group.label === '관리')
      }
    }
  })

  it('권한이 필요한 화면 정의는 메뉴 항목과 같은 권한을 쓴다', () => {
    const byPath = new Map(NAV_GROUPS.flatMap((g) => g.items.map((i) => [i.to, i] as const)))
    expect(byPath.get('/alerts')?.action).toBe(SCREENS.alerts.action)
    expect(byPath.get('/audit')?.action).toBe(SCREENS.audit.action)
    expect(byPath.get('/accounts')?.action).toBe(SCREENS.accounts.action)
  })
})

describe('findNavItem', () => {
  it('경로에서 현재 위치를 찾는다', () => {
    expect(findNavItem(NAV_GROUPS, '/')?.item.label).toBe('대시보드')
    expect(findNavItem(NAV_GROUPS, '/incidents')?.item.label).toBe('인시던트')
    expect(findNavItem(NAV_GROUPS, '/audit')?.group.label).toBe('관리')
  })

  it('하위 경로도 그 항목이다. 대시보드(/)는 정확히 같을 때만', () => {
    const hit = findNavItem(NAV_GROUPS, '/incidents/R003%7Cv2%7C1.2.3.4')
    expect(hit?.group.label).toBe('관제')
    expect(hit?.item.label).toBe('인시던트')
    expect(findNavItem(NAV_GROUPS, '/incidentsx')).toBeUndefined()
    expect(findNavItem(NAV_GROUPS, '/nowhere')).toBeUndefined()
    expect(findNavItem(NAV_GROUPS, '/dev/components')).toBeUndefined()
  })
})
