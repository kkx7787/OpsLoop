import {
  IconAccounts,
  IconAssets,
  IconAudit,
  IconBlock,
  IconDashboard,
  IconIncident,
  IconNodes,
  IconNotify,
  IconReport,
  IconRules,
  IconSources,
} from '@/components/atoms/icons'
import type { NavGroup } from '@/components/organisms/nav/nav-items'
import { SCREENS } from './screens'

/** 메뉴 묶음(와이어프레임 Main.dc.html 사이드바). 관리 묶음은 admin 이 아니면 흐리게 보인다. */
export const NAV_GROUPS: readonly NavGroup[] = [
  {
    label: '관제',
    items: [
      { to: '/', label: '대시보드', icon: IconDashboard },
      { to: '/incidents', label: '인시던트', icon: IconIncident },
    ],
  },
  { label: '대응', items: [{ to: '/blocklist', label: '차단', icon: IconBlock }] },
  {
    label: '분석',
    items: [
      { to: '/rules', label: '규칙 · 리플레이', icon: IconRules },
      { to: '/sources', label: '출발지 분석', icon: IconSources },
      { to: '/reports', label: '보고서', icon: IconReport },
    ],
  },
  {
    label: '수집',
    items: [
      { to: '/nodes', label: '수집 노드', icon: IconNodes },
      { to: '/inventory', label: '자산 · 취약점', icon: IconAssets },
    ],
  },
  {
    label: '관리',
    items: [
      { to: '/alerts', label: '알림', icon: IconNotify, action: SCREENS.alerts.action },
      { to: '/audit', label: '감사 기록', icon: IconAudit, action: SCREENS.audit.action },
      { to: '/accounts', label: '계정', icon: IconAccounts, action: SCREENS.accounts.action },
    ],
  },
]
