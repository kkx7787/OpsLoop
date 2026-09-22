import type { Action } from '@/auth/roles'

/** 화면 자리의 정보: 설계 번호 · 제목 · 한 줄 설명 · 채우는 WBS 단계 · 보는 데 필요한 권한 */
export interface Screen {
  code: string
  title: string
  description: string
  /** 이 화면을 채우는 WBS 항목 */
  wbs: string
  /** 이 권한이 없으면 403 안내를 보인다(관리 묶음) */
  action?: Action
}

/** 화면 설계(docs/2026-09-18-화면-설계.md 1장)와 WBS 3.6.x 의 짝 */
export const SCREENS = {
  dashboard: {
    code: 'S-02',
    title: '미판정 현황',
    description: '미판정 인시던트의 경과 시간과 판정 목표. 이 프로젝트가 줄이려는 비용을 보이는 화면.',
    wbs: '3.6.4',
  },
  incidents: {
    code: 'S-03',
    title: '인시던트',
    description: '무엇부터 볼지 정하는 목록. 상세와 판정 패널로 이어진다.',
    wbs: '3.6.2',
  },
  blocklist: {
    code: 'S-06',
    title: '차단 목록',
    description: '조치가 실제로 적용됐는지 확인한다. 만료와 조치 이력.',
    wbs: '3.6.6',
  },
  rules: {
    code: 'S-07',
    title: '규칙과 리플레이',
    description: '폐루프의 결과. 규칙 회차별 리플레이 결과와 억제 · 승인.',
    wbs: '3.6.x (폐루프 2회차와 함께)',
  },
  sources: {
    code: 'S-09',
    title: '출발지 분석',
    description: '주소가 아니라 도구 지문 단위로 묶어 판정한다.',
    wbs: '3.6.x (선택)',
  },
  reports: {
    code: 'S-11',
    title: '보고서',
    description: '규칙 회차별 결과를 같은 형식으로 남긴다. 회차 비교 · 주간 자동 생성.',
    wbs: '3.6.10',
  },
  nodes: {
    code: 'S-08 · S-13',
    title: '수집 노드',
    description: '수집이 멈추면 화면이 조용해져 평온으로 오인한다. 노드 상태와 추가.',
    wbs: '3.6.x (Ansible 배포와 함께)',
  },
  alerts: {
    code: 'S-12',
    title: '알림 설정',
    description: '등급 · 묶음 · 재시도. 알림이 없으면 미판정 경과 시간을 줄일 수단이 없다.',
    wbs: '3.6.7',
    action: 'notify.manage',
  },
  audit: {
    code: 'S-14',
    title: '감사 기록',
    description: '기준과 권한을 바꾼 행위를 남긴다.',
    wbs: '3.6.8',
    action: 'audit.read',
  },
  accounts: {
    code: 'S-15',
    title: '계정',
    description: '역할 변경 · 비활성. 추가는 명령줄에서 하고 삭제하지 않는다.',
    wbs: '3.6.8',
    action: 'account.manage',
  },
} as const satisfies Record<string, Screen>
