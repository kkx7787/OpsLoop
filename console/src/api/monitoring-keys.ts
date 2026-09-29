/** 목록·상세 조치와 웹소켓에서도 같은 요약·차단 · 대상 상태판 · 관제 이상 캐시를 갱신한다. */
export const monitoringKeys = {
  summary: ['stats', 'summary'],
  blocklist: ['blocklist'],
  /** 관제 대상 상태판(이슈 #52). 사건 · 판정 · 조치 통보마다 대상별 수치가 바뀐다 */
  targets: ['dashboard', 'targets'],
  /** 관제 이상(#72). 대시보드 띠와 사이드바 요약이 같은 캐시를 쓴다 */
  health: ['dashboard', 'monitor'],
} as const
