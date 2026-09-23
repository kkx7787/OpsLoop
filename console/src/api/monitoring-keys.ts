/** 목록·상세 조치와 웹소켓에서도 같은 요약·차단 캐시를 갱신한다. */
export const monitoringKeys = {
  summary: ['stats', 'summary'],
  blocklist: ['blocklist'],
} as const
