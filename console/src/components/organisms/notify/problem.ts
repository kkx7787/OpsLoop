/**
 * 발송 실패 원인을 조치 안내로 바꾼다. 서버(app/notifier.py post_json)는 예외 이름 · 'HTTP 코드' 만 남기고
 * 주소 · 응답 본문은 넣지 않는다. 응답 코드는 한 번만 보인다.
 */

const REASONS: Record<string, string> = {
  gaierror: '이름 해석 실패 · 주소의 호스트 이름과 콘솔의 DNS 를 확인해 주세요',
  TimeoutError: '연결 시간 초과 · 방화벽(콘솔 → 인터넷 443)과 받는 쪽 상태를 확인해 주세요',
  ConnectionRefusedError: '연결 거부 · 받는 쪽 주소 · 포트를 확인해 주세요',
  ConnectionResetError: '연결이 끊겼습니다 · 받는 쪽 상태를 확인해 주세요',
  SSLCertVerificationError: '인증서 오류 · 받는 쪽 인증서를 확인해 주세요',
  SSLError: 'TLS 오류 · 받는 쪽 인증서 · TLS 설정을 확인해 주세요',
  ChannelDisabled: '채널을 중지해 보내지 않았습니다',
  ChannelChanged: '채널 설정이 바뀌어 보내지 않았습니다',
  ChannelMissing: '채널이 없어져 보내지 않았습니다',
}

function httpReason(code: number): string {
  if (code === 404 || code === 410) return '워크플로가 삭제됐거나 주소가 만료됐습니다 · 흐름을 다시 저장해 새 주소를 넣어 주세요'
  if (code === 401 || code === 403) return '주소의 서명이 맞지 않거나 권한이 없습니다 · 워크플로의 트리거 권한("누구나")과 주소를 확인해 주세요'
  if (code === 429) return 'Teams 전송 제한에 걸렸습니다 · 잠시 뒤 자동으로 다시 보냅니다'
  if (code === 400) return '받는 쪽이 메시지 형식을 거부했습니다 · 워크플로의 카드 게시 단계를 확인해 주세요'
  if (code >= 300 && code < 400) return '리다이렉트는 따라가지 않습니다 · 최종 주소를 넣어 주세요'
  if (code >= 500) return '받는 쪽 서버 오류 · 잠시 뒤 자동으로 다시 보냅니다'
  return '받는 쪽이 요청을 거부했습니다'
}

/** 실패 · 재시도 원인 한 줄. 성공이거나 원인이 없으면 빈 문자열 */
export function deliveryProblem(error: string | null | undefined, code: number | null | undefined): string {
  if (typeof code === 'number' && code >= 200 && code < 300) return ''
  if (typeof code === 'number') return `HTTP ${code} · ${httpReason(code)}`
  if (!error) return ''
  const reason = REASONS[error]
  return reason ? `${reason} (${error})` : error
}
