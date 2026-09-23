import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// 전역 describe · it 을 쓰지 않으므로 testing-library 의 자동 정리가 걸리지 않는다. 직접 정리한다.
afterEach(() => {
  cleanup()
})

/**
 * 화면 틀(AppLayout)이 실시간 통보(WS /ws)를 잇는다. jsdom 의 WebSocket 은 실제로 접속을 시도해
 * 실패 · 재시도 소음을 내므로 아무 일도 하지 않는 소켓으로 바꿔 둔다.
 * 연결 상태를 시험하는 곳은 vi.stubGlobal('WebSocket', 가짜) 로 덮어 쓴다(unstub 하면 이것으로 돌아온다).
 */
class InertSocket extends EventTarget {
  readonly url: string
  constructor(url: string) {
    super()
    this.url = url
  }
  close() {}
}
Object.defineProperty(globalThis, 'WebSocket', { value: InertSocket, writable: true, configurable: true })
