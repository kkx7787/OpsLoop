import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// 전역 describe · it 을 쓰지 않으므로 testing-library 의 자동 정리가 걸리지 않는다. 직접 정리한다.
afterEach(() => {
  cleanup()
})
