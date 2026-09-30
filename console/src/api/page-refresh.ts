import { useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useState } from 'react'

/**
 * 새로고침(#79). 상단바 단추와 화면 머리의 기준 시각 옆 단추(PageRefresh)가 같은 동작을 한다:
 * 모든 조회를 무효로 하고 보이는 조회를 다시 받는다(invalidateQueries). 주기 조회만 멈춘 조회(로그 자동 갱신 정지)도
 * 켜져(enabled) 있으면 한 번 받고, 멈춤은 그대로다.
 */
export function useRefreshAll() {
  const client = useQueryClient()
  const [refreshing, setRefreshing] = useState(false)
  const refresh = useCallback(async () => {
    setRefreshing(true)
    try {
      await client.invalidateQueries()
    } finally {
      setRefreshing(false)
    }
  }, [client])
  return { refresh, refreshing }
}

/** 화면이 자기 새로고침을 둘 때 틀(AppLayout)에 알리는 자리 */
export interface PageRefreshSlot {
  /** 화면 머리에 새로고침을 둔다고 알린다. 그동안 상단바 새로고침을 숨긴다. 돌려준 함수로 되돌린다 */
  claim: () => () => void
}

/** AppLayout 이 준다. 틀 밖(시험 · 카탈로그)에서는 null 이라 상단바와 상관없이 단추만 그린다 */
export const PageRefreshContext = createContext<PageRefreshSlot | null>(null)
