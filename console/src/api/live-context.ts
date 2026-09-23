import { createContext, useContext } from 'react'
import type { LiveState } from './live'

export const LiveContext = createContext<LiveState>({ status: 'connecting', retries: 0 })
export const useLiveState = () => useContext(LiveContext)
