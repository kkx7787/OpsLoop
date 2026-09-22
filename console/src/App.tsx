import { RouterProvider } from 'react-router'
import { createAppRouter } from './app/router'

const router = createAppRouter()

/** 진입점. 경로표(src/app/router.tsx)에 따라 틀과 화면을 그린다. */
export function App() {
  return <RouterProvider router={router} />
}
