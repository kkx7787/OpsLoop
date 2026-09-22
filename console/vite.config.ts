import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// 개발 서버는 화면만 맡고, 인증 · API · 웹소켓은 로컬 백엔드로 넘긴다.
// 같은 출처로 보이게 해서 운영(HAProxy 뒤 같은 출처)과 쿠키 · 출처 확인 조건을 맞춘다.
// Host 를 바꾸지 않는다. 백엔드의 출처 확인이 Origin 과 Host 를 비교하기 때문이다.
// Vite 는 문자열 단축형('/api/': backend)에 changeOrigin: true 를 넣어 Host 를 백엔드 주소로 바꾸므로
// 객체로 주고 false 를 명시한다. 그러지 않으면 개발 서버에서 POST /login · /logout 이 403 이다.
const backend = process.env.OPSLOOP_BACKEND ?? 'http://127.0.0.1:8000'
const keep = { target: backend, changeOrigin: false }

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    proxy: {
      '/api/': keep,
      '/login': keep,
      '/logout': keep,
      '/health': keep,
      '/ws': { target: backend.replace(/^http/, 'ws'), ws: true },
    },
  },
  build: {
    // 콘솔 이미지(app/)가 그대로 서빙한다. app/static/ 은 git 에 넣지 않는다.
    outDir: '../app/static',
    emptyOutDir: true,
    // CSS 를 파일 하나로 낸다. 화면을 지연 로딩해도 스타일 파일이 늘지 않아 CSP · 캐시 점검이 단순하다.
    cssCodeSplit: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
  },
})
