// #94 폭별 실측용 개발 서버(저장소 밖, 84/mock/vite.84.mts 를 옮겨 씀). 캐시를 이 폴더에 두고 목 백엔드(8794)로 넘긴다
import tailwindcss from '/Users/hanseongmin/opsloop-repo/console/node_modules/@tailwindcss/vite/dist/index.mjs'
import react from '/Users/hanseongmin/opsloop-repo/console/node_modules/@vitejs/plugin-react/dist/index.js'
const backend = process.env.OPSLOOP_BACKEND ?? 'http://127.0.0.1:8794'
const keep = { target: backend, changeOrigin: false }
export default {
  root: '/Users/hanseongmin/opsloop-repo/console',
  cacheDir: '<작업 폴더>/mock/.vite',
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': '/Users/hanseongmin/opsloop-repo/console/src' } },
  server: {
    port: 5194, strictPort: true,
    proxy: { '/api/': keep, '/login': keep, '/logout': keep, '/health': keep, '/ws': { target: backend.replace(/^http/, 'ws'), ws: true } },
  },
}
