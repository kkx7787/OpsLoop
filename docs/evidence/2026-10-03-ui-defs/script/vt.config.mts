// #94 폭별 실측용: 시험 픽스처를 JSON 으로 뽑는다(저장소 밖, 84/mock/vt.config.mts 를 옮겨 씀)
import react from '/Users/hanseongmin/opsloop-repo/console/node_modules/@vitejs/plugin-react/dist/index.js'
import { defineConfig } from '/Users/hanseongmin/opsloop-repo/console/node_modules/vitest/dist/config.js'
export default defineConfig({
  plugins: [react()],
  root: '/Users/hanseongmin/opsloop-repo/console',
  cacheDir: '<작업 폴더>/mock/.vite',
  resolve: { alias: { '@': '/Users/hanseongmin/opsloop-repo/console/src' } },
  server: { fs: { allow: ['/Users/hanseongmin/opsloop-repo', '<작업 폴더>/mock'] } },
  test: { environment: 'node', css: false, dir: '<작업 폴더>/mock', include: ['**/*.dump.test.ts'] },
})
