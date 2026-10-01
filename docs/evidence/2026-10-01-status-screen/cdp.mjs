// #84 배치 실측 · 스크린샷(저장소 밖). 헤드리스 Chrome 을 DevTools 프로토콜로 몬다(새 의존 없음, Node 22 의 WebSocket · fetch).
// 앞서 띄울 것: python3 server.py 8784 · console/node_modules/.bin/vite --config vite.84.mts(5184)
// 실행: node cdp.mjs <증거 폴더> [장면 이름 거르개]
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = 9284
const APP = 'http://localhost:5184'
const MOCK = 'http://127.0.0.1:8784'
const OUT = process.argv[2]
const ONLY = process.argv[3] ? new RegExp(process.argv[3]) : null
const MEASURE = readFileSync(new URL('./measure84.js', import.meta.url), 'utf8')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'cdp84-'))}`,
  '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--lang=ko-KR', 'about:blank'], { stdio: 'ignore' })
let pages
for (let i = 0; i < 50; i++) {
  try { pages = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json(); if (pages.some((p) => p.type === 'page')) break } catch { /* 아직 */ }
  await sleep(200)
}
const ws = new WebSocket(pages.find((p) => p.type === 'page').webSocketDebuggerUrl)
await new Promise((r) => ws.addEventListener('open', r))
let seq = 0
const waiting = new Map()
const listeners = []
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data)
  if (msg.id && waiting.has(msg.id)) { const { resolve, reject } = waiting.get(msg.id); waiting.delete(msg.id); msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result) }
  else if (msg.method) for (const l of listeners) l(msg)
})
const send = (method, params = {}) => new Promise((resolve, reject) => { const id = ++seq; waiting.set(id, { resolve, reject }); ws.send(JSON.stringify({ id, method, params })) })
const once = (method) => new Promise((r) => { const l = (m) => { if (m.method === method) { listeners.splice(listeners.indexOf(l), 1); r(m) } }; listeners.push(l) })
const evaluate = async (expression) => {
  const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (res.exceptionDetails) throw new Error(JSON.stringify(res.exceptionDetails))
  return res.result.value
}

await send('Page.enable')
await send('Runtime.enable')
// 넓은 화면은 고전 스크롤바 15px 로 잰다(나쁜 쪽, #83 과 같은 기준). 모바일은 겹침 스크롤바라 0 이다
await send('Page.addScriptToEvaluateOnNewDocument', { source: `
  if (!matchMedia('(max-width: 767px)').matches) {
    const s = document.createElement('style'); s.textContent = '::-webkit-scrollbar{width:15px;height:15px}::-webkit-scrollbar-thumb{background:#c1c1c1}::-webkit-scrollbar-track{background:#f1f1f1}'
    document.documentElement.appendChild(s)
  }` })

async function viewport(width, height, mobile) {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile })
  await send('Emulation.setTouchEmulationEnabled', { enabled: mobile })
}
async function go(path, settle = 2500) {
  const loaded = once('Page.loadEventFired')
  await send('Page.navigate', { url: APP + path })
  await loaded
  await sleep(settle)
}
async function mode(m) {
  const base = { targets: '2', band: '0', ws: '1', unmapped: 'auto', tfail: '0', nfail: '0', nodes: '4', role: 'admin' }
  await fetch(`${MOCK}/__mode?${new URLSearchParams({ ...base, ...m })}`)
}
async function shot(name) {
  const { data } = await send('Page.captureScreenshot', { format: 'jpeg', quality: 80 })
  writeFileSync(join(OUT, `${name}.jpg`), Buffer.from(data, 'base64'))
}
const log = (line) => { console.log(line); appendFileSync(join(OUT, 'measure-raw.txt'), line + '\n') }

const scenes = [
  // 대시보드 1440×800: 띠 0 · 1줄 + 실시간 끊김(결정 13). ws=1 은 비교 기준
  { name: 'dash-1440x800-band0-ws1', m: { band: '0', ws: '1' }, w: 1440, h: 800, path: '/' },
  { name: 'dash-1440x800-band0-ws0', m: { band: '0', ws: '0' }, w: 1440, h: 800, path: '/' },
  { name: 'dash-1440x800-band1-ws0', m: { band: '1', ws: '0' }, w: 1440, h: 800, path: '/' },
  { name: 'dash-1440x800-bandS-ws0', m: { band: 's', ws: '0' }, w: 1440, h: 800, path: '/' },
  { name: 'dash-1440x800-bandS-ws1', m: { band: 's', ws: '1' }, w: 1440, h: 800, path: '/' },
  // 수집 · 관제 상태 ?open 두 경우(1440 · 390)
  { name: 'nodes-1440x800-plain', m: {}, w: 1440, h: 800, path: '/nodes' },
  { name: 'nodes-1440x800-open-aws-sensor', m: {}, w: 1440, h: 800, path: '/nodes?open=aws-sensor' },
  { name: 'nodes-1440x800-open-data-node', m: {}, w: 1440, h: 800, path: '/nodes?open=data-node' },
  { name: 'nodes-390x844-plain', m: {}, w: 390, h: 844, mobile: true, path: '/nodes' },
  { name: 'nodes-390x844-open-aws-sensor', m: {}, w: 390, h: 844, mobile: true, path: '/nodes?open=aws-sensor' },
  { name: 'nodes-390x844-open-data-node', m: {}, w: 390, h: 844, mobile: true, path: '/nodes?open=data-node' },
  // 대시보드 맨 아래 링크 → /nodes 뒤 스크롤
  {
    name: 'dash-1440x800-foot-link-to-nodes', m: { band: '1' }, w: 1440, h: 800, path: '/',
    after: async () => {
      log(`  끝까지 내림 scrollY=${await evaluate('(scrollTo(0, document.documentElement.scrollHeight), new Promise(r => setTimeout(() => r(Math.round(scrollY)), 300)))')}`)
      await evaluate(`[...document.querySelectorAll('a')].find(a => a.textContent.includes('수집 · 관제 상태 보기')).click()`)
      await sleep(2500)
    },
  },
  // 390 보호 대상 줄 배지 최대(지점 적용 · 보고 문제 · 웹 로그 적재 없음 · 지표 오래됨 + 상태판 갱신 실패 '이전 결과')
  { name: 'dash-390x844-protected-badges-max', m: { targets: 'busy' }, w: 390, h: 844, mobile: true, path: '/' },
  {
    name: 'dash-390x844-protected-badges-max-stale', m: { targets: 'busy' }, w: 390, h: 844, mobile: true, path: '/',
    after: async () => {
      await mode({ targets: 'busy', tfail: '1' })
      await evaluate(`document.querySelector('[data-page-status] button[aria-label="새로고침"]').click()`)
      await sleep(2500)
    },
  },
  // 기록만: 노드 25대에서 먼 줄 펼침 · 일부 갱신 실패
  { name: 'nodes-1440x800-25-open-data-node', m: { nodes: '25' }, w: 1440, h: 800, path: '/nodes?open=data-node' },
  {
    name: 'nodes-1440x800-partial-fail', m: { targets: 'busy' }, w: 1440, h: 800, path: '/nodes',
    after: async () => {
      await mode({ targets: 'busy', tfail: '1' })
      await evaluate(`document.querySelector('[data-page-status] button[aria-label="새로고침"]').click()`)
      await sleep(2500)
    },
  },
]

for (const s of scenes) {
  if (ONLY && !ONLY.test(s.name)) continue
  await mode(s.m)
  await viewport(s.w, s.h, !!s.mobile)
  await go(s.path)
  if (s.after) await s.after()
  const m = JSON.parse(await evaluate(MEASURE))
  log(`${s.name} ${JSON.stringify(m)}`)
  await shot(s.name)
}
ws.close()
chrome.kill()
process.exit(0)
