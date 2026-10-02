// #94 폭별 실측 · 화면 갈무리(저장소 밖, 84/mock/cdp.mjs 를 옮겨 씀). 헤드리스 Chrome 을 DevTools 프로토콜로 몬다(새 의존 없음, Node 22 의 WebSocket · fetch).
// 앞서 띄울 것: python3 server.py 8794 · console/node_modules/.bin/vite --config vite.94.mts(5194)
// 실행: node cdp94.mjs <결과 폴더> [장면 이름 거르개]. 모든 응답은 가짜 자료(시험 픽스처)다
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = 9294
const APP = 'http://localhost:5194'
const MOCK = 'http://127.0.0.1:8794'
const OUT = process.argv[2]
const ONLY = process.argv[3] ? new RegExp(process.argv[3]) : null
const MEASURE = readFileSync(new URL('./measure.js', import.meta.url), 'utf8')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'cdp94-'))}`,
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
// 스크롤바: 넓은 화면은 고전 스크롤바 15px(나쁜 쪽, #83 · #84 와 같은 기준). 장면에 bar=0 이면 0px 로 잰다. 모바일은 겹침 스크롤바라 0 이다
let scrollbarScript = null
async function scrollbar(px) {
  if (scrollbarScript) await send('Page.removeScriptToEvaluateOnNewDocument', { identifier: scrollbarScript })
  const { identifier } = await send('Page.addScriptToEvaluateOnNewDocument', { source: `
    if (!matchMedia('(max-width: 767px)').matches) {
      const s = document.createElement('style'); s.textContent = ${px} ? '::-webkit-scrollbar{width:${px}px;height:${px}px}::-webkit-scrollbar-thumb{background:#c1c1c1}::-webkit-scrollbar-track{background:#f1f1f1}' : 'html{scrollbar-width:none}'
      document.documentElement.appendChild(s)
    }` })
  scrollbarScript = identifier
}
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
  const base = { targets: '2', band: '0', ws: '1', unmapped: 'auto', tfail: '0', nfail: '0', nodes: '4', role: 'admin', incident: 'judged' }
  await fetch(`${MOCK}/__mode?${new URLSearchParams({ ...base, ...m })}`)
}
async function shot(name) {
  const { data } = await send('Page.captureScreenshot', { format: 'jpeg', quality: 80 })
  writeFileSync(join(OUT, `${name}.jpg`), Buffer.from(data, 'base64'))
}
const log = (line) => { console.log(line); appendFileSync(join(OUT, 'measure-raw.txt'), line + '\n') }
const click = (text) => evaluate(`(() => { const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith(${JSON.stringify(text)})); if (!b) return false; b.click(); return true })()`)

const KEY = encodeURIComponent('R003|v2|4.4.66.84|2026-09-18T06:00:00+00:00')
const scenes = []
// 대시보드: 보호 대상 카드 2장(web-01 · web-02), 높이 800, 스크롤바 15px
for (const w of [768, 1023, 1024, 1100, 1179, 1180, 1199, 1200, 1280, 1440]) scenes.push({ name: `dash-${w}x800-cards2-bar15`, m: {}, w, h: 800, path: '/' })
// 경계: 스크롤바 0
// 새 문서 스크립트는 documentElement 가 생기기 전에 돌 수 있어, 스크롤바 0 은 불러온 뒤 style 을 넣는다
const noBar = async () => { await evaluate(`(() => { const s = document.createElement('style'); s.textContent = 'html{scrollbar-width:none}'; document.head.appendChild(s) })()`); await sleep(800) }
for (const w of [1179, 1180, 1199, 1200]) scenes.push({ name: `dash-${w}x800-cards2-bar0`, m: {}, w, h: 800, path: '/', bar: 0, after: noBar })
// 카드 1장: 1199(한 열 전체 폭) · 1200(반쪽 폭)
for (const w of [1199, 1200]) scenes.push({ name: `dash-${w}x800-cards1-bar15`, m: { targets: '1' }, w, h: 800, path: '/' })
// 390: 접힌 줄, web-01 펼침
scenes.push({ name: 'dash-390x844-folded', m: {}, w: 390, h: 844, mobile: true, path: '/' })
scenes.push({ name: 'dash-390x844-web01-open', m: {}, w: 390, h: 844, mobile: true, path: '/', after: async () => { await evaluate(`document.querySelector('[data-target-summary="web-01"] > button').click()`); await sleep(2500) } })
// 390 차단 목록: 기본(접힘) · 나머지 칸 펼침
scenes.push({ name: 'block-390x844-folded', m: {}, w: 390, h: 844, mobile: true, path: '/blocklist' })
scenes.push({ name: 'block-390x844-all-counts', m: {}, w: 390, h: 844, mobile: true, path: '/blocklist', after: async () => { log(`  펼침 단추 누름 ${await click('나머지 칸')}`); await sleep(500) } })
scenes.push({ name: 'block-768x800-bar15', m: {}, w: 768, h: 800, path: '/blocklist' })
// 390 사건 상세: 종결(접힘) · 재판정 펼침 · 미판정(펼침)
scenes.push({ name: 'incident-390x844-judged-folded', m: { incident: 'judged' }, w: 390, h: 844, mobile: true, path: `/incidents/${KEY}`, after: async () => { await evaluate(`[...document.querySelectorAll('[role="region"]')].find(e => document.getElementById(e.getAttribute('aria-labelledby'))?.textContent.includes('조치와 판정'))?.scrollIntoView()`); await sleep(400) } })
scenes.push({ name: 'incident-390x844-judged-open', m: { incident: 'judged' }, w: 390, h: 844, mobile: true, path: `/incidents/${KEY}`, after: async () => { log(`  재판정 단추 누름 ${await click('재판정')}`); await sleep(400); await evaluate(`[...document.querySelectorAll('[role="region"]')].find(e => document.getElementById(e.getAttribute('aria-labelledby'))?.textContent.includes('조치와 판정'))?.scrollIntoView()`); await sleep(400) } })
scenes.push({ name: 'incident-390x844-open', m: { incident: 'open' }, w: 390, h: 844, mobile: true, path: `/incidents/${KEY}`, after: async () => { await evaluate(`[...document.querySelectorAll('[role="region"]')].find(e => document.getElementById(e.getAttribute('aria-labelledby'))?.textContent.includes('조치와 판정'))?.scrollIntoView()`); await sleep(400) } })
// 390 출발지 상세: 사건 흐름 장비 칸
scenes.push({ name: 'source-390x844', m: {}, w: 390, h: 844, mobile: true, path: '/sources/detail?ip=198.51.100.23', after: async () => { await evaluate(`document.querySelector('table[aria-label="사건 흐름"]')?.scrollIntoView()`); await sleep(400) } })

scenes.push({ name: 'source-390x844-row3', m: {}, w: 390, h: 844, mobile: true, path: '/sources/detail?ip=198.51.100.23', after: async () => { await evaluate(`[...document.querySelectorAll('td[data-label="장비"]')][2]?.scrollIntoView({ block: 'center' })`); await sleep(400) } })

for (const s of scenes) {
  if (ONLY && !ONLY.test(s.name)) continue
  await mode(s.m)
  await scrollbar(s.bar ?? 15)
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
