// 첫 화면 측정(javascript_tool 로 실행). 구현 뒤에는 data-* 선택자를 실제 카드 · 대기열에 맞춘다
const r = (el) => { if (!el) return null; const b = el.getBoundingClientRect(); return { top: Math.round(b.top), bottom: Math.round(b.bottom), h: Math.round(b.height * 10) / 10, w: Math.round(b.width * 10) / 10 } }
const cards = [...document.querySelectorAll('[data-target]')].filter((c) => c.closest('section'))
const queue = document.querySelector('[data-queue]')
const first = queue?.querySelector('ol li')
const box = document.querySelector('[data-log-box]')
JSON.stringify({
  viewport: [innerWidth, innerHeight, innerWidth - document.documentElement.clientWidth],
  cards: cards.map((c) => ({ id: c.dataset.target, ...r(c) })),
  logBox: box && { ...r(box), scroll: [box.scrollHeight, box.clientHeight], focusable: box.tabIndex },
  queueHead: r(queue?.firstElementChild), firstRow: r(first),
  pass: !!first && first.getBoundingClientRect().bottom <= innerHeight && cards.every((c) => c.getBoundingClientRect().bottom <= innerHeight),
  hScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
})
