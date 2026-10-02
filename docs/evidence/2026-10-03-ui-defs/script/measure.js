// #94 폭별 실측(cdp94.mjs 가 페이지 안에서 실행). JSON 글을 돌려준다. 가짜 자료(시험 픽스처)로 잰다
(() => {
  const r = (el) => { if (!el) return null; const b = el.getBoundingClientRect(); return { top: Math.round(b.top * 10) / 10, bottom: Math.round(b.bottom * 10) / 10, h: Math.round(b.height * 10) / 10, w: Math.round(b.width * 10) / 10, left: Math.round(b.left * 10) / 10 } }
  const shown = (el) => !!el && getComputedStyle(el).display !== 'none' && el.getClientRects().length > 0
  const out = {
    path: location.pathname + location.search,
    viewport: [innerWidth, innerHeight],
    scrollbar: innerWidth - document.documentElement.clientWidth,
    hScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }
  const p = location.pathname
  if (p === '/') {
    const grid = document.querySelector('[data-target-grid]')
    const cards = grid ? [...grid.querySelectorAll('[data-target]')].filter((c) => c.parentElement === grid || c.parentElement?.parentElement === grid) : []
    // 접힌 줄(모바일)에서 펼친 카드도 잰다
    const opened = [...document.querySelectorAll('ul[aria-label="보호 대상 요약"] [data-target]')]
    out.gridCols = grid ? getComputedStyle(grid).gridTemplateColumns.split(' ').length : null
    out.cards = [...cards, ...opened].map((c) => {
      const box = c.querySelector('[data-log-box]')
      const head = box ? [...box.querySelectorAll('span')].find((s) => s.textContent === '요청 · 결과') : null
      const reqs = box ? [...box.querySelectorAll('[data-request]')] : []
      const req = reqs.find(shown)
      // 요청 칸 안 경로 글(결과 코드 칸을 뺀 첫 span)의 보이는 폭
      const pathEl = req ? [...req.children].find((s) => !s.hasAttribute('data-request-code')) : null
      return {
        id: c.dataset.target, ...r(c),
        logHead: head ? shown(head) : null,
        requestShown: reqs.length ? reqs.filter(shown).length + '/' + reqs.length : null,
        pathW: pathEl ? Math.round(pathEl.getBoundingClientRect().width * 10) / 10 : null,
        pathClipped: pathEl ? pathEl.scrollWidth > pathEl.clientWidth : null,
      }
    })
    out.foldedRows = document.querySelectorAll('ul[aria-label="보호 대상 요약"] > li').length
    const first = document.querySelector('[data-queue] ol li')
    out.queueFirstRow = r(first)
    out.firstScreen = !!first && first.getBoundingClientRect().bottom <= innerHeight
  } else if (p === '/blocklist') {
    const counts = document.querySelector('[data-count-fold]')
    const card = counts && document.getElementById(counts.getAttribute('aria-controls'))
    out.countsCard = r(card)
    out.countsShown = card ? [...card.children].filter(shown).map((c) => c.firstElementChild?.textContent) : null
    out.fold = counts && { ...r(counts), shown: shown(counts), expanded: counts.getAttribute('aria-expanded'), text: counts.textContent }
    const firstRow = document.querySelector('.worklist-panel ul > li')
    out.firstRow = r(firstRow)
    out.firstRowInView = !!firstRow && firstRow.getBoundingClientRect().top < innerHeight
    out.firstRowFull = !!firstRow && firstRow.getBoundingClientRect().bottom <= innerHeight
  } else if (p.startsWith('/incidents/')) {
    const region = [...document.querySelectorAll('[role="region"]')].find((e) => document.getElementById(e.getAttribute('aria-labelledby'))?.textContent.includes('조치와 판정'))
    const btn = [...document.querySelectorAll('button')].find((b) => b.textContent === '재판정' || b.textContent === '접기')
    const form = region?.querySelector('form')
    const hist = [...(region?.querySelectorAll('h3') ?? [])].find((h) => h.textContent === '이력')
    out.region = r(region)
    out.clock = document.querySelector('[data-elapsed-tone] span')?.textContent ?? null
    out.panelHeading = [...(region?.querySelectorAll('h3') ?? [])].map((h) => h.textContent)
    out.reverdict = btn ? { text: btn.textContent, expanded: btn.getAttribute('aria-expanded'), ...r(btn) } : null
    out.form = form ? r(form) : null
    out.history = r(hist)
    out.historyInView = !!hist && hist.getBoundingClientRect().top < innerHeight
  } else if (p === '/sources/detail') {
    const table = document.querySelector('table[aria-label="사건 흐름"]')
    out.headers = table ? [...table.querySelectorAll('thead th')].map((th) => th.textContent) : null
    out.deviceCells = table ? [...table.querySelectorAll('td[data-label="장비"]')].map((td) => ({ text: td.textContent, unknown: !!td.querySelector('[data-device-unknown]'), ...r(td) })) : null
    out.targetCells = table ? table.querySelectorAll('td[data-label="대상"]').length : null
    const region = table?.closest('[class*="overflow"]')
    out.tableBox = table && { ...r(table), scroll: region ? [region.scrollWidth, region.clientWidth] : null }
  }
  return JSON.stringify(out)
})()
