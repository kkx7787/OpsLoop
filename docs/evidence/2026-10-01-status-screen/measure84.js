// #84 배치 실측(cdp.mjs 가 페이지 안에서 실행). 대시보드 · 수집 · 관제 상태 화면 공통. JSON 글을 돌려준다
(() => {
  const r = (el) => { if (!el) return null; const b = el.getBoundingClientRect(); return { top: Math.round(b.top * 10) / 10, bottom: Math.round(b.bottom * 10) / 10, h: Math.round(b.height * 10) / 10, w: Math.round(b.width * 10) / 10 } }
  /** 목록 항목이 몇 줄로 놓였는가(서로 다른 top 수) */
  const lines = (items) => new Set([...items].map((li) => Math.round(li.getBoundingClientRect().top))).size
  const out = {
    path: location.pathname + location.search,
    viewport: [innerWidth, innerHeight, innerWidth - document.documentElement.clientWidth],
    scrollY: Math.round(scrollY),
    hScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    topbarRefresh: [...document.querySelectorAll('header button, [data-page-status] button')].filter((b) => b.getAttribute('aria-label') === '새로고침').length,
    pageStatus: document.querySelector('[data-page-status]')?.textContent ?? null,
    h1: r(document.querySelector('h1')),
    banners: [...document.querySelectorAll('main [role="status"], main [role="alert"]')].map((e) => e.textContent).filter((t) => /실시간 연결이/.test(t)),
  }
  const bands = [...document.querySelectorAll('section[aria-label="관제 이상"]')]
  out.bands = bands.map((b) => ({ ...r(b), items: [...b.querySelectorAll('[data-monitor-item]')].map((li) => li.dataset.monitorItem), lines: lines(b.querySelectorAll('[data-monitor-item]')), text: b.textContent }))
  if (location.pathname === '/') {
    const cards = [...document.querySelectorAll('[data-target]')].filter((c) => c.closest('[data-target-grid]'))
    const queue = document.querySelector('[data-queue]')
    const first = queue?.querySelector('ol li')
    out.cards = cards.map((c) => ({ id: c.dataset.target, ...r(c) }))
    out.queueFirstRow = r(first)
    out.foot = r(document.querySelector('[data-dashboard-foot]'))
    out.pass = !!first && first.getBoundingClientRect().bottom <= innerHeight && cards.every((c) => c.getBoundingClientRect().bottom <= innerHeight)
    out.protectedRows = [...document.querySelectorAll('ul[aria-label="보호 대상 요약"] > li')].map((li) => {
      const button = li.querySelector(':scope > button')
      return { id: li.dataset.targetSummary, button: r(button), badges: button.querySelectorAll('[data-head-badge], [data-summary-flag], [data-stale-badge]').length, text: button.textContent }
    })
  } else {
    out.sections = [...document.querySelectorAll('[data-status-section]')].map((s) => ({ id: s.dataset.statusSection, ...r(s) }))
    const region = document.querySelector('[aria-label="등록 노드 표"]')
    out.table = region && { ...r(region), scroll: [region.scrollWidth, region.clientWidth] }
    const open = new URLSearchParams(location.search).get('open')
    const li = open && document.querySelector(`[data-target-summary="${open}"]`)
    if (li) {
      const button = li.querySelector(':scope > button')
      out.open = { id: open, row: r(button), expanded: button.getAttribute('aria-expanded'), focused: li.contains(document.activeElement), card: r(li.querySelector('[data-target]')), underTopbar: button.getBoundingClientRect().top >= 48 }
    }
    out.rows = [...document.querySelectorAll('[data-target-summary]')].map((li) => ({ id: li.dataset.targetSummary, h: r(li.querySelector(':scope > button')).h, text: li.querySelector(':scope > button').textContent }))
    out.logLinks = [...document.querySelectorAll('[data-node-logs]')].map((a) => a.getAttribute('href'))
    out.metricsStale = document.querySelectorAll('[data-metrics-stale]').length
    out.stale = document.querySelectorAll('[data-stale-badge]').length
  }
  return JSON.stringify(out)
})()
