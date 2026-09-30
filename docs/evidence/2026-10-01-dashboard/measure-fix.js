// #83 수정 뒤 실측(javascript_tool 에 붙여 실행). mock/measure.js 의 통과 기준 + 요청 칸 잘림 · 결과 코드 보임 · 취약점/동선 바닥 붙음 · '이전 결과' · 낭독 칸
(() => {
  const R = (e) => { if (!e) return null; const b = e.getBoundingClientRect(); return { t: +b.top.toFixed(1), b: +b.bottom.toFixed(1), h: +b.height.toFixed(1), w: +b.width.toFixed(1) } }
  const de = document.documentElement
  const shown = (e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.height > 0 && getComputedStyle(e).display !== 'none' }
  const cards = [...document.querySelectorAll('[data-target]')].filter((c) => c.closest('[data-target-grid]') || c.closest('[data-target-summary]'))
  const q = document.querySelector('[data-queue]')
  const f = q?.querySelector('ol li')
  const clipped = (root) => [...root.querySelectorAll('*')].filter((e) => shown(e) && !e.closest('.sr-only') && ['hidden', 'clip'].includes(getComputedStyle(e).overflowX) && e.scrollWidth > e.clientWidth + 1).map((e) => e.textContent.trim().slice(0, 36))
  return JSON.stringify({
    vp: [innerWidth, innerHeight, innerWidth - de.clientWidth],
    cards: cards.map((c) => {
      const box = c.querySelector('[data-log-box]')
      const v = c.querySelector('[data-vulns]')
      const l = c.querySelector('[data-device-links]')
      const req = [...c.querySelectorAll('[data-request]')].filter(shown)
      return {
        id: c.dataset.target, ...R(c),
        box: box && { t: R(box).t, sc: [box.scrollHeight, box.clientHeight] },
        vuln: R(v), links: R(l),
        linksToBottom: l ? +(c.getBoundingClientRect().bottom - l.getBoundingClientRect().bottom).toFixed(1) : null,
        req: req.length ? { rows: req.length, pathW: req[0].children[0].clientWidth, pathClipped: req.filter((e) => e.children[0].scrollWidth > e.children[0].clientWidth + 1).length, codeInside: req.every((e) => e.children[1].getBoundingClientRect().right <= e.getBoundingClientRect().right + 0.5 && e.children[1].getBoundingClientRect().width > 0), code0: req[0].children[1].textContent.trim() } : null,
        stale: !!c.querySelector('[data-stale-badge]'),
        clipped: clipped(c).slice(0, 4),
      }
    }),
    unmapped: R(document.querySelector('[data-unmapped]')),
    qHead: R(q?.firstElementChild), first: R(f),
    pass: !!f && f.getBoundingClientRect().bottom <= innerHeight && cards.every((c) => c.getBoundingClientRect().bottom <= innerHeight),
    hScroll: de.scrollWidth > de.clientWidth,
    status: document.querySelector('[data-page-status]')?.textContent.trim(),
    live: document.querySelector('[data-refresh-announce]')?.textContent ?? null,
    summaries: [...document.querySelectorAll('[data-target-summary]')].map((li) => { const b = li.querySelector('button'); return { id: li.dataset.targetSummary, h: R(b).h, stale: !!b.querySelector('[data-stale-badge]'), text: b.textContent.trim() } }),
    bands: [...document.querySelectorAll('main [role=alert], main [data-health-band]')].map((b) => R(b)),
  })
})()
