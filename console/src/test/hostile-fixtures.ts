import { fireEvent, within } from '@testing-library/react'
import { expect } from 'vitest'
import { hasHidden, untrustedParts } from '@/lib/untrusted'

/**
 * 악성 표본 묶음(#41). 로그 · 공격자 입력 · 자산 수집 결과 자리에 넣어 화면이 실행 · 외부 요청 · 표시 위조를 만들지 않는지 본다.
 * 숨은 문자는 소스에서 보이도록 \u{…} 로 적는다.
 */
export const HOSTILE = {
  img: '<img src=//a.attacker.test/p.png onerror=alert(1)>',
  svg: '<svg onload=alert(1)>',
  jsUrl: 'javascript:alert(1)',
  mdLink: '[x](https://b.attacker.test)',
  mdImage: '![i](https://c.attacker.test/p.png)',
  mention: '<at>admin</at>',
  style: '</style><style>*{background:url(//d.attacker.test)}</style>',
  prefetch: '<link rel=dns-prefetch href=//e.attacker.test>',
  rlo: 'admin\u{202E}gnp.exe',
  zwsp: 'ad\u{200B}min',
  isolate: '\u{2066}x\u{2069}',
  bom: '\u{FEFF}',
  ansi: '\u{1B}[31m빨강',
  csi: '\u{9B}2K',
  decoy: '줄1\n2026-09-18 15:00:00 decoy login.success',
  crlf: '\r\n',
} as const

/** 2만 자. 끝에 표지를 둬 접힘(표지 없음) · 펼침(표지 있음)을 가린다 */
export const LONG = `${'L'.repeat(19_995)}TAIL!`
/** 기본 max(500)로 접었을 때의 단추 이름 */
export const LONG_MORE = '… 19,500자 더 · 펼치기'

/** 짧은 표본을 모두 이은 한 값. 한 칸에 모든 공격을 넣을 때 쓴다 */
export const MIXED = Object.values(HOSTILE).join(' ')

/** MIXED 를 그린 화면에 보여야 하는 표식 */
export const MIXED_MARKS = ['⟨U+202E⟩', '⟨U+200B⟩', '⟨U+2066⟩', '⟨U+2069⟩', '⟨U+FEFF⟩', '⟨U+001B⟩', '⟨U+009B⟩', '⟨U+000D⟩', '↵']

/** 글에 원문으로 남은 숨은 문자(코드 표기, 중복 없이). 실패 때 무엇이 남았는지 보이려고 쓴다 */
function hiddenCodes(text: string): string[] {
  return [...new Set(untrustedParts(text).flatMap((part) => (part.kind === 'hidden' ? [part.code] : [])))]
}

/** 글자로 들어가는 자리(낭독 · 말풍선)의 속성 */
const TEXT_ATTRS = ['title', 'aria-label', 'aria-description', 'placeholder', 'alt']

/**
 * 화면이 비신뢰 문자열을 글자로만 그렸는지 본다.
 *  실행 · 외부 요청을 만드는 요소 0(앱 아이콘인 aria-hidden svg 는 뺀다) · on* 속성 0 · src 속성 0
 *  모든 a[href] 는 같은 출처 경로('/' 로 시작, '//' · '/\' 아님)
 *  글자와 글자 속성에 숨은 문자가 원문으로 남지 않는다 · 가짜 줄(줄바꿈 뒤 시각)이 없다
 */
export function expectInertDom(root: HTMLElement) {
  expect(root.querySelectorAll('img, iframe, object, embed, style, link, script, [src], [srcset]').length).toBe(0)
  expect(root.querySelectorAll('svg:not([aria-hidden="true"])').length).toBe(0)
  const onAttrs = [...root.querySelectorAll('*')].flatMap((el) =>
    [...el.attributes].filter((a) => a.name.toLowerCase().startsWith('on')).map((a) => `${el.tagName}[${a.name}]`),
  )
  expect(onAttrs).toEqual([])
  const hrefs = [...root.querySelectorAll('[href]')].map((el) => el.getAttribute('href') ?? '')
  expect(hrefs.filter((href) => !/^\/(?![/\\])/.test(href))).toEqual([])
  const styles = [...root.querySelectorAll('[style]')].map((el) => el.getAttribute('style') ?? '')
  expect(styles.filter((style) => style.includes('attacker'))).toEqual([])

  const text = root.textContent ?? ''
  expect(hiddenCodes(text)).toEqual([])
  expect(text).not.toContain('줄1\n2026')
  const badAttrs = [...root.querySelectorAll('*')].flatMap((el) =>
    TEXT_ATTRS.filter((name) => {
      const value = el.getAttribute(name)
      return value !== null && (hasHidden(value) || value.includes('\n'))
    }).map((name) => `${el.tagName}[${name}]`),
  )
  expect(badAttrs).toEqual([])
}

/** MIXED 가 들어간 화면: 표식이 모두 보이고 공격 문자열은 글자로 남는다 */
export function expectMixedRevealed(root: HTMLElement) {
  const text = root.textContent ?? ''
  expect(MIXED_MARKS.filter((mark) => !text.includes(mark))).toEqual([])
  expect(text).toContain('줄1↵2026-09-18 15:00:00 decoy')
  expect(text).toContain(HOSTILE.img)
  expect(text).toContain(HOSTILE.mdLink)
}

/** LONG 이 들어간 화면: 처음에는 접혀 있고(끝 표지 없음), 펼치기를 모두 누르면 전부 보인다 */
export function expectLongFolds(root: HTMLElement) {
  expect(root.textContent).not.toContain(LONG)
  const more = within(root).getAllByRole('button', { name: LONG_MORE })
  for (const button of more) fireEvent.click(button)
  expect(root.textContent).toContain(LONG)
  expect(within(root).getAllByRole('button', { name: '접기' }).length).toBeGreaterThanOrEqual(more.length)
}
