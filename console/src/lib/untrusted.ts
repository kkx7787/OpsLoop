/**
 * 비신뢰 문자열(로그 · 공격자 입력 · 자산 수집 결과)을 화면에 보일 때의 규칙(#41).
 * 원문은 서버 · DB 에 그대로 둔다(증거). 여기서 바꾸는 것은 보이는 모습뿐이다.
 *  숨은 문자  유니코드 Cf(형식 문자: 방향 제어 · 제로폭 · BOM · 태그 문자 …) · Cc(제어 문자) 중 탭 · 줄바꿈을 뺀 것.
 *             화면에서는 줄 · 문단 구분자(U+2028 · U+2029)도 줄을 끊으므로 함께 숨은 문자로 본다.
 *             기본 무시 문자(Default_Ignorable: 한글 채움 U+3164 · U+034F · 이형 선택자 …)와 점자 빈칸(U+2800)도
 *             아무것도 그리지 않으므로 숨은 문자다.
 *             표식 '⟨U+202E⟩'(대문자 16진 4~6자리)로 바꾼다
 *  줄바꿈     '↵' 로 바꾼다. 한 값 안에서 가짜 로그 줄을 만들지 못하게 한다
 *  탭         공백 하나로 본다
 * 화면 조각은 atoms/UntrustedText 이고, 이 파일의 revealHidden 은 title · aria-label · <option> 처럼 문자열만 들어가는 자리에 쓴다.
 */

/** 바꿀 문자 전부(탭 · 줄바꿈 포함). 전역 검색용 */
const SPECIAL = /[\p{Cf}\p{Cc}\p{Default_Ignorable_Code_Point}\u{2028}\u{2029}\u{2800}]/gu

/** 숨은 문자 하나라도 있는가(탭 · 줄바꿈은 숨은 문자가 아니다) */
const HIDDEN = /(?![\t\n])[\p{Cf}\p{Cc}\p{Default_Ignorable_Code_Point}\u{2028}\u{2029}\u{2800}]/u

export const NEWLINE_MARK = '↵'

export type UntrustedPart = { kind: 'text'; text: string } | { kind: 'hidden'; code: string } | { kind: 'newline' }

/** 코드 포인트의 표기. 'U+202E' · 'U+001B' · 'U+E0041' */
function codeOf(ch: string): string {
  return `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`
}

/** 숨은 문자 하나의 표식. '⟨U+202E⟩' */
export function hiddenMark(code: string): string {
  return `⟨${code}⟩`
}

export function hasHidden(s: string): boolean {
  return HIDDEN.test(s)
}

/** 숨은 문자를 표식으로, 줄바꿈을 ↵ 로, 탭을 공백으로 바꾼 문자열. title · aria-label 등 문자열 자리에 쓴다 */
export function revealHidden(s: string): string {
  return s.replace(SPECIAL, (ch) => (ch === '\t' ? ' ' : ch === '\n' ? NEWLINE_MARK : hiddenMark(codeOf(ch))))
}

/** 화면 조각이 그릴 토막. 글자는 이어 붙이고, 숨은 문자 · 줄바꿈은 따로 떼어 표식 배지로 그린다 */
export function untrustedParts(s: string): UntrustedPart[] {
  const parts: UntrustedPart[] = []
  const text = (t: string) => {
    const prev = parts[parts.length - 1]
    if (prev?.kind === 'text') prev.text += t
    else parts.push({ kind: 'text', text: t })
  }
  let last = 0
  for (const match of s.matchAll(SPECIAL)) {
    const ch = match[0]
    const at = match.index
    if (at > last) text(s.slice(last, at))
    if (ch === '\t') text(' ')
    else if (ch === '\n') parts.push({ kind: 'newline' })
    else parts.push({ kind: 'hidden', code: codeOf(ch) })
    last = at + ch.length
  }
  if (last < s.length) text(s.slice(last))
  return parts
}

/** 글자 수(코드 포인트). 태그 문자처럼 두 칸(UTF-16)을 쓰는 글자도 한 자로 센다 */
export function codePointLength(s: string): number {
  let n = 0
  for (const _ of s) n += 1
  return n
}

/** 앞에서 n 자(코드 포인트). 두 칸짜리 글자를 반으로 가르지 않는다 */
export function sliceCodePoints(s: string, n: number): string {
  if (s.length <= n) return s
  let end = 0
  let count = 0
  for (const ch of s) {
    if (count === n) break
    end += ch.length
    count += 1
  }
  return s.slice(0, end)
}
