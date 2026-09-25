import { describe, expect, it } from 'vitest'
import { codePointLength, hasHidden, revealHidden, sliceCodePoints, untrustedParts } from './untrusted'

/** 계약의 숨은 문자 목록(Cf 대표 · 태그 문자 · 제어 문자 · 기본 무시 문자). 모두 표식이 돼야 한다 */
const HIDDEN_CODES = [
  0x00ad, 0x061c, 0x180e, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069, 0x206a, 0x206f, 0xfeff, 0xfff9, 0xfffa, 0xfffb,
  0xe0001, 0xe0020, 0xe0041, 0xe007f,
  0x0000, 0x0007, 0x0008, 0x000b, 0x000c, 0x000d, 0x001b, 0x007f, 0x0085, 0x009b,
  0x2028, 0x2029,
  // 기본 무시 문자 가운데 Cf 가 아닌 것(결합 자소 연결 · 한글 채움 · 크메르 · 몽골 이형 선택자 · 이형 선택자)과 점자 빈칸
  0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180f, 0x3164, 0xffa0, 0xfe00, 0xfe0f, 0xe0100, 0xe01ef, 0x2800,
]

function mark(code: number): string {
  return `⟨U+${code.toString(16).toUpperCase().padStart(4, '0')}⟩`
}

describe('revealHidden', () => {
  it('숨은 문자는 대문자 16진 표식으로 바꾼다', () => {
    expect(revealHidden('admin\u{202E}gnp.exe')).toBe('admin⟨U+202E⟩gnp.exe')
    expect(revealHidden('\u001b[31m빨강')).toBe('⟨U+001B⟩[31m빨강')
    expect(revealHidden('x\u{E0041}y')).toBe('x⟨U+E0041⟩y')
    const revealed = HIDDEN_CODES.map((code) => revealHidden(`a${String.fromCodePoint(code)}b`))
    expect(revealed).toEqual(HIDDEN_CODES.map((code) => `a${mark(code)}b`))
    expect(HIDDEN_CODES.filter((code) => !hasHidden(String.fromCodePoint(code)))).toEqual([])
  })

  it('줄바꿈은 ↵ · 탭은 공백 하나 · CR 은 숨은 문자다', () => {
    expect(revealHidden('줄1\n2026-09-18 15:00:00 decoy')).toBe('줄1↵2026-09-18 15:00:00 decoy')
    expect(revealHidden('a\tb')).toBe('a b')
    expect(revealHidden('\r\n')).toBe('⟨U+000D⟩↵')
    expect(hasHidden('a\tb\nc')).toBe(false)
  })

  it("'adm\\u3164in' 은 'admin' 과 같아 보이지 않는다", () => {
    expect(revealHidden('adm\u3164in')).toBe('adm⟨U+3164⟩in')
    expect(revealHidden('root\u2800')).toBe('root⟨U+2800⟩')
  })

  it('보이는 글자(한글 · 기호 · 이모지 · 결합 문자)는 그대로 둔다', () => {
    const plain = '관리자 admin <img src=x> [x](y) é 😀 ⟨U+202E⟩'
    expect(revealHidden(plain)).toBe(plain)
    expect(hasHidden(plain)).toBe(false)
  })
})

describe('untrustedParts', () => {
  it('글자는 이어 붙이고 숨은 문자 · 줄바꿈은 토막으로 뗀다', () => {
    expect(untrustedParts('ad\u{200B}min\tx\ny')).toEqual([
      { kind: 'text', text: 'ad' },
      { kind: 'hidden', code: 'U+200B' },
      { kind: 'text', text: 'min x' },
      { kind: 'newline' },
      { kind: 'text', text: 'y' },
    ])
    expect(untrustedParts('\u{2066}x\u{2069}')).toEqual([
      { kind: 'hidden', code: 'U+2066' },
      { kind: 'text', text: 'x' },
      { kind: 'hidden', code: 'U+2069' },
    ])
    expect(untrustedParts('')).toEqual([])
  })
})

describe('codePointLength · sliceCodePoints', () => {
  it('두 칸짜리 글자(태그 문자 · 이모지)를 한 자로 세고 반으로 가르지 않는다', () => {
    const s = 'a\u{E0041}😀b'
    expect(s.length).toBe(6)
    expect(codePointLength(s)).toBe(4)
    expect(sliceCodePoints(s, 2)).toBe('a\u{E0041}')
    expect(sliceCodePoints(s, 3)).toBe('a\u{E0041}😀')
    expect(sliceCodePoints('짧다', 10)).toBe('짧다')
  })
})
