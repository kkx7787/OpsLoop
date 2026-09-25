import { useState, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { codePointLength, hiddenMark, NEWLINE_MARK, sliceCodePoints, untrustedParts, type UntrustedPart } from '@/lib/untrusted'
import { SOFT_TONE } from './tones'

export interface UntrustedTextProps {
  /** 비신뢰 원문(로그 · 공격자 입력 · 자산 수집 결과). 서버 값 그대로 준다 */
  value: string | null | undefined
  /** 원문 글자 수(표식으로 바꾸기 전)가 이보다 많으면 앞부분만 보이고 펼치기 단추를 둔다. 기본 500 */
  max?: number
  /**
   * 한 줄 말줄임 자리(목록 행 · 카드 · 링크 안). 펼치기 단추 없이 max 자까지만 그리고 '…' 를 붙인다.
   * 말줄임(truncate)은 감싸는 쪽이 주고, 전체는 감싸는 쪽이 title={revealHidden(값)} 으로 보인다
   */
  clip?: boolean
  /** 값이 없을 때(null · undefined · 빈 문자열) 보일 것 */
  fallback?: ReactNode
  className?: string
}

/** 펼쳐도 그리는 글자 수(원문 코드 포인트) 상한. 넘는 부분은 개수만 알린다(수십만 자 한 값이 화면을 멈추지 않게) */
export const EXPAND_MAX = 20_000

const MARK = cn('mx-px rounded-sm px-0.5 font-mono text-[0.85em] font-normal whitespace-nowrap', SOFT_TONE.warning)

function Part({ part }: { part: UntrustedPart }) {
  if (part.kind === 'text') return <>{part.text}</>
  if (part.kind === 'newline') {
    return (
      <span className={MARK} data-hidden-char="newline" title="줄바꿈">
        {NEWLINE_MARK}
      </span>
    )
  }
  return (
    <span className={MARK} data-hidden-char={part.code} title={`숨은 문자 ${part.code}`}>
      {hiddenMark(part.code)}
    </span>
  )
}

/**
 * 비신뢰 문자열 한 값(#41). 원문은 그대로 두고 보이는 모습만 바꾼다.
 *  숨은 문자(방향 제어 · 제로폭 · 제어 문자 …)는 '⟨U+202E⟩' 배지, 줄바꿈은 '↵' 배지, 탭은 공백으로 보인다
 *  전체를 <bdi dir="ltr"> 로 격리해 옆 값 · 뒤 필드의 글자 방향이 뒤집히지 않는다
 *  max 자를 넘으면 앞부분만 보이고 '… N자 더 · 펼치기' 로 펼친다. 긴 무공백 문자열은 칸 안에서 끊는다
 *  펼쳐도 EXPAND_MAX 자까지만 그리고 나머지는 개수만 적는다 · 값이 바뀌면(다른 행 · 다시 조회) 다시 접힌다
 * 문자열만 들어가는 자리(title · aria-label · <option>)는 lib/untrusted 의 revealHidden 을 쓴다.
 */
export function UntrustedText({ value, max = 500, clip = false, fallback = null, className }: UntrustedTextProps) {
  // 펼친 값을 기억한다. 같은 자리에 다른 값이 오면 펼침이 따라가지 않는다
  const [openedFor, setOpenedFor] = useState<string | null>(null)
  if (value === null || value === undefined || value === '') return <>{fallback}</>

  const open = openedFor === value
  // UTF-16 길이가 max 이하면 글자 수도 max 이하다. 넘을 때만 센다
  const total = value.length > max ? codePointLength(value) : value.length
  const cut = total > max
  const expanded = cut && open && !clip
  const shown = !cut ? value : expanded ? sliceCodePoints(value, EXPAND_MAX) : sliceCodePoints(value, max)
  // 펼쳐도 그리지 않는 글자 수
  const rest = expanded ? Math.max(0, total - EXPAND_MAX) : 0
  return (
    <span data-untrusted="" className={cn('[overflow-wrap:anywhere]', className)}>
      <bdi dir="ltr">
        {untrustedParts(shown).map((part, i) => (
          <Part key={i} part={part} />
        ))}
      </bdi>
      {cut &&
        (clip ? (
          '…'
        ) : (
          <>
            {rest > 0 && (
              <span className="ml-1 font-sans text-2xs whitespace-nowrap text-ink-muted">{`… ${rest.toLocaleString('ko-KR')}자 더는 화면에 그리지 않음`}</span>
            )}
            <button
              type="button"
              aria-expanded={open}
              onClick={() => setOpenedFor(open ? null : value)}
              className="ml-1 inline cursor-pointer rounded-sm border-0 bg-transparent p-0 align-baseline font-sans text-2xs font-medium whitespace-nowrap text-primary hover:underline"
            >
              {open ? '접기' : `… ${(total - max).toLocaleString('ko-KR')}자 더 · 펼치기`}
            </button>
          </>
        ))}
    </span>
  )
}
