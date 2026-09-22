import { clsx, type ClassValue } from 'clsx'
import { extendTailwindMerge } from 'tailwind-merge'

/**
 * 디자인 토큰 중 tailwind-merge 가 모르는 이름을 알려 준다(src/styles/index.css 의 @theme).
 * 등록하지 않으면 shadow-card 를 그림자 색으로, rounded-card 를 모르는 클래스로 보고
 * 뒤에 온 shadow-none · rounded-none 과 합치지 않는다. 토큰을 늘리면 여기도 늘린다.
 */
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      radius: ['control', 'panel', 'tile', 'card'],
      shadow: ['card', 'control', 'field', 'raised', 'hairline', 'hairline-up', 'sidebar'],
      tracking: ['heading', 'display'],
    },
  },
})

/** 조건부 클래스(clsx)를 모은 뒤 겹치는 Tailwind 클래스는 뒤의 것을 남긴다. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
