/**
 * 상세 화면의 표 모양. 클래스 이름을 조립하지 않고 통째로 적는다(Tailwind 는 소스에 적힌 클래스만 만든다).
 * 표는 카드 안에서 가로로 넘칠 수 있으므로 감싸는 쪽에 wrap 을 준다.
 */
export const TABLE = {
  wrap: 'w-full overflow-auto',
  table: 'w-full border-collapse text-xs',
  th: 'sticky top-0 bg-surface px-2.5 py-2 text-left font-medium whitespace-nowrap text-ink-muted shadow-hairline',
  td: 'px-2.5 py-1.5 align-top shadow-hairline',
  mono: 'font-mono tabular-nums whitespace-nowrap',
} as const
