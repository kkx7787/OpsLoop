export const PAGE_SIZES = [25, 50, 100] as const
export const DEFAULT_PAGE_SIZE = PAGE_SIZES[0]

/** 잘못된 URL이 음수 offset, 소수, 과도한 정수로 API에 전달되지 않게 한다. */
export function paginationFromSearch(params: URLSearchParams) {
  const raw = params.get('page') ?? '1'
  const number = /^\d+$/.test(raw) ? Number(raw) : 1
  const page = Number.isSafeInteger(number) && number >= 1 && number <= 1_000_000 ? number : 1
  const size = Number(params.get('page_size'))
  const pageSize = PAGE_SIZES.find((allowed) => allowed === size) ?? DEFAULT_PAGE_SIZE
  return { page, pageSize }
}

/** 처음·끝과 현재 페이지 주변만 보여 준다. 건수가 많아도 단추 수가 늘어나지 않는다. */
export function pageNumbers(page: number, count: number): Array<number | 'gap-left' | 'gap-right'> {
  if (count <= 7) return Array.from({ length: count }, (_, i) => i + 1)
  const start = Math.max(2, Math.min(page - 1, count - 3))
  const end = Math.min(count - 1, Math.max(page + 1, 4))
  return [1, ...(start > 2 ? ['gap-left' as const] : []),
    ...Array.from({ length: end - start + 1 }, (_, i) => start + i),
    ...(end < count - 1 ? ['gap-right' as const] : []), count]
}
