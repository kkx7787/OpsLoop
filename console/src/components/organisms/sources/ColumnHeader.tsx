import { useId, type ReactNode } from 'react'
import { InfoTip } from '../../molecules/InfoTip'

/**
 * 표 열 머리. 칸의 계산 기준(tip)이 있으면 이름 옆 도움말(ⓘ)로 두고 머리가 그 설명을 읽는다.
 * 좁은 화면(responsive-table)은 머리를 숨기므로 ⓘ 도 보이지 않는다. 늘 봐야 하는 말은 여기 두지 않는다
 */
export function ColumnHeader({ label, tip, className }: { label: string; tip?: ReactNode; className: string }) {
  const id = useId()
  if (!tip) {
    return (
      <th scope="col" className={className}>
        {label}
      </th>
    )
  }
  return (
    <th scope="col" className={className} aria-describedby={id}>
      {label}{' '}
      {/* 열린 설명이 좁은 열 폭(단어 단위 줄바꿈)에 갇혀 세로로 길어지지 않게 최소 폭을 준다(열리면 열이 넓어진다) */}
      <InfoTip label={label} id={id} panelClassName="min-w-56">
        {tip}
      </InfoTip>
    </th>
  )
}
