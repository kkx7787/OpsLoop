import type { ComponentProps, ReactNode } from 'react'

/**
 * 선 아이콘(24 격자 · 1.8 굵기 · currentColor). 메뉴 아이콘은 와이어프레임 사이드바에서 옮겼다.
 * 장식이 기본이다(aria-hidden). 아이콘만 있는 단추는 단추 쪽에 aria-label 을 준다.
 */
export interface IconProps extends Omit<ComponentProps<'svg'>, 'children'> {
  size?: number
}

function Svg({ size = 18, strokeWidth = 1.8, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  )
}

/** 제품 표지(순환 화살표). 어두운 칸 위에 흰색으로 쓴다. */
export function IconLogo(props: IconProps) {
  return (
    <Svg strokeWidth={2.2} {...props}>
      <path d="M4.5 12a7.5 7.5 0 0 1 13.2-4.9M19.5 12a7.5 7.5 0 0 1-13.2 4.9" />
      <path d="M18 3.5v4h-4M6 20.5v-4h4" />
    </Svg>
  )
}

export function IconDashboard(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="2" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="2" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="2" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="2" />
    </Svg>
  )
}

export function IconIncident(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M6 9a6 6 0 0 1 12 0c0 6 2.5 8 2.5 8h-17S6 15 6 9" />
      <path d="M10.3 20.5a2 2 0 0 0 3.4 0" />
    </Svg>
  )
}

export function IconBlock(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M6 6l12 12" />
    </Svg>
  )
}

export function IconRules(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1" />
      <circle cx="15" cy="7" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="17" cy="17" r="2" />
    </Svg>
  )
}

export function IconSources(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4.5" />
      <circle cx="12" cy="12" r="1" />
    </Svg>
  )
}

export function IconReport(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M7 3.5h7l4.5 4.5v12.5H7z" />
      <path d="M14 3.5V8h4.5" />
      <path d="M10 17v-3M13 17v-5M16 17v-2" />
    </Svg>
  )
}

export function IconNodes(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3.5" y="4" width="17" height="7" rx="2" />
      <rect x="3.5" y="13" width="17" height="7" rx="2" />
      <path d="M7.5 7.5h.01M7.5 16.5h.01" />
    </Svg>
  )
}

export function IconNotify(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 12l16-7-5 15-3-6z" />
      <path d="M12 14l3-3" />
    </Svg>
  )
}

export function IconAudit(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3.5l7 3v5c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9v-5z" />
      <path d="M9 12l2 2 4-4" />
    </Svg>
  )
}

export function IconAccounts(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="9" cy="8.5" r="3.5" />
      <path d="M2.5 20c.8-3.5 3.4-5.5 6.5-5.5s5.7 2 6.5 5.5" />
      <path d="M16 5.5a3.5 3.5 0 0 1 0 6.5M18.5 14.8c1.6.8 2.7 2.6 3 5.2" />
    </Svg>
  )
}

export function IconRefresh(props: IconProps) {
  return (
    <Svg strokeWidth={2} {...props}>
      <path d="M20 11a8 8 0 1 0-2.3 5.7" />
      <path d="M20 4v7h-7" />
    </Svg>
  )
}

export function IconMenu(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Svg>
  )
}

export function IconClose(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  )
}

export function IconCheck(props: IconProps) {
  return (
    <Svg strokeWidth={2} {...props}>
      <path d="M5 12.5l4.5 4.5L19 7.5" />
    </Svg>
  )
}

/** 연결 끊김(S-10): 데이터베이스와 × */
export function IconDatabaseOff(props: IconProps) {
  return (
    <Svg {...props}>
      <ellipse cx="12" cy="6" rx="7" ry="2.5" />
      <path d="M5 6v6c0 1.4 3.1 2.5 7 2.5M19 6v4" />
      <path d="M5 12v6c0 1.4 3.1 2.5 7 2.5" />
      <path d="M16 15l5 5M21 15l-5 5" />
    </Svg>
  )
}

/** 권한 밖(403) */
export function IconLock(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
      <path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3" />
      <path d="M12 14.5v2.5" />
    </Svg>
  )
}

/** 세션 만료 */
export function IconClock(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </Svg>
  )
}

/** 오류 */
export function IconAlert(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M10.3 4.3L2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z" />
      <path d="M12 9.5v4M12 17h.01" />
    </Svg>
  )
}

/** 결과 없음 */
export function IconInbox(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3.5 13.5l2.6-7.2A2 2 0 0 1 8 5h8a2 2 0 0 1 1.9 1.3l2.6 7.2" />
      <path d="M3.5 13.5V18a1.5 1.5 0 0 0 1.5 1.5h14a1.5 1.5 0 0 0 1.5-1.5v-4.5h-5l-1.5 2.5h-4L7.5 13.5z" />
    </Svg>
  )
}

/** 없는 주소(404) */
export function IconCompass(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M15.5 8.5l-2 5-5 2 2-5z" />
    </Svg>
  )
}
