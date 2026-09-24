import type { NotifyGrade } from '@/api/notify'

/**
 * 메시지 틀 미리보기(화면에서만). 서버(app/notifier.py render · build_message)와 같은 규칙으로 자리표시자를 바꾼다:
 *  - 아는 자리표시자만 바꾸고, 모르는 것은 글자 그대로 둔다
 *  - 값이 없으면 '-'
 *  - 형식 지정자({x:>5} 등)는 자리표시자가 아니다(문자 치환만, 값 노출 방지)
 *  - 사건이 1건이면 머리말에도 그 사건 값이 들어가고, 링크는 그 사건 상세다
 *  - 일일 요약은 항목 틀을 쓰지 않고 고정 요약 줄 하나다
 */

export const PLACEHOLDERS = [
  ['event_label', '사건 종류 이름'],
  ['count', '건수'],
  ['severity_counts', '심각도별 건수'],
  ['rule_id', '규칙 번호'],
  ['rule_name', '규칙 이름'],
  ['severity', '심각도'],
  ['who', '출발지 IP 또는 대상'],
  ['elapsed', '경과(예 12분 전)'],
  ['first_ts', '발생 시각(KST)'],
  ['incident_key', '사건 키'],
  ['link', '콘솔 상세 주소'],
] as const

export type Placeholder = (typeof PLACEHOLDERS)[number][0]
export type TemplateValues = Partial<Record<Placeholder, string | number | null | undefined>>

const KNOWN = new Set<string>(PLACEHOLDERS.map(([key]) => key))

export function renderTemplate(template: string, values: TemplateValues): string {
  return template.replace(/\{([a-z_]+)\}/g, (match, key: string) => {
    if (!KNOWN.has(key)) return match
    const value = values[key as Placeholder]
    return value === undefined || value === null || value === '' ? '-' : String(value)
  })
}

const CONSOLE = 'https://<콘솔 주소>'

/** 미리보기 예시 값. 운영 값이 아니다. */
export const SAMPLE_HEADER: TemplateValues = {
  event_label: '새 인시던트',
  count: 2,
  severity_counts: 'high 1 · medium 1',
  link: `${CONSOLE}/incidents`,
}

export const SAMPLE_ITEMS: readonly TemplateValues[] = [
  {
    rule_id: 'R101',
    rule_name: 'SSH 무차별 대입',
    severity: 'high',
    who: '203.0.113.10',
    elapsed: '12분 전',
    first_ts: '2026-09-24 09:12',
    incident_key: 'R101|v2|203.0.113.10',
    link: `${CONSOLE}/incidents/R101%7Cv2%7C203.0.113.10`,
  },
  {
    rule_id: 'R003',
    rule_name: '허니팟 SSH 접속',
    severity: 'medium',
    who: '198.51.100.7',
    elapsed: '35분 전',
    first_ts: '2026-09-24 08:49',
    incident_key: 'R003|v2|198.51.100.7',
    link: `${CONSOLE}/incidents/R003%7Cv2%7C198.51.100.7`,
  },
]

/** 일일 요약 예시. 서버 daily_line 과 같은 문장 */
export const SAMPLE_DAILY = {
  header: { event_label: '일일 요약', count: 4, severity_counts: 'high 1 · low 3', link: `${CONSOLE}/` } satisfies TemplateValues,
  line: '미판정 4건 · 최고 경과 3시간 전 · 목표 초과 1건 · 최근 24시간 사건 9건',
}

export interface PreviewSection {
  title: string
  lines: string[]
}

/** 머리말 한 줄 + 항목 줄들 + 콘솔 링크. 서버가 보내는 본문과 같은 순서. 즉시 등급은 1건 · 여러 건을 둘 다 보인다 */
export function previewSections(header: string, item: string, grade: NotifyGrade = 'immediate'): PreviewSection[] {
  if (grade === 'daily') {
    return [{
      title: '매일 09:00 KST',
      lines: [renderTemplate(header, SAMPLE_DAILY.header), SAMPLE_DAILY.line, `콘솔에서 보기 → ${SAMPLE_DAILY.header.link}`],
    }]
  }
  const [first] = SAMPLE_ITEMS
  const single: TemplateValues = { ...SAMPLE_HEADER, count: 1, severity_counts: 'high 1', ...first }
  return [
    { title: '1건일 때', lines: [renderTemplate(header, single), renderTemplate(item, first), `콘솔에서 보기 → ${first.link}`] },
    {
      title: '여러 건일 때',
      lines: [renderTemplate(header, SAMPLE_HEADER), ...SAMPLE_ITEMS.map((values) => renderTemplate(item, values)), `콘솔에서 보기 → ${SAMPLE_HEADER.link}`],
    },
  ]
}
