import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { APPLICABILITY_LABEL, MAPPING_LABEL, ROLE_LABEL, sigmaHref, type CveCti, type IncidentCti, type SigmaSource, type SignatureCti, type SignatureMapping } from '@/api/cti'
import { isApiError } from '@/api/errors'
import { revealHidden } from '@/lib/untrusted'
import { Badge } from '../../atoms/Badge'
import type { Tone } from '../../atoms/tones'
import { UntrustedText } from '../../atoms/UntrustedText'
import { Banner } from '../../molecules/Banner'
import { CtiBadge } from '../../molecules/CtiBadge'
import { InfoTip } from '../../molecules/InfoTip'
import { CtiFreshnessFacts } from '../assets/CtiFreshnessFacts'
import { APPLICABILITY_TONE, cvssTone, formatCvss, formatPercentile, formatProbability, ransomwareLabel, staleSources, truncate } from '../assets/cti-format'
import { ApiErrorState } from '../states/ApiErrorState'
import { DetailSection } from './DetailSection'
import { TABLE } from './table-styles'

export interface VulnLinkPanelProps {
  /** GET /api/incidents/{key}/cti 응답. 없으면 첫 조회 중이거나 실패다 */
  data: IncidentCti | undefined
  pending: boolean
  fetching: boolean
  error: unknown
  onRetry: () => void
  className?: string
}

const NUMBER = '⑥'
const TITLE = '취약점 연계'

/** 대응 방식 표지의 색. 명시 대응만 정보 색이고, 공개 규칙(Sigma)은 분석가 대응과 가려 보이게 보라색이다 */
const MAPPING_TONE: Record<SignatureMapping, Tone> = { explicit: 'info', analyst: 'neutral', sigma: 'violet' }

/**
 * ⑥ 취약점 연계(#39): 요청 경로 서명(R105 · R106 · 공개 규칙 R107)이 가리킨 제품 · CVE 와 공개 정보(KEV · CVSS · EPSS),
 * 자산마다 그 제품이 있는지(해당 · 비해당 · 미확인), 공개 정보의 신선도.
 * 조회는 페이지가 갖고 이 구역은 그리기만 한다. 서명 규칙 사건이 아니면(applicable=false) 구역을 그리지 않고,
 * 첫 조회 중에도 그리지 않는다(대부분의 사건은 대상이 아니라 빈 구역이 잠깐 보였다 사라지지 않게).
 * 404 는 이 기능을 모르는 이전 서버로 보고 안내 한 줄만, 그 밖의 오류는 구역 안에서 다시 시도할 수 있게 보인다.
 * 머리에는 목록 · 대상 카드와 같은 CVE 배지(서버 badge, #52)를 둔다. 배지가 없는 이전 서버는 그리지 않는다.
 * 공개 규칙(Sigma) 서명은 원본 규칙 출처 · 변환 메모 · 응답 코드 조건을 함께 보인다(#54).
 * 판정에 쓰지 않는 운영 정보는 접어 둔다: 공개 정보 신선도(구역 끝 '신선도 보기') · 원본 규칙의 작성 · 위치 · 변환 메모('출처 보기') ·
 * 명시 · 분석가 대응의 근거 문장(대응 방식 표지 옆 ⓘ). 오래됨 띠 · 적용 판정 · 미확인 안내는 본문에 둔다.
 * 공개 규칙의 근거 문장(source)은 원본 규칙 출처와 같은 말이라 그리지 않는다.
 */
export function VulnLinkPanel({ data, pending, fetching, error, onRetry, className }: VulnLinkPanelProps) {
  if (!data) {
    if (pending) return null
    return (
      <DetailSection number={NUMBER} title={TITLE} className={className}>
        {isApiError(error) && error.status === 404 ? (
          <p className="m-0 text-xs text-ink-muted">취약점 연계 정보가 없습니다. 콘솔 API 가 이 기능 이전 판일 수 있습니다.</p>
        ) : (
          <ApiErrorState error={error} onRetry={onRetry} retrying={fetching} titleAs="h3" />
        )}
      </DetailSection>
    )
  }
  if (data.applicable !== true) return null
  if (!data.available) {
    return (
      <DetailSection number={NUMBER} title={TITLE} className={className}>
        <p className="m-0 text-xs text-ink-muted">공개 취약점 정보 표가 아직 없습니다. 관리자에게 수집 상태를 확인해 주세요.</p>
      </DetailSection>
    )
  }

  const stale = staleSources(data.freshness)
  return (
    <DetailSection
      number={NUMBER}
      title={TITLE}
      aside={
        <>
          {data.badge && <CtiBadge badge={data.badge} />}
          <span>
            규칙 {data.rule_id} {data.rule_version} · 서명 {data.signatures.length}개 · CVE {data.cves.length}건
          </span>
        </>
      }
      className={className}
    >
      <p className="m-0 text-xs text-ink-muted">CVE 정보는 조사 우선순위 참고용입니다. 판정은 행위 증거로 합니다.</p>
      {data.stale && (
        <Banner tone="warning">
          공개 정보가 오래됐습니다. 비해당으로 읽지 않습니다.{stale.length > 0 && ` 오래된 출처: ${stale.join(' · ')}`}
        </Banner>
      )}

      {data.signatures.map((signature) => (
        <SignatureBlock key={signature.id} signature={signature} />
      ))}

      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-ink-muted">이어진 CVE · KEV 먼저, EPSS 높은 순</span>
        <CveTable cves={data.cves} showSignatures={data.signatures.length > 1} />
      </div>

      {/* 신선도는 운영 정보라 접는다. 오래됐으면 위 띠가 어느 출처인지 본문에서 알린다 */}
      <InfoTip
        variant="text"
        label="취약점 연계"
        text="공개 정보 신선도"
        panelAs="div"
        panelClassName="mt-2"
        render={({ button, panel }) => (
          <div className="flex flex-col">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              {button}
              <Link to="/inventory">
                자산 · 취약점 <span aria-hidden="true">→</span>
              </Link>
            </div>
            {panel}
          </div>
        )}
      >
        <CtiFreshnessFacts freshness={data.freshness} />
      </InfoTip>
    </DetailSection>
  )
}

/**
 * 서명 하나: 제품 · 공급사 · 대응 방식(옆에 근거 문장 ⓘ) · 적용 요약 · 메서드 · 응답 코드 조건 · 원본 규칙 출처 · 자산 적용 표.
 * 공개 규칙은 원본 규칙 출처가 근거 문장과 같은 말이라 근거 문장(ⓘ)을 두지 않는다
 */
function SignatureBlock({ signature: s }: { signature: SignatureCti }) {
  if (s.sigma || !s.source) return <SignatureBody signature={s} />
  return (
    <InfoTip label={`${truncate(s.product, 60)} 대응 근거`} render={(source) => <SignatureBody signature={s} source={source} />}>
      <UntrustedText value={s.source} />
    </InfoTip>
  )
}

function SignatureBody({ signature: s, source }: { signature: SignatureCti; source?: { button: ReactNode; panel: ReactNode } }) {
  return (
    <div className="flex flex-col gap-1.5" data-signature={s.id}>
      <div className="flex flex-wrap items-center gap-1.5 text-sm">
        <strong className="min-w-0 font-semibold">
          <UntrustedText value={s.product} max={120} />
        </strong>
        <span className="min-w-0 text-xs text-ink-muted">
          <UntrustedText value={s.vendor} max={120} />
        </span>
        <Badge tone={MAPPING_TONE[s.mapping] ?? 'neutral'} data-mapping={s.mapping}>
          {MAPPING_LABEL[s.mapping] ?? s.mapping}
        </Badge>
        {source && source.button}
        <span className="text-xs text-ink-muted">적용</span>
        <Badge tone={APPLICABILITY_TONE[s.summary] ?? 'neutral'} data-applicability={s.summary}>
          {APPLICABILITY_LABEL[s.summary] ?? s.summary}
        </Badge>
        <span className="font-mono text-2xs text-ink-muted">
          {s.id}
          {s.methods && s.methods.length > 0 && ` · ${s.methods.join(' · ')} 만`}
        </span>
        {s.statuses && s.statuses.length > 0 && <span className="text-xs text-ink-muted" data-statuses="">{`응답 코드 ${s.statuses.join(' · ')} 일 때만`}</span>}
      </div>
      {source && source.panel}
      {s.sigma && <SigmaSourceBlock sigma={s.sigma} />}
      {s.kev_products && (
        <span className="text-xs text-ink-muted">
          {s.kev_products.length > 0 ? `KEV 에 이 제품 항목 ${s.kev_products.length}건` : 'KEV 에 이 제품 항목이 없습니다.'}
        </span>
      )}
      {s.applicability.length === 0 ? (
        <span className="text-xs text-ink-muted">자산 표가 비어 있어 적용 여부를 판정하지 못했습니다. 자산 수집을 먼저 돌려야 합니다.</span>
      ) : (
        <div className={TABLE.wrap}>
          <table className={TABLE.table} aria-label={`${revealHidden(s.product)} 자산 적용`}>
            <thead>
              <tr>
                <th scope="col" className={TABLE.th}>
                  자산
                </th>
                <th scope="col" className={TABLE.th}>
                  요청 받음
                </th>
                <th scope="col" className={TABLE.th}>
                  판정
                </th>
                <th scope="col" className={TABLE.th}>
                  이유
                </th>
              </tr>
            </thead>
            <tbody>
              {s.applicability.map((a) => (
                <tr key={a.asset_id} data-status={a.status}>
                  <td className={`${TABLE.td} whitespace-nowrap`}>
                    <span className="font-mono font-medium">{a.asset_id}</span> <span className="text-ink-muted">{ROLE_LABEL[a.role] ?? a.role}</span>
                  </td>
                  <td className={TABLE.td}>{a.targeted ? <Badge tone="violet">받음</Badge> : <span className="text-ink-muted">—</span>}</td>
                  <td className={TABLE.td}>
                    <Badge tone={APPLICABILITY_TONE[a.status] ?? 'neutral'}>{APPLICABILITY_LABEL[a.status] ?? a.status}</Badge>
                  </td>
                  <td className={`${TABLE.td} min-w-[220px]`}>
                    <UntrustedText value={a.reason} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/**
 * 공개 규칙 서명의 원본 규칙 출처(#54): 제목 · id 는 늘 보이고, 작성자 · 성숙도 · 등급 · 라이선스 · 원본 위치 · 변환 메모는 '출처 보기' 로 접는다.
 * 값은 서버 규칙 정의의 글자라 비신뢰 글자로 그린다. 원본 위치는 SigmaHQ 저장소 주소(sigmaHref)일 때만 새 창 링크다
 */
function SigmaSourceBlock({ sigma }: { sigma: SigmaSource }) {
  const href = sigmaHref(sigma.url)
  const notes = sigma.notes ?? []
  return (
    <InfoTip
      variant="text"
      label="원본 규칙"
      text="출처 보기"
      panelAs="div"
      panelClassName="mt-0 flex flex-col gap-1 text-xs leading-5 text-ink"
      render={({ button, panel }) => (
        <div className="flex flex-col gap-1 rounded-sm border border-line px-2.5 py-2 text-xs leading-5" data-sigma-source="">
          <span className="flex flex-wrap items-baseline gap-x-2">
            <span className="min-w-0">
              원본 규칙: <UntrustedText value={sigma.title} max={200} fallback="제목 없음" /> ·{' '}
              <span className="font-mono">
                <UntrustedText value={sigma.id} max={64} fallback="id 없음" />
              </span>
            </span>
            {button}
          </span>
          {panel}
        </div>
      )}
    >
      <SigmaSourceDetails sigma={sigma} href={href} notes={notes} />
    </InfoTip>
  )
}

/** 원본 규칙의 작성 · 성숙도 · 등급 · 라이선스 · 원본 위치 · 변환 메모(접힌 쪽) */
function SigmaSourceDetails({ sigma, href, notes }: { sigma: SigmaSource; href: string | null; notes: readonly string[] }) {
  return (
    <>
      <span className="text-ink-muted">
        작성 <UntrustedText value={sigma.author} max={200} fallback="—" /> · 성숙도 <UntrustedText value={sigma.status} max={32} fallback="—" /> · 등급{' '}
        <UntrustedText value={sigma.level} max={32} fallback="—" /> · 라이선스 <UntrustedText value={sigma.license} max={64} fallback="—" />
      </span>
      <span className="text-ink-muted">
        원본 위치{' '}
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer" className="font-mono [overflow-wrap:anywhere]">
            {href}
          </a>
        ) : (
          <span className="font-mono">
            <UntrustedText value={sigma.url} max={300} fallback="—" />
          </span>
        )}
      </span>
      {notes.length > 0 && (
        <div className="flex flex-col gap-0.5">
          <span className="text-ink-muted">변환 메모</span>
          <ul aria-label="변환 메모" className="m-0 list-disc space-y-0.5 pl-4 text-ink-muted">
            {notes.map((note, i) => (
              <li key={i}>
                <UntrustedText value={note} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}

/** CVE 표: KEV 등재일 · 랜섬웨어 · CVSS · EPSS(백분위) · 요약. 서명이 여럿이면 CVE 아래에 부른 서명을 적는다 */
function CveTable({ cves, showSignatures }: { cves: CveCti[]; showSignatures: boolean }) {
  if (cves.length === 0) return <p className="m-0 text-xs text-ink-muted">이 사건의 서명에 이어진 CVE 가 없습니다.</p>
  return (
    <div className={`${TABLE.wrap} max-h-96`}>
      <table className={TABLE.table} aria-label="이어진 CVE">
        <thead>
          <tr>
            <th scope="col" className={TABLE.th}>
              CVE
            </th>
            <th scope="col" className={TABLE.th}>
              KEV 등재일
            </th>
            <th scope="col" className={TABLE.th}>
              랜섬웨어
            </th>
            <th scope="col" className={TABLE.th}>
              CVSS
            </th>
            <th scope="col" className={TABLE.th}>
              EPSS (백분위)
            </th>
            <th scope="col" className={TABLE.th}>
              요약
            </th>
          </tr>
        </thead>
        <tbody>
          {cves.map((c) => {
            const summary = c.kev?.name ?? c.description
            return (
              <tr key={c.cve_id} data-kev={c.kev ? 'yes' : 'no'}>
                <td className={TABLE.td}>
                  <span className={`${TABLE.mono} font-medium`}>
                    <UntrustedText value={c.cve_id} max={64} />
                  </span>
                  {showSignatures && (
                    <span className="block font-mono text-2xs text-ink-muted">
                      <UntrustedText value={c.signature_ids.join(' · ')} max={120} />
                    </span>
                  )}
                </td>
                <td className={TABLE.td}>
                  {c.kev ? (
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={c.kev.due_date ? `조치 기한 ${revealHidden(c.kev.due_date)}` : undefined}>
                      <Badge tone="danger">KEV</Badge>
                      <span className={TABLE.mono}>
                        <UntrustedText value={c.kev.date_added} max={64} />
                      </span>
                    </span>
                  ) : (
                    <span className="text-ink-muted">—</span>
                  )}
                </td>
                <td className={`${TABLE.td} whitespace-nowrap`}>
                  {c.kev?.ransomware?.toLowerCase() === 'known' ? (
                    <Badge tone="danger">{ransomwareLabel(c.kev.ransomware)}</Badge>
                  ) : (
                    <span className="text-ink-muted">{ransomwareLabel(c.kev?.ransomware)}</span>
                  )}
                </td>
                <td className={TABLE.td}>
                  {c.cvss ? (
                    <Badge tone={cvssTone(c.cvss.severity)} title={revealHidden([c.cvss.version && `CVSS ${c.cvss.version}`, c.cvss.vector].filter(Boolean).join(' · ')) || undefined}>
                      {formatCvss(c.cvss.score, c.cvss.severity)}
                    </Badge>
                  ) : (
                    <span className="text-ink-muted">—</span>
                  )}
                </td>
                <td className={`${TABLE.td} ${TABLE.mono}`}>
                  {c.epss ? (
                    <>
                      {formatProbability(c.epss.score)} <span className="text-ink-muted">({formatPercentile(c.epss.percentile)})</span>
                    </>
                  ) : (
                    <span className="text-ink-muted">—</span>
                  )}
                </td>
                <td className={`${TABLE.td} min-w-[220px]`} title={summary ? revealHidden(summary) : undefined}>
                  <UntrustedText value={truncate(summary)} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
