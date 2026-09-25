import { Link } from 'react-router'
import { APPLICABILITY_LABEL, MAPPING_LABEL, ROLE_LABEL, type CveCti, type IncidentCti, type SignatureCti } from '@/api/cti'
import { isApiError } from '@/api/errors'
import { Badge } from '../../atoms/Badge'
import { Banner } from '../../molecules/Banner'
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

/**
 * ⑥ 취약점 연계(#39): 요청 경로 서명(R105 · R106)이 가리킨 제품 · CVE 와 공개 정보(KEV · CVSS · EPSS),
 * 자산마다 그 제품이 있는지(해당 · 비해당 · 미확인), 공개 정보의 신선도.
 * 조회는 페이지가 갖고 이 구역은 그리기만 한다. 서명 규칙 사건이 아니면(applicable=false) 구역을 그리지 않고,
 * 첫 조회 중에도 그리지 않는다(대부분의 사건은 대상이 아니라 빈 구역이 잠깐 보였다 사라지지 않게).
 * 404 는 이 기능을 모르는 이전 서버로 보고 안내 한 줄만, 그 밖의 오류는 구역 안에서 다시 시도할 수 있게 보인다.
 */
export function VulnLinkPanel({ data, pending, fetching, error, onRetry, className }: VulnLinkPanelProps) {
  if (!data) {
    if (pending) return null
    return (
      <DetailSection number={NUMBER} title={TITLE} className={className}>
        {isApiError(error) && error.status === 404 ? (
          <p className="m-0 text-xs text-ink-muted">취약점 연계 정보가 없습니다. 콘솔 API 가 이 기능(#39) 이전 판일 수 있습니다.</p>
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
        <p className="m-0 text-xs text-ink-muted">공개 취약점 정보 표가 아직 없습니다. 서버에 CTI 마이그레이션을 적용하고 수집기를 한 번 돌리면 보입니다.</p>
      </DetailSection>
    )
  }

  const stale = staleSources(data.freshness)
  return (
    <DetailSection
      number={NUMBER}
      title={TITLE}
      aside={
        <span>
          규칙 {data.rule_id} {data.rule_version} · 서명 {data.signatures.length}개 · CVE {data.cves.length}건
        </span>
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

      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-ink-muted">공개 정보 신선도</span>
        <CtiFreshnessFacts freshness={data.freshness} />
      </div>

      <p className="m-0 text-xs text-ink-muted">
        자산별 설치 패키지 · 배포판 취약점은 <Link to="/inventory">자산 · 취약점</Link> 화면에서 봅니다.
      </p>
    </DetailSection>
  )
}

/** 서명 하나: 제품 · 공급사 · 대응 방식 · 적용 요약 · 근거 문장 · 자산 적용 표 */
function SignatureBlock({ signature: s }: { signature: SignatureCti }) {
  return (
    <div className="flex flex-col gap-1.5" data-signature={s.id}>
      <div className="flex flex-wrap items-center gap-1.5 text-sm">
        <strong className="font-semibold">{s.product}</strong>
        <span className="text-xs text-ink-muted">{s.vendor}</span>
        <Badge tone={s.mapping === 'explicit' ? 'info' : 'neutral'}>{MAPPING_LABEL[s.mapping] ?? s.mapping}</Badge>
        <span className="text-xs text-ink-muted">적용</span>
        <Badge tone={APPLICABILITY_TONE[s.summary] ?? 'neutral'} data-applicability={s.summary}>
          {APPLICABILITY_LABEL[s.summary] ?? s.summary}
        </Badge>
        <span className="font-mono text-2xs text-ink-muted">
          {s.id}
          {s.methods && s.methods.length > 0 && ` · ${s.methods.join(' · ')} 만`}
        </span>
      </div>
      <p className="m-0 text-xs leading-5 text-ink-muted">{s.source}</p>
      {s.kev_products && (
        <span className="text-xs text-ink-muted">
          {s.kev_products.length > 0 ? `KEV 에 이 제품 항목 ${s.kev_products.length}건 · 아래 CVE 표에 함께 보입니다` : 'KEV 에 이 제품 항목이 없습니다.'}
        </span>
      )}
      {s.applicability.length === 0 ? (
        <span className="text-xs text-ink-muted">자산 표가 비어 있어 적용 여부를 판정하지 못했습니다. 자산 수집을 먼저 돌려야 합니다.</span>
      ) : (
        <div className={TABLE.wrap}>
          <table className={TABLE.table} aria-label={`${s.product} 자산 적용`}>
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
                  <td className={`${TABLE.td} min-w-[220px]`}>{a.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
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
                  <span className={`${TABLE.mono} font-medium`}>{c.cve_id}</span>
                  {showSignatures && <span className="block font-mono text-2xs text-ink-muted">{c.signature_ids.join(' · ')}</span>}
                </td>
                <td className={TABLE.td}>
                  {c.kev ? (
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={c.kev.due_date ? `조치 기한 ${c.kev.due_date}` : undefined}>
                      <Badge tone="danger">KEV</Badge>
                      <span className={TABLE.mono}>{c.kev.date_added}</span>
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
                    <Badge tone={cvssTone(c.cvss.severity)} title={[c.cvss.version && `CVSS ${c.cvss.version}`, c.cvss.vector].filter(Boolean).join(' · ') || undefined}>
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
                <td className={`${TABLE.td} min-w-[220px]`} title={summary ?? undefined}>
                  {truncate(summary)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
