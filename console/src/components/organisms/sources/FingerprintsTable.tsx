import { Link } from 'react-router'
import type { Fingerprint, FingerprintKind } from '@/api/sources'
import { revealHidden } from '@/lib/untrusted'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { fingerprintHref } from './model'

const cell = 'px-4 py-2.5 align-top'
const HEADERS = ['지문 값', '출발지', '연결', '사건 있는 출발지', '첫 관측 (KST)', '마지막 관측 (KST)']

/**
 * 도구 지문 한 쪽. 값을 누르면 출발지 탭이 그 지문을 쓴 출발지 가운데 사건 있는 출발지로 좁혀진다.
 * 출발지 목록은 사건 있는 출발지만 보이므로, 사건 있는 출발지가 없는 값은 빈 목록으로 가지 않게 링크를 걸지 않고 까닭을 적는다.
 * 값은 공격자가 보낸 글자라 링크 안에서는 앞 160자만 말줄임으로 그리고 전체는 title(숨은 문자 표식)로 보인다
 * (링크 안에 펼치기 단추를 두지 않는다). 링크가 아닌 값은 펼치기로 본다
 */
export function FingerprintsTable({ kind, items }: { kind: FingerprintKind; items: readonly Fingerprint[] }) {
  return (
    <table className="responsive-table w-full text-left text-sm" aria-label="도구 지문 목록">
      <thead className="sticky top-0 z-10 border-b border-line bg-surface text-xs text-ink-muted">
        <tr>
          {HEADERS.map((label) => (
            <th key={label} scope="col" className={`${cell} font-medium whitespace-nowrap`}>
              {label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {items.map((item, i) => (
          <tr key={`${i}:${item.value}`}>
            <td className={`${cell} max-w-xl`}>
              {item.incident_sources > 0 ? (
                <Link to={fingerprintHref(kind, item.value)} title={revealHidden(item.value)} className="font-mono text-xs break-all">
                  <UntrustedText value={item.value} max={160} clip />
                </Link>
              ) : (
                <>
                  <span className="font-mono text-xs break-all"><UntrustedText value={item.value} max={160} /></span>
                  <span className="mt-0.5 block text-xs text-ink-muted" data-no-incident-sources>사건 있는 출발지 없음 · 출발지 목록에 나오지 않습니다</span>
                </>
              )}
            </td>
            <td data-label="출발지" className={`${cell} whitespace-nowrap tabular-nums`}>{item.sources.toLocaleString('ko-KR')}곳</td>
            <td data-label="연결" className={`${cell} whitespace-nowrap tabular-nums`}>{item.connections.toLocaleString('ko-KR')}회</td>
            <td data-label="사건 있는 출발지" className={`${cell} whitespace-nowrap tabular-nums`}>{item.incident_sources.toLocaleString('ko-KR')}곳</td>
            <td data-label="첫 관측 (KST)" className={`${cell} whitespace-nowrap`}><Time value={item.first_ts} format="short" /></td>
            <td data-label="마지막 관측 (KST)" className={`${cell} whitespace-nowrap`}><Time value={item.last_ts} format="short" /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
