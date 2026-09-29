import { Link } from 'react-router'
import type { Fingerprint, FingerprintKind } from '@/api/sources'
import { revealHidden } from '@/lib/untrusted'
import { Time } from '../../atoms/Time'
import { UntrustedText } from '../../atoms/UntrustedText'
import { ColumnHeader } from './ColumnHeader'
import { fingerprintHref } from './model'

const cell = 'px-4 py-2.5 align-top'
/** 열 이름과 칸의 뜻(열 머리 ⓘ) */
const HEADERS: ReadonlyArray<readonly [string, string?]> = [
  ['지문 값'],
  ['출발지'],
  ['연결', '그 지문이 나온 이벤트 수입니다.'],
  ['사건 있는 출발지', '그 지문을 쓴 출발지 가운데 사건이 하나라도 있는 곳입니다. 출발지 목록에는 이 출발지만 나오므로 0곳인 값은 누를 수 없습니다.'],
  ['첫 관측 (KST)'],
  ['마지막 관측 (KST)'],
]

/**
 * 도구 지문 한 쪽. 값을 누르면 출발지 탭이 그 지문을 쓴 출발지 가운데 사건 있는 출발지로 좁혀진다.
 * 출발지 목록은 사건 있는 출발지만 보이므로, 사건 있는 출발지가 없는 값은 빈 목록으로 가지 않게 링크를 걸지 않는다.
 * 까닭은 '사건 있는 출발지' 열 머리 ⓘ 에 한 번 적는다(행마다 되풀이하지 않는다. 같은 행의 '0곳'이 보인다).
 * 값은 공격자가 보낸 글자라 링크 안에서는 앞 160자만 말줄임으로 그리고 전체는 title(숨은 문자 표식)로 보인다
 * (링크 안에 펼치기 단추를 두지 않는다). 링크가 아닌 값은 펼치기로 본다
 */
export function FingerprintsTable({ kind, items }: { kind: FingerprintKind; items: readonly Fingerprint[] }) {
  return (
    <table className="responsive-table w-full text-left text-sm" aria-label="도구 지문 목록">
      <thead className="sticky top-0 z-10 border-b border-line bg-surface text-xs text-ink-muted">
        <tr>
          {HEADERS.map(([label, tip]) => (
            <ColumnHeader key={label} label={label} tip={tip} className={`${cell} font-medium whitespace-nowrap`} />
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
                <span className="font-mono text-xs break-all" data-no-incident-sources><UntrustedText value={item.value} max={160} /></span>
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
