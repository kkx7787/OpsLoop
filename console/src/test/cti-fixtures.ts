import type {
  AssetApplicability,
  AssetDetail,
  AssetDetailAvailable,
  AssetRow,
  AssetsResult,
  AssetVulnerability,
  CtiFreshness,
  CveCti,
  IncidentCtiDetail,
  SignatureCti,
  WatchAsset,
  WatchResult,
  WatchRow,
} from '@/api/cti'

/** CVE · KEV 연계(#39) 픽스처. 값은 실측(facts: CVE-2024-6387 EPSS 0.99506 · 백분위 0.99944)과 rules_cve.json c1 을 따른다 */

export const CTI_AS_OF = '2026-09-25T03:00:00Z'
export const CTI_KEY = 'R105|c1|203.0.113.7|2026-09-25T01:00:00+00:00'

export function freshness(extra: Partial<CtiFreshness> = {}): CtiFreshness {
  return {
    kev: { fetched_at: '2026-09-25T02:00:00Z', source_ts: '2026-09-23T00:00:00Z', stale: false },
    epss: { fetched_at: '2026-09-25T02:01:00Z', source_ts: '2026-09-24T12:00:20Z', stale: false },
    osv: { fetched_at: '2026-09-25T02:05:00Z', source_ts: null, stale: false },
    nvd: { fetched_at: '2026-09-25T02:20:00Z', source_ts: null, stale: false },
    assets: { oldest_collected_at: '2026-09-24T20:10:00Z', stale_assets: [] },
    ...extra,
  }
}

export function applicability(extra: Partial<AssetApplicability> = {}): AssetApplicability {
  return { asset_id: 'web-01', role: 'target', targeted: true, status: 'not_affected', reason: '자산 표의 패키지 · 컨테이너 이미지에 없다', collected_at: '2026-09-24T20:10:00Z', ...extra }
}

export function signature(extra: Partial<SignatureCti> = {}): SignatureCti {
  return {
    id: 'geoserver',
    product: 'GeoServer',
    vendor: 'OSGeo',
    mapping: 'analyst',
    source: 'GeoServer 기본 배포의 웹 관리 화면이 /geoserver/web/ 아래에 있다.',
    methods: null,
    cves: [],
    kev_products: [{ cve_id: 'CVE-2024-36401', vendor_project: 'OSGeo', product: 'GeoServer', name: 'OSGeo GeoServer GeoTools Eval Injection Vulnerability', date_added: '2024-07-15', due_date: '2024-08-05', ransomware: 'Unknown' }],
    applicability: [
      applicability({ asset_id: 'web-decoy', role: 'sensor', reason: '웹 디코이는 모르는 경로에 404 를 돌려주는 모의 서비스다. 실제 제품이 없다.', collected_at: null }),
      applicability(),
      applicability({ asset_id: 'fw', role: 'platform', targeted: false, status: 'unknown', reason: '자산 정보가 오래됐다 (마지막 수집 2026-09-22 05:10 KST). 비해당으로 보지 않는다' }),
    ],
    summary: 'not_affected',
    ...extra,
  }
}

export function cve(extra: Partial<CveCti> = {}): CveCti {
  return {
    cve_id: 'CVE-2024-36401',
    signature_ids: ['geoserver'],
    kev: { date_added: '2024-07-15', due_date: '2024-08-05', ransomware: 'Known', name: 'OSGeo GeoServer GeoTools Eval Injection Vulnerability', vendor_project: 'OSGeo', product: 'GeoServer' },
    cvss: { score: 9.8, version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'CRITICAL' },
    epss: { score: 0.94421, percentile: 0.99873, date: '2026-09-24' },
    description: 'GeoServer 의 속성 이름 평가로 원격 코드 실행이 된다.',
    nvd_fetched_at: '2026-09-25T02:20:00Z',
    ...extra,
  }
}

export function incidentCti(extra: Partial<IncidentCtiDetail> = {}): IncidentCtiDetail {
  return {
    as_of: CTI_AS_OF,
    incident_key: CTI_KEY,
    applicable: true,
    available: true,
    rule_id: 'R105',
    rule_version: 'c1',
    stale: false,
    freshness: freshness(),
    signatures: [signature()],
    cves: [cve()],
    ...extra,
  }
}

export function assetRow(extra: Partial<AssetRow> = {}): AssetRow {
  return {
    asset_id: 'web-01',
    role: 'target',
    method: 'ssh',
    host: 'opsloop-web-01',
    collected_at: '2026-09-24T20:10:00Z',
    received_at: '2026-09-24T20:10:05Z',
    stale: false,
    last_attempt_at: '2026-09-24T20:10:00Z',
    last_error: null,
    os_pretty: 'Ubuntu 24.04.5 LTS',
    kernel_running: '6.8.0-139-generic',
    kernel_running_version: '6.8.0-139.139',
    kernel_newest_version: '6.8.0-139.139',
    reboot_pending: false,
    packages: 612,
    images: 0,
    checked_at: '2026-09-25T02:05:00Z',
    check_error: null,
    vuln_total: 12,
    vuln_kev: 0,
    vuln_fix_available: 0,
    vuln_reboot_pending: 0,
    max_epss: 0.00431,
    ...extra,
  }
}

export function assetsResult(extra: Partial<AssetsResult> = {}): AssetsResult {
  return {
    as_of: CTI_AS_OF,
    available: true,
    freshness: freshness(),
    rows: [
      assetRow(),
      assetRow({ asset_id: 'fw', role: 'platform', host: 'opsloop-fw', kernel_newest_version: '6.8.0-142.142', reboot_pending: true, vuln_total: 30, vuln_kev: 2, vuln_fix_available: 3, vuln_reboot_pending: 25, max_epss: 0.99506 }),
      assetRow({ asset_id: 'console-b', role: 'platform', host: null, collected_at: null, stale: true, last_error: '연결 실패: ssh: connect to host console-b port 22: Operation timed out', checked_at: null, vuln_total: 0, max_epss: null }),
    ],
    ...extra,
  }
}

export function assetDetail(extra: Partial<AssetDetail> = {}): AssetDetail {
  const { images: _count, ...row } = assetRow({ asset_id: 'fw', role: 'platform', host: 'opsloop-fw', kernel_newest_version: '6.8.0-142.142', reboot_pending: true, vuln_total: 30, vuln_kev: 2, vuln_fix_available: 3, vuln_reboot_pending: 25 })
  return {
    ...row,
    os: { id: 'ubuntu', version_id: '24.04', codename: 'noble', pretty: 'Ubuntu 24.04.5 LTS' },
    kernel: { running: '6.8.0-139-generic', running_package: 'linux-image-6.8.0-139-generic', running_version: '6.8.0-139.139', installed: [{ package: 'linux-image-6.8.0-139-generic', version: '6.8.0-139.139' }, { package: 'linux-image-6.8.0-142-generic', version: '6.8.0-142.142' }] },
    images: [{ container: 'opsloop-api', image: 'opsloop-console:5adc7de', image_id: 'sha256:abc' }],
    probe_errors: [],
    key_packages: [{ name: 'openssh-server', version: '1:9.6p1-3ubuntu13.19' }, { name: 'haproxy', version: '2.8.16-0ubuntu0.24.04.3' }, { name: 'sudo', version: '1.9.15p5-3ubuntu5.24.04.3' }],
    ...extra,
  }
}

export function vuln(extra: Partial<AssetVulnerability> = {}): AssetVulnerability {
  return {
    osv_id: 'UBUNTU-CVE-2024-1086',
    cve_id: 'CVE-2024-1086',
    source_package: 'linux',
    version: '6.8.0-139.139',
    fix_state: 'reboot_pending',
    fixed_version: '6.8.0-142.142',
    kev: { date_added: '2024-05-30', ransomware: 'Known', name: 'Linux Kernel Use-After-Free Vulnerability' },
    epss: { score: 0.8412, percentile: 0.9921, date: '2026-09-24' },
    cvss: { score: 7.8, severity: 'HIGH' },
    ubuntu_priority: 'high',
    summary: 'netfilter nf_tables 의 해제 뒤 사용',
    ...extra,
  }
}

export function assetDetailResult(extra: Partial<AssetDetailAvailable> = {}): AssetDetailAvailable {
  return {
    as_of: CTI_AS_OF,
    available: true,
    asset: assetDetail(),
    vulnerabilities: { rows: [vuln(), vuln({ osv_id: 'UBUNTU-CVE-2026-82474', cve_id: 'CVE-2026-82474', source_package: 'sudo', version: '1.9.15p5-3ubuntu5.24.04.3', fix_state: 'no_fix', fixed_version: null, kev: null, epss: null, cvss: null, ubuntu_priority: 'medium', summary: 'sudo 의 권한 확인 결함' })], total: 120, limit: 50, offset: 0, filter: 'all' },
    freshness: freshness(),
    ...extra,
  }
}

export function watchAsset(extra: Partial<WatchAsset> = {}): WatchAsset {
  return { asset_id: 'web-01', role: 'target', status: 'not_affected', reason: 'openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3', package: 'openssh', installed: '1:9.6p1-3ubuntu13.19', fixed: '1:9.6p1-3ubuntu13.3', ...extra }
}

/** 주목 CVE 한 행. 기본값은 CVE-2024-6387(regreSSHion): KEV 아님 · EPSS 0.99506 · Ubuntu 24.04 수정판 1:9.6p1-3ubuntu13.3 */
export function watchRow(extra: Partial<WatchRow> = {}): WatchRow {
  return {
    cve_id: 'CVE-2024-6387',
    reason: 'OpenSSH regreSSHion · 인증 전 원격 코드 실행 · 모든 노드의 sshd',
    osv_id: 'UBUNTU-CVE-2024-6387',
    record_found: true,
    checked_at: '2026-09-25T02:05:00Z',
    ubuntu_priority: 'high',
    description: 'OpenSSH 서버의 신호 처리기 경쟁 상태로 인증 전 원격 코드 실행이 될 수 있다.',
    kev: null,
    epss: { score: 0.99506, percentile: 0.99944, date: '2026-09-24' },
    cvss: { score: 8.1, severity: 'HIGH' },
    affected_packages: [{ package: 'openssh', fixed: '1:9.6p1-3ubuntu13.3' }],
    assets: [
      watchAsset(),
      watchAsset({ asset_id: 'fw', role: 'platform' }),
      watchAsset({ asset_id: 'console-b', role: 'platform', status: 'unknown', reason: '자산 정보가 아직 없다', package: null, installed: null, fixed: null }),
    ],
    summary: 'not_affected',
    ...extra,
  }
}

export function watchResult(extra: Partial<WatchResult> = {}): WatchResult {
  return {
    as_of: CTI_AS_OF,
    available: true,
    freshness: freshness(),
    rows: [
      watchRow({
        cve_id: 'CVE-2026-53266',
        reason: '커널 netfilter ebtables · KEV 2026-09-18 등재',
        osv_id: 'UBUNTU-CVE-2026-53266',
        ubuntu_priority: 'medium',
        description: 'netfilter ebtables SNAT 처리 결함',
        kev: { date_added: '2026-09-18', ransomware: 'Unknown', name: 'Linux Kernel ebtables Improper Input Validation Vulnerability' },
        epss: { score: 0.0213, percentile: 0.842, date: '2026-09-24' },
        cvss: null,
        affected_packages: [{ package: 'linux', fixed: null }],
        assets: [
          watchAsset({ status: 'affected', reason: 'linux 6.8.0-139.139 · 배포판 수정판 없음', package: 'linux', installed: '6.8.0-139.139', fixed: null }),
          watchAsset({ asset_id: 'fw', role: 'platform', status: 'affected', reason: 'linux 6.8.0-139.139 · 배포판 수정판 없음', package: 'linux', installed: '6.8.0-139.139', fixed: null }),
          watchAsset({ asset_id: 'console-b', role: 'platform', status: 'unknown', reason: '자산 정보가 아직 없다', package: null, installed: null, fixed: null }),
        ],
        summary: 'affected',
      }),
      watchRow(),
      watchRow({
        cve_id: 'CVE-2021-3156',
        reason: 'sudo Baron Samedit · 로컬 권한 상승 · KEV',
        osv_id: null,
        record_found: false,
        ubuntu_priority: null,
        description: null,
        kev: { date_added: '2022-04-06', ransomware: 'Unknown', name: 'Sudo Heap-Based Buffer Overflow Vulnerability' },
        epss: null,
        cvss: null,
        affected_packages: [],
        assets: [
          watchAsset({ status: 'unknown', reason: '배포판(Ubuntu) 기록이 없다', package: null, installed: null, fixed: null }),
          watchAsset({ asset_id: 'fw', role: 'platform', status: 'unknown', reason: '배포판(Ubuntu) 기록이 없다', package: null, installed: null, fixed: null }),
        ],
        summary: 'unknown',
      }),
    ],
    ...extra,
  }
}

