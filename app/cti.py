"""CVE · KEV 연계 조회 API (이슈 #39). 사건의 서명에 공개 취약점 정보(KEV · EPSS · CVSS)와 자산 해당 여부를 붙이고,
자산 조사 결과 · 자산별 배포판 취약점 · 주목 CVE 대조를 보인다. 읽기 조회라 역할 검사 없이 세션 미들웨어만 둔다.

CVE · KEV · EPSS · CVSS 는 판정값이 아니라 조사 우선순위 정보다. 판정은 행위 증거로 한다(판정 기준 §8).
원본은 데이터 노드 수집기(cti/opsloop_cti.py)가 S3 cti/ 에 한 번만 쓰고, 콘솔은 DB 의 정리된 행만 읽는다.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key
from typing import Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request

router = APIRouter()

# 공개 정보 · 자산 조사가 이보다 오래되면 '오래됨'이다. 수집기 · 자산 수집은 하루 한 번이라 한 번 거른 것까지는 본다.
STALE_HOURS = 48
KST = timezone(timedelta(hours=9))

# 이 표가 모두 있어야 조회한다. 마이그레이션(20260925_cti.sql) 전 DB 에서는 500 대신 available=false 로 답한다
CTI_TABLES = ["cti_snapshots", "cti_kev", "cti_cve", "cti_osv", "asset_inventory", "asset_vulnerabilities"]
# 주목 CVE 조회는 cti_watch 도 있어야 한다
WATCH_TABLES = [*CTI_TABLES, "cti_watch"]
# PostgreSQL 의 잘못된 정규식 오류(invalid_regular_expression). 서명 kev_match 가 PG 정규식 문법으로 틀리면 난다
INVALID_REGEX = "2201B"
# 자산 취약점 쪽 넘김의 offset 상한. 자산 하나의 취약점은 커널을 넣어도 수천 건이다.
#   상한이 없으면 int64 를 넘는 값이 DB 에 닿아 422 가 아니라 500 이 된다
MAX_OFFSET = 1_000_000

# 사건의 sensor 값 → 자산 id. 그 밖의 sensor 값(수집 노드 id, 예: web-01)은 그대로 자산 id 다.
#   웹 디코이(decoy)는 자산이 아니라 모의 서비스라 가상 항목 하나로 보인다
SENSOR_ASSETS = {"cowrie": "honeypot-dmz", "gateway": "gateway"}
DECOY_SENSOR = "decoy"
DECOY_ENTRY = {"asset_id": "web-decoy", "role": "sensor", "targeted": True, "status": "not_affected",
               "reason": "웹 디코이는 모르는 경로에 404 를 돌려주는 모의 서비스다. 실제 제품이 없다.",
               "collected_at": None}
# 요청을 받았는데 자산 표에 아직 없는 자산의 역할. 수집 노드(nginx.request 의 sensor)는 관제 대상이다
MISSING_ROLES = {"honeypot-dmz": "sensor", "gateway": "platform"}

ROLE_ORDER = {"target": 0, "platform": 1, "sensor": 2}
AFFECTED, NOT_AFFECTED, UNKNOWN = "affected", "not_affected", "unknown"
FIX_LABELS = {"fix_available": "수정판 있음", "reboot_pending": "재부팅하면 해소",
              "no_fix": "배포판 수정판 없음", "unknown": "수정 여부 미확인"}
PLATFORM_LABELS = {"windows": "Windows 전용", "appliance": "전용 장비 펌웨어"}
# 자산 상세에 따로 보이는 패키지. 공격 면(원격 접속 · 웹 · 권한 상승 · 컨테이너)과 관제 기반 순서다
KEY_PACKAGES = ["openssh-server", "nginx", "haproxy", "openssl", "sudo", "libc6", "systemd", "docker.io",
                "containerd", "tailscale", "python3.12", "postgresql-16"]

# 커널 소스 패키지(계약 10.5). linux · linux-aws · linux-hwe-6.8 · linux-signed-aws · linux-meta-aws 꼴이다.
#   이름이 linux 로 시작해도 커널이 아닌 소스(공용 스크립트 · 펌웨어 · 사용자 공간 · DKMS)는 뺀다.
#   수집기(cti/opsloop_cti.py)의 KERNEL_SOURCE_RE · NON_KERNEL_SOURCES 와 같게 둔다(test_cti 가 두 쪽 답을 견준다)
KERNEL_SOURCE_RE = re.compile(r"linux(-signed|-meta)?(-[a-z0-9.]+)*")
NON_KERNEL_SOURCES = frozenset({"linux-base", "linux-atm", "linux-sound-base", "linux-igd", "linux-wlan-ng",
                                "linux-apfs-rw", "linux-gpib", "linux-show-player"})
# 커널 릴리스(uname -r)의 판(flavor). 6.8.0-139-generic → generic, 6.8.0-1015-aws → aws
KERNEL_RELEASE_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([a-z0-9.+-]+)")
KERNEL_IMAGE_PREFIX = "linux-image-"

# 자산 정렬: 관제 대상 → 관제 기반 → 센서, 그다음 id
ASSET_ORDER = "CASE a.role WHEN 'target' THEN 0 WHEN 'platform' THEN 1 ELSE 2 END, a.asset_id"

TABLES_SQL = "SELECT bool_and(to_regclass(t) IS NOT NULL) FROM unnest($1::text[]) AS t"

INCIDENT_SQL = "SELECT incident_key, rule_id, rule_version, evidence FROM incidents WHERE incident_key = $1"

# 사건을 만든 규칙 정의. 규칙 버전 파일(rule_versions)에 서명의 제품 · CVE · KEV · 자산 조건이 함께 있다
RULE_SQL = """
    SELECT r FROM rule_versions rv, jsonb_array_elements(rv.definition -> 'rules') r
    WHERE rv.rule_version = $1 AND r ->> 'id' = $2 LIMIT 1"""

# 출처별 마지막 성공 회차. 실패 회차(status='failed')는 DB 를 갱신하지 않았으므로 신선도에 넣지 않는다
SNAPSHOTS_SQL = """
    SELECT DISTINCT ON (source) source, fetched_at, source_ts FROM cti_snapshots
    WHERE status = 'ok' AND source IN ('kev', 'epss', 'osv', 'nvd')
    ORDER BY source, fetched_at DESC, id DESC"""

# 서명 kev_match 로 KEV 항목을 고른다(대소문자 무시). vendor 는 필수, product · 설명 조건은 있을 때만
KEV_PRODUCTS_SQL = """
    SELECT cve_id, vendor_project, product, name, date_added, due_date, ransomware FROM cti_kev
    WHERE vendor_project ~* $1 AND ($2::text IS NULL OR product ~* $2)
      AND ($3::text IS NULL OR (name || ' ' || coalesce(description, '')) ~* $3)
    ORDER BY date_added DESC, cve_id"""

# CVE 하나에 KEV · EPSS · CVSS 를 붙인다. 요약은 NVD 설명, 아직 없으면 KEV 설명이다
CVES_SQL = """
    SELECT u.cve_id, k.cve_id IS NOT NULL AS in_kev, k.vendor_project, k.product, k.name, k.date_added,
           k.due_date, k.ransomware, c.epss, c.epss_percentile, c.epss_date, c.cvss_score, c.cvss_version,
           c.cvss_vector, c.cvss_severity, coalesce(c.description, k.description) AS description, c.nvd_fetched_at
    FROM unnest($1::text[]) AS u(cve_id)
    LEFT JOIN cti_kev k ON k.cve_id = u.cve_id
    LEFT JOIN cti_cve c ON c.cve_id = u.cve_id"""

# 적용 판정에 쓰는 자산 정보. 패키지는 수천 개라 서명이 찾는 이름(바이너리 또는 소스)만 DB 에서 걸러 온다.
#   package_count 는 거르기 전 전체 수다(0 이면 목록이 비어 '없음'을 말할 수 없다).
#   received_at 은 checked_at 과 같은 DB 시계라, 대조가 지금 조사보다 앞선 것인지 가린다
APPLICABILITY_ASSETS_SQL = f"""
    SELECT a.asset_id, a.role, a.collected_at, a.received_at, a.os, a.images, a.probe_errors, a.checked_at,
           jsonb_array_length(a.packages) AS package_count,
           coalesce((SELECT jsonb_agg(p ORDER BY p ->> 'name', p ->> 'version')
                     FROM jsonb_array_elements(a.packages) p
                     WHERE p ->> 'name' = ANY($1::text[]) OR p ->> 'source' = ANY($1::text[])), '[]') AS packages
    FROM asset_inventory a
    ORDER BY {ASSET_ORDER}"""

VULN_HITS_SQL = """
    SELECT asset_id, source_package, version, cve_id, fix_state FROM asset_vulnerabilities
    WHERE cve_id = ANY($1::text[]) ORDER BY asset_id, cve_id, source_package, osv_id"""

# 자산 목록 · 상세의 한 행. $1 이 NULL 이면 전체. vuln_kev 는 CVE 가 KEV 에 있는 행 수다
ASSETS_SQL = f"""
    SELECT a.asset_id, a.role, a.method, a.host, a.collected_at, a.received_at, a.last_attempt_at, a.last_error,
           a.os, a.kernel, a.images, a.probe_errors, jsonb_array_length(a.packages) AS packages,
           a.checked_at, a.check_error,
           coalesce(v.total, 0) AS vuln_total, coalesce(v.kev, 0) AS vuln_kev,
           coalesce(v.fix_available, 0) AS vuln_fix_available, coalesce(v.reboot_pending, 0) AS vuln_reboot_pending,
           v.max_epss
    FROM asset_inventory a
    LEFT JOIN LATERAL (
        SELECT count(*) AS total, count(k.cve_id) AS kev,
               count(*) FILTER (WHERE av.fix_state = 'fix_available') AS fix_available,
               count(*) FILTER (WHERE av.fix_state = 'reboot_pending') AS reboot_pending,
               max(c.epss) AS max_epss
        FROM asset_vulnerabilities av
        LEFT JOIN cti_kev k ON k.cve_id = av.cve_id
        LEFT JOIN cti_cve c ON c.cve_id = av.cve_id
        WHERE av.asset_id = a.asset_id) v ON true
    WHERE ($1::text IS NULL OR a.asset_id = $1)
    ORDER BY {ASSET_ORDER}"""

# 신선도의 자산 부분(수집 시각만)
ASSET_TIMES_SQL = f"SELECT a.asset_id, a.collected_at FROM asset_inventory a ORDER BY {ASSET_ORDER}"

KEY_PACKAGES_SQL = """
    SELECT p ->> 'name' AS name, p ->> 'version' AS version
    FROM asset_inventory a, jsonb_array_elements(a.packages) p
    WHERE a.asset_id = $1 AND p ->> 'name' = ANY($2::text[])
    ORDER BY p ->> 'name', p ->> 'version'"""

# 자산 취약점 목록. $2 필터: kev = KEV 에 있는 CVE 만, fix = 수정판 있음 · 재부팅하면 해소
VULNS_FROM = """
    FROM asset_vulnerabilities av
    LEFT JOIN cti_kev k ON k.cve_id = av.cve_id
    LEFT JOIN cti_cve c ON c.cve_id = av.cve_id
    LEFT JOIN cti_osv o ON o.osv_id = av.osv_id
    WHERE av.asset_id = $1
      AND ($2::text <> 'kev' OR k.cve_id IS NOT NULL)
      AND ($2::text <> 'fix' OR av.fix_state IN ('fix_available', 'reboot_pending'))"""
VULN_COUNT_SQL = "SELECT count(*)" + VULNS_FROM
# 정렬: KEV 먼저 → EPSS 높은 순(없는 것 뒤) → 조치할 수 있는 것 먼저 → CVE · OSV id · 소스 패키지.
#   끝의 세 열이 기본 키(자산 안에서 소스 패키지 · osv_id)를 덮어야 쪽 사이 순서가 바뀌지 않는다
#   (같은 osv_id 가 소스 패키지 여럿에 걸리면 동률이 되어 쪽마다 행이 겹치거나 빠진다)
VULNS_SQL = """
    SELECT av.osv_id, av.cve_id, av.source_package, av.version, av.fix_state, av.fixed_version,
           k.cve_id IS NOT NULL AS in_kev, k.date_added AS kev_date_added, k.ransomware AS kev_ransomware,
           k.name AS kev_name, c.epss, c.epss_percentile, c.epss_date, c.cvss_score, c.cvss_severity,
           o.ubuntu_priority, o.summary""" + VULNS_FROM + """
    ORDER BY (k.cve_id IS NULL), c.epss DESC NULLS LAST,
             array_position(ARRAY['fix_available', 'reboot_pending', 'no_fix', 'unknown'], av.fix_state),
             av.cve_id, av.osv_id, av.source_package
    LIMIT $3 OFFSET $4"""

# 주목 CVE 와 그 배포판 기록. affected 는 기록의 모든 영향 항목 {"생태계/패키지": 수정판 또는 null} 이다.
#   상세를 받지 않은 기록(detailed=false)의 affected 는 빈 사전이라 '영향 없음'으로 읽지 않는다. 요약은 NVD 설명, 없으면 OSV 요약이다
WATCH_SQL = """
    SELECT w.cve_id, w.reason, w.osv_id, w.record_found, w.checked_at, o.ubuntu_priority, o.detailed, o.affected,
           coalesce(c.description, o.summary) AS description,
           k.cve_id IS NOT NULL AS in_kev, k.date_added AS kev_date_added, k.ransomware AS kev_ransomware,
           k.name AS kev_name, c.epss, c.epss_percentile, c.epss_date, c.cvss_score, c.cvss_severity
    FROM cti_watch w
    LEFT JOIN cti_osv o ON o.osv_id = w.osv_id
    LEFT JOIN cti_kev k ON k.cve_id = w.cve_id
    LEFT JOIN cti_cve c ON c.cve_id = w.cve_id
    ORDER BY w.cve_id"""

# 주목 CVE 대조에 쓰는 자산 정보. 패키지는 영향 패키지(소스 이름)와 실행 중인 커널의 이미지 · 모듈 패키지만 걸러 온다
#   (커널 소스 이름을 정하는 데 쓴다, 계약 10.5)
WATCH_ASSETS_SQL = f"""
    SELECT a.asset_id, a.role, a.collected_at, a.os, a.kernel, a.probe_errors,
           jsonb_array_length(a.packages) AS package_count,
           coalesce((SELECT jsonb_agg(p ORDER BY p ->> 'name', p ->> 'version')
                     FROM jsonb_array_elements(a.packages) p
                     WHERE p ->> 'source' = ANY($1::text[])
                        OR p ->> 'name' = (a.kernel ->> 'running_package')
                        OR p ->> 'name' = ('linux-modules-' || (a.kernel ->> 'running'))), '[]') AS packages
    FROM asset_inventory a
    ORDER BY {ASSET_ORDER}"""


# ----------------------------------------------------------------------
#  순수 함수 (DB 없이 시험한다)
# ----------------------------------------------------------------------

def loads(value):
    """jsonb 는 풀에 코덱이 없어 문자열로 온다."""
    return json.loads(value) if isinstance(value, str) else value


def iso(value):
    """시각은 UTC ISO, 날짜는 YYYY-MM-DD 로 낸다."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return value.isoformat() if value is not None else None


def kst(value: datetime) -> str:
    """이유 문장 안의 시각. 사람이 읽는 문장이라 한국 시각으로 쓴다."""
    return value.astimezone(KST).strftime("%Y-%m-%d %H:%M KST")


def is_stale(value, now) -> bool:
    return value is None or now - value > timedelta(hours=STALE_HOURS)


def score(value):
    """EPSS 는 real 이라 5자리에서 자른다(원천도 5자리다). 소수 끝의 부동소수 잡음을 화면에 내지 않는다."""
    return round(float(value), 5) if value is not None else None


def sentences(*parts) -> str:
    """이유 문장들을 마침표로 잇는다. 빈 것은 건너뛰고, 이미 마침표로 끝난 문장에는 더 붙이지 않는다."""
    out = ""
    for part in parts:
        if not isinstance(part, str) or not part.strip():
            continue
        if out:
            out += ("" if out.endswith(".") else ".") + " "
        out += part.strip()
    return out


def stale_asset_reason(collected: datetime) -> str:
    return f"자산 정보가 오래됐다 (마지막 수집 {kst(collected)}). 비해당으로 보지 않는다"


def freshness(snapshots, assets, now) -> dict:
    """출처별 마지막 성공 수집과 자산 조사의 신선도. 한 번도 받지 못한 출처도 오래됨이다.
    NVD 는 초점 CVE 만 골라 받으므로 오래됨으로 보지 않는다."""
    last = {row["source"]: row for row in snapshots}
    out = {}
    for source in ("kev", "epss", "osv", "nvd"):
        row = last.get(source)
        fetched = row["fetched_at"] if row else None
        out[source] = {"fetched_at": iso(fetched), "source_ts": iso(row["source_ts"]) if row else None,
                       "stale": source != "nvd" and is_stale(fetched, now)}
    collected = [a["collected_at"] for a in assets if a["collected_at"] is not None]
    out["assets"] = {"oldest_collected_at": iso(min(collected)) if collected else None,
                     "stale_assets": [a["asset_id"] for a in assets if is_stale(a["collected_at"], now)]}
    return out


def any_stale(fresh: dict) -> bool:
    return any(fresh[source]["stale"] for source in ("kev", "epss", "osv"))


def os_name(os_info: dict) -> str:
    return (os_info.get("pretty")
            or " ".join(str(os_info[k]) for k in ("id", "version_id") if os_info.get(k))
            or "알 수 없는 운영체제")


def probe_failed(asset: dict, part: str) -> bool:
    """자산 조사(cti/probe.py)가 그 부분을 읽지 못했는가. 못 읽은 것은 errors 에 'packages: …' · 'images: …' 로 남는다.
    그때 목록은 빈 채로 오므로 '없음'으로 읽으면 안 된다."""
    errors = asset.get("probe_errors")
    return isinstance(errors, list) and any(isinstance(e, str) and e.startswith(part + ":") for e in errors)


def image_patterns(match: dict) -> tuple[list, bool]:
    """서명의 컨테이너 이미지 정규식(re.search, 대소문자 무시). 읽지 못한 식이 있으면 (읽은 것, True).
    규칙 버전 정의는 한 번 들어가면 고칠 수 없으니, 틀린 식 하나로 조회가 500 이 되지 않고 그 경로만 모름이 된다."""
    patterns, broken = [], False
    for pattern in match.get("images") or []:
        try:
            patterns.append(re.compile(pattern, re.I))
        except (re.error, TypeError, OverflowError, RecursionError):
            broken = True
    return patterns, broken


def judge(signature: dict, asset: dict, hits: list, now) -> tuple[str, str]:
    """서명 하나가 자산 하나에 해당하는지 (status, reason). 모르는 것은 비해당이 아니라 미확인이다.

    hits 는 이 자산의 배포판 취약점 중 서명 CVE 에 맞은 행이다(asset_vulnerabilities).
    조사가 패키지 · 이미지 목록을 읽지 못했으면(probe_errors) 빈 목록을 '설치 안 됨'으로 읽지 않는다.
    배포판 대조(checked_at)가 지금 조사(received_at)보다 앞서면 지금 목록은 대조한 적이 없으니 비해당이라 하지 않는다.
    두 시각은 모두 DB 시계(now())다. collected_at 은 노드 시계라 이 비교에 쓰지 않는다.
    """
    collected = asset.get("collected_at")
    if collected is None:
        return UNKNOWN, "자산 정보가 아직 없다"
    if is_stale(collected, now):
        return UNKNOWN, stale_asset_reason(collected)
    match = signature.get("asset_match")
    if not match:
        return UNKNOWN, "서명에 자산 대조 조건이 없다"
    platforms = match.get("platforms") or []
    os_info = asset.get("os")
    if platforms and "linux" not in platforms and os_info:
        kinds = " · ".join(PLATFORM_LABELS.get(p, p) for p in platforms)
        return NOT_AFFECTED, f"{signature.get('product')} 는 {kinds} 제품이다. 이 자산은 {os_name(os_info)} 다"

    names = {n for n in match.get("packages") or [] if isinstance(n, str)}
    packages = [p for p in asset.get("packages") or []
                if isinstance(p, dict) and (p.get("name") in names or p.get("source") in names)]
    patterns, broken = image_patterns(match)
    listed = [i for i in asset.get("images") or [] if isinstance(i, dict) and isinstance(i.get("image"), str)]
    images = [i for i in listed if any(p.search(i["image"]) for p in patterns)]
    # 보지 못한 경로. 패키지 조건이 있는데 패키지 목록이 없거나, 이미지 조건이 있는데 이미지를 가리지 못했다
    blind_packages, blind_images = [], []
    if names:
        if probe_failed(asset, "packages"):
            blind_packages.append("조사 중 패키지 목록을 읽지 못했다")
        elif asset.get("package_count") == 0:
            blind_packages.append("조사 결과에 패키지 목록이 비어 있다")
    if match.get("images"):
        if probe_failed(asset, "images"):
            blind_images.append("조사 중 컨테이너 이미지 목록을 읽지 못했다")
        # 틀린 식은 읽은 식에 맞지 않은 이미지가 있을 때만 모름이다(이미지가 없으면 무엇에도 맞을 수 없다)
        if broken and len(images) < len(listed):
            blind_images.append("서명의 컨테이너 이미지 조건(정규식)을 읽지 못했다")
    if not packages and not images:
        if blind_packages or blind_images:
            return UNKNOWN, sentences(*blind_packages, *blind_images)
        return NOT_AFFECTED, sentences("자산 표의 패키지 · 컨테이너 이미지에 없다", match.get("note"))

    found = " · ".join([f"{p.get('name')} {p.get('version')}" for p in packages] + [i["image"] for i in images])
    if not signature.get("cves"):
        return AFFECTED, f"{found}가 설치돼 있다. KEV 항목별 버전 대조가 필요하다"
    checked, received = asset.get("checked_at"), asset.get("received_at")
    before_check = checked is not None and received is not None and checked < received
    if before_check:
        # 지난 조사로 대조한 행이다. 그 소스 버전이 지금도 깔려 있을 때만 근거로 쓴다
        installed = {(p.get("source"), p.get("source_version")) for p in packages}
        hits = [h for h in hits if (h["source_package"], h["version"]) in installed]
    if hits:
        return AFFECTED, ", ".join(f"{h['source_package']} {h['version']} · {h['cve_id']} "
                                   f"({FIX_LABELS.get(h['fix_state'], h['fix_state'])})" for h in hits)
    # 배포판 취약점 대조(OSV)는 dpkg 패키지만 본다. 컨테이너 이미지 안은 대조하지 않았으니 비해당이라 할 수 없다
    if images:
        return UNKNOWN, f"{found} 있음 · 컨테이너 이미지 안 패키지는 배포판 취약점 대조 대상이 아니다"
    if checked is None:
        return UNKNOWN, f"{found} 설치됨 · 배포판 취약점 대조 전이다"
    if before_check:
        return UNKNOWN, f"{found} 설치됨 · 이번 조사 뒤 배포판 대조 전이다"
    if is_stale(checked, now):
        return UNKNOWN, f"{found} 설치됨 · 배포판 취약점 대조가 오래됐다 (대조 {kst(checked)}). 비해당으로 보지 않는다"
    verdict = f"{found} 설치됨 · 배포판 기준 이 CVE 에 해당하지 않는다 (대조 {kst(checked)})"
    # 패키지로는 비해당이지만 이미지 쪽을 보지 못했다
    if blind_images:
        return UNKNOWN, sentences(verdict, *blind_images)
    return NOT_AFFECTED, verdict


def applicability(signature: dict, sensors: list, assets: list, vulns: list, now) -> list[dict]:
    """서명 하나를 자산마다 판정한다. 디코이 가상 항목이 맨 앞, 그다음 역할(관제 대상 → 관제 기반 → 센서) · id 순.

    assets 는 asset_inventory 행(os · packages · images 는 풀어 둔 것), vulns 는 서명 CVE 들에 맞은 자산 취약점 행이다.
    요청을 받았는데 자산 표에 없는 자산도 미확인 행으로 넣는다. 빼면 요약이 비해당으로 기운다.
    """
    cves = set(signature.get("cves") or [])
    targeted = {SENSOR_ASSETS.get(s, s) for s in sensors if s != DECOY_SENSOR}
    rows = [dict(DECOY_ENTRY)] if DECOY_SENSOR in sensors else []
    known = {a["asset_id"] for a in assets}
    missing = [{"asset_id": a, "role": MISSING_ROLES.get(a, "target"), "collected_at": None}
               for a in sorted(targeted - known)]
    for asset in sorted([*assets, *missing], key=lambda a: (ROLE_ORDER.get(a["role"], len(ROLE_ORDER)), a["asset_id"])):
        hits = [v for v in vulns if v["asset_id"] == asset["asset_id"] and v["cve_id"] in cves]
        status, reason = judge(signature, asset, hits, now)
        rows.append({"asset_id": asset["asset_id"], "role": asset["role"], "targeted": asset["asset_id"] in targeted,
                     "status": status, "reason": reason, "collected_at": iso(asset["collected_at"])})
    return rows


def summarize(rows: list[dict]) -> str:
    """하나라도 해당이면 해당. 요청을 받은 자산이나 관제 대상 중 미확인이 있으면 미확인. 나머지는 비해당이다.
    요청을 받지 않은 관제 기반 · 센서의 미확인은 요약을 흐리지 않는다. 주목 CVE 행에는 요청 받음(targeted)이 없다."""
    if any(r["status"] == AFFECTED for r in rows):
        return AFFECTED
    if any(r["status"] == UNKNOWN and (r.get("targeted") or r["role"] == "target") for r in rows):
        return UNKNOWN
    return NOT_AFFECTED


def summarize_watch(rows: list[dict], record_found) -> str:
    """주목 CVE 한 행의 요약. 하나라도 해당이면 해당이다. 배포판 기록을 조회하기 전이거나 기록이 없으면 미확인이다.
    관제 대상(role=target) 자산이 판정에 없거나 그중 미확인이 있으면 미확인이다. 모르는 것을 비해당으로 요약하지 않는다."""
    if any(r["status"] == AFFECTED for r in rows):
        return AFFECTED
    if record_found is not True:
        return UNKNOWN
    targets = [r for r in rows if r["role"] == "target"]
    if not targets or any(r["status"] == UNKNOWN for r in targets):
        return UNKNOWN
    return NOT_AFFECTED


def kev_item(row) -> dict:
    return {"cve_id": row["cve_id"], "vendor_project": row["vendor_project"], "product": row["product"],
            "name": row["name"], "date_added": iso(row["date_added"]), "due_date": iso(row["due_date"]),
            "ransomware": row["ransomware"]}


def cve_item(row, signature_ids) -> dict:
    return {
        "cve_id": row["cve_id"], "signature_ids": sorted(signature_ids),
        "kev": {"date_added": iso(row["date_added"]), "due_date": iso(row["due_date"]),
                "ransomware": row["ransomware"], "name": row["name"],
                "vendor_project": row["vendor_project"], "product": row["product"]} if row["in_kev"] else None,
        "cvss": {"score": float(row["cvss_score"]), "version": row["cvss_version"],
                 "vector": row["cvss_vector"], "severity": row["cvss_severity"]}
                if row["cvss_score"] is not None else None,
        "epss": {"score": score(row["epss"]), "percentile": score(row["epss_percentile"]),
                 "date": iso(row["epss_date"])} if row["epss"] is not None else None,
        "description": row["description"], "nvd_fetched_at": iso(row["nvd_fetched_at"]),
    }


def cve_sort_key(item: dict):
    """KEV 에 있는 것 먼저 → EPSS 높은 순(없는 것 뒤) → CVE id."""
    epss = item["epss"]["score"] if item["epss"] else None
    return (item["kev"] is None, epss is None, -(epss or 0.0), item["cve_id"])


# dpkg 버전 비교(dpkg lib/dpkg/version.c 의 verrevcmp 와 같은 규칙). 커널의 재부팅 대기 · 주목 CVE 수정판 비교에 쓴다.
#   '~' 는 끝보다 앞, 글자는 기호보다 앞, 숫자 덩어리는 수로 비교한다. epoch → upstream → revision 순
def _isdigit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _order(ch: str) -> int:
    if ch.isascii() and ch.isalpha():
        return ord(ch)
    if ch == "~":
        return -1
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not _isdigit(a[i])) or (j < len(b) and not _isdigit(b[j])):
            ac = _order(a[i]) if i < len(a) and not _isdigit(a[i]) else 0
            bc = _order(b[j]) if j < len(b) and not _isdigit(b[j]) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and _isdigit(a[i]) and j < len(b) and _isdigit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and _isdigit(a[i]):
            return 1
        if j < len(b) and _isdigit(b[j]):
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(version: str):
    epoch, rest = version.split(":", 1) if ":" in version else ("0", version)
    upstream, revision = rest.rsplit("-", 1) if "-" in rest else (rest, "")
    return int(epoch) if epoch.isdigit() else 0, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """a < b 면 음수, 같으면 0, 크면 양수."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def kernel_flavor(release) -> str | None:
    """커널 릴리스 이름의 판. 6.8.0-139-generic → generic, 6.8.0-1015-aws → aws. 꼴이 다르면 None."""
    found = KERNEL_RELEASE_RE.fullmatch(release) if isinstance(release, str) else None
    return found.group(1) if found else None


def kernel_state(kernel) -> dict:
    """실행 중 커널과 설치된 가장 높은 커널. 둘이 다르면 재부팅 대기다(새 커널이 깔렸지만 아직 옛 커널로 돈다).

    가장 높은 커널은 실행 중인 커널과 같은 판(generic · aws …)의 이미지 중에서만 고른다(계약 10.5). 판이 다르면
    버전 체계가 달라(generic 6.8.0-142.142 · aws 6.8.0-1015.16) 옆 판의 이미지가 늘 '더 새것'으로 보인다.
    실행 중인 커널의 판을 모르면 모든 이미지를 본다."""
    kernel = kernel if isinstance(kernel, dict) else {}
    running = kernel.get("running_version")
    flavor = kernel_flavor(kernel.get("running"))
    installed = []
    for k in kernel.get("installed") or []:
        if not isinstance(k, dict) or not isinstance(k.get("version"), str):
            continue
        package = k.get("package")
        release = package[len(KERNEL_IMAGE_PREFIX):] if isinstance(package, str) and package.startswith(
            KERNEL_IMAGE_PREFIX) else None
        if flavor is None or kernel_flavor(release) == flavor:
            installed.append(k["version"])
    newest = max(installed, key=cmp_to_key(dpkg_compare)) if installed else None
    return {"kernel_running": kernel.get("running"), "kernel_running_version": running,
            "kernel_newest_version": newest, "reboot_pending": bool(newest and running and newest != running)}


def is_kernel_source(name) -> bool:
    """커널 소스 패키지 이름인가(linux · linux-aws · linux-azure-fde · linux-hwe-6.8 …). 공용 스크립트 · 펌웨어 ·
    사용자 공간 헤더처럼 이름만 linux 로 시작하는 것은 아니다."""
    return (isinstance(name, str) and bool(KERNEL_SOURCE_RE.fullmatch(name))
            and name not in NON_KERNEL_SOURCES and not name.startswith("linux-firmware"))


def _kernel_source_name(source) -> str | None:
    """이미지 · 모듈 패키지의 소스 → 커널 소스 이름. 서명 · 메타 소스는 접두를 뗀다
    (linux-signed-aws → linux-aws, linux-meta-aws → linux-aws, linux-signed → linux). 커널 소스가 아니면 None."""
    if not is_kernel_source(source):
        return None
    for prefix in ("linux-signed", "linux-meta"):
        if source == prefix or source.startswith(prefix + "-"):
            return "linux" + source[len(prefix):]
    return source


def kernel_source(kernel, packages) -> str:
    """실행 중인 커널의 배포판 소스 패키지 이름(계약 10.5). 수집기(cti/opsloop_cti.py)와 같은 규칙이다.

    실행 중인 커널 이미지 패키지(kernel.running_package)의 소스를 보고, 없으면 linux-modules-<실행 중 릴리스> 의 소스를
    본다. 서명한 이미지(linux-signed-aws) · 메타(linux-meta-aws)는 커널 소스(linux-aws)로 바꾼다. 못 찾으면 linux 다."""
    kernel = kernel if isinstance(kernel, dict) else {}
    running = kernel.get("running")
    names = [kernel.get("running_package"), f"linux-modules-{running}" if isinstance(running, str) else None]
    for name in names:
        if not isinstance(name, str):
            continue
        for p in packages or []:
            if isinstance(p, dict) and p.get("name") == name:
                source = _kernel_source_name(p.get("source"))
                if source:
                    return source
    return "linux"


def ubuntu_ecosystem(os_info) -> str | None:
    """자산의 OSV 생태계 이름(수집기와 같은 규칙). XX.04 이고 XX 가 짝수면 LTS 다. Ubuntu 가 아니면 None."""
    if not isinstance(os_info, dict) or os_info.get("id") != "ubuntu":
        return None
    version = os_info.get("version_id")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{2}\.[0-9]{2}", version):
        return None
    return f"Ubuntu:{version}:LTS" if version.endswith(".04") and int(version[:2]) % 2 == 0 else f"Ubuntu:{version}"


def affected_entries(affected, ecosystems) -> list[tuple[str, str, str | None]]:
    """배포판 기록의 영향 항목 중 그 생태계들의 것 [(생태계, 패키지, 수정판 또는 None)], 생태계 · 패키지 순."""
    if not isinstance(affected, dict):
        return []
    out = []
    for key, fixed in affected.items():
        ecosystem, _, package = key.rpartition("/")
        if ecosystem in ecosystems and package:
            out.append((ecosystem, package, fixed if isinstance(fixed, str) and fixed else None))
    return sorted(out, key=lambda e: (e[0], e[1]))


def judge_watch(watch: dict, asset: dict, now) -> dict:
    """주목 CVE 하나가 자산 하나에 해당하는지(계약 10.6). 모르는 것은 비해당이 아니라 미확인이다.

    watch 는 {"record_found", "affected"}(cti_watch · cti_osv.affected), asset 은 자산 행(패키지는 걸러 온 것)이다.
    영향 패키지마다 설치 버전(커널 소스면 실행 중인 커널 버전, 아니면 그 소스의 설치 버전 중 가장 낮은 것)과 배포판
    수정판을 dpkg 규칙으로 비교한다. 돌려주는 package · installed · fixed 는 판정을 정한 첫 항목이다(없으면 None).
    """
    def out(status, reason, package=None, installed=None, fixed=None):
        return {"status": status, "reason": reason, "package": package, "installed": installed, "fixed": fixed}

    collected = asset.get("collected_at")
    if collected is None:
        return out(UNKNOWN, "자산 정보가 아직 없다")
    if is_stale(collected, now):
        return out(UNKNOWN, stale_asset_reason(collected))
    record_found = watch.get("record_found")
    if record_found is None:
        return out(UNKNOWN, "배포판 기록을 아직 조회하지 않았다")
    if record_found is False:
        return out(UNKNOWN, "배포판(Ubuntu) 기록이 없다")
    # 기록 조회가 멈춰 옛 기록으로 판정하면, 그사이 배포판이 이 릴리스를 영향 목록에 넣어도 비해당으로 남는다
    checked = watch.get("checked_at")
    if checked is None or is_stale(checked, now):
        return out(UNKNOWN, "배포판 기록 조회가 오래됐다" + (f" (조회 {kst(checked)})" if checked else "")
                   + ". 비해당으로 보지 않는다")
    if not isinstance(watch.get("affected"), dict):
        return out(UNKNOWN, "배포판 기록의 영향 항목을 아직 받지 않았다")
    os_info = asset.get("os")
    ecosystem = ubuntu_ecosystem(os_info)
    if ecosystem is None:
        return out(UNKNOWN, f"{os_name(os_info)} 는 배포판(Ubuntu) 기록으로 대조하지 않는다"
                   if isinstance(os_info, dict) else "운영체제를 알 수 없다")
    entries = [(package, fixed) for _, package, fixed in affected_entries(watch["affected"], [ecosystem])]
    if not entries:
        return out(NOT_AFFECTED, f"배포판 기록에 이 릴리스({os_name(os_info)})의 영향 패키지가 없다")
    if probe_failed(asset, "packages"):
        return out(UNKNOWN, "조사 중 패키지 목록을 읽지 못했다")
    if asset.get("package_count") == 0:
        return out(UNKNOWN, "조사 결과에 패키지 목록이 비어 있다")

    kernel = asset.get("kernel") if isinstance(asset.get("kernel"), dict) else {}
    packages = [p for p in asset.get("packages") or [] if isinstance(p, dict)]
    running_source = kernel_source(kernel, packages)
    running = kernel.get("running_version") if isinstance(kernel.get("running_version"), str) else None
    results = []
    for package, fixed in entries:
        if package == running_source:
            installed = running
            if installed is None:
                results.append((UNKNOWN, f"{package} · 실행 중인 커널 버전을 모른다", package, None, fixed))
                continue
        elif is_kernel_source(package):
            continue    # 다른 판의 커널이다. 이 자산에서 돌지 않는다
        else:
            versions = [p["source_version"] for p in packages
                        if p.get("source") == package and isinstance(p.get("source_version"), str)]
            if not versions:
                continue
            installed = min(versions, key=cmp_to_key(dpkg_compare))
        if fixed is None:
            results.append((AFFECTED, f"{package} {installed} · 배포판 수정판 없음", package, installed, None))
        elif dpkg_compare(installed, fixed) < 0:
            results.append((AFFECTED, f"{package} {installed} < 수정판 {fixed}", package, installed, fixed))
        else:
            results.append((NOT_AFFECTED, f"{package} {installed} ≥ 수정판 {fixed}", package, installed, fixed))
    for status in (AFFECTED, UNKNOWN, NOT_AFFECTED):
        chosen = [r for r in results if r[0] == status]
        if chosen:
            return out(status, ", ".join(r[1] for r in chosen), *chosen[0][2:])
    return out(NOT_AFFECTED, f"영향 패키지({' · '.join(p for p, _ in entries)})가 설치돼 있지 않다")


def watch_item(row, affected, assets: list, ecosystems: list, now) -> dict:
    """주목 CVE 한 행. assets 는 자산 정렬 순(관제 대상 → 관제 기반 → 센서, id)이다.
    affected_packages 는 자산들의 생태계 항목만 보이고, 생태계가 여럿이면 항목마다 생태계를 적는다."""
    watch = {"record_found": row["record_found"], "affected": affected, "checked_at": row["checked_at"]}
    judged = [{"asset_id": a["asset_id"], "role": a["role"], **judge_watch(watch, a, now)} for a in assets]
    many = len(ecosystems) > 1
    return {
        "cve_id": row["cve_id"], "reason": row["reason"], "osv_id": row["osv_id"],
        "record_found": row["record_found"], "checked_at": iso(row["checked_at"]),
        "ubuntu_priority": row["ubuntu_priority"], "description": row["description"],
        "kev": {"date_added": iso(row["kev_date_added"]), "ransomware": row["kev_ransomware"],
                "name": row["kev_name"]} if row["in_kev"] else None,
        "epss": {"score": score(row["epss"]), "percentile": score(row["epss_percentile"]),
                 "date": iso(row["epss_date"])} if row["epss"] is not None else None,
        "cvss": {"score": float(row["cvss_score"]), "severity": row["cvss_severity"]}
                if row["cvss_score"] is not None else None,
        "affected_packages": [{**({"ecosystem": e} if many else {}), "package": p, "fixed": f}
                              for e, p, f in affected_entries(affected, ecosystems)],
        "assets": judged, "summary": summarize_watch(judged, row["record_found"]),
    }


def watch_sort_key(item: dict):
    """해당 먼저 → KEV 에 있는 것 → EPSS 높은 순(없는 것 뒤) → CVE id."""
    epss = item["epss"]["score"] if item["epss"] else None
    return (item["summary"] != AFFECTED, item["kev"] is None, epss is None, -(epss or 0.0), item["cve_id"])


def asset_row(row, now) -> dict:
    """자산 목록의 한 행."""
    os_info = loads(row["os"])
    images = loads(row["images"])
    return {
        "asset_id": row["asset_id"], "role": row["role"], "method": row["method"], "host": row["host"],
        "collected_at": iso(row["collected_at"]), "received_at": iso(row["received_at"]),
        "stale": is_stale(row["collected_at"], now),
        "last_attempt_at": iso(row["last_attempt_at"]), "last_error": row["last_error"],
        "os_pretty": os_info.get("pretty") if isinstance(os_info, dict) else None,
        **kernel_state(loads(row["kernel"])),
        "packages": row["packages"] or 0, "images": len(images) if isinstance(images, list) else 0,
        "checked_at": iso(row["checked_at"]), "check_error": row["check_error"],
        "vuln_total": row["vuln_total"], "vuln_kev": row["vuln_kev"],
        "vuln_fix_available": row["vuln_fix_available"], "vuln_reboot_pending": row["vuln_reboot_pending"],
        "max_epss": score(row["max_epss"]),
    }


def key_packages(rows) -> list[dict]:
    """설치된 주요 패키지를 KEY_PACKAGES 순서로. 같은 이름(여러 아키텍처)은 하나만."""
    first = {}
    for row in rows:
        first.setdefault(row["name"], {"name": row["name"], "version": row["version"]})
    return [first[name] for name in KEY_PACKAGES if name in first]


def vuln_row(row) -> dict:
    return {
        "osv_id": row["osv_id"], "cve_id": row["cve_id"], "source_package": row["source_package"],
        "version": row["version"], "fix_state": row["fix_state"], "fixed_version": row["fixed_version"],
        "kev": {"date_added": iso(row["kev_date_added"]), "ransomware": row["kev_ransomware"],
                "name": row["kev_name"]} if row["in_kev"] else None,
        "epss": {"score": score(row["epss"]), "percentile": score(row["epss_percentile"]),
                 "date": iso(row["epss_date"])} if row["epss"] is not None else None,
        "cvss": {"score": float(row["cvss_score"]), "severity": row["cvss_severity"]}
                if row["cvss_score"] is not None else None,
        "ubuntu_priority": row["ubuntu_priority"], "summary": row["summary"],
    }


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------
#  모두 반복 읽기 · 읽기 전용 트랜잭션 하나에서 읽는다. 수집기가 도중에 표를 바꿔도 한 응답은 한 시점이다.
#  main.py 는 이 라우터를 상세 조회(/api/incidents/{incident_key:path})보다 먼저 붙인다. 뒤에 붙이면 …/cti 가
#  상세 조회의 키로 빨려 들어간다. 주목 CVE 는 /api/assets/{asset_id} 와 겹치지 않게 /api/cti 아래에 둔다.

async def kev_products_for(c, match: dict):
    """서명 kev_match 에 맞는 KEV 항목. 조건 값이 문자열이 아니거나 PostgreSQL 정규식으로 읽을 수 없으면 None 이다.

    규칙 버전 정의는 한 번 들어가면 고칠 수 없으니, 틀린 식 하나로 그 규칙 버전의 모든 사건이 500 이 되지 않게
    그 서명만 KEV 항목을 비우고 나머지 응답은 낸다. 오류가 난 질의는 저장점으로 되돌려 같은 트랜잭션을 이어 쓴다.
    """
    args = [match.get(k) for k in ("vendor", "product", "text")]
    if not isinstance(args[0], str) or any(a is not None and not isinstance(a, str) for a in args[1:]):
        return None
    try:
        async with c.transaction():
            return await c.fetch(KEV_PRODUCTS_SQL, *args)
    except Exception as error:
        if getattr(error, "sqlstate", None) == INVALID_REGEX:
            return None
        raise


@router.get("/api/incidents/{incident_key:path}/cti")
async def incident_cti(incident_key: str, request: Request):
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        inc = await c.fetchrow(INCIDENT_SQL, incident_key)
        if inc is None:
            raise HTTPException(404, "인시던트를 찾을 수 없습니다")
        rule = loads(await c.fetchval(RULE_SQL, inc["rule_version"], inc["rule_id"])) or {}
        evidence = loads(inc["evidence"]) or {}
        by_id = {s.get("id"): s for s in (rule.get("params") or {}).get("signatures") or []}
        signatures = [by_id[s] for s in evidence.get("signatures") or [] if s in by_id]
        # 서명 규칙이 아닌 사건(또는 서명 근거가 없는 사건)에는 붙일 것이 없다. 화면은 구역을 그리지 않는다
        if rule.get("type") != "url_signature" or not signatures:
            return {"as_of": iso(as_of), "incident_key": incident_key, "applicable": False}
        head = {"as_of": iso(as_of), "incident_key": incident_key, "applicable": True,
                "rule_id": inc["rule_id"], "rule_version": inc["rule_version"]}
        if not await c.fetchval(TABLES_SQL, CTI_TABLES):
            return {**head, "available": False}

        snapshots = await c.fetch(SNAPSHOTS_SQL)
        # 서명 id → KEV 항목(kev_match 가 없는 서명은 빠진다. 조건을 읽지 못한 서명은 None)
        kev_products = {}
        for sig in signatures:
            m = sig.get("kev_match")
            if isinstance(m, dict) and m.get("vendor"):
                kev_products[sig["id"]] = await kev_products_for(c, m)
        cve_sigs: dict[str, set] = {}
        for sig in signatures:
            for cve in sig.get("cves") or []:
                cve_sigs.setdefault(cve, set()).add(sig["id"])
            for row in kev_products.get(sig["id"]) or []:
                cve_sigs.setdefault(row["cve_id"], set()).add(sig["id"])
        cve_rows = await c.fetch(CVES_SQL, sorted(cve_sigs))
        wanted = sorted({p for sig in signatures for p in (sig.get("asset_match") or {}).get("packages") or []})
        assets = [{**dict(r), "os": loads(r["os"]), "images": loads(r["images"]), "packages": loads(r["packages"]),
                   "probe_errors": loads(r["probe_errors"])}
                  for r in await c.fetch(APPLICABILITY_ASSETS_SQL, wanted)]
        sig_cves = sorted({cve for sig in signatures for cve in sig.get("cves") or []})
        vulns = [dict(r) for r in await c.fetch(VULN_HITS_SQL, sig_cves)] if sig_cves else []

    sensors = [s for s in evidence.get("sensors") or [] if isinstance(s, str)]
    out = []
    for sig in signatures:
        rows = applicability(sig, sensors, assets, vulns, as_of)
        kev = kev_products.get(sig["id"])
        out.append({"id": sig["id"], "product": sig.get("product"), "vendor": sig.get("vendor"),
                    "mapping": sig.get("mapping"), "source": sig.get("source"), "methods": sig.get("methods"),
                    "cves": sig.get("cves") or [],
                    "kev_products": [kev_item(r) for r in kev] if kev is not None else None,
                    "applicability": rows, "summary": summarize(rows)})
    fresh = freshness(snapshots, assets, as_of)
    return {**head, "available": True, "stale": any_stale(fresh), "freshness": fresh, "signatures": out,
            "cves": sorted((cve_item(r, cve_sigs[r["cve_id"]]) for r in cve_rows), key=cve_sort_key)}


@router.get("/api/cti/watch")
async def watch_list(request: Request):
    """주목 CVE(cti/watchlist.json) 대조. 자산마다 설치 버전과 배포판 수정판을 비교해 해당 여부를 보인다.
    asset_vulnerabilities 는 걸린 것만 담으므로 이미 고쳐진(비해당) CVE 의 근거는 여기서 나온다."""
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        if not await c.fetchval(TABLES_SQL, WATCH_TABLES):
            return {"as_of": iso(as_of), "available": False, "freshness": None, "rows": []}
        snapshots = await c.fetch(SNAPSHOTS_SQL)
        watch = await c.fetch(WATCH_SQL)
        affected = {r["cve_id"]: loads(r["affected"]) for r in watch}
        wanted = sorted({key.rpartition("/")[2] for a in affected.values() if isinstance(a, dict) for key in a} - {""})
        assets = [{**dict(r), "os": loads(r["os"]), "kernel": loads(r["kernel"]), "packages": loads(r["packages"]),
                   "probe_errors": loads(r["probe_errors"])}
                  for r in await c.fetch(WATCH_ASSETS_SQL, wanted)]
    ecosystems = sorted({e for e in (ubuntu_ecosystem(a["os"]) for a in assets) if e})
    rows = [watch_item(r, affected[r["cve_id"]] if r["detailed"] else None, assets, ecosystems, as_of) for r in watch]
    return {"as_of": iso(as_of), "available": True, "freshness": freshness(snapshots, assets, as_of),
            "rows": sorted(rows, key=watch_sort_key)}


@router.get("/api/assets")
async def assets_list(request: Request):
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        if not await c.fetchval(TABLES_SQL, CTI_TABLES):
            return {"as_of": iso(as_of), "available": False, "freshness": None, "rows": []}
        snapshots = await c.fetch(SNAPSHOTS_SQL)
        rows = await c.fetch(ASSETS_SQL, None)
    return {"as_of": iso(as_of), "available": True, "freshness": freshness(snapshots, rows, as_of),
            "rows": [asset_row(r, as_of) for r in rows]}


@router.get("/api/assets/{asset_id}")
async def asset_detail(request: Request,
                       asset_id: str = Path(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$"),
                       vuln_filter: Literal["all", "kev", "fix"] = Query("all", alias="filter"),
                       limit: int = Query(50, ge=1, le=200),
                       offset: int = Query(0, ge=0, le=MAX_OFFSET)):
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        if not await c.fetchval(TABLES_SQL, CTI_TABLES):
            return {"as_of": iso(as_of), "available": False, "asset": None, "vulnerabilities": None,
                    "freshness": None}
        row = await c.fetchrow(ASSETS_SQL, asset_id)
        if row is None:
            raise HTTPException(404, "자산 정보를 찾을 수 없습니다")
        snapshots = await c.fetch(SNAPSHOTS_SQL)
        # 신선도의 자산 부분은 목록과 같게 전체 자산으로 센다(어느 화면에서 보든 같은 값)
        everyone = await c.fetch(ASSET_TIMES_SQL)
        keys = await c.fetch(KEY_PACKAGES_SQL, asset_id, KEY_PACKAGES)
        total = await c.fetchval(VULN_COUNT_SQL, asset_id, vuln_filter)
        vulns = await c.fetch(VULNS_SQL, asset_id, vuln_filter, limit, offset)
    asset = {**asset_row(row, as_of), "os": loads(row["os"]), "kernel": loads(row["kernel"]),
             "images": loads(row["images"]), "probe_errors": loads(row["probe_errors"]),
             "key_packages": key_packages(keys)}
    return {"as_of": iso(as_of), "available": True, "asset": asset,
            "vulnerabilities": {"rows": [vuln_row(r) for r in vulns], "total": total, "limit": limit,
                                "offset": offset, "filter": vuln_filter},
            "freshness": freshness(snapshots, everyone, as_of)}
