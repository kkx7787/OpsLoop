"""CVE · KEV 연계 조회(cti.py)의 PostgreSQL 시험.  OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app -p 'test_cti_db.py'

연결 전용 임시 표만 쓰고 search_path=pg_temp 로 운영 표를 가린다. CTI 표는 마이그레이션(20260925_cti.sql)의 표 정의를
그대로 임시 스키마에 적용한다. 권한 블록(DO $$ … $$)은 공유 시험 DB 의 역할에 닿으므로 빼고 적용한다.

  - 사건: KEV · EPSS · CVSS 결합 · CVE 정렬 · kev_match 로 고른 KEV 항목(설명까지 보는 text 조건) ·
    적용 판정(해당: 배포판 취약점 행 · CVE 없는 서명의 이미지 / 비해당: 없음 · 배포판 기준 / 미확인: 오래됨 · 수집 전 ·
    조사가 목록을 못 읽음(probe_errors) · 대조가 이번 조사보다 앞섬) · 디코이 가상 항목 · 요약 ·
    신선도(실패 회차 제외 · osv 오래됨 · NVD 예외) · 적용 대상 아님 · 없는 키 404 ·
    PG 에서 틀린 kev_match 정규식(그 서명만 kev_products=null, 저장점 뒤 같은 트랜잭션으로 나머지 서명) · 틀린 이미지 정규식
  - 자산 목록: 정렬 · 취약점 집계(KEV · 수정판 · 재부팅 대기 · 최고 EPSS) · 커널 재부팅 대기 · 오래됨
  - 자산 상세: 주요 패키지 · 필터(kev · fix) · 쪽 · 정렬 · 없는 자산 404 · offset 상한 ·
    같은 osv_id 가 소스 패키지 여럿에 걸린 행의 쪽 넘김(겹침 · 빠짐 없음)
  - 주목 CVE: 비해당(설치 ≥ 수정판) · 해당(설치 < 수정판) · 수정판 없음(커널, AWS 커널은 linux-aws) · 기록 없음 ·
    이 릴리스 항목 없음 · 미설치(다른 판 커널 포함) · 상세 없는 기록 · 오래된 자산 · 수집 전 · 빈 패키지 목록 · 정렬 · 요약 ·
    설명(NVD → OSV) · cti_watch 가 없으면 available=false
  - 표가 없는 DB: available=false (사건은 적용 대상 여부와 404 를 그대로 가린다)
"""
import json
import os
import unittest
from contextlib import asynccontextmanager
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException

import cti

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "infra" / "migrations" / "20260925_cti.sql"
RULES_CVE = ROOT / "detector" / "rules_cve.json"

K106 = "R106|c1|192.0.2.10|2026-09-25T00:00:00+00:00"
K105 = "R105|c1|198.51.100.7|2026-09-25T01:00:00+00:00"
K_NOSIG = "R105|c1|198.51.100.8|2026-09-25T02:00:00+00:00"
K_OTHER = "R101|w2|203.0.113.5|2026-09-25T02:00:00+00:00"
K_BADRE = "R105|c9|198.51.100.9|2026-09-25T02:30:00+00:00"
UBUNTU = {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "pretty": "Ubuntu 24.04.5 LTS"}
BASE_TABLES = """
    CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_version text NOT NULL,
        rule_name text, severity text, actor_ip inet, target text, first_ts timestamptz, last_ts timestamptz,
        signal_count integer, session_count integer, evidence jsonb, status text DEFAULT 'open',
        created_at timestamptz DEFAULT now());
    CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
"""


def migration_tables() -> str:
    """마이그레이션의 표 · 색인 정의(BEGIN; 뒤 ~ 권한 블록 앞). 트랜잭션은 시험 연결이 따로 둔다."""
    body = MIGRATION.read_text().split("BEGIN;", 1)[1]
    return body.split("\nDO $$", 1)[0]


def request_for(pool):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=pool)),
                           state=SimpleNamespace(user={"u": "tester", "r": "viewer"}))


class Base(unittest.IsolatedAsyncioTestCase):
    with_cti = True

    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute(BASE_TABLES)
        if self.with_cti:
            await self.conn.execute(migration_tables())
        broken = json.loads(RULES_CVE.read_text())
        for rule in broken["rules"]:
            for sig in rule["params"]["signatures"]:
                if sig["id"] == "geoserver":
                    # 파이썬 re 로는 맞고 PostgreSQL 정규식으로는 틀린 식 · 파이썬 re 로 틀린 이미지 식
                    sig["kev_match"]["vendor"] = "^(?P<v>OSGeo)$"
                    sig["asset_match"]["images"] = ["("]
        await self.conn.execute("INSERT INTO rule_versions VALUES ('c1', $1::jsonb), ('w2', $2::jsonb), ('c9', $3::jsonb)",
                                RULES_CVE.read_text(),
                                json.dumps({"rules": [{"id": "R101", "type": "actor_rate", "params": {}}]}),
                                json.dumps(broken))
        self.now = await self.conn.fetchval("SELECT now()")
        for key, rule, version, evidence in [
                (K106, "R106", "c1", {"sample": ["/cgi-bin/.%2e/.%2e/bin/sh"], "sessions": [],
                                      "signatures": ["apache-path-traversal", "phpunit-eval-stdin"],
                                      "sensors": ["decoy", "web-01"]}),
                (K105, "R105", "c1", {"sample": ["/geoserver/web/"], "signatures": ["geoserver"],
                                      "sensors": ["web-01"]}),
                (K_NOSIG, "R105", "c1", {"sample": ["/geoserver/web/"]}),
                (K_BADRE, "R105", "c9", {"signatures": ["geoserver", "exchange-owa"], "sensors": ["web-01"]}),
                (K_OTHER, "R101", "w2", {"signatures": ["geoserver"], "sensors": ["web-01"]})]:
            await self.conn.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, evidence)
                VALUES ($1, $2, $3, $4::jsonb)""", key, rule, version, json.dumps(evidence))
        self.request = request_for(SimpleNamespace(acquire=self.acquire))

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class CtiDatabaseTests(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        now, h = self.now, lambda n: self.now - timedelta(hours=n)
        snap = {}
        for source, fetched, status in [("kev", h(2), "ok"), ("kev", h(1), "failed"), ("epss", h(3), "ok"),
                                        ("osv", h(60), "ok"), ("nvd", h(24 * 30), "ok"), ("assets", h(1), "ok")]:
            ok = status == "ok"
            snap[(source, status)] = await self.conn.fetchval("""
                INSERT INTO cti_snapshots (source, fetched_at, source_ts, source_version, s3_key, sha256, bytes,
                    records, status, error)
                VALUES ($1, $2, $3, $4, $5, $6, 10, 1, $7, $8) RETURNING id""",
                source, fetched, fetched - timedelta(hours=6), "2026.09.23" if source == "kev" else None,
                f"cti/v1/source={source}/date=2026-09-25/0123456789abcdef.json" if ok else None,
                "a" * 64 if ok else None, status, None if ok else "S3 쓰기 실패")
        kev, epss, osv, assets = (snap[("kev", "ok")], snap[("epss", "ok")], snap[("osv", "ok")],
                                  snap[("assets", "ok")])
        self.kev_fetched, self.osv_fetched = h(2), h(60)
        for row in [("CVE-2021-41773", "Apache", "HTTP Server", "Apache HTTP Server Path Traversal Vulnerability",
                     "경로 조작", date(2021, 11, 3), date(2021, 11, 17), "Known"),
                    ("CVE-2017-9841", "PHPUnit", "PHPUnit", "PHPUnit Command Injection Vulnerability", None,
                     date(2022, 2, 15), date(2022, 8, 15), "Unknown"),
                    ("CVE-2022-24816", "OSGeo", "JAI-EXT", "OSGeo JAI-EXT Code Injection Vulnerability",
                     "GeoServer 가 쓰는 JAI-EXT 의 코드 주입", date(2023, 4, 24), date(2023, 5, 15), "Unknown"),
                    ("CVE-2024-36401", "OSGeo", "GeoServer", "OSGeo GeoServer Eval Injection Vulnerability", None,
                     date(2024, 7, 15), date(2024, 8, 5), "Unknown"),
                    ("CVE-2023-99999", "OSGeo", "MapServer", "OSGeo MapServer 시험 항목", "다른 제품",
                     date(2025, 1, 1), None, "Unknown"),
                    ("CVE-2024-1086", "Linux", "Kernel", "Linux Kernel Use-After-Free Vulnerability", None,
                     date(2024, 5, 30), date(2024, 6, 20), "Known"),
                    ("CVE-2026-53266", "Linux", "Kernel", "Linux Kernel ebtables 시험 항목", None,
                     date(2026, 9, 18), date(2026, 10, 9), "Unknown"),
                    ("CVE-2023-21709", "Microsoft", "Exchange Server", "Microsoft Exchange Server 시험 항목", None,
                     date(2023, 8, 8), None, "Unknown")]:
            await self.conn.execute("""INSERT INTO cti_kev (cve_id, vendor_project, product, name, description,
                date_added, due_date, ransomware, snapshot_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""", *row, kev)
        for cve, score, pct, cvss, desc in [("CVE-2021-41773", 0.9442, 0.99967, "7.5", "NVD 설명"),
                                            ("CVE-2021-42013", 0.943, 0.9996, None, None),
                                            ("CVE-2017-9841", 0.94, 0.9995, "9.8", None),
                                            ("CVE-2022-24816", 0.9, 0.99, None, None),
                                            ("CVE-2024-36401", 0.95, 0.999, None, None),
                                            ("CVE-2024-1086", 0.8, 0.98, None, None),
                                            ("CVE-2026-82474", 0.001, 0.2, None, None),
                                            ("CVE-2024-6387", 0.99506, 0.99944, None, None),
                                            ("CVE-2026-53266", 0.01, 0.5, None, "NVD 커널 설명"),
                                            ("CVE-2024-3094", 0.85, 0.99, None, None),
                                            ("CVE-2023-4911", 0.7, 0.98, None, None)]:
            await self.conn.execute("""INSERT INTO cti_cve (cve_id, epss, epss_percentile, epss_date, epss_snapshot_id,
                cvss_score, cvss_version, cvss_vector, cvss_severity, description, nvd_fetched_at)
                VALUES ($1, $2, $3, '2026-09-24', $4, $5::numeric, $6, $7, $8, $9, $10)""",
                cve, score, pct, epss, cvss, "3.1" if cvss else None, "CVSS:3.1/AV:N" if cvss else None,
                "HIGH" if cvss else None, desc, h(24 * 30) if cvss else None)
        for osv_id, cve, prio, detailed in [("UBUNTU-CVE-2017-9841", "CVE-2017-9841", "medium", True),
                                            ("UBUNTU-CVE-2024-1086", "CVE-2024-1086", "high", True),
                                            ("UBUNTU-CVE-2026-82474", "CVE-2026-82474", "low", True),
                                            ("UBUNTU-CVE-2024-11111", "CVE-2024-11111", None, False),
                                            ("UBUNTU-CVE-2024-22222", "CVE-2024-22222", None, False)]:
            await self.conn.execute("""INSERT INTO cti_osv (osv_id, cve_id, detailed, ubuntu_priority, summary,
                snapshot_id) VALUES ($1, $2, $3, $4, $5, $6)""", osv_id, cve, detailed, prio,
                f"{osv_id} 요약" if detailed else None, osv)
        # 주목 CVE 의 배포판 기록(affected: 생태계/패키지 → 수정판 또는 null)
        await self.conn.execute("""UPDATE cti_osv SET affected = '{"Ubuntu:24.04:LTS/linux-azure-fde": null}'
            WHERE osv_id = 'UBUNTU-CVE-2024-1086'""")
        for osv_id, prio, summary, affected in [
                ("UBUNTU-CVE-2024-6387", "high", "regreSSHion 요약",
                 {"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3", "Ubuntu:22.04:LTS/openssh": "1:8.9p1-3ubuntu0.10"}),
                ("UBUNTU-CVE-2026-53266", "medium", "커널 OSV 요약",
                 {"Ubuntu:24.04:LTS/linux": None, "Ubuntu:24.04:LTS/linux-aws": None}),
                ("UBUNTU-CVE-2024-3094", "critical", "xz 요약", {"Ubuntu:24.04:LTS/xz-utils": "5.4.5-0.3"}),
                ("UBUNTU-CVE-2021-3156", "high", "sudo 요약", {"Ubuntu:20.04:LTS/sudo": "1.8.31-1ubuntu1.2"}),
                ("UBUNTU-CVE-2023-4911", "high", "glibc 요약", {"Ubuntu:24.04:LTS/glibc": "2.38-1ubuntu6"})]:
            await self.conn.execute("""INSERT INTO cti_osv (osv_id, cve_id, detailed, ubuntu_priority, summary, fixed,
                affected, snapshot_id) VALUES ($1, $2, true, $3, $4, $5::jsonb, $6::jsonb, $7)""",
                osv_id, osv_id[len("UBUNTU-"):], prio, summary,
                json.dumps({k: v for k, v in affected.items() if v}), json.dumps(affected), osv)
        for cve, osv_id, found in [("CVE-2024-6387", "UBUNTU-CVE-2024-6387", True),
                                   ("CVE-2026-53266", "UBUNTU-CVE-2026-53266", True),
                                   ("CVE-2024-3094", "UBUNTU-CVE-2024-3094", True),
                                   ("CVE-2021-3156", "UBUNTU-CVE-2021-3156", True),
                                   ("CVE-2023-4911", "UBUNTU-CVE-2023-4911", True),
                                   ("CVE-2024-1086", "UBUNTU-CVE-2024-1086", True),
                                   ("CVE-2021-4034", None, False),
                                   ("CVE-2024-11111", "UBUNTU-CVE-2024-11111", True)]:   # 상세를 받지 않은 기록
            await self.conn.execute("""INSERT INTO cti_watch (cve_id, reason, osv_id, record_found, checked_at,
                snapshot_id) VALUES ($1, $2, $3, $4, $5, $6)""", cve, f"{cve} 시험", osv_id, found, h(3), osv)

        def pkg(name, version, source=None):
            return {"name": name, "version": version, "source": source or name, "source_version": version,
                    "arch": "amd64"}
        kernel = {"running": "6.8.0-139-generic", "running_package": "linux-image-6.8.0-139-generic",
                  "running_version": "6.8.0-139.139",
                  "installed": [{"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"}]}
        fw_kernel = dict(kernel, installed=kernel["installed"] + [{"package": "linux-image-6.8.0-142-generic",
                                                                   "version": "6.8.0-142.142"}])
        web_packages = [pkg("nginx", "1.24.0-2ubuntu7.18"), pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh"),
                        pkg("phpunit", "9.6.17-1"), pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2"),
                        pkg("libc6", "2.39-0ubuntu8.6", "glibc"), dict(pkg("libc6", "2.39-0ubuntu8.6", "glibc"), arch="i386"),
                        pkg("linux-image-6.8.0-139-generic", "6.8.0-139.139", "linux-signed")]
        self.times = {"web-01": h(1), "fw": h(2), "data-01": h(1), "console-a": h(72), "console-b": None,
                      "honeypot-dmz": h(1)}
        for asset_id, role, method, host, packages, images, k in [
                ("web-01", "target", "ssh", "opsloop-web-01", web_packages, [], kernel),
                ("fw", "platform", "ssh", "opsloop-fw",
                 [pkg("haproxy", "2.8.16-0ubuntu0.24.04.3"), pkg("sudo", "1.9.15p5-3ubuntu5.24.04.3"),
                  pkg("libc6", "2.38-1ubuntu5", "glibc")], [], fw_kernel),
                ("data-01", "platform", "ssh", "opsloop-data-01", [pkg("apache2", "2.4.58-1ubuntu8.4")],
                 [{"container": "opsloop-db", "image": "postgres:16-alpine", "image_id": "sha256:1"},
                  {"container": "geo", "image": "docker.osgeo.org/geoserver:2.25.2", "image_id": "sha256:2"}], kernel),
                ("console-a", "platform", "ssh", "opsloop-console-a", [pkg("apache2", "2.4.58-1ubuntu8.4")], [], kernel),
                ("honeypot-dmz", "sensor", "ssm", "i-0123456789abcdef0", [], [], kernel)]:
            await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, host, collected_at,
                received_at, os, kernel, packages, images, snapshot_id, checked_at, check_snapshot_id)
                VALUES ($1, $2, $3, $4, $5, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10, $5, $11)""",
                asset_id, role, method, host, self.times[asset_id], json.dumps(UBUNTU), json.dumps(k),
                json.dumps(packages), json.dumps(images), assets, osv)
        await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, last_error)
            VALUES ('console-b', 'platform', 'ssh', '연결 실패: 시험')""")
        for row in [("web-01", "phpunit", "9.6.17-1", "UBUNTU-CVE-2017-9841", "CVE-2017-9841", "fix_available",
                     "9.6.17-1ubuntu0.1"),
                    ("fw", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-1086", "CVE-2024-1086", "reboot_pending",
                     "6.8.0-142.142"),
                    ("fw", "sudo", "1.9.15p5-3ubuntu5.24.04.3", "UBUNTU-CVE-2026-82474", "CVE-2026-82474",
                     "fix_available", "1.9.15p5-3ubuntu5.24.04.4"),
                    ("fw", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-22222", "CVE-2024-22222", "unknown", None),
                    ("fw", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-11111", "CVE-2024-11111", "no_fix", None)]:
            await self.conn.execute("""INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id,
                cve_id, fix_state, fixed_version, snapshot_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""", *row, osv)

    # ------------------------------------------------------------ 사건

    async def test_공격_시도_사건에_KEV_EPSS_와_적용_판정을_붙인다(self):
        body = await cti.incident_cti(K106, self.request)
        self.assertEqual((body["incident_key"], body["applicable"], body["available"], body["rule_id"],
                          body["rule_version"]), (K106, True, True, "R106", "c1"))
        sigs = {s["id"]: s for s in body["signatures"]}
        self.assertEqual([s["id"] for s in body["signatures"]], ["apache-path-traversal", "phpunit-eval-stdin"])
        apache, phpunit = sigs["apache-path-traversal"], sigs["phpunit-eval-stdin"]
        self.assertEqual((apache["cves"], apache["kev_products"], apache["methods"], apache["mapping"]),
                         (["CVE-2021-41773", "CVE-2021-42013"], None, None, "analyst"))

        rows = apache["applicability"]
        self.assertEqual([r["asset_id"] for r in rows],
                         ["web-decoy", "web-01", "console-a", "console-b", "data-01", "fw", "honeypot-dmz"])
        by_id = {r["asset_id"]: r for r in rows}
        self.assertEqual([r["asset_id"] for r in rows if r["targeted"]], ["web-decoy", "web-01"])
        self.assertEqual(by_id["web-01"]["status"], "not_affected")
        self.assertEqual(by_id["web-01"]["reason"], "자산 표의 패키지 · 컨테이너 이미지에 없다")
        checked = cti.kst(self.times["data-01"])
        self.assertEqual((by_id["data-01"]["status"], by_id["data-01"]["reason"]),
                         ("not_affected", f"apache2 2.4.58-1ubuntu8.4 설치됨 · 배포판 기준 이 CVE 에 해당하지 않는다 (대조 {checked})"))
        self.assertEqual(by_id["console-a"]["status"], "unknown")
        self.assertIn(f"마지막 수집 {cti.kst(self.times['console-a'])}", by_id["console-a"]["reason"])
        self.assertEqual((by_id["console-b"]["status"], by_id["console-b"]["reason"], by_id["console-b"]["collected_at"]),
                         ("unknown", "자산 정보가 아직 없다", None))
        # 미확인은 요청을 받지 않은 관제 기반뿐이라 요약은 비해당이다
        self.assertEqual(apache["summary"], "not_affected")

        web = next(r for r in phpunit["applicability"] if r["asset_id"] == "web-01")
        self.assertEqual((web["status"], web["reason"]), ("affected", "phpunit 9.6.17-1 · CVE-2017-9841 (수정판 있음)"))
        self.assertEqual(phpunit["summary"], "affected")
        data = next(r for r in phpunit["applicability"] if r["asset_id"] == "data-01")
        self.assertTrue(data["reason"].startswith("자산 표의 패키지 · 컨테이너 이미지에 없다. composer"))

        cves = body["cves"]
        self.assertEqual([c["cve_id"] for c in cves], ["CVE-2021-41773", "CVE-2017-9841", "CVE-2021-42013"])
        first = cves[0]
        self.assertEqual(first["signature_ids"], ["apache-path-traversal"])
        self.assertEqual(first["kev"], {"date_added": "2021-11-03", "due_date": "2021-11-17", "ransomware": "Known",
                                        "name": "Apache HTTP Server Path Traversal Vulnerability",
                                        "vendor_project": "Apache", "product": "HTTP Server"})
        self.assertEqual(first["epss"], {"score": 0.9442, "percentile": 0.99967, "date": "2026-09-24"})
        self.assertEqual(first["cvss"], {"score": 7.5, "version": "3.1", "vector": "CVSS:3.1/AV:N", "severity": "HIGH"})
        self.assertEqual(first["description"], "NVD 설명")
        self.assertEqual((cves[2]["kev"], cves[2]["cvss"], cves[2]["description"]), (None, None, None))
        self.assertEqual(cves[1]["description"], None)
        json.dumps(body)   # 응답은 그대로 JSON 이 된다(시각 · 날짜는 문자열)

    async def test_신선도는_마지막_성공_회차로_본다(self):
        body = await cti.incident_cti(K106, self.request)
        fresh = body["freshness"]
        self.assertEqual(fresh["kev"]["fetched_at"], cti.iso(self.kev_fetched))   # 더 새 실패 회차는 빼고
        self.assertFalse(fresh["kev"]["stale"])
        self.assertFalse(fresh["epss"]["stale"])
        self.assertEqual((fresh["osv"]["fetched_at"], fresh["osv"]["stale"]), (cti.iso(self.osv_fetched), True))
        self.assertFalse(fresh["nvd"]["stale"])
        self.assertTrue(body["stale"])
        self.assertEqual(fresh["assets"], {"oldest_collected_at": cti.iso(self.times["console-a"]),
                                           "stale_assets": ["console-a", "console-b"]})

    async def test_제품_식별_탐색은_kev_match_로_KEV_항목을_고른다(self):
        body = await cti.incident_cti(K105, self.request)
        [geo] = body["signatures"]
        self.assertEqual([k["cve_id"] for k in geo["kev_products"]], ["CVE-2024-36401", "CVE-2022-24816"])
        self.assertEqual(geo["kev_products"][1], {"cve_id": "CVE-2022-24816", "vendor_project": "OSGeo",
                                                  "product": "JAI-EXT",
                                                  "name": "OSGeo JAI-EXT Code Injection Vulnerability",
                                                  "date_added": "2023-04-24", "due_date": "2023-05-15",
                                                  "ransomware": "Unknown"})
        self.assertEqual([(c["cve_id"], c["signature_ids"]) for c in body["cves"]],
                         [("CVE-2024-36401", ["geoserver"]), ("CVE-2022-24816", ["geoserver"])])
        by_id = {r["asset_id"]: r for r in geo["applicability"]}
        self.assertNotIn("web-decoy", by_id)
        self.assertEqual((by_id["data-01"]["status"], by_id["data-01"]["reason"]),
                         ("affected", "docker.osgeo.org/geoserver:2.25.2가 설치돼 있다. KEV 항목별 버전 대조가 필요하다"))
        self.assertEqual(by_id["web-01"]["status"], "not_affected")
        self.assertEqual(geo["summary"], "affected")
        # 이미지 판정이 사라지면 요청을 받은 web-01 이 비해당이라 요약도 비해당이다
        await self.conn.execute("UPDATE asset_inventory SET images = '[]' WHERE asset_id = 'data-01'")
        self.assertEqual((await cti.incident_cti(K105, self.request))["signatures"][0]["summary"], "not_affected")
        # 요청을 받은 web-01 의 정보가 오래되면 미확인이다
        await self.conn.execute("UPDATE asset_inventory SET collected_at = now() - interval '3 days' "
                                "WHERE asset_id = 'web-01'")
        self.assertEqual((await cti.incident_cti(K105, self.request))["signatures"][0]["summary"], "unknown")

    async def test_조사가_목록을_못_읽은_자산은_비해당이_아니라_미확인이다(self):
        # dpkg-query 가 실패하고 sudo 가 암호를 물어 두 목록이 빈 채로 적재됐다(적재기는 받는다)
        await self.conn.execute("""UPDATE asset_inventory SET packages = '[]', images = '[]',
            probe_errors = '["packages: dpkg-query -W -f: 종료 2", "images: sudo -n docker: 종료 1 sudo: a password is required"]'
            WHERE asset_id = 'web-01'""")
        body = await cti.incident_cti(K106, self.request)
        apache = next(s for s in body["signatures"] if s["id"] == "apache-path-traversal")
        web = next(r for r in apache["applicability"] if r["asset_id"] == "web-01")
        self.assertEqual((web["status"], web["reason"]),
                         ("unknown", "조사 중 패키지 목록을 읽지 못했다. 조사 중 컨테이너 이미지 목록을 읽지 못했다"))
        self.assertEqual(apache["summary"], "unknown")   # 요청을 받은 자산이 미확인이다
        [geo] = (await cti.incident_cti(K105, self.request))["signatures"]
        web = next(r for r in geo["applicability"] if r["asset_id"] == "web-01")
        self.assertEqual((web["status"], web["reason"]), ("unknown", "조사 중 컨테이너 이미지 목록을 읽지 못했다"))
        # 패키지 목록이 빈 센서(오류 없음)도 '설치 안 됨'이 아니라 미확인이다. 요청을 받지 않아 요약은 흐리지 않는다
        dmz = next(r for r in apache["applicability"] if r["asset_id"] == "honeypot-dmz")
        self.assertEqual((dmz["status"], dmz["reason"]), ("unknown", "조사 결과에 패키지 목록이 비어 있다"))

    async def test_대조가_이번_조사보다_앞선_자산은_미확인이다(self):
        # 새 조사(received_at)는 들어왔는데 그 뒤 배포판 대조가 실패해 checked_at 은 30시간 전 그대로다
        await self.conn.execute("""UPDATE asset_inventory SET checked_at = received_at - interval '30 hours'
            WHERE asset_id = 'data-01'""")
        body = await cti.incident_cti(K106, self.request)
        apache = next(s for s in body["signatures"] if s["id"] == "apache-path-traversal")
        data = next(r for r in apache["applicability"] if r["asset_id"] == "data-01")
        self.assertEqual((data["status"], data["reason"]),
                         ("unknown", "apache2 2.4.58-1ubuntu8.4 설치됨 · 이번 조사 뒤 배포판 대조 전이다"))
        # 대조가 조사 뒤면(같은 적재에서 이어 대조) 그대로 배포판 기준 비해당이다
        await self.conn.execute("""UPDATE asset_inventory SET checked_at = received_at + interval '1 second'
            WHERE asset_id = 'data-01'""")
        body = await cti.incident_cti(K106, self.request)
        apache = next(s for s in body["signatures"] if s["id"] == "apache-path-traversal")
        self.assertEqual(next(r for r in apache["applicability"] if r["asset_id"] == "data-01")["status"],
                         "not_affected")

    async def test_PG_에서_틀린_kev_match_는_그_서명만_KEV_항목을_비운다(self):
        body = await cti.incident_cti(K_BADRE, self.request)
        self.assertEqual((body["available"], body["rule_version"]), (True, "c9"))
        sigs = {s["id"]: s for s in body["signatures"]}
        self.assertIsNone(sigs["geoserver"]["kev_products"])
        # 저장점으로 되돌린 뒤 같은 트랜잭션에서 다음 서명의 KEV 질의가 돈다
        self.assertEqual([k["cve_id"] for k in sigs["exchange-owa"]["kev_products"]], ["CVE-2023-21709"])
        self.assertEqual([(c["cve_id"], c["signature_ids"]) for c in body["cves"]],
                         [("CVE-2023-21709", ["exchange-owa"])])
        # 이미지 정규식도 틀렸다. 이미지가 있는 자산은 모름, 이미지가 없는 자산은 맞을 것이 없다
        geo = {r["asset_id"]: r for r in sigs["geoserver"]["applicability"]}
        self.assertEqual((geo["data-01"]["status"], geo["data-01"]["reason"]),
                         ("unknown", "서명의 컨테이너 이미지 조건(정규식)을 읽지 못했다"))
        self.assertEqual(geo["web-01"]["status"], "not_affected")
        json.dumps(body)

    async def test_적용_대상이_아닌_사건과_없는_사건(self):
        for key in (K_NOSIG, K_OTHER):
            with self.subTest(key=key):
                body = await cti.incident_cti(key, self.request)
                self.assertEqual((body["incident_key"], body["applicable"]), (key, False))
                self.assertNotIn("signatures", body)
        with self.assertRaises(HTTPException) as error:
            await cti.incident_cti("R106|c1|192.0.2.99|없음", self.request)
        self.assertEqual((error.exception.status_code, error.exception.detail), (404, "인시던트를 찾을 수 없습니다"))

    # ------------------------------------------------------------ 자산

    async def test_자산_목록은_역할_순이고_취약점을_집계한다(self):
        body = await cti.assets_list(self.request)
        self.assertTrue(body["available"])
        rows = {r["asset_id"]: r for r in body["rows"]}
        self.assertEqual([r["asset_id"] for r in body["rows"]],
                         ["web-01", "console-a", "console-b", "data-01", "fw", "honeypot-dmz"])
        fw = rows["fw"]
        self.assertEqual((fw["vuln_total"], fw["vuln_kev"], fw["vuln_fix_available"], fw["vuln_reboot_pending"],
                          fw["max_epss"]), (4, 1, 1, 1, 0.8))
        self.assertEqual((fw["reboot_pending"], fw["kernel_running_version"], fw["kernel_newest_version"],
                          fw["kernel_running"]), (True, "6.8.0-139.139", "6.8.0-142.142", "6.8.0-139-generic"))
        web = rows["web-01"]
        self.assertEqual((web["packages"], web["images"], web["vuln_total"], web["vuln_kev"], web["max_epss"],
                          web["reboot_pending"], web["os_pretty"], web["stale"]),
                         (7, 0, 1, 1, 0.94, False, "Ubuntu 24.04.5 LTS", False))
        self.assertEqual((rows["data-01"]["images"], rows["data-01"]["vuln_total"], rows["data-01"]["max_epss"]),
                         (2, 0, None))
        b = rows["console-b"]
        self.assertEqual((b["collected_at"], b["stale"], b["last_error"], b["os_pretty"], b["packages"],
                          b["kernel_running"], b["reboot_pending"]), (None, True, "연결 실패: 시험", None, 0, None, False))
        self.assertTrue(rows["console-a"]["stale"])
        self.assertEqual(body["freshness"]["assets"]["stale_assets"], ["console-a", "console-b"])
        json.dumps(body)

    async def test_자산_상세는_주요_패키지와_취약점_쪽을_준다(self):
        body = await cti.asset_detail(self.request, "web-01", "all", 50, 0)
        asset = body["asset"]
        self.assertEqual(asset["key_packages"], [{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.19"},
                                                 {"name": "nginx", "version": "1.24.0-2ubuntu7.18"},
                                                 {"name": "sudo", "version": "1.9.15p5-3ubuntu5.24.04.2"},
                                                 {"name": "libc6", "version": "2.39-0ubuntu8.6"}])
        self.assertEqual((asset["os"], asset["images"], asset["probe_errors"]), (UBUNTU, [], []))
        self.assertEqual(asset["kernel"]["running_version"], "6.8.0-139.139")
        [vuln] = body["vulnerabilities"]["rows"]
        self.assertEqual(vuln, {"osv_id": "UBUNTU-CVE-2017-9841", "cve_id": "CVE-2017-9841", "source_package": "phpunit",
                                "version": "9.6.17-1", "fix_state": "fix_available", "fixed_version": "9.6.17-1ubuntu0.1",
                                "kev": {"date_added": "2022-02-15", "ransomware": "Unknown",
                                        "name": "PHPUnit Command Injection Vulnerability"},
                                "epss": {"score": 0.94, "percentile": 0.9995, "date": "2026-09-24"},
                                "cvss": {"score": 9.8, "severity": "HIGH"}, "ubuntu_priority": "medium",
                                "summary": "UBUNTU-CVE-2017-9841 요약"})
        self.assertEqual(body["freshness"]["assets"]["stale_assets"], ["console-a", "console-b"])
        json.dumps(body)

    async def test_자산_취약점_정렬_필터_쪽(self):
        async def ids(flt="all", limit=50, offset=0):
            body = await cti.asset_detail(self.request, "fw", flt, limit, offset)
            v = body["vulnerabilities"]
            return [r["osv_id"] for r in v["rows"]], v["total"], (v["limit"], v["offset"], v["filter"])
        order = ["UBUNTU-CVE-2024-1086", "UBUNTU-CVE-2026-82474", "UBUNTU-CVE-2024-11111", "UBUNTU-CVE-2024-22222"]
        self.assertEqual(await ids(), (order, 4, (50, 0, "all")))
        self.assertEqual(await ids("kev"), (["UBUNTU-CVE-2024-1086"], 1, (50, 0, "kev")))
        self.assertEqual(await ids("fix"), (order[:2], 2, (50, 0, "fix")))
        self.assertEqual(await ids("all", 2, 1), (order[1:3], 4, (2, 1, "all")))
        self.assertEqual(await ids("all", 2, 10), ([], 4, (2, 10, "all")))
        body = await cti.asset_detail(self.request, "fw", "all", 1, 0)
        self.assertEqual(body["vulnerabilities"]["rows"][0]["kev"]["name"], "Linux Kernel Use-After-Free Vulnerability")
        self.assertTrue(body["asset"]["reboot_pending"])

    async def test_같은_osv_id_가_소스_패키지_여럿에_걸려도_쪽_사이에_겹치거나_빠지지_않는다(self):
        osv = await self.conn.fetchval("SELECT id FROM cti_snapshots WHERE source = 'osv'")
        ids = [f"UBUNTU-CVE-2025-{1000 + i}" for i in range(40)]
        await self.conn.executemany("INSERT INTO cti_osv (osv_id, cve_id, snapshot_id) VALUES ($1, $2, $3)",
                                    [(i, i[len("UBUNTU-"):], osv) for i in ids])
        # 정렬 앞 열(KEV · EPSS · fix_state)이 모두 같은 160행. osv_id 하나가 소스 패키지 넷에 걸린다
        await self.conn.executemany("""INSERT INTO asset_vulnerabilities (asset_id, source_package, version, osv_id,
            cve_id, fix_state, snapshot_id) VALUES ('data-01', $1, '1', $2, $3, 'unknown', $4)""",
            [(p, i, i[len("UBUNTU-"):], osv) for i in ids
             for p in ("docker.io-app", "containerd-app", "runc-app", "golang-1.22")])
        await self.conn.execute("ANALYZE asset_vulnerabilities")
        for size in (1, 3, 7, 50):
            seen, offset = [], 0
            while True:
                v = (await cti.asset_detail(self.request, "data-01", "all", size, offset))["vulnerabilities"]
                if not v["rows"]:
                    break
                seen += [(r["osv_id"], r["source_package"]) for r in v["rows"]]
                offset += size
            with self.subTest(size=size):
                self.assertEqual((v["total"], len(seen), len(set(seen))), (160, 160, 160))
                self.assertEqual(seen, sorted(seen))   # 동률 안에서는 CVE · OSV id · 소스 패키지 순이다

    async def test_offset_상한까지는_DB_가_받는다(self):
        body = await cti.asset_detail(self.request, "fw", "all", 50, cti.MAX_OFFSET)
        self.assertEqual((body["vulnerabilities"]["rows"], body["vulnerabilities"]["total"]), ([], 4))

    async def test_없는_자산은_404_다(self):
        with self.assertRaises(HTTPException) as error:
            await cti.asset_detail(self.request, "web-99", "all", 50, 0)
        self.assertEqual((error.exception.status_code, error.exception.detail), (404, "자산 정보를 찾을 수 없습니다"))


    # ------------------------------------------------------------ 주목 CVE

    async def add_gateway(self):
        """AWS 커널이 도는 자산. linux 소스의 사용자 공간 헤더(linux-libc-dev)도 깔려 있다."""
        kernel = {"running": "6.8.0-1015-aws", "running_package": "linux-image-6.8.0-1015-aws",
                  "running_version": "6.8.0-1015.16",
                  "installed": [{"package": "linux-image-6.8.0-1015-aws", "version": "6.8.0-1015.16"}]}
        packages = [{"name": "linux-image-6.8.0-1015-aws", "version": "6.8.0-1015.16", "source": "linux-signed-aws",
                     "source_version": "6.8.0-1015.16", "arch": "amd64"},
                    {"name": "linux-libc-dev", "version": "6.8.0-139.139", "source": "linux",
                     "source_version": "6.8.0-139.139", "arch": "amd64"},
                    {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.19", "source": "openssh",
                     "source_version": "1:9.6p1-3ubuntu13.19", "arch": "amd64"}]
        await self.conn.execute("""INSERT INTO asset_inventory (asset_id, role, method, host, collected_at, received_at,
            os, kernel, packages) VALUES ('gateway', 'platform', 'ssm', 'i-0fedcba9876543210', now() - interval '1 hour',
            now() - interval '1 hour', $1::jsonb, $2::jsonb, $3::jsonb)""",
            json.dumps(UBUNTU), json.dumps(kernel), json.dumps(packages))

    async def test_주목_CVE_는_자산마다_설치_버전과_수정판을_비교한다(self):
        await self.add_gateway()
        body = await cti.watch_list(self.request)
        self.assertTrue(body["available"])
        rows = {r["cve_id"]: r for r in body["rows"]}
        self.assertEqual([r["cve_id"] for r in body["rows"]],
                         ["CVE-2026-53266", "CVE-2023-4911", "CVE-2024-1086", "CVE-2024-6387", "CVE-2024-3094",
                          "CVE-2021-3156", "CVE-2021-4034", "CVE-2024-11111"])
        self.assertEqual({c: r["summary"] for c, r in rows.items()},
                         {"CVE-2026-53266": "affected", "CVE-2023-4911": "affected", "CVE-2024-1086": "not_affected",
                          "CVE-2024-6387": "not_affected", "CVE-2024-3094": "not_affected",
                          "CVE-2021-3156": "not_affected", "CVE-2021-4034": "unknown", "CVE-2024-11111": "unknown"})

        def asset_of(cve):
            return {a["asset_id"]: a for a in rows[cve]["assets"]}

        # 비해당: web-01 openssh 13.19 ≥ 배포판 수정판 13.3. 자산 순서는 역할 → id
        ssh = rows["CVE-2024-6387"]
        self.assertEqual([a["asset_id"] for a in ssh["assets"]],
                         ["web-01", "console-a", "console-b", "data-01", "fw", "gateway", "honeypot-dmz"])
        self.assertEqual(ssh["assets"][0], {"asset_id": "web-01", "role": "target", "status": "not_affected",
                                            "reason": "openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3",
                                            "package": "openssh", "installed": "1:9.6p1-3ubuntu13.19",
                                            "fixed": "1:9.6p1-3ubuntu13.3"})
        by = asset_of("CVE-2024-6387")
        # 오래된 자산 · 수집 전 · 빈 패키지 목록은 미확인, 설치 안 된 자산은 비해당
        self.assertEqual((by["console-a"]["status"], by["console-a"]["reason"]),
                         ("unknown", f"자산 정보가 오래됐다 (마지막 수집 {cti.kst(self.times['console-a'])}). "
                                     "비해당으로 보지 않는다"))
        self.assertEqual((by["console-b"]["status"], by["console-b"]["reason"]), ("unknown", "자산 정보가 아직 없다"))
        self.assertEqual((by["honeypot-dmz"]["status"], by["honeypot-dmz"]["reason"]),
                         ("unknown", "조사 결과에 패키지 목록이 비어 있다"))
        self.assertEqual((by["data-01"]["status"], by["data-01"]["reason"]),
                         ("not_affected", "영향 패키지(openssh)가 설치돼 있지 않다"))
        self.assertEqual(by["gateway"]["status"], "not_affected")
        self.assertEqual({k: ssh[k] for k in ("osv_id", "record_found", "ubuntu_priority", "description", "kev", "epss",
                                              "affected_packages", "reason")},
                         {"osv_id": "UBUNTU-CVE-2024-6387", "record_found": True, "ubuntu_priority": "high",
                          "description": "regreSSHion 요약", "kev": None,
                          "epss": {"score": 0.99506, "percentile": 0.99944, "date": "2026-09-24"},
                          "affected_packages": [{"package": "openssh", "fixed": "1:9.6p1-3ubuntu13.3"}],
                          "reason": "CVE-2024-6387 시험"})
        self.assertEqual(ssh["checked_at"], cti.iso(self.now - timedelta(hours=3)))

        # 수정판 없음(커널): 실행 중인 커널 소스 · 버전으로 본다. AWS 커널은 linux-aws 항목이다
        kern = rows["CVE-2026-53266"]
        by = asset_of("CVE-2026-53266")
        self.assertEqual((by["web-01"]["status"], by["web-01"]["reason"]),
                         ("affected", "linux 6.8.0-139.139 · 배포판 수정판 없음"))
        self.assertEqual((by["gateway"]["status"], by["gateway"]["reason"], by["gateway"]["package"]),
                         ("affected", "linux-aws 6.8.0-1015.16 · 배포판 수정판 없음", "linux-aws"))
        self.assertEqual(by["fw"]["status"], "affected")
        self.assertEqual((kern["kev"], kern["description"]),
                         ({"date_added": "2026-09-18", "ransomware": "Unknown", "name": "Linux Kernel ebtables 시험 항목"},
                          "NVD 커널 설명"))
        self.assertEqual(kern["affected_packages"], [{"package": "linux", "fixed": None},
                                                     {"package": "linux-aws", "fixed": None}])

        # 해당: fw glibc 2.38-1ubuntu5 < 2.38-1ubuntu6. web-01 은 2.39 라 비해당
        by = asset_of("CVE-2023-4911")
        self.assertEqual((by["fw"]["status"], by["fw"]["reason"]),
                         ("affected", "glibc 2.38-1ubuntu5 < 수정판 2.38-1ubuntu6"))
        self.assertEqual((by["web-01"]["status"], by["web-01"]["reason"]),
                         ("not_affected", "glibc 2.39-0ubuntu8.6 ≥ 수정판 2.38-1ubuntu6"))
        # 미설치 · 다른 판 커널만 영향(linux-azure-fde)
        self.assertEqual(asset_of("CVE-2024-3094")["web-01"]["reason"], "영향 패키지(xz-utils)가 설치돼 있지 않다")
        self.assertEqual(asset_of("CVE-2024-1086")["web-01"]["reason"], "영향 패키지(linux-azure-fde)가 설치돼 있지 않다")
        self.assertEqual(rows["CVE-2024-1086"]["kev"]["name"], "Linux Kernel Use-After-Free Vulnerability")
        # 이 릴리스 항목 없음 · 기록 없음 · 상세 없는 기록
        self.assertEqual((asset_of("CVE-2021-3156")["web-01"]["status"], asset_of("CVE-2021-3156")["web-01"]["reason"]),
                         ("not_affected", "배포판 기록에 이 릴리스(Ubuntu 24.04.5 LTS)의 영향 패키지가 없다"))
        self.assertEqual(rows["CVE-2021-3156"]["affected_packages"], [])
        self.assertEqual((asset_of("CVE-2021-4034")["web-01"]["status"], asset_of("CVE-2021-4034")["web-01"]["reason"]),
                         ("unknown", "배포판(Ubuntu) 기록이 없다"))
        self.assertEqual((rows["CVE-2021-4034"]["osv_id"], rows["CVE-2021-4034"]["record_found"]), (None, False))
        self.assertEqual(asset_of("CVE-2024-11111")["web-01"]["reason"], "배포판 기록의 영향 항목을 아직 받지 않았다")
        self.assertEqual(body["freshness"]["assets"]["stale_assets"], ["console-a", "console-b"])
        self.assertTrue(body["freshness"]["osv"]["stale"])
        json.dumps(body)

    async def test_주목_CVE_표가_없으면_available_false(self):
        await self.conn.execute("DROP TABLE cti_watch")
        body = await cti.watch_list(self.request)
        self.assertEqual((body["available"], body["rows"], body["freshness"]), (False, [], None))
        # 나머지 조회는 cti_watch 없이 돈다
        self.assertTrue((await cti.assets_list(self.request))["available"])


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class CtiWithoutTablesTests(Base):
    """마이그레이션 전 DB. 500 이 아니라 available=false 다."""
    with_cti = False

    async def test_표가_없으면_available_false(self):
        body = await cti.incident_cti(K106, self.request)
        self.assertEqual((body["applicable"], body["available"], body["rule_id"]), (True, False, "R106"))
        self.assertFalse((await cti.incident_cti(K_NOSIG, self.request))["applicable"])
        with self.assertRaises(HTTPException) as error:
            await cti.incident_cti("없는 키", self.request)
        self.assertEqual(error.exception.status_code, 404)
        listing = await cti.assets_list(self.request)
        self.assertEqual((listing["available"], listing["rows"], listing["freshness"]), (False, [], None))
        detail = await cti.asset_detail(self.request, "web-01", "all", 50, 0)
        self.assertEqual((detail["available"], detail["asset"], detail["vulnerabilities"]), (False, None, None))
        watch = await cti.watch_list(self.request)
        self.assertEqual((watch["available"], watch["rows"], watch["freshness"]), (False, [], None))


if __name__ == "__main__":
    unittest.main()
