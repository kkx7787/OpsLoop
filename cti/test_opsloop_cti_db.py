#!/usr/bin/env python3
"""CTI 수집기 DB 시험. 실제 PostgreSQL 에서 적재 · upsert · 자산 적재 · fix_state 를 본다.

  OPSLOOP_TEST_DATABASE_URL=postgresql://… python3 cti/test_opsloop_cti_db.py

시험마다 무작위 스키마(opsloop_cti_test_<pid>_<난수>)를 만들어 infra/migrations/20260925_cti.sql 을 그대로 적용하고
(rule_versions 는 먼저 만들어 detector/rules_cve.json 을 c1 으로 넣는다), 끝나면 DROP SCHEMA … CASCADE 한다.
운영 표 · public 스키마는 건드리지 않는다. 외부 API 는 부르지 않는다 (가짜 HTTP · 가짜 S3 는 단위 시험의 것을 쓴다).
"""
import io
import json
import os
import secrets
import sys
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import opsloop_cti as cti  # noqa: E402
from test_opsloop_cti import (AWS_KERNEL, AWS_PACKAGES, ECO, NO_WATCH, T0, FakeHttp, FakeS3, S3Error,  # noqa: E402
                              bundle, epss_gz, kev_doc, load_rules, osv_routes, pkg, probe, vuln, watch_file)

try:
    import psycopg2
    REAL_PG = True
except ImportError:
    REAL_PG = False

MIGRATION = os.path.join(os.path.dirname(HERE), "infra", "migrations", "20260925_cti.sql")
URL = os.environ.get("OPSLOOP_TEST_DATABASE_URL")

# web-01: openssh 는 수정판이 있고, sudo 는 수정판이 없고, 커널은 142 가 깔렸는데 139 로 돈다 (재부팅 대기)
WEB_PACKAGES = [pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh"), pkg("openssh-client", "1:9.6p1-3ubuntu13.2", "openssh"),
                pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2"), pkg("bash", "5.2.21-2ubuntu4"),
                pkg("linux-image-6.8.0-139-generic", "6.8.0-139.139", "linux-signed"),
                pkg("linux-image-6.8.0-142-generic", "6.8.0-142.142", "linux-signed"),
                pkg("linux-modules-6.8.0-139-generic", "6.8.0-139.139", "linux")]
OSV_TABLE = {
    (ECO, "openssh", "1:9.6p1-3ubuntu13.2"): [[vuln("UBUNTU-CVE-2024-6387"), vuln("USN-6859-1")]],
    (ECO, "sudo", "1.9.15p5-3ubuntu5.24.04.2"): [[vuln("UBUNTU-CVE-2026-82474")]],
    # 커널 질의는 쪽이 나뉜다
    (ECO, "linux", "6.8.0-139.139"): [[vuln("UBUNTU-CVE-2021-44228"), vuln("UBUNTU-CVE-2024-2222")],
                                      [vuln("UBUNTU-CVE-2024-3333")]],
    (ECO, "linux", "6.8.0-142.142"): [[vuln("UBUNTU-CVE-2024-2222")]],
}
OSV_DETAILS = {
    "UBUNTU-CVE-2024-6387": {"id": "UBUNTU-CVE-2024-6387", "modified": "2026-09-20T00:00:00Z", "upstream": ["CVE-2024-6387"],
                             "details": "regreSSHion", "severity": [{"type": "Ubuntu", "score": "high"}],
                             "affected": [{"package": {"ecosystem": ECO, "name": "openssh"},
                                           "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.3"}]}]}]},
    "UBUNTU-CVE-2026-82474": {"id": "UBUNTU-CVE-2026-82474", "modified": "2026-09-20T00:00:00Z",
                              "upstream": ["CVE-2026-82474"], "severity": [{"type": "Ubuntu", "score": "medium"}],
                              "affected": [{"package": {"ecosystem": ECO, "name": "sudo"},
                                            "ranges": [{"events": [{"introduced": "0"}]}]}]},
    # 커널 기록이지만 CVE 가 KEV 에 있어 상세를 받는다 (시험용으로 KEV 의 CVE 를 빌렸다)
    "UBUNTU-CVE-2021-44228": {"id": "UBUNTU-CVE-2021-44228", "modified": "2026-09-20T00:00:00Z",
                              "upstream": ["CVE-2021-44228"],
                              "affected": [{"package": {"ecosystem": ECO, "name": "linux"},
                                            "ranges": [{"events": [{"fixed": "6.8.0-140.140"}]}]}]},
}


def web_asset(collected_at="2026-09-25T02:50:00+00:00"):
    return {"asset_id": "web-01", "role": "target", "method": "ssh", "host": "opsloop-web-01",
            "probe": probe(WEB_PACKAGES, installed=("6.8.0-139.139", "6.8.0-142.142"), collected_at=collected_at)}


def data_asset():
    return {"asset_id": "data-01", "role": "platform", "method": "ssh", "host": "opsloop-data-01",
            "probe": probe([pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")])}


@unittest.skipUnless(REAL_PG and URL, "PostgreSQL 시험 연결 미지정")
class CtiDatabaseTest(unittest.TestCase):
    def setUp(self):
        self.schema = f"opsloop_cti_test_{os.getpid()}_{secrets.token_hex(4)}"
        self.admin = psycopg2.connect(URL)
        self.admin.autocommit = True
        try:
            self.admin.cursor().execute(f"CREATE SCHEMA {self.schema}")
        except psycopg2.Error as e:
            self.admin.close()
            self.skipTest(f"시험 스키마를 만들 수 없습니다: {e}")
        self.options = f"-c search_path={self.schema}"
        setup = psycopg2.connect(URL, options=self.options)
        setup.autocommit = True
        cur = setup.cursor()
        cur.execute("""CREATE TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL, reason text,
                                                    created_at timestamptz NOT NULL DEFAULT now())""")
        cur.execute("INSERT INTO rule_versions (rule_version, definition) VALUES ('c1', %s::jsonb)",
                    (json.dumps(load_rules()),))
        with open(MIGRATION, encoding="utf-8") as f:
            cur.execute(f.read())
        setup.close()
        self.conn = psycopg2.connect(URL, options=self.options, application_name="opsloop-cti-test")
        self.home = tempfile.mkdtemp()
        self.s3 = FakeS3()

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()
        self.admin.cursor().execute(f"DROP SCHEMA {self.schema} CASCADE")
        self.admin.close()

    def ctx(self, http=None, s3=None, sleeps=None, now=T0, watch=NO_WATCH):
        return cti.Ctx(self.conn, s3 or self.s3, "opsloop-archive-test", self.home, http=http,
                       sleep=sleeps.append if sleeps is not None else (lambda s: None), now=lambda: now,
                       watchlist=watch)

    def q(self, sql, params=None):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        self.conn.rollback()
        return rows

    def load_kev(self, entries=None):
        self.assertTrue(cti.fetch_kev(self.ctx(FakeHttp({cti.KEV_URL: kev_doc(entries)}))))

    def load_bundle(self, assets, check=True):
        return cti.load_assets(self.ctx(FakeHttp(osv_routes(OSV_TABLE, OSV_DETAILS))), bundle(assets), check=check)

    # ── 시험 ──

    def test_KEV_는_목록과_같게_맞추고_원본_기록을_남긴다(self):
        self.load_kev()
        self.assertEqual(self.q("SELECT cve_id, vendor_project, product, date_added::text, due_date::text, ransomware"
                                "  FROM cti_kev ORDER BY 1"),
                         [("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", "2021-12-24", "Known"),
                          ("CVE-2022-24816", "OSGeo", "JAI-EXT", "2024-06-26", "2024-07-17", "Unknown"),
                          ("CVE-2024-36401", "OSGeo", "GeoServer", "2024-07-15", "2024-08-05", "Unknown")])
        snap = self.q("SELECT id, source, status, s3_key, records, source_version, source_ts, bytes FROM cti_snapshots")
        self.assertEqual(snap[0][1:6], ("kev", "ok", self.s3.calls[0]["Key"], 3, "2026.09.23"))
        self.assertEqual(snap[0][6], datetime(2026, 9, 23, 17, 3, 57, 231700, timezone.utc))
        self.assertEqual(snap[0][7], len(self.s3.calls[0]["Body"]))
        # 다음 회차: 하나는 바뀌고 하나는 목록에서 빠졌다
        entries = kev_doc()["vulnerabilities"][:2]
        entries[0] = dict(entries[0], product="GeoServer 2")
        self.load_kev(entries)
        second = self.q("SELECT max(id) FROM cti_snapshots")[0][0]
        self.assertEqual(self.q("SELECT cve_id, product, snapshot_id FROM cti_kev ORDER BY 1"),
                         [("CVE-2022-24816", "JAI-EXT", second), ("CVE-2024-36401", "GeoServer 2", second)])

    def test_S3_에_못_쓰면_DB_를_고치지_않는다(self):
        self.load_kev()
        before = self.q("SELECT * FROM cti_kev ORDER BY 1")
        s3 = FakeS3(fail=S3Error("AccessDenied"))
        self.assertFalse(cti.fetch_kev(self.ctx(FakeHttp({cti.KEV_URL: kev_doc(kev_doc()["vulnerabilities"][:1])}), s3=s3)))
        self.assertEqual(self.q("SELECT * FROM cti_kev ORDER BY 1"), before)
        last = self.q("SELECT status, s3_key, error FROM cti_snapshots ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(last[:2], ("failed", None))
        self.assertTrue(last[2].startswith("원본 보관(S3) 실패"))
        # 같은 원본을 다시 받으면 412(이미 있음)라도 성공이다
        self.assertTrue(cti.fetch_kev(self.ctx(FakeHttp({cti.KEV_URL: kev_doc()}))))
        self.assertEqual(self.q("SELECT count(*) FROM cti_snapshots WHERE status = 'ok'")[0][0], 2)

    def test_자산_적재_대조_fix_state(self):
        self.load_kev()
        assets = [web_asset(), data_asset(),
                  {"asset_id": "console-b", "role": "platform", "method": "ssh", "host": None, "error": "연결 실패: 시간 초과"},
                  {"asset_id": "fw", "role": "platform", "method": "ssh", "host": "opsloop-fw",
                   "probe": probe([pkg("haproxy", "2.8.16-0ubuntu0.24.04.3")], os_id="debian", version_id="12")},
                  {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "host": "i-0f8f7c0f698ca941a",
                   "probe": probe([pkg("evil;rm", "1")])}]
        http = FakeHttp(osv_routes(OSV_TABLE, OSV_DETAILS))
        self.assertEqual(cti.load_assets(self.ctx(http), bundle(assets)), 1)        # 형식 오류 자산이 있다
        inv = {r[0]: r[1:] for r in self.q(
            "SELECT asset_id, role, method, host, collected_at, received_at IS NOT NULL, last_error, checked_at IS NOT NULL,"
            "       check_error, jsonb_array_length(packages), kernel ->> 'running_version' FROM asset_inventory")}
        self.assertEqual(inv["web-01"], ("target", "ssh", "opsloop-web-01", datetime(2026, 9, 25, 2, 50, tzinfo=timezone.utc),
                                         True, None, True, None, 7, "6.8.0-139.139"))
        self.assertEqual(inv["console-b"], ("platform", "ssh", None, None, False, "연결 실패: 시간 초과", False, None, 0, None))
        self.assertEqual(inv["fw"][7], "지원하지 않는 배포판")
        self.assertEqual(inv["honeypot-dmz"][:3], ("sensor", "ssm", "i-0f8f7c0f698ca941a"))
        self.assertIsNone(inv["honeypot-dmz"][3])
        self.assertTrue(inv["honeypot-dmz"][5].startswith("조사 결과 형식 오류: packages.name 형식이 틀리다"))
        vulns = self.q("SELECT asset_id, source_package, version, osv_id, cve_id, fix_state, fixed_version"
                       "  FROM asset_vulnerabilities ORDER BY 1, 2, 4")
        self.assertEqual(vulns, [
            # data-01 은 설치된 커널이 실행 중인 것 하나뿐이라 재부팅 대기가 없다. 배포판 수정판이 있으면 fix_available
            ("data-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2021-44228", "CVE-2021-44228", "fix_available", "6.8.0-140.140"),
            ("data-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-2222", "CVE-2024-2222", "unknown", None),
            ("data-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-3333", "CVE-2024-3333", "unknown", None),
            ("data-01", "openssh", "1:9.6p1-3ubuntu13.2", "UBUNTU-CVE-2024-6387", "CVE-2024-6387", "fix_available",
             "1:9.6p1-3ubuntu13.3"),
            ("web-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2021-44228", "CVE-2021-44228", "reboot_pending", "6.8.0-142.142"),
            ("web-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-2222", "CVE-2024-2222", "unknown", None),
            ("web-01", "linux", "6.8.0-139.139", "UBUNTU-CVE-2024-3333", "CVE-2024-3333", "reboot_pending", "6.8.0-142.142"),
            ("web-01", "openssh", "1:9.6p1-3ubuntu13.2", "UBUNTU-CVE-2024-6387", "CVE-2024-6387", "fix_available",
             "1:9.6p1-3ubuntu13.3"),
            ("web-01", "sudo", "1.9.15p5-3ubuntu5.24.04.2", "UBUNTU-CVE-2026-82474", "CVE-2026-82474", "no_fix", None)])
        osv = {r[0]: r[1:] for r in self.q("SELECT osv_id, cve_id, detailed, ubuntu_priority, fixed FROM cti_osv")}
        self.assertEqual(osv["UBUNTU-CVE-2024-6387"], ("CVE-2024-6387", True, "high", {f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3"}))
        self.assertEqual(osv["UBUNTU-CVE-2024-2222"], ("CVE-2024-2222", False, None, {}))
        self.assertNotIn("USN-6859-1", osv)
        # 두 자산이 같은 openssh 질의를 하지만 한 번만 묻는다. 커널 질의는 두 쪽이다
        asked = [(q["package"]["name"], q["version"], q.get("page_token")) for u, sent in http.calls
                 if u == cti.OSV_BATCH_URL for q in sent["queries"]]
        # fw(데비안)의 haproxy 는 묻지 않는다
        self.assertEqual(sorted(asked, key=str), sorted([
            ("bash", "5.2.21-2ubuntu4", None), ("linux", "6.8.0-139.139", None), ("linux", "6.8.0-142.142", None), ("openssh", "1:9.6p1-3ubuntu13.2", None),
            ("sudo", "1.9.15p5-3ubuntu5.24.04.2", None), ("linux", "6.8.0-139.139", "1")], key=str))
        self.assertEqual(self.q("SELECT source, status FROM cti_snapshots ORDER BY id"),
                         [("kev", "ok"), ("assets", "ok"), ("osv", "ok")])
        osv_snap = self.q("SELECT id FROM cti_snapshots WHERE source = 'osv'")[0][0]
        self.assertEqual(self.q("SELECT DISTINCT check_snapshot_id FROM asset_inventory WHERE checked_at IS NOT NULL"),
                         [(osv_snap,)])

        # 조사 실패가 오면 옛 결과는 두고 시도 기록만 고친다
        later = T0 + timedelta(hours=1)
        rc = cti.load_assets(self.ctx(now=later), bundle([{"asset_id": "web-01", "role": "target", "method": "ssh",
                                                            "host": "x", "error": "연결 실패"}]))
        self.assertEqual(rc, 0)
        self.assertEqual(self.q("SELECT host, collected_at IS NOT NULL, last_error, jsonb_array_length(packages)"
                                "  FROM asset_inventory WHERE asset_id = 'web-01'"), [("opsloop-web-01", True, "연결 실패", 7)])
        self.assertEqual(self.q("SELECT count(*) FROM asset_vulnerabilities WHERE asset_id = 'web-01'")[0][0], 5)
        # 옛 조사(collected_at 이 더 이르다)는 덮어쓰지 않는다
        old = web_asset(collected_at="2026-09-20T00:00:00+00:00")
        old["probe"]["packages"] = [pkg("bash", "5.2.21-2ubuntu4")]
        self.assertEqual(cti.load_assets(self.ctx(), bundle([old]), check=False), 0)
        self.assertEqual(self.q("SELECT jsonb_array_length(packages), collected_at FROM asset_inventory WHERE asset_id = 'web-01'"),
                         [(7, datetime(2026, 9, 25, 2, 50, tzinfo=timezone.utc))])
        # 새 조사: 커널을 재부팅해 142 로 돈다 → 재부팅 대기가 사라지고 142 질의 결과만 남는다
        new = web_asset(collected_at="2026-09-25T04:00:00+00:00")
        new["probe"]["kernel"]["running_version"] = "6.8.0-142.142"
        self.assertEqual(cti.load_assets(self.ctx(FakeHttp(osv_routes(OSV_TABLE, OSV_DETAILS)), now=later), bundle([new])), 0)
        self.assertEqual(self.q("SELECT source_package, osv_id, fix_state FROM asset_vulnerabilities"
                                " WHERE asset_id = 'web-01' ORDER BY 1, 2"),
                         [("linux", "UBUNTU-CVE-2024-2222", "unknown"), ("openssh", "UBUNTU-CVE-2024-6387", "fix_available"),
                          ("sudo", "UBUNTU-CVE-2026-82474", "no_fix")])
        self.assertEqual(self.q("SELECT last_error FROM asset_inventory WHERE asset_id = 'web-01'"), [(None,)])

    def test_EPSS_관심_CVE_사본으로_새_자산_CVE_채움(self):
        self.load_kev()
        rows = [("CVE-2021-44228", "0.94358", "0.99962"), ("CVE-2021-41773", "0.94", "0.998"),
                ("CVE-2024-6387", "0.99506", "0.99944"), ("CVE-2099-0001", "0.5", "0.5")]
        self.assertTrue(cti.fetch_epss(self.ctx(FakeHttp({cti.EPSS_URL: epss_gz(rows)}))))
        epss_snap = self.q("SELECT id FROM cti_snapshots WHERE source = 'epss'")[0][0]
        # KEV · 서명 CVE 만. 아직 자산 CVE(6387)와 관심 밖(2099)은 없다
        self.assertEqual(self.q("SELECT cve_id, epss, epss_date::text, epss_snapshot_id FROM cti_cve ORDER BY 1"),
                         [("CVE-2021-41773", 0.94, "2026-09-24", epss_snap),
                          ("CVE-2021-44228", 0.94358, "2026-09-24", epss_snap)])
        # 자산 대조로 생긴 CVE 의 EPSS 는 로컬 사본에서 채운다
        self.assertEqual(self.load_bundle([data_asset()]), 0)
        self.assertEqual(self.q("SELECT epss, epss_percentile, epss_snapshot_id FROM cti_cve WHERE cve_id = 'CVE-2024-6387'"),
                         [(0.99506, 0.99944, epss_snap)])
        # 다음 EPSS 회차는 이미 있는 행과 자산 CVE 를 관심 집합에 넣는다
        rows2 = [(c, "0.1", "0.2") for c, _, _ in rows]
        self.assertTrue(cti.fetch_epss(self.ctx(FakeHttp({cti.EPSS_URL: epss_gz(rows2)}))))
        self.assertEqual(self.q("SELECT count(*), min(epss), max(epss) FROM cti_cve"), [(3, 0.1, 0.1)])

    def test_NVD_초점_갱신과_14일_건너뛰기(self):
        self.load_kev()
        self.assertEqual(self.load_bundle([data_asset()]), 0)

        def route(url, _):
            cve = url.split("cveId=")[1]
            if cve == "CVE-2021-45046":
                return {"totalResults": 0, "vulnerabilities": []}
            return {"vulnerabilities": [{"cve": {
                "id": cve, "published": "2021-12-10T10:15:09.143", "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": f"{cve} 설명"}],
                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                    "version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "CRITICAL"}}]}}}]}
        sleeps, http = [], FakeHttp(route)
        self.assertTrue(cti.fetch_nvd(self.ctx(http, sleeps=sleeps)))
        asked = [u.split("cveId=")[1] for u, _ in http.calls]
        # 서명 CVE 8개 → 서명 제품(geoserver)의 KEV 2개 → 자산 CVE 중 EPSS 상위(없음 · EPSS 를 받지 않았다)
        self.assertEqual(asked, ["CVE-2017-9841", "CVE-2018-10561", "CVE-2018-10562", "CVE-2021-36260", "CVE-2021-41773",
                                 "CVE-2021-42013", "CVE-2021-44228", "CVE-2021-45046", "CVE-2024-36401", "CVE-2022-24816"])
        self.assertEqual(sleeps, [6.5] * 9)
        self.assertEqual(self.q("SELECT cvss_score::text, cvss_version, cvss_severity, description, nvd_status, published"
                                "  FROM cti_cve WHERE cve_id = 'CVE-2021-44228'"),
                         [("9.8", "3.1", "CRITICAL", "CVE-2021-44228 설명", "Analyzed",
                           datetime(2021, 12, 10, 10, 15, 9, 143000, timezone.utc))])
        self.assertEqual(self.q("SELECT cvss_score, nvd_fetched_at IS NOT NULL FROM cti_cve WHERE cve_id = 'CVE-2021-45046'"),
                         [(None, True)])
        n = self.q("SELECT count(*) FROM cti_snapshots WHERE source = 'nvd'")[0][0]
        http2 = FakeHttp(route)
        self.assertTrue(cti.fetch_nvd(self.ctx(http2)))               # 모두 14일 안에 받았다
        self.assertEqual((http2.calls, self.q("SELECT count(*) FROM cti_snapshots WHERE source = 'nvd'")[0][0]), ([], n))

    def test_수집기_역할의_권한만으로_돈다(self):
        """마이그레이션의 권한 블록(opsloop_cti)을 임시 역할에 그대로 주고 SET ROLE 로 모든 출처 · 적재 · 상태를 돌린다.

        INSERT … RETURNING · ON CONFLICT DO UPDATE … WHERE · DELETE · 시퀀스 사용이 준 권한 안에서 되는지 본다.
        역할은 클러스터 전체라 이름에 난수를 붙이고 끝에 DROP OWNED · DROP ROLE 한다. 만들 수 없으면 건너뛴다.
        """
        role = f"opsloop_cti_t{secrets.token_hex(4)}"
        cur = self.admin.cursor()
        try:
            cur.execute(f"CREATE ROLE {role} NOLOGIN")
        except psycopg2.Error as e:
            self.skipTest(f"시험 역할을 만들 수 없습니다: {e}")
        self.addCleanup(self._drop_role, role)
        with open(MIGRATION, encoding="utf-8") as f:
            mig = f.read()
        block = mig[mig.index("DO $$"):mig.index("END\n$$;") + len("END\n$$;")]
        self.assertIn("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_cti')", block)
        grant = psycopg2.connect(URL, options=self.options)
        grant.autocommit = True
        grant.cursor().execute(block.replace("opsloop_cti", role))
        grant.cursor().execute(f"GRANT USAGE ON SCHEMA {self.schema} TO {role}")    # 운영은 public (블록이 준다)
        grant.close()
        c = self.conn.cursor()
        c.execute(f"SET ROLE {role}")
        self.conn.commit()
        with self.assertRaises(psycopg2.Error):                                  # 원본 기록은 고치지 못한다
            c.execute("UPDATE cti_snapshots SET error = 'x'")
        self.conn.rollback()

        self.load_kev()
        self.assertTrue(cti.fetch_epss(self.ctx(FakeHttp({cti.EPSS_URL: epss_gz([("CVE-2024-6387", "0.9", "0.99")])}))))
        self.assertEqual(self.load_bundle([web_asset(), data_asset(),
                                           {"asset_id": "console-b", "role": "platform", "method": "ssh", "error": "꺼짐"}]), 0)
        self.assertEqual(self.load_bundle([{"asset_id": "console-b", "role": "platform", "method": "ssh", "error": "꺼짐"}]), 0)
        watch = watch_file([("CVE-2024-6387", "regreSSHion"), ("CVE-2021-4034", "PwnKit")])
        self.assertTrue(cti.fetch_osv(self.ctx(FakeHttp(osv_routes(OSV_TABLE, OSV_DETAILS)), watch=watch)))
        self.assertTrue(cti.fetch_osv(self.ctx(FakeHttp(osv_routes(OSV_TABLE, OSV_DETAILS)),
                                               watch=watch_file([("CVE-2024-6387", "regreSSHion")]))))
        self.assertEqual(self.q("SELECT cve_id, record_found FROM cti_watch"), [("CVE-2024-6387", True)])
        nvd = FakeHttp(lambda u, _: {"vulnerabilities": []})
        self.assertTrue(cti.fetch_nvd(self.ctx(nvd)))
        cti.status(self.conn, io.StringIO())
        self.assertEqual(self.q("SELECT current_user, count(*) FILTER (WHERE status = 'failed') FROM cti_snapshots"),
                         [(role, 0)])
        self.assertEqual(self.q("SELECT count(*) FROM asset_vulnerabilities")[0][0], 9)

    def test_비신뢰_자산_하나가_묶음을_깨지_않는다(self):
        """실제 psycopg2 에서: 대리 문자는 UTF-8 인코딩 오류, 넘치는 시각은 OverflowError 를 내던 입력이다.
        그 자산만 last_error 로 남고 나머지 자산은 적재 · 대조된다 (계약 5장)."""
        hp = probe([pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")])
        hp["os"]["pretty"] = "Ubuntu \ud800"
        gw = probe([pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2")], collected_at="0001-01-01T00:00:00+09:00")
        fw = probe([pkg("sudo", "1.9.15p5-3ubuntu5.24.04.3")])
        fw["errors"] = ["images: sudo -n docker: \udcff 실패"]
        assets = [web_asset(),
                  {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "host": "i-0abc", "probe": hp},
                  {"asset_id": "gateway", "role": "platform", "method": "ssm", "host": "i-0def", "probe": gw},
                  {"asset_id": "fw", "role": "platform", "method": "ssh", "host": "opsloop-fw", "probe": fw},
                  {"asset_id": "console-b", "role": "platform", "method": "ssh", "host": None, "error": "꺼짐 \ud800"}]
        self.assertEqual(self.load_bundle(assets), 1)
        inv = {r[0]: r[1:] for r in self.q("SELECT asset_id, collected_at IS NOT NULL, last_error, checked_at IS NOT NULL,"
                                           "       probe_errors FROM asset_inventory")}
        self.assertEqual(inv["web-01"], (True, None, True, []))
        self.assertEqual(inv["fw"], (True, None, True, ["images: sudo -n docker: \ufffd 실패"]))
        self.assertEqual(inv["console-b"][:2], (False, "꺼짐 \ufffd"))
        self.assertTrue(inv["honeypot-dmz"][1].startswith("조사 결과 형식 오류: os.pretty"))
        self.assertIn("collected_at 이 시각이 아니다", inv["gateway"][1])
        self.assertEqual(self.q("SELECT source, status FROM cti_snapshots ORDER BY id"), [("assets", "ok"), ("osv", "ok")])

    def test_AWS_커널_자산은_linux_aws_로_대조한다(self):
        self.load_kev([{"cveID": "CVE-2024-1086", "vendorProject": "Linux", "product": "Kernel",
                        "vulnerabilityName": "Linux Kernel Use-After-Free", "dateAdded": "2024-05-30"}])
        gw = probe(AWS_PACKAGES)
        gw["kernel"] = AWS_KERNEL
        table = dict(OSV_TABLE)
        table.update({(ECO, "linux-aws", "6.8.0-1036.38"): [[vuln("UBUNTU-CVE-2024-1086"), vuln("UBUNTU-CVE-2024-2222")]],
                      (ECO, "linux-aws", "6.8.0-1040.42"): [[vuln("UBUNTU-CVE-2024-2222")]],
                      (ECO, "linux-firmware", "20240318.git3b128b60-0ubuntu2.19"): [[vuln("UBUNTU-CVE-2024-7777")]]})
        details = dict(OSV_DETAILS)
        details["UBUNTU-CVE-2024-1086"] = {"id": "UBUNTU-CVE-2024-1086", "upstream": ["CVE-2024-1086"],
                                           "affected": [{"package": {"ecosystem": ECO, "name": "linux-aws"},
                                                         "ranges": [{"events": [{"fixed": "6.8.0-1040.42"}]}]}]}
        http = FakeHttp(osv_routes(table, details))
        rc = cti.load_assets(self.ctx(http), bundle([web_asset(), {"asset_id": "gateway", "role": "platform",
                                                                   "method": "ssm", "host": "i-0gw", "probe": gw}]))
        self.assertEqual(rc, 0)
        self.assertEqual(self.q("SELECT source_package, version, osv_id, fix_state, fixed_version FROM asset_vulnerabilities"
                                " WHERE asset_id = 'gateway' ORDER BY 1, 3"),
                         [("linux-aws", "6.8.0-1036.38", "UBUNTU-CVE-2024-1086", "reboot_pending", "6.8.0-1040.42"),
                          ("linux-aws", "6.8.0-1036.38", "UBUNTU-CVE-2024-2222", "unknown", None),
                          ("linux-firmware", "20240318.git3b128b60-0ubuntu2.19", "UBUNTU-CVE-2024-7777", "unknown", None),
                          ("sudo", "1.9.15p5-3ubuntu5.24.04.2", "UBUNTU-CVE-2026-82474", "no_fix", None)])
        # web-01(generic)은 그대로 linux 로 묻는다
        self.assertEqual({r[0] for r in self.q("SELECT DISTINCT source_package FROM asset_vulnerabilities"
                                               " WHERE asset_id = 'web-01'")}, {"linux", "openssh", "sudo"})
        # AWS 커널 버전을 linux 로 묻지 않고, 커널 바이너리(linux-aws-headers 등)를 여느 패키지로 묻지 않는다
        asked = {(q["package"]["name"], q["version"]) for u, sent in http.calls if u == cti.OSV_BATCH_URL
                 for q in sent["queries"]}
        self.assertEqual({q for q in asked if q[1].startswith(("6.8.0-10", "6.8.0.10"))},
                         {("linux-aws", "6.8.0-1036.38"), ("linux-aws", "6.8.0-1040.42")})

    def test_주목_CVE_를_목록과_같게_맞춘다(self):
        rec_4911 = {"id": "UBUNTU-CVE-2023-4911", "modified": "2026-01-01T00:00:00Z", "upstream": ["CVE-2023-4911"],
                    "severity": [{"type": "Ubuntu", "score": "high"}],
                    "affected": [{"package": {"ecosystem": ECO, "name": "glibc"},
                                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.38-1ubuntu6"}]}]},
                                 {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "glibc"},
                                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.35-0ubuntu3.4"}]}]}]}
        rec_53266 = {"id": "UBUNTU-CVE-2026-53266", "modified": "2026-09-19T00:00:00Z", "upstream": ["CVE-2026-53266"],
                     "affected": [{"package": {"ecosystem": ECO, "name": "linux"}, "ranges": [{"events": [{"introduced": "0"}]}]}]}
        recs = {"UBUNTU-CVE-2023-4911": rec_4911, "UBUNTU-CVE-2026-53266": rec_53266}

        def route(url, sent):
            oid = urllib.parse.unquote(url[len(cti.OSV_VULN_URL):])
            if oid == "UBUNTU-CVE-2024-3094":
                return cti.HttpStatus(500, url)
            return recs.get(oid)
        first = watch_file([("CVE-2023-4911", "Looney Tunables"), ("CVE-2021-4034", "PwnKit"),
                            ("CVE-2024-3094", "xz"), ("CVE-2026-53266", "ebtables")])
        self.assertTrue(cti.fetch_osv(self.ctx(FakeHttp(route), watch=first)))
        snap = self.q("SELECT id FROM cti_snapshots WHERE source = 'osv'")[0][0]
        self.assertEqual(self.q("SELECT cve_id, reason, osv_id, record_found, checked_at IS NOT NULL, snapshot_id"
                                "  FROM cti_watch ORDER BY 1"),
                         [("CVE-2021-4034", "PwnKit", None, False, True, snap),
                          ("CVE-2023-4911", "Looney Tunables", "UBUNTU-CVE-2023-4911", True, True, snap),
                          ("CVE-2024-3094", "xz", None, None, False, None),               # 오류: 조회 전으로 둔다
                          ("CVE-2026-53266", "ebtables", "UBUNTU-CVE-2026-53266", True, True, snap)])
        self.assertEqual(self.q("SELECT osv_id, cve_id, detailed, ubuntu_priority, fixed, affected FROM cti_osv ORDER BY 1"),
                         [("UBUNTU-CVE-2023-4911", "CVE-2023-4911", True, "high",
                           {f"{ECO}/glibc": "2.38-1ubuntu6", "Ubuntu:22.04:LTS/glibc": "2.35-0ubuntu3.4"},
                           {f"{ECO}/glibc": "2.38-1ubuntu6", "Ubuntu:22.04:LTS/glibc": "2.35-0ubuntu3.4"}),
                          ("UBUNTU-CVE-2026-53266", "CVE-2026-53266", True, None, {}, {f"{ECO}/linux": None})])
        # 주목 CVE 는 EPSS 관심 집합과 NVD 초점(맨 앞)에 든다
        self.assertTrue({"CVE-2023-4911", "CVE-2021-4034", "CVE-2024-3094", "CVE-2026-53266"} <= cti.epss_interest(self.ctx()))
        self.assertEqual(cti.nvd_focus(self.ctx())[:4], ["CVE-2021-4034", "CVE-2023-4911", "CVE-2024-3094", "CVE-2026-53266"])
        # 다음 회차: 목록에서 4034 · 53266 이 빠지고 3094 는 이번에 기록이 없다(404)
        recs.pop("UBUNTU-CVE-2024-3094", None)
        second = watch_file([("CVE-2023-4911", "glibc"), ("CVE-2024-3094", "xz-utils")])
        self.assertTrue(cti.fetch_osv(self.ctx(FakeHttp(lambda u, s: recs.get(urllib.parse.unquote(
            u[len(cti.OSV_VULN_URL):]))), watch=second)))
        self.assertEqual(self.q("SELECT cve_id, reason, osv_id, record_found FROM cti_watch ORDER BY 1"),
                         [("CVE-2023-4911", "glibc", "UBUNTU-CVE-2023-4911", True),
                          ("CVE-2024-3094", "xz-utils", None, False)])
        # 빠진 CVE 의 배포판 기록(cti_osv)은 남는다 (다른 참조 · 원본 재현용)
        self.assertEqual(self.q("SELECT count(*) FROM cti_osv")[0][0], 2)

    def test_대조한_자산이_없으면_osv_기록을_남기지_않고_1(self):
        p = probe([])
        p["kernel"], p["errors"] = None, ["packages: dpkg-query -W -f: 종료 2"]
        rc = self.load_bundle([{"asset_id": "web-01", "role": "target", "method": "ssh", "host": "opsloop-web-01",
                                "probe": p}])
        self.assertEqual(rc, 1)
        self.assertEqual(self.q("SELECT source, status FROM cti_snapshots"), [("assets", "ok")])
        self.assertEqual(self.q("SELECT checked_at, check_error FROM asset_inventory"), [(None, "패키지 목록이 없다")])

    @staticmethod
    def _drop_role(role):
        # tearDown 뒤에 돈다 (SET ROLE 한 연결은 이미 닫혔다)
        conn = psycopg2.connect(URL)
        conn.autocommit = True
        conn.cursor().execute(f"DROP OWNED BY {role}; DROP ROLE {role}")
        conn.close()

    def test_실행기_fetch_와_status(self):
        env_file = os.path.join(self.home, "cti.env")
        sep = "&" if "?" in URL else "?"
        with open(env_file, "w") as f:
            f.write(f"DATABASE_URL={URL}{sep}options={urllib.parse.quote(self.options)}\n")
        http = FakeHttp({cti.KEV_URL: kev_doc(), cti.EPSS_URL: epss_gz([("CVE-2021-44228", "0.9", "0.99")])})
        env = {"OPSLOOP_CTI_DB_ENV": env_file, "OPSLOOP_BUCKET": "opsloop-archive-test", "OPSLOOP_CTI_HOME": self.home,
               "OPSLOOP_CTI_DEFAULTS": os.path.join(self.home, "없음"), "OPSLOOP_CTI_WATCHLIST": NO_WATCH}
        with mock.patch.dict(os.environ, env), mock.patch.object(cti, "s3_client", lambda cfg: self.s3), \
                mock.patch.object(cti, "new_http", lambda: http), mock.patch.object(cti, "NVD_GAP", 0):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cti.main(["fetch", "--only", "kev,epss,osv"]), 0)
            self.assertIn("끝: kev 정상 · epss 정상 · osv 정상", out.getvalue())
            self.assertEqual(cti.main(["fetch", "--only", "nvd"]), 1)     # 가짜 HTTP 에 NVD 가 없어 모두 실패
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cti.main(["status"]), 0)
        text = out.getvalue()
        self.assertIn("== 출처 (마지막 성공)", text)
        self.assertRegex(text, r"kev +2026-09-\d\d \d\d:\d\d KST  기준 2026-09-24 02:03 KST  판 2026.09.23  3건")
        self.assertIn("osv     성공 기록 없음", text)             # 자산도 주목 CVE 도 없어 할 일이 없었다
        self.assertIn("== 주목 CVE (배포판 기록 조회)\n  없음", text)
        self.assertIn("nvd     성공 기록 없음", text)
        self.assertIn("마지막 실패", text)
        self.assertIn("자산 조사 결과가 없다", text)
        self.assertEqual(self.q("SELECT count(*) FROM pg_stat_activity WHERE application_name = 'opsloop-cti'")[0][0], 0)


if __name__ == "__main__":
    unittest.main()
