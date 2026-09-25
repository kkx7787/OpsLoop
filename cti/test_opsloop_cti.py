#!/usr/bin/env python3
"""CTI 수집기(opsloop_cti.py) 단위 시험. 네트워크 · DB 없이 돈다.  python3 cti/test_opsloop_cti.py

가짜 HTTP(경로별 응답, 없는 경로는 404) · 가짜 S3(같은 키를 다시 쓰면 412 를 흉내) · 가짜 DB(문장 · 인자를 기록하고
커밋된 것만 남긴다. psycopg2 처럼 UTF-8 로 못 바꾸는 문자열 인자는 거부한다)로 출처별 파싱 · 원본 키 · 한 번 쓰기 ·
실패 시 DB 미갱신 · fix_state 계산 · 커널 소스(AWS 커널) · 재부팅 대기 · 주목 CVE · 자산 묶음 검증(나쁜 입력 · 넘치는 시각 ·
대리 문자) · EPSS 긴 줄 · dpkg 버전 비교 · kev_match(실제 rules_cve.json 서명) · 한국어 도움말을 본다.
실제 표에서 적재 · upsert 를 돌리는 시험은 test_opsloop_cti_db.py 다 (OPSLOOP_TEST_DATABASE_URL).
"""
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import opsloop_cti as cti  # noqa: E402

RULES = os.path.join(os.path.dirname(HERE), "detector", "rules_cve.json")
WATCHLIST = os.path.join(HERE, "watchlist.json")


def watch_file(items, note="시험"):
    """주목 CVE 목록 파일을 임시로 만든다. items: [(CVE, 이유)] 또는 파일에 그대로 쓸 값."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        if isinstance(items, list) and all(isinstance(x, tuple) for x in items):
            json.dump({"note": note, "watch": [{"cve": c, "reason": r} for c, r in items]}, f, ensure_ascii=False)
        else:
            f.write(items if isinstance(items, str) else json.dumps(items))
    return path


NO_WATCH = watch_file([])      # 주목 CVE 를 보지 않는 시험의 기본 목록 (빈 목록)


def load_rules():
    with open(RULES, encoding="utf-8") as f:
        return json.load(f)
T0 = datetime(2026, 9, 25, 3, 0, tzinfo=timezone.utc)
ECO = "Ubuntu:24.04:LTS"


# ── 가짜들 ─────────────────────────────────────────────────────────────────────

class S3Error(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """put_object 만. 같은 키를 다시 쓰면 If-None-Match 처럼 412(PreconditionFailed)를 낸다."""

    def __init__(self, fail=None):
        self.objs, self.calls, self.fail = {}, [], fail

    def put_object(self, **kw):
        self.calls.append(kw)
        if self.fail is not None:
            raise self.fail
        if kw["Key"] in self.objs:
            raise S3Error("PreconditionFailed")
        self.objs[kw["Key"]] = kw["Body"]


class FakeHttp(cti.Http):
    """routes(url, 보낸 JSON) → bytes · JSON 으로 바꿀 값 · 예외. None 이면 404 (cti.HttpStatus)."""

    def __init__(self, routes):
        super().__init__(sleep=lambda s: None)
        self.routes, self.calls = routes, []

    def fetch(self, url, limit, data=None, headers=None):
        sent = json.loads(data) if data else None
        self.calls.append((url, sent))
        r = self.routes(url, sent) if callable(self.routes) else self.routes.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise cti.HttpStatus(404, url)
        return r if isinstance(r, bytes) else json.dumps(r).encode("utf-8")


def utf8_params(v):
    """psycopg2 처럼 문자열 인자를 UTF-8 로 바꿔 본다. 짝 없는 대리 문자가 있으면 UnicodeEncodeError 다."""
    if isinstance(v, str):
        v.encode("utf-8")
    elif isinstance(v, (list, tuple)):
        for x in v:
            utf8_params(x)
    elif isinstance(v, dict):
        for x in v.values():
            utf8_params(x)


class FakeCursor:
    def __init__(self, conn):
        self.conn, self.rows, self.rowcount = conn, [], 0

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        utf8_params(params)
        self.conn.pending.append((flat, params))
        if any(n in flat for n in self.conn.fail_on):
            raise RuntimeError("가짜 DB 오류")
        self.rows = []
        for needle, rows in self.conn.answers:
            if needle in flat:
                self.rows = list(rows(params) if callable(rows) else rows)
                break
        if "RETURNING id" in flat:
            self.conn.next_id += 1
            self.rows = [(self.conn.next_id,)]
        self.rowcount = len(self.rows) if flat.startswith("SELECT") else self.conn.rowcount

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    """문장을 기록한다. 커밋된 것만 committed 에 남고 되돌리면 버린다. SELECT 답은 (문장 조각, 행) 목록으로 준다."""

    def __init__(self, answers=(), fail_on=(), rowcount=1):
        self.answers, self.fail_on, self.rowcount = list(answers), list(fail_on), rowcount
        self.pending, self.committed, self.next_id = [], [], 100

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed.extend(self.pending)
        self.pending = []

    def rollback(self):
        self.pending = []

    def close(self):
        pass

    def writes(self):
        return [(s, p) for s, p in self.committed if not s.startswith("SELECT")]

    def snapshots(self):
        return [p for s, p in self.committed if s.startswith("INSERT INTO cti_snapshots")]


def ctx_for(conn, s3=None, http=None, home=None, sleeps=None, watch=NO_WATCH):
    return cti.Ctx(conn, s3 if s3 is not None else FakeS3(), "opsloop-archive-test", home or tempfile.mkdtemp(),
                   http=http, sleep=(sleeps.append if sleeps is not None else (lambda s: None)), now=lambda: T0,
                   watchlist=watch)


def kev_doc(entries=None):
    return {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.09.23",
            "dateReleased": "2026-09-23T17:03:57.2317Z", "count": 3,
            "vulnerabilities": entries if entries is not None else [
                {"cveID": "CVE-2024-36401", "vendorProject": "OSGeo", "product": "GeoServer",
                 "vulnerabilityName": "OSGeo GeoServer Eval Injection Vulnerability", "dateAdded": "2024-07-15",
                 "shortDescription": "OSGeo GeoServer contains an eval injection vulnerability.",
                 "requiredAction": "Apply mitigations.", "dueDate": "2024-08-05",
                 "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": ["CWE-95"]},
                {"cveID": "CVE-2022-24816", "vendorProject": "OSGeo", "product": "JAI-EXT",
                 "vulnerabilityName": "OSGeo JAI-EXT Code Injection Vulnerability", "dateAdded": "2024-06-26",
                 "shortDescription": "OSGeo JAI-EXT contains a code injection vulnerability. This affects GeoServer.",
                 "dueDate": "2024-07-17", "knownRansomwareCampaignUse": "Unknown"},
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
                 "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability", "dateAdded": "2021-12-10",
                 "shortDescription": "Apache Log4j2 contains a JNDI injection vulnerability.",
                 "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
                {"cveID": "bogus", "vendorProject": "X", "product": "Y", "vulnerabilityName": "Z",
                 "dateAdded": "2024-01-01"},
            ]}


def epss_gz(rows, first="#model_version:v2026.06.15,score_date:2026-09-24T12:00:20Z", header="cve,epss,percentile"):
    text = first + "\n" + header + "\n" + "".join(f"{c},{e},{p}\n" for c, e, p in rows)
    return gzip.compress(text.encode("utf-8"))


def osv_routes(table, details):
    """table: {(생태계, 패키지, 버전): [1쪽 vulns, 2쪽 vulns, …]}, details: {id: 상세 기록}."""
    def route(url, sent):
        if url == cti.OSV_BATCH_URL:
            results = []
            for q in sent["queries"]:
                pages = table.get((q["package"]["ecosystem"], q["package"]["name"], q["version"])) or [[]]
                i = int(q.get("page_token") or 0)
                r = {"vulns": pages[i]} if pages[i] else {}
                if i + 1 < len(pages):
                    r["next_page_token"] = str(i + 1)
                results.append(r)
            return {"results": results}
        if url.startswith(cti.OSV_VULN_URL):
            return details.get(urllib.parse.unquote(url[len(cti.OSV_VULN_URL):]))
        return None
    return route


def vuln(oid, modified="2026-09-20T00:00:00Z"):
    return {"id": oid, "modified": modified}


def pkg(name, version, source=None, source_version=None):
    return {"name": name, "version": version, "source": source or name, "source_version": source_version or version,
            "arch": "amd64"}


def probe(packages, running="6.8.0-139.139", installed=("6.8.0-139.139",), os_id="ubuntu", version_id="24.04",
          collected_at="2026-09-25T02:50:00+00:00"):
    return {"probe_version": 1, "hostname": "opsloop-web-01", "collected_at": collected_at,
            "os": {"id": os_id, "version_id": version_id, "codename": "noble", "pretty": "Ubuntu 24.04.5 LTS"},
            "kernel": {"running": "6.8.0-139-generic", "running_package": "linux-image-6.8.0-139-generic",
                       "running_version": running,
                       "installed": [{"package": f"linux-image-{v.rsplit('.', 1)[0]}-generic", "version": v}
                                     for v in installed]},
            "packages": packages, "images": [], "errors": []}


def bundle(assets, **extra):
    doc = {"schema": "opsloop-assets/1", "collected_by": "collect-assets.sh", "sent_at": "2026-09-25T02:55:00Z",
           "assets": assets}
    doc.update(extra)
    return json.dumps(doc).encode("utf-8")


# ── 시험 ───────────────────────────────────────────────────────────────────────

class DpkgCompareTest(unittest.TestCase):
    def test_계약의_네_쌍(self):
        for a, b in (("1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.19"),
                     ("1.9.15p5-3ubuntu5.24.04.2", "1.9.15p5-3ubuntu5.24.04.3"),
                     ("6.8.0-139.139", "6.8.0-142.142"), ("1.0~rc1", "1.0")):
            self.assertLess(cti.dpkg_compare(a, b), 0, (a, b))
            self.assertGreater(cti.dpkg_compare(b, a), 0, (a, b))

    def test_에포크_리비전_물결표_같음(self):
        self.assertGreater(cti.dpkg_compare("1:1.0", "9.9"), 0)          # 에포크가 먼저
        self.assertEqual(cti.dpkg_compare("1.0", "0:1.0"), 0)             # 에포크 0 은 없는 것과 같다
        self.assertEqual(cti.dpkg_compare("1.01", "1.1"), 0)              # 숫자 토막의 앞 0 무시
        self.assertLess(cti.dpkg_compare("1.0-1", "1.0-1ubuntu1"), 0)
        self.assertLess(cti.dpkg_compare("1.0~~", "1.0~"), 0)
        self.assertLess(cti.dpkg_compare("1.0~", "1.0"), 0)
        self.assertLess(cti.dpkg_compare("1.0", "1.0a"), 0)               # 끝 < 문자
        self.assertLess(cti.dpkg_compare("1.0a", "1.0+"), 0)              # 문자 < 기호
        self.assertLess(cti.dpkg_compare("2.30-0ubuntu2", "2.30-0ubuntu10"), 0)

    def test_정렬(self):
        vs = ["6.8.0-142.142", "6.8.0-139.139", "6.8.0-45.45", "6.8.0-139.139~22.04.1"]
        self.assertEqual(sorted(vs, key=cti.dpkg_key),
                         ["6.8.0-45.45", "6.8.0-139.139~22.04.1", "6.8.0-139.139", "6.8.0-142.142"])


class ParseTest(unittest.TestCase):
    def test_시각(self):
        utc = timezone.utc
        self.assertEqual(cti.parse_ts("2026-09-23T17:03:57.2317Z"), datetime(2026, 9, 23, 17, 3, 57, 231700, utc))
        self.assertEqual(cti.parse_ts("2024-07-01T12:00:00.123456789Z"), datetime(2024, 7, 1, 12, 0, 0, 123456, utc))
        self.assertEqual(cti.parse_ts("2024-07-01T13:15:10.683"), datetime(2024, 7, 1, 13, 15, 10, 683000, utc))
        self.assertEqual(cti.parse_ts("2026-09-25T11:50:00+09:00"), datetime(2026, 9, 25, 2, 50, tzinfo=utc))
        self.assertEqual(cti.parse_ts("2026-09-24"), datetime(2026, 9, 24, tzinfo=utc))
        for bad in ("어제", "2026-13-01T00:00:00Z", "", None, 17, "2026-09-24T12:00:00Zjunk"):
            self.assertIsNone(cti.parse_ts(bad), bad)

    def test_달력_끝_시각과_큰_시간대는_예외가_아니라_None(self):
        # UTC 로 바꾸면 1년 1월 1일 앞 · 9999년 뒤로 넘친다 (OverflowError). 24시간 넘는 시간대는 ValueError
        for bad in ("0001-01-01T00:00:00+09:00", "9999-12-31T23:59:59-09:00", "2026-09-25T00:00:00+99:00",
                    "2026-09-25T00:00:00-24:00"):
            self.assertIsNone(cti.parse_ts(bad), bad)
        self.assertEqual(cti.parse_ts("0001-01-01T09:00:00+09:00"), datetime(1, 1, 1, tzinfo=timezone.utc))

    def test_로그용_값은_제어_문자와_대리_문자를_바꾼다(self):
        self.assertEqual(cti.safe("a\nb\ud800c\udfff"), "a?b?c?")
        cti.safe("x\ud800" * 10).encode("utf-8")

    def test_C1_제어_문자도_로그와_오류_문구에서_지운다(self):
        # U+009B(CSI)는 C1 을 제어로 읽는 터미널에서 ESC [ 와 같다. collect-assets.sh 가 적재기 출력을 운영자
        # 터미널에 그대로 찍으므로, 노드가 넣은 C1 이 로그 · 오류 문구에 남으면 줄을 지우거나 덮어쓸 수 있다
        self.assertEqual(cti.safe("x\x9b1A\x9b2K y\x85z"), "x?1A?2K y?z")
        self.assertEqual(cti.error_text("a\x9bb", "error"), "a b")
        with self.assertRaises(ValueError) as e:
            cti.text("sudo\x9b31m", "packages.name", pattern=cti.PKG_RE)
        self.assertNotIn("\x9b", str(e.exception))

    def test_UBUNTU_CVE_id_만_CVE_가_된다(self):
        self.assertEqual(cti.cve_from_id("UBUNTU-CVE-2024-6387"), "CVE-2024-6387")
        self.assertIsNone(cti.cve_from_id("USN-6859-1"))
        self.assertIsNone(cti.cve_from_id("UBUNTU-CVE-24-1"))


class KevTest(unittest.TestCase):
    def test_파싱_틀린_항목은_건너뛴다(self):
        rows, meta = cti.parse_kev(json.dumps(kev_doc()).encode())
        self.assertEqual([r[0] for r in rows], ["CVE-2021-44228", "CVE-2022-24816", "CVE-2024-36401"])
        self.assertEqual(rows[2], ("CVE-2024-36401", "OSGeo", "GeoServer", "OSGeo GeoServer Eval Injection Vulnerability",
                                   "OSGeo GeoServer contains an eval injection vulnerability.", "2024-07-15",
                                   "2024-08-05", "Unknown"))
        self.assertEqual((meta["bad"], meta["version"]), (1, "2026.09.23"))
        self.assertEqual(meta["source_ts"], datetime(2026, 9, 23, 17, 3, 57, 231700, timezone.utc))

    def test_형식이_틀리면_실패(self):
        for body in (b"<html>", json.dumps({"x": 1}).encode(), json.dumps(kev_doc([])).encode(),
                     json.dumps(kev_doc([{"cveID": "CVE-2024-1", "vendorProject": "a"}])).encode()):
            with self.assertRaises(cti.CtiError):
                cti.parse_kev(body)
        rows, _ = cti.parse_kev(json.dumps(kev_doc([
            {"cveID": "CVE-2024-0001", "vendorProject": "a", "product": "b", "vulnerabilityName": "c",
             "dateAdded": "2024/01/01"},
            {"cveID": "CVE-2024-0002", "vendorProject": "a", "product": "b", "vulnerabilityName": "c",
             "dateAdded": "2024-01-01", "dueDate": ""}])).encode())
        self.assertEqual([(r[0], r[6]) for r in rows], [("CVE-2024-0002", None)])


class EpssTest(unittest.TestCase):
    ROWS = [("CVE-2024-6387", "0.99506", "0.99944"), ("CVE-2021-44228", "0.94358", "0.99962"),
            ("CVE-1999-0001", "0.01", "0.5"), ("not-a-cve", "0.1", "0.1"), ("CVE-2020-0001", "1.5", "0.3"),
            ("CVE-2020-0002", "nan", "0.3")]

    def test_관심_CVE_만_모으고_줄은_모두_센다(self):
        meta, rows, count = cti.parse_epss(epss_gz(self.ROWS), want={"CVE-2024-6387", "CVE-2099-0001"})
        self.assertEqual(meta, {"model_version": "v2026.06.15",
                                "score_date": datetime(2026, 9, 24, 12, 0, 20, tzinfo=timezone.utc)})
        self.assertEqual(rows, {"CVE-2024-6387": (0.99506, 0.99944)})
        self.assertEqual(count, 3)                       # 틀린 줄 3개는 세지 않는다
        _, everything, _ = cti.parse_epss(epss_gz(self.ROWS))
        self.assertEqual(len(everything), 3)

    def test_형식이_틀리면_실패(self):
        for body in (b"not gzip", gzip.compress(b"cve,epss,percentile\n"), epss_gz(self.ROWS, header="cve,score"),
                     epss_gz([]), epss_gz(self.ROWS)[:-8]):
            with self.assertRaises(cti.CtiError):
                cti.parse_epss(body)

    def test_줄바꿈_없는_큰_입력은_메모리에_올리기_전에_멈춘다(self):
        # 풀면 32 MiB 인 한 줄 (압축 수십 KiB). 줄 전체를 만든 뒤 크기를 세면 그만큼 메모리를 먼저 쓴다
        body = gzip.compress(b"#model_version:v1,score_date:2026-09-24T12:00:20Z\ncve,epss,percentile\n"
                             + b"A" * (32 * cti.MIB))
        tracemalloc.start()
        try:
            with self.assertRaisesRegex(cti.CtiError, "EPSS 줄 하나가 256자를 넘는다"):
                cti.parse_epss(body)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 4 * cti.MIB)
        # 마지막 줄에 줄바꿈이 없어도 짧으면 읽는다
        meta, rows, count = cti.parse_epss(gzip.compress(
            b"#model_version:v1,score_date:2026-09-24T12:00:20Z\ncve,epss,percentile\nCVE-2024-6387,0.9,0.99"))
        self.assertEqual((rows, count), ({"CVE-2024-6387": (0.9, 0.99)}, 1))

    def test_사본과_채움(self):
        home = tempfile.mkdtemp()
        body = epss_gz(self.ROWS)
        p = cti.Payload(body, "csv.gz", cti.EPSS_URL, {"meta": cti.parse_epss(body)[0]})
        ctx = ctx_for(FakeConn(), home=home)
        cti.save_epss_copy(ctx, 7, p)
        with open(os.path.join(home, cti.EPSS_META)) as f:
            self.assertEqual(json.load(f), {"snapshot_id": 7, "score_date": "2026-09-24T12:00:20Z",
                                            "model_version": "v2026.06.15"})
        conn = FakeConn(answers=[("epss IS NOT NULL", [("CVE-2021-44228",)]),
                                 ("FROM cti_snapshots WHERE id", [(1,)])])
        ctx = ctx_for(conn, home=home)
        n = cti.epss_fill(ctx, conn.cursor(), {"CVE-2024-6387", "CVE-2021-44228", "CVE-2099-0001"})
        self.assertEqual(n, 1)
        sql, params = conn.pending[-1]
        self.assertTrue(sql.startswith("INSERT INTO cti_cve"))
        self.assertEqual(params, ("2026-09-24", 7, ["CVE-2024-6387"], [0.99506], [0.99944]))

    def test_사본이_없거나_기록이_없으면_채우지_않는다(self):
        conn = FakeConn()
        self.assertEqual(cti.epss_fill(ctx_for(conn), conn.cursor(), {"CVE-2024-6387"}), 0)
        home = tempfile.mkdtemp()
        body = epss_gz(self.ROWS)
        cti.save_epss_copy(ctx_for(conn, home=home), 7, cti.Payload(body, "csv.gz", "", {"meta": cti.parse_epss(body)[0]}))
        conn = FakeConn()        # cti_snapshots 에 그 id 가 없다 (DB 를 복원했다 등) → 참조 키가 깨지므로 넣지 않는다
        self.assertEqual(cti.epss_fill(ctx_for(conn, home=home), conn.cursor(), {"CVE-2024-6387"}), 0)
        self.assertFalse(any(s.startswith("INSERT") for s, _ in conn.pending))


class S3Test(unittest.TestCase):
    def test_키_모양(self):
        key, sha = cti.s3_key("kev", b"{}", "json", datetime(2026, 9, 25, 23, 30, tzinfo=timezone(timedelta(hours=9))))
        self.assertEqual(sha, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        self.assertEqual(key, "cti/v1/source=kev/date=2026-09-25/44136fa355b3678a.json")   # UTC 날짜

    def test_한_번_쓰기_412_는_이미_있음(self):
        s3 = FakeS3()
        self.assertTrue(cti.put_once(s3, "b", "cti/v1/x.json", b"1", "application/json", {"sha256": "x"}))
        self.assertFalse(cti.put_once(s3, "b", "cti/v1/x.json", b"1", "application/json", {"sha256": "x"}))
        self.assertEqual(s3.calls[0]["ChecksumAlgorithm"], "SHA256")
        for err in (S3Error("412"),):
            self.assertFalse(cti.put_once(FakeS3(fail=err), "b", "k", b"", "t", {}))
        with self.assertRaises(S3Error):
            cti.put_once(FakeS3(fail=S3Error("AccessDenied")), "b", "k", b"", "t", {})

    def test_서명_직전_훅은_cti_경로에만_조건을_붙인다(self):
        class Req:
            def __init__(self, url):
                self.url, self.headers = url, {}
        for url, want in (("https://b.s3.ap-northeast-2.amazonaws.com/cti/v1/source=kev/x.json", "*"),
                          ("https://s3.ap-northeast-2.amazonaws.com/b/cti/v1/source=kev/x.json", "*"),
                          ("https://b.s3.ap-northeast-2.amazonaws.com/raw/v1/x.jsonl", None),
                          ("https://b.s3.ap-northeast-2.amazonaws.com/hb/v1/host=i-1/latest.json", None)):
            r = Req(url)
            cti.cti_if_none_match(r)
            self.assertEqual(r.headers.get("If-None-Match"), want, url)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, script):
        self.script, self.requests = list(script), []

    def open(self, req, timeout):
        self.requests.append((req, timeout))
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return FakeResponse(step)


class HttpTest(unittest.TestCase):
    def http(self, script):
        sleeps = []
        opener = FakeOpener(script)
        return cti.Http(opener=opener, sleep=sleeps.append), opener, sleeps

    def err(self, code):
        return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))

    def test_UA_를_붙이고_5xx_는_두_번_더(self):
        h, opener, sleeps = self.http([self.err(503), self.err(502), b'{"ok": 1}'])
        self.assertEqual(h.get_json("https://x/a", 100), {"ok": 1})
        self.assertEqual(sleeps, [5, 20])
        req, timeout = opener.requests[0]
        self.assertEqual((req.get_header("User-agent"), timeout), ("OpsLoop-CTI/1", 60))

    def test_시간_초과도_두_번까지_그다음은_실패(self):
        h, _, sleeps = self.http([TimeoutError(), urllib.error.URLError(TimeoutError()), TimeoutError()])
        with self.assertRaisesRegex(cti.CtiError, "시간 초과"):
            h.fetch("https://x/a", 100)
        self.assertEqual(sleeps, [5, 20])

    def test_4xx_와_연결_실패는_다시_하지_않는다(self):
        for step in (self.err(403), urllib.error.URLError(ConnectionRefusedError()), ConnectionResetError()):
            h, opener, sleeps = self.http([step, b"never"])
            with self.assertRaises(cti.CtiError):
                h.fetch("https://x/a", 100)
            self.assertEqual((sleeps, len(opener.requests)), ([], 1))

    def test_크기_상한(self):
        h, _, _ = self.http([b"x" * 11])
        with self.assertRaisesRegex(cti.CtiError, "상한"):
            h.fetch("https://x/a", 10)
        h, _, _ = self.http([b"x" * 10])
        self.assertEqual(h.fetch("https://x/a", 10), b"x" * 10)

    def test_POST_JSON(self):
        h, opener, _ = self.http([b'{"results": []}'])
        h.post_json(cti.OSV_BATCH_URL, {"queries": []}, 100)
        req = opener.requests[0][0]
        self.assertEqual((req.get_method(), req.data, req.get_header("Content-type")),
                         ("POST", b'{"queries":[]}', "application/json"))


class RunSourceTest(unittest.TestCase):
    """원본을 S3 에 남긴 회차만 DB 를 고친다."""

    def kev_http(self):
        return FakeHttp({cti.KEV_URL: kev_doc()})

    def test_정상_회차는_원본_기록과_정규화를_한_트랜잭션에(self):
        conn, s3 = FakeConn(), FakeS3()
        self.assertTrue(cti.fetch_kev(ctx_for(conn, s3=s3, http=self.kev_http())))
        body = json.dumps(kev_doc()).encode()
        key, sha = cti.s3_key("kev", body, "json", T0)
        self.assertRegex(key, r"^cti/v1/source=kev/date=2026-09-25/[0-9a-f]{16}\.json$")
        call = s3.calls[0]
        self.assertEqual((call["Key"], call["Bucket"], call["ContentType"], call["ChecksumAlgorithm"]),
                         (key, "opsloop-archive-test", "application/json", "SHA256"))
        self.assertEqual(call["Metadata"], {"source-url": cti.KEV_URL, "fetched-at": "2026-09-25T03:00:00Z",
                                            "sha256": sha})
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["s3_key"], snap["sha256"], snap["bytes"], snap["records"],
                          snap["source_version"], snap["error"]), ("ok", key, sha, len(body), 3, "2026.09.23", None))
        writes = [s.split(" (")[0] for s, _ in conn.writes()]
        self.assertEqual(writes, ["INSERT INTO cti_snapshots", "INSERT INTO cti_kev", "DELETE FROM cti_kev WHERE cve_id <> ALL(%s::text[])"])
        upsert = conn.writes()[1][1]
        self.assertEqual(upsert[0], 101)                                   # 원본 기록 id
        self.assertEqual(upsert[1], ["CVE-2021-44228", "CVE-2022-24816", "CVE-2024-36401"])
        self.assertEqual(upsert[6], ["2021-12-10", "2024-06-26", "2024-07-15"])

    def test_S3_에_못_쓰면_실패_기록만_남기고_DB_를_고치지_않는다(self):
        conn = FakeConn()
        self.assertFalse(cti.fetch_kev(ctx_for(conn, s3=FakeS3(fail=S3Error("AccessDenied")), http=self.kev_http())))
        self.assertEqual(len(conn.writes()), 1)
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["s3_key"], snap["records"]), ("failed", None, 3))
        self.assertRegex(snap["error"], "^원본 보관\\(S3\\) 실패: S3Error: AccessDenied")
        self.assertRegex(snap["sha256"], "^[0-9a-f]{64}$")
        self.assertFalse(any("cti_kev" in s for s, _ in conn.committed))

    def test_412_는_이미_보관된_같은_내용이라_성공(self):
        conn, s3 = FakeConn(), FakeS3()
        ctx = ctx_for(conn, s3=s3, http=self.kev_http())
        self.assertTrue(cti.fetch_kev(ctx))
        self.assertTrue(cti.fetch_kev(ctx))
        self.assertEqual((len(s3.calls), len(s3.objs)), (2, 1))
        self.assertEqual([p["status"] for p in conn.snapshots()], ["ok", "ok"])

    def test_받기_실패는_S3_도_DB_도_건드리지_않는다(self):
        conn, s3 = FakeConn(), FakeS3()
        self.assertFalse(cti.fetch_kev(ctx_for(conn, s3=s3, http=FakeHttp({cti.KEV_URL: cti.CtiError("HTTP 403: x")}))))
        self.assertEqual(s3.calls, [])
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["error"], snap["sha256"]), ("failed", "받기 · 검증 실패: HTTP 403: x", None))

    def test_정규화_중_DB_오류면_되돌리고_실패_기록(self):
        conn = FakeConn(fail_on=["DELETE FROM cti_kev"])
        self.assertFalse(cti.fetch_kev(ctx_for(conn, http=self.kev_http())))
        self.assertEqual([p["status"] for p in conn.snapshots()], ["failed"])
        self.assertFalse(any("cti_kev" in s for s, _ in conn.committed))
        self.assertIn("DB 갱신 실패", conn.snapshots()[0]["error"])

    def test_EPSS_는_관심_CVE_만_넣고_gz_원본을_보관한다(self):
        answers = [("UNION SELECT cve_id FROM cti_cve", [("CVE-2021-44228",), ("junk",)]),
                   ("FROM rule_versions", [("c1", load_rules())])]
        conn, s3, home = FakeConn(answers=answers), FakeS3(), tempfile.mkdtemp()
        body = epss_gz(EpssTest.ROWS + [("CVE-2021-41773", "0.94", "0.99"), ("CVE-2099-0002", "0.2", "0.2")])
        self.assertTrue(cti.fetch_epss(ctx_for(conn, s3=s3, http=FakeHttp({cti.EPSS_URL: body}), home=home)))
        self.assertTrue(s3.calls[0]["Key"].endswith(".csv.gz"))
        self.assertEqual((s3.calls[0]["Body"], s3.calls[0]["ContentType"]), (body, "application/gzip"))
        snap = conn.snapshots()[0]
        self.assertEqual((snap["records"], snap["source_version"]), (5, "v2026.06.15"))
        upsert = [p for s, p in conn.writes() if s.startswith("INSERT INTO cti_cve")][0]
        self.assertEqual(upsert[:3], ("2026-09-24", 101, ["CVE-2021-41773", "CVE-2021-44228"]))   # KEV · 서명만
        with open(os.path.join(home, cti.EPSS_COPY), "rb") as f:
            self.assertEqual(f.read(), body)


class OsvPlanTest(unittest.TestCase):
    def test_생태계(self):
        self.assertEqual(cti.osv_ecosystem({"id": "ubuntu", "version_id": "24.04"}), "Ubuntu:24.04:LTS")
        self.assertEqual(cti.osv_ecosystem({"id": "ubuntu", "version_id": "22.04"}), "Ubuntu:22.04:LTS")
        self.assertEqual(cti.osv_ecosystem({"id": "ubuntu", "version_id": "25.04"}), "Ubuntu:25.04")
        self.assertEqual(cti.osv_ecosystem({"id": "ubuntu", "version_id": "24.10"}), "Ubuntu:24.10")
        for bad in ({"id": "debian", "version_id": "12"}, {"id": "ubuntu"}, None, {"id": "ubuntu", "version_id": "24.04 x"}):
            self.assertIsNone(cti.osv_ecosystem(bad))

    def test_커널_바이너리는_빼고_실행_중_커널을_묻는다(self):
        pkgs = [pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh"),
                pkg("openssh-client", "1:9.6p1-3ubuntu13.19", "openssh"),
                pkg("linux-image-6.8.0-139-generic", "6.8.0-139.139", "linux-signed"),
                pkg("linux-image-6.8.0-142-generic", "6.8.0-142.142", "linux-signed"),
                pkg("linux-modules-6.8.0-139-generic", "6.8.0-139.139", "linux"),
                pkg("linux-headers-generic", "6.8.0-142.142", "linux-meta"),
                pkg("linux-tools-common", "6.8.0-142.142", "linux"),
                pkg("linux-firmware", "20240318.git3b128b60-0ubuntu2.19")]
        installed = [{"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"},
                     {"package": "linux-image-6.8.0-142-generic", "version": "6.8.0-142.142"}]
        plan, err = cti.osv_plan({"id": "ubuntu", "version_id": "24.04"},
                                 {"running": "6.8.0-139-generic", "running_package": "linux-image-6.8.0-139-generic",
                                  "running_version": "6.8.0-139.139", "installed": installed}, pkgs)
        self.assertIsNone(err)
        self.assertEqual(plan, {"eco": ECO, "kernel": "linux", "running": "6.8.0-139.139", "newest": "6.8.0-142.142",
                                "queries": [("linux-firmware", "20240318.git3b128b60-0ubuntu2.19"),
                                            ("openssh", "1:9.6p1-3ubuntu13.19")]})
        plan, _ = cti.osv_plan({"id": "ubuntu", "version_id": "24.04"},
                               {"running": "6.8.0-142-generic", "running_package": "linux-image-6.8.0-142-generic",
                                "running_version": "6.8.0-142.142", "installed": installed}, pkgs)
        self.assertIsNone(plan["newest"])                   # 가장 높은 커널로 돌고 있다

    def test_대조_못_하는_자산(self):
        self.assertEqual(cti.osv_plan({"id": "debian", "version_id": "12"}, None, [pkg("a", "1")]),
                         (None, "지원하지 않는 배포판"))
        self.assertEqual(cti.osv_plan({"id": "ubuntu", "version_id": "24.04"}, None, []), (None, "패키지 목록이 없다"))


# Canonical Ubuntu 24.04 AMI(관문 · 허니팟) 식 커널 패키지. probe.py 가 만드는 모양 그대로다
AWS_PACKAGES = [pkg("linux-image-6.8.0-1036-aws", "6.8.0-1036.38", "linux-signed-aws"),
                pkg("linux-image-6.8.0-1040-aws", "6.8.0-1040.42", "linux-signed-aws"),
                pkg("linux-modules-6.8.0-1036-aws", "6.8.0-1036.38", "linux-aws"),
                pkg("linux-modules-6.8.0-1040-aws", "6.8.0-1040.42", "linux-aws"),
                pkg("linux-headers-6.8.0-1036-aws", "6.8.0-1036.38", "linux-aws"),
                pkg("linux-aws-headers-6.8.0-1036", "6.8.0-1036.38", "linux-aws"),
                pkg("linux-aws-tools-6.8.0-1036", "6.8.0-1036.38", "linux-aws"),
                pkg("linux-aws", "6.8.0.1040.42", "linux-meta-aws"),
                pkg("linux-headers-aws", "6.8.0.1040.42", "linux-meta-aws"),
                pkg("linux-image-aws", "6.8.0.1040.42", "linux-meta-aws"),
                pkg("linux-libc-dev", "6.8.0-142.142", "linux"),
                pkg("linux-firmware", "20240318.git3b128b60-0ubuntu2.19"),
                pkg("linux-base", "4.5ubuntu9+24.04.1"),
                pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2")]
AWS_KERNEL = {"running": "6.8.0-1036-aws", "running_package": "linux-image-6.8.0-1036-aws",
              "running_version": "6.8.0-1036.38",
              "installed": [{"package": "linux-image-6.8.0-1036-aws", "version": "6.8.0-1036.38"},
                            {"package": "linux-image-6.8.0-1040-aws", "version": "6.8.0-1040.42"}]}


class KernelSourceTest(unittest.TestCase):
    """커널 소스 규칙 (계약 10.5). AWS 커널은 linux 가 아니라 linux-aws 로 묻는다 (OSV 기록 집합이 다르다)."""

    def ksrc(self, running_package, packages, running=None):
        return cti.kernel_source({"running": running, "running_package": running_package}, packages)

    def test_실행_중_이미지의_소스에서_얻는다(self):
        self.assertEqual(cti.kernel_source(AWS_KERNEL, AWS_PACKAGES), "linux-aws")
        generic = [pkg("linux-image-6.8.0-139-generic", "6.8.0-139.139", "linux-signed")]
        self.assertEqual(self.ksrc("linux-image-6.8.0-139-generic", generic), "linux")
        hwe = [pkg("linux-image-6.8.0-52-generic", "6.8.0-52.53~22.04.1", "linux-signed-hwe-6.8")]
        self.assertEqual(self.ksrc("linux-image-6.8.0-52-generic", hwe), "linux-hwe-6.8")
        meta = [pkg("linux-image-x", "1", "linux-meta-aws")]
        self.assertEqual(self.ksrc("linux-image-x", meta), "linux-aws")
        unsigned = [pkg("linux-image-unsigned-6.8.0-1036-aws", "6.8.0-1036.38", "linux-aws")]
        self.assertEqual(self.ksrc("linux-image-unsigned-6.8.0-1036-aws", unsigned), "linux-aws")

    def test_못_찾으면_모듈_패키지_그래도_없으면_linux(self):
        mods = [pkg("linux-modules-6.8.0-1036-aws", "6.8.0-1036.38", "linux-aws")]
        self.assertEqual(self.ksrc(None, mods, running="6.8.0-1036-aws"), "linux-aws")
        self.assertEqual(self.ksrc("linux-image-6.8.0-1036-aws", mods, running="6.8.0-1036-aws"), "linux-aws")
        self.assertEqual(self.ksrc(None, [], running="6.8.0-1036-aws"), "linux")
        self.assertEqual(cti.kernel_source(None, None), "linux")
        # 이미지 패키지의 소스가 커널 소스가 아니면 믿지 않는다 (비신뢰 자산이 openssh 로 적어도)
        self.assertEqual(self.ksrc("linux-image-x", [pkg("linux-image-x", "1", "openssh")]), "linux")
        self.assertEqual(self.ksrc("linux-image-x", [pkg("linux-image-x", "1", "linux-firmware")]), "linux")

    def test_커널_판별(self):
        kernel = ["linux-image-6.8.0-1036-aws", "linux-modules-6.8.0-1036-aws", "linux-headers-6.8.0-1036-aws",
                  "linux-aws-headers-6.8.0-1036", "linux-aws-tools-6.8.0-1036", "linux-aws", "linux-headers-aws",
                  "linux-image-aws", "linux-libc-dev"]
        other = ["linux-firmware", "linux-base", "sudo"]
        by_name = {p["name"]: p for p in AWS_PACKAGES}
        for name in kernel:
            self.assertTrue(cti.is_kernel_package(by_name[name]), name)
        for name in other:
            self.assertFalse(cti.is_kernel_package(by_name[name]), name)
        for src in ("linux", "linux-aws", "linux-signed-aws", "linux-meta-aws", "linux-hwe-6.8", "linux-azure-fde",
                    "linux-restricted-modules-aws"):
            self.assertTrue(cti.is_kernel_source(src), src)
        for src in ("linux-firmware", "linux-firmware-raspi", "linux-base", "linux-atm", "linuxlogo", "openssh", None,
                    "linux-AWS", "linux-"):
            self.assertFalse(cti.is_kernel_source(src), src)
        self.assertFalse(cti.is_kernel_package(pkg("libatm1", "1:2.5.1-5.1build1", "linux-atm")))

    def test_재부팅_대기_비교는_같은_판의_이미지만(self):
        self.assertEqual(cti.newest_kernel(AWS_KERNEL), "6.8.0-1040.42")
        # generic 142 가 함께 깔려 있어도 aws 판과 견주지 않는다 (소스가 다르다)
        mixed = dict(AWS_KERNEL, installed=AWS_KERNEL["installed"][:1] + [
            {"package": "linux-image-6.8.0-142-generic", "version": "6.8.0-142.142"}])
        self.assertEqual(cti.newest_kernel(mixed), "6.8.0-1036.38")
        generic = {"running": "6.8.0-139-generic",
                   "installed": [{"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"},
                                 {"package": "linux-image-6.8.0-1040-aws", "version": "6.8.0-1040.42"},
                                 {"package": "linux-image-6.8.0-139-generic-64k", "version": "6.8.0-139.140"}]}
        self.assertEqual(cti.newest_kernel(generic), "6.8.0-139.139")
        self.assertIsNone(cti.newest_kernel({"running": "custom", "installed": generic["installed"]}))
        self.assertIsNone(cti.newest_kernel(None))

    def test_AWS_자산의_질의_계획(self):
        plan, err = cti.osv_plan({"id": "ubuntu", "version_id": "24.04"}, AWS_KERNEL, AWS_PACKAGES)
        self.assertIsNone(err)
        # 커널 바이너리 · 메타 · linux-libc-dev(소스 linux)는 빼고, 펌웨어 · linux-base 는 여느 패키지처럼 묻는다
        self.assertEqual(plan, {"eco": ECO, "kernel": "linux-aws", "running": "6.8.0-1036.38", "newest": "6.8.0-1040.42",
                                "queries": [("linux-base", "4.5ubuntu9+24.04.1"),
                                            ("linux-firmware", "20240318.git3b128b60-0ubuntu2.19"),
                                            ("sudo", "1.9.15p5-3ubuntu5.24.04.2")]})

    def test_AWS_커널의_fix_state_는_linux_aws_기록으로(self):
        plan = {"eco": ECO, "queries": [("sudo", "1.9.15p5-3ubuntu5.24.04.2")], "kernel": "linux-aws",
                "running": "6.8.0-1036.38", "newest": "6.8.0-1040.42"}
        results = {(ECO, "linux-aws", "6.8.0-1036.38"): [("UBUNTU-CVE-2024-1086", None), ("UBUNTU-CVE-2026-53266", None),
                                                         ("UBUNTU-CVE-2025-0001", None)],
                   (ECO, "linux-aws", "6.8.0-1040.42"): [("UBUNTU-CVE-2026-53266", None), ("UBUNTU-CVE-2025-0001", None)],
                   # generic 쪽 결과는 쓰지 않는다
                   (ECO, "linux", "6.8.0-1036.38"): [("UBUNTU-CVE-2099-0001", None)]}
        info = {"UBUNTU-CVE-2026-53266": {"cve_id": "CVE-2026-53266", "detailed": True,
                                          "fixed": {f"{ECO}/linux": "6.8.0-150.150"}},        # 다른 소스의 수정판
                "UBUNTU-CVE-2025-0001": {"cve_id": "CVE-2025-0001", "detailed": True,
                                         "fixed": {f"{ECO}/linux-aws": "6.8.0-1041.43"}}}
        rows = cti.asset_vuln_rows(plan, results, info)
        self.assertEqual(rows, [
            ("linux-aws", "6.8.0-1036.38", "UBUNTU-CVE-2024-1086", "CVE-2024-1086", "reboot_pending", "6.8.0-1040.42"),
            ("linux-aws", "6.8.0-1036.38", "UBUNTU-CVE-2025-0001", "CVE-2025-0001", "fix_available", "6.8.0-1041.43"),
            ("linux-aws", "6.8.0-1036.38", "UBUNTU-CVE-2026-53266", "CVE-2026-53266", "no_fix", None)])


class FixStateTest(unittest.TestCase):
    PLAN = {"eco": ECO, "queries": [("openssh", "1:9.6p1-3ubuntu13.2"), ("sudo", "1.9.15p5-3ubuntu5.24.04.2")],
            "kernel": "linux", "running": "6.8.0-139.139", "newest": "6.8.0-142.142"}
    RESULTS = {
        (ECO, "openssh", "1:9.6p1-3ubuntu13.2"): [("UBUNTU-CVE-2024-6387", None), ("USN-6859-1", None)],
        (ECO, "sudo", "1.9.15p5-3ubuntu5.24.04.2"): [("UBUNTU-CVE-2026-82474", None), ("UBUNTU-CVE-2026-0001", None)],
        (ECO, "linux", "6.8.0-139.139"): [("UBUNTU-CVE-2024-1111", None), ("UBUNTU-CVE-2024-2222", None),
                                          ("UBUNTU-CVE-2024-3333", None), ("OSV-2024-9", None)],
        (ECO, "linux", "6.8.0-142.142"): [("UBUNTU-CVE-2024-2222", None), ("OSV-2024-9", None)],
    }
    INFO = {"UBUNTU-CVE-2024-6387": {"cve_id": "CVE-2024-6387", "detailed": True,
                                     "fixed": {f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3"}},
            "UBUNTU-CVE-2026-82474": {"cve_id": "CVE-2026-82474", "detailed": True,
                                      "fixed": {"Ubuntu:22.04:LTS/sudo": "1.9.9-1ubuntu2.5"}},
            "UBUNTU-CVE-2024-1111": {"cve_id": "CVE-2024-1111", "detailed": True,
                                     "fixed": {f"{ECO}/linux": "6.8.0-140.140"}},
            "OSV-2024-9": {"cve_id": "CVE-2024-9999", "detailed": True, "fixed": {}}}

    def test_네_가지_상태와_USN_제외(self):
        rows = cti.asset_vuln_rows(self.PLAN, self.RESULTS, self.INFO)
        self.assertEqual(rows, [
            ("linux", "6.8.0-139.139", "OSV-2024-9", "CVE-2024-9999", "no_fix", None),
            ("linux", "6.8.0-139.139", "UBUNTU-CVE-2024-1111", "CVE-2024-1111", "reboot_pending", "6.8.0-142.142"),
            ("linux", "6.8.0-139.139", "UBUNTU-CVE-2024-2222", "CVE-2024-2222", "unknown", None),
            ("linux", "6.8.0-139.139", "UBUNTU-CVE-2024-3333", "CVE-2024-3333", "reboot_pending", "6.8.0-142.142"),
            ("openssh", "1:9.6p1-3ubuntu13.2", "UBUNTU-CVE-2024-6387", "CVE-2024-6387", "fix_available", "1:9.6p1-3ubuntu13.3"),
            ("sudo", "1.9.15p5-3ubuntu5.24.04.2", "UBUNTU-CVE-2026-0001", "CVE-2026-0001", "unknown", None),
            ("sudo", "1.9.15p5-3ubuntu5.24.04.2", "UBUNTU-CVE-2026-82474", "CVE-2026-82474", "no_fix", None),
        ])

    def test_가장_높은_커널로_돌면_재부팅_대기가_없다(self):
        plan = dict(self.PLAN, newest=None)
        rows = {r[2]: r[4] for r in cti.asset_vuln_rows(plan, self.RESULTS, self.INFO) if r[0] == "linux"}
        self.assertEqual(rows, {"OSV-2024-9": "no_fix", "UBUNTU-CVE-2024-1111": "fix_available",
                                "UBUNTU-CVE-2024-2222": "unknown", "UBUNTU-CVE-2024-3333": "unknown"})

    def test_같은_소스가_두_버전이면_낮은_쪽(self):
        plan = {"eco": ECO, "queries": [("openssl", "3.0.13-0ubuntu3.4"), ("openssl", "3.0.13-0ubuntu3.15")],
                "kernel": "linux", "running": None, "newest": None}
        results = {(ECO, "openssl", "3.0.13-0ubuntu3.15"): [("UBUNTU-CVE-2024-5535", None)],
                   (ECO, "openssl", "3.0.13-0ubuntu3.4"): [("UBUNTU-CVE-2024-5535", None)]}
        rows = cti.asset_vuln_rows(plan, results, {})
        self.assertEqual(rows, [("openssl", "3.0.13-0ubuntu3.4", "UBUNTU-CVE-2024-5535", "CVE-2024-5535", "unknown", None)])


class OsvTest(unittest.TestCase):
    def test_쪽_나눔과_500개씩(self):
        queries = [(ECO, f"p{i:03d}", "1.0") for i in range(501)] + [(ECO, "linux", "6.8.0-139.139")]
        table = {(ECO, "linux", "6.8.0-139.139"): [[vuln("UBUNTU-CVE-2024-0001")], [vuln("UBUNTU-CVE-2024-0002")],
                                                   [vuln("UBUNTU-CVE-2024-0002"), vuln("bad id!")]],
                 (ECO, "p007", "1.0"): [[vuln("UBUNTU-CVE-2023-7777", "2026-09-01T00:00:00.123456789Z")]]}
        http = FakeHttp(osv_routes(table, {}))
        out = cti.osv_query(http, sorted(queries))
        self.assertEqual([len(sent["queries"]) for _, sent in http.calls], [500, 2, 1, 1])
        self.assertEqual(http.calls[2][1]["queries"][0]["page_token"], "1")
        self.assertEqual([i for i, _ in out[(ECO, "linux", "6.8.0-139.139")]],
                         ["UBUNTU-CVE-2024-0001", "UBUNTU-CVE-2024-0002"])
        self.assertEqual(out[(ECO, "p007", "1.0")],
                         [("UBUNTU-CVE-2023-7777", datetime(2026, 9, 1, 0, 0, 0, 123456, timezone.utc))])

    def test_쪽_상한과_결과_수가_다르면_실패(self):
        table = {(ECO, "linux", "1"): [[vuln("UBUNTU-CVE-2024-0001")]] * 5}
        with mock.patch.object(cti, "OSV_PAGES", 3), self.assertRaisesRegex(cti.CtiError, "쪽 수가 상한"):
            cti.osv_query(FakeHttp(osv_routes(table, {})), [(ECO, "linux", "1")])
        with self.assertRaisesRegex(cti.CtiError, "결과 수"):
            cti.osv_query(FakeHttp(lambda u, s: {"results": []}), [(ECO, "a", "1")])

    def test_상세를_받을_id(self):
        old = datetime(2026, 9, 1, tzinfo=timezone.utc)
        new = datetime(2026, 9, 20, tzinfo=timezone.utc)
        ids = {"UBUNTU-CVE-2024-0001": (new, True),     # 커널 밖 · 처음 → 받는다
               "UBUNTU-CVE-2024-0002": (old, True),     # 상세 있음 · 그대로 → 안 받는다
               "UBUNTU-CVE-2024-0003": (new, True),     # 상세 있음 · 바뀜 → 받는다
               "UBUNTU-CVE-2024-0004": (old, True),     # 상세 없이 넣어 둔 것(상한) → 받는다
               "UBUNTU-CVE-2024-0005": (new, False),    # 커널만 · KEV 아님 → 안 받는다
               "UBUNTU-CVE-2024-0006": (new, False),    # 커널만 · KEV → 받는다 (먼저)
               "OSV-2024-1": (new, True)}
        existing = {"UBUNTU-CVE-2024-0002": (old, True), "UBUNTU-CVE-2024-0003": (old, True),
                    "UBUNTU-CVE-2024-0004": (old, False)}
        self.assertEqual(cti.osv_need_detail(ids, existing, {"CVE-2024-0006", "CVE-2024-0003"}),
                         ["UBUNTU-CVE-2024-0003", "UBUNTU-CVE-2024-0006", "OSV-2024-1", "UBUNTU-CVE-2024-0001",
                          "UBUNTU-CVE-2024-0004"])

    def test_상세_기록_파싱(self):
        rec = {"id": "UBUNTU-CVE-2024-6387", "modified": "2026-09-20T01:02:03Z", "upstream": ["CVE-2024-6387"],
               "related": ["USN-6859-1"], "details": "x" * 700,
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                            {"type": "Ubuntu", "score": "high"}],
               "affected": [{"package": {"ecosystem": ECO, "name": "openssh"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.3"}]}]},
                            {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssh"},
                             "ranges": [{"events": [{"introduced": "0"}]}]}]}
        d = cti.osv_detail(rec)
        self.assertEqual((d["cve_id"], d["ubuntu_priority"], d["cvss_vector"][:8], len(d["summary"]), d["fixed"]),
                         ("CVE-2024-6387", "high", "CVSS:3.1", 500, {f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3"}))
        self.assertEqual(d["modified"], datetime(2026, 9, 20, 1, 2, 3, tzinfo=timezone.utc))
        # affected 는 수정판이 없는 영향 항목(22.04)까지 모두 담는다. fixed 는 수정판 있는 것만
        self.assertEqual(d["affected"], {f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3", "Ubuntu:22.04:LTS/openssh": None})
        d = cti.osv_detail({"id": "UBUNTU-CVE-2024-0001", "severity": [{"type": "Ubuntu", "score": "weird"}],
                            "affected": "junk", "upstream": "junk"})
        self.assertEqual((d["cve_id"], d["ubuntu_priority"], d["fixed"], d["summary"], d["affected"]),
                         ("CVE-2024-0001", None, {}, None, {}))

    def test_대조_한_회차_원본_문서와_DB_문장(self):
        packages = [pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")]
        assets = [("web-01", {"id": "ubuntu", "version_id": "24.04"},
                   {"running_version": "6.8.0-139.139", "installed": [{"package": "x", "version": "6.8.0-139.139"}]},
                   packages),
                  ("fw", {"id": "debian", "version_id": "12"}, None, packages)]
        conn = FakeConn(answers=[("FROM asset_inventory", assets), ("SELECT cve_id FROM cti_kev", [("CVE-2024-1111",)]),
                                 ("SELECT osv_id, modified, detailed", []),
                                 ("SELECT osv_id, cve_id, detailed, fixed", [
                                     ("UBUNTU-CVE-2024-6387", "CVE-2024-6387", True, {f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3"}),
                                     ("UBUNTU-CVE-2024-1111", "CVE-2024-1111", True, {}),
                                     ("UBUNTU-CVE-2024-2222", "CVE-2024-2222", False, {})])])
        table = {(ECO, "openssh", "1:9.6p1-3ubuntu13.2"): [[vuln("UBUNTU-CVE-2024-6387"), vuln("USN-6859-1")]],
                 (ECO, "linux", "6.8.0-139.139"): [[vuln("UBUNTU-CVE-2024-1111"), vuln("UBUNTU-CVE-2024-2222")]]}
        details = {"UBUNTU-CVE-2024-6387": {"id": "UBUNTU-CVE-2024-6387", "upstream": ["CVE-2024-6387"],
                                            "affected": [{"package": {"ecosystem": ECO, "name": "openssh"},
                                                          "ranges": [{"events": [{"fixed": "1:9.6p1-3ubuntu13.3"}]}]}]},
                   "UBUNTU-CVE-2024-1111": {"id": "UBUNTU-CVE-2024-1111"}}
        s3, http = FakeS3(), FakeHttp(osv_routes(table, details))
        self.assertTrue(cti.fetch_osv(ctx_for(conn, s3=s3, http=http)))
        # 커널 질의에서만 나온 KEV 아닌 기록(2222)은 상세를 받지 않는다
        self.assertEqual(sorted(u[len(cti.OSV_VULN_URL):] for u, _ in http.calls if u.startswith(cti.OSV_VULN_URL)),
                         ["UBUNTU-CVE-2024-1111", "UBUNTU-CVE-2024-6387"])
        doc = json.loads(s3.calls[0]["Body"])
        self.assertEqual(doc["schema"], "opsloop-cti-osv/1")
        self.assertEqual([(q["package"]["name"], [v["id"] for v in q["vulns"]]) for q in doc["queries"]],
                         [("linux", ["UBUNTU-CVE-2024-1111", "UBUNTU-CVE-2024-2222"]),
                          ("openssh", ["UBUNTU-CVE-2024-6387", "USN-6859-1"])])     # 원본에는 USN 도 남는다
        self.assertEqual(sorted(doc["details"]), ["UBUNTU-CVE-2024-1111", "UBUNTU-CVE-2024-6387"])
        writes = conn.writes()
        bare = [p for s, p in writes if s.startswith("INSERT INTO cti_osv (osv_id, cve_id, modified, snapshot_id)")][0]
        self.assertEqual(bare[1:3], (["UBUNTU-CVE-2024-2222"], ["CVE-2024-2222"]) if isinstance(bare, tuple)
                         else [["UBUNTU-CVE-2024-2222"], ["CVE-2024-2222"]])
        av = [p for s, p in writes if s.startswith("INSERT INTO asset_vulnerabilities")][0]
        self.assertEqual(av[0], "web-01")
        self.assertEqual(list(zip(av[4], av[6])), [("UBUNTU-CVE-2024-1111", "no_fix"), ("UBUNTU-CVE-2024-2222", "unknown"),
                                                   ("UBUNTU-CVE-2024-6387", "fix_available")])
        self.assertIn(("UPDATE asset_inventory SET check_error = %s WHERE asset_id = %s", ("지원하지 않는 배포판", "fw")), writes)
        self.assertEqual(conn.snapshots()[0]["records"], 3)                 # USN 을 뺀 기록 수


class OsvAwsTest(unittest.TestCase):
    def test_AWS_커널은_linux_aws_로_묻고_커널_기록으로_센다(self):
        assets = [("gateway", {"id": "ubuntu", "version_id": "24.04"}, AWS_KERNEL, AWS_PACKAGES)]
        conn = FakeConn(answers=[("FROM asset_inventory", assets), ("SELECT cve_id FROM cti_kev", [("CVE-2024-1086",)]),
                                 ("SELECT osv_id, modified, detailed", []),
                                 ("SELECT osv_id, cve_id, detailed, fixed", [
                                     ("UBUNTU-CVE-2024-1086", "CVE-2024-1086", True, {}),
                                     ("UBUNTU-CVE-2024-2222", "CVE-2024-2222", False, {})])])
        table = {(ECO, "linux-aws", "6.8.0-1036.38"): [[vuln("UBUNTU-CVE-2024-1086"), vuln("UBUNTU-CVE-2024-2222")]],
                 (ECO, "linux-aws", "6.8.0-1040.42"): [[vuln("UBUNTU-CVE-2024-2222")]]}
        details = {"UBUNTU-CVE-2024-1086": {"id": "UBUNTU-CVE-2024-1086", "upstream": ["CVE-2024-1086"]}}
        http = FakeHttp(osv_routes(table, details))
        self.assertTrue(cti.fetch_osv(ctx_for(conn, http=http), ["gateway"]))
        asked = sorted((q["package"]["name"], q["version"]) for u, sent in http.calls if u == cti.OSV_BATCH_URL
                       for q in sent["queries"])
        self.assertIn(("linux-aws", "6.8.0-1036.38"), asked)
        self.assertIn(("linux-aws", "6.8.0-1040.42"), asked)
        self.assertFalse([q for q in asked if q[0] in ("linux", "linux-libc-dev")])
        # 커널 질의에서만 나온 기록은 KEV 에 있는 것만 상세를 받는다 (2222 는 받지 않는다)
        self.assertEqual([u[len(cti.OSV_VULN_URL):] for u, _ in http.calls if u.startswith(cti.OSV_VULN_URL)],
                         ["UBUNTU-CVE-2024-1086"])
        # 1086 은 1040 에서 사라져 재부팅하면 해소, 2222 는 1040 에도 남고 상세가 없어 미확인
        av = [p for s, p in conn.writes() if s.startswith("INSERT INTO asset_vulnerabilities")][0]
        self.assertEqual((av[0], av[2], av[3], av[4], av[6], av[7]),
                         ("gateway", ["linux-aws", "linux-aws"], ["6.8.0-1036.38", "6.8.0-1036.38"],
                          ["UBUNTU-CVE-2024-1086", "UBUNTU-CVE-2024-2222"], ["reboot_pending", "unknown"],
                          ["6.8.0-1040.42", None]))


class WatchTest(unittest.TestCase):
    """주목 CVE 목록 (계약 10.2 · 10.4)."""

    REC_6387 = {"id": "UBUNTU-CVE-2024-6387", "modified": "2026-02-04T04:18:00.629884Z", "upstream": ["CVE-2024-6387"],
                "details": "regreSSHion", "severity": [{"type": "Ubuntu", "score": "high"}],
                "affected": [{"package": {"ecosystem": ECO, "name": "openssh"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                          {"fixed": "1:9.6p1-3ubuntu13.3"}]}]},
                             {"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "openssh"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    REC_53266 = {"id": "UBUNTU-CVE-2026-53266", "modified": "2026-09-19T00:00:00Z", "upstream": ["CVE-2026-53266"],
                 "affected": [{"package": {"ecosystem": ECO, "name": "linux"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}

    def test_저장소의_목록_파일(self):
        items = cti.load_watchlist(WATCHLIST)
        self.assertEqual([c for c, _ in items], ["CVE-2024-6387", "CVE-2024-3094", "CVE-2023-4911", "CVE-2021-4034",
                                                 "CVE-2021-3156", "CVE-2024-1086", "CVE-2026-53266"])
        self.assertTrue(all(r.strip() for _, r in items))
        with open(WATCHLIST, encoding="utf-8") as f:
            self.assertTrue(json.load(f)["note"].startswith("주목 CVE 목록"))
        # 실행기 옆의 파일이 기본값이다 (설치기가 코드 폴더에 함께 둔다)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPSLOOP_CTI_WATCHLIST", None)
            self.assertEqual(os.path.realpath(cti.watchlist_path()), os.path.realpath(WATCHLIST))
            os.environ["OPSLOOP_CTI_WATCHLIST"] = "/x/w.json"
            self.assertEqual(cti.watchlist_path(), "/x/w.json")

    def test_목록_형식이_틀리면_실패(self):
        ok = ("CVE-2024-6387", "이유")
        for bad in ("{broken", {"watch": "x"}, [1], {"watch": [{"cve": "cve-2024-1", "reason": "x"}]},
                    {"watch": [{"cve": "CVE-2024-6387", "reason": ""}]},
                    {"watch": [{"cve": "CVE-2024-6387", "reason": "줄\n바꿈"}]},
                    {"watch": [{"cve": "CVE-2024-6387", "reason": "x" * 201}]},
                    {"watch": [{"cve": "CVE-2024-6387"}]}, {"watch": ["CVE-2024-6387"]},
                    [ok, ok], [(f"CVE-2024-{i:04d}", "x") for i in range(51)]):
            with self.assertRaises(cti.CtiError, msg=bad):
                cti.load_watchlist(watch_file(bad))
        with self.assertRaisesRegex(cti.CtiError, "주목 CVE 목록을 읽지 못했다"):
            cti.load_watchlist(os.path.join(tempfile.mkdtemp(), "없음.json"))
        self.assertEqual(len(cti.load_watchlist(watch_file([(f"CVE-2024-{i:04d}", "x") for i in range(50)]))), 50)

    def routes(self, extra=None):
        recs = {"UBUNTU-CVE-2024-6387": self.REC_6387, "UBUNTU-CVE-2026-53266": self.REC_53266}
        recs.update(extra or {})

        def route(url, sent):
            oid = urllib.parse.unquote(url[len(cti.OSV_VULN_URL):]) if url.startswith(cti.OSV_VULN_URL) else None
            if oid == "UBUNTU-CVE-2024-3094":
                return cti.HttpStatus(503, url)
            return recs.get(oid)
        return route

    def test_자산이_없어도_주목_CVE_를_조회해_목록과_같게_맞춘다(self):
        watch = watch_file([("CVE-2024-6387", "regreSSHion"), ("CVE-2021-4034", "PwnKit"), ("CVE-2024-3094", "xz"),
                            ("CVE-2026-53266", "ebtables")])
        conn, s3, http = FakeConn(), FakeS3(), FakeHttp(self.routes())
        self.assertTrue(cti.fetch_osv(ctx_for(conn, s3=s3, http=http, watch=watch)))
        self.assertEqual(sorted(u[len(cti.OSV_VULN_URL):] for u, _ in http.calls),
                         ["UBUNTU-CVE-2021-4034", "UBUNTU-CVE-2024-3094", "UBUNTU-CVE-2024-6387", "UBUNTU-CVE-2026-53266"])
        doc = json.loads(s3.calls[0]["Body"])
        # 원본에는 받은 기록 그대로 · 404 는 null · 오류(503)로 건너뛴 CVE 는 넣지 않는다
        self.assertEqual(doc["watch"], {"CVE-2024-6387": self.REC_6387, "CVE-2021-4034": None,
                                        "CVE-2026-53266": self.REC_53266})
        self.assertEqual((doc["queries"], doc["details"]), ([], {}))
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["records"]), ("ok", 2))
        writes = conn.writes()
        up = [p for s, p in writes if s.startswith("INSERT INTO cti_osv (osv_id, cve_id, modified, detailed")][0]
        self.assertEqual(up[1], ["UBUNTU-CVE-2024-6387", "UBUNTU-CVE-2026-53266"])
        self.assertEqual([json.loads(x) for x in up[8]],                     # affected
                         [{f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3", "Ubuntu:20.04:LTS/openssh": None},
                          {f"{ECO}/linux": None}])
        self.assertEqual([json.loads(x) for x in up[7]], [{f"{ECO}/openssh": "1:9.6p1-3ubuntu13.3"}, {}])   # fixed
        sync = [p for s, p in writes if s.startswith("INSERT INTO cti_watch")][0]
        self.assertEqual(sync, [["CVE-2024-6387", "CVE-2021-4034", "CVE-2024-3094", "CVE-2026-53266"],
                                ["regreSSHion", "PwnKit", "xz", "ebtables"]])
        delete = [p for s, p in writes if s.startswith("DELETE FROM cti_watch")][0]
        self.assertEqual(delete, (["CVE-2024-6387", "CVE-2021-4034", "CVE-2024-3094", "CVE-2026-53266"],))
        checked = [p for s, p in writes if s.startswith("UPDATE cti_watch")][0]
        self.assertEqual(checked, [101, ["CVE-2021-4034", "CVE-2024-6387", "CVE-2026-53266"],
                                   [None, "UBUNTU-CVE-2024-6387", "UBUNTU-CVE-2026-53266"], [False, True, True]])

    def test_자산_대조로_받은_상세는_다시_받지_않는다(self):
        packages = [pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")]
        assets = [("web-01", {"id": "ubuntu", "version_id": "24.04"}, None, packages)]
        conn = FakeConn(answers=[("FROM asset_inventory", assets)])
        table = {(ECO, "openssh", "1:9.6p1-3ubuntu13.2"): [[vuln("UBUNTU-CVE-2024-6387")]]}
        http = FakeHttp(osv_routes(table, {"UBUNTU-CVE-2024-6387": self.REC_6387}))
        self.assertTrue(cti.fetch_osv(ctx_for(conn, http=http, watch=watch_file([("CVE-2024-6387", "x")]))))
        self.assertEqual([u for u, _ in http.calls if u.startswith(cti.OSV_VULN_URL)],
                         [cti.OSV_VULN_URL + "UBUNTU-CVE-2024-6387"])

    def test_load_assets_는_주목_CVE_를_보지_않는다(self):
        packages = [pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh")]
        conn = FakeConn(answers=[("FROM asset_inventory", [("web-01", {"id": "ubuntu", "version_id": "24.04"}, None,
                                                            packages)])])
        http = FakeHttp(osv_routes({}, {}))
        s3 = FakeS3()
        self.assertTrue(cti.fetch_osv(ctx_for(conn, s3=s3, http=http, watch=WATCHLIST), ["web-01"]))
        self.assertFalse([u for u, _ in http.calls if u.startswith(cti.OSV_VULN_URL)])
        self.assertNotIn("watch", json.loads(s3.calls[0]["Body"]))
        self.assertFalse([s for s, _ in conn.writes() if "cti_watch" in s])

    def test_주목_CVE_를_하나도_못_받고_자산도_없으면_실패(self):
        conn = FakeConn()
        http = FakeHttp(lambda u, s: cti.HttpStatus(503, u))
        self.assertFalse(cti.fetch_osv(ctx_for(conn, http=http, watch=watch_file([("CVE-2024-6387", "x")]))))
        snap = conn.snapshots()[0]
        self.assertEqual(snap["status"], "failed")
        self.assertIn("주목 CVE 1개의 기록을 하나도 받지 못했다", snap["error"])

    def test_목록이_틀리면_osv_가_실패로_드러난다(self):
        conn = FakeConn()
        self.assertFalse(cti.fetch_osv(ctx_for(conn, http=FakeHttp({}), watch=watch_file("{broken"))))
        self.assertIn("주목 CVE 목록을 읽지 못했다", conn.snapshots()[0]["error"])

    def test_자산도_주목_CVE_도_없으면_원본_기록이_없다(self):
        conn, s3 = FakeConn(), FakeS3()
        self.assertTrue(cti.fetch_osv(ctx_for(conn, s3=s3, http=FakeHttp({}))))
        self.assertEqual((s3.calls, conn.snapshots()), ([], []))
        # 대조 못 하는 자산뿐이어도 같다. 이유만 남긴다
        conn = FakeConn(answers=[("FROM asset_inventory", [("fw", {"id": "debian", "version_id": "12"}, None,
                                                            [pkg("haproxy", "2.8")])])])
        self.assertTrue(cti.fetch_osv(ctx_for(conn, s3=s3, http=FakeHttp({}))))
        self.assertEqual((s3.calls, conn.snapshots()), ([], []))
        self.assertEqual(conn.writes(), [("UPDATE asset_inventory SET check_error = %s WHERE asset_id = %s",
                                          ("지원하지 않는 배포판", "fw"))])


class NvdTest(unittest.TestCase):
    def resp(self, cve, metrics=None, desc="An issue."):
        return {"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": {
            "id": cve, "published": "2024-07-01T13:15:10.683", "lastModified": "2025-01-01T00:00:00.000",
            "vulnStatus": "Modified", "descriptions": [{"lang": "es", "value": "Un"}, {"lang": "en", "value": desc}],
            "metrics": metrics if metrics is not None else {}}}]}

    def test_CVSS_고르는_순서(self):
        v31 = {"cvssMetricV31": [{"source": "x", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 7.5,
                                  "vectorString": "CVSS:3.1/S", "baseSeverity": "HIGH"}},
                                 {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                                     "version": "3.1", "baseScore": 8.1, "vectorString": "CVSS:3.1/P", "baseSeverity": "HIGH"}}],
               "cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 6.8}}]}
        self.assertEqual(cti.parse_nvd(self.resp("CVE-2024-6387", v31), "CVE-2024-6387")["cvss"],
                         {"score": 8.1, "version": "3.1", "vector": "CVSS:3.1/P", "severity": "HIGH"})
        v40 = {"cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.3,
                                                                     "vectorString": "CVSS:4.0/x", "baseSeverity": "CRITICAL"}}],
               "cvssMetricV30": [{"type": "Primary", "cvssData": {"version": "3.0", "baseScore": 5.0}}]}
        self.assertEqual(cti.nvd_metric(self.resp("CVE-1", v40)["vulnerabilities"][0]["cve"])["version"], "4.0")
        v2 = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM",
                                "cvssData": {"version": "2.0", "baseScore": 6.8, "vectorString": "AV:N/AC:M"}}]}
        self.assertEqual(cti.nvd_metric(self.resp("CVE-1", v2)["vulnerabilities"][0]["cve"]),
                         {"score": 6.8, "version": "2.0", "vector": "AV:N/AC:M", "severity": "MEDIUM"})
        self.assertIsNone(cti.nvd_metric({"metrics": {"cvssMetricV31": [{"cvssData": "x"}]}}))

    def test_설명_게시_상태와_없는_CVE(self):
        got = cti.parse_nvd(self.resp("CVE-2024-6387"), "CVE-2024-6387")
        self.assertEqual((got["description"], got["status"], got["published"]),
                         ("An issue.", "Modified", datetime(2024, 7, 1, 13, 15, 10, 683000, timezone.utc)))
        self.assertIsNone(cti.parse_nvd({"totalResults": 0, "vulnerabilities": []}, "CVE-2024-6387"))
        with self.assertRaises(cti.CtiError):
            cti.parse_nvd({"message": "rate limited"}, "CVE-2024-6387")

    def test_초점_순서_중복_최근_상한(self):
        self.assertEqual(cti.focus_order([["CVE-1-0001", "CVE-2021-0001"], ["CVE-2021-0001", "CVE-2021-0002"],
                                          ["CVE-2021-0003"], ["CVE-2021-0004", "CVE-2021-0005"]],
                                         {"CVE-2021-0003"}, cap=3),
                         ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0004"])

    def test_회차_요청_간격_일부_실패_없는_CVE(self):
        sigs = load_rules()
        conn = FakeConn(answers=[("FROM rule_versions", [("c1", sigs)]), ("vendor_project, product, name", []),
                                 ("JOIN cti_kev k", [("CVE-2024-6387",)]), ("ORDER BY c.epss DESC", []),
                                 ("nvd_fetched_at >", [("CVE-2021-41773",), ("CVE-2021-42013",), ("CVE-2018-10561",),
                                                        ("CVE-2018-10562",), ("CVE-2021-36260",), ("CVE-2021-45046",)])])

        def route(url, _):
            cve = url.split("cveId=")[1]
            if cve == "CVE-2017-9841":
                return cti.CtiError("HTTP 503: x")
            if cve == "CVE-2024-6387":
                return {"totalResults": 0, "vulnerabilities": []}
            return self.resp(cve, {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "version": "3.1", "baseScore": 10.0, "vectorString": "CVSS:3.1/x", "baseSeverity": "CRITICAL"}}]})
        sleeps, s3 = [], FakeS3()
        http = FakeHttp(route)
        self.assertTrue(cti.fetch_nvd(ctx_for(conn, s3=s3, http=http, sleeps=sleeps)))
        asked = [u.split("cveId=")[1] for u, _ in http.calls]
        self.assertEqual(asked, ["CVE-2017-9841", "CVE-2021-44228", "CVE-2024-6387"])    # 서명(최근 것 뺌) → 자산∩KEV
        self.assertEqual(sleeps, [6.5, 6.5])
        doc = json.loads(s3.calls[0]["Body"])
        self.assertEqual((doc["schema"], sorted(doc["responses"])), ("opsloop-cti-nvd/1", ["CVE-2021-44228", "CVE-2024-6387"]))
        up = [p for s, p in conn.writes() if s.startswith("INSERT INTO cti_cve (cve_id, cvss_score")][0]
        self.assertEqual((up[1], up[2], up[5]), (["CVE-2021-44228"], [10.0], ["CRITICAL"]))
        touch = [p for s, p in conn.writes() if s.startswith("INSERT INTO cti_cve (cve_id, nvd_fetched_at")][0]
        self.assertEqual(touch[1], ["CVE-2024-6387"])

    def test_주목_CVE_가_맨_앞(self):
        conn = FakeConn(answers=[("FROM cti_watch", [("CVE-2021-3156",), ("CVE-2024-6387",)]),
                                 ("FROM rule_versions", [("c1", load_rules())]),
                                 ("nvd_fetched_at >", [("CVE-2021-3156",)])])
        focus = cti.nvd_focus(ctx_for(conn))
        self.assertEqual(focus[:3], ["CVE-2024-6387", "CVE-2017-9841", "CVE-2018-10561"])    # 14일 안에 받은 3156 은 뺀다

    def test_하나도_못_받으면_실패(self):
        conn = FakeConn(answers=[("JOIN cti_kev k", [("CVE-2024-6387",)])])
        self.assertFalse(cti.fetch_nvd(ctx_for(conn, http=FakeHttp(lambda u, s: cti.CtiError("HTTP 403: x")))))
        self.assertEqual(conn.snapshots()[0]["status"], "failed")

    def test_받을_것이_없으면_기록도_없다(self):
        conn, s3 = FakeConn(), FakeS3()
        self.assertTrue(cti.fetch_nvd(ctx_for(conn, s3=s3, http=FakeHttp({}))))
        self.assertEqual((s3.calls, conn.snapshots()), ([], []))


class KevMatchTest(unittest.TestCase):
    """실제 rules_cve.json 의 서명 제품 조건 (파이썬 re, 대소문자 무시, re.search)."""

    def setUp(self):
        with open(RULES, encoding="utf-8") as f:
            doc = json.load(f)
        self.sigs = {s["id"]: s for r in doc["rules"] for s in r["params"]["signatures"]}

    def row(self, cve, vendor, product, name, desc=""):
        return (cve, vendor, product, name, desc)

    def test_제품별_맞음과_안_맞음(self):
        cases = [
            ("geoserver", self.row("CVE-2024-36401", "OSGeo", "GeoServer", "OSGeo GeoServer Eval Injection"), True),
            ("geoserver", self.row("CVE-2022-24816", "OSGeo", "JAI-EXT", "OSGeo JAI-EXT Code Injection",
                                   "affects GeoServer"), True),
            ("geoserver", self.row("CVE-2099-0001", "OSGeo", "MapServer", "MapServer bug"), False),
            ("exchange-owa", self.row("CVE-2021-26855", "Microsoft", "Exchange Server", "Microsoft Exchange Server RCE"), True),
            ("exchange-owa", self.row("CVE-2021-26855", "microsoft", "exchange", "x"), True),      # 대소문자 무시
            ("exchange-owa", self.row("CVE-2024-1", "Microsoft", "Windows", "Windows bug"), False),
            ("dlink-hnap", self.row("CVE-2015-2051", "D-Link", "DIR-645 Router", "D-Link DIR-645 Router RCE",
                                    "HNAP SOAPAction header command execution"), True),
            ("dlink-hnap", self.row("CVE-2020-1", "D-Link", "DIR-600", "D-Link DIR-600 other"), False),
            ("confluence", self.row("CVE-2023-22515", "Atlassian", "Confluence Data Center and Server", "x"), True),
            ("confluence", self.row("CVE-2023-1", "Atlassian", "Jira", "x"), False),
        ]
        for sig, row, want in cases:
            self.assertEqual(cti.kev_match(self.sigs[sig]["kev_match"], row), want, (sig, row))

    def test_서명_여럿_순서와_틀린_정규식(self):
        rows = [self.row("CVE-2024-36401", "OSGeo", "GeoServer", "OSGeo GeoServer Eval Injection"),
                self.row("CVE-2021-26855", "Microsoft", "Exchange Server", "x")]
        sigs = [{"id": "bad", "kev_match": {"vendor": "("}}, {"id": "none"}, self.sigs["exchange-owa"],
                self.sigs["geoserver"], self.sigs["exchange-owa"]]
        self.assertEqual(cti.kev_matched(sigs, rows), ["CVE-2021-26855", "CVE-2024-36401"])
        self.assertEqual(cti.signature_cves(list(self.sigs.values())),
                         {"CVE-2021-41773", "CVE-2021-42013", "CVE-2018-10561", "CVE-2018-10562", "CVE-2021-36260",
                          "CVE-2021-44228", "CVE-2021-45046", "CVE-2017-9841"})


class BundleTest(unittest.TestCase):
    def good(self):
        return [{"asset_id": "web-01", "role": "target", "method": "ssh", "host": "opsloop-web-01",
                 "probe": probe([pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh")])},
                {"asset_id": "console-b", "role": "platform", "method": "ssh", "host": None,
                 "error": "연결 실패: ssh: connect to host console-b port 22: Operation timed out\n"}]

    def kinds(self, assets):
        return [(e.get("asset_id"), e["kind"]) for e in cti.validate_bundle(bundle(assets), T0)[1]]

    def test_정상_묶음(self):
        doc, entries = cti.validate_bundle(bundle(self.good()), T0)
        self.assertEqual([e["kind"] for e in entries], ["probe", "error"])
        p = entries[0]["probe"]
        self.assertEqual(p["collected_at"], datetime(2026, 9, 25, 2, 50, tzinfo=timezone.utc))
        self.assertEqual(p["packages"][0], {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.19",
                                            "source": "openssh", "source_version": "1:9.6p1-3ubuntu13.19", "arch": "amd64"})
        self.assertEqual(entries[1]["error"], "연결 실패: ssh: connect to host console-b port 22: Operation timed out ")

    def test_묶음이_틀리면_통째로_실패(self):
        deep = b'{"schema":"opsloop-assets/1","assets":' + b"[" * 200000 + b"]" * 200000 + b"}"
        for body in (b"not json", b"\xff\xfe", json.dumps({"schema": "x", "assets": []}).encode(),
                     bundle([]), bundle(self.good() * 11), b" " * (cti.BUNDLE_MAX + 1),
                     json.dumps(["opsloop-assets/1"]).encode(), deep):
            with self.assertRaises(cti.CtiError):
                cti.validate_bundle(body, T0)

    def test_최소_필드가_틀리면_버린다(self):
        a = self.good()[0]
        self.assertEqual(self.kinds(["x", dict(a, asset_id="Web_01"), dict(a, asset_id="a" * 64), dict(a, role="admin"),
                                     dict(a, method="telnet"), a, dict(a)]),
                         [(None, "reject"), (None, "reject"), (None, "reject"), ("web-01", "reject"), ("web-01", "reject"),
                          ("web-01", "reject"), ("web-01", "reject")])
        self.assertEqual(self.kinds([a, dict(a)]), [("web-01", "probe"), ("web-01", "reject")])     # 두 번째는 중복

    def test_조사_결과가_틀리면_그_자산만_형식_오류(self):
        def bad(**change):
            p = probe([pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh")])
            p.update(change)
            return {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "host": "i-0f8f7c0f698ca941a", "probe": p}
        cases = {
            "probe_version": bad(probe_version=2),
            "bool 버전": bad(probe_version=True),
            "패키지 이름에 셸 문자": bad(packages=[pkg("evil;rm -rf /", "1")]),
            "버전에 공백": bad(packages=[pkg("a", "1 2")]),
            "패키지가 너무 많다": bad(packages=[pkg("a", "1")] * (cti.MAX_PACKAGES + 1)),
            "이미지가 너무 많다": bad(images=[{"container": "c", "image": "i", "image_id": None}] * (cti.MAX_IMAGES + 1)),
            "긴 문자열": bad(hostname="h" * 257),
            "제어 문자": bad(os={"id": "ubuntu\u0000", "version_id": "24.04"}),
            "미래 수집 시각": bad(collected_at="2026-09-25T04:00:00Z"),
            "시각 아님": bad(collected_at="어제"),
            "os 형": bad(os="ubuntu"),
            "kernel 형": bad(kernel=["x"]),
            "패키지 항목 형": bad(packages=["a"]),
            "긴 오류 문구": bad(errors=["e" * 513]),
            "오류 문구 형": bad(errors=[{"x": 1}]),
            "probe 없음": {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm"},
            "host 형": dict(bad(), host=["x"]),
            "error 가 길다": {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "error": "e" * 513},
        }
        for why, asset in cases.items():
            entries = cti.validate_bundle(bundle([asset]), T0)[1]
            self.assertEqual(entries[0]["kind"], "invalid", why)
            self.assertTrue(entries[0]["error"].startswith("조사 결과 형식 오류: "), why)

    def test_대리_문자와_넘치는_시각은_그_자산만_형식_오류(self):
        """짝 없는 대리 문자(JSON \\ud800)는 UTF-8 로 쓸 수 없어 DB 인자에서 예외가 난다. 넘치는 시각은 OverflowError 를 낸다.
        어느 쪽이든 그 자산만 형식 오류(invalid)가 되고, 오류 문구도 UTF-8 로 쓸 수 있어야 한다."""
        def hp(change):
            p = probe([pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh")])
            p["images"] = [{"container": "c", "image": "nginx:1.27", "image_id": None}]
            change(p)
            return {"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "host": "i-0f8f7c0f698ca941a", "probe": p}
        cases = {
            "os.pretty": lambda p: p["os"].update(pretty="Ubuntu \ud800"),
            "kernel.running": lambda p: p["kernel"].update(running="6.8.0-139-generic\udfff"),
            "packages.arch": lambda p: p["packages"][0].update(arch="amd64\ud800"),
            "packages.name(형식 오류 문구에 값이 들어간다)": lambda p: p["packages"][0].update(name="openssh\ud800"),
            "images.image": lambda p: p["images"][0].update(image="nginx\ud800"),
            "images.container": lambda p: p["images"][0].update(container="\udc00"),
            "hostname": lambda p: p.update(hostname="h\ud800"),
            "넘치는 시각 (앞)": lambda p: p.update(collected_at="0001-01-01T00:00:00+09:00"),
            "넘치는 시각 (뒤)": lambda p: p.update(collected_at="9999-12-31T23:59:59-09:00"),
            "24시간 넘는 시간대": lambda p: p.update(collected_at="2026-09-25T00:00:00+99:00"),
        }
        for why, change in cases.items():
            entries = cti.validate_bundle(bundle([hp(change)]), T0)[1]
            self.assertEqual(entries[0]["kind"], "invalid", why)
            entries[0]["error"].encode("utf-8")
        host = dict(hp(lambda p: None), host="i-\ud800")
        self.assertEqual(self.kinds([host]), [("honeypot-dmz", "invalid")])
        # 오류 문구는 자유 문장이라 거부하지 않고 바꿔 담는다
        p = hp(lambda p: p.update(errors=["packages: dpkg \ud800 실패\n"]))
        e = cti.validate_bundle(bundle([p]), T0)[1][0]
        self.assertEqual((e["kind"], e["probe"]["errors"]), ("probe", ["packages: dpkg \ufffd 실패 "]))
        e = cti.validate_bundle(bundle([{"asset_id": "gateway", "role": "platform", "method": "ssm", "host": None,
                                         "error": "SSM 실패 \udfff"}]), T0)[1][0]
        self.assertEqual((e["kind"], e["error"]), ("error", "SSM 실패 \ufffd"))
        # asset_id 자체에 대리 문자가 있으면 버린다 (로그에도 쓸 수 있어야 한다)
        e = cti.validate_bundle(bundle([dict(self.good()[0], asset_id="web\ud800")]), T0)[1][0]
        self.assertEqual(e["kind"], "reject")
        e["reason"].encode("utf-8")

    def test_검증기가_못_막은_예외도_그_자산만(self):
        with mock.patch.object(cti, "check_probe", side_effect=TypeError("뜻밖의 모양")):
            e = cti.validate_bundle(bundle([self.good()[0]]), T0)[1][0]
        self.assertEqual((e["kind"], e["error"]), ("invalid", "조사 결과 형식 오류: TypeError: 뜻밖의 모양"))

    def test_아는_키만_담는다(self):
        a = self.good()[0]
        a["probe"]["extra"] = "x" * 100
        a["probe"]["os"]["evil"] = "y"
        a["probe"]["packages"][0]["evil"] = "z"
        p = cti.validate_bundle(bundle([a]), T0)[1][0]["probe"]
        self.assertNotIn("extra", p)
        self.assertEqual(set(p["os"]), {"id", "version_id", "codename", "pretty"})
        self.assertEqual(set(p["packages"][0]), {"name", "version", "source", "source_version", "arch"})


class LoadAssetsTest(unittest.TestCase):
    def test_적재_실패_형식_오류_종료_코드(self):
        good = BundleTest().good()
        conn, s3 = FakeConn(), FakeS3()
        self.assertEqual(cti.load_assets(ctx_for(conn, s3=s3), bundle(good), check=False), 0)
        self.assertTrue(s3.calls[0]["Key"].startswith("cti/v1/source=assets/date=2026-09-25/"))
        self.assertEqual(s3.calls[0]["Metadata"]["source-url"], "stdin")
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["records"], snap["source_url"]), ("ok", 2, None))
        self.assertEqual(snap["source_ts"], datetime(2026, 9, 25, 2, 55, tzinfo=timezone.utc))
        writes = conn.writes()
        upsert = [p for s, p in writes if "INSERT INTO asset_inventory AS a (asset_id, role, method, host, collected_at" in s][0]
        self.assertEqual(upsert[:5], ("web-01", "target", "ssh", "opsloop-web-01",
                                      datetime(2026, 9, 25, 2, 50, tzinfo=timezone.utc)))
        self.assertEqual(json.loads(upsert[6])["running_version"], "6.8.0-139.139")
        self.assertEqual(json.loads(upsert[7])[0]["source"], "openssh")
        self.assertEqual(upsert[10], 101)
        attempt = [p for s, p in writes if "INSERT INTO asset_inventory AS a (asset_id, role, method, host, last_attempt_at" in s][0]
        self.assertEqual(attempt[:4], ("console-b", "platform", "ssh", None))

        bad = good + [{"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "probe": {"probe_version": 9}}]
        self.assertEqual(cti.load_assets(ctx_for(FakeConn()), bundle(bad), check=False), 1)
        self.assertEqual(cti.load_assets(ctx_for(FakeConn()), bundle(good + ["x"]), check=False), 1)

        conn = FakeConn()
        self.assertEqual(cti.load_assets(ctx_for(conn), b"{broken", check=False), 2)
        self.assertEqual([(p["status"], p["source"]) for p in conn.snapshots()], [("failed", "assets")])

    def test_S3_에_못_쓰면_자산을_고치지_않는다(self):
        conn = FakeConn()
        rc = cti.load_assets(ctx_for(conn, s3=FakeS3(fail=RuntimeError("down"))), bundle(BundleTest().good()))
        self.assertEqual(rc, 2)
        self.assertFalse(any("asset_inventory" in s for s, _ in conn.committed))

    def test_받은_자산만_대조한다(self):
        conn = FakeConn()
        seen = []
        with mock.patch.object(cti, "fetch_osv", lambda ctx, only=None, out=None: seen.append(only) or True):
            self.assertEqual(cti.load_assets(ctx_for(conn), bundle(BundleTest().good())), 0)
            self.assertEqual(cti.load_assets(ctx_for(conn), bundle(BundleTest().good()[1:])), 0)   # 조사 결과가 없다
        self.assertEqual(seen, [["web-01"]])
        with mock.patch.object(cti, "fetch_osv", lambda ctx, only=None, out=None: False):
            self.assertEqual(cti.load_assets(ctx_for(FakeConn()), bundle(BundleTest().good())), 1)

    def test_대조하지_못한_자산이_있으면_1(self):
        def skipped(ctx, only=None, out=None):
            out["skipped"] = {"web-01": "패키지 목록이 없다"}
            return True
        with mock.patch.object(cti, "fetch_osv", skipped):
            self.assertEqual(cti.load_assets(ctx_for(FakeConn()), bundle(BundleTest().good())), 1)

    def test_패키지_목록이_없는_자산만_받으면_osv_원본_기록이_없고_1(self):
        """dpkg 조사가 실패한 자산(packages 빈 목록 + errors)만 받으면 대조한 자산이 0개다. osv 정상 회차를 남기면
        콘솔 신선도가 '대조함'으로 보이므로 남기지 않고, 대조 못 한 이유만 적고 종료 코드 1 로 드러낸다."""
        p = probe([])
        p["kernel"], p["errors"] = None, ["packages: dpkg-query -W -f: 종료 2"]
        asset = {"asset_id": "web-01", "role": "target", "method": "ssh", "host": "opsloop-web-01", "probe": p}
        conn = FakeConn(answers=[("FROM asset_inventory WHERE collected_at IS NOT NULL",
                                  [("web-01", p["os"], None, [])])])
        http = FakeHttp({})
        self.assertEqual(cti.load_assets(ctx_for(conn, http=http), bundle([asset])), 1)
        self.assertEqual([s["source"] for s in conn.snapshots()], ["assets"])        # osv 기록 없음
        self.assertIn(("UPDATE asset_inventory SET check_error = %s WHERE asset_id = %s", ("패키지 목록이 없다", "web-01")),
                      conn.writes())
        self.assertEqual(http.calls, [])

    def test_비신뢰_자산_하나가_묶음_전체를_깨지_않는다(self):
        """장악된 허니팟이 넘치는 시각 · 대리 문자를 보내도 그 자산만 형식 오류로 남고 나머지는 적재된다."""
        good = BundleTest().good()
        hp = probe([pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2")], collected_at="0001-01-01T00:00:00+09:00")
        gw = probe([pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2")])
        gw["os"]["pretty"] = "Ubuntu \ud800"
        bad = [{"asset_id": "honeypot-dmz", "role": "sensor", "method": "ssm", "host": "i-0abc", "probe": hp},
               {"asset_id": "gateway", "role": "platform", "method": "ssm", "host": "i-0def", "probe": gw},
               {"asset_id": "fw", "role": "platform", "method": "ssh", "host": "opsloop-fw",
                "probe": dict(probe([pkg("sudo", "1")]), errors=["images: sudo \ud800 실패"])}]
        body = bundle(good + bad, sent_at="9999-12-31T23:59:59-09:00")
        conn = FakeConn()
        self.assertEqual(cti.load_assets(ctx_for(conn), body, check=False), 1)
        snap = conn.snapshots()[0]
        self.assertEqual((snap["status"], snap["source_ts"]), ("ok", None))
        ups = [p[0] for s, p in conn.writes() if "collected_at, received_at" in s]
        self.assertEqual(ups, ["web-01", "fw"])
        attempts = {p[0]: p[4] for s, p in conn.writes() if "(asset_id, role, method, host, last_attempt_at" in s}
        self.assertEqual(sorted(attempts), ["console-b", "gateway", "honeypot-dmz"])
        self.assertIn("collected_at 이 시각이 아니다", attempts["honeypot-dmz"])
        self.assertIn("os.pretty", attempts["gateway"])
        fw = [p for s, p in conn.writes() if "collected_at, received_at" in s][1]
        self.assertEqual(json.loads(fw[9]), ["images: sudo \ufffd 실패"])


class CliTest(unittest.TestCase):
    def run_cli(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if k not in ("JOURNAL_STREAM",)}
        e.update(env or {})
        return subprocess.run([sys.executable, os.path.join(HERE, "opsloop_cti.py"), *args], capture_output=True,
                              text=True, env=e, timeout=60)

    def test_도움말은_한국어(self):
        r = self.run_cli("--help")
        self.assertEqual(r.returncode, 0)
        for s in ("사용법: opsloop-cti", "하위 명령", "fetch", "load-assets", "status", "종료 코드", "이 도움말을 보이고 끝낸다"):
            self.assertIn(s, r.stdout)
        self.assertNotIn("usage:", r.stdout)
        r = self.run_cli("fetch", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("사용법: opsloop-cti fetch"), r.stdout)
        self.assertIn("--no-nvd", r.stdout)
        r = self.run_cli()
        self.assertEqual(r.returncode, 2)
        self.assertIn("사용법:", r.stderr)

    def test_설정_오류는_2(self):
        tmp = tempfile.mkdtemp()
        base = {"OPSLOOP_CTI_DEFAULTS": os.path.join(tmp, "none"), "OPSLOOP_CTI_S3_ENV": os.path.join(tmp, "none"),
                "OPSLOOP_CTI_DB_ENV": os.path.join(tmp, "none"), "OPSLOOP_BUCKET": "", "OPSLOOP_CTI_HOME": tmp}
        r = self.run_cli("fetch", "--only", "kev,foo", env=base)
        self.assertEqual(r.returncode, 2)
        self.assertIn("알 수 없는 출처: foo", r.stdout)
        r = self.run_cli("fetch", env=base)
        self.assertEqual(r.returncode, 2)
        self.assertIn("OPSLOOP_BUCKET 이 없다", r.stdout)
        r = self.run_cli("fetch", env=dict(base, OPSLOOP_BUCKET="b"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("S3 쓰기 키 파일을 읽지 못했다", r.stdout)
        r = self.run_cli("status", env=base)
        self.assertEqual(r.returncode, 2)
        self.assertIn("DB 접속 파일을 읽지 못했다", r.stdout)

    def test_설정_파일은_환경변수가_없을_때만(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "opsloop-cti")
        with open(path, "w") as f:
            f.write("# 주석\nOPSLOOP_BUCKET=from-file\nOPSLOOP_CTI_HOME=/x\n")
        env = {"OPSLOOP_CTI_DEFAULTS": path}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("OPSLOOP_BUCKET", None)
            os.environ.pop("OPSLOOP_CTI_HOME", None)
            os.environ.pop("AWS_DEFAULT_REGION", None)
            self.assertEqual(cti.settings(), {"bucket": "from-file", "home": "/x", "region": "ap-northeast-2"})
            os.environ["OPSLOOP_BUCKET"] = "from-env"
            self.assertEqual(cti.settings()["bucket"], "from-env")

    def test_설치기는_주목_CVE_목록을_코드와_함께_둔다(self):
        path = os.path.join(HERE, "install-cti.sh")
        self.assertEqual(subprocess.run(["bash", "-n", path], capture_output=True).returncode, 0)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("cti/watchlist.json", text.split("== 사전 확인")[1].split("== 패키지")[0])
        self.assertIn('cp -r "$SRC/cti" /opt/opsloop/.cti.new', text)
        self.assertIn("has_table_privilege('opsloop_cti','cti_watch','DELETE')", text)

    def test_잠금은_겹치지_않는다(self):
        home = tempfile.mkdtemp()
        first = cti.take_lock(home)
        waits = []
        with self.assertRaisesRegex(cti.CtiError, "끝나지 않았다"):
            cti.take_lock(home, wait=10, sleep=waits.append)
        self.assertEqual(waits, [5, 5])
        first.close()
        cti.take_lock(home, wait=0).close()


if __name__ == "__main__":
    unittest.main()
