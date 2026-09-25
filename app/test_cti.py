"""CVE · KEV 연계 조회(cti.py) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 적용 판정(순수 함수): 디코이 가상 항목 · 수집 전 · 오래됨(48시간) · 플랫폼 불일치 · 설치 안 됨(+ 설명, 마침표로 잇기) ·
     CVE 없는 서명의 설치 · 배포판 취약점 행 · 대조 새로움 · 대조 전 · 대조 오래됨 · 대조가 이번 조사보다 앞섬 ·
     이미지만 있음 · 조사가 못 읽은 목록(probe_errors) · 빈 패키지 목록 · 틀린 이미지 정규식 ·
     요청 받은 자산(센서 → 자산) · 자산 표에 없는 요청 받은 자산 · 정렬 · 요약 세 값. 실제 서명 파일 전부
  2. 신선도: 출처별 오래됨 · 받은 적 없는 출처 · NVD 는 오래됨이 아님 · 자산 가장 오래된 수집 · 오래된 자산
  3. 정렬 · 모양: CVE(KEV 먼저 → EPSS → id) · EPSS 자리 · 커널 재부팅 대기(같은 판끼리) · 주요 패키지 · dpkg 버전 비교
  4. 커널 소스 규칙(계약 10.5) · 생태계 이름 · dpkg 비교가 수집기(cti/opsloop_cti.py)와 같은 답인지 ·
     주목 CVE 대조(judge_watch 전 분기 · 커널이 아닌 linux 소스 · 행 모양 · 정렬)
  5. 라우터 계약: 경로 순서 회귀(…/cti 가 상세 조회로 빠지지 않는다 · /api/cti/watch 가 자산 상세 · 사건 상세와 겹치지 않는다) ·
     세션 없으면 401 · 역할 검사 없음(viewer) · 잘못된 asset_id · limit · offset(상한 포함) · filter 는 DB 에 닿기 전에 422 ·
     표가 없으면 available=false · kev_match 가 PG 정규식으로 틀리면 그 서명만 kev_products=null
main 이 필요한 시험은 test_web 을 먼저 불러 asyncpg 가 없는 곳에서도 가짜를 넣는다(main 보다 먼저).
"""
import asyncio
import importlib.util
import json
import unittest
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import Match

import cti

NOW = datetime(2026, 9, 25, 3, 0, tzinfo=timezone.utc)
UBUNTU = {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "pretty": "Ubuntu 24.04.5 LTS"}
RULES_CVE = Path(__file__).resolve().parents[1] / "detector" / "rules_cve.json"

# 규칙 파일(rules_cve.json)의 서명과 같은 꼴
GEOSERVER = {"id": "geoserver", "product": "GeoServer", "vendor": "OSGeo", "cves": [],
             "kev_match": {"vendor": "^OSGeo$", "text": "GeoServer"},
             "asset_match": {"platforms": ["linux"], "packages": [], "images": ["(^|/)geoserver(:|@|$)"],
                             "note": "컨테이너 이미지 이름으로만 본다."},
             "mapping": "analyst", "source": "시험"}
APACHE = {"id": "apache-path-traversal", "product": "Apache HTTP Server", "vendor": "Apache",
          "cves": ["CVE-2021-41773", "CVE-2021-42013"],
          "asset_match": {"platforms": ["linux"], "packages": ["apache2"], "images": ["(^|/)httpd(:|@|$)"]},
          "mapping": "analyst", "source": "시험"}
EXCHANGE = {"id": "exchange-owa", "product": "Exchange Server", "vendor": "Microsoft", "cves": [],
            "asset_match": {"platforms": ["windows"], "packages": [], "images": []}}
HIKVISION = {"id": "hikvision-weblanguage", "product": "Hikvision IP 카메라", "vendor": "Hikvision",
             "cves": ["CVE-2021-36260"], "asset_match": {"platforms": ["appliance"], "packages": [], "images": []}}


def asset(asset_id="web-01", role="target", collected=NOW - timedelta(hours=1), os=UBUNTU, packages=(), images=(),
          checked=NOW - timedelta(hours=1), **extra):
    return {"asset_id": asset_id, "role": role, "collected_at": collected, "os": os, "packages": list(packages),
            "images": list(images), "checked_at": checked, **extra}


APACHE2 = {"name": "apache2", "version": "2.4.58-1ubuntu8.4", "source": "apache2", "source_version": "2.4.58-1ubuntu8.4"}
HTTPD = {"container": "web", "image": "docker.io/library/httpd:2.4.49", "image_id": "sha256:x"}
GEO_IMAGE = {"container": "geo", "image": "docker.osgeo.org/geoserver:2.25.2", "image_id": "sha256:y"}


def judge(signature, a, hits=()):
    return cti.judge(signature, a, list(hits), NOW)


class JudgeTests(unittest.TestCase):
    """자산 하나 · 서명 하나의 판정. 모르는 것은 비해당이 아니라 미확인이다."""

    def test_수집_전_자산은_미확인이다(self):
        self.assertEqual(judge(APACHE, asset(collected=None)), ("unknown", "자산 정보가 아직 없다"))

    def test_48시간이_넘은_자산은_미확인이고_마지막_수집을_한국_시각으로_적는다(self):
        status, reason = judge(APACHE, asset(collected=datetime(2026, 9, 23, 2, 59, tzinfo=timezone.utc)))
        self.assertEqual(status, "unknown")
        self.assertEqual(reason, "자산 정보가 오래됐다 (마지막 수집 2026-09-23 11:59 KST). 비해당으로 보지 않는다")
        # 딱 48시간은 아직 오래되지 않았다
        self.assertEqual(judge(APACHE, asset(collected=NOW - timedelta(hours=48)))[0], "not_affected")

    def test_리눅스가_아닌_제품은_플랫폼으로_비해당이다(self):
        self.assertEqual(judge(EXCHANGE, asset()),
                         ("not_affected", "Exchange Server 는 Windows 전용 제품이다. 이 자산은 Ubuntu 24.04.5 LTS 다"))
        self.assertEqual(judge(HIKVISION, asset(os={"id": "ubuntu", "version_id": "24.04"})),
                         ("not_affected", "Hikvision IP 카메라 는 전용 장비 펌웨어 제품이다. 이 자산은 ubuntu 24.04 다"))
        both = dict(EXCHANGE, asset_match={"platforms": ["windows", "appliance"], "packages": [], "images": []})
        self.assertIn("Windows 전용 · 전용 장비 펌웨어 제품이다", judge(both, asset())[1])

    def test_운영체제를_모르면_플랫폼으로_가르지_않는다(self):
        status, reason = judge(EXCHANGE, asset(os=None))
        self.assertEqual((status, reason), ("not_affected", "자산 표의 패키지 · 컨테이너 이미지에 없다"))

    def test_리눅스를_포함한_플랫폼은_설치_여부로_본다(self):
        vtm = {"id": "ivanti-vtm", "product": "vTM", "cves": [],
               "asset_match": {"platforms": ["linux", "appliance"], "packages": [], "images": ["(^|/)(vtm|zxtm)(:|@|$)"]}}
        self.assertEqual(judge(vtm, asset())[1], "자산 표의 패키지 · 컨테이너 이미지에 없다")
        self.assertEqual(judge(vtm, asset(images=[{"image": "pulse/ZXTM:22.2"}]))[0], "affected")

    def test_설치되지_않았으면_비해당이고_서명_설명을_붙인다(self):
        self.assertEqual(judge(GEOSERVER, asset(images=[{"image": "postgres:16-alpine"}])),
                         ("not_affected", "자산 표의 패키지 · 컨테이너 이미지에 없다. 컨테이너 이미지 이름으로만 본다."))
        # 설명이 마침표로 끝나지 않아도 두 문장은 마침표로 잇는다
        plain = dict(GEOSERVER, asset_match=dict(GEOSERVER["asset_match"], note="직접 설치한 것은 보이지 않는다"))
        self.assertEqual(judge(plain, asset())[1], "자산 표의 패키지 · 컨테이너 이미지에 없다. 직접 설치한 것은 보이지 않는다")
        self.assertEqual(judge(APACHE, asset(packages=[{"name": "nginx", "version": "1.24", "source": "nginx"}]))[1],
                         "자산 표의 패키지 · 컨테이너 이미지에 없다")

    def test_이미지_이름이_비슷해도_경계가_맞아야_한다(self):
        for image in ["geoserverx:1", "mygeoserver:1", "docker.io/library/nginx:1"]:
            with self.subTest(image=image):
                self.assertEqual(judge(GEOSERVER, asset(images=[{"image": image}]))[0], "not_affected")
        for image in ["geoserver", "GeoServer:2.25", "docker.osgeo.org/geoserver@sha256:abc"]:
            with self.subTest(image=image):
                self.assertEqual(judge(GEOSERVER, asset(images=[{"image": image}]))[0], "affected")

    def test_CVE_없는_서명은_설치돼_있으면_해당이다(self):
        self.assertEqual(judge(GEOSERVER, asset(images=[GEO_IMAGE])),
                         ("affected", "docker.osgeo.org/geoserver:2.25.2가 설치돼 있다. KEV 항목별 버전 대조가 필요하다"))
        # 패키지는 바이너리 이름이나 소스 이름 중 하나로 맞는다
        confluence = dict(GEOSERVER, asset_match={"platforms": ["linux"], "packages": ["confluence"], "images": []})
        pkg = {"name": "confluence-bin", "version": "8.5.1", "source": "confluence"}
        self.assertEqual(judge(confluence, asset(packages=[pkg])),
                         ("affected", "confluence-bin 8.5.1가 설치돼 있다. KEV 항목별 버전 대조가 필요하다"))

    def test_배포판_취약점_행이_있으면_해당이고_수정_상태를_적는다(self):
        labels = {"fix_available": "수정판 있음", "reboot_pending": "재부팅하면 해소",
                  "no_fix": "배포판 수정판 없음", "unknown": "수정 여부 미확인"}
        for state, label in labels.items():
            hit = {"asset_id": "web-01", "source_package": "apache2", "version": "2.4.58-1ubuntu8.4",
                   "cve_id": "CVE-2021-41773", "fix_state": state}
            with self.subTest(state=state):
                self.assertEqual(judge(APACHE, asset(packages=[APACHE2]), [hit]),
                                 ("affected", f"apache2 2.4.58-1ubuntu8.4 · CVE-2021-41773 ({label})"))
        two = [{"source_package": "apache2", "version": "1", "cve_id": c, "fix_state": "no_fix"}
               for c in ("CVE-2021-41773", "CVE-2021-42013")]
        self.assertEqual(judge(APACHE, asset(packages=[APACHE2]), two)[1],
                         "apache2 1 · CVE-2021-41773 (배포판 수정판 없음), apache2 1 · CVE-2021-42013 (배포판 수정판 없음)")

    def test_새로_대조했는데_행이_없으면_배포판_기준_비해당이다(self):
        checked = datetime(2026, 9, 24, 21, 30, tzinfo=timezone.utc)
        self.assertEqual(judge(APACHE, asset(packages=[APACHE2], checked=checked)),
                         ("not_affected", "apache2 2.4.58-1ubuntu8.4 설치됨 · 배포판 기준 이 CVE 에 해당하지 않는다 "
                                          "(대조 2026-09-25 06:30 KST)"))

    def test_대조_전이거나_대조가_오래됐으면_미확인이다(self):
        self.assertEqual(judge(APACHE, asset(packages=[APACHE2], checked=None)),
                         ("unknown", "apache2 2.4.58-1ubuntu8.4 설치됨 · 배포판 취약점 대조 전이다"))
        status, reason = judge(APACHE, asset(packages=[APACHE2], checked=NOW - timedelta(hours=49)))
        self.assertEqual(status, "unknown")
        self.assertIn("배포판 취약점 대조가 오래됐다 (대조 2026-09-23 11:00 KST). 비해당으로 보지 않는다", reason)

    def test_이미지로만_맞으면_대조했어도_미확인이다(self):
        # OSV 대조는 dpkg 패키지만 본다. 이미지 안 패키지를 보지 않았으니 비해당이라 하지 않는다
        for packages in ([], [APACHE2]):
            with self.subTest(packages=packages):
                status, reason = judge(APACHE, asset(packages=packages, images=[HTTPD]))
                self.assertEqual(status, "unknown")
                self.assertIn("docker.io/library/httpd:2.4.49 있음 · 컨테이너 이미지 안 패키지는", reason)

    def test_대조가_이번_조사보다_앞서면_비해당이_아니라_미확인이다(self):
        # 30시간 전 대조 뒤 1시간 전 조사에서 apache2 가 새로 보였다(대조는 실패해 옛 시각 그대로다)
        new = {"name": "apache2", "version": "2.4.49-1", "source": "apache2", "source_version": "2.4.49-1"}
        stale_check = asset(packages=[new], checked=NOW - timedelta(hours=30), received_at=NOW - timedelta(hours=1))
        self.assertEqual(judge(APACHE, stale_check), ("unknown", "apache2 2.4.49-1 설치됨 · 이번 조사 뒤 배포판 대조 전이다"))
        # 같은 조사를 대조했거나(같은 시각 · 뒤) 받은 시각을 모르면 그대로 대조 결과를 쓴다
        for received in (NOW - timedelta(hours=30), NOW - timedelta(hours=31), None):
            with self.subTest(received=received):
                a = asset(packages=[new], checked=NOW - timedelta(hours=30), received_at=received)
                self.assertEqual(judge(APACHE, a)[0], "not_affected")

    def test_대조가_이번_조사보다_앞서면_지금도_깔린_버전의_행만_근거로_쓴다(self):
        a = asset(packages=[APACHE2], checked=NOW - timedelta(hours=30), received_at=NOW - timedelta(hours=1))
        same = {"source_package": "apache2", "version": "2.4.58-1ubuntu8.4", "cve_id": "CVE-2021-41773",
                "fix_state": "fix_available"}
        self.assertEqual(judge(APACHE, a, [same]),
                         ("affected", "apache2 2.4.58-1ubuntu8.4 · CVE-2021-41773 (수정판 있음)"))
        # 지난 대조 때의 옛 버전 행이다. 지금 버전은 대조한 적이 없다
        old = dict(same, version="2.4.49-1")
        self.assertEqual(judge(APACHE, a, [old]),
                         ("unknown", "apache2 2.4.58-1ubuntu8.4 설치됨 · 이번 조사 뒤 배포판 대조 전이다"))
        # 대조가 조사 뒤면 행을 그대로 쓴다
        self.assertEqual(judge(APACHE, asset(packages=[APACHE2], received_at=NOW - timedelta(hours=2)), [old])[0],
                         "affected")

    def test_조사가_목록을_못_읽었으면_빈_목록을_설치_안_됨으로_읽지_않는다(self):
        errors = ["packages: dpkg-query -W -f: 종료 2", "images: sudo -n docker: 종료 1 sudo: a password is required"]
        both = asset(probe_errors=errors)
        self.assertEqual(judge(APACHE, both),
                         ("unknown", "조사 중 패키지 목록을 읽지 못했다. 조사 중 컨테이너 이미지 목록을 읽지 못했다"))
        # 이미지로만 보는 서명은 이미지 목록만 따진다
        self.assertEqual(judge(GEOSERVER, both), ("unknown", "조사 중 컨테이너 이미지 목록을 읽지 못했다"))
        self.assertEqual(judge(GEOSERVER, asset(probe_errors=errors[:1]))[0], "not_affected")
        # 패키지로만 보는 서명은 이미지 오류와 상관없다
        dpkg_only = dict(APACHE, asset_match={"platforms": ["linux"], "packages": ["apache2"], "images": []})
        self.assertEqual(judge(dpkg_only, asset(probe_errors=errors[1:]))[0], "not_affected")
        self.assertEqual(judge(dpkg_only, asset(probe_errors=errors[:1])), ("unknown", "조사 중 패키지 목록을 읽지 못했다"))
        # 다른 부분(os)의 오류나 이상한 값은 따지지 않는다
        self.assertEqual(judge(APACHE, asset(probe_errors=["os: 없음", None, 3, "packagesx"]))[0], "not_affected")
        self.assertEqual(judge(APACHE, asset(probe_errors="packages: 문자열"))[0], "not_affected")

    def test_패키지로는_비해당이어도_이미지_목록을_못_읽었으면_미확인이다(self):
        a = asset(packages=[APACHE2], checked=datetime(2026, 9, 24, 21, 30, tzinfo=timezone.utc),
                  probe_errors=["images: sudo -n docker: 종료 1"])
        self.assertEqual(judge(APACHE, a),
                         ("unknown", "apache2 2.4.58-1ubuntu8.4 설치됨 · 배포판 기준 이 CVE 에 해당하지 않는다 "
                                     "(대조 2026-09-25 06:30 KST). 조사 중 컨테이너 이미지 목록을 읽지 못했다"))
        # 이미 해당 · 설치로 정해졌으면 못 읽은 이미지가 바꾸지 않는다
        hit = {"source_package": "apache2", "version": "2.4.58-1ubuntu8.4", "cve_id": "CVE-2021-41773",
               "fix_state": "no_fix"}
        self.assertEqual(judge(APACHE, a, [hit])[0], "affected")

    def test_패키지_목록이_비어_있으면_패키지_조건은_모른다(self):
        self.assertEqual(judge(APACHE, asset(package_count=0)), ("unknown", "조사 결과에 패키지 목록이 비어 있다"))
        self.assertEqual(judge(GEOSERVER, asset(package_count=0))[0], "not_affected")
        self.assertEqual(judge(APACHE, asset(package_count=812))[0], "not_affected")

    def test_이미지_정규식이_틀려도_죽지_않고_그_경로만_모른다(self):
        for bad in ("(", "a{99999999999999999999}", 3, None):
            with self.subTest(bad=bad):
                sig = dict(GEOSERVER, asset_match=dict(GEOSERVER["asset_match"], images=[bad, "(^|/)geoserver(:|@|$)"]))
                self.assertEqual(judge(sig, asset(images=[GEO_IMAGE]))[0], "affected")   # 읽은 식으로 맞았다
                self.assertEqual(judge(sig, asset(images=[HTTPD])),
                                 ("unknown", "서명의 컨테이너 이미지 조건(정규식)을 읽지 못했다"))
                # 이미지가 하나도 없으면 틀린 식도 맞을 것이 없다
                self.assertEqual(judge(sig, asset())[0], "not_affected")

    def test_이유_문장_잇기(self):
        self.assertEqual(cti.sentences("가", "나.", None, "", "  ", "다"), "가. 나. 다")
        self.assertEqual(cti.sentences("가."), "가.")
        self.assertEqual(cti.sentences(), "")

    def test_자산_조건이_없는_서명은_미확인이다(self):
        self.assertEqual(judge({"id": "x", "cves": []}, asset()), ("unknown", "서명에 자산 대조 조건이 없다"))

    def test_비신뢰_자산_값이_이상해도_죽지_않는다(self):
        odd = asset(packages=["apache2", None, {"name": 3}], images=["httpd", {"image": None}, {"image": 7}])
        self.assertEqual(judge(APACHE, odd)[0], "not_affected")


class ApplicabilityTests(unittest.TestCase):
    """서명 하나를 자산 전체에 판정한다."""

    def assets(self):
        return [asset("honeypot-dmz", "sensor"), asset("fw", "platform"), asset("web-01"),
                asset("console-b", "platform", collected=None), asset("data-01", "platform", packages=[APACHE2])]

    def test_디코이는_가상_항목으로_맨_앞에_온다(self):
        rows = cti.applicability(APACHE, ["decoy"], self.assets(), [], NOW)
        self.assertEqual(rows[0], {"asset_id": "web-decoy", "role": "sensor", "targeted": True,
                                   "status": "not_affected",
                                   "reason": "웹 디코이는 모르는 경로에 404 를 돌려주는 모의 서비스다. 실제 제품이 없다.",
                                   "collected_at": None})
        self.assertFalse(any(r["targeted"] for r in rows[1:]))
        # 가상 항목은 매번 새것이다(상수를 고치지 않는다)
        rows[0]["status"] = "x"
        self.assertEqual(cti.DECOY_ENTRY["status"], "not_affected")

    def test_역할_다음_id_순이다(self):
        rows = cti.applicability(APACHE, [], self.assets(), [], NOW)
        self.assertEqual([r["asset_id"] for r in rows], ["web-01", "console-b", "data-01", "fw", "honeypot-dmz"])
        self.assertEqual(rows[0]["collected_at"], "2026-09-25T02:00:00+00:00")

    def test_센서_값을_자산으로_바꿔_요청_받은_자산을_가린다(self):
        cases = {("web-01",): {"web-01"}, ("cowrie",): {"honeypot-dmz"}, ("gateway",): {"gateway"},
                 ("decoy", "web-01"): {"web-01", "web-decoy"}}
        for sensors, want in cases.items():
            with self.subTest(sensors=sensors):
                rows = cti.applicability(APACHE, list(sensors), self.assets(), [], NOW)
                self.assertEqual({r["asset_id"] for r in rows if r["targeted"]}, want)

    def test_자산_표에_없는_요청_받은_자산은_미확인으로_넣는다(self):
        rows = cti.applicability(APACHE, ["web-02", "gateway"], self.assets(), [], NOW)
        by_id = {r["asset_id"]: r for r in rows}
        self.assertEqual(by_id["web-02"], {"asset_id": "web-02", "role": "target", "targeted": True,
                                           "status": "unknown", "reason": "자산 정보가 아직 없다", "collected_at": None})
        self.assertEqual(by_id["gateway"]["role"], "platform")
        self.assertEqual([r["asset_id"] for r in rows][:2], ["web-01", "web-02"])
        self.assertEqual(cti.summarize(rows), "unknown")

    def test_자산_취약점은_그_자산의_서명_CVE_만_본다(self):
        vulns = [{"asset_id": "data-01", "source_package": "apache2", "version": "2.4.58-1ubuntu8.4",
                  "cve_id": "CVE-2021-41773", "fix_state": "fix_available"},
                 {"asset_id": "web-01", "source_package": "apache2", "version": "x",
                  "cve_id": "CVE-2021-41773", "fix_state": "fix_available"},
                 {"asset_id": "data-01", "source_package": "apache2", "version": "x",
                  "cve_id": "CVE-2099-0001", "fix_state": "fix_available"}]
        rows = {r["asset_id"]: r for r in cti.applicability(APACHE, ["web-01"], self.assets(), vulns, NOW)}
        self.assertEqual(rows["data-01"]["reason"], "apache2 2.4.58-1ubuntu8.4 · CVE-2021-41773 (수정판 있음)")
        self.assertEqual(rows["web-01"]["status"], "not_affected")   # 설치되지 않은 자산의 행은 쓰지 않는다

    def test_실제_서명_파일의_모든_서명을_판정할_수_있다(self):
        definition = json.loads(RULES_CVE.read_text())
        sigs = [s for r in definition["rules"] if r["type"] == "url_signature" for s in r["params"]["signatures"]]
        self.assertGreater(len(sigs), 10)
        for sig in sigs:
            with self.subTest(sig=sig["id"]):
                rows = cti.applicability(sig, ["decoy", "web-01"], self.assets(), [], NOW)
                self.assertTrue(all(r["status"] in ("affected", "not_affected", "unknown") for r in rows))
                self.assertIn(cti.summarize(rows), ("affected", "not_affected", "unknown"))


class SummaryTests(unittest.TestCase):
    @staticmethod
    def row(status, targeted=False, role="platform"):
        return {"status": status, "targeted": targeted, "role": role}

    def test_하나라도_해당이면_해당이다(self):
        self.assertEqual(cti.summarize([self.row("unknown", True), self.row("affected")]), "affected")

    def test_요청_받은_자산이나_관제_대상이_미확인이면_미확인이다(self):
        self.assertEqual(cti.summarize([self.row("not_affected"), self.row("unknown", targeted=True)]), "unknown")
        self.assertEqual(cti.summarize([self.row("unknown", role="target")]), "unknown")

    def test_요청을_받지_않은_관제_기반_센서의_미확인은_비해당으로_둔다(self):
        rows = [self.row("unknown"), self.row("unknown", role="sensor"), self.row("not_affected", True, "target")]
        self.assertEqual(cti.summarize(rows), "not_affected")
        self.assertEqual(cti.summarize([]), "not_affected")
        self.assertEqual(cti.summarize([dict(cti.DECOY_ENTRY)]), "not_affected")


class FreshnessTests(unittest.TestCase):
    @staticmethod
    def snap(source, hours):
        return {"source": source, "fetched_at": NOW - timedelta(hours=hours),
                "source_ts": datetime(2026, 9, 24, 12, 0, 20, tzinfo=timezone.utc)}

    def test_출처별_오래됨과_NVD_예외(self):
        fresh = cti.freshness([self.snap("kev", 2), self.snap("epss", 48), self.snap("osv", 49), self.snap("nvd", 900)],
                              [], NOW)
        self.assertEqual(fresh["kev"], {"fetched_at": "2026-09-25T01:00:00+00:00",
                                        "source_ts": "2026-09-24T12:00:20+00:00", "stale": False})
        self.assertFalse(fresh["epss"]["stale"])
        self.assertTrue(fresh["osv"]["stale"])
        self.assertFalse(fresh["nvd"]["stale"])
        self.assertTrue(cti.any_stale(fresh))
        self.assertFalse(cti.any_stale(cti.freshness([self.snap(s, 1) for s in ("kev", "epss", "osv")], [], NOW)))

    def test_받은_적_없는_출처는_오래됨이다(self):
        fresh = cti.freshness([self.snap("kev", 1)], [], NOW)
        self.assertEqual(fresh["epss"], {"fetched_at": None, "source_ts": None, "stale": True})
        self.assertEqual(fresh["nvd"], {"fetched_at": None, "source_ts": None, "stale": False})

    def test_자산_가장_오래된_수집과_오래된_자산(self):
        assets = [{"asset_id": "web-01", "collected_at": NOW - timedelta(hours=1)},
                  {"asset_id": "console-a", "collected_at": NOW - timedelta(hours=72)},
                  {"asset_id": "console-b", "collected_at": None}]
        fresh = cti.freshness([], assets, NOW)
        self.assertEqual(fresh["assets"], {"oldest_collected_at": "2026-09-22T03:00:00+00:00",
                                           "stale_assets": ["console-a", "console-b"]})
        # 자산이 오래돼도 공개 정보 오래됨(stale)과는 따로다
        self.assertEqual(cti.freshness([], [], NOW)["assets"], {"oldest_collected_at": None, "stale_assets": []})


class ShapeTests(unittest.TestCase):
    @staticmethod
    def cve_row(cve_id, kev=False, epss=None, cvss=None):
        return {"cve_id": cve_id, "in_kev": kev, "vendor_project": "Apache" if kev else None,
                "product": "HTTP Server" if kev else None, "name": "경로 조작" if kev else None,
                "date_added": date(2021, 11, 3) if kev else None, "due_date": date(2021, 11, 17) if kev else None,
                "ransomware": "Known" if kev else None, "epss": epss, "epss_percentile": 0.9994400024414062 if epss else None,
                "epss_date": date(2026, 9, 24) if epss else None, "cvss_score": cvss, "cvss_version": "3.1" if cvss else None,
                "cvss_vector": "CVSS:3.1/AV:N" if cvss else None, "cvss_severity": "HIGH" if cvss else None,
                "description": None, "nvd_fetched_at": None}

    def test_CVE_는_KEV_먼저_EPSS_높은_순_id_순이다(self):
        rows = [self.cve_row("CVE-2024-0003"), self.cve_row("CVE-2024-0002", epss=0.1),
                self.cve_row("CVE-2024-0001", kev=True), self.cve_row("CVE-2024-0009", kev=True, epss=0.5),
                self.cve_row("CVE-2024-0004", epss=0.9), self.cve_row("CVE-2024-0000")]
        items = sorted((cti.cve_item(r, {"s"}) for r in rows), key=cti.cve_sort_key)
        self.assertEqual([i["cve_id"] for i in items], ["CVE-2024-0009", "CVE-2024-0001", "CVE-2024-0004",
                                                        "CVE-2024-0002", "CVE-2024-0000", "CVE-2024-0003"])

    def test_CVE_모양(self):
        item = cti.cve_item(self.cve_row("CVE-2021-41773", kev=True, epss=0.9950600266456604, cvss=Decimal("7.5")),
                            {"b", "a"})
        self.assertEqual(item["signature_ids"], ["a", "b"])
        self.assertEqual(item["kev"], {"date_added": "2021-11-03", "due_date": "2021-11-17", "ransomware": "Known",
                                       "name": "경로 조작", "vendor_project": "Apache", "product": "HTTP Server"})
        self.assertEqual(item["epss"], {"score": 0.99506, "percentile": 0.99944, "date": "2026-09-24"})
        self.assertEqual(item["cvss"], {"score": 7.5, "version": "3.1", "vector": "CVSS:3.1/AV:N", "severity": "HIGH"})
        bare = cti.cve_item(self.cve_row("CVE-2021-42013"), {"a"})
        self.assertEqual((bare["kev"], bare["epss"], bare["cvss"]), (None, None, None))

    def test_dpkg_버전_비교(self):
        less = [("1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.19"),
                ("1.9.15p5-3ubuntu5.24.04.2", "1.9.15p5-3ubuntu5.24.04.3"),
                ("6.8.0-139.139", "6.8.0-142.142"), ("1.0~rc1", "1.0"), ("1.0", "1.0a"), ("1.0a", "1.0+b1"),
                ("2.0", "1:0.1"), ("29.1.3-0ubuntu3~24.04.2", "29.1.3-0ubuntu3"), ("1.0-1", "1.0-1.1"),
                ("1.2", "1.10"), ("1.0~~", "1.0~")]
        for a, b in less:
            with self.subTest(a=a, b=b):
                self.assertLess(cti.dpkg_compare(a, b), 0)
                self.assertGreater(cti.dpkg_compare(b, a), 0)
        for a, b in [("1.0", "1.0"), ("1.01", "1.1"), ("0:1.0", "1.0"), ("1.0-0", "1.0")]:
            with self.subTest(a=a, b=b):
                self.assertEqual(cti.dpkg_compare(a, b), 0)

    def test_커널_재부팅_대기(self):
        kernel = {"running": "6.8.0-139-generic", "running_version": "6.8.0-139.139",
                  "installed": [{"package": "linux-image-6.8.0-142-generic", "version": "6.8.0-142.142"},
                                {"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"},
                                {"package": "linux-image-6.8.0-99-generic", "version": "6.8.0-99.99"}]}
        self.assertEqual(cti.kernel_state(kernel), {"kernel_running": "6.8.0-139-generic",
                                                    "kernel_running_version": "6.8.0-139.139",
                                                    "kernel_newest_version": "6.8.0-142.142", "reboot_pending": True})
        kernel["installed"] = kernel["installed"][1:]
        self.assertFalse(cti.kernel_state(kernel)["reboot_pending"])
        self.assertEqual(cti.kernel_state(None), {"kernel_running": None, "kernel_running_version": None,
                                                  "kernel_newest_version": None, "reboot_pending": False})
        self.assertFalse(cti.kernel_state({"installed": ["x", {"version": 3}]})["reboot_pending"])

    def test_재부팅_대기는_같은_판의_커널끼리_본다(self):
        # AWS 커널(6.8.0-1015.16)과 generic 커널(6.8.0-142.142)은 번호 체계가 달라 섞어 비교하면 늘 재부팅 대기로 보인다
        kernel = {"running": "6.8.0-1015-aws", "running_version": "6.8.0-1015.16",
                  "installed": [{"package": "linux-image-6.8.0-1015-aws", "version": "6.8.0-1015.16"},
                                {"package": "linux-image-6.8.0-142-generic", "version": "6.8.0-142.142"},
                                {"version": "6.9.0-1.1"}]}
        self.assertEqual(cti.kernel_state(kernel)["kernel_newest_version"], "6.8.0-1015.16")
        self.assertFalse(cti.kernel_state(kernel)["reboot_pending"])
        kernel["installed"].append({"package": "linux-image-6.8.0-1016-aws", "version": "6.8.0-1016.17"})
        self.assertEqual((cti.kernel_state(kernel)["kernel_newest_version"], cti.kernel_state(kernel)["reboot_pending"]),
                         ("6.8.0-1016.17", True))
        # 실행 중 커널의 판을 모르면 모든 이미지를 본다
        odd = dict(kernel, running="custom")
        self.assertEqual(cti.kernel_state(odd)["kernel_newest_version"], "6.9.0-1.1")
        self.assertEqual(cti.kernel_flavor("6.8.0-139-generic"), "generic")
        self.assertEqual(cti.kernel_flavor("6.8.0-139-lowlatency-64k"), "lowlatency-64k")
        self.assertIsNone(cti.kernel_flavor(None))

    def test_자산_행과_주요_패키지(self):
        row = {"asset_id": "fw", "role": "platform", "method": "ssh", "host": "opsloop-fw",
               "collected_at": NOW - timedelta(hours=50), "received_at": NOW, "last_attempt_at": NOW, "last_error": None,
               "os": json.dumps(UBUNTU), "kernel": json.dumps({"running_version": "1", "installed": [{"version": "2"}]}),
               "images": "[]", "packages": 812, "checked_at": None, "check_error": "지원하지 않는 배포판",
               "vuln_total": 3, "vuln_kev": 1, "vuln_fix_available": 1, "vuln_reboot_pending": 1,
               "max_epss": 0.8000000119209290}
        got = cti.asset_row(row, NOW)
        self.assertTrue(got["stale"])
        self.assertTrue(got["reboot_pending"])
        self.assertEqual((got["os_pretty"], got["packages"], got["images"], got["max_epss"]),
                         ("Ubuntu 24.04.5 LTS", 812, 0, 0.8))
        self.assertEqual(got["collected_at"], "2026-09-23T01:00:00+00:00")
        keys = cti.key_packages([{"name": "sudo", "version": "1"}, {"name": "libc6", "version": "2"},
                                 {"name": "libc6", "version": "3"}, {"name": "openssh-server", "version": "4"}])
        self.assertEqual(keys, [{"name": "openssh-server", "version": "4"}, {"name": "sudo", "version": "1"},
                                {"name": "libc6", "version": "2"}])


# ----------------------------------------------------------------------
#  커널 소스 규칙 · 주목 CVE 대조
# ----------------------------------------------------------------------

def pkg(name, version, source=None, source_version=None):
    return {"name": name, "version": version, "source": source or name, "source_version": source_version or version,
            "arch": "amd64"}


GENERIC = {"running": "6.8.0-139-generic", "running_package": "linux-image-6.8.0-139-generic",
           "running_version": "6.8.0-139.139",
           "installed": [{"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"}]}
AWS = {"running": "6.8.0-1015-aws", "running_package": "linux-image-6.8.0-1015-aws", "running_version": "6.8.0-1015.16",
       "installed": [{"package": "linux-image-6.8.0-1015-aws", "version": "6.8.0-1015.16"}]}
GENERIC_IMAGE = pkg("linux-image-6.8.0-139-generic", "6.8.0-139.139", "linux-signed")
AWS_IMAGE = pkg("linux-image-6.8.0-1015-aws", "6.8.0-1015.16", "linux-signed-aws")
# linux 소스에서 나오지만 커널이 아닌 패키지(사용자 공간 헤더)
LIBC_DEV = pkg("linux-libc-dev", "6.8.0-139.139", "linux")
FETCHER = Path(__file__).resolve().parents[1] / "cti" / "opsloop_cti.py"


def load_fetcher():
    """수집기 모듈을 다른 이름으로 불러온다(콘솔의 cti 모듈과 이름이 겹친다). 표준 라이브러리만 쓴다."""
    spec = importlib.util.spec_from_file_location("opsloop_cti_for_test", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sign(n: int) -> int:
    return (n > 0) - (n < 0)


class KernelSourceTests(unittest.TestCase):
    """계약 10.5: 실행 중인 커널의 소스 패키지 이름. 수집기와 같은 규칙이다."""

    def test_실행_중인_이미지_패키지의_소스에서_서명_메타_접두를_뗀다(self):
        cases = [(GENERIC, [GENERIC_IMAGE], "linux"), (AWS, [AWS_IMAGE], "linux-aws"),
                 (AWS, [pkg("linux-image-6.8.0-1015-aws", "1", "linux-meta-aws")], "linux-aws"),
                 (AWS, [pkg("linux-image-6.8.0-1015-aws", "1", "linux-aws")], "linux-aws"),
                 (dict(GENERIC, running="6.11.0-29-generic", running_package="linux-image-6.11.0-29-generic"),
                  [pkg("linux-image-6.11.0-29-generic", "6.11.0-29.29~24.04.1", "linux-signed-hwe-6.11")], "linux-hwe-6.11")]
        for kernel, packages, want in cases:
            with self.subTest(want=want, packages=packages):
                self.assertEqual(cti.kernel_source(kernel, packages), want)

    def test_이미지가_없으면_모듈_패키지_그래도_없으면_linux(self):
        modules = pkg("linux-modules-6.8.0-1015-aws", "6.8.0-1015.16", "linux-aws")
        self.assertEqual(cti.kernel_source(AWS, [LIBC_DEV, modules]), "linux-aws")
        # 이미지 패키지의 소스가 커널 꼴이 아니면 모듈을 본다
        self.assertEqual(cti.kernel_source(AWS, [pkg("linux-image-6.8.0-1015-aws", "1", "weird"), modules]), "linux-aws")
        self.assertEqual(cti.kernel_source(AWS, [LIBC_DEV]), "linux")
        self.assertEqual(cti.kernel_source(None, None), "linux")
        self.assertEqual(cti.kernel_source({"running": 3, "running_package": None}, ["x", {"name": None}]), "linux")

    def test_커널_소스_판별(self):
        for name in ["linux", "linux-aws", "linux-azure-fde", "linux-hwe-6.8", "linux-signed-aws", "linux-meta",
                     "linux-lowlatency-hwe-6.11"]:
            with self.subTest(name=name):
                self.assertTrue(cti.is_kernel_source(name))
        # 이름만 linux 로 시작하는 사용자 공간 · 펌웨어 · DKMS 소스(수집기의 NON_KERNEL_SOURCES 와 같다)
        for name in ["linux-firmware", "linux-firmware-raspi", "linux-base", "linux-atm", "linux-sound-base",
                     "linux-igd", "linux-wlan-ng", "linux-apfs-rw", "linux-gpib", "linux-show-player",
                     "linuxdoc-tools", "openssh", "", None, 3]:
            with self.subTest(name=name):
                self.assertFalse(cti.is_kernel_source(name))

    def test_수집기와_같은_답을_낸다(self):
        """콘솔과 수집기(cti/opsloop_cti.py)는 따로 배포되어 코드를 나누지 않는다. 같은 입력에 같은 답인지 본다."""
        fetcher = load_fetcher()
        sources = ["linux", "linux-aws", "linux-signed", "linux-signed-aws", "linux-meta-aws", "linux-hwe-6.8",
                   "linux-azure-fde", "linux-lowlatency-hwe-6.11", "linux-firmware", "linux-firmware-raspi",
                   "linux-base", "linux-atm", "linux-sound-base", "linux-igd", "linux-wlan-ng", "linux-apfs-rw",
                   "linux-gpib", "linux-show-player", "linux-libc-dev", "linuxdoc-tools", "linux-signedx",
                   "linux-metadata", "openssh", "", None]
        for name in sources:
            with self.subTest(source=name):
                self.assertEqual(cti.is_kernel_source(name), fetcher.is_kernel_source(name))
        image = lambda source: pkg("linux-image-6.8.0-1015-aws", "6.8.0-1015.16", source)
        modules = pkg("linux-modules-6.8.0-1015-aws", "6.8.0-1015.16", "linux-aws")
        cases = [(GENERIC, [GENERIC_IMAGE]), (AWS, [AWS_IMAGE]), (AWS, [LIBC_DEV]), (AWS, [LIBC_DEV, modules]),
                 (AWS, [image("weird"), modules]), (AWS, [image("linux-firmware"), modules]),
                 (AWS, [image("linux-signedx")]), (AWS, [image("linux-meta")]), (AWS, [image("linux-apfs-rw")]),
                 (None, None), ({"running": 3, "running_package": None}, [{"name": None}])]
        for kernel, packages in cases:
            with self.subTest(kernel=kernel, packages=packages):
                self.assertEqual(cti.kernel_source(kernel, packages), fetcher.kernel_source(kernel, packages))
        for os_info in [UBUNTU, {"id": "ubuntu", "version_id": "22.04"}, {"id": "ubuntu", "version_id": "24.10"},
                        {"id": "ubuntu", "version_id": "25.04"}, {"id": "debian", "version_id": "12"}, None]:
            with self.subTest(os_info=os_info):
                self.assertEqual(cti.ubuntu_ecosystem(os_info), fetcher.osv_ecosystem(os_info))
        versions = ["1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.19", "9.6p1-3ubuntu13.19", "2.38-1ubuntu6",
                    "2.39-0ubuntu8.6", "1.0~rc1-1", "1.0-1", "1.0+b1-1", "6.8.0-139.139", "6.8.0-1015.16", "5.4.5-0.3"]
        for a in versions:
            for b in versions:
                with self.subTest(a=a, b=b):
                    self.assertEqual(sign(cti.dpkg_compare(a, b)), sign(fetcher.dpkg_compare(a, b)))

    def test_생태계_이름은_수집기와_같다(self):
        cases = [(UBUNTU, "Ubuntu:24.04:LTS"), ({"id": "ubuntu", "version_id": "22.04"}, "Ubuntu:22.04:LTS"),
                 ({"id": "ubuntu", "version_id": "25.04"}, "Ubuntu:25.04"),
                 ({"id": "ubuntu", "version_id": "24.10"}, "Ubuntu:24.10"),
                 ({"id": "debian", "version_id": "12"}, None), ({"id": "ubuntu", "version_id": "24.04.5"}, None),
                 ({"id": "ubuntu"}, None), (None, None), ("ubuntu", None)]
        for os_info, want in cases:
            with self.subTest(os_info=os_info):
                self.assertEqual(cti.ubuntu_ecosystem(os_info), want)


OPENSSH = pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh")
RECORD_AT = NOW - timedelta(hours=2)   # 배포판 기록을 조회한 시각 (48시간 안)
WATCH_6387 = {"record_found": True, "checked_at": RECORD_AT,
              "affected": {"Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3",
                           "Ubuntu:22.04:LTS/openssh": "1:8.9p1-3ubuntu0.10"}}
WATCH_KERNEL = {"record_found": True, "checked_at": RECORD_AT,
                "affected": {"Ubuntu:24.04:LTS/linux": None, "Ubuntu:24.04:LTS/linux-aws": None}}


def watched(watch, a):
    return cti.judge_watch(watch, a, NOW)


def result(status, reason, package=None, installed=None, fixed=None):
    return {"status": status, "reason": reason, "package": package, "installed": installed, "fixed": fixed}


class JudgeWatchTests(unittest.TestCase):
    """계약 10.6: 주목 CVE 하나 · 자산 하나. 설치 버전과 배포판 수정판을 dpkg 규칙으로 비교한다."""

    def test_자산_정보가_없거나_오래되면_미확인이다(self):
        self.assertEqual(watched(WATCH_6387, asset(collected=None)), result("unknown", "자산 정보가 아직 없다"))
        self.assertEqual(watched(WATCH_6387, asset(collected=datetime(2026, 9, 23, 2, 59, tzinfo=timezone.utc))),
                         result("unknown", "자산 정보가 오래됐다 (마지막 수집 2026-09-23 11:59 KST). 비해당으로 보지 않는다"))

    def test_배포판_기록을_모르면_미확인이다(self):
        a = asset(packages=[OPENSSH], kernel=GENERIC)
        self.assertEqual(watched({"record_found": None, "affected": None}, a),
                         result("unknown", "배포판 기록을 아직 조회하지 않았다"))
        self.assertEqual(watched({"record_found": False, "affected": None}, a),
                         result("unknown", "배포판(Ubuntu) 기록이 없다"))
        # 기록은 있다는데 영향 항목을 받지 않았다(상세 없는 기록). 빈 사전을 '영향 없음'으로 읽지 않는다
        self.assertEqual(watched({"record_found": True, "checked_at": RECORD_AT, "affected": None}, a),
                         result("unknown", "배포판 기록의 영향 항목을 아직 받지 않았다"))

    def test_Ubuntu_가_아니면_미확인이다(self):
        self.assertEqual(watched(WATCH_6387, asset(os={"id": "debian", "version_id": "12", "pretty": "Debian 12"})),
                         result("unknown", "Debian 12 는 배포판(Ubuntu) 기록으로 대조하지 않는다"))
        self.assertEqual(watched(WATCH_6387, asset(os=None)), result("unknown", "운영체제를 알 수 없다"))

    def test_이_릴리스의_영향_항목이_없으면_비해당이다(self):
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:20.04:LTS/sudo": "1.8.31-1ubuntu1.2"}}
        self.assertEqual(watched(watch, asset(packages=[pkg("sudo", "1.9.15p5-3ubuntu5.24.04.2")])),
                         result("not_affected", "배포판 기록에 이 릴리스(Ubuntu 24.04.5 LTS)의 영향 패키지가 없다"))
        self.assertEqual(watched({"record_found": True, "checked_at": RECORD_AT, "affected": {}}, asset())["status"], "not_affected")

    def test_조사가_패키지_목록을_못_읽었으면_미확인이다(self):
        self.assertEqual(watched(WATCH_6387, asset(probe_errors=["packages: dpkg-query: 종료 2"])),
                         result("unknown", "조사 중 패키지 목록을 읽지 못했다"))
        self.assertEqual(watched(WATCH_6387, asset(package_count=0)),
                         result("unknown", "조사 결과에 패키지 목록이 비어 있다"))

    def test_설치_버전과_수정판을_비교한다(self):
        self.assertEqual(watched(WATCH_6387, asset(packages=[OPENSSH])),
                         result("not_affected", "openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3",
                                "openssh", "1:9.6p1-3ubuntu13.19", "1:9.6p1-3ubuntu13.3"))
        old = pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")
        self.assertEqual(watched(WATCH_6387, asset(packages=[old])),
                         result("affected", "openssh 1:9.6p1-3ubuntu13.2 < 수정판 1:9.6p1-3ubuntu13.3",
                                "openssh", "1:9.6p1-3ubuntu13.2", "1:9.6p1-3ubuntu13.3"))
        same = pkg("openssh-server", "1:9.6p1-3ubuntu13.3", "openssh")
        self.assertEqual(watched(WATCH_6387, asset(packages=[same]))["status"], "not_affected")

    def test_같은_소스의_설치_버전이_여럿이면_가장_낮은_것으로_본다(self):
        # 바이너리 둘이 다른 소스 버전으로 남아 있다(한쪽만 올라감)
        packages = [pkg("openssh-server", "1:9.6p1-3ubuntu13.19", "openssh"),
                    pkg("openssh-client", "1:9.6p1-3ubuntu13.2", "openssh")]
        self.assertEqual(watched(WATCH_6387, asset(packages=packages))["installed"], "1:9.6p1-3ubuntu13.2")
        # 소스 버전이 바이너리 버전과 다르면 소스 버전을 쓴다
        binnmu = pkg("openssh-server", "1:9.6p1-3ubuntu13.19+b1", "openssh", "1:9.6p1-3ubuntu13.19")
        self.assertEqual(watched(WATCH_6387, asset(packages=[binnmu]))["installed"], "1:9.6p1-3ubuntu13.19")

    def test_수정판이_없으면_해당이다(self):
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/sudo": None}}
        self.assertEqual(watched(watch, asset(packages=[pkg("sudo", "1.9.15p5-3ubuntu5.24.04.3")])),
                         result("affected", "sudo 1.9.15p5-3ubuntu5.24.04.3 · 배포판 수정판 없음", "sudo",
                                "1.9.15p5-3ubuntu5.24.04.3", None))

    def test_영향_패키지가_없으면_비해당이다(self):
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/xz-utils": "5.4.5-0.3",
                                                    "Ubuntu:24.04:LTS/policykit-1": None}}
        self.assertEqual(watched(watch, asset(packages=[OPENSSH])),
                         result("not_affected", "영향 패키지(policykit-1 · xz-utils)가 설치돼 있지 않다"))

    def test_커널은_실행_중인_커널_소스와_버전으로_본다(self):
        generic = asset(packages=[GENERIC_IMAGE, LIBC_DEV], kernel=GENERIC)
        self.assertEqual(watched(WATCH_KERNEL, generic),
                         result("affected", "linux 6.8.0-139.139 · 배포판 수정판 없음", "linux", "6.8.0-139.139"))
        # AWS 커널이 도는 자산은 linux-aws 항목으로 본다. linux 소스의 사용자 공간 헤더를 커널로 읽지 않는다
        aws = asset(packages=[AWS_IMAGE, LIBC_DEV], kernel=AWS)
        self.assertEqual(watched(WATCH_KERNEL, aws),
                         result("affected", "linux-aws 6.8.0-1015.16 · 배포판 수정판 없음", "linux-aws", "6.8.0-1015.16"))
        fixed = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/linux": "6.8.0-140.140"}}
        self.assertEqual(watched(fixed, generic)["reason"], "linux 6.8.0-139.139 < 수정판 6.8.0-140.140")
        self.assertEqual(watched(fixed, aws), result("not_affected", "영향 패키지(linux)가 설치돼 있지 않다"))
        # 다른 판의 커널(linux-azure-fde)만 기록에 있다
        azure = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/linux-azure-fde": None}}
        self.assertEqual(watched(azure, generic)["reason"], "영향 패키지(linux-azure-fde)가 설치돼 있지 않다")

    def test_커널이_아닌_linux_소스는_여느_패키지처럼_본다(self):
        # linux-apfs-rw 는 DKMS · 사용자 공간 소스다. 다른 판 커널로 읽어 건너뛰면 '설치 안 됨'이 된다
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/linux-apfs-rw": "0.3.8-1"}}
        a = asset(packages=[GENERIC_IMAGE, pkg("apfs-dkms", "0.3.7-1", "linux-apfs-rw")], kernel=GENERIC)
        self.assertEqual(watched(watch, a), result("affected", "linux-apfs-rw 0.3.7-1 < 수정판 0.3.8-1",
                                                   "linux-apfs-rw", "0.3.7-1", "0.3.8-1"))

    def test_실행_중인_커널_버전을_모르면_미확인이다(self):
        self.assertEqual(watched(WATCH_KERNEL, asset(packages=[OPENSSH], kernel={"running": "6.8.0-139-generic"})),
                         result("unknown", "linux · 실행 중인 커널 버전을 모른다", "linux"))
        self.assertEqual(watched(WATCH_KERNEL, asset(packages=[OPENSSH], kernel=None))["status"], "unknown")

    def test_여러_항목이면_해당이_먼저고_이유를_잇는다(self):
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/glibc": "2.38-1ubuntu6",
                                                    "Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3",
                                                    "Ubuntu:24.04:LTS/sudo": None}}
        packages = [pkg("libc6", "2.38-1ubuntu5", "glibc"), OPENSSH, pkg("sudo", "1.9.15p5-3ubuntu5.24.04.3")]
        got = watched(watch, asset(packages=packages))
        self.assertEqual(got, result("affected", "glibc 2.38-1ubuntu5 < 수정판 2.38-1ubuntu6, "
                                                 "sudo 1.9.15p5-3ubuntu5.24.04.3 · 배포판 수정판 없음",
                                     "glibc", "2.38-1ubuntu5", "2.38-1ubuntu6"))
        # 해당이 없으면 비해당 항목들의 이유를 잇는다
        packages[0] = pkg("libc6", "2.39-0ubuntu8.6", "glibc")
        del watch["affected"]["Ubuntu:24.04:LTS/sudo"]
        self.assertEqual(watched(watch, asset(packages=packages))["reason"],
                         "glibc 2.39-0ubuntu8.6 ≥ 수정판 2.38-1ubuntu6, "
                         "openssh 1:9.6p1-3ubuntu13.19 ≥ 수정판 1:9.6p1-3ubuntu13.3")
        # 미확인(커널 버전 모름)은 해당보다 뒤, 비해당보다 앞이다
        mixed = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/linux": None,
                                                    "Ubuntu:24.04:LTS/openssh": "1:9.6p1-3ubuntu13.3"}}
        self.assertEqual(watched(mixed, asset(packages=[OPENSSH], kernel={}))["status"], "unknown")

    def test_비신뢰_값이_이상해도_죽지_않는다(self):
        watch = {"record_found": True, "checked_at": RECORD_AT, "affected": {"Ubuntu:24.04:LTS/openssh": 3, "Ubuntu:24.04:LTS/": "1",
                                                    "no-slash": "1"}}
        odd = asset(packages=["x", None, {"source": "openssh", "source_version": None},
                              {"source": "openssh", "source_version": "1:9.6p1-3ubuntu13.19"}], kernel="x")
        # 수정판 값이 문자열이 아니면 수정판 없음으로 본다(해당 쪽으로 기운다)
        self.assertEqual(watched(watch, odd)["reason"], "openssh 1:9.6p1-3ubuntu13.19 · 배포판 수정판 없음")


class WatchItemTests(unittest.TestCase):
    @staticmethod
    def row(cve_id, kev=False, epss=None, cvss=None, record_found=True):
        return {"cve_id": cve_id, "reason": "시험", "osv_id": "UBUNTU-" + cve_id, "record_found": record_found,
                "checked_at": NOW - timedelta(hours=2), "ubuntu_priority": "high", "description": "설명",
                "in_kev": kev, "kev_date_added": date(2024, 5, 30) if kev else None,
                "kev_ransomware": "Known" if kev else None, "kev_name": "시험 항목" if kev else None,
                "epss": epss, "epss_percentile": 0.9994400024414062 if epss else None,
                "epss_date": date(2026, 9, 24) if epss else None, "cvss_score": cvss,
                "cvss_severity": "HIGH" if cvss else None}

    def test_행_모양과_요약(self):
        old = pkg("openssh-server", "1:9.6p1-3ubuntu13.2", "openssh")
        assets = [asset("web-01", packages=[OPENSSH]), asset("fw", "platform", packages=[old]),
                  asset("console-b", "platform", collected=None)]
        item = cti.watch_item(self.row("CVE-2024-6387", epss=0.9950600266456604, cvss=Decimal("8.1")),
                              WATCH_6387["affected"], assets, ["Ubuntu:24.04:LTS"], NOW)
        self.assertEqual({k: item[k] for k in ("cve_id", "reason", "osv_id", "record_found", "checked_at",
                                               "ubuntu_priority", "description", "kev", "epss", "cvss")},
                         {"cve_id": "CVE-2024-6387", "reason": "시험", "osv_id": "UBUNTU-CVE-2024-6387",
                          "record_found": True, "checked_at": "2026-09-25T01:00:00+00:00", "ubuntu_priority": "high",
                          "description": "설명", "kev": None,
                          "epss": {"score": 0.99506, "percentile": 0.99944, "date": "2026-09-24"},
                          "cvss": {"score": 8.1, "severity": "HIGH"}})
        # 자산 생태계가 하나면 그 생태계 항목만, 생태계 이름 없이
        self.assertEqual(item["affected_packages"], [{"package": "openssh", "fixed": "1:9.6p1-3ubuntu13.3"}])
        self.assertEqual([(a["asset_id"], a["role"], a["status"]) for a in item["assets"]],
                         [("web-01", "target", "not_affected"), ("fw", "platform", "affected"),
                          ("console-b", "platform", "unknown")])
        self.assertEqual(item["assets"][1], {"asset_id": "fw", "role": "platform", "status": "affected",
                                             "reason": "openssh 1:9.6p1-3ubuntu13.2 < 수정판 1:9.6p1-3ubuntu13.3",
                                             "package": "openssh", "installed": "1:9.6p1-3ubuntu13.2",
                                             "fixed": "1:9.6p1-3ubuntu13.3"})
        self.assertEqual(item["summary"], "affected")
        json.dumps(item)

    def test_생태계가_여럿이면_항목에_생태계를_적는다(self):
        item = cti.watch_item(self.row("CVE-2024-6387"), WATCH_6387["affected"], [],
                              ["Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS"], NOW)
        self.assertEqual(item["affected_packages"],
                         [{"ecosystem": "Ubuntu:22.04:LTS", "package": "openssh", "fixed": "1:8.9p1-3ubuntu0.10"},
                          {"ecosystem": "Ubuntu:24.04:LTS", "package": "openssh", "fixed": "1:9.6p1-3ubuntu13.3"}])
        # 판정한 자산이 없으면 모르는 것이다. 비해당으로 요약하지 않는다
        self.assertEqual((item["assets"], item["summary"]), ([], "unknown"))
        self.assertEqual(cti.watch_item(self.row("CVE-2021-4034", record_found=False), None, [], [], NOW)
                         ["affected_packages"], [])

    def test_요약은_관제_대상의_미확인만_따진다(self):
        platform_unknown = [asset("web-01", packages=[OPENSSH]), asset("console-b", "platform", collected=None)]
        self.assertEqual(cti.watch_item(self.row("CVE-2024-6387"), WATCH_6387["affected"], platform_unknown,
                                        ["Ubuntu:24.04:LTS"], NOW)["summary"], "not_affected")
        target_unknown = [asset("web-01", collected=None)]
        self.assertEqual(cti.watch_item(self.row("CVE-2024-6387"), WATCH_6387["affected"], target_unknown,
                                        ["Ubuntu:24.04:LTS"], NOW)["summary"], "unknown")

    def test_관제_대상이_없거나_기록을_모르면_요약은_미확인이다(self):
        platform_only = [asset("fw", "platform", packages=[OPENSSH])]
        self.assertEqual(cti.watch_item(self.row("CVE-2024-6387"), WATCH_6387["affected"], platform_only,
                                        ["Ubuntu:24.04:LTS"], NOW)["summary"], "unknown")
        web = [asset("web-01", packages=[OPENSSH])]
        for found in (None, False):
            with self.subTest(record_found=found):
                item = cti.watch_item(self.row("CVE-2024-6387", record_found=found), None, web, ["Ubuntu:24.04:LTS"], NOW)
                self.assertEqual(item["summary"], "unknown")
                self.assertEqual(item["assets"][0]["status"], "unknown")

    def test_배포판_기록_조회가_오래되면_비해당이_아니라_미확인이다(self):
        web = asset("web-01", packages=[OPENSSH])
        old = dict(WATCH_6387, checked_at=NOW - timedelta(hours=49))
        got = watched(old, web)
        self.assertEqual(got["status"], "unknown")
        self.assertTrue(got["reason"].startswith("배포판 기록 조회가 오래됐다 (조회 "), got["reason"])
        self.assertTrue(got["reason"].endswith(". 비해당으로 보지 않는다"), got["reason"])
        self.assertEqual(watched(dict(WATCH_6387, checked_at=None), web)["status"], "unknown")
        self.assertEqual(watched(WATCH_6387, web)["status"], "not_affected")   # 48시간 안이면 판정한다
        stale_row = dict(self.row("CVE-2024-6387"), checked_at=NOW - timedelta(hours=49))
        self.assertEqual(cti.watch_item(stale_row, WATCH_6387["affected"], [web], ["Ubuntu:24.04:LTS"], NOW)["summary"],
                         "unknown")

    def test_정렬은_해당_KEV_EPSS_id_순이다(self):
        def item(cve_id, summary, kev=False, epss=None):
            return {"cve_id": cve_id, "summary": summary, "kev": {"x": 1} if kev else None,
                    "epss": {"score": epss} if epss is not None else None}
        items = [item("CVE-2021-0001", "not_affected"), item("CVE-2021-0002", "unknown", epss=0.5),
                 item("CVE-2021-0003", "affected"), item("CVE-2021-0004", "not_affected", kev=True),
                 item("CVE-2021-0005", "affected", kev=True, epss=0.1), item("CVE-2021-0006", "affected", epss=0.9),
                 item("CVE-2021-0000", "not_affected", epss=0.0)]
        self.assertEqual([i["cve_id"] for i in sorted(items, key=cti.watch_sort_key)],
                         ["CVE-2021-0005", "CVE-2021-0006", "CVE-2021-0003", "CVE-2021-0004", "CVE-2021-0002",
                          "CVE-2021-0000", "CVE-2021-0001"])


# ----------------------------------------------------------------------
#  라우터 계약
# ----------------------------------------------------------------------

class FakeConn:
    """질의 글자로 답을 고른다. 들어온 질의를 모두 남겨 어느 처리기가 불렸는지 본다."""

    def __init__(self, calls, incident=None, rule=None, tables=True, errors=None):
        self.calls, self.incident, self.rule, self.tables = calls, incident, rule, tables
        self.errors = errors or {}

    async def fetchval(self, sql, *args):
        self.calls.append(sql)
        if sql == "SELECT now()":
            return NOW
        if sql == cti.TABLES_SQL:
            return self.tables
        if sql == cti.RULE_SQL:
            return self.rule
        return None

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        return self.incident if sql == cti.INCIDENT_SQL else None

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        if sql in self.errors:
            raise self.errors[sql]
        return []

    @asynccontextmanager
    async def transaction(self, **_kw):
        yield


class FakePool:
    def __init__(self, **kw):
        self.calls, self.kw = [], kw

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.calls, **self.kw)


KEY = "R105|c1|192.0.2.1|x"
ENCODED = "/api/incidents/R105%7Cc1%7C192.0.2.1%7Cx/cti"
R105_INCIDENT = {"incident_key": KEY, "rule_id": "R105", "rule_version": "c1",
                 "evidence": json.dumps({"signatures": ["geoserver"], "sensors": ["web-01"]})}
R105_RULE = json.dumps({"id": "R105", "type": "url_signature", "params": {"signatures": [GEOSERVER]}})


class PgError(Exception):
    """asyncpg 오류처럼 sqlstate 를 가진 오류(asyncpg 를 불러오지 않는다)."""

    def __init__(self, sqlstate):
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


class RouterContractTests(unittest.TestCase):
    """라우터만 붙인 앱. 사용자는 viewer 다(읽기 조회라 역할 검사가 없다)."""

    def setUp(self):
        self.pool = FakePool()
        app = FastAPI()
        app.include_router(cti.router)
        app.state.pool = self.pool

        @app.middleware("http")
        async def as_viewer(request, call_next):
            request.state.user = {"u": "tester", "r": "viewer"}
            return await call_next(request)
        self.client = TestClient(app)

    def test_잘못된_입력은_DB_에_닿기_전에_422_다(self):
        bad = ["/api/assets/Web-01", "/api/assets/-web", "/api/assets/web_01", "/api/assets/" + "a" * 64,
               "/api/assets/web-01?limit=0", "/api/assets/web-01?limit=201", "/api/assets/web-01?offset=-1",
               "/api/assets/web-01?filter=high", "/api/assets/web-01?limit=x",
               # int64 를 넘는 offset 이 DB 에 닿으면 500 이다. 상한에서 막는다
               "/api/assets/web-01?offset=1000001", "/api/assets/web-01?offset=9223372036854775808",
               "/api/assets/web-01?offset=" + "9" * 30]
        for path in bad:
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 422)
        self.assertEqual(self.pool.calls, [])

    def test_offset_상한까지는_받는다(self):
        self.pool.kw = {"tables": False}
        response = self.client.get(f"/api/assets/web-01?offset={cti.MAX_OFFSET}")
        self.assertEqual((response.status_code, response.json()["available"]), (200, False))

    def test_표가_없으면_available_false_로_200_이다(self):
        self.pool.kw = {"tables": False}
        body = self.client.get("/api/assets").json()
        self.assertEqual(body, {"as_of": "2026-09-25T03:00:00+00:00", "available": False, "freshness": None, "rows": []})
        body = self.client.get("/api/assets/web-01?filter=kev&limit=200&offset=5").json()
        self.assertFalse(body["available"])
        self.pool.kw = {"tables": False, "incident": R105_INCIDENT,
                        "rule": json.dumps({"id": "R105", "type": "url_signature",
                                            "params": {"signatures": [GEOSERVER]}})}
        body = self.client.get(ENCODED).json()
        self.assertEqual(body, {"as_of": "2026-09-25T03:00:00+00:00", "incident_key": KEY, "applicable": True,
                                "rule_id": "R105", "rule_version": "c1", "available": False})

    def test_주목_CVE_표가_없으면_available_false_다(self):
        self.pool.kw = {"tables": False}
        self.assertEqual(self.client.get("/api/cti/watch").json(),
                         {"as_of": "2026-09-25T03:00:00+00:00", "available": False, "freshness": None, "rows": []})
        self.assertIn(cti.TABLES_SQL, self.pool.calls)
        self.assertNotIn(cti.WATCH_SQL, self.pool.calls)

    def test_주목_CVE_가_없으면_빈_목록이다(self):
        body = self.client.get("/api/cti/watch").json()
        self.assertEqual((body["available"], body["rows"]), (True, []))
        self.assertEqual(body["freshness"]["assets"], {"oldest_collected_at": None, "stale_assets": []})
        self.assertIn(cti.WATCH_SQL, self.pool.calls)

    def test_kev_match_가_PG_정규식으로_틀리면_그_서명만_KEV_항목이_없다(self):
        self.pool.kw = {"incident": R105_INCIDENT, "rule": R105_RULE,
                        "errors": {cti.KEV_PRODUCTS_SQL: PgError(cti.INVALID_REGEX)}}
        response = self.client.get(ENCODED)
        self.assertEqual(response.status_code, 200)
        [geo] = response.json()["signatures"]
        # 자산 표가 비어 요청 받은 web-01 은 미확인이다(판정은 KEV 항목과 상관없이 그대로 한다)
        self.assertEqual((geo["id"], geo["kev_products"], geo["summary"]), ("geoserver", None, "unknown"))
        self.assertEqual(response.json()["cves"], [])
        # 오류 뒤에도 같은 트랜잭션으로 나머지를 읽었다
        self.assertIn(cti.APPLICABILITY_ASSETS_SQL, self.pool.calls)

    def test_정규식_밖의_DB_오류는_숨기지_않는다(self):
        # 처리기 밖에서 KEV 질의 함수만 부른다(시험 클라이언트로 예외를 받으면 스트림이 닫히지 않는다)
        calls = []
        conn = FakeConn(calls, errors={cti.KEV_PRODUCTS_SQL: PgError("57014")})
        with self.assertRaises(PgError):
            asyncio.run(cti.kev_products_for(conn, GEOSERVER["kev_match"]))
        conn.errors = {cti.KEV_PRODUCTS_SQL: PgError(cti.INVALID_REGEX)}
        self.assertIsNone(asyncio.run(cti.kev_products_for(conn, GEOSERVER["kev_match"])))
        self.assertEqual(calls, [cti.KEV_PRODUCTS_SQL, cti.KEV_PRODUCTS_SQL])

    def test_kev_match_값이_문자열이_아니면_묻지_않고_null_이다(self):
        for bad in ({"vendor": 3}, {"vendor": "^OSGeo$", "product": ["x"]}, {"vendor": "^OSGeo$", "text": 1}):
            sig = dict(GEOSERVER, kev_match=bad)
            self.pool = FakePool(incident=R105_INCIDENT,
                                 rule=json.dumps({"id": "R105", "type": "url_signature", "params": {"signatures": [sig]}}))
            self.client.app.state.pool = self.pool
            with self.subTest(kev_match=bad):
                self.assertIsNone(self.client.get(ENCODED).json()["signatures"][0]["kev_products"])
                self.assertNotIn(cti.KEV_PRODUCTS_SQL, self.pool.calls)
        # 조건이 없으면 KEV 항목 자리 자체가 없다(null)
        self.pool = FakePool(incident=R105_INCIDENT, rule=json.dumps(
            {"id": "R105", "type": "url_signature", "params": {"signatures": [dict(GEOSERVER, kev_match=None)]}}))
        self.client.app.state.pool = self.pool
        self.assertIsNone(self.client.get(ENCODED).json()["signatures"][0]["kev_products"])

    def test_서명_규칙이_아니거나_서명_근거가_없으면_적용_대상이_아니다(self):
        cases = [(R105_INCIDENT, None),
                 (R105_INCIDENT, json.dumps({"id": "R105", "type": "event_match", "params": {"signatures": [GEOSERVER]}})),
                 (dict(R105_INCIDENT, evidence=json.dumps({"sample": ["/geoserver"]})),
                  json.dumps({"id": "R105", "type": "url_signature", "params": {"signatures": [GEOSERVER]}})),
                 (dict(R105_INCIDENT, evidence=None),
                  json.dumps({"id": "R105", "type": "url_signature", "params": {"signatures": [GEOSERVER]}})),
                 (dict(R105_INCIDENT, evidence=json.dumps({"signatures": ["gone"]})),
                  json.dumps({"id": "R105", "type": "url_signature", "params": {"signatures": [GEOSERVER]}}))]
        for incident, rule in cases:
            self.pool.kw = {"incident": incident, "rule": rule}
            with self.subTest(evidence=incident["evidence"], rule=rule):
                self.assertEqual(self.client.get(ENCODED).json(),
                                 {"as_of": "2026-09-25T03:00:00+00:00", "incident_key": KEY, "applicable": False})

    def test_없는_사건은_404_다(self):
        response = self.client.get(ENCODED)
        self.assertEqual((response.status_code, response.json()), (404, {"detail": "인시던트를 찾을 수 없습니다"}))


class RouteOrderTests(unittest.TestCase):
    """main 앱 그대로. …/cti 가 상세 조회(/api/incidents/{incident_key:path})의 키로 빠지지 않아야 한다."""

    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        patcher = patch.object(self.main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def login(self, role="viewer"):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", role))

    def first_route(self, path, method="GET"):
        """이 경로 · 메서드를 처음으로 온전히 받는 경로(라우터가 실제로 고르는 것)."""
        scope = {"type": "http", "path": path, "method": method, "root_path": "", "headers": []}
        for route in self.main.app.routes:
            if route.matches(scope)[0] == Match.FULL:
                return route
        return None

    def test_cti_라우터가_상세_조회보다_먼저_붙는다(self):
        paths = [getattr(r, "path", None) for r in self.main.app.routes]
        self.assertLess(paths.index("/api/incidents/{incident_key:path}/cti"),
                        paths.index("/api/incidents/{incident_key:path}"))

    def test_경로마다_처리기가_하나로_정해진다(self):
        cases = {"/api/cti/watch": cti.watch_list, "/api/assets": cti.assets_list,
                 "/api/assets/web-01": cti.asset_detail, "/api/assets/watch": cti.asset_detail,
                 "/api/assets/cti": cti.asset_detail, ENCODED: cti.incident_cti, "/api/incidents/a/b/cti": cti.incident_cti}
        for path, endpoint in cases.items():
            with self.subTest(path=path):
                self.assertIs(self.first_route(path).endpoint, endpoint)
        # 사건 상세 · 조치 경로는 cti 처리기로 오지 않는다
        for path in ["/api/incidents/cti/watch", "/api/incidents/R105%7Cc1%7C192.0.2.1%7Cx"]:
            with self.subTest(path=path):
                self.assertEqual(self.first_route(path).path, "/api/incidents/{incident_key:path}")
        self.assertEqual(self.first_route(ENCODED + "/x").path, "/api/incidents/{incident_key:path}")
        self.assertIsNone(self.first_route("/api/cti/watch/x"))
        self.assertIsNone(self.first_route("/api/cti/watch", "POST"))

    def test_주목_CVE_요청은_watch_처리기로_간다(self):
        self.login()
        self.pool.kw = {"tables": False}
        response = self.client.get("/api/cti/watch")
        self.assertEqual((response.status_code, response.json()["available"], response.json()["rows"]), (200, False, []))
        self.assertIn(cti.TABLES_SQL, self.pool.calls)
        # 자산 상세의 'watch' 자산은 자산 상세 처리기다
        self.assertIn("asset", self.client.get("/api/assets/watch").json())
        # 사건 상세 경로로 온 cti/watch 는 사건 키다
        self.pool.calls.clear()
        self.assertEqual(self.client.get("/api/incidents/cti/watch").status_code, 404)
        self.assertTrue(any("signal_count" in c for c in self.pool.calls))
        self.assertNotIn(cti.WATCH_SQL, self.pool.calls)

    def test_부호화된_키의_cti_요청은_cti_처리기로_간다(self):
        self.login()
        self.pool.kw = {"incident": R105_INCIDENT}
        response = self.client.get(ENCODED)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["incident_key"], KEY)
        self.assertFalse(response.json()["applicable"])
        self.assertIn(cti.INCIDENT_SQL, self.pool.calls)

    def test_없는_사건의_404_도_cti_처리기가_낸다(self):
        self.login()
        response = self.client.get(ENCODED)
        self.assertEqual((response.status_code, response.json()), (404, {"detail": "인시던트를 찾을 수 없습니다"}))
        self.assertEqual([c for c in self.pool.calls if "FROM incidents" in c], [cti.INCIDENT_SQL])

    def test_빗금이_든_키도_cti_로_간다(self):
        self.login()
        self.pool.kw = {"incident": dict(R105_INCIDENT, incident_key="a/b")}
        response = self.client.get("/api/incidents/a/b/cti")
        self.assertEqual(response.json()["incident_key"], "a/b")

    def test_상세_조회는_그대로_상세_처리기로_간다(self):
        self.login()
        response = self.client.get("/api/incidents/R105%7Cc1%7C192.0.2.1%7Cx")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(cti.INCIDENT_SQL, self.pool.calls)
        self.assertTrue(any("signal_count" in c for c in self.pool.calls))

    def test_세션이_없으면_401_이다(self):
        for path in [ENCODED, "/api/assets", "/api/assets/web-01", "/api/cti/watch"]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual(self.pool.calls, [])

    def test_viewer_도_읽고_잘못된_자산_id_는_422_다(self):
        self.login("viewer")
        self.pool.kw = {"tables": False}
        self.assertEqual(self.client.get("/api/assets").status_code, 200)
        self.assertEqual(self.client.get("/api/assets/WEB-01").status_code, 422)
        self.assertEqual(self.client.get("/api/assets/web-01").json()["available"], False)


if __name__ == "__main__":
    unittest.main()
