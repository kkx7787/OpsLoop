"""관제 대상별 상태판(targets.py · 이슈 #52 · #64 · #72 · #82) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 사건 → 대상 매핑(resolve): node:<id> · user:… · 근거의 발생원 · 규칙의 발생원 후보(sensors ∪ 이벤트 접두) ·
     발생원이 섞인 규칙은 이벤트로 고름(빈도 규칙은 탐지와 같은 창 · 임계치 · 응답 코드 · 제외 경로) · 한 대상 안에서 AWS 발생원이
     여럿이면 나눔만 고름 · 발생원 조건 없는 세션 규칙은 세션으로 나눔 · 기준선 · 키 심기는 Cowrie ·
     정의 없음 · 모르는 발생원. 실제 규칙 파일 전부(detector/rules*.json)가 계약대로 붙는지
  2. 집계(tally · latest_of): 한 사건이 여러 대상에 붙음 · 1시간 경계 · 높은 심각도 · 미판정 · 나눔 · 붙이지 못한 사건 ·
     최근 중요 탐지(높음 우선 → 없으면 아무 사건 · 24시간 경계 · 같은 시각은 키 순)
  3. 수집 상태: 허니팟 센서(표 없음 · 행 없음 · 적재기 확인 중단 30분 · 신호 없음 · 확인 시점 기준 15분 경계 · 기록 지연 · 남은 행 무시 ·
     정상 · 요청 없음) ·
     web-01(노드 수신 판정 네 값) · 콘솔(응답 중 · DB 연결 확인 · 확인 불가, 신호 null, 이슈 #76) · 데이터 노드(탐지 실행 · 적재기 · 집행기 확인)
  4. 시스템 · 대응 · 취약점: 미수집 · 권한 없음 · 행 없음 · 오래됨 · 지점 없는 대상은 수 대신 null(0 이 아님) · 실패는 미확인과 따로 ·
     집행기 확인 멈춤이면 적용 확인을 미확인으로 합침 ·
     보고 신호 · 자산 없음은 0 이 아니라 missing · 48시간 · 미확인을 확인 중(5분 안) · 확인 지연으로 나눔(이슈 #84) ·
     카드 보고 문제(report_issue)는 띠 report:<지점> 과 같은 판정
  5. 라우터: main 앱에 붙음 · 세션 없으면 401 · 표 · 권한이 없는 DB 에서도 200(미확인) · 집행 제외 말머리가 main 과 같다 ·
     nodes 를 읽을 수 없으면 고정 네 대상만(web-01 수신 미확인) · 등록 노드 카드는 고정 대상 뒤에 web-01 카드와 같은 필드로
  6. 등록 노드(이슈 #64): 발생원 · node:<id> 가 그 노드 카드로 감(고정 발생원이 먼저) · 노드 에이전트 이벤트(sshd. · nginx.)는
     등록 노드가 있으면 이벤트로 고르고 고르지 못하면 web-01 대체 추정(실제 규칙 파일에서 바뀌는 것은 n1 R101 뿐) ·
     카드로 붙일 노드(폐기 · 고정 대상 id · 고정 발생원 · 겹치는 발생원 제외, node_id 순, 이름은 hostname) · 수집(그 노드 로그) ·
     자원 지표(보내는 노드만, 행 없으면 미수집) · 취약점(같은 이름의 자산만) · 대응(지점 없음) · 집계
  7. 관련 장비(이슈 #72): 연결 근거(확인 · 규칙 범위 · 대체 추정) 판정표와 실제 규칙 파일 전부 · shown · 옛 모양 ·
     장비 표기(이름 · 무리 · 로그 종류 · 정렬 · 상태) · 대체 추정을 뺀 집계 · 먼저 처리할 사건(앞 · 뒤 묶음) ·
     관제 이상(적재기 · 집행기 · 탐지 경로 · 적용 실패 · 관문 불일치 · 노드 수신) · 데이터 노드 멈춤 구조 값 · 취약점 수정 상태별 수
  8. 관제 이상 보완(이슈 #82): 센서 · 관문 기록 수신(카드와 같은 판정) · 한 대라도 끊긴 노드(이름 3개까지) · 등록 노드 열 모름 ·
     1분 다리 기대 버전 대조(BRIDGE_VERSIONS = 수집 설정 RULESETS · 23 · 25시간 · 옛 버전 무시 · 새 버전 기록 없음) · 지점 불일치 ·
     지점 보고 · 웹 로그 적재 없음 · 자원 지표 오래됨 · 겹침 제외 · 생존 신호 표를 읽을 수 없을 때의 대응 · 데이터 노드 탐지 멈춤 ·
     관제 이상 질의 8개 이하
  9. 대시보드 개편(이슈 #83): 미결(최신 판정이 사람의 판단 유보)은 미판정과 따로 세고 창 밖 미결은 rows(최근 중요 탐지 · 대응 금지
     대역 수)에 넣지 않음 · 최근 사건 줄의 최신 판정 값 · 취약점 대조 실패 · 대조 오래됨(48시간, 수는 그대로) · 앞선 시각 줄 상한이
     장비 로그 목록과 같음 · 사건 목록 미결 필터(judged 와 AND)
main 이 필요한 시험은 test_web 을 먼저 불러 asyncpg 가 없는 곳에서도 가짜를 넣는다(main 보다 먼저).
"""
import ast
import json
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import block_points as bp
import targets as t

NOW = datetime(2026, 9, 28, 3, 0, tzinfo=timezone.utc)
RULE_FILES = sorted((Path(__file__).resolve().parents[1] / "detector").glob("rules*.json"))


def spec(type_="event_match", sensors=None, eventids=None, eventid=None, eventid_like=None):
    """RULES_SQL 한 행과 같은 꼴(jsonb 는 글자로 온다)."""
    return t.rule_spec({"type": type_, "sensors": json.dumps(sensors) if sensors is not None else None,
                        "eventids": json.dumps(eventids) if eventids is not None else None,
                        "eventid": json.dumps(eventid) if eventid is not None else None,
                        "eventid_like": json.dumps(eventid_like) if eventid_like is not None else None})


def file_rules():
    """실제 규칙 파일의 (규칙 버전, 규칙 id, 규칙 정의 한 행)."""
    for path in RULE_FILES:
        doc = json.loads(path.read_text())
        for rule in doc["rules"]:
            p = rule.get("params") or {}
            yield doc["rule_version"], rule["id"], t.rule_spec(
                {"type": rule.get("type"), **{k: json.dumps(p[k]) if k in p else None for k in (
                    "sensors", "eventids", "eventid", "eventid_like", "http_status", "exclude_url_patterns",
                    "window_seconds", "threshold")}})


def incident(key, first_min=10, last_min=None, severity="medium", judged=False, actor="198.51.100.1", rule="R001"):
    last_min = first_min if last_min is None else last_min
    return {"incident_key": key, "rule_id": rule, "rule_name": f"{rule} 규칙", "severity": severity, "actor_ip": actor,
            "target": None, "first_ts": NOW - timedelta(minutes=first_min), "last_ts": NOW - timedelta(minutes=last_min),
            "judged": judged}


def hb(source, kind="uploader", role="sensor", seen=3, checked=1, problem=None, host=None):
    """생존 신호 행. seen · checked 는 분 전(None 이면 없음)."""
    return {"source": source, "kind": kind, "role": role, "host": host or source.split(":", 1)[1],
            "seen_at": NOW - timedelta(minutes=seen) if seen is not None else None,
            "checked_at": NOW - timedelta(minutes=checked), "problem": problem}


# ----------------------------------------------------------------------
#  1. 매핑
# ----------------------------------------------------------------------

class ResolveTests(unittest.TestCase):
    def test_노드_대상은_그_노드의_대상이다(self):
        self.assertEqual(t.resolve("node:web-01", None, spec()), ({("web-01", None)}, False))
        # 모르는 노드는 붙이지 못한다(규칙으로 넘어가지 않는다)
        self.assertEqual(t.resolve("node:web-09", None, spec(eventids=["cowrie.login.failed"])), (set(), False))

    def test_사람_대상은_콘솔이다(self):
        self.assertEqual(t.resolve("user:han", None, None), ({("console", None)}, False))

    def test_근거의_발생원이_규칙보다_먼저다(self):
        pairs, join = t.resolve(None, json.dumps(["decoy", "web-01"]), spec(eventids=["nginx.request"]))
        self.assertEqual((pairs, join), ({("aws-sensor", "decoy"), ("web-01", None)}, False))
        # 빈 목록 · 목록이 아닌 값은 없는 것으로 보고 규칙으로 간다
        for bad in (json.dumps([]), json.dumps("decoy"), json.dumps([3, None])):
            with self.subTest(sensors=bad):
                self.assertEqual(t.resolve(None, bad, spec(eventids=["nginx.request"])), ({("web-01", None)}, False))

    def test_규칙의_발생원_후보는_sensors_와_이벤트_접두의_합이다(self):
        s = spec(sensors=["audit"], eventids=["console.block.released"])
        self.assertEqual(t.candidate_sources(s), ["audit", "console"])
        self.assertEqual(t.resolve(None, None, s), ({("console", None)}, False))
        # eventid 한 개 · LIKE 식의 접두도 본다. 와일드카드로 시작하면 접두가 없다
        self.assertEqual(t.candidate_sources(spec(eventid="cowrie.direct-tcpip.request")), ["cowrie"])
        self.assertEqual(t.candidate_sources(spec(eventid_like="cowrie.session.file_%")), ["cowrie"])
        self.assertEqual(t.candidate_sources(spec(eventid_like="%.agent.rejected")), [])

    def test_대상이_섞인_규칙은_이벤트로_고른다(self):
        self.assertEqual(t.resolve(None, None, spec(eventids=["nginx.request", "decoy.request"])), (set(), t.EVENTS))
        self.assertEqual(t.resolve(None, None, spec(sensors=["decoy", "console"], eventid_like="%.action.upload")),
                         (set(), t.EVENTS))

    def test_한_대상_안에서_AWS_발생원이_여럿이면_나눔만_이벤트로_고른다(self):
        self.assertEqual(t.resolve(None, None, spec(eventids=["cowrie.login.failed", "decoy.login.failed"])),
                         ({("aws-sensor", None)}, t.EVENTS))

    def test_후보가_없으면_세션_기준선_키_심기만_AWS_센서다(self):
        # 발생원 조건 없는 세션 규칙(v3 R002)은 sessions 표 전체(Cowrie · 디코이 세션)를 본다. 나눔은 사건의 세션으로 고른다
        self.assertEqual(t.resolve(None, None, spec("session_compound")), ({("aws-sensor", None)}, t.SESSIONS))
        for type_ in ("baseline_deviation", "key_plant"):
            with self.subTest(type=type_):
                self.assertEqual(t.resolve(None, None, spec(type_)), ({("aws-sensor", "cowrie")}, False))
        # 발생원 조건이 있는 세션 규칙(w2 R103)은 그 발생원이다
        self.assertEqual(t.resolve(None, None, spec("session_compound", sensors=["decoy"])),
                         ({("aws-sensor", "decoy")}, False))
        self.assertEqual(t.resolve(None, None, spec("node_silence")), (set(), False))
        self.assertEqual(t.resolve(None, None, None), (set(), False))   # 규칙 정의를 못 찾음
        # 모르는 발생원뿐이면 붙이지 못한다
        self.assertEqual(t.resolve(None, None, spec(sensors=["web-09"])), (set(), False))

    def test_규칙_정의의_이상한_값은_없는_것으로_본다(self):
        s = t.rule_spec({"type": "event_match", "sensors": json.dumps("cowrie"), "eventids": json.dumps({"a": 1}),
                         "eventid": json.dumps(3), "eventid_like": None})
        self.assertEqual(s, {"type": "event_match", "sensors": None, "eventids": [], "eventid_like": None,
                             "http_status": None, "exclude": None, "window": None, "threshold": None})
        s = t.rule_spec({"type": None, "sensors": None, "eventids": json.dumps(["cowrie.login.failed"]),
                         "eventid": json.dumps("cowrie.login.failed"), "eventid_like": None})
        self.assertEqual(s["eventids"], ["cowrie.login.failed"])   # eventid 는 eventids 에 한 번만 합친다

    def test_이벤트_조회_항목(self):
        inc = incident("k", first_min=10, last_min=5)
        item = t.join_item(inc, spec(sensors=["decoy", "console"], eventid_like="%.action.upload"))
        self.assertEqual(item, {"k": "k", "ip": "198.51.100.1", "f": (NOW - timedelta(minutes=10)).isoformat(),
                                "l": (NOW - timedelta(minutes=5)).isoformat(), "ids": None, "lk": "%.action.upload",
                                "ss": ["decoy", "console"], "st": None, "ex": None, "w": None, "th": None})

    def test_출발지_빈도_규칙은_탐지와_같은_조건을_넘긴다(self):
        # w2 R102: 404 만 · 제외 경로는 ^(?: … )$ 로 감싼다(detect.signals_actor_rate 와 같다) · 창 600초 · 임계치 5
        r102 = next(s for v, rid, s in file_rules() if (v, rid) == ("w2", "R102"))
        item = t.join_item(incident("k"), r102)
        self.assertEqual((item["st"], item["w"], item["th"]), ([404], 600, 5))
        self.assertIn("^(?:^/sitemap\\.xml$)$", item["ex"])
        r101 = next(s for v, rid, s in file_rules() if (v, rid) == ("w2", "R101"))
        self.assertEqual({k: t.join_item(incident("k"), r101)[k] for k in ("st", "ex", "w", "th")},
                         {"st": None, "ex": None, "w": 600, "th": 5})
        # 빈도 규칙이 아니면 창 · 조건을 넘기지 않는다(첫 시각 ~ 끝 시각의 이벤트)
        r104 = next(s for v, rid, s in file_rules() if (v, rid) == ("w2", "R104"))
        self.assertEqual({k: t.join_item(incident("k"), r104)[k] for k in ("st", "ex", "w", "th")},
                         {"st": None, "ex": None, "w": None, "th": None})

    def test_세션_조회_항목(self):
        self.assertEqual(t.session_item(incident("k") | {"sessions": json.dumps(["a", "", 3, "b"])}),
                         {"k": "k", "s": ["a", "b"]})
        self.assertIsNone(t.session_item(incident("k") | {"sessions": None}))

    def test_실제_규칙_파일은_계약대로_붙는다(self):
        expected = {
            ("v1", "R001"): {("aws-sensor", "cowrie")}, ("v1", "R002"): {("aws-sensor", None)},
            ("v1", "R003"): {("aws-sensor", "cowrie")}, ("v1", "R004"): {("aws-sensor", "cowrie")},
            ("v1", "R005"): {("aws-sensor", "cowrie")},
            ("v3", "R006"): {("aws-sensor", "cowrie")},
            ("n1", "R101"): {("web-01", None)},
            ("w2", "R103"): {("aws-sensor", "decoy")},
            ("a1", "R201"): {("console", None)},
            ("s1", "R202"): {("data-node", None)},
        }
        joins = {("w2", "R101"), ("w2", "R102"), ("w2", "R104"), ("c1", "R105"), ("c1", "R106"), ("sg1", "R107")}
        sessions = {"R002"}        # 발생원 조건 없는 세션 규칙: 대상은 허니팟 센서, 나눔은 세션으로
        seen = set()
        for version, rule_id, s in file_rules():
            seen.add((version, rule_id))
            pairs, join = t.resolve(None, None, s)
            with self.subTest(version=version, rule=rule_id):
                if (version, rule_id) in joins:
                    self.assertEqual((pairs, join), (set(), t.EVENTS))
                elif rule_id in sessions:
                    self.assertEqual((pairs, join), ({("aws-sensor", None)}, t.SESSIONS))
                elif (version, rule_id) == ("i2", "R301"):
                    self.assertEqual((pairs, join), (set(), False))   # 대상(node:<id>)으로만 붙는다
                    self.assertEqual(t.resolve("node:web-01", None, s), ({("web-01", None)}, False))
                else:
                    key = (version, rule_id) if (version, rule_id) in expected else ("v1", rule_id)
                    self.assertEqual((pairs, join), (expected[key], False))
        self.assertTrue(joins <= seen)


# ----------------------------------------------------------------------
#  2. 집계
# ----------------------------------------------------------------------

class TallyTests(unittest.TestCase):
    def test_대상별_1시간_높음_미판정과_나눔(self):
        rows = [incident("a", 60, severity="high"),              # 1시간 경계(포함)
                incident("b", 61, severity="critical"),          # 1시간 밖, 미판정
                incident("c", 5, severity="low", judged=True),
                incident("d", 5, severity="high"),               # 두 대상
                incident("e", 5), incident("f", 300, judged=True)]
        attached = {"a": {("aws-sensor", "cowrie")}, "b": {("aws-sensor", "cowrie")}, "c": {("console", None)},
                    "d": {("aws-sensor", "decoy"), ("web-01", None)}, "e": set()}
        per, unmapped = t.tally(rows, attached, NOW)
        aws = per["aws-sensor"]
        self.assertEqual((aws["incidents_1h"], aws["high_1h"], aws["pending"]), (2, 2, 3))
        self.assertEqual(aws["parts"], {"cowrie": {"incidents_1h": 1, "pending": 2},
                                        "decoy": {"incidents_1h": 1, "pending": 1},
                                        "gateway": {"incidents_1h": 0, "pending": 0}})
        self.assertEqual((per["web-01"]["incidents_1h"], per["web-01"]["high_1h"], per["web-01"]["pending"]), (1, 1, 1))
        self.assertEqual((per["console"]["incidents_1h"], per["console"]["pending"]), (1, 0))
        self.assertEqual((per["data-node"]["incidents_1h"], per["data-node"]["pending"]), (0, 0))
        # 붙이지 못한 사건은 숨기지 않는다(f 는 판정됐고 1시간 밖이라 어디에도 세지 않는다)
        self.assertEqual(unmapped, {"incidents_1h": 1, "pending": 1, "undetermined": 0})
        block = t.security_block("aws-sensor", aws, NOW)
        self.assertEqual([p["key"] for p in block["parts"]], ["cowrie", "decoy", "gateway"])
        self.assertEqual(block["parts"][1], {"key": "decoy", "label": "웹 디코이", "incidents_1h": 1, "pending": 1})
        self.assertEqual(t.security_block("web-01", per["web-01"], NOW)["parts"], [])

    def test_최근_중요_탐지는_높음_이상을_먼저_고른다(self):
        rows = [incident("low-new", 1, severity="low"), incident("high-old", 600, severity="high", judged=True),
                incident("crit-older", 700, severity="critical")]
        latest = t.latest_of(rows, NOW)
        self.assertEqual((latest["incident_key"], latest["severity"], latest["judged"]), ("high-old", "high", True))
        self.assertEqual(latest["last_ts"], (NOW - timedelta(minutes=600)).isoformat())
        self.assertEqual(set(latest), {"incident_key", "rule_id", "rule_name", "severity", "actor_ip", "target",
                                       "last_ts", "judged", "verdict"})

    def test_높음이_없으면_아무_사건_최신이고_24시간_밖은_없다(self):
        self.assertEqual(t.latest_of([incident("m", 30), incident("l", 3, severity="low")], NOW)["incident_key"], "l")
        edge = incident("edge", 24 * 60, severity="high")                 # 24시간 경계(포함)
        self.assertEqual(t.latest_of([edge], NOW)["incident_key"], "edge")
        self.assertIsNone(t.latest_of([incident("old", 24 * 60 + 1, severity="high")], NOW))
        self.assertIsNone(t.latest_of([], NOW))
        # 같은 시각이면 키 순
        self.assertEqual(t.latest_of([incident("b", 5, severity="high"), incident("a", 5, severity="high")],
                                     NOW)["incident_key"], "a")

    def test_미결은_따로_세고_창_밖_미결은_rows_에_넣지_않는다(self):
        # 미결(최신 판정이 사람의 판단 유보)은 판정됨이라 미판정에 들지 않는다. 창 밖 미결(in_window 거짓, 판정 뒤 24시간 넘게 지남)은
        #   미결 수에만 세고 rows 에는 넣지 않는다(최근 중요 탐지 · 대응 금지 대역 수가 바뀌지 않게). 시스템 전환 기록은 미결이 아니다
        def judged(key, minutes, undetermined, in_window=True, **kw):
            return incident(key, minutes, judged=True, **kw) | {
                "verdict": "undetermined", "undetermined": undetermined, "in_window": in_window}
        rows = [judged("in", 5, True), judged("old", 3 * 24 * 60, True, False, severity="high", actor="10.0.0.9"),
                judged("system", 5, False), judged("lost", 5, True)]
        attached = {"in": {("web-01", None)}, "old": {("web-01", None)}, "system": {("web-01", None)}, "lost": set()}
        per, unmapped = t.tally(rows, attached, NOW)
        web = per["web-01"]
        self.assertEqual((web["undetermined"], web["pending"], web["incidents_1h"]), (2, 0, 2))
        self.assertEqual([i["incident_key"] for i in web["rows"]], ["in", "system"])
        self.assertEqual(unmapped, {"incidents_1h": 1, "pending": 0, "undetermined": 1})
        block = t.security_block("web-01", web, NOW)
        self.assertEqual(block["undetermined"], 2)
        # 최근 사건 줄은 판정됨이면서 최신 판정 값을 싣는다(화면이 '판정됨' 대신 '미결' 로 보인다)
        self.assertEqual({k: block["latest"][k] for k in ("incident_key", "judged", "verdict")},
                         {"incident_key": "in", "judged": True, "verdict": "undetermined"})
        self.assertEqual(t.security_block("console", per["console"], NOW)["undetermined"], 0)


# ----------------------------------------------------------------------
#  3. 수집 상태
# ----------------------------------------------------------------------

LOGS_ACTIVE = {"cowrie": NOW - timedelta(minutes=30), "gateway": NOW - timedelta(minutes=1)}


class SensorCollectionTests(unittest.TestCase):
    def test_표가_없거나_행이_없으면_미확인이다(self):
        c = t.sensor_collection(NOW, False, [], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("unknown", "생존 신호 미기록 · 생존 신호 표를 읽을 수 없음"))
        self.assertEqual(c["signal"], {"label": "업로더 생존 신호", "seen_at": None, "checked_at": None,
                                       "stale_after_seconds": 900, "problem": None})
        # 관문 업로더 · 차단 보고 행은 센서 신호가 아니다(관문 기록 신호 시각은 까닭 끝에 붙는다)
        c = t.sensor_collection(NOW, True, [hb("uploader:i-0aaaaaaaa", role="gateway"),
                                            hb("block:gateway", kind="block_report", role="gateway")], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("unknown", "생존 신호 미기록 · 관문 기록 신호 3분 전"))
        self.assertEqual([(l["key"], l["label"]) for l in c["logs"]],
                         [("cowrie", "SSH 허니팟(Cowrie)"), ("decoy", "웹 디코이"), ("gateway", "허니팟 관문 기록")])
        self.assertEqual(c["logs"][1]["last_at"], None)
        self.assertEqual(c["extra"], [])

    def test_적재기가_30분_넘게_확인하지_않으면_미확인이다(self):
        c = t.sensor_collection(NOW, True, [hb("uploader:i-01", seen=35, checked=31)], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("unknown", "적재기 확인 중단 · 마지막 확인 31분 전"))
        self.assertEqual(c["signal"]["checked_at"], (NOW - timedelta(minutes=31)).isoformat())
        # 30분 정각은 아직 확인 중이다(받기가 길어 기록이 늦을 수 있다: 회차 간격 5분 + 받기 최장 10분 + 적재 · 탐지)
        self.assertEqual(t.sensor_collection(NOW, True, [hb("uploader:i-01", seen=33, checked=30)], LOGS_ACTIVE)["state"],
                         "ok")

    def test_신호가_없거나_15분_넘으면_수신_없음이다(self):
        c = t.sensor_collection(NOW, True, [hb("uploader:i-01", seen=None, problem="hb 없음")], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"], c["signal"]["problem"]),
                         ("no_signal", "업로더 생존 신호 없음 · hb 없음", "hb 없음"))
        # 확인 시점 기준으로 잰다: 확인(1분 전) 때 이미 15분 넘게 새 신호가 없었다
        row = hb("uploader:i-01") | {"seen_at": NOW - timedelta(seconds=961)}
        c = t.sensor_collection(NOW, True, [row], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]),
                         ("no_signal", "업로더 생존 신호 16분 전 · 적재기 확인 1분 전 · 확인 때 이미 15분 넘게 새 신호 없음"))
        row = hb("uploader:i-01") | {"seen_at": NOW - timedelta(seconds=960)}
        self.assertEqual(t.sensor_collection(NOW, True, [row], LOGS_ACTIVE)["state"], "ok")
        # 받기가 길어 기록이 늦었을 뿐이면(확인 13분 전 · 그때 신호 5분 전) 지금 기준 18분이어도 수신 없음이 아니다
        row = hb("uploader:i-01", seen=18, checked=13)
        self.assertEqual(t.sensor_collection(NOW, True, [row], LOGS_ACTIVE)["state"], "ok")

    def test_신호가_새로우면_로그로_정상과_요청_없음을_가른다(self):
        rows = [hb("uploader:i-01", seen=3)]
        c = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("ok", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음"))
        self.assertEqual(c["signal"]["seen_at"], (NOW - timedelta(minutes=3)).isoformat())
        # 관문 기록만 있으면 요청 없음이다(로그 시각만으로 장애로 읽지 않는다)
        c = t.sensor_collection(NOW, True, rows, {"gateway": NOW, "cowrie": NOW - timedelta(minutes=61)})
        self.assertEqual((c["state"], c["reason"]), ("quiet", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 요청 없음"))
        # 1시간 경계(포함)
        self.assertEqual(t.sensor_collection(NOW, True, rows, {"decoy": NOW - timedelta(hours=1)})["state"], "ok")

    def test_센서가_여럿이면_가장_늦은_신호로_보고_적재기가_버린_행은_보지_않는다(self):
        rows = [hb("uploader:i-01", seen=2), hb("uploader:i-02", seen=8, problem=None),
                hb("uploader:i-03", seen=60 * 48, checked=60 * 48)]      # 떼어 둔 호스트의 남은 행
        c = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]),
                         ("ok", "업로더 생존 신호 8분 전(센서 2대 중 가장 늦은 것) · 적재기 확인 1분 전 · 최근 1시간 로그 있음"))
        rows.append(hb("uploader:i-04", seen=None, problem="형식이 틀림"))
        c = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("no_signal", "업로더 생존 신호 없음(센서 3대 중 가장 늦은 것) · 형식이 틀림"))

    def test_관문_기록_신호는_센서와_같은_기준이고_카드_까닭_끝에_붙는다(self):
        gw = hb("uploader:i-0bbbbbbbb", role="gateway", seen=20, checked=1)
        state, reason, row = t.uploader_signal(NOW, True, [hb("uploader:i-01"), gw], "gateway")
        self.assertEqual((state, reason, row["host"]),
                         ("no_signal", "관문 기록 신호 20분 전 · 적재기 확인 1분 전 · 확인 때 이미 15분 넘게 새 신호 없음",
                          "i-0bbbbbbbb"))
        # 센서 카드의 state 는 센서 판정 그대로다
        c = t.sensor_collection(NOW, True, [hb("uploader:i-01"), gw], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), (
            "ok", "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음 · 관문 기록 신호 20분 전"))
        self.assertEqual(c["signal"]["seen_at"], (NOW - timedelta(minutes=3)).isoformat())
        c = t.sensor_collection(NOW, True, [hb("uploader:i-01"), gw | {"seen_at": None}], LOGS_ACTIVE)
        self.assertEqual(c["reason"], "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음 · 관문 기록 신호 없음")
        # 여럿이면 가장 늦은 것 · 확인 때 15분 정각은 새롭다 · 관문 업로더가 없는 구성은 고른 행이 없다
        rows = [gw, hb("uploader:i-0cccccccc", role="gateway", seen=2)]
        self.assertEqual(t.uploader_signal(NOW, True, rows, "gateway")[1],
                         "관문 기록 신호 20분 전(관문 2대 중 가장 늦은 것) · 적재기 확인 1분 전 · 확인 때 이미 15분 넘게 새 신호 없음")
        self.assertEqual(t.uploader_signal(NOW, True, [hb("uploader:i-0b", role="gateway", seen=16, checked=1)], "gateway")[:2],
                         (None, "관문 기록 신호 16분 전 · 적재기 확인 1분 전"))
        self.assertEqual(t.uploader_signal(NOW, True, [hb("uploader:i-01")], "gateway"), ("unknown", "생존 신호 미기록", None))
        self.assertEqual(t.uploader_signal(NOW, True, [gw | {"checked_at": NOW - timedelta(minutes=31)}], "gateway")[:2],
                         ("unknown", "적재기 확인 중단 · 마지막 확인 31분 전"))
        # 적재기가 확인하지 않는 관문 행(떼어 둔 호스트의 남은 행)뿐이면 카드 까닭에 붙이지 않는다
        c = t.sensor_collection(NOW, True, [hb("uploader:i-01"), gw | {"checked_at": NOW - timedelta(days=3)}], LOGS_ACTIVE)
        self.assertEqual(c["reason"], "업로더 생존 신호 3분 전 · 적재기 확인 1분 전 · 최근 1시간 로그 있음")


class OtherCollectionTests(unittest.TestCase):
    def node(self, reception, seen=2, loaded=2):
        return {"status": "active", "reception": reception,
                "last_seen_at": NOW - timedelta(minutes=seen) if seen is not None else None,
                "last_loaded_at": NOW - timedelta(minutes=loaded) if loaded is not None else None}

    def test_web_01_은_노드_수신_판정으로_가른다(self):
        logs = {"web-01": NOW - timedelta(minutes=5)}
        cases = [(None, "unknown", "노드 등록 기록 없음"), (self.node("revoked"), "unknown", "노드 폐기됨"),
                 (self.node("waiting", None), "unknown", "노드 등록 대기 · 수신 전"),
                 (self.node("silent", 12), "no_signal", "노드 수신 12분 전 · 10분 넘게 끊김"),
                 (self.node("silent", None), "no_signal", "노드 수신 기록 없음 · 등록 뒤 10분 넘게 수신 없음"),
                 (self.node("normal"), "ok", "노드 수신 2분 전 · 최근 1시간 로그 있음")]
        for node, state, reason in cases:
            with self.subTest(reason=reason):
                c = t.node_collection(NOW, node, logs)
                self.assertEqual((c["state"], c["reason"]), (state, reason))
                self.assertEqual((c["signal"]["label"], c["signal"]["stale_after_seconds"], c["signal"]["checked_at"]),
                                 ("노드 수신", 600, None))
                self.assertEqual([x["label"] for x in c["extra"]], ["마지막 적재"])
        c = t.node_collection(NOW, self.node("normal"), {"web-01": NOW - timedelta(minutes=61)})
        self.assertEqual((c["state"], c["reason"]), ("quiet", "노드 수신 2분 전 · 최근 1시간 요청 없음"))
        self.assertEqual(c["logs"], [{"key": "web-01", "label": "web-01 로그",
                                      "last_at": (NOW - timedelta(minutes=61)).isoformat()}])
        self.assertEqual(c["extra"][0]["at"], (NOW - timedelta(minutes=2)).isoformat())

    def test_콘솔은_응답_중이고_DB_연결의_있음_없음만_적는다(self):
        # 이슈 #76: 이 조회에 응답했다는 사실('응답 중')과 콘솔 이름표 연결의 있음 · 없음. 대기 · 정상 · 생존으로 꾸미지 않는다
        def links(a, b):
            return t.db_links_of([{"name": "opsloop-console-a", "present": a}, {"name": "opsloop-console-b", "present": b}])
        cases = [(links(True, False), "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)"),
                 (links(False, True), "DB 연결 확인: 콘솔 A 없음 · 콘솔 B 있음"),
                 (links(True, True), "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 있음"),
                 (links(False, False), "DB 연결 확인: 콘솔 A 없음 · 콘솔 B 없음(평소 꺼 두는 예비)"),
                 (None, "DB 연결 확인 불가")]
        for value, reason in cases:
            with self.subTest(reason=reason):
                c = t.console_collection({"console": NOW}, value)
                self.assertEqual((c["state"], c["reason"], c["signal"], c["extra"], c["db_links"]),
                                 ("responding", reason, None, [], value))
                for word in ("대기", "정상", "생존", "미확인"):
                    self.assertNotIn(word, c["reason"])
                self.assertEqual(c["logs"], [{"key": "console", "label": "마지막 로그인 기록", "last_at": NOW.isoformat()}])
        self.assertEqual(links(True, False), [
            {"name": "opsloop-console-a", "label": "콘솔 A", "present": True, "note": None},
            {"name": "opsloop-console-b", "label": "콘솔 B", "present": False, "note": "평소 꺼 두는 예비"}])
        # 질의는 이름마다 한 행을 낸다. 행이 없는 이름은 없음이다. 이름표는 compose OPSLOOP_WORKER 값이다
        self.assertEqual([x["present"] for x in t.db_links_of([])], [False, False])
        self.assertEqual([name for name, _, _ in t.CONSOLES], ["opsloop-console-a", "opsloop-console-b"])
        # 인자 없이 부르면(옛 호출) 확인 불가다
        self.assertEqual(t.console_collection({})["reason"], "DB 연결 확인 불가")

    def test_콘솔_DB_연결_질의는_콘솔_역할의_이름표_연결만_본다(self):
        # 수는 보지 않는다(풀 유휴 정리로 오르내린다). 다른 역할이 같은 이름표를 써도 세지 않는다. 이 DB 의 연결만이다
        for part in ("a.datname = current_database()", "a.usename = current_user", "a.application_name = u.n",
                     "FROM unnest($1::text[]) WITH ORDINALITY AS u(n, i) ORDER BY u.i",
                     "EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity a"):
            self.assertIn(part, t.CONSOLE_LINKS_SQL)
        self.assertNotIn("count(", t.CONSOLE_LINKS_SQL)
        self.assertEqual(t.CONSOLE_LINKS_READABLE_SQL,
                         "SELECT has_table_privilege('pg_catalog.pg_stat_activity', 'SELECT')"
                         " AND has_function_privilege('pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')")

    def test_데이터_노드는_탐지_실행이_신호다(self):
        rows = [hb("uploader:i-01", checked=2), hb("uploader:i-02", checked=1),
                hb("block:gateway", kind="block_report", role="gateway", checked=4)]
        c = t.data_collection(NOW, NOW - timedelta(minutes=4), True, rows)
        self.assertEqual((c["state"], c["reason"], c["logs"]), ("ok", "마지막 탐지 실행 4분 전", []))
        self.assertEqual(c["extra"], [
            {"label": "적재기 확인", "at": (NOW - timedelta(minutes=1)).isoformat(), "note": None},
            {"label": "집행기 확인", "at": (NOW - timedelta(minutes=4)).isoformat(), "note": None}])
        c = t.data_collection(NOW, NOW - timedelta(seconds=901), True, [])
        self.assertEqual((c["state"], c["reason"]), ("no_signal", "마지막 탐지 실행 15분 전 · 15분 넘게 실행 없음"))
        self.assertEqual([x["note"] for x in c["extra"]], ["기록 없음", "기록 없음"])
        # 적재기 30분 · 집행기 10분 넘게 확인이 없으면 '멈춤' 이고 까닭에 붙는다
        rows = [hb("uploader:i-01", checked=31), hb("block:gateway", kind="block_report", role="gateway", checked=11)]
        c = t.data_collection(NOW, NOW - timedelta(minutes=4), True, rows)
        self.assertEqual((c["state"], c["reason"]),
                         ("ok", "마지막 탐지 실행 4분 전 · 적재기 확인 중단 · 마지막 31분 전 · 집행기 확인 중단 · 마지막 11분 전"))
        self.assertEqual([x["note"] for x in c["extra"]], ["멈춤", "멈춤"])
        c = t.data_collection(NOW, None, False, [])
        self.assertEqual((c["state"], c["reason"], c["signal"]["seen_at"]), ("unknown", "탐지 실행 기록 없음", None))
        self.assertEqual([x["note"] for x in c["extra"]], ["생존 신호 표를 읽을 수 없음"] * 2)

    def test_경과_표기(self):
        cases = [(timedelta(seconds=-30), "방금"), (timedelta(seconds=59), "방금"), (timedelta(seconds=60), "1분 전"),
                 (timedelta(minutes=119), "119분 전"), (timedelta(minutes=120), "2시간 전"),
                 (timedelta(hours=47), "47시간 전"), (timedelta(hours=48), "2일 전")]
        for delta, text in cases:
            with self.subTest(delta=delta):
                self.assertEqual(t.ago(NOW, NOW - delta), text)


# ----------------------------------------------------------------------
#  4. 시스템 · 대응 · 취약점
# ----------------------------------------------------------------------

class BlocksTests(unittest.TestCase):
    ROW = {"ts": NOW - timedelta(minutes=1), "cpu_pct": 12.340000152587891, "mem_used_pct": 55.5,
           "disk_root_pct": None, "load1": 0.123456}

    def test_자원_지표는_web_01_만_모은다(self):
        for tid in ("aws-sensor", "console", "data-node"):
            self.assertEqual(t.system_block(tid, True, self.ROW, NOW), {"state": "not_collected", "metrics": None})
        self.assertEqual(t.system_block("web-01", False, None, NOW), {"state": "no_privilege", "metrics": None})
        self.assertEqual(t.system_block("web-01", True, None, NOW), {"state": "no_data", "metrics": None})
        ok = t.system_block("web-01", True, self.ROW, NOW)
        self.assertEqual(ok, {"state": "ok", "metrics": {"ts": (NOW - timedelta(minutes=1)).isoformat(), "cpu_pct": 12.3,
                                                          "mem_used_pct": 55.5, "disk_root_pct": None, "load1": 0.12}})
        self.assertEqual(t.system_block("web-01", True, self.ROW | {"ts": NOW - timedelta(seconds=600)}, NOW)["state"], "ok")
        self.assertEqual(t.system_block("web-01", True, self.ROW | {"ts": NOW - timedelta(seconds=601)}, NOW)["state"],
                         "stale")

    def test_지점이_없는_대상은_수_대신_null_이다(self):
        blocks = {"gateway_applied": 0, "gateway_failed": 0, "gateway_unverified": 0, "gateway_stale": 0,
                  "gateway_checking": 0, "gateway_delayed": 0, "gateway_unrequested": 0, "gateway_removing": 0,
                  "fw_applied": 0, "fw_failed": 0, "fw_unverified": 0, "fw_stale": 0, "fw_checking": 0, "fw_delayed": 0,
                  "fw_unrequested": 0, "fw_removing": 0}
        for tid in ("console", "data-node"):
            r = t.response_block(tid, blocks, 2, {}, NOW, True)
            self.assertEqual(r, {"point": None, "point_label": None, "applied": None, "failed": None, "unverified": None,
                                 "stale": None, "checking": None, "delayed": None, "unrequested": None, "removing": None,
                                 "exempt": 2, "report": None, "report_issue": None, "stalled": None, "unreadable": None})

    def test_지점이_있으면_그_지점의_확인_수와_보고를_낸다(self):
        blocks = {"gateway_applied": 3, "gateway_failed": 0, "gateway_unverified": 1, "gateway_stale": 1,
                  "gateway_checking": 0, "gateway_delayed": 1, "gateway_unrequested": 2, "gateway_removing": 1,
                  "fw_applied": 0, "fw_failed": 2, "fw_unverified": 4, "fw_stale": 3, "fw_checking": 1, "fw_delayed": 3,
                  "fw_unrequested": 0, "fw_removing": 0}
        report = hb("block:fw", kind="block_report", role="fw", seen=None, checked=1, problem="보고 파일 없음")
        # 생존 신호 표를 읽을 수 없으면(마이그레이션 전 · 권한 빠짐) 멈춤을 판정하지 못해 옛 '적용 확인' 을 믿지 않는다(#82).
        #   관문 미요청 · 빠짐 확인 전(이슈 #77)은 집행기 멈춤과 무관한 요청 사실이라 합치지 않는다
        aws = t.response_block("aws-sensor", blocks, 0, {"fw": report}, NOW, False)
        #   멈춘 지점은 확인 중 · 확인 지연도 가르지 않고, 보고 문제(띠 report:<지점>)도 없다(띠는 enforcer · heartbeats 가 말한다)
        self.assertEqual(aws, {"point": "gateway", "point_label": "허니팟 관문", "applied": 0, "failed": 0, "unverified": 4,
                               "stale": 0, "checking": 0, "delayed": 0, "unrequested": 2, "removing": 1, "exempt": 0,
                               "report": None, "report_issue": None,
                               "stalled": "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가", "unreadable": True})
        # 표는 읽는데 그 지점의 집행기 확인 기록이 없으면 적용 확인을 믿지 않는다(집행기 멈춤이다)
        aws = t.response_block("aws-sensor", blocks, 0, {"fw": report}, NOW, True)
        self.assertEqual((aws["applied"], aws["failed"], aws["unverified"], aws["stale"], aws["stalled"], aws["unreadable"]),
                         (0, 0, 4, 0, "집행기 확인 기록 없음", False))
        # 지점 불일치(stale)는 미확인 가운데 따로 센 수다. 확인 중 + 확인 지연 = 미확인이다(이슈 #84)
        web = t.response_block("web-01", blocks, 1, {"fw": report}, NOW, True)
        self.assertEqual((web["point"], web["point_label"], web["applied"], web["failed"], web["unverified"], web["stale"],
                          web["checking"], web["delayed"], web["exempt"], web["stalled"]),
                         ("fw", "내부 방화벽", 0, 2, 4, 3, 1, 3, 1, None))
        # 받은 보고가 없으면 띠 report:fw 와 같은 글이다
        self.assertEqual(web["report_issue"], "받은 보고 없음 · 보고 파일 없음")
        # 집행기 확인이 10분 넘게 멈췄다: 실패 · 적용 · 미확인을 모두 미확인으로 합친다(10분 정각은 아직 확인 중)
        old = hb("block:gateway", kind="block_report", role="gateway", seen=11, checked=11)
        aws = t.response_block("aws-sensor", blocks, 0, {"gateway": old}, NOW, True)
        self.assertEqual((aws["applied"], aws["unverified"], aws["stale"], aws["stalled"]),
                         (0, 4, 0, "집행기 확인 중단 · 마지막 확인 11분 전"))
        edge = hb("block:gateway", kind="block_report", role="gateway", seen=10, checked=10)
        self.assertEqual({k: v for k, v in t.response_block("aws-sensor", blocks, 0, {"gateway": edge}, NOW, True).items()
                          if k in ("applied", "stale", "unrequested", "removing")},
                         {"applied": 3, "stale": 1, "unrequested": 2, "removing": 1})
        self.assertEqual((web["unrequested"], web["removing"]), (0, 0))
        self.assertEqual(web["report"], {"seen_at": None, "checked_at": (NOW - timedelta(minutes=1)).isoformat(),
                                         "problem": "보고 파일 없음"})

    def test_취약점은_자산이_없으면_0_이_아니라_missing_이다(self):
        assets = {"web-01": {"vuln_total": 5, "vuln_kev": 1, "vuln_fix_available": 2, "vuln_reboot_pending": 1,
                             "vuln_fix_unknown": 1, "collected_at": NOW - timedelta(hours=1),
                             "checked_at": NOW - timedelta(hours=1)},
                  "honeypot-dmz": {"vuln_total": 2, "vuln_kev": 0, "vuln_fix_available": 0, "vuln_reboot_pending": 0,
                                   "vuln_fix_unknown": 2, "collected_at": NOW - timedelta(hours=49), "checked_at": None}}
        self.assertEqual(t.vulns_block("web-01", False, assets, NOW), {"available": False, "assets": []})
        web = t.vulns_block("web-01", True, assets, NOW)
        self.assertEqual(web["assets"], [{"asset_id": "web-01", "vuln_total": 5, "vuln_kev": 1, "vuln_fix_available": 2,
                                          "vuln_reboot_pending": 1, "vuln_fix_unknown": 1,
                                          "collected_at": (NOW - timedelta(hours=1)).isoformat(),
                                          "checked_at": (NOW - timedelta(hours=1)).isoformat(),
                                          "stale": False, "missing": False, "check_failed": False,
                                          "check_stale": False}])
        aws = t.vulns_block("aws-sensor", True, assets, NOW)["assets"]
        self.assertEqual([(a["asset_id"], a["stale"], a["missing"]) for a in aws],
                         [("honeypot-dmz", True, False), ("gateway", True, True)])
        # 자산이 없으면 새 세 칸(수정판 있음 · 재부팅 대기 · 수정 여부 미확인)도 0 이다
        self.assertEqual({k: v for k, v in aws[1].items() if k.startswith("vuln_")},
                         {"vuln_total": 0, "vuln_kev": 0, "vuln_fix_available": 0, "vuln_reboot_pending": 0,
                          "vuln_fix_unknown": 0})
        self.assertEqual(aws[1]["collected_at"], None)
        self.assertEqual(aws[0]["vuln_fix_unknown"], 2)
        self.assertEqual([a["asset_id"] for a in t.vulns_block("console", True, {}, NOW)["assets"]],
                         ["console-a", "console-b"])
        self.assertEqual([a["asset_id"] for a in t.vulns_block("data-node", True, {}, NOW)["assets"]], ["data-01"])

    def test_취약점_대조_실패와_대조_오래됨은_수를_두고_칸으로_보인다(self):
        # 대조 실패는 check_error, 대조 오래됨은 마지막 대조가 48시간 넘음(조사 오래됨과 같은 기준). 수는 숨기거나 0 으로 바꾸지 않는다
        base = {"vuln_total": 4, "vuln_kev": 1, "vuln_fix_available": 2, "vuln_reboot_pending": 0, "vuln_fix_unknown": 2,
                "collected_at": NOW - timedelta(hours=1)}
        cases = [({"checked_at": NOW - timedelta(hours=1), "check_error": "대조 오류"}, (True, False)),
                 ({"checked_at": NOW - timedelta(hours=49), "check_error": None}, (False, True)),
                 ({"checked_at": NOW - timedelta(hours=49), "check_error": "대조 오류"}, (True, True)),
                 ({"checked_at": NOW - timedelta(hours=48), "check_error": ""}, (False, False)),    # 48시간 정각은 아직 아니다
                 ({"checked_at": None, "check_error": None}, (False, False)),                       # 대조 전은 오래됨이 아니다
                 ({"checked_at": NOW - timedelta(hours=1)}, (False, False))]                        # check_error 칸이 없는 행
        for extra, want in cases:
            with self.subTest(extra=extra):
                [asset] = t.vulns_block("web-01", True, {"web-01": base | extra}, NOW)["assets"]
                self.assertEqual((asset["check_failed"], asset["check_stale"]), want)
                self.assertEqual({k: asset[k] for k in t.VULN_COUNTS}, {k: base[k] for k in t.VULN_COUNTS})
                self.assertNotIn("check_error", asset)          # 오류 글은 싣지 않는다(자산 화면에 있다)
        [missing] = t.vulns_block("web-01", True, {}, NOW)["assets"]
        self.assertEqual((missing["missing"], missing["check_failed"], missing["check_stale"]), (True, False, False))


# ----------------------------------------------------------------------
#  5. 라우터
# ----------------------------------------------------------------------

class FakeConn:
    """표 · 권한이 하나도 없는 DB. 선검사는 모두 거짓이고 조회는 빈 답이다."""

    def __init__(self, calls):
        self.calls = calls

    async def fetchval(self, sql, *args):
        self.calls.append(sql)
        return NOW if sql == "SELECT now()" else None

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        return None

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        return []

    @asynccontextmanager
    async def transaction(self, **kw):
        self.calls.append(("transaction", kw))
        yield


class NodesConn(FakeConn):
    """nodes 만 읽을 수 있는 DB(운영 콘솔처럼 열 권한). 등록 노드 행은 ROWS 다."""
    ROWS = []

    async def fetchval(self, sql, *args):
        if sql == t.NODES_READABLE_SQL:
            self.calls.append(sql)
            return True
        return await super().fetchval(sql, *args)

    async def fetchrow(self, sql, *args):
        if sql == t.MONITOR_READABLE_SQL:
            self.calls.append(sql)
            return {"heartbeats": False, "metrics": False, "cards": True, "web": True, "parse": True}
        return await super().fetchrow(sql, *args)

    async def fetch(self, sql, *args):
        if sql == t.NODES_SQL:
            self.calls.append(sql)
            return self.ROWS
        return await super().fetch(sql, *args)


class ConsoleConn(FakeConn):
    """pg_stat_activity 를 읽을 수 있는 DB. 콘솔 A 이름표 연결만 있다. seen 은 CONSOLE_LINKS_SQL 인자다."""
    seen = []

    async def fetchval(self, sql, *args):
        if sql == t.CONSOLE_LINKS_READABLE_SQL:
            self.calls.append(sql)
            return True
        return await super().fetchval(sql, *args)

    async def fetch(self, sql, *args):
        if sql == t.CONSOLE_LINKS_SQL:
            self.calls.append(sql)
            ConsoleConn.seen.append(args)
            return [{"name": n, "present": n == "opsloop-console-a"} for n in args[0]]
        return await super().fetch(sql, *args)


class FakePool:
    def __init__(self, conn=FakeConn):
        self.calls, self.conn = [], conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn(self.calls)


class RouterTests(unittest.TestCase):
    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        patcher = patch.object(self.main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # 세션 검사의 계정 조회(auth.lookup)는 가짜 계정 표가 받는다. 가짜 풀의 질의 기록에 섞이지 않는다
        self.accounts = test_web.FakeAccounts().patch(self)
        self.accounts["han"] = test_web.account_row("viewer")
        self.client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def test_집행_제외_말머리는_main_과_같다(self):
        self.assertEqual(t.ENFORCE_EXCLUDED, self.main.ENFORCE_EXCLUDED)
        self.assertIn(f"NOT LIKE '{self.main.ENFORCE_EXCLUDED}%'", t.BLOCKS_SQL)

    def test_관문_불일치_말머리는_main_과_같고_차단_질의에_불일치_칸이_있다(self):
        # 관문 불일치 칸은 관문을 요청한 행만 센다(이슈 #77). 종합 상태도 관문 요청 행의 쪽지만 불일치로 본다
        self.assertEqual(t.ENFORCE_MISMATCH, self.main.ENFORCE_MISMATCH)
        self.assertIn(f"FILTER (WHERE 'gateway' = ANY(points) AND enforce_note LIKE '{self.main.ENFORCE_MISMATCH}%') "
                      "AS mismatch", t.BLOCKS_SQL)
        self.assertIn(f"('gateway' = ANY(points) AND (enforce_note LIKE '{self.main.ENFORCE_MISMATCH}%'",
                      self.main.BLOCK_STATES_SQL)
        # 요청하지 않은 행은 기록이 남았으면(관문 빼기 뒤 관문이 뺐다고 확인하기 전) 빠짐 확인 전, 아니면 미요청이다(결정 14)
        for p in ("gateway", "fw"):
            self.assertIn(f"count(*) FILTER (WHERE {bp.unrequested_sql(p)}) AS {p}_unrequested", t.BLOCKS_SQL)
            self.assertIn(f"count(*) FILTER (WHERE {bp.removing_sql(p)}) AS {p}_removing", t.BLOCKS_SQL)
        # 남은 기록은 state 가 글자인 결과 기록(관문은 확인 시각도)이다. 집행기 held_at · 화면 heldPoint 와 같다
        self.assertEqual(bp.removing_sql("gateway"), "NOT 'gateway' = ANY(points) AND "
                         "(jsonb_typeof(enforcement -> 'gateway' -> 'state') IS NOT DISTINCT FROM 'string' "
                         "OR enforced_at IS NOT NULL)")
        self.assertEqual(bp.unrequested_sql("fw"), "NOT 'fw' = ANY(points) AND "
                         "NOT (jsonb_typeof(enforcement -> 'fw' -> 'state') IS NOT DISTINCT FROM 'string')")

    def test_앞선_시각_줄_상한은_장비_로그_목록과_같다(self):
        # 마지막 로그 · 웹 로그 적재 판정 · 요약 최근 원문 수집은 장비 로그 목록(node_logs)과 같은 기준(기준 시각 + 5분)으로 자른다
        import node_logs
        self.assertEqual(t.FUTURE_LIMIT, "interval '5 minutes'")
        for name, sql in (("장비 로그 목록", node_logs.LINES_SQL), ("앞선 줄 수", node_logs.FUTURE_SQL),
                          ("마지막 로그", t.LOGS_SQL), ("웹 로그 적재", t.PARSE_SQL), ("요약", self.main.EVENTS_SQL)):
            with self.subTest(name=name):
                self.assertIn(f"::timestamptz + {t.FUTURE_LIMIT}", sql)

    def test_사건_목록의_미결_필터는_judged_와_함께_쓰면_둘_다_건다(self):
        # undetermined=true 는 최신 판정이 사람의 미결인 사건만이다(대시보드 미결 수와 같은 식). judged 와 함께여도 422 가 아니다
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        human = t.HUMAN_UNDETERMINED.format(v="v")
        for params, clause in [({"undetermined": "true", "judged": "true"}, f"WHERE v.verdict IS NOT NULL AND {human}"),
                               ({"undetermined": "true", "device": "web-01"}, f"WHERE {human}"),
                               ({"undetermined": "false"}, f"WHERE NOT {human}"),
                               ({}, None)]:
            self.pool.calls.clear()
            with self.subTest(params=params):
                response = self.client.get("/api/incidents", params=params)
                self.assertEqual(response.status_code, 200)
                sql = next(c for c in self.pool.calls if isinstance(c, str) and "FROM incidents i" in c)
                if clause:
                    self.assertIn(clause, sql)
                else:
                    self.assertNotIn(human, sql)
        # 판정자(operator)는 목록 칸에 싣지 않는다
        self.assertNotIn("v.operator", self.main.PAGE_COLUMNS)
        self.assertEqual(self.client.get("/api/incidents", params={"undetermined": "maybe"}).status_code, 422)

    def test_세션이_없으면_401_이다(self):
        for path in ("/api/dashboard/targets", "/api/dashboard/monitor"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual(self.pool.calls, [])
        self.assertEqual(self.accounts.calls, [], "세션이 없으면 계정도 조회하지 않는다")

    def test_표가_없는_DB_에서_먼저_처리할_사건은_비어_있다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        body = self.client.get("/api/dashboard/targets").json()
        self.assertEqual(body["queue"], {"total": 0, "front": 0, "back": 0, "unconfirmed": 0, "overdue": 0, "items": []})
        self.assertIn(t.PENDING_ROWS, self.pool.calls)
        # 데이터 노드만 멈춤 구조 값이 있다. 생존 신호 표를 읽을 수 없으면 비어 있다
        self.assertEqual([x["collection"].get("stopped") for x in body["targets"]], [None, None, None, []])

    def test_관제_이상은_표가_없으면_모름이고_탐지_경로는_멈춤이다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        response = self.client.get("/api/dashboard/monitor")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["as_of"], NOW.isoformat())
        self.assertEqual([(x["key"], x["level"]) for x in body["items"]],
                         [("heartbeats", "unknown"), ("detect:honeypot", "alert"), ("detect:bridge", "alert"),
                          ("nodes", "unknown"), ("data_resources", "unknown")])
        for item in body["items"]:
            self.assertEqual(set(item), {"key", "level", "label", "reason", "at", "count"})
        self.assertEqual([(p["key"], p["stale"], p["reason"], p["versions"]) for p in body["detect_paths"]],
                         [("honeypot", True, "24시간 안 실행 기록 없음", []), ("bridge", True, "24시간 안 실행 기록 없음", [])])
        # 한 트랜잭션(반복 읽기 · 읽기 전용)이고 질의는 10개 이하(now 포함)다. 없는 표는 읽지 않는다
        self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                         [("transaction", {"isolation": "repeatable_read", "readonly": True})])
        self.assertLessEqual(len([c for c in self.pool.calls if isinstance(c, str)]), 10)
        for sql in (t.HEARTBEATS_SQL, t.NODES_SQL, t.NODE_SQL):
            self.assertNotIn(sql, self.pool.calls)
        self.assertIn(t.DETECT_PATHS_SQL, self.pool.calls)

    def test_관제_이상은_등록_노드가_모두_끊기면_이상이다(self):
        self.pool.conn = type("Conn", (NodesConn,), {"ROWS": [
            node_row("web-01", reception="silent", seen=12), node_row("web-02", reception="silent", seen=30),
            node_row("web-03", status="pending", reception="waiting", seen=None)]})
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        items = self.client.get("/api/dashboard/monitor").json()["items"]
        self.assertEqual(next(x for x in items if x["key"] == "nodes_silent"), {"key": "nodes_silent", "level": "alert", "label": "노드 수신",
                                     "reason": "노드 2대 수신 끊김", "at": None, "count": 2})
        self.assertIn(t.NODES_SQL, self.pool.calls)

    def test_관제_이상은_질의_10개_이하로_보완_항목을_싣는다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        for can, keys in [
                ({}, ["sensor", "point_stale:fw", "report:fw", "nodes_silent", "parse:web-03", "metrics:web-01"]),
                # web-01 이 읽는 열만 되면 web-01 한 행으로 판정하고 등록 노드 열은 모름이다
                ({"cards": False}, ["sensor", "point_stale:fw", "report:fw", "nodes", "metrics:web-01"])]:
            with self.subTest(can=can):
                self.pool.calls.clear()
                self.pool.conn = type("Conn", (MonitorConn,), {"CAN": {**MonitorConn.CAN, **can}})
                items = self.client.get("/api/dashboard/monitor").json()["items"]
                self.assertEqual([x["key"] for x in items], keys + ["data_resources"])
                self.assertLessEqual(len([c for c in self.pool.calls if isinstance(c, str)]), 10)
        self.assertEqual(items[3]["reason"], "등록 노드 열을 읽을 수 없음")
        self.assertIn(t.NODE_SQL, self.pool.calls)
        self.assertNotIn(t.NODES_SQL, self.pool.calls)

    def test_관제_이상은_web_01_행으로_등록_기록_없음과_폐기의_옛_지표를_가른다(self):
        # web-01 행이 없으면 카드 '노드 등록 기록 없음' 과 짝인 노드 수신 모름, 폐기된 web-01 의 옛 지표는 싣지 않는다
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        others = [node_row("web-02", reception="silent", seen=12), node_row("web-03")]
        for rows, keys in [
                (others, ["sensor", "point_stale:fw", "report:fw", "nodes_silent", "nodes", "parse:web-03", "metrics:web-01"]),
                ([node_row("web-01", status="revoked", reception="revoked"), *others],
                 ["sensor", "point_stale:fw", "report:fw", "nodes_silent", "parse:web-03"])]:
            with self.subTest(web=[r["reception"] for r in rows if r["node_id"] == "web-01"]):
                self.pool.conn = type("Conn", (MonitorConn,), {"ROWS": rows})
                items = self.client.get("/api/dashboard/monitor").json()["items"]
                self.assertEqual([x["key"] for x in items], keys + ["data_resources"])
                if "nodes" in keys:
                    self.assertEqual(items[keys.index("nodes")]["reason"], "web-01 등록 기록 없음")

    def test_표_권한이_없는_DB_에서도_미확인으로_답한다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        response = self.client.get("/api/dashboard/targets")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["as_of"], body["window_seconds"], body["heartbeats_available"], body["metrics_available"]),
                         (NOW.isoformat(), 3600, False, False))
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        self.assertEqual([x["label"] for x in body["targets"]], ["허니팟 센서", "web-01", "관제 콘솔", "데이터 노드"])
        # 콘솔은 이 조회에 응답했으니 응답 중이다. 연결 목록을 읽을 수 없으면 확인 불가다(이슈 #76)
        self.assertEqual([x["collection"]["state"] for x in body["targets"]], ["unknown", "unknown", "responding", "unknown"])
        console = body["targets"][2]["collection"]
        self.assertEqual((console["reason"], console["db_links"]), ("DB 연결 확인 불가", None))
        self.assertIn(t.CONSOLE_LINKS_READABLE_SQL, self.pool.calls)
        self.assertEqual([x["system"]["state"] for x in body["targets"]],
                         ["not_collected", "no_privilege", "not_collected", "no_data"])
        self.assertEqual([x["vulns"] for x in body["targets"]], [{"available": False, "assets": []}] * 4)
        self.assertEqual(body["unmapped"], {"incidents_1h": 0, "pending": 0, "undetermined": 0})
        # 한 트랜잭션(반복 읽기 · 읽기 전용)이고, 없는 표는 읽지 않는다
        self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                         [("transaction", {"isolation": "repeatable_read", "readonly": True})])
        for sql in (t.HEARTBEATS_SQL, t.METRICS_SQL, t.RULES_SQL, t.JOIN_SQL, t.CONSOLE_LINKS_SQL):
            self.assertNotIn(sql, self.pool.calls)
        self.assertIn(t.HEARTBEATS_READABLE_SQL, self.pool.calls)
        self.assertIn(t.METRICS_READABLE_SQL, self.pool.calls)

    def test_콘솔_카드는_응답_중이고_DB_연결은_이름표_연결의_있음_없음이다(self):
        self.pool.conn = ConsoleConn
        ConsoleConn.seen = []
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        body = self.client.get("/api/dashboard/targets").json()
        console = next(x for x in body["targets"] if x["id"] == "console")["collection"]
        self.assertEqual((console["state"], console["reason"], console["signal"]),
                         ("responding", "DB 연결 확인: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)", None))
        self.assertEqual(console["db_links"], [
            {"name": "opsloop-console-a", "label": "콘솔 A", "present": True, "note": None},
            {"name": "opsloop-console-b", "label": "콘솔 B", "present": False, "note": "평소 꺼 두는 예비"}])
        # 콘솔 이름표들을 한 번에 묻는다. 같은 트랜잭션(반복 읽기 · 읽기 전용) 안이다
        self.assertEqual(ConsoleConn.seen, [(["opsloop-console-a", "opsloop-console-b"],)])
        self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                         [("transaction", {"isolation": "repeatable_read", "readonly": True})])
        # 다른 대상에는 DB 연결 칸이 없다
        self.assertEqual([x["id"] for x in body["targets"] if "db_links" in x["collection"]], ["console"])

    def test_nodes_를_읽을_수_없으면_고정_네_대상만이다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        body = self.client.get("/api/dashboard/targets").json()
        self.assertEqual([(x["id"], x["kind"]) for x in body["targets"]],
                         [("aws-sensor", "fixed"), ("web-01", "fixed"), ("console", "fixed"), ("data-node", "fixed")])
        # 등록 기록이 없는 것이 아니라 모르는 것이다. 권한 없는 표는 읽지 않는다
        web = body["targets"][1]["collection"]
        self.assertEqual((web["state"], web["reason"]), ("unknown", "노드 표를 읽을 수 없음"))
        self.assertIn(t.NODES_READABLE_SQL, self.pool.calls)
        for sql in (t.NODES_SQL, t.NODE_SQL):
            self.assertNotIn(sql, self.pool.calls)

    def test_등록_노드_카드는_고정_대상_뒤에_web_01_카드와_같은_모양으로_붙는다(self):
        self.pool.conn = type("Conn", (NodesConn,), {"ROWS": [
            node_row("web-03", status="pending", reception="waiting", seen=None, loaded=None),
            node_row("web-02", hostname="web02.lab", sensor="web-02"),
            node_row("web-01", hostname="web-01", sensor="web-01"),
            node_row("probe-01", sensor="probe-01", status="revoked", reception="revoked")]})
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        body = self.client.get("/api/dashboard/targets").json()
        self.assertEqual([(x["id"], x["kind"], x["label"], x["role"]) for x in body["targets"]][4:],
                         [("web-02", "node", "web02.lab", "등록 노드"), ("web-03", "node", "web-03", "등록 노드")])
        self.assertEqual([x["id"] for x in body["targets"]][:4], ["aws-sensor", "web-01", "console", "data-node"])
        web, node = body["targets"][1], body["targets"][4]
        self.assertEqual(set(node), set(web))
        for key in ("collection", "security", "system", "response", "vulns"):
            with self.subTest(block=key):
                self.assertEqual(set(node[key]), set(web[key]))
        self.assertEqual((node["collection"]["state"], node["collection"]["reason"]),
                         ("quiet", "노드 수신 2분 전 · 최근 1시간 요청 없음"))
        self.assertEqual(node["collection"]["logs"], [{"key": "web-02", "label": "web02.lab 로그", "last_at": None}])
        self.assertEqual(body["targets"][5]["collection"]["reason"], "노드 등록 대기 · 수신 전")
        self.assertEqual((node["response"]["point"], node["response"]["applied"]), (None, None))
        self.assertEqual(node["system"], {"state": "no_privilege", "metrics": None})    # node_metrics 를 읽을 수 없음
        # web-01 은 고정 카드(NODE_SQL)로 읽는다. 가짜 DB 에는 그 행이 없다
        self.assertEqual(web["collection"]["reason"], "노드 등록 기록 없음")
        self.assertIn(t.NODES_SQL, self.pool.calls)

    def test_경로는_상태판_처리기로_간다(self):
        from starlette.routing import Match
        for path, endpoint in (("/api/dashboard/targets", t.dashboard_targets),
                               ("/api/dashboard/monitor", t.dashboard_monitor)):
            scope = {"type": "http", "path": path, "method": "GET", "root_path": "", "headers": []}
            route = next(r for r in self.main.app.routes if r.matches(scope)[0] == Match.FULL)
            self.assertIs(route.endpoint, endpoint)


# ----------------------------------------------------------------------
#  6. 등록 노드 (이슈 #64)
# ----------------------------------------------------------------------

NODES = {"web-02": "web-02"}      # 등록 노드 {발생원: 노드 id}


def node_row(node_id, status="active", hostname=None, sensor=None, reception="normal", seen=2, loaded=2):
    """NODES_SQL 한 행과 같은 꼴. seen · loaded 는 분 전(None 이면 없음)."""
    return {"node_id": node_id, "hostname": hostname, "sensor": sensor, "status": status, "reception": reception,
            "last_seen_at": NOW - timedelta(minutes=seen) if seen is not None else None,
            "last_loaded_at": NOW - timedelta(minutes=loaded) if loaded is not None else None}


class NodeResolveTests(unittest.TestCase):
    def test_등록_노드의_발생원은_그_노드_카드다(self):
        self.assertEqual(t.attach(["web-02", "cowrie", "web-09"], NODES), {("web-02", None), ("aws-sensor", "cowrie")})
        # 고정 발생원이 먼저다(등록 노드가 고정 발생원을 가져가지 못한다)
        self.assertEqual(t.attach(["web-01"], {"web-01": "web-01b"}), {("web-01", None)})
        # 등록 노드를 모르면 지금처럼 버린다
        self.assertEqual(t.attach(["web-02"]), set())
        # 근거의 발생원(url_signature 의 evidence.sensors)
        self.assertEqual(t.resolve(None, json.dumps(["decoy", "web-02"]), spec(eventids=["nginx.request"]), NODES),
                         ({("aws-sensor", "decoy"), ("web-02", None)}, False))

    def test_노드_대상은_등록_노드면_그_카드다(self):
        self.assertEqual(t.resolve("node:web-02", None, spec(), NODES), ({("web-02", None)}, False))
        self.assertEqual(t.resolve("node:web-01", None, spec(), NODES), ({("web-01", None)}, False))
        # 폐기 · 미등록 노드는 카드가 없어 붙이지 못한다(지금과 같다)
        self.assertEqual(t.resolve("node:probe-01", None, spec(), NODES), (set(), False))
        self.assertEqual(t.resolve("node:web-02", None, spec()), (set(), False))

    def test_노드_에이전트_이벤트는_등록_노드가_있으면_이벤트로_고른다(self):
        r101 = spec("actor_rate", eventids=["sshd.login.failed", "sshd.login.invalid_user"])
        self.assertEqual(t.candidate_sources(r101, NODES), ["web-01", "web-02"])
        self.assertEqual(t.candidate_sources(spec(eventid_like="nginx.%"), NODES), ["web-01", "web-02"])
        self.assertEqual(t.candidate_sources(spec(eventids=["cowrie.login.failed", "decoy.request"]), NODES),
                         ["cowrie", "decoy"])
        # 등록 노드가 없으면 지금처럼 web-01 이다. 있으면 이벤트로 고르고, 고르지 못하면 전처럼 web-01 이다
        self.assertEqual(t.resolve(None, None, r101), ({("web-01", None)}, False))
        self.assertEqual(t.resolve(None, None, r101, NODES), ({("web-01", None)}, t.EVENTS))
        # 고정 발생원만으로도 섞인 규칙은 전처럼 붙인 곳 없이 이벤트로 고른다
        self.assertEqual(t.resolve(None, None, spec(eventids=["nginx.request", "decoy.request"]), NODES),
                         (set(), t.EVENTS))
        # 등록 노드 발생원이 더해져 섞였을 뿐이면 고르지 못할 때 등록 노드 없이 정한 값이다(허니팟 센서 나눔도 그대로)
        cowrie_and_node = spec(sensors=["cowrie", "web-02"], eventids=["cowrie.login.failed"])
        self.assertEqual(t.resolve(None, None, cowrie_and_node), ({("aws-sensor", "cowrie")}, False))
        self.assertEqual(t.resolve(None, None, cowrie_and_node, NODES), ({("aws-sensor", "cowrie")}, t.EVENTS))

    def test_실제_규칙_파일은_등록_노드가_있으면_고르지_못할_때_대체_추정이다(self):
        changed = {}
        for version, rule_id, s in file_rules():
            before, join = t.resolve_links(None, None, s)
            after, join_after = t.resolve_links(None, None, s, NODES)
            with self.subTest(version=version, rule=rule_id):
                self.assertEqual(set(after), set(before))       # 붙인 곳(옛 resolve 값)은 같다
                if (after, join_after) != (before, join):
                    changed[(version, rule_id)] = (before, join, after, join_after)
        # 노드 에이전트 이벤트만 보는 규칙(n1 R101)만 바뀐다: 등록 노드가 없으면 web-01 규칙 범위, 있으면 이벤트로 고르고
        #   고르지 못하면 web-01 대체 추정이다(카드 · 장비 필터에서 빠져 장비 미확인)
        self.assertEqual(changed, {("n1", "R101"): ({("web-01", None): t.RULE_SCOPE}, False,
                                                    {("web-01", None): t.FALLBACK}, t.EVENTS)})
        self.assertEqual(t.shown(changed[("n1", "R101")][2]), set())

    def test_집계는_등록_노드_카드를_함께_센다(self):
        rows = [incident("a", 5, severity="high"), incident("b", 5), incident("c", 5)]
        attached = {"a": {("web-02", None)}, "b": {("web-01", None), ("web-02", None)}, "c": set()}
        per, unmapped = t.tally(rows, attached, NOW, ["web-02"])
        self.assertEqual(list(per), ["aws-sensor", "web-01", "console", "data-node", "web-02"])
        self.assertEqual((per["web-02"]["incidents_1h"], per["web-02"]["high_1h"], per["web-02"]["pending"]), (2, 1, 2))
        self.assertEqual((per["web-01"]["incidents_1h"], per["web-01"]["high_1h"]), (1, 0))
        self.assertEqual(unmapped, {"incidents_1h": 1, "pending": 1, "undetermined": 0})
        self.assertEqual(t.security_block("web-02", per["web-02"], NOW)["parts"], [])
        self.assertEqual(t.security_block("web-02", per["web-02"], NOW)["latest"]["incident_key"], "a")


class NodeCardTests(unittest.TestCase):
    def test_폐기_고정_대상_고정_발생원_겹치는_발생원은_카드가_없다(self):
        rows = [node_row("web-03", status="pending", reception="waiting", seen=None),
                node_row("web-02", hostname="web02.lab", sensor="web-02"),
                node_row("web-01", hostname="web-01", sensor="web-01"),              # 고정 대상
                node_row("probe-01", sensor="probe-01", status="revoked", reception="revoked"),
                node_row("audit", sensor="audit"),                                    # 고정 발생원(콘솔 감사 기록)
                node_row("web-04", sensor="web-02"),                                  # 앞 노드와 같은 발생원
                node_row("data-node", sensor="data-node")]                            # 고정 대상 id
        cards = t.node_targets(rows)
        self.assertEqual([(c["id"], c["label"], c["sensor"]) for c in cards],
                         [("web-02", "web02.lab", "web-02"), ("web-03", "web-03", "web-03")])
        self.assertEqual(t.node_sources(cards), {"web-02": "web-02", "web-03": "web-03"})
        self.assertEqual(t.node_targets([]), [])

    def test_수집은_web_01_과_같은_판정이고_그_노드_로그로_가른다(self):
        sources = [("web-02", "web02.lab 로그")]
        logs = {"web-02": NOW - timedelta(minutes=5), "web-01": NOW}
        c = t.node_collection(NOW, node_row("web-02"), logs, sources)
        self.assertEqual((c["state"], c["reason"]), ("ok", "노드 수신 2분 전 · 최근 1시간 로그 있음"))
        self.assertEqual(c["logs"], [{"key": "web-02", "label": "web02.lab 로그",
                                      "last_at": (NOW - timedelta(minutes=5)).isoformat()}])
        self.assertEqual(c["extra"], [{"label": "마지막 적재", "at": (NOW - timedelta(minutes=2)).isoformat(), "note": None}])
        # web-01 로그만 있으면 이 노드는 요청 없음이다
        c = t.node_collection(NOW, node_row("web-02"), {"web-01": NOW}, sources)
        self.assertEqual((c["state"], c["reason"]), ("quiet", "노드 수신 2분 전 · 최근 1시간 요청 없음"))
        for row, state, reason in [
                (node_row("web-03", status="pending", reception="waiting", seen=None), "unknown", "노드 등록 대기 · 수신 전"),
                (node_row("web-02", reception="silent", seen=12), "no_signal", "노드 수신 12분 전 · 10분 넘게 끊김")]:
            with self.subTest(reason=reason):
                c = t.node_collection(NOW, row, logs, sources)
                self.assertEqual((c["state"], c["reason"]), (state, reason))

    def test_nodes_를_읽을_수_없으면_web_01_수신은_미확인이다(self):
        c = t.node_collection(NOW, None, {"web-01": NOW}, readable=False)
        self.assertEqual((c["state"], c["reason"], c["extra"][0]["at"]), ("unknown", "노드 표를 읽을 수 없음", None))
        self.assertEqual([(l["key"], l["label"]) for l in c["logs"]], [("web-01", "web-01 로그")])

    def test_자원_지표는_보내는_노드만이고_행이_없으면_미수집이다(self):
        row = BlocksTests.ROW
        self.assertEqual(t.system_block("web-02", True, None, NOW, True), {"state": "not_collected", "metrics": None})
        self.assertEqual(t.system_block("web-02", False, row, NOW, True), {"state": "no_privilege", "metrics": None})
        self.assertEqual(t.system_block("web-02", True, row, NOW, True), t.system_block("web-01", True, row, NOW))
        stale = row | {"ts": NOW - timedelta(seconds=601)}
        self.assertEqual(t.system_block("web-02", True, stale, NOW, True)["state"], "stale")
        # 등록 노드로 넘기지 않은 id 는 고정 대상처럼 미수집이다. web-01 은 행이 없으면 지금처럼 '없음' 이다
        self.assertEqual(t.system_block("web-02", True, row, NOW), {"state": "not_collected", "metrics": None})
        self.assertEqual(t.system_block("web-01", True, None, NOW), {"state": "no_data", "metrics": None})

    def test_취약점은_같은_이름의_자산만_잇고_대응은_지점이_없다(self):
        assets = {"web-02": {"vuln_total": 3, "vuln_kev": 1, "vuln_fix_available": 1, "vuln_reboot_pending": 0,
                             "vuln_fix_unknown": 2, "collected_at": NOW - timedelta(hours=1), "checked_at": None}}
        self.assertEqual(t.vulns_block("web-02", True, assets, NOW)["assets"], [{
            "asset_id": "web-02", "vuln_total": 3, "vuln_kev": 1, "vuln_fix_available": 1, "vuln_reboot_pending": 0,
            "vuln_fix_unknown": 2, "collected_at": (NOW - timedelta(hours=1)).isoformat(),
            "checked_at": None, "stale": False, "missing": False, "check_failed": False, "check_stale": False}])
        self.assertEqual(t.vulns_block("web-03", True, assets, NOW), {"available": True, "assets": []})
        self.assertEqual(t.vulns_block("web-02", False, assets, NOW), {"available": False, "assets": []})
        blocks = {"gateway_applied": 3, "gateway_failed": 0, "gateway_unverified": 1, "gateway_stale": 0,
                  "gateway_checking": 1, "gateway_delayed": 0, "gateway_unrequested": 0, "gateway_removing": 0,
                  "fw_applied": 1, "fw_failed": 0, "fw_unverified": 0, "fw_stale": 0, "fw_checking": 0, "fw_delayed": 0,
                  "fw_unrequested": 0, "fw_removing": 0}
        self.assertEqual(t.response_block("web-02", blocks, 1, {}, NOW, True),
                         {"point": None, "point_label": None, "applied": None, "failed": None, "unverified": None,
                          "stale": None, "checking": None, "delayed": None, "unrequested": None, "removing": None,
                          "exempt": 1, "report": None, "report_issue": None, "stalled": None, "unreadable": None})


# ----------------------------------------------------------------------
#  7. 관련 장비 · 먼저 처리할 사건 · 관제 이상 (이슈 #72)
# ----------------------------------------------------------------------

C, S, F = t.CONFIRMED, t.RULE_SCOPE, t.FALLBACK
AWS, WEB = "aws-sensor", "web-01"
CARDS = [{"id": "web-02", "label": "web02.lab", "sensor": "web-02", "node": None}]


def file_spec(version, rule_id):
    return next(s for v, rid, s in file_rules() if (v, rid) == (version, rule_id))


class ResolveLinksTests(unittest.TestCase):
    def test_사건_자체가_가리키면_확인이다(self):
        self.assertEqual(t.resolve_links("node:web-02", None, spec(), NODES), ({("web-02", None): C}, False))
        self.assertEqual(t.resolve_links("node:web-01", None, spec(), NODES), ({(WEB, None): C}, False))
        self.assertEqual(t.resolve_links("user:han", None, None), ({("console", None): C}, False))
        self.assertEqual(t.resolve_links(None, json.dumps(["decoy", "web-02"]), spec(eventids=["nginx.request"]), NODES),
                         ({(AWS, "decoy"): C, ("web-02", None): C}, False))

    def test_폐기_모르는_노드_정의_없음은_붙이지_못한다(self):
        self.assertEqual(t.resolve_links("node:probe-01", None, spec(), NODES), ({}, False))
        self.assertEqual(t.resolve_links("node:web-09", None, spec(eventids=["cowrie.login.failed"])), ({}, False))
        self.assertEqual(t.resolve_links(None, None, None), ({}, False))
        self.assertEqual(t.resolve_links(None, None, spec("node_silence")), ({}, False))

    def test_후보가_한_대상이면_규칙_범위다(self):
        for version, rule_id, pair in [("v3", "R001", (AWS, "cowrie")), ("v3", "R003", (AWS, "cowrie")),
                                       ("v3", "R004", (AWS, "cowrie")), ("v3", "R006", (AWS, "cowrie")),
                                       ("w2", "R103", (AWS, "decoy")), ("s1", "R202", ("data-node", None)),
                                       ("n1", "R101", (WEB, None))]:
            with self.subTest(version=version, rule=rule_id):
                self.assertEqual(t.resolve_links(None, None, file_spec(version, rule_id)), ({pair: S}, False))

    def test_나눔만_여럿이면_대상은_규칙_범위이고_이벤트로_고른다(self):
        self.assertEqual(t.resolve_links(None, None, spec(eventids=["cowrie.login.failed", "decoy.login.failed"])),
                         ({(AWS, None): S}, t.EVENTS))

    def test_등록_노드로_섞였을_뿐이면_고르지_못할_때_대체_추정이다(self):
        self.assertEqual(t.resolve_links(None, None, file_spec("n1", "R101"), NODES), ({(WEB, None): F}, t.EVENTS))
        # 고정 발생원만으로도 섞인 규칙은 붙인 곳 없이 이벤트로 고른다
        self.assertEqual(t.resolve_links(None, None, file_spec("w2", "R101"), NODES), ({}, t.EVENTS))
        self.assertEqual(t.resolve_links(None, None, file_spec("w2", "R101")), ({}, t.EVENTS))

    def test_세션_규칙은_규칙_범위_기준선은_대체_추정이다(self):
        self.assertEqual(t.resolve_links(None, None, file_spec("v3", "R002")), ({(AWS, None): S}, t.SESSIONS))
        # 기준선(R005)은 Cowrie · 디코이 · 콘솔을 함께 센다. 한 장비만 보는 규칙이 아니라 Cowrie 는 추정이다
        self.assertEqual(t.resolve_links(None, None, file_spec("v3", "R005")), ({(AWS, "cowrie"): F}, False))
        self.assertEqual(t.resolve_links(None, None, spec("key_plant")), ({(AWS, "cowrie"): F}, False))

    def test_실제_규칙_파일_근거표(self):
        # 등록 노드 없음 · {web-02: web-02} 두 경우. 목록에 없는 규칙은 v1 값을 쓴다(v1 · v2 · v3 가 같다)
        honeypot = {"R001": ({(AWS, "cowrie"): S}, False), "R002": ({(AWS, None): S}, t.SESSIONS),
                    "R003": ({(AWS, "cowrie"): S}, False), "R004": ({(AWS, "cowrie"): S}, False),
                    "R005": ({(AWS, "cowrie"): F}, False), "R006": ({(AWS, "cowrie"): S}, False)}
        joins = ({}, t.EVENTS)
        expected = {("w2", "R101"): joins, ("w2", "R102"): joins, ("w2", "R104"): joins, ("c1", "R105"): joins,
                    ("c1", "R106"): joins, ("sg1", "R107"): joins, ("w2", "R103"): ({(AWS, "decoy"): S}, False),
                    ("a1", "R201"): ({("console", None): S}, False), ("s1", "R202"): ({("data-node", None): S}, False),
                    ("i2", "R301"): ({}, False)}
        # 옛 resolve 값(ResolveTests 의 표 · 등록 노드가 있어도 n1 R101 은 전처럼 web-01). legacy_pairs 는 이것과 같아야 한다
        old_honeypot = {"R001": {(AWS, "cowrie")}, "R002": {(AWS, None)}, "R003": {(AWS, "cowrie")},
                        "R004": {(AWS, "cowrie")}, "R005": {(AWS, "cowrie")}, "R006": {(AWS, "cowrie")}}
        old = {("w2", "R103"): {(AWS, "decoy")}, ("a1", "R201"): {("console", None)},
               ("s1", "R202"): {("data-node", None)}, ("i2", "R301"): set(), ("n1", "R101"): {(WEB, None)},
               **{key: set() for key, want in expected.items() if want == joins}}
        for nodes in (None, NODES):
            for version, rule_id, s in file_rules():
                want = expected.get((version, rule_id)) or honeypot.get(rule_id)
                if (version, rule_id) == ("n1", "R101"):
                    want = ({(WEB, None): F}, t.EVENTS) if nodes else ({(WEB, None): S}, False)
                with self.subTest(nodes=bool(nodes), version=version, rule=rule_id):
                    links, need = t.resolve_links(None, None, s, nodes)
                    self.assertEqual((links, need), want)
                    # 옛 모양(legacy_pairs)은 옛 resolve 값과 같다
                    self.assertEqual(t.legacy_pairs(links), old.get((version, rule_id), old_honeypot.get(rule_id)))
        # R301 은 대상(node:<id>)으로만 붙는다(확인)
        self.assertEqual(t.resolve_links("node:web-01", None, file_spec("i2", "R301")), ({(WEB, None): C}, False))
        self.assertEqual(t.resolve_links("user:han", None, file_spec("a1", "R201")), ({("console", None): C}, False))

    def test_shown_은_대체_추정을_빼고_나눔이_있으면_대상만_짝을_뺀다(self):
        bare_r002 = {(AWS, None): S, (AWS, "cowrie"): F}
        self.assertEqual(t.shown(bare_r002), {(AWS, None)})
        self.assertEqual(t.shown_targets(bare_r002), {AWS})
        self.assertEqual(t.shown({(AWS, None): S, (AWS, "decoy"): C}), {(AWS, "decoy")})
        self.assertEqual(t.shown({(WEB, None): F}), set())
        self.assertEqual(t.shown({}), set())
        # 옛 모양: 세션으로 고르지 못한 R002 는 전처럼 Cowrie · 대체 추정도 붙인 곳이다
        self.assertEqual(t.legacy_pairs(bare_r002), {(AWS, "cowrie")})
        self.assertEqual(t.legacy_pairs({(WEB, None): F}), {(WEB, None)})

    def test_장비_필터_조건은_shown_대상이다(self):
        self.assertTrue(t.device_matches(AWS, {(AWS, None): S, (AWS, "cowrie"): F}))
        self.assertFalse(t.device_matches(WEB, {(WEB, None): F}))
        self.assertTrue(t.device_matches(t.UNCONFIRMED, {(WEB, None): F}))
        self.assertTrue(t.device_matches(t.UNCONFIRMED, {}))
        self.assertFalse(t.device_matches(t.UNCONFIRMED, {("console", None): C}))
        self.assertFalse(t.device_matches("web-09", {(WEB, None): C}))


class DeviceTests(unittest.TestCase):
    def test_보호_대상이_먼저이고_여러_장비를_싣는다(self):
        # w2 R102 에서 web-01 과 디코이 이벤트를 모두 찾은 사건
        got = t.devices_of({(AWS, "decoy"): C, (WEB, None): C}, file_spec("w2", "R102"), [])
        self.assertEqual(got, {"devices": [
            {"id": WEB, "part": None, "label": "web-01", "group": "protected", "logs": ["웹 접근"], "basis": C},
            {"id": AWS, "part": "decoy", "label": "웹 디코이", "group": "sensor", "logs": ["웹 요청"], "basis": C}],
            "device_state": "confirmed", "device_fallback": []})

    def test_정렬은_보호_대상_관측_센서_관제_시스템이다(self):
        links = {("data-node", None): S, ("console", None): C, (AWS, "gateway"): S, (AWS, "cowrie"): S,
                 ("web-03", None): C, ("web-02", None): C, (WEB, None): S}
        cards = CARDS + [{"id": "web-03", "label": "web-03", "sensor": "web-03", "node": None}]
        got = t.devices_of(links, None, cards)["devices"]
        self.assertEqual([(d["id"], d["part"], d["group"]) for d in got],
                         [(WEB, None, "protected"), ("web-02", None, "protected"), ("web-03", None, "protected"),
                          (AWS, "cowrie", "sensor"), (AWS, "gateway", "sensor"),
                          ("console", None, "monitor"), ("data-node", None, "monitor")])
        self.assertEqual([d["logs"] for d in got], [[]] * 7)          # 규칙 정의가 없으면 로그 종류도 없다
        self.assertEqual(t.devices_of(links, None, cards)["device_state"], "confirmed")

    def test_대체_추정만_있으면_장비_미확인이고_추정은_따로_싣는다(self):
        got = t.devices_of({(AWS, "cowrie"): F}, file_spec("v3", "R005"), [])
        self.assertEqual(got, {"devices": [], "device_state": "unconfirmed", "device_fallback": [
            {"id": AWS, "part": "cowrie", "label": "SSH 허니팟(Cowrie)", "group": "sensor", "logs": ["SSH 세션"], "basis": F}]})
        got = t.devices_of({(WEB, None): F}, file_spec("n1", "R101"), CARDS)
        self.assertEqual((got["devices"], got["device_state"]), ([], "unconfirmed"))
        self.assertEqual([(d["label"], d["logs"]) for d in got["device_fallback"]], [("web-01", ["SSH 인증"])])
        self.assertEqual(t.devices_of({}, None, []), {"devices": [], "device_state": "unconfirmed", "device_fallback": []})

    def test_세션을_고르지_못한_R002_는_허니팟_센서_세션_기록이다(self):
        got = t.devices_of({(AWS, None): S, (AWS, "cowrie"): F}, file_spec("v3", "R002"), [])
        self.assertEqual(got["devices"], [{"id": AWS, "part": None, "label": "허니팟 센서", "group": "sensor",
                                           "logs": ["세션 기록"], "basis": S}])
        self.assertEqual(got["device_state"], "rule_scope")
        self.assertEqual([(d["label"], d["logs"], d["basis"]) for d in got["device_fallback"]],
                         [("SSH 허니팟(Cowrie)", ["SSH 세션"], F)])
        # 세션으로 찾은 나눔
        got = t.devices_of({(AWS, "decoy"): C}, file_spec("v3", "R002"), [])
        self.assertEqual([(d["label"], d["logs"]) for d in got["devices"]], [("웹 디코이", ["웹 요청"])])

    def test_로그_종류(self):
        cases = [
            # (링크, 규칙, 카드, [(이름, 로그 종류)])
            ({(WEB, None): C}, file_spec("i2", "R301"), [], [("web-01", ["지표 수신"])]),
            ({("web-02", None): C}, file_spec("i2", "R301"), CARDS, [("web02.lab", ["지표 수신"])]),
            ({("console", None): C}, file_spec("a1", "R201"), [], [("관제 콘솔", ["감사 기록"])]),
            ({("data-node", None): S}, file_spec("s1", "R202"), [], [("데이터 노드", ["수집 관문", "원장 가져오기"])]),
            ({(AWS, "cowrie"): S}, file_spec("v3", "R001"), [], [("SSH 허니팟(Cowrie)", ["SSH 세션"])]),
            ({(AWS, "decoy"): S}, file_spec("w2", "R103"), [], [("웹 디코이", ["웹 요청"])]),
            # 등록 노드 카드는 hostname 이름 · 보호 대상이고 노드 에이전트 이벤트(sshd. · nginx.)를 본다
            ({("web-02", None): C}, file_spec("n1", "R101"), CARDS, [("web02.lab", ["SSH 인증"])]),
            ({("web-02", None): C, (AWS, "decoy"): C}, file_spec("c1", "R106"), CARDS,
             [("web02.lab", ["웹 접근"]), ("웹 디코이", ["웹 요청"])]),
            # 섞인 규칙: 장비마다 그 장비의 이벤트만
            ({(WEB, None): C, ("console", None): C, (AWS, "decoy"): C}, file_spec("w2", "R101"), [],
             [("web-01", ["SSH 인증"]), ("웹 디코이", ["웹 요청"]), ("관제 콘솔", ["콘솔 기록"])]),
            ({("console", None): C}, file_spec("w2", "R104"), [], [("관제 콘솔", ["콘솔 기록"])]),
            ({(AWS, "gateway"): C}, file_spec("w2", "R102"), [], [("허니팟 관문", ["관문 기록"])]),
        ]
        for links, s, cards, want in cases:
            with self.subTest(links=sorted(links, key=str)):
                got = t.devices_of(links, s, cards)["devices"]
                self.assertEqual([(d["label"], d["logs"]) for d in got], want)
        self.assertEqual(t.log_kinds(WEB, None, None, []), [])
        self.assertEqual(t.device_group("web-02", CARDS), "protected")

    def test_장비_선택지는_행과_관계없이_보호_대상_관측_센서_관제_시스템_순이다(self):
        self.assertEqual(t.device_options(CARDS), [
            {"id": WEB, "label": "web-01", "group": "protected"}, {"id": "web-02", "label": "web02.lab", "group": "protected"},
            {"id": AWS, "label": "허니팟 센서", "group": "sensor"}, {"id": "console", "label": "관제 콘솔", "group": "monitor"},
            {"id": "data-node", "label": "데이터 노드", "group": "monitor"}])
        self.assertEqual([o["id"] for o in t.device_options([])], [WEB, AWS, "console", "data-node"])


class ShownTallyTests(unittest.TestCase):
    def test_대체_추정은_장비_미확인으로_세고_세션_규칙은_나눔에서만_빠진다(self):
        rows = [incident("r005", 5, rule="R005"), incident("n-bare", 5, rule="R101"), incident("s-bare", 5, rule="R002"),
                incident("s-decoy", 5, rule="R002")]
        links = {"r005": {(AWS, "cowrie"): F}, "n-bare": {(WEB, None): F},
                 "s-bare": {(AWS, None): S, (AWS, "cowrie"): F}, "s-decoy": {(AWS, "decoy"): C}}
        per, unmapped = t.tally(rows, {k: t.shown(v) for k, v in links.items()}, NOW)
        self.assertEqual(unmapped, {"incidents_1h": 2, "pending": 2, "undetermined": 0})
        self.assertEqual((per[AWS]["incidents_1h"], per[AWS]["pending"]), (2, 2))
        self.assertEqual({k: v["pending"] for k, v in per[AWS]["parts"].items()}, {"cowrie": 0, "decoy": 1, "gateway": 0})
        self.assertEqual(per[WEB]["pending"], 0)
        # 옛 모양이면 모두 붙었다(카드 수가 바뀌는 경우)
        per, unmapped = t.tally(rows, {k: t.legacy_pairs(v) for k, v in links.items()}, NOW)
        self.assertEqual((unmapped["pending"], per[AWS]["parts"]["cowrie"]["pending"], per[WEB]["pending"]), (0, 2, 1))


def pending_row(key, minutes, rule="R001", version="v3", severity="medium", overdue=False, actor="198.51.100.1",
                target=None):
    """PENDING_ROWS 한 행과 같은 꼴."""
    return {"incident_key": key, "rule_id": rule, "rule_version": version, "rule_name": f"{rule} 규칙",
            "severity": severity, "actor_ip": actor, "target": target, "first_ts": NOW - timedelta(minutes=minutes),
            "pending_seconds": minutes * 60.0, "target_seconds": 43200, "overdue": overdue}


class QueueTests(unittest.TestCase):
    def test_묶음은_장비로_가른다(self):
        self.assertEqual(t.lane_of({}), "front")                                           # 장비 미확인
        self.assertEqual(t.lane_of({(AWS, "cowrie"): F}), "front")                         # 대체 추정뿐 = 장비 미확인
        self.assertEqual(t.lane_of({("data-node", None): S}), "front")                     # R202
        self.assertEqual(t.lane_of({("console", None): C}), "front")                       # R201
        self.assertEqual(t.lane_of({("web-02", None): C}), "front")                        # R301 노드
        self.assertEqual(t.lane_of({(WEB, None): C, (AWS, "decoy"): C}), "front")
        self.assertEqual(t.lane_of({(AWS, "cowrie"): S}), "back")
        self.assertEqual(t.lane_of({(AWS, None): S, (AWS, "cowrie"): F}), "back")

    def test_앞_묶음_먼저_오래된_순이고_합계_8건에서_자른다(self):
        rows = [pending_row(f"b{i}", 1000 + i) for i in range(5)]                          # 허니팟(뒤), 더 오래됨
        rows += [pending_row(f"f{i}", 10 * i, rule="R202", version="s1", overdue=i == 0) for i in range(5)]
        rows += [pending_row("same-b", 50, rule="R202", version="s1"), pending_row("same-a", 50, rule="R202", version="s1")]
        links = {**{f"b{i}": {(AWS, "cowrie"): S} for i in range(5)},
                 **{f"f{i}": {("data-node", None): S} for i in range(5)},
                 "same-a": {("data-node", None): S}, "same-b": {("data-node", None): S}}
        specs = {("s1", "R202"): file_spec("s1", "R202"), ("v3", "R001"): file_spec("v3", "R001")}
        q = t.queue_of(rows, links, specs, [])
        self.assertEqual({k: q[k] for k in ("total", "front", "back", "unconfirmed", "overdue")},
                         {"total": 12, "front": 7, "back": 5, "unconfirmed": 0, "overdue": 1})
        # 같은 묶음 안은 첫 시각 → 키 순. 앞 7건 뒤에 뒤 묶음 1건
        self.assertEqual([x["incident_key"] for x in q["items"]],
                         ["same-a", "same-b", "f4", "f3", "f2", "f1", "f0", "b4"])
        self.assertEqual([x["lane"] for x in q["items"]], ["front"] * 7 + ["back"])
        first = q["items"][0]
        self.assertEqual(set(first), {"incident_key", "rule_id", "rule_name", "severity", "actor_ip", "target", "first_ts",
                                      "pending_seconds", "target_seconds", "overdue", "lane", "devices", "device_state",
                                      "device_fallback"})
        self.assertEqual((first["first_ts"], first["pending_seconds"], first["device_state"]),
                         ((NOW - timedelta(minutes=50)).isoformat(), 3000.0, "rule_scope"))
        self.assertEqual([(d["label"], d["logs"]) for d in first["devices"]], [("데이터 노드", ["수집 관문", "원장 가져오기"])])
        json.dumps(q)

    def test_매핑에_없는_사건은_장비_미확인_앞_묶음이다(self):
        q = t.queue_of([pending_row("x", 5, rule="R999", version="zz"), pending_row("y", 9)], {"y": {(AWS, "cowrie"): S}},
                       {}, [], size=1)
        self.assertEqual((q["total"], q["front"], q["back"], q["unconfirmed"]), (2, 1, 1, 1))
        self.assertEqual([(x["incident_key"], x["device_state"]) for x in q["items"]], [("x", "unconfirmed")])
        self.assertEqual(t.queue_of([], {}, {}, []),
                         {"total": 0, "front": 0, "back": 0, "unconfirmed": 0, "overdue": 0, "items": []})


def run_row(version, minutes, honeypot):
    """DETECT_PATHS_SQL 한 행."""
    return {"rule_version": version, "last_at": NOW - timedelta(minutes=minutes), "honeypot": honeypot}


BLOCK_ROW = {"gateway_applied": 3, "gateway_failed": 0, "gateway_unverified": 1, "gateway_stale": 0,
             "gateway_checking": 1, "gateway_delayed": 0, "gateway_unrequested": 0, "gateway_removing": 0,
             "fw_applied": 1, "fw_failed": 2, "fw_unverified": 0, "fw_stale": 0, "fw_checking": 0, "fw_delayed": 0,
             "fw_unrequested": 0, "fw_removing": 0, "mismatch": 0}
BLOCK_OK = {**BLOCK_ROW, "fw_failed": 0}


class MonitorConn(FakeConn):
    """관제 이상이 읽는 표 · 열을 모두 읽을 수 있는 DB. CAN 은 선검사(MONITOR_READABLE_SQL) 답이다. 센서 신호 20분 전 ·
    내부 방화벽 보고 20분 전 · 내부 방화벽 불일치 2 · web-02 수신 끊김 · web-03 웹 로그 적재 없음 · web-01 · web-02 자원 지표 오래됨."""
    CAN = {"heartbeats": True, "metrics": True, "cards": True, "web": True, "parse": True}
    ROWS = [node_row("web-01"), node_row("web-02", reception="silent", seen=12), node_row("web-03")]

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        if sql == t.MONITOR_READABLE_SQL:
            return self.CAN
        if sql == t.NODE_SQL:
            return {k: v for k, v in node_row("web-01").items() if k in ("status", "last_seen_at", "last_loaded_at", "reception")}
        return {**BLOCK_OK, "fw_stale": 2} if sql == t.BLOCKS_SQL else None

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        if sql == t.HEARTBEATS_SQL:
            return [hb("uploader:i-01", seen=20), hb("block:gateway", kind="block_report", role="gateway"),
                    hb("block:fw", kind="block_report", role="fw", seen=20)]
        if sql == t.NODES_SQL:
            return self.ROWS
        if sql == t.DETECT_PATHS_SQL:
            return [run_row("v3", 2, True), *(run_row(v, 1, False) for v in t.BRIDGE_VERSIONS)]
        if sql == t.METRICS_SQL:
            return [BlocksTests.ROW | {"node_id": n, "ts": NOW - timedelta(minutes=m)}
                    for n, m in (("web-01", 12), ("web-02", 20), ("web-03", 1)) if n in args[0]]
        if sql == t.PARSE_SQL:
            receipt = json.dumps({"nginx": {"last_line_at": (NOW - timedelta(minutes=2)).isoformat()}})
            return [{"node_id": n, "logs": ["nginx"], "receipt": receipt, "nginx_at": at}
                    for n, at in (("web-01", NOW - timedelta(minutes=2)), ("web-03", None)) if n in args[0]]
        return []


class MonitorTests(unittest.TestCase):
    def fresh(self):
        return [hb("uploader:i-01", checked=1), hb("block:gateway", kind="block_report", role="gateway", checked=1),
                hb("block:fw", kind="block_report", role="fw", checked=1)]

    def points(self, heartbeats, blocks=None, available=True):
        reports = t.reports_of(heartbeats)
        return {p: t.point_counts(p, blocks, reports.get(p), NOW, available) for p in t.POINT_LABELS}

    def paths(self):
        return t.detect_paths([run_row("v3", 2, True)] + [run_row(v, 1, False) for v in t.BRIDGE_VERSIONS], NOW)

    def items(self, heartbeats=None, blocks=None, mismatch=0, node_rows=(), readable=True, paths=None, available=True,
              **kw):
        """monitor_view 처럼 생존 신호 행에서 센서 · 관문 기록 판정과 지점 보고를 넘긴다(kw 로 바꾼다)."""
        heartbeats = self.fresh() if heartbeats is None else heartbeats
        kw = {"as_of": NOW, "reports": t.reports_of(heartbeats), "sensor": t.sensor_signal(NOW, available, heartbeats),
              "gateway": t.uploader_signal(NOW, available, heartbeats, "gateway"), **kw}
        return t.monitor_items(t.checkers(NOW, available, heartbeats), self.points(heartbeats, blocks, available), mismatch,
                               list(node_rows), readable, self.paths() if paths is None else paths, available, **kw)

    def test_적재기_30분_집행기_10분_경계는_정각이_정상이다(self):
        def stopped(rows):
            return [(x["key"], x["note"], x["stopped"]) for x in t.checkers(NOW, True, rows)]
        self.assertEqual(stopped([hb("uploader:i-01", checked=30), hb("block:gateway", kind="block_report", role="gateway",
                                                                     checked=10)]),
                         [("loader", None, None), ("enforcer", None, None)])
        rows = [hb("uploader:i-01") | {"checked_at": NOW - timedelta(seconds=1801)},
                hb("block:gateway", kind="block_report", role="gateway") | {"checked_at": NOW - timedelta(seconds=601)}]
        self.assertEqual(stopped(rows), [("loader", "멈춤", "적재기 확인 중단 · 마지막 30분 전"),
                                         ("enforcer", "멈춤", "집행기 확인 중단 · 마지막 10분 전")])
        self.assertEqual(stopped([]), [("loader", "기록 없음", None), ("enforcer", "기록 없음", None)])
        self.assertEqual([x["note"] for x in t.checkers(NOW, False, [])], ["생존 신호 표를 읽을 수 없음"] * 2)

    def test_지점별_수는_카드_대응과_같은_정의다(self):
        report = hb("block:fw", kind="block_report", role="fw", checked=1)
        blocks = {**BLOCK_ROW, "fw_unverified": 2, "fw_stale": 1, "fw_checking": 1, "fw_delayed": 1, "gateway_unrequested": 3,
                  "gateway_removing": 1}
        # 생존 신호 표를 읽을 수 없으면 집행 보고를 모르니 적용 · 실패 · 불일치를 미확인에 합친다(옛 '적용 확인' 을 초록으로 두지 않는다)
        #   집행기가 멈춘 것이 아니라 모르는 것이라 unreadable 로 가른다(화면은 '집행기 멈춤' 이 아니라 '확인 불가').
        #   미요청 · 빠짐 확인 전(이슈 #77)은 합치지 않는다
        self.assertEqual(t.point_counts("gateway", blocks, None, NOW, False),
                         {"point": "gateway", "label": "허니팟 관문", "applied": 0, "failed": 0, "unverified": 4, "stale": 0,
                          "checking": 0, "delayed": 0, "unrequested": 3, "removing": 1,
                          "stalled": "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가", "unreadable": True})
        self.assertEqual(t.point_counts("fw", blocks, report, NOW, True),
                         {"point": "fw", "label": "내부 방화벽", "applied": 1, "failed": 2, "unverified": 2, "stale": 1,
                          "checking": 1, "delayed": 1, "unrequested": 0, "removing": 0, "stalled": None, "unreadable": False})
        # 집행기 확인이 없으면 적용 · 실패를 미확인에 합친다
        self.assertEqual(t.point_counts("gateway", blocks, None, NOW, True),
                         {"point": "gateway", "label": "허니팟 관문", "applied": 0, "failed": 0, "unverified": 4, "stale": 0,
                          "checking": 0, "delayed": 0, "unrequested": 3, "removing": 1, "stalled": "집행기 확인 기록 없음",
                          "unreadable": False})
        keys = ("applied", "failed", "unverified", "stale", "checking", "delayed", "unrequested", "removing", "stalled",
                "unreadable")
        for tid, point in (("aws-sensor", "gateway"), ("web-01", "fw")):
            for reports, available in (({}, True), ({"fw": report}, True), ({}, False)):
                with self.subTest(target=tid, reports=list(reports), available=available):
                    card = t.response_block(tid, blocks, 0, reports, NOW, available)
                    counts = t.point_counts(point, blocks, reports.get(point), NOW, available)
                    self.assertEqual({k: card[k] for k in keys}, {k: counts[k] for k in keys})
        self.assertEqual(t.response_block("console", blocks, 0, {}, NOW, False)["unreadable"], None)
        self.assertEqual(t.point_counts("fw", None, None, NOW, False)["applied"], 0)

    def test_이상이_없으면_빈_목록이다(self):
        self.assertEqual(self.items(blocks={**BLOCK_ROW, "fw_failed": 0}, node_rows=[node_row("web-01")]), [])

    def test_적용_실패와_관문_불일치(self):
        items = self.items(blocks=BLOCK_ROW, mismatch=2, node_rows=[node_row("web-01")])
        self.assertEqual(items, [
            {"key": "block_failed:fw", "level": "alert", "label": "내부 방화벽 적용 실패", "reason": None, "at": None, "count": 2},
            {"key": "gateway_mismatch", "level": "alert", "label": "관문 불일치", "reason": None, "at": None, "count": 2}])
        # 집행기가 멈추면 실패도 미확인에 합친다(멈춤 항목만 남는다)
        rows = [r for r in self.fresh() if r["source"] != "block:fw"]
        self.assertEqual([(x["key"], x["reason"]) for x in self.items(heartbeats=rows, blocks=BLOCK_ROW,
                                                                      node_rows=[node_row("web-01")])],
                         [("enforcer:fw", "집행기 확인 기록 없음")])

    def test_멈춤_항목의_순서와_글(self):
        rows = [hb("uploader:i-01") | {"checked_at": NOW - timedelta(minutes=45)},
                hb("block:gateway", kind="block_report", role="gateway", checked=12)]
        paths = t.detect_paths([run_row("v3", 20, True)], NOW)
        items = self.items(heartbeats=rows, blocks=BLOCK_ROW, mismatch=1, readable=False, paths=paths)
        self.assertEqual([(x["key"], x["level"], x["label"]) for x in items], [
            ("loader", "alert", "적재기"), ("enforcer:gateway", "alert", "허니팟 관문 집행기"),
            ("enforcer:fw", "alert", "내부 방화벽 집행기"), ("detect:honeypot", "alert", "허니팟 탐지(5분)"),
            ("detect:bridge", "alert", "노드 · 관제 탐지(1분)"), ("gateway_mismatch", "alert", "관문 불일치"),
            ("nodes", "unknown", "노드 수신")])
        self.assertEqual([x["reason"] for x in items], [
            "적재기 확인 중단 · 마지막 45분 전", "집행기 확인 중단 · 마지막 확인 12분 전", "집행기 확인 기록 없음",
            "마지막 실행 20분 전", "24시간 안 실행 기록 없음", None, "노드 표를 읽을 수 없음"])
        self.assertEqual((items[0]["at"], items[3]["at"]),
                         ((NOW - timedelta(minutes=45)).isoformat(), (NOW - timedelta(minutes=20)).isoformat()))

    def test_생존_신호_표를_읽을_수_없으면_적재기_집행기는_판정하지_않는다(self):
        # 지점 결과도 믿지 않고 미확인으로 합쳐(point_counts) 적용 실패 항목이 없다. 센서 · 지점 보고도 판정하지 않는다
        items = self.items(heartbeats=[], blocks=BLOCK_ROW, available=False, node_rows=[node_row("web-01")])
        self.assertEqual([(x["key"], x["level"], x["reason"]) for x in items],
                         [("heartbeats", "unknown", "생존 신호 표를 읽을 수 없음")])
        self.assertEqual({k: v["stalled"] for k, v in self.points([], BLOCK_ROW, False).items()},
                         {p: "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가" for p in t.POINT_LABELS})
        # 표는 읽는데 적재기 행이 없으면 모름이다
        rows = [r for r in self.fresh() if r["kind"] != "uploader"]
        self.assertEqual([(x["key"], x["level"], x["reason"]) for x in self.items(heartbeats=rows,
                                                                                  node_rows=[node_row("web-01")])],
                         [("loader", "unknown", "적재기 확인 기록 없음")])

    def test_활성_노드가_한_대라도_끊기면_노드_수신_이상이다(self):
        silent, normal = node_row("web-01", reception="silent", seen=11), node_row("web-02", reception="normal")
        waiting = node_row("web-03", status="pending", reception="waiting", seen=None)
        revoked = node_row("probe-01", status="revoked", reception="revoked")
        many = [node_row(f"web-0{n}", reception="silent", seen=12) for n in (6, 2, 5, 3, 4)]    # node_id 순으로 적는다
        # 확인한 사실만: 한 대면 그 노드와 마지막 수신, 여러 대면 대수로 묶는다(상세는 /nodes)
        never = node_row("web-07", reception="silent", seen=None)
        for rows, want in [([silent, waiting, revoked], [("nodes_silent", "web-01 수신 끊김 · 마지막 수신 11분 전", 1)]),
                           ([silent, node_row("web-02", reception="silent")], [("nodes_silent", "노드 2대 수신 끊김", 2)]),
                           ([normal, silent, waiting], [("nodes_silent", "web-01 수신 끊김 · 마지막 수신 11분 전", 1)]),
                           ([normal, never], [("nodes_silent", "web-07 수신 끊김 · 수신 기록 없음", 1)]),
                           ([node_row("web-01"), *many[:3]], [("nodes_silent", "노드 3대 수신 끊김", 3)]),
                           ([node_row("web-01"), *many], [("nodes_silent", "노드 5대 수신 끊김", 5)]),
                           ([normal], []), ([waiting, revoked], []), ([], [])]:
            with self.subTest(rows=[r["node_id"] for r in rows]):
                self.assertEqual([(x["key"], x["reason"], x["count"]) for x in self.items(blocks=BLOCK_OK, node_rows=rows)],
                                 want)

    def test_등록_노드_열을_읽을_수_없으면_모름이다(self):
        silent = node_row("web-01", reception="silent", seen=11)
        for rows, want in [([silent], [("nodes_silent", "alert", "web-01 수신 끊김 · 마지막 수신 11분 전"),
                                       ("nodes", "unknown", "등록 노드 열을 읽을 수 없음")]),
                           ([node_row("web-01")], [("nodes", "unknown", "등록 노드 열을 읽을 수 없음")])]:
            items = self.items(blocks=BLOCK_OK, node_rows=rows, cards_readable=False)
            self.assertEqual([(x["key"], x["level"], x["reason"]) for x in items], want)
        # nodes 를 읽을 수 없으면 한 항목이다
        items = self.items(blocks=BLOCK_OK, readable=False, cards_readable=False, web_expected=True)
        self.assertEqual([(x["key"], x["reason"]) for x in items], [("nodes", "노드 표를 읽을 수 없음")])

    def test_web_01_등록_기록이_없으면_모름이다(self):
        # 고정 web-01 카드가 '노드 등록 기록 없음' 이면 띠에도 한 항목이다(카드 ⇒ 띠). 등록 노드 열 모름과 같으면 한 항목에 잇는다
        rows = [node_row("web-02")]
        for kw, want in [({}, "web-01 등록 기록 없음"),
                         ({"cards_readable": False}, "등록 노드 열을 읽을 수 없음 · web-01 등록 기록 없음")]:
            with self.subTest(kw=kw):
                items = self.items(blocks=BLOCK_OK, node_rows=rows, web_expected=True, **kw)
                self.assertEqual([(x["key"], x["level"], x["label"], x["reason"]) for x in items],
                                 [("nodes", "unknown", "노드 수신", want)])
        self.assertEqual(t.node_collection(NOW, None, {})["reason"], "노드 등록 기록 없음")
        # web-01 행이 있으면(등록 대기 · 폐기 포함) 싣지 않는다
        for row in (node_row("web-01"), node_row("web-01", status="revoked", reception="revoked")):
            self.assertEqual(self.items(blocks=BLOCK_OK, node_rows=[row], web_expected=True), [])

    def test_센서_수신은_카드와_같은_판정이다(self):
        web = [node_row("web-01")]
        rows = [hb("uploader:i-01", seen=20), *self.fresh()[1:]]
        card = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertEqual(card["state"], "no_signal")
        self.assertEqual(self.items(heartbeats=rows, blocks=BLOCK_OK, node_rows=web), [
            {"key": "sensor", "level": "alert", "label": "허니팟 센서 수신", "reason": card["reason"],
             "at": (NOW - timedelta(minutes=20)).isoformat(), "count": None}])
        # 관문 업로더 행이 있으면 까닭 끝의 관문 기록 신호 시각까지 카드와 같은 글이다
        rows = [hb("uploader:i-01", seen=20), hb("uploader:i-0g", role="gateway", seen=4), *self.fresh()[1:]]
        card = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertTrue(card["reason"].endswith(" · 관문 기록 신호 4분 전"))
        self.assertEqual([(x["key"], x["reason"]) for x in self.items(heartbeats=rows, blocks=BLOCK_OK, node_rows=web)],
                         [("sensor", card["reason"])])
        # 센서 행이 없으면 모름이다(적재기는 관문 업로더 행으로 확인 중이다)
        rows = [hb("uploader:i-0g", role="gateway"), *self.fresh()[1:]]
        card = t.sensor_collection(NOW, True, rows, LOGS_ACTIVE)
        self.assertEqual((card["state"], card["reason"]), ("unknown", "생존 신호 미기록 · 관문 기록 신호 3분 전"))
        self.assertEqual([(x["key"], x["level"], x["reason"]) for x in self.items(heartbeats=rows, blocks=BLOCK_OK,
                                                                                  node_rows=web)],
                         [("sensor", "unknown", card["reason"])])
        # 표를 읽을 수 없거나 적재기가 멈추면(모든 업로더 행 확인 30분 넘음 · 기록 없음) 그 항목 하나다
        self.assertEqual([x["key"] for x in self.items(heartbeats=[], available=False, blocks=BLOCK_OK, node_rows=web)],
                         ["heartbeats"])
        rows = [hb("uploader:i-01", seen=40, checked=35), hb("uploader:i-0g", role="gateway", seen=40, checked=35),
                *self.fresh()[1:]]
        self.assertEqual([x["key"] for x in self.items(heartbeats=rows, blocks=BLOCK_OK, node_rows=web)], ["loader"])
        self.assertEqual([x["key"] for x in self.items(heartbeats=self.fresh()[1:], blocks=BLOCK_OK, node_rows=web)],
                         ["loader"])

    def test_관문_기록_수신(self):
        web = [node_row("web-01")]
        gw = hb("uploader:i-0g", role="gateway", seen=20, checked=1)
        items = self.items(heartbeats=[*self.fresh(), gw], blocks=BLOCK_OK, node_rows=web)
        self.assertEqual([(x["key"], x["level"], x["label"], x["reason"], x["at"]) for x in items], [
            ("gateway_uploader", "alert", "허니팟 관문 기록 수신",
             "관문 기록 신호 20분 전 · 적재기 확인 1분 전 · 확인 때 이미 15분 넘게 새 신호 없음",
             (NOW - timedelta(minutes=20)).isoformat())])
        # 적재기가 더는 확인하지 않는 관문 행뿐이면(구성에서 뺀 호스트의 남은 행) 싣지 않는다. 적재기는 센서 행으로 확인 중이다.
        #   관문 업로더가 없는 구성도 싣지 않는다
        dead = gw | {"checked_at": NOW - timedelta(days=3)}
        self.assertEqual(self.items(heartbeats=[*self.fresh(), dead], blocks=BLOCK_OK, node_rows=web), [])
        self.assertEqual(self.items(heartbeats=[*self.fresh(), gw | {"checked_at": NOW - timedelta(minutes=31)}],
                                    blocks=BLOCK_OK, node_rows=web), [])
        self.assertEqual(self.items(heartbeats=[*self.fresh(), gw | {"seen_at": NOW - timedelta(minutes=16)}],
                                    blocks=BLOCK_OK, node_rows=web), [])
        # 센서와 함께 끊기면 둘 다다(센서 먼저, 탐지 경로 앞)
        rows = [hb("uploader:i-01", seen=20), gw, *self.fresh()[1:]]
        paths = t.detect_paths([], NOW)
        self.assertEqual([x["key"] for x in self.items(heartbeats=rows, blocks=BLOCK_OK, node_rows=web, paths=paths)],
                         ["sensor", "gateway_uploader", "detect:honeypot", "detect:bridge"])

    def test_지점_불일치는_지점별이고_관문은_관문_불일치가_먼저다(self):
        web = [node_row("web-01")]
        blocks = {**BLOCK_OK, "gateway_stale": 1, "fw_stale": 2}
        self.assertEqual(self.items(blocks=blocks, node_rows=web), [
            {"key": "point_stale:gateway", "level": "alert", "label": "허니팟 관문 불일치", "reason": None, "at": None, "count": 1},
            {"key": "point_stale:fw", "level": "alert", "label": "내부 방화벽 불일치", "reason": None, "at": None, "count": 2}])
        # 관문 불일치가 있으면 관문 지점 불일치는 그 항목 하나다. 순서는 적용 실패 → 지점 불일치 → 관문 불일치
        items = self.items(blocks={**blocks, "fw_failed": 1}, mismatch=1, node_rows=web)
        self.assertEqual([(x["key"], x["count"]) for x in items],
                         [("block_failed:fw", 1), ("point_stale:fw", 2), ("gateway_mismatch", 1)])
        # 집행기가 멈춘 지점은 불일치도 미확인에 합친다(멈춤 항목만)
        rows = [r for r in self.fresh() if r["source"] != "block:fw"]
        self.assertEqual([x["key"] for x in self.items(heartbeats=rows, blocks=blocks, node_rows=web)],
                         ["enforcer:fw", "point_stale:gateway"])

    def test_지점_보고가_오래됐거나_문제가_있으면_이상이다(self):
        web = [node_row("web-01")]
        base = [r for r in self.fresh() if r["source"] != "block:fw"]

        def got(report):
            return [(x["key"], x["level"], x["label"], x["reason"], x["at"])
                    for x in self.items(heartbeats=[*base, report], blocks=BLOCK_OK, node_rows=web)]
        fw = hb("block:fw", kind="block_report", role="fw", seen=16)
        self.assertEqual(got(fw), [("report:fw", "alert", "내부 방화벽 보고", "마지막 보고 16분 전",
                                    (NOW - timedelta(minutes=16)).isoformat())])
        self.assertEqual(got(fw | {"seen_at": NOW - timedelta(minutes=15)}), [])
        # 읽기 문제는 5분 넘게 이어질 때만(못 읽은 회차는 옛 seen_at 이 남는다). 한두 회차 일시 오류는 넘긴다
        self.assertEqual(got(fw | {"seen_at": NOW - timedelta(minutes=1), "problem": "보고 서명이 틀림"}), [])
        self.assertEqual(got(fw | {"seen_at": NOW - timedelta(minutes=5), "problem": "RequestTimeout"}), [])
        self.assertEqual(got(fw | {"seen_at": NOW - timedelta(minutes=6), "problem": "보고 서명이 틀림"}),
                         [("report:fw", "alert", "내부 방화벽 보고", "마지막 보고 6분 전 · 보고 서명이 틀림",
                           (NOW - timedelta(minutes=6)).isoformat())])
        self.assertEqual(got(fw | {"seen_at": None, "problem": "보고 파일 없음"}),
                         [("report:fw", "alert", "내부 방화벽 보고", "받은 보고 없음 · 보고 파일 없음", None)])
        self.assertEqual(got(fw | {"problem": "보고 파일 없음"})[0][3], "마지막 보고 16분 전 · 보고 파일 없음")
        # 집행기가 멈춘 지점은 집행기 항목만이다
        self.assertEqual([x[0] for x in got(fw | {"checked_at": NOW - timedelta(minutes=11)})], ["enforcer:fw"])
        # 보고 행이 없으면 모름이다(집행기 판정과 따로 넘겼을 때)
        self.assertEqual([(x["key"], x["level"], x["reason"]) for x in self.items(blocks=BLOCK_OK, node_rows=web, reports={})],
                         [("report:gateway", "unknown", "보고 기록 없음"), ("report:fw", "unknown", "보고 기록 없음")])

    def test_카드_보고_문제는_띠_지점_보고와_같은_판정이다(self):
        # 이슈 #84 결정 1: 접힌 줄 '보고 문제' 배지(response.report_issue)는 띠 report:<지점> 의 reason 과 같다(15분 오래됨 · 읽기 문제
        #   5분 이어짐). 집행기가 멈추면 둘 다 없다(띠는 enforcer:<지점>)
        web = [node_row("web-01")]
        base = [r for r in self.fresh() if r["source"] != "block:fw"]
        fw = hb("block:fw", kind="block_report", role="fw", seen=16)
        for name, report, want in [
                ("16분 전", fw, "마지막 보고 16분 전"),
                ("15분 정각", fw | {"seen_at": NOW - timedelta(minutes=15)}, None),
                ("문제 4분", fw | {"seen_at": NOW - timedelta(minutes=4), "problem": "RequestTimeout"}, None),
                ("문제 6분", fw | {"seen_at": NOW - timedelta(minutes=6), "problem": "보고 서명이 틀림"},
                 "마지막 보고 6분 전 · 보고 서명이 틀림"),
                ("받은 보고 없음", fw | {"seen_at": None, "problem": "보고 파일 없음"}, "받은 보고 없음 · 보고 파일 없음"),
                ("집행기 멈춤", fw | {"checked_at": NOW - timedelta(minutes=11)}, None)]:
            with self.subTest(name):
                rows = [*base, report]
                band = {x["key"]: x["reason"] for x in self.items(heartbeats=rows, blocks=BLOCK_OK, node_rows=web)}
                card = t.response_block("web-01", BLOCK_OK, 0, t.reports_of(rows), NOW, True)
                self.assertEqual((card["report_issue"], band.get("report:fw")), (want, want))
        self.assertIsNone(t.response_block("web-01", BLOCK_OK, 0, t.reports_of(base + [fw]), NOW, False)["report_issue"])
        self.assertIsNone(t.response_block("console", BLOCK_OK, 0, t.reports_of(base + [fw]), NOW, True)["report_issue"])

    def test_확인_중과_확인_지연은_미확인을_나누고_집행기_5분_기준과_같다(self):
        # 이슈 #84 결정 6: 확인 전(pending · 기록 없음)이 정상 반영 시간(5분) 안이면 확인 중, 넘었거나 지점 불일치면 확인 지연.
        #   5분은 집행기 point_state '5분 넘게 반영되지 않음'(enforcer STALE)과 같은 기준이다. 시각은 enforcement.<지점>.since,
        #   기록이 없거나 요청 지점 상태(집행기 POINT_STATES, 남은 removing 은 아님)가 아니거나 시각 글자가 아니면 요청 시각(created_at)이고,
        #   캐스트 오류가 나지 않게 먼저 가른다
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "enforcer" / "block_enforcer.py").read_text())

        def const(name):
            return next(n.value for n in tree.body
                        if isinstance(n, ast.Assign) and any(getattr(x, "id", None) == name for x in n.targets))
        self.assertEqual(eval(ast.unparse(const("STALE")), {"timedelta": timedelta}).total_seconds(), t.APPLY_WAIT)   # noqa: S307
        self.assertEqual(ast.literal_eval(const("POINT_STATES")), t.POINT_STATES)
        for p in ("gateway", "fw"):
            with self.subTest(point=p):
                since = f"enforcement -> '{p}' ->> 'since'"
                self.assertIn(f"coalesce(CASE WHEN enforcement -> '{p}' ->> 'state' IN ('pending', 'confirmed', 'failed', 'stale')"
                              f" AND pg_input_is_valid({since}, 'timestamptz') THEN ({since})::timestamptz END, created_at)",
                              t.BLOCKS_SQL)
                self.assertIn(f"AS {p}_checking", t.BLOCKS_SQL)
                self.assertIn(f"AS {p}_delayed", t.BLOCKS_SQL)
                self.assertIn(f"coalesce(enforcement -> '{p}' ->> 'state', '') NOT IN ('confirmed', 'failed', 'stale')",
                              t.BLOCKS_SQL)
        self.assertIn(f"> $1::timestamptz - make_interval(secs => {t.APPLY_WAIT}), false)", t.BLOCKS_SQL)

    def test_5분_넘은_확인_전은_지점별_확인_지연이고_그_지점_보고가_있으면_뺀다(self):
        # 이슈 #84 결정 6 · 카드 ⇒ 띠: 카드 '적용 확인 지연'(delayed) 가운데 지점 불일치(point_stale)를 뺀 수다. 집행기가 보고를 판정하지
        #   못한 회차(보류)에는 직전 대기와 그 시각이 남는다. 그 지점 보고 항목이 있으면 같은 현상이라 싣지 않고, 집행기가 멈춘 지점은 0 이다
        web = [node_row("web-01")]
        blocks = {**BLOCK_OK, "gateway_unverified": 3, "gateway_stale": 1, "gateway_checking": 0, "gateway_delayed": 3,
                  "fw_unverified": 1, "fw_checking": 0, "fw_delayed": 1}
        self.assertEqual([(x["key"], x["level"], x["label"], x["reason"], x["count"]) for x in self.items(blocks=blocks, node_rows=web)], [
            ("point_stale:gateway", "alert", "허니팟 관문 불일치", None, 1),
            ("point_delayed:gateway", "alert", "허니팟 관문 적용 확인 지연", None, 2),
            ("point_delayed:fw", "alert", "내부 방화벽 적용 확인 지연", None, 1)])
        # 확인 중(5분 안)만이면 없다
        self.assertEqual(self.items(blocks={**BLOCK_OK, "fw_unverified": 2, "fw_checking": 2}, node_rows=web), [])
        # 그 지점 보고 항목이 있으면 그 항목 하나다(다른 지점은 그대로)
        rows = [*(r for r in self.fresh() if r["source"] != "block:fw"), hb("block:fw", kind="block_report", role="fw", seen=16)]
        self.assertEqual([x["key"] for x in self.items(heartbeats=rows, blocks=blocks, node_rows=web)],
                         ["point_stale:gateway", "report:fw", "point_delayed:gateway"])
        # 집행기가 멈춘 지점은 나누지 않아(point_counts) 집행기 항목만이다
        rows = [r for r in self.fresh() if r["source"] != "block:fw"]
        self.assertEqual([x["key"] for x in self.items(heartbeats=rows, blocks=blocks, node_rows=web)],
                         ["enforcer:fw", "point_stale:gateway", "point_delayed:gateway"])

    def test_웹_로그_적재와_자원_지표는_보호_대상별이다(self):
        rows = [node_row("web-01"), node_row("web-02", reception="silent", seen=12), node_row("web-03")]
        devices = [{"id": "web-01", "label": "web-01", "gap": None, "metrics_at": NOW - timedelta(minutes=12)},
                   {"id": "web-02", "label": "web02.lab", "gap": NOW - timedelta(minutes=3),
                    "metrics_at": NOW - timedelta(minutes=20)},
                   {"id": "web-03", "label": "web-03", "gap": NOW - timedelta(minutes=1), "metrics_at": None}]
        # 수신이 끊긴 web-02 는 자원 지표를 싣지 않는다(웹 로그 적재는 다른 현상이라 싣는다)
        self.assertEqual(self.items(blocks=BLOCK_OK, node_rows=rows, devices=devices), [
            {"key": "nodes_silent", "level": "alert", "label": "노드 수신",
             "reason": "web-02 수신 끊김 · 마지막 수신 12분 전", "at": (NOW - timedelta(minutes=12)).isoformat(), "count": 1},
            {"key": "parse:web-02", "level": "alert", "label": "web02.lab 웹 로그 적재",
             "reason": "로그는 도착하는데 적재되지 않음 · 마지막 도착 3분 전", "at": (NOW - timedelta(minutes=3)).isoformat(),
             "count": None},
            {"key": "parse:web-03", "level": "alert", "label": "web-03 웹 로그 적재",
             "reason": "로그는 도착하는데 적재되지 않음 · 마지막 도착 1분 전", "at": (NOW - timedelta(minutes=1)).isoformat(),
             "count": None},
            {"key": "metrics:web-01", "level": "alert", "label": "web-01 자원 지표", "reason": "마지막 지표 12분 전",
             "at": (NOW - timedelta(minutes=12)).isoformat(), "count": None}])

    def test_보호_대상별_판정은_카드와_같다(self):
        cards = [{"id": "web-02", "label": "web02.lab", "sensor": "web-02", "node": None},
                 {"id": "web-03", "label": "web-03", "sensor": "web-03", "node": None}]
        row = BlocksTests.ROW
        metrics = {"web-01": row | {"ts": NOW - timedelta(seconds=601)}, "web-02": row | {"ts": NOW - timedelta(seconds=600)}}
        gap = NOW - timedelta(minutes=3)
        got = t.device_checks(NOW, cards, {"web-03": gap}, metrics, True)
        self.assertEqual(got, [{"id": "web-01", "label": "web-01", "gap": None, "metrics_at": NOW - timedelta(seconds=601)},
                               {"id": "web-02", "label": "web02.lab", "gap": None, "metrics_at": None},
                               {"id": "web-03", "label": "web-03", "gap": gap, "metrics_at": None}])
        for device, registered in zip(got, (False, True, True)):
            system = t.system_block(device["id"], True, metrics.get(device["id"]), NOW, registered)
            self.assertEqual(device["metrics_at"] is not None, system["state"] == "stale")
        # 지표를 읽을 수 없으면(권한 없음) 오래됨이 아니다
        self.assertEqual([d["metrics_at"] for d in t.device_checks(NOW, cards, {}, metrics, False)], [None] * 3)
        # 폐기 · 등록 대기(재등록 중)인 장비의 옛 지표는 싣지 않는다. 수신이 끊긴 활성 노드는 nodes_silent 가 겹침을 뺀다
        old = row | {"ts": NOW - timedelta(hours=2)}
        pending = [{**cards[0], "node": node_row("web-02", status="pending", reception="waiting", seen=None)}]
        for web, want in [(node_row("web-01", status="revoked", reception="revoked"), None),
                          (node_row("web-01", status="pending", reception="waiting", seen=None), None),
                          (node_row("web-01", reception="silent", seen=30), old["ts"]), (None, old["ts"])]:
            with self.subTest(web=web and web["reception"]):
                got = t.device_checks(NOW, pending, {}, {"web-01": old, "web-02": old}, True, web)
                self.assertEqual([d["metrics_at"] for d in got], [want, None])

    def test_탐지_경로(self):
        # 허니팟은 경로 최댓값: 옛 버전(v1)이 멈춰도 v3 가 돌면 정상이다
        rows = [run_row("c1", 1, False), run_row("v1", 600, True), run_row("v3", 2, True), run_row("w2", 16, False),
                *(run_row(v, 1, False) for v in ("a1", "i2", "s1", "sg1"))]
        honeypot, bridge = t.detect_paths(rows, NOW)
        self.assertEqual({k: honeypot[k] for k in ("key", "label", "last_at", "stale", "reason")},
                         {"key": "honeypot", "label": "허니팟 탐지(5분)", "last_at": (NOW - timedelta(minutes=2)).isoformat(),
                          "stale": False, "reason": None})
        self.assertEqual([(v["rule_version"], v["stale"]) for v in honeypot["versions"]], [("v1", True), ("v3", False)])
        # 1분 다리는 버전별: w2 가 15분 넘게 멈췄다
        self.assertEqual((bridge["stale"], bridge["reason"], bridge["last_at"]),
                         (True, "w2 마지막 실행 16분 전", (NOW - timedelta(minutes=1)).isoformat()))
        self.assertEqual([(v["rule_version"], v["stale"]) for v in bridge["versions"]],
                         [("a1", False), ("c1", False), ("i2", False), ("s1", False), ("sg1", False), ("w2", True)])
        # 15분 경계: 정각은 정상
        edge = [{"rule_version": "v3", "last_at": NOW - timedelta(seconds=900), "honeypot": True},
                {"rule_version": "c1", "last_at": NOW - timedelta(seconds=901), "honeypot": False},
                *(run_row(v, 1, False) for v in t.BRIDGE_VERSIONS if v != "c1")]
        self.assertEqual([(p["stale"], p["reason"]) for p in t.detect_paths(edge, NOW)],
                         [(False, None), (True, "c1 마지막 실행 15분 전")])
        # 24시간 안 행이 없으면 멈춤이다
        self.assertEqual([(p["stale"], p["last_at"], p["reason"]) for p in t.detect_paths([], NOW)],
                         [(True, None, "24시간 안 실행 기록 없음")] * 2)

    def test_데이터_노드_멈춤_구조_값(self):
        started = NOW - timedelta(minutes=4)
        c = t.data_collection(NOW, started, True, self.fresh())
        self.assertEqual((c["state"], c["reason"], c["stopped"]), ("ok", "마지막 탐지 실행 4분 전", []))
        # 내부 방화벽 보고(block:fw)만 없으면 집행기 멈춤이다(관제 이상 enforcer:fw 와 같은 판정). 문장 · state 는 그대로다
        rows = [r for r in self.fresh() if r["source"] != "block:fw"]
        c = t.data_collection(NOW, started, True, rows)
        self.assertEqual((c["state"], c["reason"], c["stopped"]), ("ok", "마지막 탐지 실행 4분 전", ["enforcer"]))
        self.assertIn("enforcer:fw", [x["key"] for x in self.items(heartbeats=rows, node_rows=[node_row("web-01")])])
        # 적재기 확인 중단 · 탐지 실행 없음이어도 state 는 새로 만들지 않는다
        rows = [hb("uploader:i-01", checked=31), *self.fresh()[1:]]
        c = t.data_collection(NOW, NOW - timedelta(minutes=20), True, rows)
        self.assertEqual((c["state"], c["reason"], c["stopped"]),
                         ("no_signal", "마지막 탐지 실행 20분 전 · 15분 넘게 실행 없음 · 적재기 확인 중단 · 마지막 31분 전",
                          ["loader"]))
        rows = [hb("uploader:i-01", checked=31), hb("block:gateway", kind="block_report", role="gateway", checked=11)]
        self.assertEqual(t.data_collection(NOW, started, True, rows)["stopped"], ["loader", "enforcer"])
        self.assertEqual(t.data_collection(NOW, None, False, [])["stopped"], [])

    def test_데이터_노드는_탐지_경로가_하나라도_멈추면_주의다(self):
        started = NOW - timedelta(minutes=1)
        paths = t.detect_paths([run_row("v3", 2, True)] + [run_row(v, 1, False) for v in t.BRIDGE_VERSIONS if v != "c1"], NOW)
        c = t.data_collection(NOW, started, True, self.fresh(), paths)
        self.assertEqual((c["state"], c["reason"], c["stopped"]),
                         ("ok", "마지막 탐지 실행 1분 전 · 노드 · 관제 탐지(1분) 멈춤 · c1 24시간 넘게 실행 없음", ["detect"]))
        self.assertIn("detect:bridge",
                      [x["key"] for x in self.items(paths=paths, blocks=BLOCK_OK, node_rows=[node_row("web-01")])])
        # 1분 다리 전체가 멈추고 허니팟만 돌아도 주의다(전체 최신 실행만 보면 정상이었다)
        c = t.data_collection(NOW, started, True, self.fresh(), t.detect_paths([run_row("v3", 1, True)], NOW))
        self.assertEqual((c["state"], c["reason"], c["stopped"]),
                         ("ok", "마지막 탐지 실행 1분 전 · 노드 · 관제 탐지(1분) 멈춤 · 24시간 안 실행 기록 없음", ["detect"]))
        # 두 경로가 돌면 그대로다. 마지막 실행이 15분 넘었으면 수신 없음이 말하므로 붙이지 않는다
        c = t.data_collection(NOW, started, True, self.fresh(), self.paths())
        self.assertEqual((c["state"], c["reason"], c["stopped"]), ("ok", "마지막 탐지 실행 1분 전", []))
        c = t.data_collection(NOW, NOW - timedelta(minutes=20), True, self.fresh(), t.detect_paths([], NOW))
        self.assertEqual((c["state"], c["reason"], c["stopped"]),
                         ("no_signal", "마지막 탐지 실행 20분 전 · 15분 넘게 실행 없음", []))
        # 적재기 멈춤과 함께면 탐지 까닭이 먼저다
        rows = [hb("uploader:i-01", checked=31), *self.fresh()[1:]]
        c = t.data_collection(NOW, started, True, rows, t.detect_paths([run_row("v3", 1, True)], NOW))
        self.assertEqual((c["reason"], c["stopped"]), (
            "마지막 탐지 실행 1분 전 · 노드 · 관제 탐지(1분) 멈춤 · 24시간 안 실행 기록 없음 · 적재기 확인 중단 · 마지막 31분 전",
            ["loader", "detect"]))


class BridgeVersionTests(unittest.TestCase):
    """1분 다리가 돌려야 할 버전 대조(이슈 #82). 탐지 경로 창은 24시간이라 25시간 전 실행은 행이 없다."""

    def fresh(self, but=()):
        return [run_row("v3", 2, True)] + [run_row(v, 1, False) for v in t.BRIDGE_VERSIONS if v not in but]

    def test_다리_버전_목록은_수집_설정_RULESETS_와_같다(self):
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "collector" / "pull_loki.py").read_text())
        files = next(ast.literal_eval(n.value) for n in tree.body
                     if isinstance(n, ast.Assign) and any(getattr(x, "id", None) == "RULESETS" for x in n.targets))
        self.assertEqual(t.BRIDGE_VERSIONS,
                         tuple(json.loads((root / "detector" / name).read_text())["rule_version"] for name in files))

    def test_기대_버전_하나가_23시간_25시간_멈춰도_멈춤이다(self):
        _, bridge = t.detect_paths(self.fresh(but=("c1",)) + [run_row("c1", 23 * 60, False)], NOW)
        self.assertEqual((bridge["stale"], bridge["reason"], bridge["last_at"]),
                         (True, "c1 마지막 실행 23시간 전", (NOW - timedelta(minutes=1)).isoformat()))
        # 25시간 전이면 창 밖이라 행이 없다. 기대 버전이라 기록 없음으로 남는다(옛 판정은 경고가 사라졌다)
        _, bridge = t.detect_paths(self.fresh(but=("c1",)), NOW)
        self.assertEqual((bridge["stale"], bridge["reason"]), (True, "c1 24시간 넘게 실행 없음"))
        self.assertEqual([(v["rule_version"], v["last_at"], v["stale"]) for v in bridge["versions"]][:2],
                         [("a1", (NOW - timedelta(minutes=1)).isoformat(), False), ("c1", None, True)])
        self.assertEqual([v["rule_version"] for v in bridge["versions"]], sorted(t.BRIDGE_VERSIONS))
        # 멈춘 버전과 기록 없는 버전이 함께면 두 글을 잇는다
        _, bridge = t.detect_paths(self.fresh(but=("c1", "w2")) + [run_row("w2", 20, False)], NOW)
        self.assertEqual(bridge["reason"], "w2 마지막 실행 20분 전 · c1 24시간 넘게 실행 없음")

    def test_기대_밖_옛_버전의_기록은_보지_않는다(self):
        # 교체된 w1(1시간 전까지) · 떼어 낸 n1 · 정의 없는 zz 는 멈춰 있어도 경보하지 않는다
        rows = self.fresh() + [run_row("w1", 61, False), run_row("n1", 23 * 60, False), run_row("zz", 30, False)]
        _, bridge = t.detect_paths(rows, NOW)
        self.assertEqual((bridge["stale"], bridge["reason"]), (False, None))
        self.assertEqual([v["rule_version"] for v in bridge["versions"]], sorted(t.BRIDGE_VERSIONS))
        # 옛 버전 기록만 있으면 기대 버전이 모두 기록 없음이다
        _, bridge = t.detect_paths([run_row("w1", 61, False)], NOW)
        self.assertEqual((bridge["reason"], bridge["last_at"]), ("a1 · c1 · i2 · s1 · sg1 · w2 24시간 넘게 실행 없음", None))

    def test_새_기대_버전의_기록이_없으면_멈춤이다(self):
        rows = self.fresh()
        with patch.object(t, "BRIDGE_VERSIONS", t.BRIDGE_VERSIONS + ("x1",)):
            _, bridge = t.detect_paths(rows, NOW)
        self.assertEqual((bridge["stale"], bridge["reason"]), (True, "x1 24시간 넘게 실행 없음"))


class ParseGapTests(unittest.TestCase):
    """웹 로그 적재 없음(parse_gap) · 카드 경고 표지(이슈 #82)."""

    def node(self, logs=("nginx", "auth", "metrics"), nginx=2, auth=None):
        receipt = {job: {"lines": 9, "malformed": 9, "last_line_at": (NOW - timedelta(minutes=m)).isoformat()}
                   for job, m in (("nginx", nginx), ("auth", auth)) if m is not None}
        return {"node_id": "web-02", "logs": list(logs), "receipt": json.dumps(receipt)}

    def test_도착한_웹_로그가_적재되지_않으면_그_도착_시각이다(self):
        at = NOW - timedelta(minutes=2)
        self.assertEqual(t.parse_gap(NOW, self.node(), None), at)
        self.assertEqual(t.parse_gap(NOW, self.node(), at - timedelta(seconds=601)), at)
        # 도착보다 10분 안(정각 포함) · 뒤의 이벤트가 있으면 적재된 것이다
        self.assertIsNone(t.parse_gap(NOW, self.node(), at - timedelta(seconds=600)))
        self.assertIsNone(t.parse_gap(NOW, self.node(), at))
        # 1시간 경계(포함). jsonb 가 사전으로 와도 같다
        self.assertEqual(t.parse_gap(NOW, self.node(nginx=60), None), NOW - timedelta(minutes=60))
        self.assertEqual(t.parse_gap(NOW, self.node() | {"receipt": json.loads(self.node()["receipt"])}, None), at)

    def test_선언_밖_도착_없음_오래된_도착_모양이_틀린_기록은_경고가_아니다(self):
        self.assertIsNone(t.parse_gap(NOW, self.node(logs=("auth", "metrics")), None))     # nginx 를 선언하지 않음
        self.assertIsNone(t.parse_gap(NOW, self.node(nginx=None, auth=1), None))            # 조용한 서버. auth 는 보지 않는다
        self.assertIsNone(t.parse_gap(NOW, self.node(nginx=61), None))                      # 1시간 넘게 도착 없음
        self.assertIsNone(t.parse_gap(NOW, None, None))
        self.assertIsNone(t.parse_gap(NOW, {"node_id": "web-02", "logs": None, "receipt": "{}"}, None))
        for receipt in (None, "{", "[]", json.dumps({"nginx": {"last_line_at": "2026-09-28T02:59:00"}}),
                        json.dumps({"nginx": {"last_line_at": 5}}), json.dumps({"nginx": "어제"})):
            with self.subTest(receipt=receipt):
                self.assertIsNone(t.parse_gap(NOW, {"node_id": "web-02", "logs": ["nginx"], "receipt": receipt}, None))

    def test_카드는_state_를_두고_경고_표지를_단다(self):
        gap = NOW - timedelta(minutes=2)
        sources = [("web-02", "web02.lab 로그")]
        c = t.node_collection(NOW, node_row("web-02"), {}, sources, gap=gap)
        self.assertEqual((c["state"], c["reason"]), ("quiet", "노드 수신 2분 전 · 최근 1시간 요청 없음"))
        self.assertEqual(c["warnings"], [{"key": "parse", "label": "웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖)",
                                          "at": gap.isoformat()}])
        self.assertEqual(t.node_collection(NOW, node_row("web-02"), {}, sources)["warnings"], [])
        self.assertEqual(t.node_collection(NOW, None, {}, readable=False)["warnings"], [])


if __name__ == "__main__":
    unittest.main()
