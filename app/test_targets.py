"""관제 대상별 상태판(targets.py · 이슈 #52) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 사건 → 대상 매핑(resolve): node:<id> · user:… · 근거의 발생원 · 규칙의 발생원 후보(sensors ∪ 이벤트 접두) ·
     발생원이 섞인 규칙은 이벤트로 고름(빈도 규칙은 탐지와 같은 창 · 임계치 · 응답 코드 · 제외 경로) · 한 대상 안에서 AWS 발생원이
     여럿이면 나눔만 고름 · 발생원 조건 없는 세션 규칙은 세션으로 나눔 · 기준선 · 키 심기는 Cowrie ·
     정의 없음 · 모르는 발생원. 실제 규칙 파일 전부(detector/rules*.json)가 계약대로 붙는지
  2. 집계(tally · latest_of): 한 사건이 여러 대상에 붙음 · 1시간 경계 · 높은 심각도 · 미판정 · 나눔 · 붙이지 못한 사건 ·
     최근 중요 탐지(높음 우선 → 없으면 아무 사건 · 24시간 경계 · 같은 시각은 키 순)
  3. 수집 상태: AWS 센서(표 없음 · 행 없음 · 적재기 확인 중단 30분 · 신호 없음 · 확인 시점 기준 15분 경계 · 기록 지연 · 남은 행 무시 ·
     정상 · 요청 없음) ·
     web-01(노드 수신 판정 네 값) · 콘솔(늘 미확인, 신호 null) · 데이터 노드(탐지 실행 · 적재기 · 집행기 확인)
  4. 시스템 · 대응 · 취약점: 미수집 · 권한 없음 · 행 없음 · 오래됨 · 지점 없는 대상은 수 대신 null(0 이 아님) · 실패는 미확인과 따로 ·
     집행기 확인 멈춤이면 적용 확인을 미확인으로 합침 ·
     보고 신호 · 자산 없음은 0 이 아니라 missing · 48시간
  5. 라우터: main 앱에 붙음 · 세션 없으면 401 · 표 · 권한이 없는 DB 에서도 200(미확인) · 집행 제외 말머리가 main 과 같다
main 이 필요한 시험은 test_web 을 먼저 불러 asyncpg 가 없는 곳에서도 가짜를 넣는다(main 보다 먼저).
"""
import json
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

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
        sessions = {"R002"}        # 발생원 조건 없는 세션 규칙: 대상은 AWS 센서, 나눔은 세션으로
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
        self.assertEqual(unmapped, {"incidents_1h": 1, "pending": 1})
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
                                       "last_ts", "judged"})

    def test_높음이_없으면_아무_사건_최신이고_24시간_밖은_없다(self):
        self.assertEqual(t.latest_of([incident("m", 30), incident("l", 3, severity="low")], NOW)["incident_key"], "l")
        edge = incident("edge", 24 * 60, severity="high")                 # 24시간 경계(포함)
        self.assertEqual(t.latest_of([edge], NOW)["incident_key"], "edge")
        self.assertIsNone(t.latest_of([incident("old", 24 * 60 + 1, severity="high")], NOW))
        self.assertIsNone(t.latest_of([], NOW))
        # 같은 시각이면 키 순
        self.assertEqual(t.latest_of([incident("b", 5, severity="high"), incident("a", 5, severity="high")],
                                     NOW)["incident_key"], "a")


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
        # 관문 업로더 · 차단 보고 행은 센서 신호가 아니다
        c = t.sensor_collection(NOW, True, [hb("uploader:i-0aaaaaaaa", role="gateway"),
                                            hb("block:gateway", kind="block_report", role="gateway")], LOGS_ACTIVE)
        self.assertEqual((c["state"], c["reason"]), ("unknown", "생존 신호 미기록"))
        self.assertEqual([(l["key"], l["label"]) for l in c["logs"]],
                         [("cowrie", "Cowrie"), ("decoy", "웹 디코이"), ("gateway", "AWS 관문 기록")])
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

    def test_콘솔은_늘_생존_상태_미확인이다(self):
        c = t.console_collection({"console": NOW})
        self.assertEqual((c["state"], c["reason"], c["signal"], c["extra"]),
                         ("unknown", "생존 신호 없음 · 현재 콘솔은 실시간 연결로 표시", None, []))
        self.assertEqual(c["logs"], [{"key": "console", "label": "마지막 로그인 기록", "last_at": NOW.isoformat()}])

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
        blocks = {"gateway_applied": 0, "gateway_failed": 0, "gateway_unverified": 0,
                  "fw_applied": 0, "fw_failed": 0, "fw_unverified": 0}
        for tid in ("console", "data-node"):
            r = t.response_block(tid, blocks, 2, {}, NOW, True)
            self.assertEqual(r, {"point": None, "point_label": None, "applied": None, "failed": None, "unverified": None,
                                 "exempt": 2, "report": None, "stalled": None})

    def test_지점이_있으면_그_지점의_확인_수와_보고를_낸다(self):
        blocks = {"gateway_applied": 3, "gateway_failed": 0, "gateway_unverified": 1,
                  "fw_applied": 0, "fw_failed": 2, "fw_unverified": 4}
        report = hb("block:fw", kind="block_report", role="fw", seen=None, checked=1, problem="보고 파일 없음")
        # 생존 신호 표를 읽을 수 없으면(마이그레이션 전) 멈춤을 판정하지 못해 수를 그대로 둔다
        aws = t.response_block("aws-sensor", blocks, 0, {"fw": report}, NOW, False)
        self.assertEqual(aws, {"point": "gateway", "point_label": "AWS 관문", "applied": 3, "failed": 0, "unverified": 1,
                               "exempt": 0, "report": None, "stalled": None})
        # 표는 읽는데 그 지점의 집행기 확인 기록이 없으면 적용 확인을 믿지 않는다
        aws = t.response_block("aws-sensor", blocks, 0, {"fw": report}, NOW, True)
        self.assertEqual((aws["applied"], aws["failed"], aws["unverified"], aws["stalled"]), (0, 0, 4, "집행기 확인 기록 없음"))
        web = t.response_block("web-01", blocks, 1, {"fw": report}, NOW, True)
        self.assertEqual((web["point"], web["point_label"], web["applied"], web["failed"], web["unverified"], web["exempt"],
                          web["stalled"]), ("fw", "내부 방화벽", 0, 2, 4, 1, None))
        # 집행기 확인이 10분 넘게 멈췄다: 실패 · 적용 · 미확인을 모두 미확인으로 합친다(10분 정각은 아직 확인 중)
        old = hb("block:gateway", kind="block_report", role="gateway", seen=11, checked=11)
        aws = t.response_block("aws-sensor", blocks, 0, {"gateway": old}, NOW, True)
        self.assertEqual((aws["applied"], aws["unverified"], aws["stalled"]), (0, 4, "집행기 확인 중단 · 마지막 확인 11분 전"))
        edge = hb("block:gateway", kind="block_report", role="gateway", seen=10, checked=10)
        self.assertEqual(t.response_block("aws-sensor", blocks, 0, {"gateway": edge}, NOW, True)["applied"], 3)
        self.assertEqual(web["report"], {"seen_at": None, "checked_at": (NOW - timedelta(minutes=1)).isoformat(),
                                         "problem": "보고 파일 없음"})

    def test_취약점은_자산이_없으면_0_이_아니라_missing_이다(self):
        assets = {"web-01": {"vuln_total": 5, "vuln_kev": 1, "collected_at": NOW - timedelta(hours=1),
                             "checked_at": NOW - timedelta(hours=1)},
                  "honeypot-dmz": {"vuln_total": 2, "vuln_kev": 0, "collected_at": NOW - timedelta(hours=49),
                                   "checked_at": None}}
        self.assertEqual(t.vulns_block("web-01", False, assets, NOW), {"available": False, "assets": []})
        web = t.vulns_block("web-01", True, assets, NOW)
        self.assertEqual(web["assets"], [{"asset_id": "web-01", "vuln_total": 5, "vuln_kev": 1,
                                          "collected_at": (NOW - timedelta(hours=1)).isoformat(),
                                          "checked_at": (NOW - timedelta(hours=1)).isoformat(),
                                          "stale": False, "missing": False}])
        aws = t.vulns_block("aws-sensor", True, assets, NOW)["assets"]
        self.assertEqual([(a["asset_id"], a["stale"], a["missing"]) for a in aws],
                         [("honeypot-dmz", True, False), ("gateway", True, True)])
        self.assertEqual((aws[1]["vuln_total"], aws[1]["vuln_kev"], aws[1]["collected_at"]), (0, 0, None))
        self.assertEqual([a["asset_id"] for a in t.vulns_block("console", True, {}, NOW)["assets"]],
                         ["console-a", "console-b"])
        self.assertEqual([a["asset_id"] for a in t.vulns_block("data-node", True, {}, NOW)["assets"]], ["data-01"])


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


class FakePool:
    def __init__(self):
        self.calls = []

    @asynccontextmanager
    async def acquire(self):
        yield FakeConn(self.calls)


class RouterTests(unittest.TestCase):
    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        patcher = patch.object(self.main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def test_집행_제외_말머리는_main_과_같다(self):
        self.assertEqual(t.ENFORCE_EXCLUDED, self.main.ENFORCE_EXCLUDED)
        self.assertIn(f"NOT LIKE '{self.main.ENFORCE_EXCLUDED}%'", t.BLOCKS_SQL)

    def test_세션이_없으면_401_이다(self):
        response = self.client.get("/api/dashboard/targets")
        self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual(self.pool.calls, [])

    def test_표_권한이_없는_DB_에서도_미확인으로_답한다(self):
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", "viewer"))
        response = self.client.get("/api/dashboard/targets")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["as_of"], body["window_seconds"], body["heartbeats_available"], body["metrics_available"]),
                         (NOW.isoformat(), 3600, False, False))
        self.assertEqual([x["id"] for x in body["targets"]], ["aws-sensor", "web-01", "console", "data-node"])
        self.assertEqual([x["label"] for x in body["targets"]], ["AWS 센서", "web-01", "관제 콘솔", "데이터 노드"])
        self.assertEqual([x["collection"]["state"] for x in body["targets"]], ["unknown"] * 4)
        self.assertEqual([x["system"]["state"] for x in body["targets"]],
                         ["not_collected", "no_privilege", "not_collected", "not_collected"])
        self.assertEqual([x["vulns"] for x in body["targets"]], [{"available": False, "assets": []}] * 4)
        self.assertEqual(body["unmapped"], {"incidents_1h": 0, "pending": 0})
        # 한 트랜잭션(반복 읽기 · 읽기 전용)이고, 없는 표는 읽지 않는다
        self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                         [("transaction", {"isolation": "repeatable_read", "readonly": True})])
        for sql in (t.HEARTBEATS_SQL, t.METRICS_SQL, t.RULES_SQL, t.JOIN_SQL):
            self.assertNotIn(sql, self.pool.calls)
        self.assertIn(t.HEARTBEATS_READABLE_SQL, self.pool.calls)
        self.assertIn(t.METRICS_READABLE_SQL, self.pool.calls)

    def test_경로는_상태판_처리기로_간다(self):
        from starlette.routing import Match
        scope = {"type": "http", "path": "/api/dashboard/targets", "method": "GET", "root_path": "", "headers": []}
        route = next(r for r in self.main.app.routes if r.matches(scope)[0] == Match.FULL)
        self.assertIs(route.endpoint, t.dashboard_targets)


if __name__ == "__main__":
    unittest.main()
