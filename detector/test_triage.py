#!/usr/bin/env python3
"""판정 검토 도구(triage.py)의 중복 제안 시험.  python3 detector/test_triage.py

중복(대표 인시던트) 계산은 같은 규칙 버전의 인시던트 안에서만 해야 한다. 버전이 다른 인시던트가
심각도가 더 높다고 대표가 되면, 새 버전 인시던트가 까닭 없이 '무시 가능(중복)'으로 제안된다.
같은 페이로드 흡수(규칙 v3): 첫 사건의 흡수 기록을 보이고, 차단할 때 흡수 출발지를 함께 올리는 선택을 본다.
R006(키 심기)은 순환 규칙이다.
SSH 허니팟 규칙(R001~R006, app/proposals.py SSH_RULES) 밖에는 판정을 제안하지 않는다(판정 기준 §8).
웹 · 감사 · 인프라 · 요청 경로 서명(R105 · R106) 사건에 같은 출발지의 cowrie 기록이 있어도 제안이 없고, 일괄 수락에서도
남는다.
판정 화면은 공격자 값(아이디 · 비밀번호 · 명령 · URL)의 제어 문자(ESC · C1) · 숨은 문자를 ⟨U+XXXX⟩ 표식으로, 줄바꿈을 ↵ 로
보인다. ANSI 이스케이프로 판정자 터미널을 지우거나 제안 · 근거 줄을 덮어쓰지 못한다.
차단(이슈 #47): 이 출발지 차단은 만료(기본 24시간)가 있고 요청자는 'triage:<판정자>' 다. 사람이 푼 출발지는 되살리지 않고,
차단 금지 대역 · 대역 주소는 트리거가 거부해도 판정은 남는다. 살아 있는 차단의 만료는 줄이지 않는다. 집행 정보는 새 요청이어도
요청 시각에 두고 집행기가 판단한다(이슈 #77 결정 2). 흡수 차단은 DB 금지 대역(block_exempt)도 뺀다.
적용 지점(이슈 #77): 규칙 기본값(R004 → 관문 + 내부 방화벽, 나머지 → 내부 방화벽)이 app/block_points.py 와 같고, 이 출발지 ·
흡수 함께 차단 · 후속 차단 약속이 그 지점으로 오른다. 살아 있는 차단 · 약속은 넓히기만 하고, 관문을 포함하면 다른 사건으로 살아
있는 흡수 출발지(kept)도 지점만 넓힌다. 판정 화면 · 묻는 줄에 '차단 지점' 이 보인다.

  - 가짜 커서: DB 없이 조회 문장과 인자에 규칙 버전이 들어가는지 본다
  - 임시 테이블: OPSLOOP_TEST_DATABASE_URL 이 있으면 연결 전용 임시 테이블(search_path=pg_temp)에서
    실제 조회 결과를 본다. 운영 테이블은 건드리지 않는다
"""
import io
import json
import os
import re
import secrets
import sys
import types
from unittest import mock
import unittest
from datetime import datetime, timedelta, timezone

try:
    import psycopg2  # noqa: F401
    REAL_PG = True
except ImportError:
    # psycopg2 가 없는 곳에서도 가짜 커서 시험은 돌게 한다 (DB 에는 붙지 않는다)
    sys.modules["psycopg2"] = types.ModuleType("psycopg2")
    REAL_PG = False

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import triage  # noqa: E402

ACTOR = "192.0.2.8"
T0 = datetime(2026, 9, 20, 3, tzinfo=timezone.utc)

# 차단 목록 표(schema.sql 과 같은 열)
POINTS_COLUMN = "points text[] NOT NULL DEFAULT '{gateway,fw}' CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[]))"
BLOCKLIST = f"""
    CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, incident_key text,
        created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, released_at timestamptz,
        method text, requested_by text, enforced_at timestamptz, enforce_note text, released_by text,
        {POINTS_COLUMN});
"""

# 차단 금지 대역 표와 트리거. 계약(이슈 #47 인터페이스)대로 흉내 낸다: 한 주소가 아니면 23514 blocklist_host_only,
# 금지 대역이면 23514 blocklist_exempt, UPDATE 는 주소가 바뀔 때만 본다. 실제 트리거(schema.sql blocklist_guard)는 infra 시험이 본다.
# 적용 지점(이슈 #77): 살아 있는 행을 풀지 않고 좁히면 23514 blocklist_points_narrow(schema.sql blocklist_points_change, 감사는 뺐다)
GUARD = """
    CREATE TEMP TABLE block_exempt (cidr inet PRIMARY KEY, note text NOT NULL, created_at timestamptz DEFAULT now());
    CREATE FUNCTION pg_temp.blocklist_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF TG_OP = 'UPDATE' AND NEW.actor_ip IS NOT DISTINCT FROM OLD.actor_ip THEN RETURN NEW; END IF;
        IF masklen(NEW.actor_ip) <> (CASE WHEN family(NEW.actor_ip) = 4 THEN 32 ELSE 128 END) THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_host_only', MESSAGE = '대역 주소';
        END IF;
        IF EXISTS (SELECT 1 FROM block_exempt WHERE cidr >>= NEW.actor_ip) THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_exempt', MESSAGE = '금지 대역';
        END IF;
        RETURN NEW;
    END $$;
    CREATE TRIGGER blocklist_guard BEFORE INSERT OR UPDATE OF actor_ip ON blocklist
        FOR EACH ROW EXECUTE FUNCTION pg_temp.blocklist_guard();
    CREATE FUNCTION pg_temp.blocklist_points_change() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF OLD.released_at IS NULL AND (OLD.expires_at IS NULL OR OLD.expires_at > now())
           AND NEW.released_at IS NULL AND NOT NEW.points @> OLD.points THEN
            RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_points_narrow', MESSAGE = '좁히기';
        END IF;
        RETURN NULL;
    END $$;
    CREATE TRIGGER trg_blocklist_points AFTER UPDATE OF points ON blocklist
        FOR EACH ROW EXECUTE FUNCTION pg_temp.blocklist_points_change();
    INSERT INTO block_exempt (cidr, note) VALUES ('10.0.0.0/8', '사설 · AWS VPC'), ('15.164.37.49/32', 'AWS 관문 EIP'),
        ('192.168.0.0/16', '사설 · 관리망 · 서비스망');
"""


class FakeCursor:
    """조회 문장과 인자를 기록한다. 결과는 모두 비어 있다."""

    def __init__(self):
        self.calls = []

    def execute(self, sql, args=None):
        self.calls.append((" ".join(sql.split()), args))

    def fetchall(self):
        return []

    def fetchone(self):
        return None


class CircularTests(unittest.TestCase):
    def test_key_plant_is_circular_and_matches_console(self):
        # 콘솔(app/proposals.py)과 같은 목록이어야 판정자가 같은 기준으로 본다
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import proposals
        finally:
            sys.path.pop(0)
        self.assertEqual(set(triage.CIRCULAR), proposals.CIRCULAR_RULES)
        ev = {"counts": {"cowrie.command.input": 2}, "covered_by": None}
        suggestion, basis = triage.propose("R006", ev)
        self.assertEqual(suggestion, "threat")
        self.assertIn("authorized_keys", " ".join(basis))


class NonSshRuleTests(unittest.TestCase):
    """SSH 판정 기준(로그인 · 명령 · 파일 · 경유)은 cowrie 기록이라 다른 규칙의 판정 근거가 아니다. 콘솔과 같은 경계다."""

    # 저장소 규칙 파일의 SSH 밖 규칙 전부. R105 · R106 은 CVE · KEV 연계(c1), R107 은 공개 규칙(Sigma) 서명(sg1)이다
    OTHERS = ("R101", "R102", "R103", "R104", "R105", "R106", "R107", "R201", "R202", "R301")

    def test_SSH_규칙_목록이_콘솔과_같다(self):
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import proposals
        finally:
            sys.path.pop(0)
        self.assertEqual(triage.SSH_RULES, proposals.SSH_RULES)
        self.assertLessEqual(set(triage.CIRCULAR), triage.SSH_RULES)

    def test_SSH_밖_규칙에는_제안하지_않는다(self):
        # 같은 출발지가 SSH 허니팟에서 명령 · 파일 · 로그인까지 했고, 더 높은 심각도 사건에 덮여도 제안이 없다
        for counts in ({"cowrie.command.input": 3, "cowrie.session.file_download": 1},
                       {"cowrie.login.success": 1}, {"cowrie.login.failed": 9}, {}):
            for covered_by in (None, "R106"):
                for rid in self.OTHERS:
                    with self.subTest(rule=rid, counts=counts, covered_by=covered_by):
                        suggestion, basis = triage.propose(rid, {"counts": counts, "covered_by": covered_by})
                        self.assertIsNone(suggestion)
                        self.assertIn("자동 제안 기준이 없다", basis[0])
                        # 중복 정보는 참고 줄로만 남는다
                        self.assertEqual(any("R106 가 더 높은 심각도" in line for line in basis), bool(covered_by))

    def test_SSH_규칙은_전과_같다(self):
        ev = {"counts": {"cowrie.command.input": 1}, "covered_by": None}
        for rid in sorted(triage.SSH_RULES):
            with self.subTest(rule=rid):
                self.assertEqual(triage.propose(rid, ev)[0], "threat")
        self.assertEqual(triage.propose("R001", {"counts": {"cowrie.login.failed": 5}, "covered_by": None})[0],
                         "non_actionable")
        self.assertEqual(triage.propose("R001", {"counts": {}, "covered_by": "R002"})[0], "non_actionable")


class AbsorbedSqlSameAsConsoleTests(unittest.TestCase):
    """triage 의 흡수 차단 문장은 콘솔(app/absorbed.py)과 자리표시자만 다르다. 한쪽만 고치면 여기서 걸린다."""

    def test_same_statements_and_nets(self):
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import absorbed
        finally:
            sys.path.pop(0)
        self.assertEqual(triage.NO_BLOCK_NETS, absorbed.NO_BLOCK_NETS)
        self.assertEqual(triage.EXEMPT_READABLE_SQL, absorbed.EXEMPT_READABLE_SQL)
        self.assertEqual((triage.REFUSED_SQLSTATE, triage.REFUSED_CONSTRAINTS),
                         (absorbed.REFUSED_SQLSTATE, absorbed.REFUSED_CONSTRAINTS))
        self.assertEqual(triage.absorbed_reason_tag("k"), absorbed.absorbed_reason_tag("k"))
        for name, names in (("BLOCK_ABSORBED_SQL", ("key", "reason", "ip", "who", "expires", "nets", "points")),
                            ("ABSORBED_STATE_SQL", ("key", "reason", "ip", "nets", "n")),
                            ("FOLLOW_UPSERT_SQL", ("key", "hours", "who", "points")),
                            ("WIDEN_KEPT_SQL", ("key", "reason", "ip", "points"))):
            with self.subTest(sql=name):
                console = re.sub(r"\$(\d)", lambda m: f"%({names[int(m.group(1)) - 1]})s", getattr(absorbed, name))
                self.assertEqual(getattr(triage, name), console)


def rule_ids():
    """저장소 규칙 파일(detector/rules*.json)의 규칙 id 전부."""
    ids = set()
    for name in os.listdir(HERE):
        if name.startswith("rules") and name.endswith(".json"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                ids |= {r["id"] for r in json.load(f)["rules"]}
    return ids


class BlockPointsTests(unittest.TestCase):
    """차단 적용 지점(이슈 #77). 기본값 · 합집합 식은 app/block_points.py 의 사본이고, 판정 화면에 '차단 지점' 한 줄이 보인다."""

    def test_지점_사본이_콘솔과_같다(self):
        sys.path.insert(0, os.path.join(HERE, "..", "app"))
        try:
            import block_points
        finally:
            sys.path.pop(0)
        self.assertEqual(triage.HONEYPOT_ABUSE_RULES, block_points.HONEYPOT_ABUSE_RULES)
        self.assertEqual(triage.POINTS, block_points.POINTS)
        self.assertEqual(triage.union_of("a.points", "$9"), block_points.union_of("a.points", "$9"))
        ids = rule_ids()
        self.assertLessEqual({"R001", "R004", "R006", "R102", "R201"}, ids)
        for rid in sorted(ids) + [None, "R999"]:
            with self.subTest(rule=rid):
                self.assertEqual(triage.default_points(rid), block_points.default_points(rid))
        # 이 출발지 차단(콘솔 BLOCK_SQL 과 다른 문장)도 살아 있으면 같은 합집합 식이다
        self.assertIn(f"points       = CASE WHEN {triage._LIVE} THEN {block_points.UNION_SQL} ELSE EXCLUDED.points END",
                      triage.OWN_BLOCK_SQL)
        # 다시 걸기는 관문 포함 여부와 무관하게 관문 세 열 · 지점 결과를 건드리지 않는다(콘솔과 같다, 결정 2)
        for sql in (triage.OWN_BLOCK_SQL, triage.BLOCK_ABSORBED_SQL):
            update = sql.split("DO UPDATE", 1)[1]
            for col in ("method", "enforced_at", "enforce_note", "enforcement"):
                with self.subTest(col=col):
                    self.assertIsNone(re.search(rf"\b{col}\s*=", update), col)

    def test_규칙_기본값(self):
        self.assertEqual(triage.default_points("R004"), ["gateway", "fw"])
        for rid in ("R001", "R002", "R003", "R005", "R006", "R102", "R105", "R201", "R301", None):
            with self.subTest(rule=rid):
                self.assertEqual(triage.default_points(rid), ["fw"])
        self.assertEqual(triage.points_name(["fw"]), "내부 방화벽")
        self.assertEqual(triage.points_name(["fw", "gateway"]), "AWS 관문 + 내부 방화벽")

    def shown(self, rid, ip="192.0.2.8", target=None, **ev):
        base = {"counts": {}, "creds": [], "commands": [], "files": [], "also": [], "blocked": False,
                "no_expiry": False, "live_points": None, "released": None, "exempt": None, "covered_by": None,
                "absorbed": {"total": 0, "sources": 0, "sample": []}}
        row = (f"{rid}|v3|k", rid, "v3", "시험 규칙", "high", ip, T0, T0, 1, 1, None, "open", target)
        with mock.patch("sys.stdout", io.StringIO()) as out:
            triage.show(row, 1, 1, base | ev, None, ["근거"], 1.0, "알림 신호 수")
        return [line for line in out.getvalue().splitlines() if "차단 지점" in line]

    def test_판정_화면의_차단_지점(self):
        self.assertEqual(self.shown("R001"), ["  차단 지점 내부 방화벽"])
        self.assertEqual(self.shown("R004"), ["  차단 지점 AWS 관문 + 내부 방화벽"])
        # 살아 있는 차단은 넓히기만 한다: 두 지점 차단이 살아 있으면 R001 로 다시 걸어도 두 지점이 남는다
        self.assertEqual(self.shown("R001", blocked=True, live_points=["gateway", "fw"]),
                         ["  차단 지점 AWS 관문 + 내부 방화벽"])
        # 올릴 수 없는 출발지(금지 대역 · 사람이 푼 곳)와 IP 가 아닌 대상에는 없다
        self.assertEqual(self.shown("R001", exempt=("10.0.0.0/8", "사설")), [])
        self.assertEqual(self.shown("R001", released=("admin", T0)), [])
        self.assertEqual(self.shown("R201", ip=None, target="user:han"), [])


class OverlapQueryTests(unittest.TestCase):
    def test_overlap_query_is_limited_to_rule_version(self):
        cur = FakeCursor()
        triage.gather(cur, "R003|v2", ACTOR, T0, T0, [], "v2")
        sql, args = next((s, a) for s, a in cur.calls if "interval '15 minutes'" in s)
        self.assertIn("rule_version = %s", sql)
        self.assertEqual(args[:2], (ACTOR, "v2"))

    def test_absorbed_query_is_by_first_key(self):
        cur = FakeCursor()
        ev = triage.gather(cur, "R006|v3", ACTOR, T0, T0, [], "v3")
        sql, args = next((s, a) for s, a in cur.calls if "FROM incident_absorbed" in s)
        self.assertIn("first_key = %s", sql)
        self.assertEqual(args, (ACTOR, "R006|v3"))
        self.assertEqual(ev["absorbed"], {"total": 0, "sources": 0, "sample": []})

    def test_covered_by_drives_duplicate_proposal_only_when_set(self):
        ev = {"counts": {"cowrie.login.success": 1}, "covered_by": None}
        self.assertNotIn("이미 떴다", " ".join(triage.propose("R003", ev)[1]))
        ev["covered_by"] = "R002"
        suggestion, basis = triage.propose("R003", ev)
        self.assertEqual(suggestion, "non_actionable")
        self.assertIn("R002", basis[1])


class HostileDisplayTests(unittest.TestCase):
    """공격자가 정한 값(cowrie 아이디 · 비밀번호 · 명령 · 내려받은 URL)은 파서가 NUL 만 지워 ESC · C1 · 방향 제어가 DB 에
    그대로 있다. 판정 화면에 찍기 전에 보이는 표식으로 바꾼다. 원문(DB)은 그대로 둔다."""

    ESC = ("\x1b[2J\x1b[H", "\x1b]0;x\x07", "\x9b31m", "\x1b[1A\x1b[2K")

    @staticmethod
    def hidden(text):
        """출력에 남은 제어 문자(줄바꿈 제외) · 숨은 문자(Cf)."""
        import unicodedata
        return [f"U+{ord(c):04X}" for c in text if unicodedata.category(c) in ("Cf", "Cc") and c != "\n"]

    def test_표식_규칙(self):
        self.assertEqual(triage.shown("a\x1b[31mb"), "a⟨U+001B⟩[31mb")
        self.assertEqual(triage.shown("\x9b2K\x07\x7f\x00"), "⟨U+009B⟩2K⟨U+0007⟩⟨U+007F⟩⟨U+0000⟩")
        self.assertEqual(triage.shown("admin\u202egnp.exe"), "admin⟨U+202E⟩gnp.exe")
        self.assertEqual(triage.shown("ad\u200bmin\ufeff\u2066x\u2069\U000e0041"),
                         "ad⟨U+200B⟩min⟨U+FEFF⟩⟨U+2066⟩x⟨U+2069⟩⟨U+E0041⟩")
        self.assertEqual(triage.shown("줄1\u2028줄2\u2029"), "줄1⟨U+2028⟩줄2⟨U+2029⟩")
        self.assertEqual(triage.shown("줄1\r\n2026-09-18 15:00:00 decoy\tlogin.success"),
                         "줄1⟨U+000D⟩↵2026-09-18 15:00:00 decoy login.success")
        self.assertEqual(triage.shown("<img src=//a.attacker.test/p.png> 한글"), "<img src=//a.attacker.test/p.png> 한글")
        # 자를 때 표식을 가르지 않는다
        self.assertEqual(triage.shown("ab\x1bcd", 5), "ab…")
        self.assertEqual(triage.shown("ab\x1bcd", 12), "ab⟨U+001B⟩cd")
        self.assertEqual(triage.shown("x" * 62, 62), "x" * 62)
        self.assertEqual(triage.shown("x" * 20000, 62), "x" * 61 + "…")
        # 기본 무시 문자와 점자 빈칸도 표식이다
        self.assertEqual(triage.shown("adm\u3164in\u034f\ufe0f\u2800"), "adm⟨U+3164⟩in⟨U+034F⟩⟨U+FE0F⟩⟨U+2800⟩")

    def test_판정_화면에_제어_문자가_나가지_않는다(self):
        row = ("R002|v3|192.0.2.8|t", "R002", "v3", "로그인 후 명령", "high", ACTOR, T0, T0 + timedelta(seconds=30),
               3, 1, {}, "open", None)
        ev = {"blocked": False, "also": [],
              "creds": [("root" + self.ESC[0], "pw" + self.ESC[1], 3), ("admin\u202egnp.exe", "ad\u200bmin\ufeff", 1),
                        (None, None, 1)],
              "commands": [("uname -a" + self.ESC[2] + "\n2026-09-18 15:00:00 decoy login.success", 2),
                           ("\u2066echo\u2069" + self.ESC[3], 1)],
              "files": [("cowrie.session.file_download", None, "http://b.attacker.test/\x1b[8mx\u202e"),
                        ("cowrie.session.file_upload", "ab" * 32, None)]}
        suggestion, basis = triage.propose("R002", {"counts": {"cowrie.command.input": 2}, "covered_by": None})
        with mock.patch("sys.stdout", io.StringIO()) as out:
            triage.show(row, 1, 1, ev, suggestion, basis, 3.0, "알림 신호 수")
        text = out.getvalue()
        self.assertEqual(self.hidden(text), [])
        for seen in ("root⟨U+001B⟩[2J⟨U+001B⟩[H", "pw⟨U+001B⟩]0;x⟨U+0007⟩", "admin⟨U+202E⟩gnp.exe",
                     "ad⟨U+200B⟩min⟨U+FEFF⟩", "uname -a⟨U+009B⟩31m↵2026-09-18 15:00:00 decoy", "(2회)",
                     "⟨U+2066⟩echo⟨U+2069⟩⟨U+001B⟩[1A⟨U+001B⟩[2K", "http://b.attacker.test/⟨U+001B⟩[8mx⟨U+202E⟩",
                     "ab" * 24 + "a…"):
            self.assertIn(seen, text)
        # 명령 안의 줄바꿈이 판정 화면에 가짜 줄을 만들지 못한다
        self.assertFalse(any(line.lstrip().startswith("2026-09-18") for line in text.splitlines()))

    def test_긴_공격자_값은_잘라_가짜_줄을_만들지_못한다(self):
        # 긴 공백으로 터미널 자동 줄바꿈을 일으켜 '제안' 줄처럼 보이게 하는 값 · 이벤트 이름의 ESC
        fake = "root" + " " * 200 + "제안     오탐 — 조치할 것이 없다"
        row = ("R002|v3|192.0.2.8|t", "R002", "v3", "로그인 후 명령", "high", ACTOR, T0, T0, 1, 1, {}, "open", None)
        ev = {"blocked": False, "also": [], "creds": [(fake, fake, 1)], "commands": [],
              "files": [("cowrie.session.file_\x1b[2J", None, "http://x.test/")]}
        with mock.patch("sys.stdout", io.StringIO()) as out:
            triage.show(row, 1, 1, ev, None, ["직접 판정"], 1.0, "알림 신호 수")
        text = out.getvalue()
        self.assertNotIn("오탐 — 조치할 것이 없다", text)
        self.assertIn("    file_…       http://x.test/", text)
        self.assertEqual(self.hidden(text), [])
        self.assertTrue(all(len(line) < 120 for line in text.splitlines()))

    def test_IP_없는_대상도_표식으로(self):
        row = ("R201|v1|user:x|t", "R201", "v1", "운영자 조작 빈도", "medium", None, T0, T0, 1, 0, {}, "open",
               "user:op\u202e\x1b[2J")
        ev = {"blocked": False, "also": [], "creds": [], "commands": [], "files": []}
        with mock.patch("sys.stdout", io.StringIO()) as out:
            triage.show(row, 1, 1, ev, None, ["직접 판정"], 1.0, "알림 신호 수")
        self.assertIn("대상     user:op⟨U+202E⟩⟨U+001B⟩[2J", out.getvalue())
        self.assertEqual(self.hidden(out.getvalue()), [])


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class OverlapDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text NOT NULL, severity text, actor_ip inet, first_ts timestamptz,
                last_ts timestamptz);
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, eventid text,
                username text, password text, input text, shasum text, url text);
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
        """ + BLOCKLIST)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def incident(self, key, rule, version, severity, minutes=0):
        first = T0 + timedelta(minutes=minutes)
        self.cur.execute(
            "INSERT INTO incidents VALUES (%s, %s, '시험 규칙', %s, %s, %s, %s, %s)",
            (key, rule, version, severity, ACTOR, first, first + timedelta(minutes=1)))
        return first

    def gather(self, key, version, first):
        return triage.gather(self.cur, key, ACTOR, first, first + timedelta(minutes=1), [], version)

    def test_higher_severity_of_other_version_is_not_representative(self):
        # 버전을 가리지 않으면 더 높은 심각도의 v1 인시던트가 대표가 된다
        self.incident("R002|v1", "R002", "v1", "critical")
        first = self.incident("R003|v2", "R003", "v2", "high", minutes=2)
        self.assertIsNone(self.gather("R003|v2", "v2", first)["covered_by"])

    def test_newer_version_is_not_representative_of_older(self):
        self.incident("R002|v2", "R002", "v2", "critical")
        first = self.incident("R003|v1", "R003", "v1", "high", minutes=2)
        self.assertIsNone(self.gather("R003|v1", "v1", first)["covered_by"])

    def test_same_version_representative_is_still_found(self):
        self.incident("R002|v1", "R002", "v1", "critical")
        self.incident("R004|v2", "R004", "v2", "critical", minutes=1)
        first = self.incident("R003|v2", "R003", "v2", "high", minutes=2)
        ev = self.gather("R003|v2", "v2", first)
        self.assertEqual(ev["covered_by"], "R004")
        self.assertEqual(triage.propose("R003", ev)[0], "non_actionable")


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class NonSshBulkAcceptDatabaseTests(unittest.TestCase):
    """일괄 수락([a])은 제안이 있는 사건만 기록한다. 같은 출발지가 SSH 허니팟에서 명령을 친 기록이 있어도 R106(c1) 사건은
    제안이 없어 미판정으로 남는다."""

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text NOT NULL, severity text, actor_ip inet, first_ts timestamptz,
                last_ts timestamptz, signal_count integer DEFAULT 1, session_count integer DEFAULT 1,
                evidence jsonb, status text DEFAULT 'open', target text);
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, eventid text,
                username text, password text, input text, shasum text, url text);
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
                reason text, observed_value double precision, operator text, proposed text, decision_seconds integer);
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
                operator text, note text);
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
        """ + BLOCKLIST)
        for key, rid, name, ver, sev in (("R002|v3|k", "R002", "로그인 후 명령", "v3", "high"),
                                         ("R106|c1|k", "R106", "알려진 취약점 공격 시도", "c1", "medium"),
                                         ("R105|c1|k", "R105", "제품 식별 탐색", "c1", "low")):
            self.cur.execute("""INSERT INTO incidents (incident_key, rule_id, rule_name, rule_version, severity,
                actor_ip, first_ts, last_ts, evidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '{"sessions": ["c1"]}')""",
                             (key, rid, name, ver, sev, ACTOR, T0, T0 + timedelta(minutes=1)))
        # 같은 출발지 · 같은 구간의 cowrie 로그인 · 명령과 웹 요청
        for eid, inp in (("cowrie.login.success", None), ("cowrie.command.input", "uname -a"),
                         ("decoy.request", None), ("nginx.request", None)):
            self.cur.execute("INSERT INTO events (ts, src_ip, session, eventid, input) VALUES (%s, %s, 'c1', %s, %s)",
                             (T0, ACTOR, eid, inp))

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def test_일괄_수락은_R105_R106_을_남긴다(self):
        answers = iter(["a", "y"])
        with mock.patch("builtins.input", lambda prompt="": next(answers)), \
                mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, None, 10, "han")
        self.cur.execute("SELECT incident_key, verdict, proposed FROM verdicts ORDER BY incident_key")
        self.assertEqual(self.cur.fetchall(), [("R002|v3|k", "threat", "threat")])
        self.assertIn("판정 1건 · 건너뜀 2건", out.getvalue())


FIRST = "R006|v3|192.0.2.1|2026-09-20T00:00:00+00:00"
OWN = "192.0.2.1"


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class AbsorbedDatabaseTests(unittest.TestCase):
    """흡수 기록 표시와 흡수 출발지 함께 차단(record absorbed=True). 이 출발지의 차단은 --block-hours(기본 24시간),
    흡수 출발지는 --absorbed-hours(기본 24시간) 만료이며 후속 차단 약속을 남긴다. 요청자는 'triage:<판정자>' 다."""

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_name text,
                rule_version text NOT NULL, severity text, actor_ip inet, first_ts timestamptz,
                last_ts timestamptz, status text DEFAULT 'open');
            CREATE TEMP TABLE events (ts timestamptz, src_ip inet, session text, eventid text,
                username text, password text, input text, shasum text, url text);
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
                reason text, observed_value double precision, operator text, proposed text, decision_seconds integer);
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
                operator text, note text);
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
            CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
                requested_by text, created_at timestamptz NOT NULL DEFAULT now(), released_at timestamptz,
                released_by text, """ + POINTS_COLUMN + """);
            CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
            INSERT INTO rule_versions VALUES ('v3', '{"rules": [{"id": "R002", "params": {}},
                {"id": "R006", "params": {"absorb_same_payload": {"window_hours": 24, "max_sources": 100}}}]}');
        """ + BLOCKLIST + GUARD)
        self.cur.execute("INSERT INTO incidents VALUES (%s, 'R006', 'SSH 키 심기', 'v3', 'critical', %s, %s, %s)",
                         (FIRST, OWN, T0, T0))
        for i, (ip, kind) in enumerate([("198.51.100.2", "absorbed"), ("198.51.100.2", "absorbed"),
                                        ("198.51.100.3", "absorbed"), ("198.51.100.4", "absorbed"),
                                        (OWN, "absorbed"), ("198.51.100.2", "suppressed")]):
            self.cur.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, via_key, rule_id,
                rule_version, actor_ip, first_ts, last_ts, signal_count, sessions)
                VALUES (%s, %s, %s, %s, 'R006', 'v3', %s, %s, %s, 1, ARRAY['s1'])""",
                (FIRST, f"m{i}", kind, "m0" if kind == "suppressed" else None, ip,
                 T0 + timedelta(minutes=i), T0 + timedelta(minutes=i)))
        # 198.51.100.4 는 다른 사건 차단으로 살아 있다(콘솔 24시간)
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method)
            VALUES ('198.51.100.4', 'console', 'R002|v3|other', now() + interval '1 hour', 'nft')""")

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def rows(self):
        self.cur.execute("SELECT host(actor_ip), reason, incident_key, expires_at, requested_by, method FROM blocklist")
        return {r[0]: r[1:] for r in self.cur.fetchall()}

    def test_gather_counts_absorbed_sources(self):
        ev = triage.gather(self.cur, FIRST, OWN, T0, T0, [], "v3")
        self.assertEqual((ev["absorbed"]["total"], ev["absorbed"]["sources"]), (6, 3))
        self.assertEqual([r[3] for r in ev["absorbed"]["sample"]], ["absorbed"] * 5 + ["suppressed"])
        self.assertEqual(ev["absorbed"]["state"], {"blocked": 0, "kept": 1, "skipped_total": 0, "skipped": [],
                                                   "unblockable": 0, "open": 2})
        self.assertTrue(triage.rule_absorbs(self.cur, "v3", "R006"))
        self.assertFalse(triage.rule_absorbs(self.cur, "v3", "R002"))

    def test_record_blocks_absorbed_sources_with_expiry(self):
        # record 는 커밋한다. 임시 테이블이라 연결을 닫으면 사라진다
        before = self.rows()["198.51.100.4"]
        done = triage.record(self.conn, FIRST, OWN, "threat", "키 심기 캠페인", 1.0, "han", None, True,
                             absorbed=True)
        rows = self.rows()
        tag = triage.absorbed_reason_tag(FIRST)
        self.assertEqual(set(rows), {OWN, "198.51.100.2", "198.51.100.3", "198.51.100.4"})
        now = datetime.now(timezone.utc)
        # 이 출발지의 triage 차단도 만료(기본 24시간)가 있고 요청자는 triage:<판정자> 다
        self.assertTrue(now + timedelta(hours=23) < rows[OWN][2] < now + timedelta(hours=25))
        self.assertEqual(rows[OWN][3], "triage:han")
        for ip in ("198.51.100.2", "198.51.100.3"):
            self.assertEqual((rows[ip][0], rows[ip][1], rows[ip][3], rows[ip][4]), (tag, FIRST, "triage:han", None))
            self.assertTrue(now + timedelta(hours=23) < rows[ip][2] < now + timedelta(hours=25))
        # 다른 사건으로 살아 있는 차단은 그 사건 것으로 두고 만료도 건드리지 않는다
        self.assertEqual(rows["198.51.100.4"], before)
        self.assertEqual({k: done[k] for k in ("blocked", "kept", "skipped_total", "unblockable")},
                         {"blocked": 2, "kept": 1, "skipped_total": 0, "unblockable": 0})
        self.assertEqual(done["follow_expires_at"], rows["198.51.100.2"][2])
        self.cur.execute("SELECT expires_at, requested_by FROM absorbed_blocks WHERE first_key = %s", (FIRST,))
        self.assertEqual(self.cur.fetchone(), (rows["198.51.100.2"][2], "triage:han"))
        self.cur.execute("SELECT note FROM actions WHERE action = 'block_ip'")
        self.assertEqual(self.cur.fetchone()[0], "키 심기 캠페인 [흡수 출발지 2곳 함께 차단 · "
                                                 "1곳은 다른 사건으로 차단 중 · 만료 전 새 흡수도 차단]")

    def test_record_skips_human_released_source(self):
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, released_by)
            VALUES ('198.51.100.3', 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin')""")
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True,
                             absorbed_hours=48)
        rows = self.rows()
        self.assertEqual(rows["198.51.100.3"][1], "R002|v3|x")      # 사람이 푼 행은 그대로
        self.assertEqual((done["blocked"], done["skipped"]), (1, ["198.51.100.3"]))
        with self.assertRaises(ValueError):
            triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True,
                          absorbed_hours=0)

    def test_triage_flow_asks_absorbed_block_with_expiry(self):
        # 판정 화면 흐름: 위협 → 근거(엔터) → 차단 y → 흡수 함께 차단 y. 흡수 차단은 --absorbed-hours 만료로 오른다
        self.cur.execute("""ALTER TABLE incidents ADD COLUMN signal_count integer DEFAULT 1,
            ADD COLUMN session_count integer DEFAULT 1, ADD COLUMN evidence jsonb, ADD COLUMN target text""")
        prompts = []
        answers = iter(["t", "", "y", "y"])

        def fake_input(prompt=""):
            prompts.append(prompt)
            return next(answers)
        with mock.patch("builtins.input", fake_input), mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, "R006", 5, "han", absorbed_hours=12)
        self.assertIn("흡수된 출발지 3곳도 함께 차단할까요? (만료 12시간", prompts[-1])
        rows = self.rows()
        now = datetime.now(timezone.utc)
        self.assertTrue(now + timedelta(hours=11) < rows["198.51.100.2"][2] < now + timedelta(hours=13))
        self.assertIn("흡수 2곳 함께(다른 사건 차단 1곳 유지)", out.getvalue())
        self.assertIn("다른 사건 차단 중 1곳", out.getvalue())

    def test_record_without_option_blocks_own_source_only(self):
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True)
        self.assertIsNone(done)
        self.assertEqual(set(self.rows()), {OWN, "198.51.100.4"})

    # ------------------------------------------------------------ 이 출발지 차단(이슈 #47)

    def row(self, ip):
        self.cur.execute("""SELECT expires_at, released_at, released_by, requested_by, method, enforced_at, enforce_note,
                                   reason, points FROM blocklist WHERE actor_ip = %s""", (ip,))
        return self.cur.fetchone()

    def last_action(self):
        self.cur.execute("SELECT action, note FROM actions ORDER BY id DESC LIMIT 1")
        return self.cur.fetchone()

    def test_record_block_hours_and_range(self):
        triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, block_hours=3)
        now = datetime.now(timezone.utc)
        self.assertTrue(now + timedelta(hours=2) < self.row(OWN)[0] < now + timedelta(hours=4))
        for hours in (0, 721):
            with self.subTest(hours=hours), self.assertRaises(ValueError):
                triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, block_hours=hours)

    def test_record_does_not_revive_human_release(self):
        # 사람이 푼 출발지: 해제 기록 · 사유 · 요청자를 그대로 두고 판정만 남긴다. 조치는 확인이고 까닭이 이력에 남는다
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, released_by,
            requested_by) VALUES (%s, 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin', 'op')""", (OWN,))
        before = self.row(OWN)
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True)
        self.assertEqual(self.row(OWN), before)
        self.assertIn("admin 가", done["refused"])
        self.assertIn("콘솔에서 차단", done["refused"])
        action, note = self.last_action()
        self.assertEqual(action, "acknowledge")
        self.assertTrue(note.startswith("근거 [차단 안 함 · admin 가"))
        self.cur.execute("SELECT verdict FROM verdicts")
        self.assertEqual(self.cur.fetchall(), [("threat",)])
        # 이 출발지를 올리지 못했으면 흡수 차단 · 후속 차단 약속도 걸지 않는다
        self.cur.execute("SELECT count(*) FROM absorbed_blocks")
        self.assertEqual(self.cur.fetchone()[0], 0)
        self.assertEqual(set(self.rows()), {OWN, "198.51.100.4"})

    def test_record_revives_release_without_person(self):
        # 누가 풀었는지 없는 해제 · 만료된 행은 새 요청이다. 관문 세 열은 두고 관문이 실제로 뺐는지는 집행기가 판단한다
        # (2026-10-01 결정 · 결정 2, test_다시_걸면_관문_포함_여부와_무관하게_관문_세_열을_둔다)
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, method,
            enforced_at, enforce_note) VALUES
            (%s, 'old', 'R002|v3|x', now() - interval '1 hour', NULL, 'nft', now() - interval '2 hours', '관문 반영 · abcd1234 · x'),
            ('198.51.100.7', 'old', 'R002|v3|y', now() + interval '1 hour', now(), 'nft', now(), '관문 반영 · abcd1234 · y')""",
                         (OWN,))
        self.assertIsNone(triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True))
        self.assertIsNone(triage.record(self.conn, "R002|v3|z", "198.51.100.7", "threat", "근거", 1.0, "han", None, True))
        now = datetime.now(timezone.utc)
        for ip, note in ((OWN, "관문 반영 · abcd1234 · x"), ("198.51.100.7", "관문 반영 · abcd1234 · y")):
            expires, released_at, released_by, who, method, enforced_at, enforce_note, reason, points = self.row(ip)
            self.assertIsNone(released_at)
            self.assertEqual((who, method, enforced_at is not None, enforce_note, reason, points),
                             ("triage:han", "nft", True, note, "근거", ["fw"]))    # 새 요청: 두 지점이던 옛 행도 규칙 기본값
            self.assertTrue(now + timedelta(hours=23) < expires < now + timedelta(hours=25))
        self.assertEqual(self.last_action()[0], "block_ip")

    def test_record_keeps_live_block_expiry_and_enforcement(self):
        # 살아 있는 콘솔 차단(72시간 · 관문 반영)에 다시 걸면 만료를 줄이지 않고 집행 정보도 그대로다(관문에 이미 있다).
        # 만료 없는 옛 차단은 그대로 없다(집행 제외로 남는다)
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method, enforced_at,
            enforce_note, requested_by) VALUES
            (%s, 'console', 'R002|v3|x', now() + interval '72 hours', 'fail2ban', now(), '관문 반영 · abcd1234 · x', 'op'),
            ('198.51.100.8', 'old', 'R002|v1|y', NULL, NULL, NULL, '집행 제외 · 만료 없음', NULL)""", (OWN,))
        live = self.row(OWN)
        triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True)
        triage.record(self.conn, "R002|v3|z", "198.51.100.8", "threat", "근거", 1.0, "han", None, True)
        got = self.row(OWN)
        self.assertEqual((got[0], got[4], got[5], got[6]), (live[0], live[4], live[5], live[6]))
        self.assertEqual(got[3], "triage:han")
        self.assertEqual(self.row("198.51.100.8")[0], None)
        self.assertEqual(self.row("198.51.100.8")[6], "집행 제외 · 만료 없음")

    def test_record_refused_by_exempt_net_keeps_verdict(self):
        # 차단 금지 대역(트리거 23514): 판정은 남고 차단 · 흡수 차단은 없다. 까닭에 걸린 대역과 메모가 보인다
        key = "R002|v3|192.168.50.21|x"
        self.cur.execute("INSERT INTO incidents VALUES (%s, 'R002', '침해 후 행위', 'v3', 'high', '192.168.50.21', %s, %s)",
                         (key, T0, T0))
        done = triage.record(self.conn, key, "192.168.50.21", "threat", "근거", 1.0, "han", None, True)
        self.assertEqual(done["refused"], "192.168.50.21 는 차단 금지 대역 192.168.0.0/16(사설 · 관리망 · 서비스망)에 들어 "
                                          "차단하지 않습니다. 인프라 · 사설 · 예약 주소는 막지 않습니다")
        self.assertIsNone(self.row("192.168.50.21"))
        self.assertEqual(self.last_action(), ("acknowledge", f"근거 [차단 안 함 · {done['refused']}]"))
        self.cur.execute("SELECT verdict FROM verdicts WHERE incident_key = %s", (key,))
        self.assertEqual(self.cur.fetchone(), ("threat",))
        # 관문 EIP 는 사설 대역이 아니어도 막지 않는다
        done = triage.record(self.conn, key, "15.164.37.49", "threat", "근거", 1.0, "han", None, True)
        self.assertIn("15.164.37.49/32(AWS 관문 EIP)", done["refused"])

    def test_gather_and_flow_do_not_offer_block_for_exempt_or_released(self):
        # 판정 화면이 까닭을 미리 보이고 차단을 묻지 않는다. 판정은 남고 이력에 까닭이 붙는다
        self.cur.execute("""ALTER TABLE incidents ADD COLUMN signal_count integer DEFAULT 1,
            ADD COLUMN session_count integer DEFAULT 1, ADD COLUMN evidence jsonb, ADD COLUMN target text""")
        key = "R006|v3|15.164.37.49|x"
        self.cur.execute("INSERT INTO incidents (incident_key, rule_id, rule_name, rule_version, severity, actor_ip, "
                         "first_ts, last_ts) VALUES (%s, 'R006', 'SSH 키 심기', 'v3', 'critical', '15.164.37.49', %s, %s)",
                         (key, T0, T0))
        ev = triage.gather(self.cur, key, "15.164.37.49", T0, T0, [], "v3")
        self.assertEqual(ev["exempt"], ("15.164.37.49/32", "AWS 관문 EIP"))
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, released_by)
            VALUES (%s, 'console', 'x', now() + interval '1 hour', now(), 'admin')""", (OWN,))
        ev = triage.gather(self.cur, FIRST, OWN, T0, T0, [], "v3")
        self.assertEqual(ev["released"][0], "admin")
        self.assertFalse(ev["blocked"])
        prompts = []
        answers = iter(["t", "", "t", ""])

        def fake_input(prompt=""):
            prompts.append(prompt)
            return next(answers)
        with mock.patch("builtins.input", fake_input), mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, "R006", 5, "han")
        self.assertFalse(any("차단 목록에 올릴까요" in p for p in prompts))
        self.assertIn("차단하지 않습니다: 15.164.37.49 는 차단 금지 대역 15.164.37.49/32(AWS 관문 EIP)", out.getvalue())
        self.assertIn("차단하지 않습니다: admin 가", out.getvalue())
        self.cur.execute("SELECT count(*) FROM verdicts WHERE verdict = 'threat'")
        self.assertEqual(self.cur.fetchone()[0], 2)
        self.cur.execute("SELECT note FROM actions WHERE incident_key = %s", (key,))
        self.assertIn("[차단 안 함 · 15.164.37.49 는 차단 금지 대역", self.cur.fetchone()[0])

    def test_flow_asks_block_with_hours(self):
        self.cur.execute("""ALTER TABLE incidents ADD COLUMN signal_count integer DEFAULT 1,
            ADD COLUMN session_count integer DEFAULT 1, ADD COLUMN evidence jsonb, ADD COLUMN target text""")
        prompts = []
        answers = iter(["t", "", "y", "n"])

        def fake_input(prompt=""):
            prompts.append(prompt)
            return next(answers)
        with mock.patch("builtins.input", fake_input), mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, "R006", 5, "han", block_hours=6)
        self.assertIn("차단 목록에 올릴까요? (만료 6시간 · 차단 지점 내부 방화벽)", prompts[2])
        self.assertIn("  차단 지점 내부 방화벽\n", out.getvalue())
        self.assertIn("기록됨: 실제 위협  · 차단 6시간", out.getvalue())
        now = datetime.now(timezone.utc)
        self.assertTrue(now + timedelta(hours=5) < self.row(OWN)[0] < now + timedelta(hours=7))
        self.assertEqual(self.row(OWN)[8], ["fw"])                           # R006 → 내부 방화벽만

    def test_flow_says_legacy_block_without_expiry_stays_unenforced(self):
        # 만료 없는 옛 차단(운영 13건 꼴 · 집행 제외)이 살아 있는 출발지. 다시 걸어도 만료를 줄이지 않으므로 만료가 그대로 없고
        # 관문 집행에서 빠진다. 판정 화면은 묻기 전에 알리고, 기록 뒤에 '차단 N시간' 이라 하지 않으며 이력에 까닭을 남긴다
        self.cur.execute("""ALTER TABLE incidents ADD COLUMN signal_count integer DEFAULT 1,
            ADD COLUMN session_count integer DEFAULT 1, ADD COLUMN evidence jsonb, ADD COLUMN target text""")
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, enforce_note)
            VALUES (%s, 'v1 triage', 'R002|v1|x', '집행 제외 · 만료 없음')""", (OWN,))
        ev = triage.gather(self.cur, FIRST, OWN, T0, T0, [], "v3")
        self.assertTrue(ev["blocked"])
        self.assertTrue(ev["no_expiry"])
        prompts = []
        answers = iter(["t", "", "y", "n"])

        def fake_input(prompt=""):
            prompts.append(prompt)
            return next(answers)
        with mock.patch("builtins.input", fake_input), mock.patch("sys.stdout", io.StringIO()) as out:
            triage.triage(self.conn, "R006", 5, "han", block_hours=6)
        text = out.getvalue()
        self.assertIn("[이미 차단됨 · 만료 없음 · 관문 집행 제외]", text)
        self.assertIn(f"차단     {triage.NO_EXPIRY_TEXT}", text)
        self.assertIn("차단 목록에 올릴까요?", prompts[2])
        self.assertNotIn("차단 6시간", text)
        self.assertIn(f"기록됨: 실제 위협  · 차단 요청 유지({triage.NO_EXPIRY_TEXT})", text)
        self.assertIsNone(self.row(OWN)[0])
        self.assertEqual(self.last_action(), ("block_ip", f"실제 위협 [{triage.NO_EXPIRY_TAG}]"))
        # record 도 까닭을 돌려준다. 새 차단 · 만료가 있는 살아 있는 차단은 전처럼 None 이다
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True)
        self.assertEqual(done, {"no_expiry": triage.NO_EXPIRY_TEXT})
        self.assertIsNone(triage.record(self.conn, "R002|v3|z", "198.51.100.9", "threat", "근거", 1.0, "han", None, True))

    def test_exempt_unreadable_degrades_to_constants(self):
        # 역할 블록(20260924_db_roles.sql)만 다시 적용하면 콘솔의 block_exempt 읽기가 사라진다. 표가 있어도 읽지 못하면 코드 상수만
        # 거르고 사유는 비운다. 판정 화면(gather)이 권한 오류로 죽지 않는다. 읽지 못하는 역할로 바꿔 본다(슈퍼유저 연결일 때만).
        # 역할은 이 트랜잭션 안에서 만들어 tearDown 의 rollback 이 지운다
        self.cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        if not self.cur.fetchone()[0]:
            self.skipTest("시험 역할을 만들 수 없는 연결")
        role = f"t47_triage_{os.getpid()}_{secrets.token_hex(3)}"
        self.cur.execute(f"CREATE ROLE {role} NOLOGIN NOINHERIT")
        self.cur.execute(f"GRANT SELECT ON incidents, events, incident_absorbed, blocklist TO {role}")
        self.cur.execute(f"SET ROLE {role}")
        try:
            self.cur.execute("SELECT to_regclass('block_exempt') IS NOT NULL")
            self.assertTrue(self.cur.fetchone()[0])                                # 표는 보이지만
            self.assertFalse(triage.has_exempt_table(self.cur))                     # 읽지 못한다
            self.assertEqual(triage.block_nets(self.cur), triage.NO_BLOCK_NETS)
            self.assertIsNone(triage.exempt_of(self.cur, "15.164.37.49"))
            ev = triage.gather(self.cur, FIRST, "15.164.37.49", T0, T0, [], "v3")
            self.assertIsNone(ev["exempt"])
            self.assertEqual(ev["absorbed"]["state"]["unblockable"], 0)            # 관문 EIP 는 상수에 없다(트리거가 막는다)
        finally:
            self.cur.execute("RESET ROLE")
        self.assertTrue(triage.has_exempt_table(self.cur))
        self.assertEqual(triage.exempt_of(self.cur, "15.164.37.49"), ("15.164.37.49/32", "AWS 관문 EIP"))
        self.assertEqual(triage.refused_text("15.164.37.49", "blocklist_exempt", None),
                         "15.164.37.49 는 차단 금지 대역에 들어 차단하지 않습니다. 인프라 · 사설 · 예약 주소는 막지 않습니다")

    def test_absorbed_block_skips_db_exempt_and_net_rows(self):
        # 흡수 차단은 코드 상수에 없는 DB 금지 대역(관문 EIP)과 대역 주소를 미리 빼 트리거에 걸리지 않는다
        for i, ip in enumerate(("15.164.37.49", "198.51.100.64/26")):
            self.cur.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version,
                actor_ip, first_ts, last_ts, signal_count) VALUES (%s, %s, 'absorbed', 'R006', 'v3', %s, %s, %s, 1)""",
                             (FIRST, f"x{i}", ip, T0, T0))
        self.assertIn("15.164.37.49/32", triage.block_nets(self.cur))
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True)
        self.assertEqual((done["blocked"], done["unblockable"]), (2, 2))
        self.assertNotIn("15.164.37.49", self.rows())

    # ------------------------------------------------------------ 적용 지점(이슈 #77)

    def points(self):
        self.cur.execute("SELECT host(actor_ip), points FROM blocklist")
        return dict(self.cur.fetchall())

    def r004(self, key, ip):
        self.cur.execute("INSERT INTO incidents VALUES (%s, 'R004', '프록시 남용 시도', 'v3', 'high', %s, %s, %s)",
                         (key, ip, T0, T0))

    def test_record_은_사건_규칙의_기본_지점으로_올린다(self):
        key4 = "R004|v3|192.0.2.4|x"
        self.r004(key4, "192.0.2.4")
        triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True)             # R006
        triage.record(self.conn, key4, "192.0.2.4", "threat", "근거", 1.0, "han", None, True)     # R004
        triage.record(self.conn, "R002|v3|z", "198.51.100.9", "threat", "근거", 1.0, "han", None, True)  # 사건 없음
        got = self.points()
        self.assertEqual((got[OWN], got["192.0.2.4"], got["198.51.100.9"]), (["fw"], ["gateway", "fw"], ["fw"]))
        # 차단하지 않는 판정은 지점도 읽지 않는다
        triage.record(self.conn, FIRST, OWN, "non_actionable", "근거", 1.0, "han", None, False)
        self.assertEqual(self.points()[OWN], ["fw"])

    def test_살아_있는_차단은_넓히기만_하고_새_요청은_규칙_기본값이다(self):
        key4 = "R004|v3|198.51.100.11|x"
        self.r004(key4, "198.51.100.11")
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, points) VALUES
            (%s, 'console', 'R004|v3|x', now() + interval '72 hours', NULL, '{gateway,fw}'),
            ('198.51.100.11', 'console', 'R001|v3|y', now() + interval '1 hour', NULL, '{fw}'),
            ('198.51.100.12', 'old', 'R004|v3|y', now() - interval '1 hour', NULL, '{gateway,fw}'),
            ('198.51.100.13', 'old', 'R004|v3|y', now() + interval '1 hour', now(), '{gateway,fw}')""", (OWN,))
        # 좁히기는 트리거가 거부한다(흉내가 실제로 막는지 먼저 본다)
        self.cur.execute("SAVEPOINT narrow")
        with self.assertRaises(psycopg2.Error) as cm:
            self.cur.execute("UPDATE blocklist SET points = '{fw}' WHERE actor_ip = %s", (OWN,))
        self.assertEqual((cm.exception.pgcode, cm.exception.diag.constraint_name), ("23514", "blocklist_points_narrow"))
        self.cur.execute("ROLLBACK TO SAVEPOINT narrow")
        live = self.row(OWN)
        # 살아 있는 두 지점 차단에 R006(내부 방화벽) 판정으로 다시 걸어도 두 지점이 남는다(만료 · 집행 정보도 그대로)
        self.assertIsNone(triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True))
        self.assertEqual((self.row(OWN)[0], self.row(OWN)[8]), (live[0], ["gateway", "fw"]))
        # 살아 있는 내부 방화벽 차단에 R004 로 다시 걸면 관문까지 넓어진다
        triage.record(self.conn, key4, "198.51.100.11", "threat", "근거", 1.0, "han", None, True)
        self.assertEqual(self.points()["198.51.100.11"], ["gateway", "fw"])
        # 만료된 행 · 누가 풀었는지 없는 해제는 새 요청이라 규칙 기본값(좁아져도 된다)
        for ip in ("198.51.100.12", "198.51.100.13"):
            with self.subTest(ip=ip):
                self.assertIsNone(triage.record(self.conn, f"R006|v3|{ip}", ip, "threat", "근거", 1.0, "han", None, True))
                self.assertEqual(self.points()[ip], ["fw"])

    def test_사람이_푼_행은_지점도_그대로다(self):
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, released_at, released_by, points)
            VALUES ('192.0.2.4', 'console', 'R002|v3|x', now() + interval '1 hour', now(), 'admin', '{fw}')""")
        key4 = "R004|v3|192.0.2.4|x"
        self.r004(key4, "192.0.2.4")
        before = self.row("192.0.2.4")
        self.assertIn("admin 가", triage.record(self.conn, key4, "192.0.2.4", "threat", "근거", 1.0, "han", None,
                                                True)["refused"])
        self.assertEqual(self.row("192.0.2.4"), before)

    def test_흡수_함께_차단과_약속은_규칙_지점이고_kept_는_그대로다(self):
        # R006 첫 사건: 흡수 출발지 · 약속 모두 내부 방화벽. 내부 방화벽만인 kept 행은 넓히지 않는다
        self.cur.execute("DELETE FROM blocklist WHERE actor_ip = '198.51.100.4'")
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method, points)
            VALUES ('198.51.100.4', 'console', 'R002|v3|other', now() + interval '1 hour', 'nft', '{fw}')""")
        kept = self.rows()["198.51.100.4"]
        done = triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True)
        self.assertEqual((done["blocked"], done["kept"]), (2, 1))
        self.assertEqual(self.points(), {OWN: ["fw"], "198.51.100.2": ["fw"], "198.51.100.3": ["fw"],
                                         "198.51.100.4": ["fw"]})
        self.assertEqual(self.rows()["198.51.100.4"], kept)
        self.cur.execute("SELECT points FROM absorbed_blocks WHERE first_key = %s", (FIRST,))
        self.assertEqual(self.cur.fetchone(), (["fw"],))

    def test_관문을_포함하면_약속_흡수_행_kept_의_지점을_넓힌다(self):
        # R004 첫 사건. 살아 있는 약속(내부 방화벽 · 48시간)과 이 사건의 흡수 차단(내부 방화벽 · 72시간), 다른 사건 차단(kept,
        # 내부 방화벽 · 1시간)이 있다. 약속은 합집합 · 만료 그대로, 흡수 행은 넓히고 만료는 늦은 쪽, kept 는 지점만 넓힌다
        key4, own4 = "R004|v3|192.0.2.4|x", "192.0.2.4"
        tag = triage.absorbed_reason_tag(key4)
        self.r004(key4, own4)
        for i, ip in enumerate(("198.51.100.21", "198.51.100.22", "198.51.100.23")):
            self.cur.execute("""INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version,
                actor_ip, first_ts, last_ts, signal_count) VALUES (%s, %s, 'absorbed', 'R004', 'v3', %s, %s, %s, 1)""",
                             (key4, f"p{i}", ip, T0, T0))
        self.cur.execute("""INSERT INTO absorbed_blocks (first_key, expires_at, requested_by, points)
            VALUES (%s, now() + interval '48 hours', 'triage:kim', '{fw}')""", (key4,))
        self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method, requested_by,
            enforced_at, points) VALUES
            ('198.51.100.21', 'console', 'R002|v3|other', now() + interval '1 hour', 'nft', 'op', now(), '{fw}'),
            ('198.51.100.23', %s, %s, now() + interval '72 hours', NULL, 'triage:kim', NULL, '{fw}')""", (tag, key4))
        self.cur.execute("SELECT expires_at FROM absorbed_blocks WHERE first_key = %s", (key4,))
        promise = self.cur.fetchone()[0]
        before = self.rows()
        done = triage.record(self.conn, key4, own4, "threat", "근거", 1.0, "han", None, True, absorbed=True)
        after = self.rows()
        self.assertEqual({k: done[k] for k in ("blocked", "kept")}, {"blocked": 2, "kept": 1})
        got = self.points()
        for ip in (own4, "198.51.100.21", "198.51.100.22", "198.51.100.23"):
            with self.subTest(ip=ip):
                self.assertEqual(got[ip], ["gateway", "fw"])
        self.assertEqual(after["198.51.100.21"], before["198.51.100.21"])   # kept: 만료 · 근거 사건 · 요청자 · 집행 그대로
        self.assertEqual(after["198.51.100.23"], before["198.51.100.23"])   # 이 사건 흡수 행: 만료는 줄지 않는다(72시간)
        self.assertEqual(after["198.51.100.22"][2], promise)                # 새 흡수 행은 약속의 만료
        self.cur.execute("SELECT points, expires_at, requested_by FROM absorbed_blocks WHERE first_key = %s", (key4,))
        self.assertEqual(self.cur.fetchone(), (["gateway", "fw"], promise, "triage:kim"))

    def test_다시_걸면_관문_포함_여부와_무관하게_관문_세_열을_둔다(self):
        # 만료된 두 지점 행(관문 확인 남음)을 다시 걸면 관문 세 열을 둔다(2026-10-01 결정 · 결정 2). 관문이 실제로 뺐다고 확인되면 집행기가
        # 비우고(unenforced 도 그때), 아니면 새 보고로 기존 차단 유지 · 연속성 확인 불가를 적는다(결정 3, enforcer RearmPgTest)
        #   R006(내부 방화벽) 판정: 이 출발지 · 흡수 출발지. R004(관문 포함) 판정: 이 출발지. 관문을 포함한 흡수 다시 걸기는 문장으로 본다
        key4, ip4 = "R004|v3|198.51.100.11|x", "198.51.100.11"
        self.r004(key4, ip4)
        stamp = datetime(2026, 9, 30, 1, tzinfo=timezone.utc)
        applied = "관문 반영 · abcd1234 · x"
        for ip in (OWN, "198.51.100.2", "198.51.100.3", ip4):
            self.cur.execute("""INSERT INTO blocklist (actor_ip, reason, incident_key, expires_at, method, enforced_at,
                enforce_note) VALUES (%s, 'old', 'R002|v3|x', now() - interval '1 second', 'nft', %s, %s)""",
                             (ip, stamp, applied))
        self.cur.execute("UPDATE blocklist SET released_at = now() WHERE actor_ip = '198.51.100.3'")   # 누가 풀었는지 없는 해제
        triage.record(self.conn, FIRST, OWN, "threat", "근거", 1.0, "han", None, True, absorbed=True)   # R006
        triage.record(self.conn, key4, ip4, "threat", "근거", 1.0, "han", None, True)                   # R004
        self.cur.execute("UPDATE blocklist SET expires_at = now() - interval '1 second' WHERE actor_ip = '198.51.100.2'")
        self.cur.execute(triage.BLOCK_ABSORBED_SQL, {"key": FIRST, "reason": triage.absorbed_reason_tag(FIRST), "ip": OWN,
                                                     "who": "triage:han", "expires": datetime.now(timezone.utc) + timedelta(days=1),
                                                     "nets": triage.NO_BLOCK_NETS, "points": ["gateway", "fw"]})
        now = datetime.now(timezone.utc)
        # .2 는 만료 뒤 관문을 포함해 다시 걸었고, .3 은 살아 있어 지점만 넓혔다(세 열은 원래 두는 경우)
        for ip, points in ((OWN, ["fw"]), ("198.51.100.2", ["gateway", "fw"]), ("198.51.100.3", ["gateway", "fw"]),
                           (ip4, ["gateway", "fw"])):
            with self.subTest(ip=ip):
                expires, released_at, _, _, method, enforced_at, note, _, got = self.row(ip)
                self.assertEqual((got, released_at, (method, enforced_at, note)), (points, None, ("nft", stamp, applied)))
                self.assertGreater(expires, now)


if __name__ == "__main__":
    unittest.main()
