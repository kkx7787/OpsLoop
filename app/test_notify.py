"""알림 채널 주소 검증 · 메시지 틀 · Teams 카드 · 재시도 일정 · 마스킹 · 권한 시험. DB · 외부 네트워크 없이 돈다.
리다이렉트 시험만 127.0.0.1 에 잠깐 HTTP 서버를 띄운다. 비신뢰 값 정리(이슈 #41)도 여기서 본다."""
import json
import socket
import ssl
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import notifier
import notify
from notify import ChannelIn, ChannelUpdate, public_channel

NOW = datetime(2026, 9, 24, 3, 0, tzinfo=timezone.utc)
# Power Automate 가 지금 발급하는 Workflows 트리거 주소 모양
TEAMS_HOST = "default0123456789abcdef0123456789ab.cd.environment.api.powerplatform.com"
TEAMS_URL = (f"https://{TEAMS_HOST}:443/powerautomate/automations/direct/workflows/0a1b2c/triggers/manual/paths/invoke"
             "?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SECRETSIG")
CHANNEL = {"kind": "teams", "template_header": "[OpsLoop] {event_label} {count}건",
           "template_item": "{rule_id} {rule_name} · {severity} · {who} · {elapsed}"}


def card_texts(body):
    """Teams 카드 본문의 글을 덩이 순서대로 꺼낸다. 첫째가 머리말, 나머지가 항목 줄이다."""
    return ["".join(run["text"] for run in block["inlines"]) for block in body["attachments"][0]["content"]["body"]]


def incident(n, severity="high"):
    return {"incident_key": f"R00{n}|v2|192.0.2.{n}|{n}", "rule_id": f"R00{n}", "rule_name": f"규칙 {n}", "severity": severity,
            "who": f"192.0.2.{n}", "first_ts": (NOW - timedelta(minutes=12 * n)).isoformat()}


class UrlTests(unittest.TestCase):
    def test_teams_accepts_power_platform_workflow_hosts_only(self):
        self.assertEqual(notifier.validate_url("teams", TEAMS_URL), TEAMS_HOST)
        self.assertEqual(notifier.validate_url("teams", TEAMS_URL.replace(":443", "").replace(TEAMS_HOST, TEAMS_HOST.upper() + ".")), TEAMS_HOST)
        for url in [TEAMS_URL.replace("https", "http"), "https://environment.api.powerplatform.com/x",
                    "https://evil.com/x.environment.api.powerplatform.com", "https://x.environment.api.powerplatform.com.evil.com/x",
                    f"https://user:pw@{TEAMS_HOST}/x", "https://hooks.example.com/x", "https://10.0.0.1/x", "", "https://",
                    f"ftp://{TEAMS_HOST}/x", "https://[::1/x"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                notifier.validate_url("teams", url)

    def test_teams_rejects_retired_logic_azure_and_office_connector_hosts_with_guidance(self):
        for url in ["https://prod-12.koreacentral.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x",
                    "https://contoso.webhook.office.com/webhookb2/x@y/IncomingWebhook/z"]:
            with self.subTest(url=url), self.assertRaises(ValueError) as error:
                notifier.validate_url("teams", url)
            self.assertIn("environment.api.powerplatform.com", str(error.exception))
            self.assertIn("다시 저장", str(error.exception))

    def test_webhook_rejects_private_linklocal_localhost_userinfo_and_http(self):
        self.assertEqual(notifier.validate_url("webhook", "https://hooks.example.com/opsloop?token=x"), "hooks.example.com")
        self.assertEqual(notifier.validate_url("webhook", "https://8.8.8.8/hook"), "8.8.8.8")
        for url in ["http://hooks.example.com/x", "https://10.0.0.1/x", "https://192.168.70.254:8443/x", "https://172.16.0.9/x",
                    "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://[::1]/x", "https://[fd00::1]/x",
                    "https://[fe80::1]/x", "https://localhost/x", "https://api.localhost/x", "https://user:pw@hooks.example.com/x",
                    "https://user@hooks.example.com/x", "https://0.0.0.0/x", "https://224.0.0.1/x", "x" * 2049]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                notifier.validate_url("webhook", url)
        with self.assertRaises(ValueError):
            notifier.validate_url("email", "https://hooks.example.com/x")

    def test_webhook_rejects_numeric_shorthand_and_non_global_ranges(self):
        """해석기(inet_aton)가 IP 로 읽는 줄임 · 16진 · 8진 · 정수 표기와 비전역 대역도 거른다."""
        for url in ["https://3232253694/x", "https://127.1/x", "https://0x7f.1/x", "https://2130706433/x", "https://0x7f000001/x",
                    "https://192.168.070.254/x", "https://0177.0.0.1/x", "https://127.0.0.1./x", "https://localhost./x",
                    "https://api.localhost./x", "https://100.64.0.1/x", "https://192.0.2.10/x", "https://198.18.0.1/x",
                    "https://[::ffff:127.0.0.1]/x", "https://[::ffff:c0a8:46fe]/x", "https://[2001:db8::1]/x", "https://0x/x"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                notifier.validate_url("webhook", url)
        # 숫자 이름표만으로 된 것이 아니면 이름이다(해석하지 않는다)
        for url, host in [("https://1e100.net/x", "1e100.net"), ("https://123.example.com/x", "123.example.com"),
                          ("https://face.bad/x", "face.bad"), ("https://hooks.example.com./x", "hooks.example.com"),
                          ("https://[2606:4700:4700::1111]/x", "2606:4700:4700::1111")]:
            with self.subTest(url=url):
                self.assertEqual(notifier.validate_url("webhook", url), host)

    def test_error_messages_never_echo_the_url(self):
        for kind, url in [("teams", "https://user:pw@hooks.example.com/SECRET"), ("webhook", "http://10.0.0.1/SECRET")]:
            with self.assertRaises(ValueError) as error:
                notifier.validate_url(kind, url)
            self.assertNotIn("SECRET", str(error.exception))


class TemplateTests(unittest.TestCase):
    def test_render_substitutes_known_placeholders_only(self):
        values = {"rule_id": "R001", "rule_name": "다중 로그인", "severity": "high", "who": "192.0.2.8", "elapsed": "12분 전"}
        self.assertEqual(notifier.render(CHANNEL["template_item"], values), "R001 다중 로그인 · high · 192.0.2.8 · 12분 전")
        self.assertEqual(notifier.render("{unknown} {rule_id} {first_ts}", values), "{unknown} R001 -")
        self.assertEqual(notifier.render("{count}건 {severity_counts}", {"count": 0, "severity_counts": ""}), "0건 -")

    def test_render_is_plain_substitution_not_str_format(self):
        values = {"rule_id": "R001", "count": 3}
        self.assertEqual(notifier.render("{count:>5}|{rule_id.__class__}|{__class__}|{0}|{}", values),
                         "{count:>5}|{rule_id.__class__}|{__class__}|{0}|{}")
        self.assertEqual(notifier.render("{{count}}", values), "{3}")

    def test_validate_template_rejects_format_specifiers_and_blank(self):
        self.assertEqual(notifier.validate_template("[OpsLoop] {event_label} {count}건"), "[OpsLoop] {event_label} {count}건")
        self.assertEqual(notifier.validate_template("{unknown} 그대로"), "{unknown} 그대로")
        for template in ["{count:>5}", "{rule_id!r}", "{rule_id.__class__}", "{rule_id[0]}", "{0}", "{}", "", "   ", "x" * 301]:
            with self.subTest(template=template), self.assertRaises(ValueError):
                notifier.validate_template(template)

    def test_elapsed_and_kst(self):
        self.assertEqual(notifier.elapsed_text(NOW - timedelta(seconds=30), NOW), "방금")
        self.assertEqual(notifier.elapsed_text((NOW - timedelta(minutes=12)).isoformat(), NOW), "12분 전")
        self.assertEqual(notifier.elapsed_text("2026-09-23T23:59:59.9+00:00", NOW), "3시간 전")
        self.assertEqual(notifier.elapsed_text(NOW - timedelta(days=2), NOW), "2일 전")
        self.assertEqual(notifier.elapsed_text(None, NOW), "-")
        self.assertEqual(notifier.elapsed_text("bad", NOW), "-")
        self.assertEqual(notifier.kst_text("2026-09-24T03:05:00+00:00"), "2026-09-24 12:05")


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", {"OPSLOOP_CONSOLE_URL": "http://console.test:8443/"})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_header_once_items_capped_and_link_last(self):
        payloads = [incident(n % 9 + 1, "critical" if n % 2 else "high") for n in range(25)]
        message = notifier.build_message(CHANNEL, "incident.created", payloads, NOW)
        self.assertEqual(message["title"], "[OpsLoop] 새 인시던트 25건")
        self.assertEqual(len(message["lines"]), 21)
        self.assertEqual(message["lines"][-1], "외 5건")
        self.assertEqual(message["link"], "http://console.test:8443/incidents")
        header = notifier.build_message(CHANNEL | {"template_header": "{severity_counts}"}, "incident.created", payloads, NOW)
        self.assertEqual(header["title"], "critical 12 · high 13")

    def test_test_message_links_to_alerts_and_daily_channel_uses_summary_shape(self):
        message = notifier.build_message(CHANNEL, "test", [notifier.example_payload(NOW)], NOW)
        self.assertEqual(message["link"], "http://console.test:8443/alerts")
        self.assertEqual(message["title"], "[OpsLoop] 시험 발송 1건")
        self.assertEqual(message["lines"], ["R001 예시 규칙 · high · 192.0.2.8 · 12분 전"])
        daily = CHANNEL | {"grade": "daily"}
        message = notifier.build_message(daily, "test", [notifier.example_payload(NOW, "daily")], NOW)
        self.assertEqual(message["title"], "[OpsLoop] 시험 발송 4건")
        self.assertEqual(message["lines"], ["미판정 4건 · 최고 경과 3시간 전 · 목표 초과 1건 · 최근 24시간 사건 9건"])
        self.assertEqual(message["link"], "http://console.test:8443/alerts")
        silent = [{"node_id": f"web-0{n}", "hostname": f"web-0{n}", "since": NOW.isoformat()} for n in (1, 2)]
        self.assertEqual(notifier.build_message(CHANNEL, "node.silent", silent, NOW)["link"], "http://console.test:8443/nodes")

    def test_single_item_links_to_detail_and_fills_header(self):
        channel = CHANNEL | {"template_header": "{event_label} {rule_id} {who} {first_ts}"}
        message = notifier.build_message(channel, "pending.overdue", [incident(1)], NOW)
        self.assertEqual(message["title"], "판정 지연 R001 192.0.2.1 2026-09-24 11:48")
        self.assertEqual(message["link"], "http://console.test:8443/incidents/R001%7Cv2%7C192.0.2.1%7C1")
        self.assertEqual(message["lines"], ["R001 규칙 1 · high · 192.0.2.1 · 12분 전"])

    def test_node_silent_and_daily_summary(self):
        silent = {"node_id": "web-01", "hostname": "opsloop-web", "since": (NOW - timedelta(minutes=25)).isoformat()}
        message = notifier.build_message(CHANNEL, "node.silent", [silent], NOW)
        self.assertEqual(message["lines"], ["- opsloop-web · - · node:web-01 · 25분 전"])
        self.assertEqual(message["link"], "http://console.test:8443/nodes")
        daily = {"date": "2026-09-24", "pending_total": 4, "oldest_seconds": 7200, "overdue": 2, "incidents_24h": 9,
                 "severity_counts": "high 1 · low 3"}
        message = notifier.build_message(CHANNEL | {"template_header": "{event_label} {count} {severity_counts}"}, "daily.summary", [daily], NOW)
        self.assertEqual(message["title"], "일일 요약 4 high 1 · low 3")
        self.assertEqual(message["lines"], ["미판정 4건 · 최고 경과 2시간 전 · 목표 초과 2건 · 최근 24시간 사건 9건"])

    def test_teams_card_shape(self):
        body = notifier.build_body(CHANNEL, "incident.created", [incident(1), incident(2)], NOW)
        self.assertEqual(body["type"], "message")
        attachment = body["attachments"][0]
        self.assertEqual(attachment["contentType"], "application/vnd.microsoft.card.adaptive")
        self.assertIsNone(attachment["contentUrl"])
        card = attachment["content"]
        self.assertEqual((card["$schema"], card["type"], card["version"]),
                         ("http://adaptivecards.io/schemas/adaptive-card.json", "AdaptiveCard", "1.4"))
        # 마크다운을 해석하지 않는 RichTextBlock · TextRun 이다. 항목 줄은 줄마다 한 덩이다
        self.assertEqual(card["body"][0], {"type": "RichTextBlock", "inlines": [
            {"type": "TextRun", "text": "[OpsLoop] 새 인시던트 2건", "weight": "Bolder", "size": "Medium"}]})
        self.assertEqual(card["body"][1:], [
            {"type": "RichTextBlock", "inlines": [{"type": "TextRun", "text": "R001 규칙 1 · high · 192.0.2.1 · 12분 전"}]},
            {"type": "RichTextBlock", "inlines": [{"type": "TextRun", "text": "R002 규칙 2 · high · 192.0.2.2 · 24분 전"}]}])
        self.assertEqual(card_texts(body), ["[OpsLoop] 새 인시던트 2건", "R001 규칙 1 · high · 192.0.2.1 · 12분 전",
                                            "R002 규칙 2 · high · 192.0.2.2 · 24분 전"])
        self.assertEqual(card["actions"], [{"type": "Action.OpenUrl", "title": "콘솔에서 보기", "url": "http://console.test:8443/incidents"}])

    def test_webhook_body_shape(self):
        body = notifier.build_body(CHANNEL | {"kind": "webhook"}, "incident.created", [incident(1)], NOW)
        self.assertEqual(body["source"], "opsloop")
        self.assertEqual(body["event"], "incident.created")
        self.assertEqual(body["title"], "[OpsLoop] 새 인시던트 1건")
        self.assertEqual(body["lines"], ["R001 규칙 1 · high · 192.0.2.1 · 12분 전"])
        self.assertEqual(body["items"], [incident(1)])
        self.assertEqual(body["console_url"], "http://console.test:8443/incidents/R001%7Cv2%7C192.0.2.1%7C1")


# 비신뢰 값 표본(이슈 #41). 지금 알림 값은 공격자가 정하지 못하지만 규칙이 늘어 닿게 되어도 막히는지 본다.
HOSTILE = {
    "md_link": "[눌러 확인](https://b.attacker.test/login)",
    "md_image": "![i](https://c.attacker.test/p.png)",
    "mention": "<at>admin</at>",
    "rlo": "admin\u202egnp.exe",
    "zwsp": "ad\u200bmin",
    "crlf": "줄1\r\n- 가짜 항목\n**굵게**",
    "long": "A" * 10000,
}


class HostileValueTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", {"OPSLOOP_CONSOLE_URL": "http://console.test:8443"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.channel = CHANNEL | {"template_header": "[OpsLoop] {event_label} {rule_name} {who} {incident_key}",
                                  "template_item": "{rule_id} {rule_name} · {severity} · {who} · {incident_key} · {elapsed}"}

    def payload(self, value):
        return {"incident_key": value, "rule_id": "R001", "rule_name": value, "severity": value, "who": value,
                "first_ts": (NOW - timedelta(minutes=5)).isoformat()}

    def assert_clean(self, text, label):
        for ch in ("\u202e", "\u200b", "\r", "\n", "\t"):
            self.assertNotIn(ch, text, f"{label}: {ch!r}")
        self.assertNotIn("A" * (notifier.VALUE_MAX + 1), text, label)

    def test_clean_value_rules(self):
        clean = notifier.clean_value
        self.assertEqual(clean("admin\u202egnp.exe"), "admin⟨U+202E⟩gnp.exe")
        self.assertEqual(clean("ad\u200bmin"), "ad⟨U+200B⟩min")
        self.assertEqual(clean("줄1\u2028줄2\u2029"), "줄1⟨U+2028⟩줄2⟨U+2029⟩")
        # 기본 무시 문자(한글 채움 · 결합 자소 연결 · 이형 선택자)와 점자 빈칸도 아무것도 그리지 않는다
        self.assertEqual(clean("adm\u3164in\u034f\ufe0f\U000e0100\u2800"),
                         "adm⟨U+3164⟩in⟨U+034F⟩⟨U+FE0F⟩⟨U+E0100⟩⟨U+2800⟩")
        self.assertEqual(clean("a\r\nb\tc\nd"), "a⟨U+000D⟩ b c d")
        self.assertEqual(clean("\x1b[31m빨강\x9b2K"), "⟨U+001B⟩[31m빨강⟨U+009B⟩2K")
        self.assertEqual(clean("\u2066x\u2069\ufeff\U000E0041"), "⟨U+2066⟩x⟨U+2069⟩⟨U+FEFF⟩⟨U+E0041⟩")
        self.assertEqual(clean(12), "12")
        long = clean("A" * 10000)
        self.assertEqual((len(long), long[-1]), (notifier.VALUE_MAX, "…"))
        # 상한에 걸려도 표식을 반쯤 자르지 않는다
        cut = clean("A" * 195 + "\u202e" * 3)
        self.assertEqual(cut, "A" * 195 + "…")
        self.assertEqual(notifier.clean_payload({"who": "a\u202eb", "target_seconds": 3600, "x": None}),
                         {"who": "a⟨U+202E⟩b", "target_seconds": 3600, "x": None})

    def test_teams_card_keeps_values_as_plain_text(self):
        for name, value in HOSTILE.items():
            with self.subTest(sample=name):
                body = notifier.build_body(self.channel, "incident.created", [self.payload(value)], NOW)
                card = body["attachments"][0]["content"]
                # 본문은 모두 RichTextBlock · TextRun 이다. TextBlock(마크다운 해석)은 없다
                self.assertNotIn('"TextBlock"', json.dumps(card))
                self.assertEqual({block["type"] for block in card["body"]}, {"RichTextBlock"})
                self.assertEqual({run["type"] for block in card["body"] for run in block["inlines"]}, {"TextRun"})
                texts = card_texts(body)
                self.assertEqual(len(texts), 2, "값 안의 줄바꿈이 새 줄을 만들지 않는다")
                for text in texts:
                    self.assert_clean(text, name)
                # 누를 수 있는 링크는 콘솔 주소 하나뿐이다. 사건 키는 한 경로 조각으로 인코딩된다
                (action,) = card["actions"]
                prefix = "http://console.test:8443/incidents/"
                self.assertTrue(action["url"].startswith(prefix), action["url"])
                self.assertFalse(set(action["url"][len(prefix):]) & set("/:?#[]()<> "), action["url"])
        texts = card_texts(notifier.build_body(self.channel, "incident.created", [self.payload(HOSTILE["md_link"])], NOW))
        self.assertIn("[눌러 확인](https://b.attacker.test/login)", texts[1], "마크다운은 해석되지 않고 글자로 보인다")
        texts = card_texts(notifier.build_body(self.channel, "incident.created", [self.payload(HOSTILE["rlo"])], NOW))
        self.assertIn("admin⟨U+202E⟩gnp.exe", texts[0])
        texts = card_texts(notifier.build_body(self.channel, "incident.created", [self.payload(HOSTILE["crlf"])], NOW))
        self.assertIn("줄1⟨U+000D⟩ - 가짜 항목 **굵게**", texts[1])

    def test_many_items_stay_one_block_per_item(self):
        payloads = [self.payload(HOSTILE["crlf"]) for _ in range(3)]
        texts = card_texts(notifier.build_body(self.channel, "pending.overdue", payloads, NOW))
        self.assertEqual(len(texts), 4)

    def test_webhook_json_is_cleaned_the_same_way(self):
        for name, value in HOSTILE.items():
            with self.subTest(sample=name):
                body = notifier.build_body(self.channel | {"kind": "webhook"}, "incident.created", [self.payload(value)], NOW)
                self.assert_clean(body["title"], name)
                for line in body["lines"]:
                    self.assert_clean(line, name)
                (item,) = body["items"]
                for key in ("rule_name", "severity", "who"):
                    self.assertEqual(item[key], notifier.clean_value(value), key)
                    self.assert_clean(item[key], name)
                # 사건 키는 받는 쪽이 DB · 콘솔과 맞춰 보는 식별자라 원문 그대로 JSON 문자열로 나간다
                self.assertEqual(item["incident_key"], value)
                self.assertTrue(body["console_url"].startswith("http://console.test:8443/incidents/"))
                # 보낼 본문은 JSON 으로 온전하다
                self.assertEqual(json.loads(json.dumps(body, ensure_ascii=False)), body)

    def test_node_hostname_is_cleaned(self):
        silent = {"node_id": "web-01", "hostname": "web\u202e10-bew\n가짜", "since": NOW.isoformat()}
        message = notifier.build_message(CHANNEL, "node.silent", [silent], NOW)
        self.assertEqual(message["lines"], ["- web⟨U+202E⟩10-bew 가짜 · - · node:web-01 · 방금"])


class FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.request = None
        self.timeout = None

    def open(self, request, timeout=None):
        self.request, self.timeout = request, timeout
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class HttpTests(unittest.TestCase):
    def test_post_json_posts_body_with_timeout_and_reports_code_or_exception_name_only(self):
        opener = FakeOpener(FakeResponse())
        handlers = []

        def build_opener(*args):
            handlers.extend(args)
            return opener
        with patch.object(notifier.urllib.request, "build_opener", build_opener):
            self.assertEqual(notifier.post_json(TEAMS_URL, {"a": "가"}), (202, None))
        # 리다이렉트를 따라가지 않는 처리기가 실제 opener 에 끼워진다
        self.assertEqual(handlers, [notifier._NoRedirect])
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.timeout, notifier.HTTP_TIMEOUT)
        self.assertEqual(json.loads(opener.request.data), {"a": "가"})
        self.assertTrue(opener.request.get_header("Content-type").startswith("application/json"))
        redirect = urllib.error.HTTPError(TEAMS_URL, 302, "Found", {}, None)
        with patch.object(notifier.urllib.request, "build_opener", lambda *a: FakeOpener(redirect)):
            self.assertEqual(notifier.post_json(TEAMS_URL, {}), (302, "HTTP 302"))
        with patch.object(notifier.urllib.request, "build_opener", lambda *a: FakeOpener(urllib.error.URLError(TEAMS_URL))):
            code, error = notifier.post_json(TEAMS_URL, {})
        self.assertEqual((code, error), (None, "URLError"))
        self.assertNotIn("SECRETSIG", error)
        self.assertIsNone(notifier._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere"))

    def test_url_error_reports_underlying_cause_name(self):
        """이름 해석 실패 · 연결 거부 · 시간 초과 · 인증서 오류를 구별한다(주소 · 본문은 넣지 않는다)."""
        for reason, name in [(socket.gaierror(8, "nodename nor servname"), "gaierror"),
                             (ConnectionRefusedError(61, "refused"), "ConnectionRefusedError"),
                             (TimeoutError("timed out"), "TimeoutError"),
                             (ssl.SSLCertVerificationError(1, "certificate verify failed"), "SSLCertVerificationError")]:
            with self.subTest(name=name), patch.object(notifier.urllib.request, "build_opener",
                                                       lambda *a, r=reason: FakeOpener(urllib.error.URLError(r))):
                self.assertEqual(notifier.post_json(TEAMS_URL, {}), (None, name))

    def test_302_is_not_followed_by_a_real_opener(self):
        """실제 opener 로 로컬 HTTP 서버에 보내 302 를 받아도 Location 을 따라가지 않는다."""
        import http.server
        import threading
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/moved")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(notifier.post_json(f"http://127.0.0.1:{server.server_port}/hook", {}), (302, "HTTP 302"))
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(hits, ["/hook"])

    def test_deliver_has_overall_deadline(self):
        import asyncio
        import time

        def slow(url, body):
            time.sleep(0.3)
            return 202, None
        with patch.object(notifier, "post_json", slow), patch.object(notifier, "HTTP_DEADLINE", 0.05):
            self.assertEqual(asyncio.run(notifier.deliver(TEAMS_URL, {})), (None, "TimeoutError"))

    def test_retry_schedule_and_success(self):
        self.assertEqual([notifier.retry_after(n) for n in (1, 2, 3, 4, 0)], [60, 300, 900, None, None])
        self.assertTrue(notifier.is_success(202))
        for code in (None, 199, 300, 302, 404, 500):
            self.assertFalse(notifier.is_success(code))


class MaskingTests(unittest.TestCase):
    def row(self, **extra):
        return {"id": 1, "name": "팀즈", "kind": "teams", "grade": "immediate", "events": ["incident.created"], "min_severity": "low",
                "batch_seconds": 300, "template_header": "h", "template_item": "i", "enabled": True, "url": TEAMS_URL,
                "created_at": NOW, "updated_at": NOW, "updated_by": "admin", "last_status": None, "last_sent_at": None,
                "last_response_code": None} | extra

    def test_public_channel_shows_host_and_tail_only(self):
        public = public_channel(self.row())
        self.assertNotIn("url", public)
        self.assertEqual(public["url_tail"], "TSIG")
        self.assertEqual(public["url_host"], TEAMS_HOST)
        self.assertIsNone(public["last_delivery"])
        self.assertNotIn("SECRETSIG", json.dumps(public, default=str))
        public = public_channel(self.row(last_status="sent", last_sent_at=NOW, last_response_code=202, last_at=NOW))
        self.assertEqual(public["last_delivery"], {"status": "sent", "sent_at": NOW, "response_code": 202, "error": None, "at": NOW})
        public = public_channel(self.row(last_status="failed", last_response_code=404, last_error="HTTP 404", last_at=NOW))
        self.assertEqual(public["last_delivery"], {"status": "failed", "sent_at": None, "response_code": 404, "error": "HTTP 404", "at": NOW})

    def test_audit_name_has_no_spaces(self):
        self.assertEqual(notify.audit_name("SOC  Teams\t야간"), "SOC_Teams_야간")


class InputTests(unittest.TestCase):
    base = dict(name="팀즈 보안", kind="teams", url=TEAMS_URL, grade="immediate", events=["node.silent", "incident.created", "node.silent"])

    def test_channel_input_normalises(self):
        body = ChannelIn(**self.base)
        self.assertEqual(body.events, ["incident.created", "node.silent"])
        self.assertEqual((body.min_severity, body.batch_seconds, body.enabled), ("low", 300, True))
        self.assertEqual(body.template_header, "[OpsLoop] {event_label} {count}건")
        body = ChannelIn(**(self.base | {"kind": "webhook", "url": " https://hooks.example.com/x ", "name": " 웹훅 "}))
        self.assertEqual((body.url, body.name), ("https://hooks.example.com/x", "웹훅"))
        update = ChannelUpdate(**(self.base | {"url": None}))
        self.assertIsNone(update.url)
        self.assertEqual(ChannelUpdate(**(self.base | {"url": ""})).url, "")

    def test_channel_input_rejects(self):
        for values in [dict(name=""), dict(name="  "), dict(name="x" * 65), dict(kind="email"), dict(grade="hourly"), dict(events=[]),
                       dict(events=["daily.summary"]), dict(min_severity="urgent"), dict(batch_seconds=-1), dict(batch_seconds=86401),
                       dict(template_header="{count:>5}"), dict(template_item=""), dict(template_item="x" * 301),
                       dict(url=""), dict(url="x" * 2049), dict(extra="field")]:
            with self.subTest(values=values), self.assertRaises(ValidationError):
                ChannelIn(**(self.base | values))

    def test_url_rules_are_checked_in_the_endpoint_with_a_plain_message(self):
        self.assertEqual(notify.checked_url("teams", TEAMS_URL), TEAMS_HOST)
        for kind, url in [("teams", "https://hooks.example.com/SECRET"), ("webhook", "https://10.0.0.1/SECRET"),
                          ("teams", "http://x.environment.api.powerplatform.com/SECRET")]:
            with self.subTest(url=url), self.assertRaises(HTTPException) as error:
                notify.checked_url(kind, url)
            self.assertEqual(error.exception.status_code, 422)
            self.assertNotIn("SECRET", error.exception.detail)


class ValidationEchoTests(unittest.TestCase):
    """422 응답 본문에 채널 주소 원문이 되돌아 나오지 않는다."""

    def setUp(self):
        app = FastAPI()
        app.include_router(notify.router)

        @app.middleware("http")
        async def as_admin(request, call_next):
            request.state.user = {"u": "tester", "r": "admin"}
            return await call_next(request)
        self.client = TestClient(app)

    def test_422_never_echoes_the_url(self):
        secret = "SECRETSIG"
        bodies = [
            InputTests.base | {"url": "https://prod-1.koreacentral.logic.azure.com/workflows/x?sig=" + secret},
            InputTests.base | {"kind": "webhook", "url": "https://127.1/hook?token=" + secret},
            InputTests.base | {"url": TEAMS_URL, "extra": secret},
            InputTests.base | {"url": TEAMS_URL + "x" * 2048},
            InputTests.base | {"url": TEAMS_URL, "events": []},
        ]
        for body in bodies:
            with self.subTest(body=list(body)):
                response = self.client.post("/api/notify/channels", json=body)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn(secret, response.text)
                self.assertNotIn("sig=", response.text)
                self.assertEqual(response.headers.get("cache-control"), "no-store")
        response = self.client.put("/api/notify/channels/1", json=InputTests.base | {"url": "https://x.example/" + secret, "events": []})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(secret, response.text)


class PermissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_admin_only_before_database_access(self):
        body = ChannelIn(**InputTests.base)
        update = ChannelUpdate(**(InputTests.base | {"url": None}))
        for role in ["viewer", "operator", None]:
            request = SimpleNamespace(state=SimpleNamespace(user={"u": "tester", "r": role} if role else None), app=None)
            calls = [(notify.list_channels, (request, None)), (notify.create_channel, (body, request, None)),
                     (notify.update_channel, (1, update, request, None)), (notify.test_channel, (1, request)),
                     (notify.list_deliveries, (request,))]
            for call, args in calls:
                with self.subTest(role=role, call=call.__name__), self.assertRaises(HTTPException) as error:
                    await call(*args)
                self.assertEqual(error.exception.status_code, 403 if role else 401)
