#!/usr/bin/env python3
"""방화벽 VM 설정(HAProxy · nftables) 노출 시험.  python3 infra/vmware/test_fw_haproxy.py

이슈 #41. HAProxy 통계 페이지(8404)는 인증이 없고 서버 주소 · 상태를 보인다. 그래서 방화벽 VM 안
(127.0.0.1)에서만 열고, 방화벽 input 체인의 관리망 · VPN 허용 포트에서도 뺀다. 보려면 SSH 터널을 쓴다.
원격 없이 저장소 파일만 읽는다. haproxy · nft 가 이 기계에 있으면 문법 검사도 한다(없으면 건너뛴다).
  - HAProxy     통계 bind 는 127.0.0.1:8404 하나 · 콘솔 진입점 8443 · 헬스체크 GET /health 200 은 그대로
                · 전환 관련 줄: 기준선 측정 뒤 보강 3가지(검사 실패 기록 · 재시도마다 다른 서버 · DOWN 때 연결 끊기), 나머지는 그대로 (이슈 #43)
                · 작업 프로세스는 haproxy 사용자 · chroot /var/lib/haproxy (로그 소켓은 rsyslog 가 chroot 안에 만든다)
                · 진입점은 클라이언트가 보낸 X-Forwarded-For 를 지우고 HAProxy 가 본 주소 하나만 싣는다
  - 콘솔 compose FORWARDED_ALLOW_IPS 기본값 = 방화벽 서비스망 주소 = 호스트 가드가 8000 에 들이는 유일한 주소
  - nftables    mgmt · tailscale0 허용 포트는 22 · 8443 뿐 · 8404 는 어디에도 없음 · input 정책 drop
  - 검증 스크립트 verify.sh 는 방화벽 안 통계 페이지를 통과로, 관리망 직접 접근을 실패로 기대 · bash -n
  - README      SSH 터널 안내가 있고 관리망에서 바로 연다는 문구가 없음 · '콘솔 B 운용' 절(켜는 · 끄는 절차 · reload 주의)
"""
import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HAPROXY = os.path.join(HERE, "haproxy", "haproxy.cfg")
NFT = os.path.join(HERE, "fw", "nftables.conf")
VERIFY = os.path.join(HERE, "scripts", "verify.sh")
CONFIGURE = os.path.join(HERE, "scripts", "configure.sh")
README = os.path.join(HERE, "README.md")
COMPOSE = os.path.join(HERE, "compose", "console.yml")
GUARD = os.path.join(HERE, "..", "ansible", "files", "console-guard.nft")
FW_NETPLAN = os.path.join(HERE, "netplan", "fw.yaml.template")
TUNNEL = "ssh -F ~/.ssh/config.opsloop -L 8404:127.0.0.1:8404 fw"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def haproxy_sections(text):
    """haproxy.cfg 를 절(global · defaults · frontend · backend · listen) 머리 → 지시어 목록으로 나눈다.
    주석 · 빈 줄은 뺀다."""
    out, cur = {}, None
    for line in text.splitlines():
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        if not line[0].isspace():
            cur = " ".join(body.split())
            out[cur] = []
        else:
            out[cur].append(" ".join(body.split()))
    return out


def nft_code(text):
    """주석을 뺀 nftables 규칙 줄."""
    return [ln.split("#", 1)[0].strip() for ln in text.splitlines() if ln.split("#", 1)[0].strip()]


def nft_chain(text, name):
    """table inet filter 의 체인 하나의 규칙 줄."""
    lines, inside = [], False
    for ln in nft_code(text):
        if ln == f"chain {name} {{":
            inside = True
            continue
        if inside and ln == "}":
            return lines
        if inside:
            lines.append(ln)
    raise AssertionError(f"체인 {name} 을 찾지 못했다")


class HAProxy(unittest.TestCase):
    def setUp(self):
        self.sec = haproxy_sections(read(HAPROXY))

    def test_통계_페이지는_방화벽_안에서만_연다(self):
        binds = [d for d in self.sec["listen stats"] if d.startswith("bind ")]
        self.assertEqual(binds, ["bind 127.0.0.1:8404"])
        self.assertIn("stats enable", self.sec["listen stats"])
        for head, directives in self.sec.items():
            if head == "listen stats":
                continue
            for d in directives:
                self.assertNotIn("8404", d, f"{head}: {d}")

    def test_콘솔_진입점과_헬스체크는_그대로(self):
        self.assertEqual([d for d in self.sec["frontend console"] if d.startswith("bind ")], ["bind :8443"])
        backend = self.sec["backend consoles"]
        # 콘솔 /health 는 세션 없이 200 을 준다(이슈 #41 에서 본문만 줄였다). 검사는 상태 코드만 본다
        self.assertIn("option httpchk GET /health", backend)
        self.assertIn("http-check expect status 200", backend)
        self.assertIn("default-server inter 2s fall 3 rise 3 slowstart 30s on-marked-down shutdown-sessions", backend)

    def test_전환_관련_줄(self):
        # 이슈 #43: 기준선을 잰 뒤 보강한 세 가지만 더한다. 분배 방식 · 검사 주기 · 시간 제한은 그대로
        self.assertEqual(self.sec["backend consoles"], [
            "balance roundrobin",
            "option httpchk GET /health",
            "http-check expect status 200",
            "option log-health-checks",
            "option redispatch 1",
            "default-server inter 2s fall 3 rise 3 slowstart 30s on-marked-down shutdown-sessions",
            "server console-a 192.168.50.11:8000 check",
            "server console-b 192.168.50.12:8000 check",
        ])
        timeouts = [d for d in self.sec["defaults"] if d.startswith("timeout ")]
        self.assertEqual(timeouts, ["timeout connect 5s", "timeout client 60s", "timeout server 60s", "timeout tunnel 1h"])

    def test_작업_프로세스는_root_가_아니고_chroot_안에서_돈다(self):
        g = self.sec["global"]
        for d in ("user haproxy", "group haproxy", "chroot /var/lib/haproxy", "log /dev/log local0"):
            self.assertIn(d, g)
        # uid · gid 숫자나 root 로 되돌리지 않는다
        self.assertFalse([d for d in g if re.match(r"(uid|gid) ", d) or d in ("user root", "group root")], g)

    def test_출발지_헤더는_HAProxy_가_본_주소_하나만(self):
        fe = self.sec["frontend console"]
        self.assertIn("http-request del-header X-Forwarded-For", fe)
        self.assertIn("http-request del-header X-Forwarded-Proto", fe)
        self.assertIn("option forwardfor", fe)
        # if-none 이면 클라이언트가 보낸 값을 그대로 두고, except 는 지울 곳을 좁힌다
        self.assertFalse([d for d in fe if d.startswith("option forwardfor") and d != "option forwardfor"], fe)
        self.assertLess(fe.index("http-request del-header X-Forwarded-For"), fe.index("default_backend consoles"))
        for head, directives in self.sec.items():
            if head != "frontend console":
                self.assertFalse([d for d in directives if "forwardfor" in d or "X-Forwarded-For" in d], head)

    @unittest.skipUnless(shutil.which("haproxy"), "haproxy 가 이 기계에 없다 (방화벽 VM 에서 haproxy -c 로 본다)")
    def test_haproxy_문법(self):
        r = subprocess.run(["haproxy", "-c", "-f", HAPROXY], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TrustedProxy(unittest.TestCase):
    """콘솔 uvicorn 이 믿는 프록시 주소가 HAProxy 가 서비스망에서 쓰는 주소와 같은지 (이슈 #43)."""

    def test_compose_기본값은_방화벽_서비스망_주소(self):
        lines = [ln.strip() for ln in read(COMPOSE).splitlines() if ln.strip().startswith("FORWARDED_ALLOW_IPS:")]
        self.assertEqual(lines, ["FORWARDED_ALLOW_IPS: ${OPSLOOP_TRUSTED_PROXY:-192.168.50.1}"])
        m = re.search(r"addresses: \[(192\.168\.50\.\d+)/24\]", read(FW_NETPLAN))
        self.assertEqual(m.group(1), "192.168.50.1")

    def test_호스트_가드가_들이는_주소와_같다(self):
        # 서비스망에서 8000 에 닿는 곳이 이 주소 하나여야 믿는 주소에서 온 X-Forwarded-For 가 HAProxy 것뿐이다
        accepts = re.findall(r"^\s*ip saddr (\S+) accept", read(GUARD), re.M)
        self.assertEqual(accepts, ["192.168.50.1"])


class Nftables(unittest.TestCase):
    def setUp(self):
        self.text = read(NFT)
        self.input = nft_chain(self.text, "input")

    def test_관리망_VPN_허용_포트에서_통계_페이지를_뺀다(self):
        ports = {}
        for ln in self.input:
            m = re.fullmatch(r'iifname "(mgmt|tailscale0)"(?: ip saddr \$MGMT)? tcp dport \{([^}]*)\} accept', ln)
            if m:
                self.assertNotIn(m.group(1), ports, f"같은 인터페이스의 tcp 허용 줄이 둘이다: {ln}")
                ports[m.group(1)] = {p.strip() for p in m.group(2).split(",")}
        self.assertEqual(ports, {"mgmt": {"22", "8443"}, "tailscale0": {"22", "8443"}})

    def test_관리망_VPN_의_모든_허용_줄은_정해진_포트만_연다(self):
        # 글자 한 줄만 보면 'tcp dport 8000-9000 accept' · 포트 없는 accept 가 새로 붙어도 모른다
        for ln in self.input:
            if re.match(r'iifname "(mgmt|tailscale0)"', ln) and ln.endswith("accept") and "icmp type" not in ln:
                self.assertIn(" dport ", ln, f"포트 조건 없는 허용: {ln}")
                self.assertNotRegex(ln, r"dport [^{]*\d-\d|\{[^}]*\d-\d", f"포트 범위 허용: {ln}")

    def test_8404_는_어느_규칙에도_없다(self):
        for ln in nft_code(self.text):
            self.assertNotIn("8404", ln)

    def test_input_정책은_거부(self):
        self.assertIn("type filter hook input priority 0; policy drop;", self.input)
        self.assertIn('iif "lo" accept', self.input)

    @unittest.skipUnless(shutil.which("nft") and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "nft 가 없거나 root 가 아니다 (방화벽 VM 에서 nft -c -f 로 본다)")
    def test_nft_문법(self):
        r = subprocess.run(["nft", "-c", "-f", NFT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class Scripts(unittest.TestCase):
    def test_셸_문법(self):
        for path in (VERIFY, CONFIGURE):
            r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{path}: {r.stderr}")

    def test_검증_스크립트는_방화벽_안에서만_통과를_기대한다(self):
        checks = [ln.strip() for ln in read(VERIFY).splitlines()
                  if ln.strip().startswith("check ") and "8404" in ln]
        inside = [c for c in checks if "127.0.0.1:8404" in c]
        direct = [c for c in checks if "$FW:8404" in c]
        self.assertEqual(len(inside), 1, checks)
        self.assertRegex(inside[0], r'" 통과 ssh_fw ')
        self.assertEqual(len(direct), 1, checks)
        self.assertRegex(direct[0], r'" 실패 curl ')
        self.assertEqual(len(checks), 2, checks)


class Readme(unittest.TestCase):
    def setUp(self):
        self.text = read(README)

    # README 전문을 오류 문구에 싣지 않도록 assertIn 대신 참 · 거짓으로 본다
    def test_터널_안내가_있다(self):
        for s in (TUNNEL, "http://127.0.0.1:8404"):
            self.assertTrue(s in self.text, f"없음: {s}")

    def test_관리망에서_바로_연다는_문구가_없다(self):
        for s in ("192.168.70.254:8404", "HAProxy 상태는 `:8404` 로 본다"):
            self.assertFalse(s in self.text, f"남아 있음: {s}")

    def test_배포와_되돌리기_절차가_있다(self):
        for s in ("haproxy -c -f", "nft -c -f", "systemctl reload haproxy",
                  "/etc/haproxy/haproxy.cfg.prev", "/etc/nftables.conf.prev"):
            self.assertTrue(s in self.text, f"없음: {s}")

    def test_콘솔_B_운용_절(self):
        self.assertTrue("## 콘솔 B 운용" in self.text)
        sec = self.text.split("## 콘솔 B 운용", 1)[1].split("\n## ", 1)[0]
        for s in ('echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock',
                  "set server consoles/console-b state maint", "state ready", "state drain",
                  "reload 하면 maint", "restart=no", "chrony-client.conf.template", "full-upgrade",
                  "consoles.yml --limit console-b", "docker save", "docker load",
                  "SESSION_SECRET", "OPSLOOP_CONSOLE_DB_PASSWORD", "POSTGRES_PASSWORD 는 옮기지 않는다",
                  "OPSLOOP_WORKER=opsloop-console-b", "collect-assets.sh --only console-b",
                  "scripts/console-join.sh", "--apply", "--leave", "20260926_console_connlimit.sql"):
            self.assertTrue(s in sec, f"없음: {s}")
        # HAProxy 2.8 은 maint 가 drain 을, drain 이 maint 를 푼다. 떼기 끝의 관리 상태는 9 가 아니라 1 이다
        self.assertTrue("maint 와 drain 은 서로를 푼다" in sec)
        self.assertTrue("| `state` | HAProxy 상태 (console-b 운영 0 · 관리 1" in sec)
        self.assertFalse(re.search(r"관리 9|합쳐 9", sec))

    def test_nft_적용_뒤_tailscale_규칙을_되살린다(self):
        # flush ruleset 이 Tailscale 의 iptables-nft 규칙까지 지운다. 올리기 · 되돌리기 모두 tailscaled 를 다시 띄워야 한다
        self.assertGreaterEqual(self.text.count("nft -f /etc/nftables.conf\n  sudo -n systemctl restart tailscaled"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
