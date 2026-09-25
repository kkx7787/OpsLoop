#!/usr/bin/env python3
"""노드 자산 조사(cti/probe.py) 단위 시험.  python3 cti/test_probe.py

노드 없이 Mac 에서 돈다. dpkg-query · sudo · docker 는 임시 폴더의 가짜 실행기를 PATH 앞에 두어 바꾸고,
/etc/os-release · uname -r 은 임시 파일 · 가짜 값으로 바꾼다.
  - os-release  따옴표 · 빠진 키
  - 패키지      설치 상태 거르기(ii · 고정한 hi 는 넣고 rc · un · 모양이 틀린 줄은 뺀다) · 소스 이름 · 버전이 비면
                바이너리 값으로 채움 · 이름순 · dpkg-query 에 넘기는 형식
  - 커널        실행 중 커널의 이미지 패키지 · 설치 커널 목록(메타 패키지 제외) · 실행 커널 패키지가 없을 때
  - 컨테이너    sudo -n 으로 부름 · 이름순 · 도는 컨테이너 없음 · docker 없음 · sudo 가 암호를 물을 때(errors)
  - 전체 출력   키 순서 · 한 줄 JSON · 값 하나를 못 읽어도 나머지를 보냄 · dpkg 가 없을 때
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "probe.py")

sys.dont_write_bytecode = True       # cti/ 에 __pycache__ 를 만들지 않는다


def load_probe():
    spec = importlib.util.spec_from_file_location("opsloop_probe", PROBE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t…' 가 내는 모양. 상태 약어는 뒤에 공백이 붙는다
DPKG_OUT = "\n".join([
    "ii \topenssh-server\t1:9.6p1-3ubuntu13.19\topenssh\t1:9.6p1-3ubuntu13.19\tamd64",
    "hi \tsudo\t1.9.15p5-3ubuntu5.24.04.2\tsudo\t1.9.15p5-3ubuntu5.24.04.2\tamd64",
    "rc \told-config-only\t1.0-1\told-config-only\t1.0-1\tamd64",
    "un \tnever-installed\t\t\t\t",
    "ii \tlinux-image-6.8.0-142-generic\t6.8.0-142.142\tlinux-signed\t6.8.0-142.142\tamd64",
    "ii \tlinux-image-6.8.0-139-generic\t6.8.0-139.139\tlinux-signed\t6.8.0-139.139\tamd64",
    "ii \tlinux-image-generic\t6.8.0.142.142\tlinux-meta\t6.8.0.142.142\tamd64",
    "ii \tlibc6\t2.39-0ubuntu8.6\tglibc\t2.39-0ubuntu8.6\tamd64",
    "ii \tno-source-field\t2.0-1\t\t\tall",
    "모양이 틀린 줄",
    "",
])

OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.5 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
"""

FAKE_DPKG = """#!/bin/sh
printf '%s\\n' "dpkg-query $*" >> "$FAKE_LOG"
cat "$FAKE_DPKG_OUT"
"""
FAKE_SUDO = """#!/bin/sh
printf '%s\\n' "sudo $*" >> "$FAKE_LOG"
if [ -n "${FAKE_SUDO_DENY:-}" ]; then echo "sudo: a password is required" >&2; exit 1; fi
[ "$1" = -n ] && shift
exec "$@"
"""
FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "docker $*" >> "$FAKE_LOG"
case "$1" in
  ps) cat "$FAKE_DOCKER_PS" ;;
  inspect) cat "$FAKE_DOCKER_INSPECT" ;;
  *) exit 2 ;;
esac
"""


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.t)
        self.bin = os.path.join(self.t, "bin")
        os.mkdir(self.bin)
        self.log = os.path.join(self.t, "calls")
        open(self.log, "w").close()
        self.files = {}
        for name, body in (("dpkg", DPKG_OUT), ("ps", "opsloop-db\nopsloop-loki\n"),
                           ("inspect", "/opsloop-loki\tgrafana/loki:3.7.8\tsha256:bbb\n"
                                       "/opsloop-db\tpostgres:16-alpine\tsha256:aaa\n"),
                           ("os-release", OS_RELEASE)):
            self.files[name] = os.path.join(self.t, name)
            with open(self.files[name], "w", encoding="utf-8") as f:
                f.write(body)
        env = {"PATH": self.bin + os.pathsep + "/usr/bin:/bin", "FAKE_LOG": self.log,
               "FAKE_DPKG_OUT": self.files["dpkg"], "FAKE_DOCKER_PS": self.files["ps"],
               "FAKE_DOCKER_INSPECT": self.files["inspect"]}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("FAKE_SUDO_DENY", None)
        self.m = load_probe()

    def fake(self, name, body):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def calls(self):
        with open(self.log, encoding="utf-8") as f:
            return f.read().splitlines()

    def run_main(self, running="6.8.0-139-generic"):
        orig = self.m.os_release
        out = io.StringIO()
        with mock.patch.object(self.m.platform, "release", return_value=running), \
                mock.patch.object(self.m, "os_release", lambda: orig(self.files["os-release"])), \
                contextlib.redirect_stdout(out):
            self.m.main()
        text = out.getvalue()
        self.assertEqual(text.count("\n"), 1, "출력은 JSON 한 줄이다")
        return json.loads(text)

    # ── os-release ───────────────────────────────────────────
    def test_os_release_따옴표를_벗기고_네_값만_낸다(self):
        self.assertEqual(self.m.os_release(self.files["os-release"]),
                         {"id": "ubuntu", "version_id": "24.04", "codename": "noble",
                          "pretty": "Ubuntu 24.04.5 LTS"})

    def test_os_release_빠진_키는_None_이다(self):
        p = os.path.join(self.t, "short")
        with open(p, "w") as f:
            f.write('ID=debian\n# 주석\n\nVERSION_ID="12"\n')
        self.assertEqual(self.m.os_release(p),
                         {"id": "debian", "version_id": "12", "codename": None, "pretty": None})

    # ── 패키지 ──────────────────────────────────────────────
    def test_패키지는_설치된_것만_이름순으로_낸다(self):
        self.fake("dpkg-query", FAKE_DPKG)
        pkgs = self.m.dpkg_packages()
        self.assertEqual([p["name"] for p in pkgs],
                         ["libc6", "linux-image-6.8.0-139-generic", "linux-image-6.8.0-142-generic",
                          "linux-image-generic", "no-source-field", "openssh-server", "sudo"])
        by = {p["name"]: p for p in pkgs}
        self.assertEqual(by["openssh-server"], {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.19",
                                                "source": "openssh", "source_version": "1:9.6p1-3ubuntu13.19",
                                                "arch": "amd64"})
        self.assertIn("sudo", by, "고정(hold)한 패키지(hi)도 설치된 것이다")
        self.assertEqual((by["no-source-field"]["source"], by["no-source-field"]["source_version"]),
                         ("no-source-field", "2.0-1"), "소스 값이 비면 바이너리 이름 · 버전으로 채운다")
        self.assertEqual(list(by["libc6"]), ["name", "version", "source", "source_version", "arch"])

    def test_dpkg_query_에_상태_소스_형식을_넘긴다(self):
        self.fake("dpkg-query", FAKE_DPKG)
        self.m.dpkg_packages()
        call = self.calls()[0]
        self.assertTrue(call.startswith("dpkg-query -W -f "), call)
        for field in ("${db:Status-Abbrev}", "${Package}", "${Version}", "${source:Package}",
                      "${source:Version}", "${Architecture}"):
            self.assertIn(field, call)

    # ── 커널 ────────────────────────────────────────────────
    def test_커널_실행_중인_이미지와_설치된_이미지(self):
        self.fake("dpkg-query", FAKE_DPKG)
        pkgs = self.m.dpkg_packages()
        with mock.patch.object(self.m.platform, "release", return_value="6.8.0-139-generic"):
            k = self.m.kernel_info(pkgs)
        self.assertEqual(k["running"], "6.8.0-139-generic")
        self.assertEqual(k["running_package"], "linux-image-6.8.0-139-generic")
        self.assertEqual(k["running_version"], "6.8.0-139.139")
        self.assertEqual(k["installed"], [
            {"package": "linux-image-6.8.0-139-generic", "version": "6.8.0-139.139"},
            {"package": "linux-image-6.8.0-142-generic", "version": "6.8.0-142.142"},
        ], "메타 패키지(linux-image-generic)는 커널 이미지가 아니다")

    def test_커널_실행_중인_이미지_패키지가_없으면_None(self):
        with mock.patch.object(self.m.platform, "release", return_value="6.8.0-999-custom"):
            k = self.m.kernel_info([])
        self.assertEqual(k, {"running": "6.8.0-999-custom", "running_package": None,
                             "running_version": None, "installed": []})

    # ── 컨테이너 ────────────────────────────────────────────
    def test_컨테이너_sudo_n_으로_묻고_이름순으로_낸다(self):
        self.fake("sudo", FAKE_SUDO)
        self.fake("docker", FAKE_DOCKER)
        self.assertEqual(self.m.container_images(), [
            {"container": "opsloop-db", "image": "postgres:16-alpine", "image_id": "sha256:aaa"},
            {"container": "opsloop-loki", "image": "grafana/loki:3.7.8", "image_id": "sha256:bbb"},
        ])
        sudo = [c for c in self.calls() if c.startswith("sudo ")]
        self.assertEqual(len(sudo), 2)
        self.assertTrue(all(c.startswith("sudo -n docker ") for c in sudo), sudo)

    def test_도는_컨테이너가_없으면_빈_목록이고_inspect_를_부르지_않는다(self):
        self.fake("sudo", FAKE_SUDO)
        self.fake("docker", FAKE_DOCKER)
        with open(self.files["ps"], "w") as f:
            f.write("")
        self.assertEqual(self.m.container_images(), [])
        self.assertFalse([c for c in self.calls() if c.startswith("docker inspect")])

    def test_sudo_가_암호를_물으면_오류를_낸다(self):
        self.fake("sudo", FAKE_SUDO)
        self.fake("docker", FAKE_DOCKER)
        os.environ["FAKE_SUDO_DENY"] = "1"
        with self.assertRaises(RuntimeError) as cm:
            self.m.container_images()
        self.assertIn("sudo -n docker: 종료 1 sudo: a password is required", str(cm.exception))

    def test_docker_유무는_PATH_로_본다(self):
        if not os.access("/usr/bin/docker", os.X_OK):
            self.assertFalse(self.m.has_docker())
        self.fake("docker", FAKE_DOCKER)
        self.assertTrue(self.m.has_docker())

    # ── 전체 출력 ───────────────────────────────────────────
    def test_전체_출력_모양(self):
        self.fake("dpkg-query", FAKE_DPKG)
        self.fake("sudo", FAKE_SUDO)
        self.fake("docker", FAKE_DOCKER)
        rec = self.run_main()
        self.assertEqual(list(rec), ["probe_version", "hostname", "collected_at", "os", "kernel",
                                     "packages", "images", "errors"])
        self.assertEqual(rec["probe_version"], 1)
        self.assertIsInstance(rec["hostname"], str)
        self.assertEqual(datetime.fromisoformat(rec["collected_at"]).utcoffset().total_seconds(), 0)
        self.assertEqual(rec["os"]["pretty"], "Ubuntu 24.04.5 LTS")
        self.assertEqual(rec["kernel"]["running_version"], "6.8.0-139.139")
        self.assertEqual(len(rec["packages"]), 7)
        self.assertEqual([i["container"] for i in rec["images"]], ["opsloop-db", "opsloop-loki"])
        self.assertEqual(rec["errors"], [])

    @unittest.skipIf(os.access("/usr/bin/docker", os.X_OK), "/usr/bin/docker 가 있어 docker 없음을 흉내 낼 수 없다")
    def test_docker_가_없으면_이미지를_건너뛰고_오류도_없다(self):
        self.fake("dpkg-query", FAKE_DPKG)
        self.fake("sudo", FAKE_SUDO)
        rec = self.run_main()
        self.assertEqual(rec["images"], [])
        self.assertEqual(rec["errors"], [])
        self.assertFalse([c for c in self.calls() if c.startswith("sudo ")], "docker 가 없으면 sudo 도 부르지 않는다")

    def test_sudo_가_암호를_물어도_나머지는_보낸다(self):
        self.fake("dpkg-query", FAKE_DPKG)
        self.fake("sudo", FAKE_SUDO)
        self.fake("docker", FAKE_DOCKER)
        os.environ["FAKE_SUDO_DENY"] = "1"
        rec = self.run_main()
        self.assertEqual(rec["images"], [])
        self.assertEqual(len(rec["errors"]), 1)
        self.assertTrue(rec["errors"][0].startswith("images: sudo -n docker: 종료 1"), rec["errors"])
        self.assertEqual(len(rec["packages"]), 7)
        self.assertIsNotNone(rec["kernel"])

    @unittest.skipIf(os.access("/usr/bin/docker", os.X_OK), "/usr/bin/docker 가 있어 docker 없음을 흉내 낼 수 없다")
    def test_dpkg_가_없으면_패키지_커널이_비고_오류에_남는다(self):
        if shutil.which("dpkg-query", path="/usr/bin:/bin"):
            self.skipTest("이 기계에 dpkg-query 가 있다")
        rec = self.run_main()
        self.assertEqual(rec["packages"], [])
        self.assertIsNone(rec["kernel"])
        self.assertEqual(len(rec["errors"]), 1)
        self.assertTrue(rec["errors"][0].startswith("packages: "), rec["errors"])
        self.assertEqual(rec["os"]["id"], "ubuntu", "패키지를 못 읽어도 os 는 보낸다")

    def test_os_release_를_못_읽어도_나머지는_보낸다(self):
        self.fake("dpkg-query", FAKE_DPKG)
        out = io.StringIO()
        missing = os.path.join(self.t, "없음")
        orig = self.m.os_release
        with mock.patch.object(self.m.platform, "release", return_value="6.8.0-139-generic"), \
                mock.patch.object(self.m, "os_release", lambda: orig(missing)), \
                mock.patch.object(self.m, "has_docker", return_value=False), \
                contextlib.redirect_stdout(out):
            self.m.main()
        rec = json.loads(out.getvalue())
        self.assertIsNone(rec["os"])
        self.assertTrue(rec["errors"][0].startswith("os: "), rec["errors"])
        self.assertEqual(len(rec["packages"]), 7)

    def test_실패한_명령의_오류_문구는_짧게_자른다(self):
        self.fake("noisy", "#!/bin/sh\nprintf 'x%.0s' $(seq 1 1000) >&2\nexit 3\n")
        with self.assertRaises(RuntimeError) as cm:
            self.m.run(["noisy", "a", "b", "c", "d"])
        msg = str(cm.exception)
        self.assertTrue(msg.startswith("noisy a b: 종료 3 "), msg)
        self.assertLessEqual(len(msg), 250)


if __name__ == "__main__":
    unittest.main()
