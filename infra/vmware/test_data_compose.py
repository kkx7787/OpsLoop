#!/usr/bin/env python3
"""데이터 노드 compose(compose/data.yml) 시험.  python3 infra/vmware/test_data_compose.py

이슈 #45. 빈 볼륨으로 띄우면 initdb 에 붙인 옛 schema.sql(배포할 때의 사본)이 먼저 깔려 pg_restore 가
'already exists' 로 멈췄다. 그래서 initdb 마운트를 없애고, 스키마는 설치기(install-collector.sh)가 적용한다.
원격 없이 저장소 파일만 읽는다. docker compose 가 있으면 해석 결과도 본다(없으면 건너뛴다).
  - postgres     initdb 마운트(docker-entrypoint-initdb.d)가 없다 · 볼륨은 pgdata 하나
                 · 이미지 · 컨테이너 이름 · 바인드 주소 · 소유자 · DB 이름 · 시간대 · 메모리 한도 · 헬스체크는 그대로
  - loki         이미지 · 설정 · 원장 폴더 · 루프백 게시 · 메모리 한도 그대로
  - compose 해석 프로젝트 opsloop 의 볼륨 이름이 opsloop_pgdata(운영 볼륨)로 그대로 · 마운트 · 게시 주소
  - 스키마 적용   install-collector.sh 가 운영 컨테이너에 infra/schema.sql 전체를 적용한다(initdb 대신)
  - 문서          README 'DB 복원' 절(배포본 반영 시점 · 방법, 복원 명령의 안전 줄 · 순서), 수집 파이프라인 결과의 자리표시
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
COMPOSE = os.path.join(HERE, "compose", "data.yml")
README = os.path.join(HERE, "README.md")
INSTALL_COLLECTOR = os.path.join(ROOT, "collector", "install-collector.sh")
PIPELINE_DOC = os.path.join(ROOT, "docs", "2026-09-21-수집-파이프라인-결과.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def code_lines(text):
    """주석 줄 · 빈 줄을 뺀 줄 (끝 공백 제거)."""
    return [l.rstrip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def block(lines, indent, key):
    """indent 칸 들여쓴 'key:' 아래에서 더 깊게 들여쓴 줄들을 돌려준다."""
    head = " " * indent + key + ":"
    for i, line in enumerate(lines):
        if line == head or line.startswith(head + " "):
            body = []
            for m in lines[i + 1:]:
                if len(m) - len(m.lstrip()) <= indent:
                    break
                body.append(m)
            return body
    raise KeyError(key)


def items(lines):
    """목록 항목('- 값')을 따옴표를 벗겨 돌려준다."""
    return [l.strip()[2:].strip().strip('"') for l in lines if l.strip().startswith("- ")]


def scalar(lines, indent, key):
    head = " " * indent + key + ":"
    for line in lines:
        if line.startswith(head + " "):
            return line[len(head):].strip().strip('"')
    raise KeyError(key)


class DataCompose(unittest.TestCase):
    def setUp(self):
        self.text = read(COMPOSE)
        self.lines = code_lines(self.text)
        services = block(self.lines, 0, "services")
        self.pg = block(services, 2, "postgres")
        self.loki = block(services, 2, "loki")

    def test_initdb_마운트가_없다(self):
        self.assertFalse(any("docker-entrypoint-initdb" in l for l in self.lines))
        self.assertFalse(any("schema.sql" in l for l in self.lines))
        self.assertEqual(items(block(self.pg, 4, "volumes")), ["pgdata:/var/lib/postgresql/data"])

    def test_postgres_이미지_볼륨_바인드_주소는_그대로(self):
        self.assertEqual(scalar(self.pg, 4, "image"), "postgres:16-alpine")
        self.assertEqual(scalar(self.pg, 4, "container_name"), "opsloop-db")
        self.assertEqual(scalar(self.pg, 4, "restart"), "always")
        self.assertEqual(items(block(self.pg, 4, "ports")), ["192.168.60.11:5432:5432"])
        env = block(self.pg, 4, "environment")
        self.assertEqual(scalar(env, 6, "POSTGRES_DB"), "opsloop")
        self.assertEqual(scalar(env, 6, "POSTGRES_USER"), "opsloop")
        self.assertEqual(scalar(env, 6, "TZ"), "UTC")
        self.assertTrue(scalar(env, 6, "POSTGRES_PASSWORD").startswith("${POSTGRES_PASSWORD:?"))
        self.assertIn("pg_isready -U opsloop -d opsloop", scalar(block(self.pg, 4, "healthcheck"), 6, "test"))
        self.assertEqual(scalar(block(block(block(self.pg, 4, "deploy"), 6, "resources"), 8, "limits"), 10, "memory"), "768M")
        # 최상위 이름 있는 볼륨 pgdata 하나. 이름(name:)을 따로 주지 않아 운영에서는 opsloop_pgdata 다
        self.assertEqual([l.strip() for l in block(self.lines, 0, "volumes")], ["pgdata:"])

    def test_loki_는_그대로(self):
        self.assertEqual(scalar(self.loki, 4, "image"), "grafana/loki:3.7.8")
        self.assertEqual(scalar(self.loki, 4, "container_name"), "opsloop-loki")
        self.assertEqual(items(block(self.loki, 4, "volumes")),
                         ["./loki.yaml:/etc/loki/loki.yaml:ro", "/var/lib/opsloop/loki:/loki"])
        self.assertEqual(items(block(self.loki, 4, "ports")), ["127.0.0.1:3100:3100"])
        self.assertEqual(scalar(block(block(block(self.loki, 4, "deploy"), 6, "resources"), 8, "limits"), 10, "memory"), "384M")

    def test_주석이_이유와_스키마_적용처를_적는다(self):
        for s in ("이슈 #45", "collector/install-collector.sh", "infra/schema.sql", "already exists", "down -v"):
            self.assertIn(s, self.text)

    def test_런북의_initdb_확인이_주석까지_0을_센다(self):
        # 런북 3나 · '배포본 data.yml 반영' 은 배포본 전체를 grep -c docker-entrypoint-initdb 로 센다(주석 포함).
        # 주석에 이 글자가 들어가면 반영한 뒤에도 1 이 나와 3나에서 멈춘다
        self.assertNotIn("docker-entrypoint-initdb", self.text)


@unittest.skipUnless(shutil.which("docker"), "docker 없음")
class ComposeConfig(unittest.TestCase):
    """docker compose 로 해석한다. 데이터 노드에서처럼 프로젝트 이름을 opsloop 로 준다. 데몬에 붙지 않는다."""

    @classmethod
    def setUpClass(cls):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("POSTGRES_", "COMPOSE_"))}
        env["POSTGRES_PASSWORD"] = "test-only-not-a-secret"
        try:
            r = subprocess.run(["docker", "compose", "-p", "opsloop", "-f", COMPOSE, "config", "--format", "json"],
                               cwd=os.path.dirname(COMPOSE), env=env, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise unittest.SkipTest(f"docker compose 를 돌리지 못했다: {e}")
        if r.returncode != 0 and ("is not a docker command" in r.stderr or "unknown" in r.stderr.lower()):
            raise unittest.SkipTest("docker compose 플러그인 없음")
        cls.rc = r.returncode
        cls.err = r.stderr[-400:]
        cls.cfg = json.loads(r.stdout) if r.returncode == 0 else None

    def test_해석된다(self):
        self.assertEqual(self.rc, 0, self.err)

    def test_postgres_마운트는_운영_볼륨_하나(self):
        vols = self.cfg["services"]["postgres"]["volumes"]
        self.assertEqual([(v["type"], v["source"], v["target"]) for v in vols],
                         [("volume", "pgdata", "/var/lib/postgresql/data")])
        self.assertEqual(self.cfg["volumes"]["pgdata"]["name"], "opsloop_pgdata")

    def test_게시_주소(self):
        ports = self.cfg["services"]["postgres"]["ports"]
        self.assertEqual([(p["host_ip"], str(p["published"]), p["target"]) for p in ports], [("192.168.60.11", "5432", 5432)])
        ports = self.cfg["services"]["loki"]["ports"]
        self.assertEqual([(p["host_ip"], str(p["published"]), p["target"]) for p in ports], [("127.0.0.1", "3100", 3100)])

    def test_이미지와_컨테이너_이름(self):
        pg, loki = self.cfg["services"]["postgres"], self.cfg["services"]["loki"]
        self.assertEqual((pg["image"], pg["container_name"]), ("postgres:16-alpine", "opsloop-db"))
        self.assertEqual((loki["image"], loki["container_name"]), ("grafana/loki:3.7.8", "opsloop-loki"))
        self.assertEqual({v["target"] for v in loki["volumes"]}, {"/etc/loki/loki.yaml", "/loki"})


class SchemaByInstaller(unittest.TestCase):
    """initdb 대신 설치기가 운영 컨테이너에 저장소의 스키마 전체를 적용한다 (compose 주석이 가리키는 곳)."""

    def test_install_collector_가_스키마_전체를_적용한다(self):
        text = read(INSTALL_COLLECTOR)
        self.assertRegex(text, r"(?m)^DB=opsloop-db\b")
        self.assertIn('"${PSQL[@]}" < "$SRC/infra/schema.sql"', text)


class RestoreDocs(unittest.TestCase):
    """README 'DB 복원' 절. 전문을 오류 문구에 싣지 않도록 참 · 거짓으로 본다."""

    def setUp(self):
        text = read(README)
        self.assertTrue("## DB 복원 (이슈 #45)" in text)
        self.sec = text.split("## DB 복원 (이슈 #45)", 1)[1].split("\n## ", 1)[0]

    def test_소제목(self):
        for s in ("### 백업에 드는 것 · 안 드는 것", "### 운영 DB 복원 런북", "### 배포본 data.yml 반영",
                  "### 복원 훈련", "### 데이터 노드 전손 때 더 필요한 것 (범위 밖 · 후속)"):
            self.assertTrue(s in self.sec, f"없음: {s}")
        self.assertTrue("도구: `infra/vmware/restore-drill/`" in self.sec)

    def test_백업_범위_표(self):
        for s in ("opsloop-<시각>.dump", "opsloop-<시각>.globals.sql", "--no-role-passwords", "ledger/",
                  "`/etc/opsloop` 의 파일 9개", "s3-pull.env", "s3-cti.env", "agents-state.json", "Archive created"):
            self.assertTrue(s in self.sec, f"없음: {s}")

    def test_복원_명령의_안전_줄(self):
        for s in ("pg_restore -U opsloop -d opsloop --no-owner --exit-on-error",
                  "grep -vx 'CREATE ROLE opsloop;'",
                  "grep -c docker-entrypoint-initdb /home/ops/opsloop/data.yml",
                  "docker compose down -v", "opsloop-drill-db", "슈퍼유저",
                  "default_transaction_read_only=on",
                  "opsloop-ingest --full", "--ledgers-from-start", "verify-db-roles.sh", "notify.sql",
                  "UPDATE notify_channels SET enabled = false"):
            self.assertTrue(s in self.sec, f"없음: {s}")
        # 덤프는 파일로 남기지 않고 표준입력으로 흘린다. --clean 으로 덮지 않는다
        self.assertTrue("--exit-on-error' < \"$D\"" in self.sec)
        self.assertFalse(re.search(r"pg_restore[^\n]*--clean", self.sec))
        self.assertFalse(re.search(r"pg_restore(?![^\n]*--exit-on-error)[^\n]*-d opsloop\b", self.sec))

    def test_멈춤과_되돌리기(self):
        for s in ("systemctl stop opsloop-ingest.timer opsloop-agents.timer opsloop-cti.timer",
                  "systemctl stop opsloop-gate.service", "docker stop opsloop-api", "local.opsloop.backup-db",
                  "systemctl start opsloop-gate.service",
                  "systemctl start opsloop-ingest.timer opsloop-agents.timer opsloop-cti.timer",
                  "docker start opsloop-api", "--pause", "--resume", "VERIFY=restore"):
            self.assertTrue(s in self.sec, f"없음: {s}")

    def test_비밀번호_재발급_순서(self):
        # install-collector.sh 가 schema.sql 을 다시 적용하므로 CTI 권한을 되주는 install-cti.sh 가 그 뒤다.
        # 콘솔 비밀번호(db-console-role.sh)는 콘솔을 다시 띄우므로 맨 끝 되돌리기에서 한다
        run = self.sec.split("### 운영 DB 복원 런북", 1)[1].split("### 배포본", 1)[0]
        order = [run.index(s) for s in ("pg_restore -U opsloop", "install-collector.sh $C", "install-cti.sh $CT",
                                        "infra/notify.sql", "opsloop-ingest --full", "verify-db-roles.sh",
                                        "db-console-role.sh console-a")]
        self.assertEqual(order, sorted(order))
        # 역할 목록은 복원보다 먼저 적용한다 (덤프의 권한을 받을 역할이 있어야 한다)
        self.assertLess(run.index("grep -vx 'CREATE ROLE opsloop;'"), run.index("pg_restore -U opsloop"))

    def test_배포본_반영_방법(self):
        for s in ("data.yml.prev", "config -q", "up -d postgres", "c7002275", "12,332"):
            self.assertTrue(s in self.sec, f"없음: {s}")
        # 파일만 바꿔 둔 뒤에는 서비스 이름 없는 up -d 도 postgres 를 다시 만든다
        self.assertTrue("up -d loki" in self.sec)

    def test_백업_기록에서_복원_시험_줄을_찾는다(self):
        # 2단계 grep 줄을 그대로 돌린다. backup-db.sh 는 '복원 시험' 줄 → (판정 · 조치가 늘었으면) '참고' 줄 → '백업' 줄(덤프 이름) 순서로 찍는다
        src = read(os.path.join(HERE, "scripts", "backup-db.sh"))
        self.assertLess(src.index('echo "복원 시험'), src.index('echo "참고: 덤프 뒤에'))
        self.assertLess(src.index('echo "참고: 덤프 뒤에'), src.index('echo "백업 $(du'))
        line = next(l for l in self.sec.splitlines() if "backup.log" in l and l.startswith("grep "))
        cmd = line.split("#", 1)[0]
        name = "opsloop-20260927-0730.dump"
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, "opsloop-backup"))
            with open(os.path.join(home, "opsloop-backup", "backup.log"), "w", encoding="utf-8") as f:
                f.write("== 2026-09-27 16:30:04 KST 백업 시작\n"
                        'NOTICE:  database "opsloop_restore_test" does not exist, skipping\n'
                        "복원 시험 (events verdicts actions blocklist): 복원 1 2 3 4 · 운영 5 6 3 4\n"
                        "참고: 덤프 뒤에 판정 · 조치가 늘었다 (복원 2/3 · 운영 6/3)\n"
                        f"백업 8.4M {home}/opsloop-backup/{name} · 표 23 개 · 역할 7 개 x.globals.sql\n"
                        "== 2026-09-27 16:30:12 KST 백업 성공\n")
            env = dict(os.environ, HOME=home, D=os.path.join(home, "opsloop-backup", name))
            r = subprocess.run(["bash", "-c", cmd], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("복원 시험 (events verdicts actions blocklist): 복원 1 2 3 4", r.stdout)
        self.assertIn("백업 성공", r.stdout)

    def test_배포_커밋이_저장소에_있는지_먼저_본다(self):
        # 배포에 쓴 커밋이 어느 브랜치에도 없으면(합칠 때 새 커밋) reflog 만료 뒤 사라진다. git archive 전에 있는지 본다
        run = self.sec.split("### 운영 DB 복원 런북", 1)[1].split("### 배포본", 1)[0]
        check = run.index('git cat-file -e "$c^{commit}"')
        self.assertLess(run.index("CT=$(d1 cat /opt/opsloop/cti/VERSION)"), check)
        self.assertLess(check, run.index('git archive "$C" collector'))
        self.assertLess(check, run.index('git archive "$CT" cti'))

    def test_콘솔_역할_재발급_전에_console_yml_을_대조한다(self):
        # db-console-role.sh 는 작업 트리의 console.yml 을 콘솔에 덮어쓰고 컨테이너를 다시 만든다
        text = read(os.path.join(HERE, "scripts", "db-console-role.sh"))
        self.assertIn("'cat > ~/opsloop/console.yml' < \"$ROOT/infra/vmware/compose/console.yml\"", text)
        run = self.sec.split("### 운영 DB 복원 런북", 1)[1].split("### 배포본", 1)[0]
        diff = run.index("cat ~/opsloop/console.yml' | diff - infra/vmware/compose/console.yml")
        self.assertLess(diff, run.index("infra/vmware/scripts/db-console-role.sh console-a"))

    def test_백업에_안_드는_설정_파일_수(self):
        # 데이터 노드 /etc/opsloop: *.env 8개(admin · collector · cti · detector · gate · s3-cti · s3-pull · triage) · gap-ack.json
        self.assertFalse("`/etc/opsloop/*.env` 9개" in self.sec)
        self.assertTrue("`*.env` 8개 · `gap-ack.json`" in self.sec)

    def test_수집_파이프라인_결과의_자리표시가_README_를_가리킨다(self):
        doc = read(PIPELINE_DOC)
        self.assertFalse(re.search(r"(?m)^# \(백업 복원\)$", doc))
        self.assertTrue("infra/vmware/README.md 'DB 복원 (이슈 #45)'" in doc)


if __name__ == "__main__":
    unittest.main(verbosity=1)
