#!/usr/bin/env python3
"""노드 자산 조사 (이슈 #39). 노드에서 돌고 JSON 한 덩어리를 표준 출력에 쓴다.

Mac 의 collect-assets.sh 가 SSH(VMware 노드) · SSM(AWS 노드)으로 이 파일을 표준 입력으로 넘겨 돌린다
(python3 - < probe.py). 노드에 아무것도 설치하지 않고 읽기만 한다. 표준 라이브러리만 쓴다.

모으는 것
  os        /etc/os-release 의 ID · VERSION_ID · VERSION_CODENAME · PRETTY_NAME
  kernel    실행 중인 커널(uname -r)과 그 이미지 패키지 버전, 설치된 커널 이미지 패키지 전부.
            새 커널을 깔아도 재부팅 전에는 옛 커널이 돈다. 판정은 실행 중인 쪽으로 한다
  packages  설치된 dpkg 패키지 전부(상태 약어의 두 번째 글자가 i 인 것. ii 와 고정(hold)한 hi 를 함께 넣는다.
            고정한 패키지는 옛 버전으로 남기 쉬워 빠지면 '설치 안 됨'으로 잘못 읽힌다). 이름 · 버전 · 소스 패키지 · 소스 버전.
            배포판 취약점 자료(OSV Ubuntu)는 소스 패키지 이름과 소스 버전으로 찾는다
  images    도는 컨테이너의 이름 · 이미지 참조 · 이미지 ID. 이미지 안의 패키지는 호스트 목록에 보이지 않아
            여기서는 이름만 적고 취약점 대조는 하지 않는다(미확인). sudo 가 암호를 물으면 건너뛴다(errors)

값 하나를 못 읽어도 나머지는 보낸다. 못 읽은 것은 errors 에 적는다. 받는 쪽이 errors 를 보고 미확인으로 둔다.
"""
import json
import os
import platform
import socket
import subprocess
from datetime import datetime, timezone

PROBE_VERSION = 1


def run(cmd, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}: 종료 {r.returncode} {r.stderr.strip()[:200]}")
    return r.stdout


def os_release(path="/etc/os-release"):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            k, sep, v = line.strip().partition("=")
            if sep:
                out[k] = v.strip().strip('"')
    return {"id": out.get("ID"), "version_id": out.get("VERSION_ID"),
            "codename": out.get("VERSION_CODENAME"), "pretty": out.get("PRETTY_NAME")}


def dpkg_packages():
    fmt = "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n"
    pkgs = []
    for line in run(["dpkg-query", "-W", "-f", fmt]).splitlines():
        parts = line.split("\t")
        if len(parts) != 6 or parts[0][1:2] != "i":
            continue
        _, name, ver, src, src_ver, arch = parts
        pkgs.append({"name": name, "version": ver, "source": src or name,
                     "source_version": src_ver or ver, "arch": arch})
    pkgs.sort(key=lambda p: p["name"])
    return pkgs


def kernel_info(pkgs):
    running = platform.release()
    images = [p for p in pkgs if p["name"].startswith("linux-image-") and p["name"][12:13].isdigit()]
    cur = next((p for p in images if p["name"] == f"linux-image-{running}"), None)
    return {"running": running,
            "running_package": cur["name"] if cur else None,
            "running_version": cur["version"] if cur else None,
            "installed": [{"package": p["name"], "version": p["version"]} for p in images]}


def container_images():
    names = run(["sudo", "-n", "docker", "ps", "--format", "{{.Names}}"]).split()
    if not names:
        return []
    fmt = "{{.Name}}\t{{.Config.Image}}\t{{.Image}}"
    imgs = []
    for line in run(["sudo", "-n", "docker", "inspect", "--format", fmt, *names]).splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            imgs.append({"container": parts[0].lstrip("/"), "image": parts[1], "image_id": parts[2] or None})
    return sorted(imgs, key=lambda i: i["container"])


def has_docker():
    # SSM 은 PATH 가 짧을 수 있어 /usr/bin 도 본다
    dirs = os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep) + ["/usr/bin"]
    return any(os.access(os.path.join(d, "docker"), os.X_OK) for d in dirs if d)


def main():
    rec = {"probe_version": PROBE_VERSION,
           "hostname": socket.gethostname(),
           "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "os": None, "kernel": None, "packages": [], "images": [], "errors": []}
    try:
        rec["os"] = os_release()
    except Exception as e:
        rec["errors"].append(f"os: {e}")
    try:
        rec["packages"] = dpkg_packages()
        rec["kernel"] = kernel_info(rec["packages"])
    except Exception as e:
        rec["errors"].append(f"packages: {e}")
    if has_docker():
        try:
            rec["images"] = container_images()
        except Exception as e:
            rec["errors"].append(f"images: {e}")
    print(json.dumps(rec, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
