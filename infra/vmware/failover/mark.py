#!/usr/bin/env python3
"""주입 시각 표시 (이슈 #43 장애 주입 시험). Mac 에서 돈다. 표준 라이브러리만 쓴다.

주입 명령 바로 앞에 T0 를 남긴다. 주입 명령은 여기서 돌리지 않는다. 사람이 승인 뒤 표시 바로 다음에 돌린다.
  python3 infra/vmware/failover/mark.py <회차 폴더> inject --scenario stop --target console-a && <주입 명령>
  python3 infra/vmware/failover/mark.py <회차 폴더> recover --scenario stop --target console-a && <복귀 명령>
  python3 infra/vmware/failover/mark.py <회차 폴더> note --text "HAProxy 통계 화면 확인"
  python3 infra/vmware/failover/mark.py --list        시나리오별 주입 · 복귀 명령

기록: <회차 폴더>/marks.jsonl 에 한 줄 (덧붙인다)
  {run, kind: inject|recover|note, scenario, target, host, t_local_ns, t_local_before_ns, t_remote_ns, rtt_ms, offset_ms, note}
  t_local_ns   Mac 시각. ssh 로 원격 시각을 읽고 돌아온 뒤, 주입 명령 바로 앞이다. summarize.py 는 이것을 T0 로 쓴다
  t_remote_ns  --host 의 시각(ssh <host> date +%s.%N). 주입이 일어나는 호스트의 시계로 본 T0 (docker events · 저널과 맞춰 볼 때)
  offset_ms    원격 − 로컬(왕복 가운데). 내부 노드는 방화벽을 시간원으로 쓴다(infra/vmware/README.md '시간 동기화')
  --host 의 기본은 시나리오가 정한다(컨테이너 · DB 는 대상 콘솔, VM · 망은 Mac(local), drain 은 fw). ssh 가 실패해도
  로컬 시각은 남기고 error 를 적는다(종료 0). 시나리오 이름은 summarize.py 가 회차를 묶는 열쇠다.

시나리오 (주입 · 복귀 명령은 사람이 돌린다. ssh = ssh -F ~/.ssh/config.opsloop,
          VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun",
          VMX="$HOME/Virtual Machines.localized/opsloop-console-a.vmwarevm/opsloop-console-a.vmx")
  합격선 대상
    stop     컨테이너 정지        ssh console-a 'docker stop opsloop-api'        복귀 ssh console-a 'docker start opsloop-api'
    kill     컨테이너 강제 종료   ssh console-a 'docker kill opsloop-api'        복귀 ssh console-a 'docker start opsloop-api'
    vm-off   VM 강제 끔           "$VMRUN" stop "$VMX" hard                       복귀 "$VMRUN" start "$VMX" nogui
  관찰 (승인 뒤 · 합격선은 참고)
    net-cut  망 단절(콘솔 VM 랜선)  "$VMRUN" disconnectNamedDevice "$VMX" ethernet0   복귀 "$VMRUN" connectNamedDevice "$VMX" ethernet0
    db-cut   DB 끊김(콘솔 쪽 차단)  ssh console-a 'sudo iptables -I DOCKER-USER -d 192.168.60.11 -p tcp --dport 5432 -j DROP'
                                  복귀 ssh console-a 'sudo iptables -D DOCKER-USER -d 192.168.60.11 -p tcp --dport 5432 -j DROP'
                                  (/health 가 DB 를 보므로 콘솔 A 가 빠지고, LISTEN 연결이 끊겼다 다시 붙는지 · resync 를 본다)
    drain    순차 재기동            ssh fw 'echo "@1 set server consoles/console-a state drain" | sudo -n nc -N -U /run/haproxy-master.sock'
                                  → 걸린 연결이 빠지면 컨테이너 재기동(docker restart opsloop-api) → /health 200 뒤
                                  복귀 ssh fw 'echo "@1 set server consoles/console-a state ready" | sudo -n nc -N -U /run/haproxy-master.sock'
                                  (master 소켓은 infra/vmware/README.md '콘솔 B 운용'. HAProxy 를 reload 하면 drain 이 풀린다)
  콘솔 B 로 할 때는 console-a 를 console-b 로 바꾼다. 콘솔 B 는 평소 꺼 두므로 먼저 켠다(README '콘솔 B 운용').
종료 코드: 0 · 2 설정 오류
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import common  # noqa: E402

VMRUN = '"/Applications/VMware Fusion.app/Contents/Library/vmrun"'
VMX = '"$HOME/Virtual Machines.localized/opsloop-{t}.vmwarevm/opsloop-{t}.vmx"'
SSH = "ssh -F ~/.ssh/config.opsloop {t}"
DB_RULE = "DOCKER-USER -d 192.168.60.11 -p tcp --dport 5432 -j DROP"
# 방화벽 HAProxy master 소켓 (infra/vmware/README.md '콘솔 B 운용'과 같은 꼴. @1 = 지금 작업 프로세스)
MASTER = "ssh -F ~/.ssh/config.opsloop fw 'echo \"@1 {cmd}\" | sudo -n nc -N -U /run/haproxy-master.sock'"

# 이름 → (설명, 기본 --host, 주입, 복귀, 합격선 대상). {t} 는 대상 콘솔(console-a · console-b)
SCENARIOS = {
    "stop": ("컨테이너 정지", "target", SSH + " 'docker stop opsloop-api'", SSH + " 'docker start opsloop-api'", True),
    "kill": ("컨테이너 강제 종료", "target", SSH + " 'docker kill opsloop-api'", SSH + " 'docker start opsloop-api'", True),
    "vm-off": ("VM 강제 끔", "local", VMRUN + " stop " + VMX + " hard", VMRUN + " start " + VMX + " nogui", True),
    "net-cut": ("망 단절(관찰)", "local", VMRUN + " disconnectNamedDevice " + VMX + " ethernet0",
                VMRUN + " connectNamedDevice " + VMX + " ethernet0", False),
    "db-cut": ("DB 끊김 · 콘솔 쪽 차단(관찰)", "target", SSH + " 'sudo iptables -I " + DB_RULE + "'",
               SSH + " 'sudo iptables -D " + DB_RULE + "'", False),
    "drain": ("순차 재기동 · master 소켓 drain(관찰)", "fw",
              MASTER.format(cmd="set server consoles/{t} state drain"),
              MASTER.format(cmd="set server consoles/{t} state ready"), False),
}
TARGET_RE = re.compile(r"^console-[a-z]$")


def scenario_list() -> str:
    lines = ["시나리오별 명령 (사람이 승인 뒤 mark.py 바로 다음에 돌린다. {t} 는 대상 콘솔)"]
    for name, (desc, host, inject, recover, gate) in SCENARIOS.items():
        where = "Mac" if host == "local" else ("대상 콘솔" if host == "target" else host)
        lines.append("  %-8s %s · %s · 시각 %s" % (name, desc, "합격선" if gate else "참고", where))
        lines.append("           주입  %s" % inject)
        lines.append("           복귀  %s" % recover)
    return "\n".join(lines)


def parse_remote_date(text: str):
    """'1790000000.123456789' → ns. 소수점 뒤는 9자리로 맞춘다(부동소수로 바꾸지 않는다)."""
    m = re.match(r"^\s*(\d{9,11})\.(\d{1,9})\s*$", text or "")
    if not m:
        return None
    return int(m.group(1)) * 10 ** 9 + int(m.group(2).ljust(9, "0"))


def remote_time(host: str, timeout=15):
    """→ (t_local_before_ns, t_remote_ns 또는 None, t_local_ns, error 또는 None)."""
    before = common.now_ns()
    if host == "local":
        return before, before, common.now_ns(), None
    try:
        p = subprocess.run(common.ssh_base() + [host, "date +%s.%N"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError:
        return before, None, common.now_ns(), "ssh 없음"
    except subprocess.TimeoutExpired:
        return before, None, common.now_ns(), "ssh %d초 초과" % timeout
    after = common.now_ns()
    t = parse_remote_date(p.stdout.decode("ascii", "replace"))
    if p.returncode != 0 or t is None:
        err = p.stderr.decode("utf-8", "replace").strip().splitlines()
        return before, None, after, common.clean("ssh 종료 %d: %s" % (p.returncode, err[-1] if err else "시각 없음"), 160)
    return before, t, after, None


def parse_args(argv):
    p = argparse.ArgumentParser(description="주입 시각 표시 (이슈 #43). 사용법은 파일 머리 주석")
    p.add_argument("--list", action="store_true", help="시나리오별 주입 · 복귀 명령을 보이고 끝낸다")
    p.add_argument("run_dir", nargs="?", help="회차 폴더")
    p.add_argument("kind", nargs="?", choices=("inject", "recover", "note"))
    p.add_argument("--scenario", help="시나리오 이름 (%s)" % " · ".join(SCENARIOS))
    p.add_argument("--target", help="대상 콘솔 (HAProxy 서버 이름 console-a · console-b)")
    p.add_argument("--host", help="시각을 읽을 ssh 별칭 또는 local (기본: 시나리오가 정한다)")
    p.add_argument("--run", help="회차 이름 (기본: 폴더 이름)")
    p.add_argument("--text", default=None, help="메모 (note 에는 필수)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        print(scenario_list())
        return 0
    if not args.run_dir or not args.kind:
        raise common.ToolError("회차 폴더와 inject · recover · note 가 필요하다 (--list 로 시나리오를 본다)")
    scenario = args.scenario
    if args.kind in ("inject", "recover"):
        if scenario not in SCENARIOS:
            raise common.ToolError("--scenario 는 %s 중 하나" % " · ".join(SCENARIOS))
        if not args.target or not TARGET_RE.match(args.target):
            raise common.ToolError("--target 은 console-a · console-b 꼴")
    elif not args.text:
        raise common.ToolError("note 에는 --text 가 필요하다")
    if args.target and not TARGET_RE.match(args.target):
        raise common.ToolError("--target 은 console-a · console-b 꼴")
    host = args.host
    if not host:
        role = SCENARIOS[scenario][1] if scenario in SCENARIOS else "local"
        host = args.target if role == "target" else role
    if host != "local" and not common.HOST_RE.match(host):
        raise common.ToolError("--host 가 이상하다")
    before, remote, after, error = remote_time(host)
    rec = {"run": common.run_name(args.run_dir, args.run), "kind": args.kind, "scenario": scenario,
           "target": args.target, "host": host, "t_local_ns": after, "t_local_before_ns": before,
           "t_remote_ns": remote, "rtt_ms": round((after - before) / 1e6, 3),
           "offset_ms": round((remote - (before + after) / 2) / 1e6, 3) if remote is not None else None,
           "note": common.clean(args.text, 300)}
    if error:
        rec["error"] = error
    w = common.JsonlWriter(os.path.join(args.run_dir, "marks.jsonl"))
    w.write(rec)
    w.close()
    shown = "%s %s" % (args.kind, scenario or "")
    print("표시: %s · 대상 %s · 로컬 %s · %s %s%s" % (
        shown.strip(), args.target or "-", common.iso(after), host,
        common.iso(remote) if remote is not None else "시각 없음",
        " (왕복 %.0fms)" % rec["rtt_ms"] if remote is not None and host != "local" else ""), file=sys.stderr)
    if error:
        print("경고: 원격 시각을 읽지 못했다 (%s). 로컬 시각만 남겼다" % error, file=sys.stderr)
    if args.kind in ("inject", "recover"):
        desc, _, inject, recover, _ = SCENARIOS[scenario]
        cmd = (inject if args.kind == "inject" else recover).replace("{t}", args.target)
        print("다음 명령 (사람이 돌린다): %s" % cmd, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(common.main_guard(main))
