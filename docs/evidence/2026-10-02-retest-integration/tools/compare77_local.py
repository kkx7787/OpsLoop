# #77 통합 대조 (Mac, 읽기만). 같은 순간에 받아 둔 다섯 파일을 맞대어 본다. 운영에는 닿지 않는다.
#   python3 compare77_local.py <증거 폴더> [접두어 c]
#   <접두어>-db.json            compare77_db.py (DB · 대시보드 · 상태판 · 띠)
#   <접두어>-enforcer-list.json sudo -n opsloop-enforcer list 의 표준 출력 (지금 DB 로 만든 두 지점 목록)
#   <접두어>-enforcer-status.txt sudo -n opsloop-enforcer status (올린 목록 · 지점별 수 · 관문 · 내부 방화벽 S3 보고)
#   <접두어>-fw-set.json        fw: sudo -n nft -j list set inet filter opsloop_block (실제 집합)
#   <접두어>-fw-status.json     fw: sudo -n cat /var/lib/opsloop-block-sync/status.json (내부 방화벽 동기화 마지막 보고)
# 관문 집합은 원격이라 직접 읽지 않는다. 관문 동기화가 회차마다 실제 집합(nft -j)을 목록과 대조해 보고하는 값으로 본다:
#   보고의 목록 digest = 올린 관문 목록 digest · 적용 = 집합 = 관문 목록 수 · 거부 0 · 오류 0 이면 관문 집합 = 관문 목록이다
#   (infra/aws/gateway/block-sync.py sync 4 · 5단계: 목록 밖 원소는 빼고, 남으면 오류 '목록 밖 원소', 빠지면 rejected).
import json, re, sys
from datetime import datetime
from pathlib import Path

d = Path(sys.argv[1]); p = sys.argv[2] if len(sys.argv) > 2 else "c"
db = json.loads((d / f"{p}-db.json").read_text())
lst = json.loads((d / f"{p}-enforcer-list.json").read_text())
status = (d / f"{p}-enforcer-status.txt").read_text()
fwset = json.loads((d / f"{p}-fw-set.json").read_text())
fwst = json.loads((d / f"{p}-fw-status.json").read_text())
ok = True


def check(label, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'일치' if cond else '불일치'}] {label}" + (f" · {detail}" if detail else ""))


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def nft_ips(doc):
    for item in doc.get("nftables", []):
        s = item.get("set") if isinstance(item, dict) else None
        if isinstance(s, dict) and s.get("name") == "opsloop_block":
            return sorted(e if isinstance(e, str) else e["elem"]["val"] for e in s.get("elem", []))
    raise SystemExit("nft 출력에 opsloop_block 집합이 없다")


pub = re.search(r"올린 목록 관문 (\S+)개 digest (\S+) · 내부 방화벽 (\S+)개 digest (\S+) · 올린 시각 (\S+)", status)
mode = re.search(r"관문 목록: (.+)", status)
pc = re.search(r"지점별 \(목록 행\): 관문 요청 (\d+) · 확인 (\d+)(?: · 미요청 (\d+))?(?: · 빠짐 확인 전 (\d+))?"
               r" / 내부 방화벽 요청 (\d+) · 확인 (\d+)", status)
rep = {k: re.search(rf"^{k} 보고: (\S+) · (\S+) · 목록 (\S+) (\S+) · 적용 (\S+) · 집합 (\S+) · 거부 (\d+) · 오류 (\d+)", status, re.M)
       for k in ("관문", "내부 방화벽")}
if not (pub and pc and rep["관문"] and rep["내부 방화벽"]):
    raise SystemExit("opsloop-enforcer status 출력 형식을 읽지 못했다")
bp = {x["point"]: x for x in db["blocks_by_point"]}
want_gw, want_fw = db["want"]["gateway"], db["want"]["fw"]
list_gw = sorted(e["ip"] for e in lst["entries"])
list_fw = sorted(e["ip"] for e in lst["points"]["fw"]["entries"])
real_fw = nft_ips(fwset)

print(f"기준 DB {db['as_of']} · 관문 목록 모드 {mode.group(1) if mode else '?'} · 올린 시각 {pub.group(5)}")
print(f"  DB 관문 {want_gw} · 내부 방화벽 {want_fw}")
print(f"  목록 관문 {list_gw} · 내부 방화벽 {list_fw} · fw 실제 집합 {real_fw}")
print("== 1. DB 요청 ↔ 집행기 목록")
check("관문: DB 의 관문 요청 행 = 집행기 관문 목록", want_gw == list_gw)
check("내부 방화벽: DB 의 살아 있는 행 = 집행기 내부 방화벽 목록", want_fw == list_fw)
check("지금 목록 = 올린 목록 (관문 digest)", lst["digest"][:8] == pub.group(2), f"{lst['digest'][:8]} / {pub.group(2)}")
check("지금 목록 = 올린 목록 (내부 방화벽 digest)", lst["points"]["fw"]["digest"][:8] == pub.group(4),
      f"{lst['points']['fw']['digest'][:8]} / {pub.group(4)}")
print("== 2. 내부 방화벽: 목록 ↔ 실제 집합 ↔ 보고")
check("fw 실제 집합(nft) = 내부 방화벽 목록", real_fw == list_fw)
check("fw 보고 목록 = 올린 내부 방화벽 목록", (fwst.get("list_digest") or "")[:8] == pub.group(4) and fwst.get("list") == "fw",
      f"{fwst.get('list')} {(fwst.get('list_digest') or '-')[:8]}")
check("fw 보고 적용 = 집합 = 목록 수 · 거부 0 · 오류 0",
      fwst.get("applied") == fwst.get("set_count") == len(list_fw) and not fwst.get("rejected") and not fwst.get("errors"),
      f"적용 {fwst.get('applied')} · 집합 {fwst.get('set_count')} · 거부 {len(fwst.get('rejected') or [])} · 오류 {len(fwst.get('errors') or [])}")
print("== 3. 관문: 목록 ↔ S3 보고 (관문 동기화가 실제 집합과 대조한 값)")
g = rep["관문"]
check("관문 보고 목록 = 올린 관문 목록", g.group(4) == pub.group(2), f"보고 {g.group(3)} {g.group(4)} / 올린 {pub.group(2)}")
# 관문 목록이 그대로이고 내부 방화벽 목록만 바뀐 회차면 보고가 올린 시각보다 앞설 수 있다(digest 가 같으면 같은 목록이다). 참고로만 찍는다
print(f"  (참고) 관문 보고 {g.group(1)} · 목록 올린 시각 {pub.group(5)} · "
      f"{'보고가 뒤' if ts(g.group(1)) >= ts(pub.group(5)).replace(microsecond=0) else '보고가 앞(관문 목록 digest 가 같으면 문제 아님)'}")
check("관문 적용 = 집합 = 관문 목록 수 · 거부 0 · 오류 0",
      g.group(5) == g.group(6) == str(len(list_gw)) and g.group(7) == "0" and g.group(8) == "0",
      f"적용 {g.group(5)} · 집합 {g.group(6)} · 거부 {g.group(7)} · 오류 {g.group(8)}")
print("== 4. 화면 수(대시보드 지점별 · 상태판 대응) ↔ 집행기 지점별 수")
gw_req = int(pc.group(1)); gw_ok = int(pc.group(2)); gw_un = int(pc.group(3) or 0); gw_rm = int(pc.group(4) or 0)
fw_req = int(pc.group(5)); fw_ok = int(pc.group(6))
G, F = bp["gateway"], bp["fw"]
check("관문 요청 = 적용 확인 + 실패 + 미확인", G["applied"] + G["failed"] + G["unverified"] == gw_req,
      f"화면 {G['applied']}+{G['failed']}+{G['unverified']} / 집행기 {gw_req}")
check("관문 확인", G["applied"] == gw_ok, f"화면 {G['applied']} / 집행기 {gw_ok}")
check("관문 미요청 · 빠짐 확인 전", G["unrequested"] == gw_un and G["removing"] == gw_rm,
      f"화면 {G['unrequested']} · {G['removing']} / 집행기 {gw_un} · {gw_rm}")
check("내부 방화벽 요청 = 적용 확인 + 실패 + 미확인", F["applied"] + F["failed"] + F["unverified"] == fw_req,
      f"화면 {F['applied']}+{F['failed']}+{F['unverified']} / 집행기 {fw_req}")
check("내부 방화벽 확인 = fw 실제 집합 수", F["applied"] == fw_ok == len(real_fw),
      f"화면 {F['applied']} / 집행기 {fw_ok} / 집합 {len(real_fw)}")
check("관문 확인 = 관문 보고 집합 수", G["applied"] == gw_ok == int(g.group(6)), f"화면 {G['applied']} / 보고 집합 {g.group(6)}")
check("집행기 멈춤 표시 없음", not G["stalled"] and not F["stalled"], f"{G['stalled']} · {F['stalled']}")
print("  대시보드 종합 상태", db["blocks"])
print("  관제 이상 띠", db["monitor"] or "없음")
print("결과:", "모두 일치" if ok else "불일치 있음")
sys.exit(0 if ok else 1)
