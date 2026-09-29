# results.json 조립. 입력은 이 폴더의 분석 산출물뿐이다
import json
J = lambda p: json.load(open(p, encoding="utf-8"))
req = J("req_after_normal.json"); req0 = J("req_before_normal.json"); ctl = J("control.json"); tim = J("timing.json")
na = J("normal_apply.json"); cls = J("classify.json")
lab = J("rules_sigma_lab.json")["rules"][0]["params"]["signatures"]
def kv(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        p = [x.strip() for x in line.rstrip("\n").split("|")]
        if len(p) == 2 and p[0] and p[0][0].isalpha():
            out.setdefault(p[0], p[1])
    return out
fr, ff = kv("fingerprint_restored.txt"), kv("fingerprint_final.txt")
fp = lambda d, extra: {"events": int(d["events"]), "events_real": int(d["events_real"]), "incidents": int(d["incidents"]),
                       "verdicts": int(d["verdicts"]), "actions": int(d["actions"]), "blocklist": int(d["blocklist"]),
                       "sessions": int(d["sessions"]), "detector_runs": int(d["detector_runs"]),
                       "decoy_request_real": int(d["decoy_request_real"]), "nginx_request_real": int(d["nginx_request_real"]),
                       "incident_key_md5": d["incident_key_md5"], "unjudged": int(d["unjudged"]), **extra}
st = [s for s in lab if "statuses" in s]
res = {
  "date_utc": "2026-09-28", "issue": 54, "branch": "C (계약서 6장 리플레이 비교)", "timezone": "UTC",
  "lab_db": {
    "container": "opsloop-lab54 (postgres:16-alpine · 127.0.0.1:55449 · 볼륨 없음 · --rm · 남겨 둠)",
    "runner": "opsloop-lab54-py (python:3.12-slim · psycopg2-binary 2.9.13 · pyyaml 6.0.3 · --network container:opsloop-lab54 · 저장소 읽기 전용)",
    "db_url": "postgresql://opsloop:<실험 DB 비밀번호>@127.0.0.1:55449/opsloop (러너 안에서는 127.0.0.1:5432)",
    "dump": {"file": "~/opsloop-backup/opsloop-20260928-0730.dump",
             "sha256": "456fece85b46d2f50964951177ea804d90d5072089d8be6aa7e174f3983dc033",
             "archive_created_utc": "2026-09-28 07:30:06", "dumped_from": "16.15",
             "globals": "~/opsloop-backup/opsloop-20260928-0730.globals.sql",
             "globals_sha256": "c1bbfda5486b9844936d51fb33be80ef88108f0d7ef1b299aa02ae9cf7cdbce7",
             "restore": "globals 의 CREATE ROLE · ALTER ROLE · GRANT 줄만(CREATE ROLE opsloop 제외 · PASSWORD 줄 0) → pg_restore -U opsloop -d opsloop --no-owner --exit-on-error rc=0 (13:44:47 ~ 13:44:49)",
             "backup_log_match": "backup.log 복원 시험 events 137274 · verdicts 1028 · actions 167 · blocklist 26 과 같다"},
    "fingerprint_restored": fp(fr, {"events_min_ts": "2026-09-04 07:53:52.591615+00", "events_max_ts": "2026-09-28 07:22:11.349431+00",
                                    "incidents_by_version": {"c1": 3, "i1": 2, "i2": 1, "s1": 4, "v1": 555, "v2": 321, "v3": 138, "w1": 2, "w2": 2},
                                    "rule_versions": "a1,c1,i1,i2,n1,s1,v1,v2,v3,w1,w2"}),
    "fingerprint_final": fp(ff, {"events_max_ts": "2026-09-28 16:00:47+00", "events_marked_normal49": 66,
                                 "rule_versions": "a1,c1,i1,i2,n1,s1,sg1,v1,v2,v3,w1,w2", "detector_runs_added": [29972, 29973, 29974, 29975]}),
  },
  "rules": {
    "sg1": {"file": "detector/rules_sigma.json", "sha256": "4dd02f1916ce6e4e61359e42ed9e6d22a95591f49e76a21b5fab0eb196b6e695",
            "rule": "R107", "sources": 10, "signatures": 11, "rule_versions_definition_equals_file": req["rule_versions_sg1_equals_file"]},
    "c1": {"file": "detector/rules_cve.json", "sha256": "44723683e8068476171a7ef52922b4cd11b44c6ee08aef79e10c6c8d9e886143",
           "R105_signatures": 8, "R106_signatures": 5},
    "sgx": {"file": "scratchpad sigma54/rules_sigma_lab.json (증거 폴더 사본)", "sha256": "375941b9b5361437357e89107aa9fa6c7f6018dbaee8eeeb467a84ef9e878c27",
            "regenerated_same": True, "webserver_rules": 86, "pure_rules": 70, "converted_rules": 76,
            "converted_pure": 70, "converted_partial_nonpure": 6, "not_converted": 10, "signatures": 94, "signatures_of_pure_70": 85},
    "detect_py_sha256": "504b3a7e71cae0c411a2e7bad90f8c4fe4778efba087c7d5753499bcde4114be",
    "sigma_convert_py_sha256": "6c9942abecfd4a97096896ed2bc7b53252645cec3de1577c1122fe83c27c1243",
  },
  "runs": [
    {"id": 29972, "rule_version": "c1", "range": "전체", "started_utc": "2026-09-28 13:48:40", "signals": {"R105": 25, "R106": 0}, "incidents_new": 0, "incidents_total": {"R105": 3, "R106": 0}},
    {"id": 29973, "rule_version": "sg1", "range": "전체", "started_utc": "2026-09-28 13:48:41", "signals": {"R107": 0}, "incidents_new": 0, "incidents_total": {"R107": 0}},
    {"id": 29974, "rule_version": "sg1", "range": "2026-09-28 08:30 ~ 16:30 (정상 구간)", "started_utc": "2026-09-28 13:50:46", "signals": {"R107": 0}, "incidents_new": 0},
    {"id": 29975, "rule_version": "c1", "range": "전체 (sg1 · 정상 시나리오 뒤)", "started_utc": "2026-09-28 13:50:47", "signals": {"R105": 25, "R106": 0}, "incidents_new": 0},
  ],
  "c1_unchanged": {"before": "c1_snapshot_before.txt", "after_sg1": "c1_snapshot_after_sg1.txt", "final": "c1_snapshot_final.txt",
                   "c1_rows_same": True, "all_incident_keys": {"count": 1028, "md5": fr["incident_key_md5"], "unchanged": fr["incident_key_md5"] == ff["incident_key_md5"]},
                   "method": "c1 사건 3행의 (키 · last_ts · signal_count · session_count · md5(evidence) · severity) 를 c1 → sg1 → 정상 시나리오 → c1 전후로 글자 대조"},
  "request_rows": req["request_rows"],
  "decoy_status_structure": {
    "by_status": {"200": {"requests": 130, "urls": ["/admin"]}, "302": {"requests": 203, "urls": ["/"]},
                  "405": {"requests": 3, "urls": ["/"]}, "404": {"requests": 687, "distinct_urls": 319}},
    "sg1_signatures_with_statuses": 4, "sg1_rules_with_statuses": 3,
    "sgx_signatures_with_statuses": len(st), "sgx_rules_with_statuses": len({s["sigma"]["path"] for s in st}),
    "sgx_statuses_including_404": sum(1 for s in st if 404 in s["statuses"]),
    "note": "디코이는 / (302 · 405) 와 /admin (200) 밖의 모든 경로에 404 를 준다. 응답 코드 조건이 있는 서명(sg1 4개 · sgx 22개, 모두 404 를 받지 않는다)은 디코이에서 / · /admin 밖의 경로로는 원리상 맞지 않는다",
  },
  "sql_vs_python": req["sql_vs_python"], "sql_vs_python_before_normal": req0["sql_vs_python"],
  "selected": req["selected"], "sg1_union": req["sg1_union"], "sg1_stages": req["sg1_stages"],
  "c1_signatures": req["c1_signatures"],
  "incidents": {"R107_sg1": 0, "R107_by_signature": {}, "overlapping_c1": [], "same_source_c1_any_time": 0,
                "c1_existing": [
                  {"rule": "R105", "actor_ip": "74.82.47.3", "first_ts": "2026-09-20 12:30:44.531867+00", "last_ts": "2026-09-20 12:30:44.531867+00", "signals": 1, "signatures": ["geoserver"]},
                  {"rule": "R105", "actor_ip": "172.237.27.147", "first_ts": "2026-09-24 11:47:13.158986+00", "last_ts": "2026-09-24 11:47:30.440374+00", "signals": 12, "signatures": 8},
                  {"rule": "R105", "actor_ip": "45.79.123.76", "first_ts": "2026-09-25 22:37:59.602358+00", "last_ts": "2026-09-25 22:38:15.196855+00", "signals": 12, "signatures": 8}],
                "first_production_run_note": "다리는 --since 없이 전 기간을 돈다. 덤프 시점(9/28 07:30) 데이터로는 sg1 첫 실행이 R107 사건 0 을 만든다(과거 요청으로 통보가 몰리지 않는다)"},
  "normal": {"generator": "detector/normal_traffic.py --apply (--allow-port 5432, 러너 안)", "definition": "normal49-1",
             "window_start": na["window_start"], "window_end": na["window_end"], "rows_inserted": na["rows_inserted"],
             "nginx_request_rows": req["request_rows"]["normal_marked"], "incident_keys_unchanged": na["incident_keys_unchanged"],
             "sg1_hits": req["sg1_union"]["normal_marked"], "sgx_hits": req["sgx_totals"]["requests_hit_normal"],
             "c1_hits": sum(c["normal_marked"] for c in req["c1_signatures"]), "R107_incidents_in_window": 0},
  "sgx_totals": req["sgx_totals"], "sgx_rules": req["sgx_rules"], "sgx_pattern_only_hits": req["sgx_pattern_only_hits"],
  "sgx_signatures": req["sgx_signatures"],
  "control": {k: v for k, v in ctl.items()},
  "timing_ms": tim,
}
json.dump(res, open("results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)

res["findings"] = [
  "실데이터 요청 1,023건(디코이 전부 · web-01 real 0 · 출발지 195 · 2026-09-18 02:28 ~ 2026-09-28 06:30)에 sg1(선정 10 · 서명 11) 0건 · sgx(76 · 서명 94) 0건 · c1 25건(R105 사건 3 · R106 0)",
  "응답 코드 조건 때문에 빠진 요청 0 (상태 조건을 빼도 0). pattern 만 보면 sg1 서명 2개가 6건(/owa/ 4 · /dana-cached/hc/HostCheckerInstaller.osx 2)에 맞고 둘째 조건에서 빠짐. 6건 모두 c1 R105 사건의 두 스캐너",
  "R107 사건 0 · 겹치는 c1 사건 없음. 덤프 시점 데이터로 운영 첫 실행(전 기간) 때 R107 사건 · 통보 없음",
  "정상 시나리오 요청 행 38 에 sg1 0 · sgx 0 · c1 0",
  "c1 사건 3행 · 사건 키 1,028 md5 가 c1 → sg1 → 정상 → sg1 → c1 전후 같음. SQL · 파이썬 신호 다중집합 6쌍 모두 같음",
  "디코이 url 은 질의 · 퍼센트 0건이고 / · /admin 밖은 모두 404 → 질의 조건 4개 규칙 · 응답 코드 조건 3개 규칙(서명 4)은 디코이에서 원리상 맞기 어렵다. sgx 의 응답 코드 서명 22개도 404 를 받지 않는다",
  "합성 대조군(표본 45 × 2 꼴 = 90행, 임시 표 · 롤백): sg1 38 · c1 36 · 둘 다 18 · sg1 만 20 · c1 만 18 · 응답 코드로 빠짐 8 (설계값)",
  "sgx 26858 의 keywords POST 가 url 의 post-smtp 에 맞은 예: keywords 를 url 에 대는 변환이 뜻과 다른 글자에 걸릴 수 있다(최종은 빠짐)",
]
res["limits"] = [
  "web-01 실 HTTP 0 · 디코이 url 에 질의 없음 · 디코이 응답 대부분 404 → 이 회차의 0 은 재현율 비교가 아니다",
  "공격 요청(실측 양성)이 없다. c1 R106 도 0",
  "합성 대조군 수는 표본을 만든 사람이 정한 설계값이다",
  "정상 분모 요청 행 38 · 작업자 1명 · 출발지 1개",
  "덤프(9/28 07:30) 뒤 운영 요청은 보지 않았다",
  "실험 DB 는 볼륨 없는 컨테이너다",
]
res["needs"] = [
  "코드 고침 없음",
  "결정: R107 statuses 를 디코이에도 그대로 둘지(디코이에서 sg1 서명 4개 · sgx 22개가 사실상 꺼짐). 바꾸면 sg2",
  "별도 이슈 후보: c1 ivanti-connect-secure 가 /dana-cached/ 를 보지 않는다(두 스캐너 2건을 c1 · Sigma 모두 놓침). 넓히면 c2",
  "운영 반영 확인 결과 문서에 옮길 것: 첫 실행 영향(R107 0) · 신호 질의 시간 · 한계",
]
res["queries"] = open("results.md", encoding="utf-8").read().split("## 7. 수치마다 센 방법 (한 줄씩)")[1].split("## 8.")[0].strip().splitlines()
res["commands"] = open("results.md", encoding="utf-8").read().split("## 8. 명령")[1].split("```bash")[1].split("```")[0].strip().splitlines()
json.dump(res, open("results.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
print("ok+", len(res["queries"]), len(res["commands"]))

