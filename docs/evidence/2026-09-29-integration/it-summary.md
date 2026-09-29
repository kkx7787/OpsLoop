# 4.3 통합 시험 실측 (2026-09-29, 모두 KST)

출발지: 공격자 VM 203.0.113.10 (외부 역할 세그먼트 vmnet5, test_ranges 203.0.113.0/24 '시연용 공격자 VM')
대상: web01 192.168.50.21:80 (nginx)

## 사전 상태 (15:38:51)
- 공격자 → web01 GET / : 200
- 집행 지점 보고 LastModified: hb/v1/host=fw-opsloop-block/latest.json 06:38:45Z, hb/v1/host=i-0ffeb29efad03546d-block/latest.json 06:38:50Z, block/v1/latest.json 06:36:45Z (모두 1분 안쪽)
- 활성 차단 13건 (그중 12건은 만료 없음 → 설계상 '집행 제외 · 만료 없음', 1건 178.16.54.226 관문 반영)
- rule_quality: R102 w1 incidents 2 judged 2 / R102 w2 incidents 2 judged 2 non_actionable 2 / R105 c1 incidents 4 judged 3 non_actionable 3
- is_test_source 사건 2건 (09-28 시연의 R102 w2 · R105 c1)

## 흐름
| 단계 | 시각 | 실측 |
|---|---|---|
| 요청 8건 (UA opsloop-integration-20260929) | 15:39:11 ~ 15:39:18 | /confluence/rest/applinks/1.0/manifest · /hnap1/ · /confluence/ · /opsloop-it-0929/a~e, 모두 404 |
| events 도착 | 15:39:51 다리 회차 (opsloop-agents 1분 타이머, web-01 줄 10 · 신규 10) | nginx.request 8건 provenance real |
| 사건 생성 | 15:40:01 | R102 w2 medium 신호 1, R105 c1 low 신호 3, 둘 다 first_ts 15:39:11 |
| 차단 요청 (콘솔, 관제사) | 15:41:50 | actions block_ip, blocklist 행 재사용 → 감사 console.block.rearmed (09-28 시연 행) , expires 09-30 15:41 (24시간) |
| 판정 | 15:41:51 · 15:42:31 | R102 threat, R105 non_actionable → 두 사건 resolved |
| 집행기 목록 올림 | 15:42:09 (06:42:09Z) | enforcement fw nft pending · gateway fail2ban pending |
| 내부 방화벽 적용 | 15:42:59 (block-sync 15:42:58 회차 'nft add 1') | fw confirmed, nft set inet filter opsloop_block 에 203.0.113.10 timeout 23h58m51s |
| 관문 적용 | 15:43:04 | gateway confirmed, enforce_note '관문 반영 · 37f3dbb5 · 2026-09-29T06:43:04Z', 감사 console.block.enforced 15:43:13 |
| 실제 차단 확인 | 15:43:17 | 공격자 → web01 curl 000, 5.00s 시간 초과 (종료 28) |
| 관문 직접 확인 (SSM 읽기) | 15:43 대 | fail2ban-client get opsloop-block banned 2개 중 203.0.113.10 있음, nft 집합 timeout 1d |
| 해제 (콘솔) | 15:44:44 | actions unblock_ip, 감사 console.block.released |
| 집행기 새 목록 | 15:45:15 | '목록을 올렸다: 1개 digest 83ed53b4', 'released 1 · exclude 12' |
| 다시 열림 | 15:46:10 | 공격자 → web01 200 (내부 방화벽 15:46:05 회차 뒤) |
| 집행 해제 기록 | 15:46:20 | 감사 console.block.unenforced, enforcement 비움 · enforced_at NULL (설계: 빠진 목록 적용 보고 시) |
| 관문 제거 확인 | 15:46:21 | fail2ban banned 에 203.0.113.10 0건, nft 0건. 내부 방화벽 집합 0건 |

소요: 요청 → 사건 50초 (15:39:11 → 15:40:01). 차단 요청 → 두 지점 적용 74초 (15:41:50 → 15:43:04). 해제 → 다시 열림 86초 (15:44:44 → 15:46:10).

## 사후 규칙 품질 (15:46:21)
R102 w1 2/2, R102 w2 2/2 non_actionable 2, R105 c1 incidents 4 judged 4 non_actionable 4.
R105 c1 judged 3 → 4 는 같은 때 운영자가 실제 출발지 128.241.254.83 의 R105 사건을 15:42:20 non_actionable 로 판정한 것. 시험 출발지 사건 두 건(threat · non_actionable)은 집계에서 빠짐 (rule_quality 뷰 WHERE NOT is_test_source). is_test_source 사건 2 → 4.

## 한계
- 관문은 인터넷 쪽 허니팟 앞(AWS)이라 공격자 VM 트래픽이 지나지 않는다. 관문은 적용 상태(fail2ban · nft)를 직접 읽어 확인했고, 실제 차단 효과는 내부 방화벽 경로로만 확인했다.
- 판정 · 차단 · 해제는 운영자가 화면에서 직접 했다(자동 판정 없음).
- 만료 없는 차단 12건은 집행 제외(설계). 이번 시험 대상 아님.
