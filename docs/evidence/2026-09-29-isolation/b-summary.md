# 4.2 B 결과 (2026-09-29 15:33 ~ 15:37 KST, 시각표 20260929T0633Z)

## S3 — 허니팟 i-0f8f7c0f698ca941a (instance-profile/opsloop-sensor-role)
| 시험 | 결과 | 1차(09-22) |
|---|---|---|
| 자기 경로 새로 쓰기(If-None-Match) | 200 | 200 |
| 같은 키 조건부 재작성 | 412 PreconditionFailed | 412 |
| 같은 키 조건 없이 덮어쓰기 | 403 | 403 |
| 삭제 | 403 | 403 |
| 읽기 · raw 목록 | 403 · 403 | 403 · 403 |
| 자기 호스트 decoy 경로 GLACIER 등급 | 403 | 미시험 |
| 자기 호스트에 gateway 센서로 쓰기 | 403 | 미시험 |
| 관문 호스트 경로에 쓰기 | 403 | **200 (미충족)** |
| 모르는 호스트 경로 | 403 | 200(당시 i-000… 에 씀) |
| raw 밖 경로 | 403 | 200(raw/_isolation_probe) |
| 관문 hb · 관문 -block 보고 · fw-opsloop-block 보고 | 403 · 403 · 403 | 없음 |
| 차단 목록 쓰기 · 읽기 | 403 · 403 | 없음 |
| cti/ 쓰기 | 403 | 403 |

## S3 — 관문 i-0ffeb29efad03546d (instance-profile/opsloop-gateway-role)
| 허니팟 cowrie 경로 쓰기 | 403 |
| 자기 호스트에 cowrie 센서로 쓰기 | 403 |
| 모르는 호스트 경로 | 403 |
| 허니팟 hb · fw-opsloop-block 보고 | 403 · 403 |
| 차단 목록 쓰기 | 403 |
| 차단 목록 읽기(head) | 200 |
| raw 목록 · 허니팟 시험 객체 읽기 · 삭제 | 403 · 403 · 403 |
| cti/ 쓰기 | 403 |

흔적: raw/v1/sensor=cowrie/host=i-0f8f7c0f698ca941a/_isolation_probe-20260929T0633Z.json 50바이트 1판(삭제 표식 없음). 다른 시험 키 판 0.
적재기 15:37:50 회차: "받지 않음 …: 키 규칙 위반", 종료 0.
STS 는 허니팟에서 닿지 않음(첫 시도가 get_caller_identity 에서 멈춤 → 취소). 역할은 describe-instances 로 확인.

## 수집 관문 입력 제한 (web01 → 192.168.60.11:3101, 15:35:34)
| 토큰 없음 | 401 missing |
| 모르는 토큰 | 401 unknown |
| 정상 토큰 + text/plain | 415 content_type |
| 정상 토큰 + JSON Content-Length 3MiB | 413 too_large |
collector.agent.rejected 2 · throttled 2 (15:35:35). R202 s1 high open 신호 2 (15:35:40 생성, 5초).
