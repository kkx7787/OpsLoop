# 수정 판 검토와 촬영 기능 확인

기록일 2026-10-03 · 코드 기준 main `4fb9949`(#94 · #95 병합 후) · 시각 KST.
이 폴더는 02:54 이후 재검토·촬영에서 보존한 자료다. 10/02 통합·장애 전환·전체 복원 측정값을 갱신하는 회차가 아니다. 결과서 13.2 · 13.3에서 인용한다.

## 자료와 결과

| 자료 | 확인한 것 | 범위 |
|---|---|---|
| `tests/frontend-tests.txt` · `tests/frontend-build.txt` | 콘솔 67파일 1,079건 · 타입 검사/빌드 통과 | 최초 실행 로그 복사. 별도의 새 측정 아님 |
| `tests/backend-retry.txt` | 앱 DB 시험 38건 · 웹 시험 85건, 종료 0 · OK | Docker I/O 오류 뒤 남은 두 파일 재실행 |
| `verification.json` | 후속 검토에서 관찰한 앱 25파일 729건 = 첫 23파일 606건 + 재실행 123건 | 검토 요약에서 옮긴 값. 첫 606건의 전체 원문은 별도 보존되지 않아 이 요약을 원문 로그로 부르지 않음 |
| `caffeinate-check.log` | #95 적용 뒤 00:10 수동 회차의 잠자기 방지 설정·해제 | 원본 `~/opsloop-work/review-followup/verify/caffeinate-check.log` 복사. 정기 회차 아님 |
| `tests/backup-tests.txt` | 백업 실행기 29건 통과 | Mac 프로세스 조회를 허용한 환경. 예약 실행 보장 시험 아님 |
| `source-detail.png` · `incident-closed.png` · `reports-dom.txt` | 출발지 대상 배지, 종결 사건의 상태·시계, 보고서 정의 | 후속 운영 화면의 시점 자료 |
| `dashboard-1100-two-nodes.png` · `mobile-dashboard.png` · `mobile-blocklist.png` | 1100px 요청 경로, 모바일 갱신·접기 | 가짜 자료 폭별 실측은 별도 `../2026-10-03-ui-defs/` |
| `web02-ansible.log` · `web02-postcheck.log` | 실제 노드 편입, 후속 정상 18 · 문제 0 | 인벤토리·수집 허용 경로 수작업, 방화벽 추가 줄은 실행 중 설정 |
| `block/` | HTTP 200 → 시간 초과(종료 28) → HTTP 200, SYN 거부, 해제 뒤 빈 집합 | 기존 시험 사건으로 내부 방화벽만 확인. 주기적 관찰이며 지연 재측정 아님 |
| `restore-preparation.log` · `restore-ui-db-verification.txt` | 격리 복원·무결성·역할·판정 저장 확인 | 계정 입력은 사용자, 이후 판정 저장은 에이전트. 운영 DB 판정은 바꾸지 않음 |
| `restore-capture-scope.json` · `restore-cleanup.log` | 회차 범위·SSH 터널 복구·격리 자원 정리·운영 유지 | 이번에 전체 RTO·원장 재생성을 다시 측정하지 않음 |
| `video.json` | 완성본 길이·해상도·원본 구분·SHA256 | 영상·원본 프레임은 로컬 보관, 저장소에는 넣지 않음 |

## 시험 수의 차이

#94 브랜치 기록(`../2026-10-03-ui-defs/tests.txt`)은 앱 727건이며 `test_accounts.py`가 40건이다. #95가 포함된 main 후속 검토에서는 같은 파일이 42건이라 총 729건이다. 두 판의 시험 수를 구분한다.

이번 앱 729건은 하나의 연속 전체 실행 결과가 아니다. 최초 실행의 Docker 저장 장치 오류는 제품 시험 합격으로 덮지 않고, 남은 두 파일의 재실행을 따로 적는다. 상세 결과는 [결과서 13장](../../2026-09-29-테스트-결과서.md#13-수정-판-회귀시험)에 있다.

## 보존과 확인

- 원본 위치는 `/Users/hanseongmin/opsloop-repo/output/release-review-20261003/` 및 `/tmp/opsloop-final-review/` 다. 이 폴더에는 인용에 필요한 파일만 복사했다. 비밀 파일·쿠키·등록 토큰은 포함하지 않았다.
- `SHA256SUMS`는 이 파일을 포함한 자료의 바이트 대조용이다. 해시 일치는 내용의 의미나 시험 완전성을 보장하지 않는다.
- 확인 당시 `failover-probe`는 비활성이었다. web-02 VM·등록 노드는 남겼다. 시험 차단과 격리 복원 자원은 정리했다.
- 과거 백업 간격 86,401초의 목표 미달, 기존 연결·만료·동기화 중단 미시험은 그대로다. 정기 백업 간격의 개선 효과를 이 촬영에서 확인하지 않았다.
