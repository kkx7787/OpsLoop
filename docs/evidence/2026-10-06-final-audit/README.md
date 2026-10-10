# 2026-10-06 최종 점검 자동 시험 근거

## 출처

- 원본 폴더: output/final-audit-20261006
- 2026-10-06 최종 점검(이슈 #118, 작업 브랜치 hotfix/118-final-audit, 기준 main 8d8e79b) 때 만든 기록이다. 원본을 고치지 않고 그대로 복사했다.
- 복사한 것: review.md, pr-body-final.md, pr-body.md, 그리고 *.log, *.txt 파일 전부(32개). 원본 폴더에 json 파일은 없었다. 화면 캡처(png)와 preview-server.mjs 는 복사하지 않았다.
- 복사한 파일마다 sha256 을 SHA256SUMS 에 남겼다. 확인 방법: `shasum -a 256 -c SHA256SUMS`

## 발표 자료 14쪽 수치의 근거

발표 자료 14쪽이 인용하는 수치는 review.md 의 "시험" 표(34줄부터)에 있다. 원문을 쉼표로 풀어 적었다.

| 발표 수치 | review.md 줄 | 원문 요지 | 실행 로그 |
|---|---|---|---|
| 화면 시험 1,111건 통과 | 36줄 | 프런트엔드, 1,111 통과, 마지막 수정 후 상세 70 통과, 빌드와 린트 통과 | frontend-final.log 10줄 (Tests 1111 passed) |
| API 764건 통과 | 37줄 | API, 764 통과, 격리 DB 포함 | app-final.log 53줄 (Ran 764 tests), 55줄 (OK) |
| 차단 집행기 192건 중 190건 통과, 2건은 환경 의존이라 건너뜀 | 43줄 | 집행 / 센서, 192 중 190 통과, 2 건너뜀 / 18 통과 | enforcer-sensor.log 4줄 (Ran 192 tests), 6줄 (OK, skipped=2) |

건너뜀이 해당 환경의 바이너리, DB 설정, 과거 리플레이 자료에 의존한다는 설명은 review.md 49줄에 있다. frontend-after.log 는 마지막 수정 전 실행 기록으로 3건 실패(402줄)가 남아 있으며, 수정 뒤 재실행한 frontend-final.log 가 최종 결과다. 초기 실패 기록을 지우지 않고 함께 보존한다는 원칙은 review.md 49줄과 같다.

## 범위 한정

이 수치는 2026-10-06 판(main 8d8e79b 기준, hotfix/118-final-audit) 기준이며, 그 뒤 판에 대한 통합 합격을 뜻하지 않는다.
