# 종료 후 데이터 정합성 보완 검증 (#129)

2026-10-17. [리뷰·KPT](../../2026-10-17-종료후-코드리뷰-KPT.md)의 2차 검증 기록.

## 코드와 범위

- 기반: `b152ca8a` → #126 `d4b00736` → #128 `1f4268c6`.
- 이번 코드: `16f80754`(탐지·수집·KEV), `536df613`(API·화면·실시간 통보), `3b4e020e`(감사·복원), `1ffbe0f2`(풀러 복구·오류).
- 브랜치: `fix/129-data-integrity`. 원래 `chore/127-repo-finalize`의 파일·인덱스는 수정하지 않았다.
- L7·L8·L11·L13·L17·L18·L19·L20·L21·L22·L37·L38·L45·L56의 14개 리뷰 ID. 독립 장애 14회를 관측했다는 뜻은 아니다.
- 과거 시험 성과 수치와 발표 자료는 변경하지 않았다. AWS·VM·운영 DB·실제 GPU에 접속하거나 배포하지 않았다.

## 환경과 결과

Python 3.12.15, PostgreSQL 16, 기존 `opsloop-final-tests:103` 이미지. 내부 전용 Docker 네트워크, 외부 포트 없음, DB는 tmpfs와 합성 자료만 사용했다. 화면은 Vitest의 가짜 API·DOM 시험이다. 복원 도구 시험은 macOS 27 / Python 3.14에서 가짜 외부 명령으로 실행했다.

Ran 수에는 skip이 포함된다. 반복한 동일 시험은 합산하지 않는다. 아래는 각 변경 후 최종 유효 실행이며 하나의 단일 실행을 뜻하지 않는다.

| 범위 | 결과 | 원문 로그 |
|---|---|---|
| API 전체 | 775 통과 | integrity-regression-2.log |
| 마지막 L7 통보 변경 포함 API 영향 범위 | 67 통과, 실제 DB LISTEN 포함 | integrity-regression-3.log |
| 화면 전체 | 1,131 통과 / 71파일 | frontend-all.log |
| 화면 빌드·정적 검사 | 통과 | frontend-build.log · frontend-lint.log |
| detector 전체 | 275 실행, 16 skip, 나머지 통과 | detector-integrity-final.log |
| collector 전체 | 164 통과 | integrity-regression-2.log |
| CTI 전체 | 130 실행, 1 skip, 나머지 통과 | integrity-regression-1.log |
| puller 전체 | 77 통과 | integrity-regression-3.log |
| infra DB·구조 | 152 통과 | integrity-regression-5.log |
| 감사·탐지 경계 집중 시험 | 11 통과, detector 전체에 포함 | integrity-regression-5.log |
| 복원 도구 | 48 통과 | restore-tools.log |
| AI 입력 / 디코이 | 48 / 3 통과 | integrity-regression-4.log |
| #126만 분리 실행 | 입력 정제 6 · CLI 충돌 3 · 디코이 3 통과 | issue126-isolated.log |
| 전체 스키마 적용 | 성공 | schema-check.log |
| 실제 합성 DB 덤프·복원 | 감사·추천 JSON 및 모든 복원 지문 일치, 통보 고아 0, 마이그레이션 재적용 불변 | history-dump-restore.log |
| 설치 스크립트 ShellCheck / diff 공백 검사 | 통과 | 정적 확인, 실제 설치는 하지 않음 |

원문은 개인 작업 공간 `output/postproject-review-20261017/`에 남겼다. 공개 증거에는 [실행 요약](test-results.txt), [원문 해시](raw-log-sha256.txt), [소스 해시](source-sha256.txt)를 저장한다. 이 폴더의 [SHA256SUMS](SHA256SUMS)는 자체 파일을 제외한 자료 해시다.

## 실패에서 확인한 원인과 재검증

- 수정 전 규칙 정의 재사용·시간대별 사건 키·부분 기준선·수량자 검증에서 실패를 재현했다. 파일 예산 중단/폴더 조회 실패 시 오프셋 손실과 잘못된 KEV 항목으로 기존 자료가 지워지는 경우도 재현했다(`integrity-before.log`). 같은 집중 시험은 수정 후 통과했다(`integrity-after-core.log`).
- 알림 설정은 같은 조회 결과에서 연속 저장·토글을 보내 두 번째 요청이 409가 되는지 실제 DB에서 확인했다. 시간대 없는 시각은 DB 진입 전 422, 서버가 활성 차단으로 판단하면 단말 시각과 무관하게 해제 동선을 보인다.
- 삭제 전 추천 보존, 재등장 관계 제거, 롤백, 동일 재실행 중복 보관 방지, 탐지 역할의 직접 감사 쓰기 금지, 마이그레이션 재적용을 실제 DB에서 확인했다. 제한 역할 시험은 권한을 넓혀 문제를 피하지 않는다.
- 전체 탐지 시험의 가짜 커서가 새 정의 조회를 몰라 실패했고, 새 요청 계약에 화면 시험 기대값 한 곳이 뒤처졌다. 가짜 DB 응답과 요청 기대값을 맞춘 뒤 전체 시험을 통과했다.
- 감사 표 추가로 복원 검사의 기존 표·함수·트리거 수가 뒤처진 실패가 있었다. 실제 전체 스키마 수와 기대값을 함께 갱신하고 infra 152개를 재실행했다. 실제 합성 DB 덤프·복원도 별도 확인했다.
- 기존 시험의 ResourceWarning 등은 남아 있다. 경고가 전혀 없거나 모든 실환경 경로를 통과했다고 표현하지 않는다.

## 적용 순서와 호환성

이 문서는 배포 실행 기록이 아니다. 서비스를 다시 설치할 때 적용할 절차다.

1. 탐지·적재와 콘솔의 쓰기를 중지하고 기존 DB를 백업한다. 기존 AI 추천 마이그레이션까지 적용된 DB가 전제다.
2. DB 소유자/관리자 권한으로 `infra/migrations/20261017_incident_history.sql`을 적용한다. 새 설치는 `infra/schema.sql`에 같은 정의가 포함된다. 적용은 한 트랜잭션이고 반복 적용해도 감사 기록을 지우지 않는다.
3. detector·puller·collector·CTI와 콘솔 API/화면을 같은 버전으로 갱신한다. `puller/install-ingest.sh`는 두 감사 트리거가 켜져 있는지 먼저 확인한다. 탐지 접속 설정 `/etc/opsloop/detector.env`가 필요하다.
4. 수정한 복원 도구를 함께 사용한다. 새 감사 표도 백업 대조·변경 불가 기록 검사에 들어간다. 활성 사건이 없어도 보관/흡수 근거가 있으면 발송 이력을 고아로 세지 않는다.
5. 알림 수정 요청은 `expected_updated_at`을 보내야 한다. 빠지면 428, 오래되었으면 409다. 옛 화면을 새 API와 혼용하지 않고 다시 열어 최신 화면으로 조회한다. 기존 설정값 자체는 바뀌지 않는다.

같은 규칙 버전의 정의를 바꾸면 탐지가 중단된다. 실제로 규칙을 바꾸려면 새 버전 이름과 평가 기록을 사용한다. 버전 검사만 우회하거나 저장된 정의를 덮어쓰지 않는다.

감사 표는 삭제 전 사건 전체와 추천을 담으므로 운영 자료와 동일한 접근·보존 기준을 적용한다. 기존에 지워진 과거 추천을 되살리는 변경은 아니다. 표 소유자는 보존을 관리할 수 있지만 앱·탐지 역할은 감사 내용을 덮거나 삭제할 수 없다. 운영 백업 보관 정책을 대체하지 않는다.

## 격리 원장 복구

- `OPSLOOP_GAP_ACK`는 확인한 구멍을 허용하는 목록이며 격리 해제가 아니다.
- `--retry-group <세대>`는 `pull-state.json`의 `bad_groups`에 있는 세대만 명시적으로 재검사한다. 타이머와 중첩하지 않게 멈추고 원인을 확인한 다음 사용한다. 정상 사본·기존 ETag·다른 세대의 거부 기록은 유지된다.
- 받은 자료는 해시·크기·줄 경계를 다시 검증한다. 재시도했다고 무조건 정상으로 인정하지 않는다. `recoveries`에는 최대 2,000개의 재시도 기록을 둔다.
- 내부 오류는 종료 14로 분류하며 적재 뒤 탐지는 보류한다. 일시 S3 오류는 1, 구멍은 10이다. 내부 오류를 원장 형식 오류로 숨겨 영구 거부하지 않는다.

## 재실행

실제 DB 대신 폐기 가능한 PostgreSQL을 `OPSLOOP_TEST_DATABASE_URL`로 지정한다. 폴더마다 별도 프로세스로 실행한다.

```sh
python -m unittest discover -s app -q
python -m unittest discover -s detector -q
python -m unittest discover -s collector -q
python -m unittest discover -s cti -q
python -m unittest discover -s puller -q
python -m unittest discover -s infra -q
python -m unittest discover -s infra/vmware/restore-drill -q
npm --prefix console test
npm --prefix console run build
npm --prefix console run lint
shellcheck puller/install-ingest.sh
```

실제 배포·장애 전환·방화벽·GPU 재평가는 하지 않았다. #130의 환경 의존 검증·정책·규모 과제는 계속 남는다.
