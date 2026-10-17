# 종료 후 코드 리뷰 1차 수정 검증

2026-10-17. [검토서와 KPT](../../2026-10-17-종료후-코드리뷰-KPT.md)의 실행 증거다.

## 기준과 환경

- 수정 전 기준 커밋: `b152ca8aa215017972cb9db839a82b3ff38d33f0`.
- 수정 코드 커밋: `d873bf50dcc5578b3321d579ccb32007a868dfa1`.
- 이 코드를 #126·#128로 나눈 뒤의 `1f4268c6`은 전체 소스 트리가 동일하다. 위 커밋과 이 폴더의 파일 해시는 **1차 검증 시점**이며, 이후 #129 변경은 [별도 기록](../2026-10-17-data-integrity/README.md)을 따른다.
- 수정한 코드·시험의 정확한 파일 해시: [source-sha256.txt](source-sha256.txt). 자료 해시: [SHA256SUMS](SHA256SUMS).
- Python 3.12.15, FastAPI 0.115.6, PostgreSQL 16 계열 임시 DB. 기존 로컬 시험 이미지 `opsloop-final-tests:103` 사용.
- DB는 내부 Docker 네트워크, 외부 포트 없음, 데이터 디렉터리는 tmpfs. 합성 자료만 적재했다.
- 화면은 Vitest 5.0.1의 가짜 API와 DOM에서 검증하고 TypeScript·Vite 빌드 및 oxlint를 실행했다. 운영 브라우저·실제 방화벽 시험이 아니다.
- Mac 전용 백업 시험은 macOS 27.0.1 / Python 3.14.3에서 가짜 SSH·백업·알림·잠자기 방지 명령으로 실행했다. 실제 백업을 돌리지 않았다.
- 실제 GPU·AWS·VM과 운영 DB에는 연결하지 않았다. 이 회차의 변경을 배포하지 않았다.

## 수정 전 실패와 수정 후 확인

[before-summary.txt](before-summary.txt)는 수정 전에 실행한 시험 로그에서 시험 이름과 결과 줄만 추출한 것이다. 원문 전체와 모델 입력 출력은 개인 작업 공간에 남기고 여기에는 복제하지 않는다. 원문 파일의 해시는 [raw-log-sha256.txt](raw-log-sha256.txt)에 있다.

| 항목 | 수정 전 관찰 | 수정 후 증거 |
|---|---|---|
| M1 | 상대 URL과 셸 명령의 합성 비밀 표식이 모델 요청 본문에 남음 | recommend의 EvidencePrivacyTests, 전체 48건 통과 |
| M2 | 목록 이후 저장한 다른 판정에 CLI 판정이 추가됨 | triage의 NonSshBulkAcceptDatabaseTests에서 수동·일괄 모두 기존 판정 보존 |
| M3 | 첫 성공·실패 로그인 이벤트의 session이 None | decoy의 세션 시험 3건 통과 |
| L2 | 출발지 없는 block_ip 요청이 거부되지 않음 | test_block_points.SchemaTests에서 400, 조치 0건, 사건 상태 유지 |
| L6 | 범위 밖 입력이 검증을 지나 가짜 DB 객체까지 도달 | test_notify.ValidationEchoTests에서 422. 수정 전 시험은 DB 진입을 보여 주며 실제 운영 500 이력을 재현한 것은 아님 |
| L10 | 진행 중 다른 조치로 확인 폼과 결과가 사라짐 | IncidentDetailPage 시험에서 요청 1회, 늦게 온 오류 유지 |
| L14 | 검색 한 글자 입력 뒤 해제 확인이 닫힘 | BlocklistPage 시험에서 검색에 계속 남는 행의 확인 유지 |
| L24 | 2개 사건의 판정 진척을 2/3으로 표시, 옛 관측값이 통계에 남음 | LatestVerdictReportingTests 3건에서 1/2와 최신 관측값 확인 |
| L25 | session_threshold의 현재 임계치를 읽지 못함 | 현재 value=7과 최신 관측 분포 확인 |

처음 API 재현 실행에 섞인 test_notify import 오류는 제품 결함 수에 포함하지 않는다. 수정 과정에서 Query 기본값을 직접 함수 호출에 전달하는 회귀가 API 전체 시험에 한 번 걸렸고, Annotated 인자와 None 기본값으로 고친 뒤 API 772건을 다시 통과했다. 실패 로그 요약도 남긴다.

## 확대 회귀 결과

시험 수는 unittest가 보고한 Ran 값이며 skip을 포함한다. 반복 실행한 동일 시험은 합산해 성과 수치로 쓰지 않는다.

| 범위 | 실행 수 | 최종 확인 |
|---|---:|---|
| app | 772 | 전부 통과, 실제 PostgreSQL 통합 포함 |
| console | 1,130 / 71파일 | 전부 통과, 빌드·정적 검사 통과 |
| recommend | 48 | 통과 |
| detector | 264 | 통과, 16건 skip |
| decoy | 3 | 통과 |
| parser | 65 | 통과 |
| cti | 129 | 시험 시계 수정 후 통과, 1건 skip |
| collector | 161 | 통과 |
| puller | 74 | 통과 |
| enforcer | 192 | 통과, 2건 skip |
| sensor | 18 | 통과 |
| infra | 152 | 통과 |
| infra/aws/gateway | 72 | 통과, 2건 skip |
| infra/vmware/scripts (Linux 컨테이너) | 150 | 통과 137, 실패 5, skip 8 |
| backup_db (대상 환경인 Mac 재확인) | 29 | 전부 통과. 위 Linux 실패 5건을 포함한 백업 시험 |
| infra/ansible | 32 | 통과 |

전체를 ‘skip 없이 모두 통과’라고 표현하지 않는다. Linux 이미지에는 가짜 알림 시험이 사용하는 ps가 없었고, Mac 전용 프로세스 동작까지 Linux에서 동일하게 검증하지 못했다. 백업 코드를 바꾸어 Linux 시험에 맞추지 않고 대상 환경에서 확인했다. Mac 시험 통과는 실제 예약 실행·잠자기·SSH 장애 복구 훈련을 대신하지 않는다.

CTI의 실패는 고정된 9월 표본 시각을 최근 조회 시각에 넣고 DB의 현재 시각으로 14일을 비교하는 시험 구성 때문이었다. DB 시각을 기준으로 시험 자료를 만들고, 15일 지난 자료는 다시 받는 반대 조건도 추가했다. CTI 제품 코드는 변경하지 않았다.

일부 기존 시험에서 ResourceWarning과 가짜 HTTP 서버의 BrokenPipe 출력이 있었다. 전체 경고 0이라고 보고하지 않는다. 시험 통과는 처리되지 않은 모든 경로의 안전성을 증명하지 않는다.

## 다시 실행할 때

아래 명령은 이 저장소 루트에서 실행한다. Python 의존성이 설치된 시험 환경과 **폐기 가능한 PostgreSQL DB**를 사용하고 OPSLOOP_TEST_DATABASE_URL을 그 DB로 지정한다. 실제 DB를 지정하지 않는다. 폴더마다 별도 프로세스로 실행해 동일 이름의 모듈 충돌을 피한다.

```sh
python -m unittest discover -s app -v
python -m unittest discover -s recommend -v
python -m unittest discover -s detector -v
python -m unittest discover -s decoy -v
python -m unittest discover -s cti -v
npm --prefix console test
npm --prefix console run build
npm --prefix console run lint
```

확대 범위는 parser, collector, puller, enforcer, sensor, infra, infra/aws/gateway, infra/vmware/scripts, infra/ansible에 같은 unittest discover 방식을 사용했다.

Mac 백업 시험:

```sh
python3 -m unittest discover -s infra/vmware/scripts -p test_backup_db.py -v
```

주요 시험 소스:

- [AI 입력](../../../recommend/test_opsloop_recommend.py)
- [CLI 판정과 집계](../../../detector/test_triage.py)
- [디코이 세션](../../../decoy/test_app.py)
- [차단 API](../../../app/test_block_points.py), [알림 검증](../../../app/test_notify.py)
- [조치 화면](../../../console/src/pages/incident-detail/IncidentDetailPage.test.tsx), [차단 검색](../../../console/src/pages/blocklist/BlocklistPage.test.tsx)
- [CTI 날짜 시험](../../../cti/test_opsloop_cti_db.py)

## 보존한 범위

- 과거 DB·로그를 고쳐 새 판정 집계를 과거 결과인 것처럼 바꾸지 않았다.
- p5 입력 정제는 가짜 모델로 검증했다. 실제 모델 평가 결과는 없다.
- 직접 추가한 CLI 충돌 시험은 같은 DB에서 저장 순서를 끼워 넣는 재현이다. 별도 프로세스의 모든 경쟁 조건을 검증한 것은 아니다.
- 생성한 화면 빌드는 시험용이며 운영에 올리지 않았다.
- 이번에 만든 임시 DB와 네트워크는 시험 종료 후 제거했다. 기존 이미지나 사용자 자료는 삭제하지 않았다.
