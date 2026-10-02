# #100 관제자 사용성 점검 증거

검토일 2026-10-03 · 기준 main `e85843c` · 수정 브랜치 `fix/100-operator-ux`

범위·평가는 [관제자 사용성 재점검](../../2026-10-03-관제자-사용성-재점검.md)에 있다.
여기는 화면 수정의 회귀시험과 표본 브라우저 점검 기록이다. 새 운영 성능 측정·실제 장애 전환·복원 훈련 기록이 아니다.

## 환경과 최종 결과

macOS 27.0 · Node v22.21.1 · npm 11.11.0 · Python 3.14.3. 실제 DB 시험용 주소는 지정하지 않았다.
명령은 저장소 루트 기준이며, 프런트엔드 세 명령은 `console/`에서 실행했다.

| 명령 | 결과 | 원문 |
|---|---|---|
| `npm test -- --reporter=dot` | 70개 파일 · 1,098개 통과 | [frontend-tests-final.log](frontend-tests-final.log) |
| `npm run build` | TypeScript·빌드 통과 | [build.log](build.log) |
| `npm run lint` | 통과 · 경고 없음 | [lint.log](lint.log) |
| `env -u OPSLOOP_TEST_DATABASE_URL python3 -m unittest discover -s app` | 729개 탐색, 516개 실행 통과, 213개 건너뜀 | [app-tests-final.log](app-tests-final.log) |
| `python3 -m unittest discover -s infra/vmware/scripts -p 'test_*.py'` | 132개 탐색, 131개 실행 통과, 1개 건너뜀 | [ops-unit-permitted.log](ops-unit-permitted.log) |
| `python3 -m unittest discover -s infra/vmware/failover -p 'test_*.py'` | 56개 통과 | [failover-unit-permitted.log](failover-unit-permitted.log) |
| `python3 -m unittest discover -s infra/vmware/restore-drill -p 'test_*.py'` | 48개 통과 | [restore-unit.log](restore-unit.log) |

앱의 건너뜀은 실제 DB 조건 시험이며, 운영 도구 1개는 `test_console_join.RoleLimit.test_마이그레이션을_두_번_적용해도_같다`(임시 DB 주소 없음)다.
이를 통과 개수에 더하지 않는다. 복원 도구 원문에는 시험 코드에서 파일을 닫지 않은 `ResourceWarning`이 남아 있다.

## 초기 실패와 구분

최종 결과로 덮어쓰지 않고 `initial/`에 별도로 보존했다.

- 앱: 첫 탐색에서 `test_absorbed_db`가 선택적 `asyncpg` 대역 준비보다 먼저 import되어 오류. 다른 웹 시험과 동일하게 `test_web` 초기화를 가져오도록 수정한 뒤 전체 재실행 통과.
- 운영 도구: 제한된 실행 환경에서 로컬 포트 바인딩·프로세스 조회가 막혀 4개 실패·2개 오류. 로컬 포트/프로세스 조회가 허용된 환경에서 전체 132개를 다시 실행해 위 결과를 얻었다.
- 장애 전환 도구: 같은 로컬 포트 제한으로 16개 오류. 허용된 환경에서 56개 통과.
- 프런트엔드: 구현 과정의 실패 기록이다. 신선도 시험 기준 시각, DOM 검사와 구역 이동 방식 등을 수정하고 회귀시험을 추가했다. 이후 상세 이동 버튼, 폴링 시험, 시험 표본 중복 ID까지 반영한 최종 전체 1,098개 통과 로그를 위에 보존했다.

## 브라우저 확인

배포 콘솔의 모든 주 메뉴와 주요 상세는 읽기 점검했다. 운영 판정·차단·계정 변경·토큰 발급·Teams 발송은 수행하지 않았다.
수정판은 브라우저에서 별도 localhost 표본 서버로 확인했다. 이 서버는 운영 API에 연결하지 않고 쓰기 요청을 거절한다.
503 주입·복구 시 작성 중 사유와 선택 유지, 버튼 비활성/복구, 목록 조건 복귀를 확인했다. 저장 내용·권한 오류는 단위시험으로 확인했다.

**아래 캡처의 데이터는 고정 시험 표본이다. 실제 운영 건수·지연·신선도 측정이나 발표 성과 자료로 쓰지 않는다.**
표본 간 집계 수를 실제 데이터처럼 비교해서도 안 된다.

| 캡처 | 확인 내용 |
|---|---|
| [dashboard-1440x800.png](dashboard-1440x800.png) | 보호 대상 2개·각 로그 10줄·첫 판정 대기 행 노출, 초록 연결/관제 상태, 판정 대기 이동 |
| [dashboard-1440.png](dashboard-1440.png) | 1440×900 데스크톱 배치 |
| [dashboard-1100.png](dashboard-1100.png) | 1100×800, 요청 경로 보임·카드 한 열 |
| [incidents-mobile.png](incidents-mobile.png) | 390×844, 상단 연결/새로고침·사건 목록 페이지 스크롤 |
| [detail-error-mobile.png](detail-error-mobile.png) | 모바일 전체 페이지, 503 후 입력 보존·이전 자료·조치 비활성 |
| [alerts-desktop.png](alerts-desktop.png) | 발송 이력 사건 링크와 대상 키 접기 |

추가 320×740에서는 가로 넘침 없음과 상단 동작 노출을 확인했다(별도 캡처 없음).
미판정·심각도 정렬→상세→조치 구역→원 목록에서 조건 유지, 로그 시각 설명·규칙 조회 범위 설명도 확인했다.
브라우저 검증용 서버와 탭은 종료했고, 임시 뷰포트 설정은 해제했다.

## 미검증 범위와 반영 후 확인

- 실제 DB 회귀시험 214개(앱 213 + 운영 도구 1), 다중 관제자 부하, WCAG 전체 적합성은 검증하지 않았다.
- 운영 배포는 이 증거 생성 시점에 하지 않았다. 반영 후 목록/상세, 모바일 새로고침, 조치 구역 이동, 연결·오래된 자료 표시를 확인한다.
- 10/02 탐지·차단·장애 전환·복원 수치는 해당 판의 증거로 유지한다. 이번 통과 수가 그 수치를 수정판에서 재측정했다는 뜻은 아니다.
- 상세 30초 조회로 읽기 요청이 늘어난다. 백그라운드 조회는 기존 Query 기본 정책을 사용하며 동시 접속 부하는 별도 측정이 필요하다.

이 디렉터리의 README·로그·캡처 해시는 `SHA256SUMS`에 있다(해시 파일 자체 제외).
