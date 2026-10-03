# #103 개발 시험 (2026-10-03)

기준 main `271c1e2`에서 `feat/103-console-security`의 변경을 확인했다. 운영 VM은 HAProxy 버전(2.8.16)을 읽은 것 외에는 변경하지 않았다. 실제 운영 배포·CA 신뢰 등록·VM 장애 전환·외부 Teams 수신은 미확인이다.

| 확인 | 결과 | 기록 |
|---|---|---|
| 수정 전 앱, 실제 DB 포함 | 729 통과·건너뜀 없음 | baseline-app.log |
| 수정 후 앱, 실제 DB 포함 | 745 통과·건너뜀 없음 | app-and-schema.log |
| 스키마/권한 DB 시험 | 149 통과·건너뜀 없음 | app-and-schema.log |
| 인증서 발급/검증·B 합류 | 27 통과 | certificates-and-join.log |
| Mac 감시·실제 curl·shellcheck | 54 통과 | watch.log |
| 방화벽/HAProxy 계약 | 28 중 26 통과·호스트 haproxy/nft 미설치 2 건너뜀 | firewall-contract.log |
| HAProxy 2.8 TLS 설정 문법 | 통과(공식 2.8 Docker 이미지) | haproxy-config-check.log |
| 장애 전환 계측 도구 | 56 통과 | failover-tools.log |
| 복원 훈련 도구 | 48 통과 | restore-tools.log |
| 실제 HTTPS/WSS A/B 스택 | 8 확인점 통과 | tls-stack.log |
| 잘못된 백엔드 인증서 신원 | HAProxy가 거부하고 503 | tls-wrong-backend.log |

앱/DB는 Python 3.12·PostgreSQL 16의 임시 DB/역할을 사용했다. TLS 통합은 외부 진입점 없는 Docker 내부 네트워크에서 HAProxy → 비특권 UID 1001의 uvicorn A/B → 별도 DB로 구성했다. 새 계정으로 정상/실패 로그인, Secure/HttpOnly 쿠키, A/B WSS hello, 위조 전달 헤더 제거, 공유 제한을 확인했다. TLS 발급 IP를 로컬 프록시에만 연결하도록 시험 소켓을 지정했으며 운영 IP로 시험 요청을 보내지 않았다.

개발 중 실패와 처리:

- 새 로그인 제한에 맞추어 가짜 DB 응답과 Secure 쿠키의 이전 기대값을 고쳤다.
- 전체 스키마에 마이그레이션의 BEGIN/COMMIT까지 붙이면 호출자의 트랜잭션을 커밋했다. 전체 스키마에는 본문만 남기고, 호출자 롤백 유지 시험을 추가했다. 이 문제 때문에 남았던 시험 데이터 중복도 재실행에서 해소됐다.
- 새 함수 권한과 복원 구조 수치(표 27·함수 20)에 대한 기존 계약 시험을 갱신했다.
- macOS bash 3.2의 `set -u` + 빈 배열 오류를 고쳐 Mac의 실제 curl 시험까지 재실행했다.
- 최초 로컬 계측 도구 실행은 sandbox의 루프백 bind 금지로 실패했다. 로컬 시험 서버 권한을 허용한 후 56개 통과했다. 넓은 스크립트 발견 실행은 환경 제약으로 중단하고 변경된 도구를 골라 다시 실행했다.
- TLS 시험 프로세스의 HOME이 root 경로여서 최초 기동에 실패했다. 시험 UID의 전용 HOME으로 수정했다. 운영 Dockerfile의 app 사용자는 기존 HOME을 유지한다.
- HAProxy의 `verifyhost`만 틀리게 하면 고정 SNI 이름이 우선해서 정상 연결됐다. SNI/check-sni까지 잘못된 신원으로 맞춘 거부 시험을 실행해 503을 확인했다. 운영 설정은 세 이름을 동일하게 고정하며 클라이언트 Host를 SNI로 쓰지 않는다. [HAProxy 2.8 검증 정의](https://docs.haproxy.org/2.8/configuration.html#5.2-verifyhost).

일부 기존 AnyIO·복원 시험에서 ResourceWarning이 출력된다. 통과 수와 구분해서 원문에 남겼다. 이전 전환/복원 시간 측정을 이 시험 수로 대체하지 않는다. 개인키·비밀번호·세션 쿠키는 이 증거 폴더에 넣지 않았다.
