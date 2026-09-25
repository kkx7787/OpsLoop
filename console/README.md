# OpsLoop 관제 콘솔 (console/)

React 19 · TypeScript · Vite 8 · Tailwind v4 · TanStack Query 5 · react-router 7. 화면 설계는 `docs/2026-09-18-화면-설계.md`,
시각 디자인은 2026-09-23에 채택한 공통 컴포넌트와 디자인 토큰을 기준으로 한다.
기존 와이어프레임은 기능·업무 흐름을 참고하며, 새 화면도 아래 디자인 기준을 따른다.

## 명령

| 명령 | 하는 일 |
|---|---|
| `npm run dev` | 화면만 띄운다. `/api` · `/login` · `/logout` · `/health` · `/ws` 는 `http://127.0.0.1:8000` 으로 넘긴다(`OPSLOOP_BACKEND` 로 바꾼다). |
| `npm run build` | `tsc -b` 뒤 `../app/static/` 에 만든다(git 에 넣지 않는다). CSS 는 파일 하나, 인라인 스크립트 없음(CSP). |
| `npm test` | vitest(jsdom · testing-library) |
| `npm run lint` | oxlint |

## 구조

```
src/styles/index.css   디자인 토큰(@theme): 색 · 글자 크기 · 모서리 · 그림자. 외부 글꼴 없음
src/lib/cn.ts          cn(...) = twMerge(clsx(...)). 새 토큰(모서리 · 그림자 · 자간)은 여기 등록
src/lib/domain.ts      심각도 · 판정값 · 상태 값과 화면 표기 · 발생원(sensorOf) · 판정 목표 시간(verdictTargetSeconds · elapsedTone) · 조치 이름
src/lib/time.ts        KST 표시 · 경과 시간(secondsSince)
src/lib/untrusted.ts   비신뢰 문자열 표시 규칙(#41): revealHidden(숨은 문자 → 표식 문자열) · untrustedParts · 글자 수(코드 포인트)
src/api/client.ts      fetch 공통 인스턴스(api). 시간 초과 15초 · 401 은 /login?next= 로 한 번만 이동 · 오류는 ApiError
src/api/queryClient.ts 재시도 규칙: 5xx · 네트워크만 2회
src/api/incidents.ts   인시던트 목록(useIncidentsPage · 페이지별 limit/offset) · 상세(useIncident) · 판정 · 조치(useVerdictMutation · useActionMutation) · 규칙 품질. 쿼리 키는 incidentKeys · ruleKeys
src/api/monitoring.ts  대시보드(useSummary) · 차단 목록(useBlocklist). 기존 API 조회 · 30초 재조회 · 서버 시각으로 만료 계산
src/api/notify.ts      알림 채널(useChannels · createChannel · updateChannel · testChannel) · 발송 이력(useDeliveries). 채널 주소는 함수로만 보내고 캐시에 두지 않는다. 쿼리 키는 notifyKeys
src/api/cti.ts         CVE · KEV 연계(#39): 사건 연계(useIncidentCti) · 주목 CVE(useWatch) · 자산 목록(useAssets) · 자산 상세(useAsset · 거르기 · 쪽). 쿼리 키는 ctiKeys(사건 상세 키 밑에 두지 않는다)
src/api/live-context.ts 공통 연결 상태. S-10에서 웹소켓 끊김과 REST 조회 실패를 구별
src/api/live.ts        실시간 통보(WS /ws). useLiveUpdates 가 한 번 잇고 통보마다 해당 쿼리를 무효화한다. 끊기면 1초 → 30초 지수 백오프. 재접속하면 놓친 통보를 보완하도록 목록·상세·지표 · CVE 연계를 재조회
src/auth/roles.ts      권한표(화면 설계 15장). can(role, action) · permission(role, action)
src/auth/useMe.ts      GET /api/me · usePermission(action)
src/lib/useNow.ts      상단바 시계용 지금 시각
src/components/        atoms · molecules · organisms · templates. index.ts 로 내보낸다
  organisms/states/    상태 화면(불러오는 중 · 0건 · 403 · 세션 만료 · 오류 · 404 · ApiErrorState)
  organisms/nav/       메뉴 조각: nav-items(자료형 · findNavItem) · NavMenu · Brand · UserPanel(로그아웃 폼) · SensorSummary
  organisms/incidents/       인시던트 목록(S-03) 조각: 조건(filters · 주소 왕복) · 표 행 · 모바일 카드 · 높이 제한 목록 · 페이지 탐색 · 조건 막대 · 경과 시간
  organisms/incident-detail/ 인시던트 상세(S-04) · 판정 패널(S-05) 조각: 머리글 · 구역 ①~⑤ · ⑥ 취약점 연계(VulnLinkPanel) · 조치 막대 · 판정 패널 · 이력 · format(서버 행 → 글)
  organisms/assets/          자산 · 취약점(#39) 조각: 주목 CVE(WatchCard) · 자산 표(AssetTable) · 자산 상세(AssetDetailSection) · 공개 정보 신선도(CtiFreshnessFacts) · cti-format(적용 판정 · CVSS · EPSS 표기). ⑥ 도 이 신선도 · 표기를 쓴다
  organisms/notify/          알림 설정(S-12) 조각: 채널 양식(ChannelForm · 주소 password 형 · 틀 미리보기) · 채널 표(ChannelTable) · 발송 이력(DeliveryTable) · template(자리표시자 치환)
  organisms/           TopBar(경로 표시 · 실시간 연결 표시 · KST 시계 · 새로고침 · 모바일 메뉴 단추) · LiveIndicator · SideNav(208px) · MobileNav(서랍)
  templates/           AppLayout(사이드바 + 상단바 + 본문 · /api/me 확인 · 401 → 로그인 · 실시간 통보 연결) · breadcrumbs
src/app/router.tsx     경로표(react-router 7). / · /incidents · /incidents/:key · /blocklist · /rules · /sources · /reports · /nodes · /inventory · /alerts · /audit · /accounts · *
src/app/nav.ts         메뉴 묶음(관제 · 대응 · 분석 · 수집 · 관리). 관리 묶음은 admin 이 아니면 흐리게
src/app/screens.ts     화면 자리 정보(설계 번호 · 제목 · 한 줄 설명 · WBS)
src/app/ComponentCatalog.tsx  공통 컴포넌트 모음. 개발 서버에서만 /dev/components
src/pages/             구현 화면 및 나머지 화면 자리(PlaceholderPage · PendingCard · NotFoundPage · RouteError)
  pages/dashboard/      미판정 현황(S-02): 경과 분포 · 목표 초과 · 우선 확인 8건 · 규칙별 비조치율
  pages/blocklist/      차단 목록(S-06): 활성·만료·해제 · 검색·페이지 탐색 · 관리자 해제
  pages/incidents/       인시던트 목록 화면(IncidentsPage). 조건·page·page_size를 주소에 두어 새로고침·뒤로 가기·공유에도 남는다
  pages/incident-detail/ 인시던트 상세 · 판정 화면(IncidentDetailPage). 사건 키가 바뀌면 판정 소요 시계를 다시 시작한다
  pages/alerts/          알림 설정(S-12): 채널 표 · 추가/수정 양식 · 사용/중지 · 시험 발송 · 발송 이력. admin 이 아니면 403
  pages/assets/          자산 · 취약점(#39, 경로 /inventory): 주목 CVE · 신선도 요약 · 자산 표 · 고른 자산의 주요 패키지 · 이미지 · 배포판 취약점(?asset= 로 주소에 남는다)
src/test/              vitest setup(WebSocket 은 아무 일도 하지 않는 소켓) · render(메모리 라우터 · /api/me 스텁) · hostile-fixtures(악성 표본 · DOM 점검)
```

## 규칙

- 패키지는 Mac 에서 받아 빌드 결과(app/static)만 콘솔 VM 으로 옮긴다. 외부 글꼴 · CDN 은 쓰지 않는다(CSP).
- 한국어 UI · 한국어 주석.
- 모든 공통 컴포넌트는 `className` 을 받아 `cn` 으로 합친다. 뒤에 준 클래스가 이긴다.
- 인시던트 조치 버튼은 권한에 따라 숨긴다(operator: 확인·차단, admin: 해제·억제 포함). 판정 패널과 관리 메뉴는 `Gated`로 비활성 표시한다. 서버도 같은 권한을 검사한다.
- 도구 제안은 상세 API의 `proposal`을 표시하며 자동 선택하지 않는다. 판정할 때 `proposed`·`decision_seconds`를 함께 저장하고 이력에서 수락/뒤집힘과 소요 시간을 보여 준다. 제안이 없거나 과거 이력에 미기록이면 뒤집힘으로 세지 않는다.
- 목록은 기본 25건, 50·100건 선택과 페이지 번호·이전/다음을 지원한다. 조건·정렬·페이지 크기를 바꾸면 1쪽, 실시간 판정으로 마지막 쪽이 사라지면 유효한 마지막 쪽으로 이동한다.
- 규칙 필터는 목록 API의 `rules`를 사용한다. 아직 불러오지 않은 페이지의 규칙도 선택할 수 있으며 목록 화면에서 규칙 품질 API를 별도로 호출하지 않는다.
- 로그인 화면은 서버가 그린다(GET /login). 화면은 `/api/me` 가 401 이면 `/login?next=<지금 경로>` 로 옮겨 가고, 로그아웃은 `POST /logout` 폼이다.
- 상단바 경로 표시는 메뉴 정의에서 나온다. 칸을 더하려면 경로의 `handle: { crumb }` 를 쓴다. 인시던트 상세는 '사건 상세'로 표시하며 전체 사건 키는 본문에서 펼쳐 본다.

## 채택한 디자인 기준 — 2026-09-23

- 비교 브랜치 `codex/console-design-comparison`의 디자인(`ffa9966`)을 작업 브랜치에 채택했다.
- 적용 범위: 공통 화면 틀·컴포넌트, 인시던트 목록(S-03), 상세·판정(S-04·S-05). 대시보드(S-02)·차단 목록(S-06)·연결 상태(S-10)도 같은 기준을 적용한다. 서버 로그인과 나머지 개별 화면·와이어프레임은 별도 작업이다.
- 데스크톱: 상단바 48px, 본문 위아래 16px. 목록은 나머지 화면 높이를 사용한다.
- 카드 8px·입력 5px 모서리, 패널에는 얇은 선을 사용한다.
- 심각도는 기존 등급 색, 신규 상태는 중립색, 판정 시간 목표는 황갈색으로 구별한다.
- API, 판정값, 권한, 상태 전이, 목표 시간 계산은 동일하다.
- 상세의 사건 키는 펼쳐 보고, 출발지·발생 구간·관측 정보를 별도 줄에서 읽는다.
- 새 화면은 `AppLayout`, `PageHeader`, `Card`, `Button`, 공통 입력·상태 컴포넌트를 재사용한다. 색·간격·모서리를 화면마다 따로 정하지 않는다.
- 목록은 필터 → 결과 → 페이지 탐색 순서로 배치한다. 표가 길면 표 안에서 스크롤하고, 작은 화면에서는 내용에 따른 자연스러운 스크롤을 허용한다.
- 원래 와이어프레임의 기능은 구현 여부를 확인해 반영한다. 디자인 변경만으로 기능을 삭제하거나 예시 수치를 실제 운영 상태로 표시하지 않는다.
- 비교 브랜치는 채택 후 정리했으며 이력은 로컬 `output/git-archive/console-design-comparison-8107502.bundle`에 보관했다. 현재 코드에는 채택한 제품 디자인을 유지한다.


## 대시보드 · 차단 목록 (#26)

- 새 API 경로 없이 `/api/stats/summary`와 `/api/blocklist` 응답에 필요한 집계·집행 필드를 추가했다. API와 화면 빌드를 함께 배포해야 한다.
- 미판정은 상태값이 아니라 판정 이력이 없는 사건이다. 목표 임박은 목표의 2/3 이상, 초과는 목표 이상이다. 경과 시간은 서버 조회 시각 기준이다.
- 비조치율은 사건별 마지막 판정만 센다. `(무시 가능 + 오탐 + 양성 정탐) / (마지막 판정 중 미결 제외)`이며 유효 판정이 없으면 `판정 없음`이다. 여러 규칙 버전은 따로 표시한다.
- 차단은 활성(만료·해제 전)·만료·해제로 구분하고, 집행 확인은 `enforced_at`으로 별도 표시한다. 화면의 활성 요청 수는 실제 트래픽 차단을 보장하지 않는다.
- 차단 해제는 admin만 할 수 있다. 서버가 행을 잠그고 만료·선행 해제·근거 사건 변경을 검사해 409로 거부하며, 처음 해제한 사람과 시각을 보존한다.
- 웹소켓 단절 시 재연결 안내와 30초 조회를 유지한다. REST 조회도 실패하면 마지막 결과·시각을 남기고 해제 버튼을 비활성화한다. DB·센서 장애 원인을 추정해 표시하지 않는다.
- 차단 목록은 받은 배열에서 검색·페이지 탐색한다. 서버 페이지 API는 이번 범위에 추가하지 않았다.
- DB 회귀 시험: `OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app -p test_dashboard_db.py`. 연결별 임시 테이블만 사용하며 운영 계정·사건·차단을 생성하지 않는다.

## 규칙 · 노드 · 감사 (#27)

- `/rules`(S-07): 규칙별 마지막 판정 집계, 비조치율, 규칙 정의·변경 근거, 동일 구간의 버전별 저장 결과, 최근 탐지 실행 30회를 조회한다.
- `/api/rules/quality` 기본 응답은 기존 배열을 유지한다. `details=true`에서는 `rows`, `versions`, `runs`를 반환하며 `since`·`until`을 함께 지정할 수 있다. 시간 필터는 사건 시작 시각의 `[since, until)`이다.
- 비율은 사건별 마지막 판정만 사용하고 미결을 분모에서 제외한다. 전체 기간의 버전별 결과는 관측 기간이 다를 수 있어 바로 개선율로 표시하지 않는다. 실행 이력의 `incidents`는 해당 실행에서 **새로 생성된 사건 수**다.
- 리플레이 화면은 이미 저장된 사건을 비교한다. 탐지 재실행·규칙 수정·자동 배포 기능은 포함하지 않는다. 동일 입력 여부는 실행 이력으로 확인하며, 한 버전에 기록이 없는 경우 `결과 없음`으로 표시한다. 사건 링크는 해당 규칙의 모든 버전을 연다.
- `/nodes`(S-08): `nodes`에 등록된 에이전트의 목록·검색·페이지 탐색. 마지막 수신이 10분을 넘으면 침묵, 미등록은 대기, 폐기 상태는 별도 표시한다. 침묵만으로 서버 장애를 확정하지 않는다.
- `/nodes/new`(S-13): admin만 등록 토큰을 발급·취소한다. 기존 `olE_` 형식·1시간·1회용 계약을 사용하며 서버에는 SHA-256만 저장한다. 브라우저 Query/Mutation 캐시·저장소에는 원문을 넣지 않고, 페이지를 떠나거나 만료되면 지운다. 발급 응답은 `no-store`다.
- 재발급은 기존 미사용 등록 토큰만 취소한다. 이미 등록된 에이전트의 키는 유지하며, 대상 정보가 기존 등록과 다르면 409로 거부한다. 노드 설치와 네트워크 준비는 기존 Ansible 절차로 수행한다.
- 토큰 발급·취소와 `audit_event` 기록은 같은 트랜잭션이다. 감사 실패 시 발급도 롤백한다. 감사 기록에 토큰·해시는 넣지 않는다.
- `/audit`(S-14): admin만 `audit_log`를 조회한다. 행위자·대상(노드/IP)·KST 시간 필터와 서버 페이지 탐색을 제공한다. 현재 기록 범위는 차단 해제·만료 변경과 콘솔의 등록 토큰 발급·취소다. 계정·권한 관리 전체를 구현했다는 뜻은 아니다.
- 노드·감사는 30초 조회와 웹소켓 재접속 시 재조회한다. 판정 통보는 규칙 집계, 조치 통보는 감사 기록도 갱신한다.
- 배포 전 `infra/migrations/20260923_console_ops.sql`을 적용한다. 새 표를 만들지 않고 최신 판정 집계 뷰, 감사 조회 뷰, 토큰 감사 행의 변경·삭제 방지 트리거를 갱신한다.
- DB 시험: `OPSLOOP_TEST_DATABASE_URL=... python3 -m unittest discover -s app -p 'test_*db.py'`. 연결별 임시 테이블만 사용한다. 운영 테이블에 쓰는 `audit_event`는 시험에서 임시 삽입으로 교체한다.

## 알림 (S-12 · #33)

- `/alerts`(S-12): admin만 알림 채널(Microsoft Teams Workflows 웹훅 · 일반 웹훅 JSON)을 만들고 고치고 시험 발송하며, 발송 이력을 채널·상태별로 조회한다. 등급은 즉시(immediate)와 일일 요약(daily 09:00 KST), 사건 종류는 `incident.created` · `pending.overdue` · `node.silent` 다.
- Teams 쪽 준비: Power Automate 에서 "Teams 웹훅 요청을 받으면 채널에 게시" 흐름을 만들고 나온 주소를 화면에 입력한다. 콘솔은 그 트리거 형식(`type: message` + Adaptive Card 1.4, "콘솔에서 보기" 단추)으로 보내고 2xx(보통 202)면 성공이다. Teams 주소는 https · 호스트 `*.environment.api.powerplatform.com` 만 받는다(옛 `*.logic.azure.com` · `*.webhook.office.com` 은 동작하지 않아 거부하고 흐름을 다시 저장하라고 안내한다).
- 메시지 틀은 채널마다 화면에서 고친다: 머리말(`template_header`, 채널 · 사건 종류당 한 번)과 항목 한 줄(`template_item`, 사건마다 최대 20개, 넘으면 '외 n건'), 끝에 콘솔 링크. 자리표시자는 `{event_label}` `{count}` `{severity_counts}` `{rule_id}` `{rule_name}` `{severity}` `{who}` `{elapsed}` `{first_ts}` `{incident_key}` `{link}` 만 문자 치환한다(`str.format` 금지 · 형식 지정자 불허, 모르는 자리표시자는 그대로, 빈 값은 `-`). 원문 로그 · 입력된 비밀번호 · 내부 주소는 본문에 넣지 않는다. 시험 발송도 같은 틀에 예시 값을 채워 보낸다.
- API 는 `GET/POST /api/notify/channels`, `PUT /api/notify/channels/{id}`, `POST /api/notify/channels/{id}/test`, `GET /api/notify/deliveries` 다. 채널 만들기·바꾸기는 `audit_event` 와 같은 트랜잭션이며 감사 상세에는 바뀐 필드 이름만 남긴다.
- 발송기는 콘솔 API 안에서 돈다(큐 채우기 30초 · 보내기 15초). 묶음 시간은 (채널, 사건 종류) 무리의 첫 사건부터 재고, 그 안에 들어온 사건을 모두 한 메시지로 보낸다. 실패하면 1 · 5 · 15분 뒤 다시 보내며 3회를 넘기면 `failed` 다. 콘솔 두 대가 같은 행을 집지 않도록 DB 에서 잠그고, 결과는 자기가 집은 행에만 기록한다.
- 채널을 만들거나 다시 켜거나 범위(등급 · 사건 종류 · 최소 심각도)를 넓히면 그 시각(`enabled_at`) 뒤의 사건 · 목표 초과만 보낸다. 끄면 대기 중인 알림은 보내지 않음(`ChannelDisabled`)으로 닫고, 사건 종류 · 등급을 바꿔 더는 보내지 않을 대기 알림은 `ChannelChanged` 로 닫는다.
- 일일 요약 채널은 사건 종류 · 최소 심각도 · 묶음 시간 · 항목 틀을 쓰지 않는다. 양식은 이 칸을 숨기고, 미리보기는 요약 모양(머리말 + 고정 요약 줄)으로 그린다. 즉시 채널 미리보기는 1건일 때와 여러 건일 때를 같이 보인다.
- 발송 실패 원인은 예외 이름(`gaierror` · `ConnectionRefusedError` · `TimeoutError` · `SSLCertVerificationError`)이나 응답 코드로 남기고, 화면은 이를 조치 안내(이름 해석 · 방화벽 · 인증서 · 워크플로 삭제나 주소 만료 · Teams 전송 제한)로 바꿔 보인다.
- 채널 주소는 비밀값이다. 서버는 https 만 받고, 일반 웹훅은 사설 · 링크로컬 · localhost 주소(`ipaddress` 로 판정, 이름은 해석하지 않음)와 `user:pass@` 를 거부한다. 응답과 화면에는 호스트와 끝 4자만 보이고, 발송 이력·감사 기록·서버 로그에는 주소와 응답 본문을 넣지 않는다. 채널 목록 응답은 `no-store` 다.
- 배포 전 `infra/migrations/20260924_notify.sql` 을 적용한다(`notify_channels` · `notify_deliveries` 표, 감사 조회 뷰 · 변경 방지 트리거 갱신). 이력의 `payload` 에는 요약만 넣고 원문 로그를 넣지 않는다.
- 화면(`/alerts`): 채널 표(사용/중지 토글 · 시험 발송 · 수정) · 추가/수정 양식 · 발송 이력(채널 · 상태 필터, 서버 페이지 탐색)이며 30초마다 재조회한다. 주소 입력은 password 형이고 수정 때 비우면 서버가 기존 주소를 유지한다. 양식의 '예시 미리보기'는 자리표시자를 예시 값으로 바꿔 화면에서만 그리며(`organisms/notify/template.ts`), 저장 전 시뮬레이션이 아니다. 시험 발송 결과는 띠(Banner)로 보이고 이력에 `test` 로 남는다.

## CVE · KEV 연계 (#39)

- 요청 경로 서명 규칙(`detector/rules_cve.json` c1: R105 제품 식별 탐색 · R106 알려진 취약점 공격 시도)이 만든 사건에 제품 · CVE · 공개 정보(KEV 등재 · CVSS · EPSS)와 자산 적용 판정을 붙여 보인다. **CVE 정보는 조사 우선순위 참고용이고 판정은 행위 증거로 한다.** 판정값 · 심각도를 CVE 로 정하지 않는다.
- API(`app/cti.py`): `GET /api/incidents/{key}/cti`, `GET /api/cti/watch`, `GET /api/assets`, `GET /api/assets/{asset_id}?filter=all|kev|fix&limit&offset`. 사건 키 경로는 `incidentPath` 와 같은 방식으로 부호화한다. `…/cti` 라우터는 상세 조회(`/api/incidents/{incident_key:path}`)보다 먼저 붙어야 한다(뒤에 붙으면 상세가 `KEY/cti` 를 삼켜 404).
- 사건 상세 ⑥ 취약점 연계: 왼쪽 열 끝(④ 다음)에 둔다. 판정 근거인 ① ~ ④ 보다 앞에 두지 않는다. 서명 규칙 사건이 아니면(`applicable: false`) 구역을 그리지 않고, 첫 조회 중에도 그리지 않는다(대부분의 사건은 대상이 아니라 빈 구역이 잠깐 보였다 사라지지 않게). 404 는 이 기능 이전 서버로 보고 안내 한 줄, 그 밖의 오류는 구역 안 오류 · 다시 시도, CTI 표가 없으면(`available: false`) 마이그레이션 안내다.
- 구역 내용: 원칙 한 줄, 오래됨 띠, 서명마다 제품 · 공급사 · 대응 방식(명시 대응 · 분석가 대응) · 적용 요약 · 근거 문장 · 자산 적용 표(자산 · 요청 받음 · 판정 · 이유), CVE 표(KEV 등재일 · 랜섬웨어 · CVSS · EPSS(백분위) · 요약), 신선도(KEV · EPSS · 배포판 대조 · NVD · 가장 오래된 자산 수집).
- 적용 판정은 서버가 정한다: 해당 · 비해당 · 미확인. 자산 정보가 없거나 48시간(서버 `STALE_HOURS`)을 넘었으면 미확인이다. 공개 정보(KEV · EPSS · 배포판 대조)가 오래되면 '비해당으로 읽지 않습니다' 띠를 보인다. NVD 는 초점 CVE 만 받으므로 오래됨으로 보지 않는다.
- `/inventory`(메뉴 수집 › 자산 · 취약점, 노드 화면 머리에도 링크): 맨 위 주목 CVE, 신선도 요약, 자산 표(역할 · 방법 · 수집 · 커널과 재부팅 대기 · 취약점 · KEV · 수정판 있음 · 최고 EPSS · 오류), 자산을 고르면 주요 패키지 · 도는 컨테이너 이미지 · 배포판 취약점 표(전체 · KEV · 수정 가능, 50건씩 쪽 넘김). 대조 전 자산은 0건이 아니라 '대조 전'으로 적는다. 컨테이너 이미지 안의 패키지는 조사하지 않아 미확인이다. (`/assets` 는 빌드 결과의 번들 폴더라 화면 경로로 쓰지 않는다.)
- 쪽 넘김: 뒤쪽을 보는 동안 대조가 다시 돌아 총수가 줄면(패치 뒤 재조회) 빈 쪽을 '알려진 취약점이 없습니다'로 적지 않고 유효한 마지막 쪽으로 돌아간다(인시던트 목록과 같은 방식). 총수가 있는데 행이 비어 오면 '이 쪽에는 행이 없습니다'로 적는다.
- 주목 CVE(`GET /api/cti/watch`, 목록은 수집기의 `cti/watchlist.json`): 자산 취약점 표는 걸린 것만 담으므로, 널리 알려진 CVE 몇 개(예: CVE-2024-6387 regreSSHion)를 정해 두고 자산마다 설치 버전을 배포판(Ubuntu) 수정판과 견준 결과를 보인다. 이미 고쳐진 CVE 도 '비해당'이라는 대조 결과로 남는다. 표는 CVE · 주목 이유 · KEV · EPSS(백분위) · 판정 요약 · 자산별 판정 배지이고, 행을 펼치면 설명 · 배포판 기록(조회 전 · 기록 없음) · 영향 패키지와 수정판(없으면 '배포판 수정판 없음') · 자산별 패키지 · 설치 · 수정판 · 이유를 보인다. 판정과 이유는 서버(judge_watch)가 정하고 화면은 옮겨 적는다. 자산 정보가 없거나 오래됐거나 배포판 기록이 없으면 미확인이다. 자산 목록과 따로 받아 한쪽이 실패해도 다른 쪽은 보이고, 404(이 기능 이전 서버)는 카드 안 안내 한 줄이다.
- 캐시: `ctiKeys` 는 사건 상세 키(`incidentKeys`) 밑에 두지 않는다(판정 · 조치 통보마다 다시 받을 까닭이 없다). 주목 CVE 는 `ctiKeys.watch()` 로 자산 키 밑에 두지 않는다. 사건 연계 5분 · 자산 · 주목 CVE 60초 동안 다시 묻지 않고 주기 재조회는 없다. 웹소켓 재접속 때는 다시 조회한다. 자산 상세는 같은 자산 안에서만 이전 결과를 유지한다(다른 자산의 취약점을 잠깐이라도 새 자산 것처럼 보이지 않는다).
- CVSS 등급은 NVD 대문자(`9.8 CRITICAL`)로, Ubuntu 우선순위는 한국어(긴급 · 높음 · 중간 · 낮음 · 무시 가능)로 적는다. 사건 심각도 배지(소문자 critical 등)와 섞이지 않게 하려는 것이다.
- 배포: API 와 화면 빌드를 함께 배포한다. DB 에 `infra/migrations/20260925_cti.sql` 을 적용하기 전에는 두 화면 모두 표가 없다는 안내를 보인다.

## 비신뢰 문자열 표시 (#41)

로그 · 공격자 입력 · 자산 수집 결과는 공격자가 고른 글자일 수 있다. 원문은 서버 · DB 에 그대로 두고(증거), 화면은 **보이는 모습만** 바꾼다.

- 모든 비신뢰 값은 `atoms/UntrustedText`(`value` · `max` 기본 500 · `clip` · `fallback` · `className`)로 그린다. JSX 글자로만 넣고 `dangerouslySetInnerHTML` · 마크다운 렌더러 · 외부 링크 · 이미지를 쓰지 않는다(oxlint `react/no-danger` · `react/jsx-no-script-url` · `react/jsx-no-target-blank` 가 막는다). 링크는 같은 출처 경로(`/incidents/<부호화한 키>` 등)만 만든다.
- 숨은 문자 = 유니코드 Cf(형식 문자: 방향 제어 U+202A~U+202E · U+2066~U+2069 · 제로폭 U+200B~U+200F · BOM U+FEFF · 태그 문자 U+E0001 · U+E0020~U+E007F 등) + Cc(제어 문자: ESC U+001B · CSI U+009B · CR U+000D 등) 중 탭 · 줄바꿈을 뺀 것. 줄 · 문단 구분자(U+2028 · U+2029), 기본 무시 문자(Default_Ignorable: 한글 채움 U+3164 · 결합 자소 연결 U+034F · 이형 선택자 U+FE00~U+FE0F 등), 점자 빈칸(U+2800)도 넣는다. 서버(app/untrusted.py) · 수집기 · 판정 도구 · 파서 요약도 같은 규칙이다. 표식 `⟨U+202E⟩`(경고색 작은 배지)로 보인다.
- 줄바꿈은 `↵` 배지로 보인다. 원문 로그 한 줄 안에서 가짜 로그 줄(`\n2026-09-18 15:00:00 … login.success`)을 만들지 못한다. 탭은 공백 하나다. 여러 줄로 보여야 하는 비신뢰 값은 없다.
- 값 전체를 `<bdi dir="ltr">` 로 격리해 옆 값 · 뒤 필드의 방향이 뒤집히지 않는다. 원문 로그는 필드마다 따로 격리하고 필드 사이는 공백 두 칸이다.
- `max` 자(표식으로 바꾸기 전 원문 글자 수 · 코드 포인트)를 넘으면 앞부분만 보이고 `… N자 더 · 펼치기` 단추로 펼친다(접기 단추도 있다). 긴 무공백 문자열은 칸 안에서 끊는다(`overflow-wrap: anywhere`). 표 머리글이 되는 표본 키 · 세션 칩 · 행위자 이름처럼 짧아야 하는 자리는 `max` 를 64 등으로 줄인다.
- 한 줄 말줄임(`truncate`) 자리(목록 행 · 모바일 카드 · 대시보드 링크)는 `clip` 으로 그린다. 표식으로 바꾼 뒤 CSS 로 자르고, 행을 누르면 상세로 가므로 펼치기 단추를 두지 않는다. 전체는 `title` 로 본다.
- `title` · `aria-label` · `<option>` 처럼 문자열만 들어가는 자리는 `lib/untrusted` 의 `revealHidden` 을 거친다.
- 적용한 자리: 원문 로그 · 행위 · 증거 표본(키와 값 · 세션 칩) · 사건 머리(대상 · 사건 키) · 목록 행/카드 · 대시보드 · 판정/조치 기록(사유 · 메모 · 행위자 · 제안 근거) · 행위자 구역(차단 사유 · 방식 · 센서 · 흡수 사유 · 페이로드) · 차단 목록 · 취약점 연계 · 자산 표 · 자산 상세 · 주목 CVE · 알림 발송 이력(대상 · 원인)과 채널의 마지막 오류 · 감사 기록 · 주소로 받은 사건 키(404 화면)와 규칙 조건.
- 시험: `src/test/hostile-fixtures.ts` 의 악성 표본(태그 · `javascript:` · 마크다운 링크 · 이미지 · `<at>` 멘션 · CSS · dns-prefetch · U+202E · U+200B · U+2066/2069 · BOM · ESC · CSI · 가짜 줄 · CRLF · 2만 자)을 화면마다 넣고, img · svg(앱 아이콘 제외) · iframe · object · embed · style · link · script 0 · on* 속성 0 · 모든 href 가 같은 출처 경로 · 글자와 글자 속성에 숨은 문자 원문 0 · 표식과 ↵ 표시 · 2만 자 접힘/펼침을 본다(`expectInertDom` · `expectMixedRevealed` · `expectLongFolds`).
