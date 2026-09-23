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
src/api/client.ts      fetch 공통 인스턴스(api). 시간 초과 15초 · 401 은 /login?next= 로 한 번만 이동 · 오류는 ApiError
src/api/queryClient.ts 재시도 규칙: 5xx · 네트워크만 2회
src/api/incidents.ts   인시던트 목록(useIncidentsPage · 페이지별 limit/offset) · 상세(useIncident) · 판정 · 조치(useVerdictMutation · useActionMutation) · 규칙 품질. 쿼리 키는 incidentKeys · ruleKeys
src/api/monitoring.ts  대시보드(useSummary) · 차단 목록(useBlocklist). 기존 API 조회 · 30초 재조회 · 서버 시각으로 만료 계산
src/api/live-context.ts 공통 연결 상태. S-10에서 웹소켓 끊김과 REST 조회 실패를 구별
src/api/live.ts        실시간 통보(WS /ws). useLiveUpdates 가 한 번 잇고 통보마다 해당 쿼리를 무효화한다. 끊기면 1초 → 30초 지수 백오프. 재접속하면 놓친 통보를 보완하도록 목록·상세·지표를 재조회
src/auth/roles.ts      권한표(화면 설계 15장). can(role, action) · permission(role, action)
src/auth/useMe.ts      GET /api/me · usePermission(action)
src/lib/useNow.ts      상단바 시계용 지금 시각
src/components/        atoms · molecules · organisms · templates. index.ts 로 내보낸다
  organisms/states/    상태 화면(불러오는 중 · 0건 · 403 · 세션 만료 · 오류 · 404 · ApiErrorState)
  organisms/nav/       메뉴 조각: nav-items(자료형 · findNavItem) · NavMenu · Brand · UserPanel(로그아웃 폼) · SensorSummary
  organisms/incidents/       인시던트 목록(S-03) 조각: 조건(filters · 주소 왕복) · 표 행 · 모바일 카드 · 높이 제한 목록 · 페이지 탐색 · 조건 막대 · 경과 시간
  organisms/incident-detail/ 인시던트 상세(S-04) · 판정 패널(S-05) 조각: 머리글 · 구역 ①~⑤ · 조치 막대 · 판정 패널 · 이력 · format(서버 행 → 글)
  organisms/           TopBar(경로 표시 · 실시간 연결 표시 · KST 시계 · 새로고침 · 모바일 메뉴 단추) · LiveIndicator · SideNav(208px) · MobileNav(서랍)
  templates/           AppLayout(사이드바 + 상단바 + 본문 · /api/me 확인 · 401 → 로그인 · 실시간 통보 연결) · breadcrumbs
src/app/router.tsx     경로표(react-router 7). / · /incidents · /incidents/:key · /blocklist · /rules · /sources · /reports · /nodes · /alerts · /audit · /accounts · *
src/app/nav.ts         메뉴 묶음(관제 · 대응 · 분석 · 수집 · 관리). 관리 묶음은 admin 이 아니면 흐리게
src/app/screens.ts     화면 자리 정보(설계 번호 · 제목 · 한 줄 설명 · WBS)
src/app/ComponentCatalog.tsx  공통 컴포넌트 모음. 개발 서버에서만 /dev/components
src/pages/             구현 화면 및 나머지 화면 자리(PlaceholderPage · PendingCard · NotFoundPage · RouteError)
  pages/dashboard/      미판정 현황(S-02): 경과 분포 · 목표 초과 · 우선 확인 8건 · 규칙별 비조치율
  pages/blocklist/      차단 목록(S-06): 활성·만료·해제 · 검색·페이지 탐색 · 관리자 해제
  pages/incidents/       인시던트 목록 화면(IncidentsPage). 조건·page·page_size를 주소에 두어 새로고침·뒤로 가기·공유에도 남는다
  pages/incident-detail/ 인시던트 상세 · 판정 화면(IncidentDetailPage). 사건 키가 바뀌면 판정 소요 시계를 다시 시작한다
src/test/              vitest setup(WebSocket 은 아무 일도 하지 않는 소켓) · render(메모리 라우터 · /api/me 스텁)
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
