# OpsLoop 관제 콘솔 (console/)

React 19 · TypeScript · Vite 8 · Tailwind v4 · TanStack Query 5 · react-router 7. 화면 설계는 `docs/2026-09-18-화면-설계.md`,
모양은 와이어프레임(Main · States · Error)을 따른다.

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
src/api/live.ts        실시간 통보(WS /ws). useLiveUpdates 가 한 번 잇고 통보마다 해당 쿼리를 무효화한다. 끊기면 1초 → 30초 지수 백오프
src/auth/roles.ts      권한표(화면 설계 15장). can(role, action) · permission(role, action)
src/auth/useMe.ts      GET /api/me · usePermission(action)
src/lib/useNow.ts      상단바 시계용 지금 시각
src/components/        atoms · molecules · organisms · templates. index.ts 로 내보낸다
  organisms/states/    상태 화면(불러오는 중 · 0건 · 403 · 세션 만료 · 오류 · 404 · ApiErrorState)
  organisms/nav/       메뉴 조각: nav-items(자료형 · findNavItem) · NavMenu · Brand · UserPanel(로그아웃 폼) · SensorSummary
  organisms/incidents/       인시던트 목록(S-03) 조각: 조건(filters · 주소 왕복) · 표 행 · 모바일 카드 · 높이 제한 목록 · 페이지 탐색 · 조건 막대 · 경과 시간
  organisms/incident-detail/ 인시던트 상세(S-04) · 판정 패널(S-05) 조각: 머리글 · 구역 ①~⑤ · 조치 막대 · 판정 패널 · 이력 · format(서버 행 → 글)
  organisms/           TopBar(경로 표시 · 실시간 연결 표시 · KST 시계 · 새로고침 · 모바일 메뉴 단추) · LiveIndicator · SideNav(232px) · MobileNav(서랍)
  templates/           AppLayout(사이드바 + 상단바 + 본문 · /api/me 확인 · 401 → 로그인 · 실시간 통보 연결) · breadcrumbs
src/app/router.tsx     경로표(react-router 7). / · /incidents · /incidents/:key · /blocklist · /rules · /sources · /reports · /nodes · /alerts · /audit · /accounts · *
src/app/nav.ts         메뉴 묶음(관제 · 대응 · 분석 · 수집 · 관리). 관리 묶음은 admin 이 아니면 흐리게
src/app/screens.ts     화면 자리 정보(설계 번호 · 제목 · 한 줄 설명 · WBS)
src/app/ComponentCatalog.tsx  공통 컴포넌트 모음. 개발 서버에서만 /dev/components
src/pages/             화면 자리(PlaceholderPage · PendingCard · NotFoundPage · RouteError)
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
- 상단바 경로 표시는 메뉴 정의에서 나온다. 칸을 더하려면 경로의 `handle: { crumb }` 를 쓴다(인시던트 키).
