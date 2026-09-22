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
src/lib/domain.ts      심각도 · 판정값 · 상태 값과 화면 표기
src/lib/time.ts        KST 표시 · 경과 시간
src/api/client.ts      fetch 공통 인스턴스(api). 시간 초과 15초 · 401 은 /login?next= 로 한 번만 이동 · 오류는 ApiError
src/api/queryClient.ts 재시도 규칙: 5xx · 네트워크만 2회
src/auth/roles.ts      권한표(화면 설계 15장). can(role, action) · permission(role, action)
src/auth/useMe.ts      GET /api/me · usePermission(action)
src/lib/useNow.ts      상단바 시계용 지금 시각
src/components/        atoms · molecules · organisms · templates. index.ts 로 내보낸다
  organisms/states/    상태 화면(불러오는 중 · 0건 · 403 · 세션 만료 · 오류 · 404 · ApiErrorState)
  organisms/nav/       메뉴 조각: nav-items(자료형 · findNavItem) · NavMenu · Brand · UserPanel(로그아웃 폼) · SensorSummary
  organisms/           TopBar(경로 표시 · KST 시계 · 새로고침 · 모바일 메뉴 단추) · SideNav(232px) · MobileNav(서랍)
  templates/           AppLayout(사이드바 + 상단바 + 본문 · /api/me 확인 · 401 → 로그인) · breadcrumbs
src/app/router.tsx     경로표(react-router 7). / · /incidents · /incidents/:key · /blocklist · /rules · /sources · /reports · /nodes · /alerts · /audit · /accounts · *
src/app/nav.ts         메뉴 묶음(관제 · 대응 · 분석 · 수집 · 관리). 관리 묶음은 admin 이 아니면 흐리게
src/app/screens.ts     화면 자리 정보(설계 번호 · 제목 · 한 줄 설명 · WBS)
src/app/ComponentCatalog.tsx  공통 컴포넌트 모음. 개발 서버에서만 /dev/components
src/pages/             화면 자리(PlaceholderPage · IncidentDetailPage · NotFoundPage · RouteError)
src/test/              vitest setup · render(메모리 라우터 · /api/me 스텁)
```

## 규칙

- 새 패키지를 받지 않는다(콘솔 VM 은 인터넷이 막혀 있다). 외부 글꼴 · CDN 도 쓰지 않는다(CSP).
- 한국어 UI · 한국어 주석.
- 모든 공통 컴포넌트는 `className` 을 받아 `cn` 으로 합친다. 뒤에 준 클래스가 이긴다.
- 권한 밖의 동작은 숨기지 않고 흐리게 보인다(`Gated` · `Button` 의 `disabledReason`). 화면의 검사는 보안 경계가 아니다.
- 로그인 화면은 서버가 그린다(GET /login). 화면은 `/api/me` 가 401 이면 `/login?next=<지금 경로>` 로 옮겨 가고, 로그아웃은 `POST /logout` 폼이다.
- 상단바 경로 표시는 메뉴 정의에서 나온다. 칸을 더하려면 경로의 `handle: { crumb }` 를 쓴다(인시던트 키).
