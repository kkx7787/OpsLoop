# #54 리플레이 비교 결과 — Sigma 공개 규칙(sg1 · sgx)과 c1 서명 (갈래 C)

기록 2026-09-28 · 시각은 모두 UTC · 실험 DB `opsloop-lab54`(운영 덤프 `opsloop-20260928-0730`) · 규칙 sg1(R107 · 원본 10 · 서명 11) · c1(R105 서명 8 · R106 서명 5) · sgx(원본 76 · 서명 94, 실험용) · 정상 시나리오 normal49-1(16개 · 66행, 그 가운데 요청 행 38)

운영 장비 · 운영 DB 에는 붙지 않았다. 덤프 원본은 읽기만 했다. 저장소 파일은 고치지 않았다(증거 폴더만 새로 만들었다).

## 요약 (PR 본문용)

- **실데이터 요청 1,023건에서 선정 10개(sg1)가 맞은 요청은 0건이다.** 같은 요청에 c1 은 25건(R105 · 사건 3)이 맞았다. 실험용 sgx(원본 76개 · 서명 94개, 경로 · 메서드 · 응답 코드만 쓰는 70개 모두 서명을 냈다. 1개는 갈래 하나를 버렸고 5개는 필터를 뺐다)도 0건이다.
- 요청 1,023건은 전부 웹 디코이(decoy.request · 출발지 195 · 2026-09-18 02:28 ~ 2026-09-28 06:30)다. web-01 nginx 의 real 요청은 덤프에 0건이다. 디코이 url 에는 질의(`?`)도 퍼센트 인코딩(`%`)도 0건이고, 디코이는 `/`(302 · 405) · `/admin`(200) 밖의 모든 경로에 404 를 준다.
- 그래서 **0 은 'Sigma 가 덜 잡는다' 의 증거가 아니다.** 선정 10개 중 질의 값을 보는 4개(3398 · 0688 · 25157 · 22893 일부)와 응답 코드 조건이 있는 3개(41773 200·301 · 22518 200·302·405 · ProxyShell 401)는 디코이 요청에서 원리상 맞기 어렵다. 관측된 디코이 요청은 제품 식별 탐색(`/owa/` · `/geoserver/web/` · `/dana-na/nc/nc_gina_ver.txt` 등)이라 c1 R105(제품 식별)의 몫이고, Sigma 규칙은 공격 요청(질의 · 인코딩된 경로 · 성공 응답)을 본다. 목적이 다르다.
- **응답 코드 조건 때문에 빠진 요청은 0건**이다(상태 조건을 빼도 0건). 조건 단계별로 보면 pattern 에는 2개 서명이 6건(`/owa/` 4 · `/dana-cached/hc/HostCheckerInstaller.osx` 2) 맞았고 둘째 조건(`__VIEWSTATE=` · `id=`/`token=`/낱말)에서 모두 빠졌다. 6건 모두 c1 R105 사건의 두 스캐너(172.237.27.147 · 45.79.123.76)다.
- **R107 사건 0 → 겹치는 c1 사건 없음.** 다리는 전 기간을 돌므로, 덤프 시점 데이터로는 운영 첫 실행 때 과거 요청으로 R107 통보가 몰리지 않는다.
- **정상 시나리오 요청 38행(web-01 nginx)에 sg1 0 · sgx 0 · c1 0.**
- **c1 결과 불변.** c1 → sg1(전 기간) → 정상 시나리오 → sg1(정상 구간) → c1 순서로 돌린 전후에 c1 사건 3행(키 · 끝 시각 · 건수 · 세션 수 · 근거 md5 · 심각도)과 사건 키 1,028개의 md5 `455f9282e27aaa612fe336fdd7276e6e` 가 같다. 탐지기 SQL 과 파이썬 판(`url_signature_fullmatch`)의 신호 다중집합이 sg1 · sg1(상태 뺌) · c1 R105 · R106 · sgx · sgx(상태 뺌) 모두 같다.
- 배선 확인(합성, 관측 아님): 갈래 A 표본 45건을 연결 전용 임시 표에 web-01 꼴 · 디코이 꼴로 넣고(90행) 돌리면 sg1 38 · c1 36 · 둘 다 18 · sg1 만 20 · c1 만 18 · 응답 코드로 빠짐 8 이다(롤백). 실데이터의 0 은 배선이 비어서가 아니다. 이 수는 표본을 만든 사람이 정한 설계값이다.

## 1. 입력

| 항목 | 값 |
|---|---|
| 실험 DB | Mac 도커 `opsloop-lab54`(postgres:16-alpine · 127.0.0.1:55449 · 볼륨 없음 · `--rm`). 13:44:27 기동. 같은 이름 · 포트의 컨테이너는 없었다(55449 비어 있음). **남겨 두었다** |
| 덤프 | `~/opsloop-backup/opsloop-20260928-0730.dump` sha256 `456fece8…83dc033` · Archive created 2026-09-28 07:30:06 · 16.15 |
| globals | `opsloop-20260928-0730.globals.sql` sha256 `c1bbfda5…cdbce7`. `CREATE ROLE` · `ALTER ROLE` · `GRANT` 줄만(`CREATE ROLE opsloop;` 제외 · PASSWORD 줄 0) → `pg_restore --no-owner --exit-on-error` rc 0 (13:44:47 ~ 13:44:49) |
| 복원 지문 | events 137,274(real 137,234 · 2026-09-04 07:53:52 ~ 2026-09-28 07:22:11) · incidents 1,028 · verdicts 1,028 · actions 167 · blocklist 26 · sessions 4,547 · detector_runs 29,940 · 사건 키 md5 `455f9282e27aaa612fe336fdd7276e6e` · 버전별 v1 555 · v2 321 · v3 138 · c1 3 · s1 4 · w1 2 · w2 2 · i1 2 · i2 1. backup.log 복원 시험(137274 · 1028 · 167 · 26)과 같다 |
| 요청 행 | real · eventid ∈ (nginx.request, decoy.request) 1,023건 = decoy 1,023 · web-01 0. 출발지 195. 응답 404 687 · 302 203 · 200 130 · 405 3. 메서드 GET 1,012 · OPTIONS 4 · POST 3 · CONNECT 3 · HEAD 1. url 에 `?` 0 · `%` 0 |
| 규칙 | sg1 `detector/rules_sigma.json` sha256 `4dd02f19…6e695`(실험 DB rule_versions 의 sg1 정의와 같다) · c1 `detector/rules_cve.json` `44723683…86143` · sgx `rules_sigma_lab.json` `375941b9…c878c27`(같은 원본으로 다시 만들어 글자가 같음을 확인) · detect.py `504b3a7e…4114be` |
| 실행기 | `opsloop-lab54-py`(python:3.12-slim · psycopg2-binary 2.9.13 · pyyaml 6.0.3 · `--network container:opsloop-lab54` · 저장소 읽기 전용). 실험 DB 는 그 안에서 127.0.0.1:5432 로 보인다 |
| 정상 시나리오 | `normal_traffic.py --apply --allow-port 5432` · 구간 2026-09-28 08:30 ~ 16:30 · 66행(요청 행 38 = W01 ~ W07) · 구간 안 남의 행 0 · 사건 키 집계 불변 |

## 2. 선정 10개 — 요청 단위 (PR 본문용 표)

요청 = 실데이터 요청 행 1,023건(정상 시나리오 표식 행 제외). 'c1 도' 는 같은 요청(line_hash)에 c1 서명이 맞은 수(짝 / 아무 c1 서명). 'c1 만' 은 짝 서명이 맞고 이 Sigma 규칙은 맞지 않은 요청 수. '응답 코드로 빠짐' 은 서명에서 statuses 만 뺐을 때 더 맞는 요청 수. 버린 갈래 · 뺀 필터는 10개 모두 0 이다(`sigma_convert.py report`).

| # | 원본 규칙 | c1 짝 | 변환 (서명) | 옮기지 못한 조건 · 바꾼 것 | 맞은 요청 디코이 / web-01 | 출발지 | c1 도 (짝 / 아무) | Sigma 만 | c1 만 | 응답 코드로 빠짐 | R107 사건 | 겹치는 c1 사건 | 정상 걸림 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2021-41773 Apache 경로 조작 | R106 apache-path-traversal | 변환 (1) | 없음 · 응답 200 · 301 · 퍼센트 인코딩 꼴만 봄 | 0 / 0 | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 없음 | 0 |
| 2 | Log4j CVE-2021-44228 (keywords) | R106 log4shell-in-path | 변환 (1) | 없음 · keywords 를 url 에만(좁아짐) · nessus 필터도 url 에만(필터가 약해져 넓어짐) | 0 / 0 | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 없음 | 0 |
| 3 | Confluence CVE-2019-3398 | R105 confluence | 변환 (1) | 없음 · POST · `filename=../../../../`(질의) | 0 / 0 | 0 | 0 / 0 | 0 | 2 | 0 | 0 | 없음 | 0 |
| 4 | Confluence CVE-2023-22518 | R105 confluence | 변환 (1) | 없음 · POST · 응답 200 · 302 · 405 | 0 / 0 | 0 | 0 / 0 | 0 | 2 | 0 | 0 | 없음 | 0 |
| 5 | Exchange CVE-2020-0688 | R105 exchange-owa | 변환 (1) | 없음 · GET · `__VIEWSTATE=`(질의) | 0 / 0 | 0 | 0 / 0 | 0 | 4 | 0 | 0 | 없음 | 0 |
| 6 | Exchange ProxyShell | R105 exchange-owa | 변환 (2 갈래) | 없음 · 응답 401 · 값의 `?` 를 한 글자로(넓어짐) | 0 / 0 | 0 | 0 / 0 | 0 | 4 | 0 | 0 | 없음 | 0 |
| 7 | GeoServer CVE-2023-25157 | R105 geoserver | 변환 (1) | 없음 · GET · `CQL_FILTER=` + SQL 조각(질의) | 0 / 0 | 0 | 0 / 0 | 0 | 9 | 0 | 0 | 없음 | 0 |
| 8 | Pulse Secure CVE-2019-11510 | R105 ivanti-connect-secure | 변환 (1) | 없음 · 값의 `?` 를 한 글자로(넓어짐) | 0 / 0 | 0 | 0 / 0 | 0 | 2 | 0 | 0 | 없음 | 0 |
| 9 | Pulse Connect Secure CVE-2021-22893 | R105 ivanti-connect-secure | 변환 (1) | 없음 · `?id=` · `?token=`(질의) + 경로 낱말 | 0 / 0 | 0 | 0 / 0 | 0 | 2 | 0 | 0 | 없음 | 0 |
| 10 | 일반 경로 조작 (webserver_generic) | 없음 (참고 R106 apache-path-traversal) | 변환 (1) | 없음 · 인코딩된 꼴(`%252f` · `%c0%af`)은 디코이에서 풀림 | 0 / 0 | 0 | 0 / 0 | 0 | 0 (참고) | 0 | 0 | 없음 | 0 |
| | **10개 합(요청 중복 없이)** | | 서명 11 | | **0 / 0** | 0 | 0 / 0 | 0 | c1 전체 25 | **0** | **0** | 없음 | **0** |

- 모든 서명에 공통: 원본의 cs-uri-stem · cs-uri-query 를 한 url 에 댔다(경로 · 질의 구분을 잃어 넓어짐, 서명 notes).
- 'c1 만' 요청의 url: confluence `/confluence/rest/applinks/1.0/manifest` 2 · exchange-owa `/owa/` 4 · geoserver `/geoserver/web/` 3 · `/geoserver/` 2 · `/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage` 2 · `/geoserver/index.html` 2 · ivanti-connect-secure `/dana-na/nc/nc_gina_ver.txt` 2. 모두 제품 식별 요청이고 공격 요청이 아니다. R106(공격 시도) 서명은 5개 모두 0건이다.
- c1 서명별 실데이터 매치(R105): confluence 2(출발지 2) · dlink-hnap 2(2) · exchange-owa 4(2) · geoserver 9(3) · ivanti-connect-secure 2(2) · ivanti-vtm 2(2) · qnap-qts 2(2) · samsung-magicinfo 2(2) = 25. R106 0.

조건 단계별 탈락(실데이터, 서명의 조건을 하나씩 더함). 0 이 아닌 단계만 적는다.

| 서명 | pattern 만 | + all_patterns | + methods | + statuses | 빠진 url |
|---|---|---|---|---|---|
| sg-cve-2020-0688-msexchange | 4 | 0 | 0 | – | `/owa/` GET 404 ×4 (172.237.27.147 2 · 45.79.123.76 2) |
| sg-cve-2021-22893-pulse-secure-rce | 2 | 0 | – | – | `/dana-cached/hc/HostCheckerInstaller.osx` GET 404 ×2 (두 출발지 1씩) |
| 나머지 9개 서명 | 0 | 0 | 0 | 0 | |

`/dana-cached/hc/HostCheckerInstaller.osx` 2건은 c1 ivanti-connect-secure(`^/dana-na…`)에도 맞지 않았다. 두 스캐너의 같은 탐색 묶음(c1 R105 사건 안의 시각)이다.

## 3. 사건 단위

| 항목 | 값 |
|---|---|
| sg1 전 기간 실행 (detector_runs 29973 · 13:48:41) | R107 신호 0 · 통합 0 · 사건 0 |
| sg1 정상 구간 실행 (29974 · 13:50:46 · 2026-09-28 08:30 ~ 16:30) | R107 신호 0 · 사건 0 |
| c1 전 기간 실행 (29972 · 13:48:40, 29975 · 13:50:47) | R105 신호 25 · 통합 3 · 새 사건 0(이미 있던 3건과 같은 키) · R106 0 |
| R107 사건과 같은 출발지 · 겹치는 구간의 c1 사건 | 없음(R107 사건 0). 같은 출발지의 c1 사건(구간 무관)도 0 |
| 이미 있는 c1 사건 | R105 74.82.47.3 (9/20 12:30:44 · 1건 · geoserver) · 172.237.27.147 (9/24 11:47:13 ~ 11:47:30 · 12건 · 서명 8) · 45.79.123.76 (9/25 22:37:59 ~ 22:38:15 · 12건 · 서명 8) |
| 운영 첫 실행 영향 | 다리(pull_loki)는 `--since` 없이 전 기간을 돈다. 덤프 시점(9/28 07:30) 데이터로는 sg1 첫 실행이 R107 사건 0 이다. rule_versions 에 sg1 정의가 들어가고 사건 · 통보는 생기지 않는다(덤프 뒤 운영에 쌓인 요청은 이 결과 밖이다) |
| 신호 질의 시간 (요청 행 1,061 · 5회 중앙값) | c1 R105 2.7 ms · R106 15.8 ms · sg1 R107 56.0 ms · sgx R107(서명 94) 297.2 ms |

## 4. 정상 시나리오

정의서 절차대로 `normal_traffic.py --apply` 로 66행을 넣었다(구간 2026-09-28 08:30:00 ~ 16:30:00, 요청 행은 web-01 nginx W01 ~ W07 의 38행: `/` · `/health` · `/docs/old-link` · 메타데이터 404).

| 규칙 | 표식 요청 행 38 중 맞은 수 | 걸린 시나리오 |
|---|---|---|
| sg1 (선정 10 · 서명 11) | 0 | 없음 |
| sg1 (statuses 뺌) | 0 | 없음 |
| sgx (원본 76 · 서명 94) | 0 | 없음 |
| c1 (R105 · R106) | 0 | 없음 |

정상 시나리오는 R101 · R102 경계를 보려고 만든 것이라 공격 모양의 url 이 없다. 이 0 은 '공개 규칙이 흔한 정상 요청에 걸리지 않는다' 는 최소 확인이지 오탐률이 아니다(분모 38행 · 작업자 1명).

## 5. sgx — 경로 · 메서드 · 응답 코드만 쓰는 70개 (+ 다른 필드를 쓰는 규칙 가운데 일부 변환 6개)

| 항목 | 값 |
|---|---|
| SigmaHQ 07ec293a 의 webserver 규칙 | 86개. 그 가운데 경로 · 메서드 · 응답 코드(+ keywords)만 쓰는 규칙 70개(계약 0장과 같다) |
| 변환 | 70개 모두 서명을 냈다(서명 85). 69개는 갈래를 버리지 않았고 1개(CVE-2022-27925)는 selection_shell 갈래(sc-status\|contains '200')를 옮기지 못해 버렸다(좁아짐). 70개 가운데 5개는 필터를 뺐다(넓어짐): sql_injection · ssti · xss_in_access_logs · CVE-2021-28480 은 응답 코드 부정 조건, CVE-2026-63030 webshell 은 null 필터. 다른 필드를 쓰는 16개 가운데 6개가 변환됐고(서명 9: 갈래를 버린 것 3 · 필터를 뺀 것 2 · 온전한 것 1), 10개는 변환 못 함 → 76개 · 서명 94 |
| **실데이터 요청에 한 번이라도 맞은 규칙** | **0개 / 70 (일부 변환 6개 포함 0 / 76)** · 맞은 요청 0 |
| 정상 시나리오 표식 행에 맞은 규칙 | 0 |
| 응답 코드 조건이 있는 서명 | 22개(원본 18개). 받는 코드는 200 · 301 · 302 · 401 · 405 · 500 · 207 이고 404 를 받는 서명은 없다 → 디코이에서는 `/` · `/admin` 밖의 경로로 맞을 수 없다 |
| 메서드 조건 | 서명 42개(POST 만 24). 디코이 POST 는 전 기간 3건 |

맞은 규칙 목록: **없음.** pattern 만 보면 맞던 서명(가까이 간 것)은 아래 4개다.

| 서명 | 원본 | 70개 안 | pattern 만 | 최종 | url |
|---|---|---|---|---|---|
| sg-cve-2020-0688-msexchange | CVE-2020-0688/web_cve_2020_0688_msexchange.yml (선정) | 예 | 4 | 0 | `/owa/` |
| sg-cve-2021-22893-pulse-secure-rce | CVE-2021-22893/web_cve_2021_22893_pulse_secure_rce_exploit.yml (선정) | 예 | 2 | 0 | `/dana-cached/hc/HostCheckerInstaller.osx` |
| sg-cve-2021-26858-iis-rce | CVE-2021-26858/web_cve_2021_26858_iis_rce.yml | 아니오(cs-username 갈래를 버림) | 1 | 0 | `/wp-content/plugins/post-smtp/readme.txt` |
| sg-cve-2022-36804-exchange-owassrf | CVE-2022-41082/web_cve_2022_36804_exchange_owassrf_exploitation.yml | 아니오(User-Agent 필터를 뺌 · 넓어짐) | 4 | 0 | `/owa/` |

26858 의 pattern `^.*POST.*$` 은 원본 keywords `POST`(로그 줄의 메서드를 뜻한 값)를 url 에 댄 것이라, 대소문자를 가리지 않아 `/wp-content/plugins/post-smtp/readme.txt` 의 `post` 에 맞았다(최종은 `200` · `/ecp/DDI/…` 조건에서 빠짐). keywords 를 url 에만 대는 변환이 뜻과 다른 글자에 걸리는 예다. sg1 선정 10개에는 이런 keywords 가 Log4j(`${jndi:` 꼴) 하나뿐이다.

76개 규칙마다의 수(모두 0)와 서명별 단계는 `results.json` 의 `sgx_rules` · `sgx_signatures` · `sgx_pattern_only_hits` 에 있다.

## 6. 배선 확인 — 합성 대조군 (관측 아님)

실데이터가 전부 0 이라 탐지기 질의 · 확장 서명 문장이 이 실험 DB 연결에서 실제로 맞는지를 따로 보였다. 갈래 A 시험의 표본 45건(`test_sigma_convert.SAMPLES`, 원본마다 대표 공격 요청 + 비슷한 정상 요청)을 연결 전용 임시 표(`search_path=pg_temp` 의 events)에 web-01 꼴과 디코이 꼴로 한 번씩(90행) 넣고, `detect.signals_url_signature` 로 sg1 · sg1(statuses 뺌) · c1 · sgx 를 받은 뒤 롤백했다. 실제 events 표는 건드리지 않았다.

| 항목 | 90행 중 |
|---|---|
| sg1 이 맞은 행 | 38 (web-01 꼴 기대 서명과 모두 같다) |
| c1 이 맞은 행 | 36 |
| 둘 다 | 18 |
| sg1 만 | 20 (Confluence 3398 · 22518, Exchange 0688 · ProxyShell, `/dana-cached/…meeting`, `?page=../../../etc/passwd`, `%252f` 등) |
| c1 만 | 18 (응답 404 · 없음인 41773 꼴, 디코딩된 `/cgi-bin/../../`, nessus 스캐너 log4j, `/owa/auth/logon.aspx`, `/geoserver/web/`, `/dana-na/nc/…` 등 제품 식별) |
| 응답 코드 조건 때문에 빠진 행 | 8 (41773 꼴 404 · 응답 없음, 22518 404, ProxyShell 200 — 각 두 꼴) |
| sgx 가 맞은 행 | 42 |

표본은 규칙을 알고 만든 것이라 이 수는 설계값이다(#49 정상 시나리오와 같은 성질). 말하는 것은 '실데이터 0 은 배선 문제가 아니다' 와 '응답 코드 조건이 공격 요청을 실제로 빼는 모양' 둘뿐이다.

## 7. 수치마다 센 방법 (한 줄씩)

- 요청 행: `SELECT … FROM events WHERE provenance = 'real' AND eventid = ANY('{nginx.request,decoy.request}')` (규칙 eventids 와 같다 · sensors 제한 없음). 정상 표식 행 = `message ~ '^\[정상 시나리오 [A-Z][0-9]{2}\] ' AND user_agent LIKE 'OpsLoop-Normal49/%'`, 실데이터 = 그 밖.
- 맞은 요청 수: 서명마다 `detect.url_signature_fullmatch(sig, http_method, url, http_status)` 로 line_hash 집합을 만들고 규칙(원본 파일)마다 합집합의 크기. 같은 답을 `detect.signals_url_signature(cur, rule, None, None)`(탐지기와 같은 SQL, 읽기 전용 트랜잭션)로 받아 (시각 · 출발지 · eventid · 발생원 · 메서드 · url · 응답 코드 · 서명 목록) 다중집합이 같은지 대조(sg1 0 = 0 · c1 R105 25 = 25 · R106 0 · sgx 0, 상태 뺀 판 포함 모두 같음).
- 발생원: 맞은 요청의 `sensor`(decoy · web-01) 별 개수. 출발지 수: 맞은 요청의 `src_ip` 서로 다른 수.
- c1 도(짝 / 아무): 그 규칙 합집합 ∩ c1 짝 서명(선정표 c1_pair)의 line_hash 집합 / ∩ c1 13개 서명 합집합.
- Sigma 만: 규칙 합집합 − c1 13개 합집합. c1 만: c1 짝 서명 집합 − 규칙 합집합(실데이터). 10번은 짝이 없어 R106 apache-path-traversal 을 참고로 댔다.
- 응답 코드로 빠짐: 서명에서 `statuses` 만 지운 사본으로 같은 셈을 해 (사본 합집합 − 원래 합집합) 크기.
- 조건 단계별: pattern → all_patterns → not_patterns → methods → statuses 순서로 파이썬 fullmatch(re.I · re.S)를 더해 남는 행 수. 최종 단계가 위 매치 집합과 같은지 단언했다.
- R107 사건 수: `SELECT count(*) FROM incidents WHERE rule_version = 'sg1'` (실행 뒤). 서명별은 `jsonb_array_elements_text(evidence -> 'signatures')`.
- 겹치는 c1 사건: `incidents i JOIN incidents c ON c.rule_version = 'c1' AND c.actor_ip = i.actor_ip AND c.first_ts <= i.last_ts AND c.last_ts >= i.first_ts WHERE i.rule_version = 'sg1'`.
- 정상 걸림: 위 매치 집합 ∩ 정상 표식 행(요청 행 38). 정상 구간 사건은 `detect.py --rules rules_sigma.json --run --since 2026-09-28T08:30:00+00:00 --until 2026-09-28T16:30:00+00:00` 의 요약.
- 70개: `classify.py` 가 원본 86개의 detection 필드를 모아 url 필드 · cs-method · sc-status · keywords 밖의 필드가 없는 규칙을 센 것(70). sgx 매치는 위와 같은 셈을 `rules_sigma_lab.json` 에 한 것.
- c1 불변: c1 사건 행 `(incident_key, last_ts, signal_count, session_count, md5(evidence::text), severity)` 과 `md5(string_agg(incident_key, E'\n' ORDER BY incident_key COLLATE "C"))` 를 실행 전 · sg1 뒤 · 마지막에 글자 대조.
- 복원 지문: `sql/fingerprint.sql`(표별 count · events 최소 · 최대 ts · 사건 키 md5 · 버전별 사건 수).

## 8. 명령

```bash
S=<스크래치>/sigma54   # 실험 DB 비밀번호는 <스크래치>/lab54.pw (0600, 출력 · 증거에 없음)
docker run -d --rm --name opsloop-lab54 -e POSTGRES_USER=opsloop -e POSTGRES_PASSWORD=<실험 DB 비밀번호> -e POSTGRES_DB=opsloop -p 127.0.0.1:55449:5432 postgres:16-alpine
G=~/opsloop-backup/opsloop-20260928-0730.globals.sql; grep -E '^(CREATE ROLE|ALTER ROLE|GRANT) ' "$G" | grep -vx 'CREATE ROLE opsloop;' | grep -vi password | docker exec -i opsloop-lab54 psql -U opsloop -d postgres -v ON_ERROR_STOP=1 -q
docker exec -i opsloop-lab54 pg_restore -U opsloop -d opsloop --no-owner --exit-on-error < ~/opsloop-backup/opsloop-20260928-0730.dump
docker exec -i opsloop-lab54 psql -U opsloop -d opsloop -At -F ' | ' < $S/sql/fingerprint.sql
docker run -d --rm --name opsloop-lab54-py --network container:opsloop-lab54 -v ~/opsloop-repo:/repo:ro -v $S:/out -v <스크래치>/lab54.pw:/pw:ro -v <스크래치>/sigma-07ec293a…:/sigma-src:ro -w /repo python:3.12-slim sleep infinity
docker exec opsloop-lab54-py pip install psycopg2-binary pyyaml
docker exec opsloop-lab54-py python3 detector/sigma_convert.py build --check                       # 같다
docker exec opsloop-lab54-py python3 detector/sigma_convert.py lab /sigma-src --out /out/rules_sigma_lab.regen.json   # 저장본과 글자 같음
docker exec opsloop-lab54-py python3 /out/classify.py                                               # 86 · 70
docker exec opsloop-lab54-py python3 /out/analyze.py /out/req_before_normal.json                    # 읽기 전용
docker exec opsloop-lab54-py sh -c 'DATABASE_URL=… python3 detector/detect.py --rules detector/rules_cve.json --run'     # 29972
docker exec opsloop-lab54-py sh -c 'DATABASE_URL=… python3 detector/detect.py --rules detector/rules_sigma.json --run'   # 29973
docker exec opsloop-lab54-py sh -c 'python3 detector/normal_traffic.py --db-url … --allow-port 5432'          # dry-run
docker exec opsloop-lab54-py sh -c 'python3 detector/normal_traffic.py --db-url … --allow-port 5432 --apply'  # 66행
docker exec opsloop-lab54-py python3 /out/analyze.py /out/req_after_normal.json                     # 읽기 전용
docker exec opsloop-lab54-py python3 /out/control.py                                                # 임시 표 · 롤백
docker exec opsloop-lab54-py sh -c 'DATABASE_URL=… python3 detector/detect.py --rules detector/rules_sigma.json --run --since 2026-09-28T08:30:00+00:00 --until 2026-09-28T16:30:00+00:00'   # 29974
docker exec opsloop-lab54-py sh -c 'DATABASE_URL=… python3 detector/detect.py --rules detector/rules_cve.json --run'     # 29975
docker exec -i opsloop-lab54 psql -U opsloop -d opsloop -At -F ' | ' < $S/sql/c1_snapshot.sql       # 전 · 후 대조
docker exec -i opsloop-lab54 psql -U opsloop -d opsloop -At -F ' | ' < $S/sql/incidents.sql
docker exec opsloop-lab54-py python3 /out/timing.py
```

## 9. 한계

- **web-01 실 HTTP 가 0 이다.** 비교 대상은 디코이 요청뿐이고, 디코이 url 은 1회 디코딩된 경로(질의 없음)이며 응답은 `/` · `/admin` 밖은 모두 404 다. 질의 값 · 퍼센트 인코딩 · 성공 응답을 보는 Sigma 조건은 이 데이터에서 원리상 거의 맞을 수 없다. 이 회차의 0 은 '이 데이터에서 공개 규칙이 추가로 준 것이 없다' 까지이고 재현율 비교가 아니다.
- **공격 요청이 없다.** 관측 기간 디코이 요청은 제품 식별 · 일반 탐색이었고 R106(공격 시도) c1 도 0 이다. Sigma 와 c1 R106 을 가를 실측 양성이 없다.
- **표본 대조군은 설계값이다.** 6장 수는 표본을 만든 사람이 정했다. 비율로 옮기지 않는다.
- **정상 분모가 작다.** 요청 행 38 · 작업자 1명 · 출발지 1개.
- 덤프(9/28 07:30) 뒤 운영에 쌓인 요청은 보지 않았다(운영 DB 에 붙지 않았다).
- 실험 DB 는 볼륨이 없어 컨테이너를 멈추면 사라진다. 지문 · 명령 · 산출물은 증거 폴더에 있다.

## 10. 필요한 고침 · 결정거리 (저장소는 고치지 않았다)

- 코드 고침은 필요 없다. sg1 은 실험 DB 에서 예외 없이 돌았고, rule_versions 에 들어간 정의가 파일과 같으며, c1 결과가 바뀌지 않았다.
- (결정) R107 응답 코드 조건을 디코이 요청에도 그대로 둘지. 디코이는 거의 모든 경로에 404 라 statuses 가 있는 서명 4개(sg1) · 22개(sgx)는 디코이에서 사실상 꺼져 있다. Sigma 의 뜻('성공 가능 응답만')을 지키는 지금이 맞다고 보되, 결과 문서에 '디코이에서는 꺼진 서명' 으로 적어 둘 것을 권한다. 바꾸면 sg2 다.
- (관찰 · 별도) c1 ivanti-connect-secure 는 `^/dana-na` 만 본다. 두 스캐너의 `/dana-cached/hc/HostCheckerInstaller.osx` 2건은 c1 · Sigma 모두 놓쳤다(Sigma 22893 은 pattern 은 맞고 둘째 조건에서 빠짐). 제품 식별 서명을 넓힐지는 c1 버전 올림(c2)이라 별도 이슈다.
- (문서) 운영 반영 확인 결과 문서에 옮길 것: 첫 실행 영향(덤프 시점 데이터로 R107 0 사건 · 통보 없음) · 신호 질의 시간(sg1 56 ms, 요청 행 1,061) · 위 한계.

## 증거

`docs/evidence/2026-09-29-sigma/` (git 에 넣지 않는다) — `results.json` · `results.md` · `sha256.json` · `fingerprint_restored.txt` · `fingerprint_final.txt` · `c1_snapshot_before.txt` · `c1_snapshot_after_sg1.txt` · `c1_snapshot_final.txt` · `run_c1_full_1.txt` · `run_sg1_full.txt` · `run_sg1_normal.txt` · `run_c1_full_2.txt` · `runs_after_sg1.txt` · `incidents.txt` · `normal_dry_run.json` · `normal_apply.json` · `req_before_normal.json` · `req_after_normal.json` · `control.json` · `timing.json` · `classify.json` · `rules_sigma_lab.json` · `lab_report.txt` · `analyze.py` · `control.py` · `classify.py` · `timing.py` · `assemble.py` · `sql/fingerprint.sql` · `sql/c1_snapshot.sql` · `sql/incidents.sql`. 비밀값은 없다.

## 8. 검토 뒤 변환기 수정과 다시 셈 (2026-09-28)

네 관점 검토에서 변환기 결함 둘이 나왔다. 한쪽 필드(cs-uri-query · cs-uri-stem)의 앵커 조건(로 시작 · 로 끝남 · 같음)을 url 전체에 대던 것을
url 모양(질의는 url 처음 또는 ? 뒤, 경로는 ? 앞)에 맞춰 옮기게 고쳤고, 필터(음의 조건) 쪽 메모가 양의 조건과 반대 방향이 되게 고쳤다.
선정 10개(sg1)의 탐지 조건은 한 글자도 바뀌지 않았고 Log4j · 22893 두 서명의 메모만 바뀌었다. 실험용 sgx 는 서명 2개(CVE-2021-21972 · CVE-2025-31324 SAP 첫 갈래)의
조건이 바뀌었다. 새 변환기로 sgx 를 다시 만들어(`fix54/rules_sigma_lab.v2.json`) 같은 요청 1,023건 · 정상 표식 38행에 다시 댄 결과는 맞은 요청 0 · 0 으로 같고,
pattern 만 맞는 서명도 같은 4개(0688 4 · 22893 2 · 26858 1 · owassrf 4)다. 요청 url 에 '?' 가 0건이라 앵커 조건의 변화가 셈에 닿지 않는다.
