# OpsLoop

실공격 데이터 기반 실시간 위협 탐지·대응 관제 플랫폼

> 대시보드에서 끝나지 않고, 조치가 탐지를 개선하는 폐루프(Closed-Loop) 관제 시스템

데이터분석과 파이널 프로젝트 (1인) · 발표 2026-10-16

## 구성

```
scripts/   허니팟 기동·배포 스크립트, Cowrie 설정
parser/    수집 로그 정규화 (WBS 2.2)
infra/     Terraform / cloud-init (예정)
docs/      운영 노트, 장애 기록, ADR
```

## 현재 운영 중인 것

| 구성요소 | 내용 |
|---|---|
| 허니팟 | Cowrie (SSH 22 / Telnet 23), AWS EC2 ap-northeast-2 |
| 로그 | `/opt/cowrie/log/cowrie.json*` — 날짜별 회전 |
| 관리 접근 | AWS SSM Session Manager (인바운드 관리 포트 없음) |

## 서버에서 쓰는 법

```bash
git clone <이 저장소> ~/opsloop-repo
~/opsloop-repo/scripts/deploy.sh          # 설정·파서 배치
~/opsloop-repo/scripts/run-cowrie.sh      # 허니팟 (재)기동

python3 ~/opsloop/parser/parse_cowrie.py                          # 적재 + 리포트
python3 ~/opsloop/parser/parse_cowrie.py --report --since 2026-09-05 --until 2026-09-06
```

파서는 재실행해도 중복이 쌓이지 않는다. 시간 범위를 인자로 받으므로
동일 구간에 다른 규칙 버전을 재적용하는 리플레이 평가에 그대로 쓸 수 있다.

## 데이터 출처 구분

허니팟 유입은 정의상 공격이지만, 구축 중 수행한 자체 접속 테스트가 섞여 있다.
`parser/exclusions.txt` 에 등록된 IP는 `provenance=fixture` 로 분류되어
실측 통계에서 제외된다.
