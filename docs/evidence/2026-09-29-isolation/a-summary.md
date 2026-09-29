# 4.2 A 연결 시도 · 권한 실측 (2026-09-29)

탐침: t42/probe.py (TCP 연결 4초 제한 · DNS 질의 · 이름 해석). 각 노드에서 한 번씩. 결과 원본은 t42/<노드>.out.
AWS 노드는 SSM(AWS-RunShellScript), VMware 노드는 SSH 로 실행. 운영 설정 변경 없음.

## 허니팟 i-0f8f7c0f698ca941a (10.0.21.10, DMZ, 14:28:33 KST)
| 대상 | 결과 |
|---|---|
| 옛 AWS DB 5432 · 옛 앱 8000 | 시간 초과 · 시간 초과 (옛 노드는 이미 없음) |
| 외부 HTTPS 1.1.1.1:443 | 시간 초과 |
| 외부 HTTPS example.com:443 | 거부·오류 |
| 외부 DNS 1.1.1.1:53 | 시간 초과 |
| VPC DNS 10.0.0.2 | 응답 61바이트, example.com 이름 해석됨 (172.66.147.243) → **DNS 를 통한 유출 경로 잔여** |
| S3 · SSM 엔드포인트 443 | 연결됨 · 연결됨 |
| 관문 SSH 10.0.1.10:22 | 시간 초과 |
| 내부 DB 5432 · 콘솔 8000 · 방화벽 관리 22 | 모두 시간 초과 |
| STS (B 시험 중 확인) | 닿지 않음 (boto3 get_caller_identity 가 연결 대기에서 멈춤) |

## 관문 i-0ffeb29efad03546d (10.0.1.10, 14:29:20 KST)
| 허니팟 22 | 연결됨 (관리 경로) |
| 외부 HTTPS 1.1.1.1 · example.com | 연결됨 · 연결됨 → **관문 외부 목적지 제한 없음(잔여)** |
| 외부 DNS 1.1.1.1 | 응답 → 잔여 |
| S3 · SSM 엔드포인트 | 연결됨 |
| 내부 DB 5432 · 방화벽 관리 22 | 시간 초과 |

## console-a 192.168.50.11 (15:22:26)
| data01 DB 5432 | 연결됨 (필요 경로) |
| data01 SSH 22 · 수집 관문 3101 · Loki 3100 | 시간 초과 |
| 방화벽 관리 22 · web01 80 | 시간 초과 |
| S3 443 | 연결됨 |
| 외부 1.1.1.1:443 · example.com:443 | 연결됨 → 포트만 제한, 목적지 제한 없음 (1차와 같음) |

## web01 192.168.50.21 (15:22:47) — 관제 대상 노드
| data01 수집 관문 3101 | 연결됨 (유일한 허용 경로) |
| data01 DB 5432 · SSH 22 · Loki 3100 | 시간 초과 |
| console-a 8000 · 22 | 시간 초과 |
| 방화벽 콘솔 8443 · 관리 22 | 시간 초과 |
| S3 443 | 이름 해석 실패(-3) |
| 외부 1.1.1.1:443 | 시간 초과 |

## data01 192.168.60.11 (15:23:40)
| 방화벽 관리 22 · web01 80 · console-a 8000 | 시간 초과 |
| S3 443 | 연결됨 (필요 경로) |
| 외부 1.1.1.1:443 · example.com:443 | 연결됨 → 목적지 제한 없음 (1차와 같음) |

## attacker 203.0.113.10 (15:23:54) — 외부 역할 세그먼트
| web01 80 (공개 서비스) | 연결됨 |
| web01 22 · console-a 8000 · 콘솔 진입점 8443 · data01 5432 · 3101 · 방화벽 관리 22 | 모두 시간 초과 |

## 서비스 권한 (data01 systemd, 15:5x 확인)
| 서비스 | 사용자 | 권한(CapabilityBoundingSet) | NoNewPrivileges | ProtectSystem | ProtectHome | PrivateTmp | MemoryMax |
|---|---|---|---|---|---|---|---|
| opsloop-ingest | opsloop-pull | 없음 | yes | strict | yes | yes | 512MiB |
| opsloop-gate | opsloop-gate | 없음 | yes | strict | yes | yes | 64MiB |
| opsloop-enforcer | opsloop-enforcer | 없음 | yes | strict | yes | yes | 256MiB |
| opsloop-agents | opsloop-pull | 없음 | yes | strict | yes | yes | 256MiB |
| opsloop-cti | opsloop-cti | 없음 | yes | strict | yes | yes | 512MiB |

## DB 역할 분리 점검 (infra/vmware/scripts/verify-db-roles.sh, 2026-09-29 15:5x)
종료 0, 항목 146 모두 ✔, ✘ 0. 절: 역할별 문장 · 상태판 · 계정 관리 · 계정 추가/삭제/비밀번호 · 접속 한도 · 집행 역할 속성 · 지금 붙어 있는 접속 · 네트워크(5432 는 콘솔 · 데이터 노드만).
원본 t42/verify-db-roles.out.

## 제외
- console-b (꺼짐 · MAINT) — 4.4 장애 주입 재측정에서 다룸
- 계정의 다른 인스턴스 i-009e9f578cc97472e "ec2" — OpsLoop 구성 아님
