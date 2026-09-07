# 2026-09-04 허니팟 구축 중 장애 2건

## 1. 관리 포트 추가 후 SSH 전면 차단

**증상**
- `ssh.socket` 드롭인으로 22·54321 동시 개방 설정 후, 두 포트 모두 신규 연결이 즉시 RST
- 기존에 맺어진 세션만 생존. 두 개의 서로 다른 회선에서 동일하게 재현
- 서버는 `ss -tln` 상 두 포트 모두 LISTEN, iptables 규칙 없음, 보안그룹 정상

**원인**
- Ubuntu 24.04는 sshd를 systemd 소켓 활성화(`ssh.socket`)로 기동한다
- 스크립트가 소켓 유닛에는 포트를 추가했으나 `sshd_config` 에는 반영하지 않았다
- sshd가 자기 설정에 없는 포트의 소켓을 물려받으면서 연결 처리가 실패

**복구**
- SSM Session Manager로 우회 진입 (SSH에 의존하지 않는 경로)
- 드롭인 제거 후 `ssh.socket` 재시작 → 정상화 확인

**설계 변경**
- 관리 접근을 SSM으로 일원화. 허니팟 서버에 인바운드 관리 포트를 열지 않는다
- 22·23번은 전부 허니팟에 할당

## 2. cowrie.json 미생성

**증상**
- 컨테이너는 정상 동작하고 `docker logs` 에는 이벤트가 찍히는데, 마운트한
  `/opt/cowrie/log` 에 JSON 파일이 생기지 않음

**원인**
- `docker logs cowrie` 첫 40줄에 스택 트레이스가 있었다
  `PermissionError: [Errno 13] Permission denied: 'var/log/cowrie/cowrie.json'`
- 볼륨을 `1000:1000` 으로 소유 설정했으나 컨테이너 내부 cowrie 사용자는 UID `999`
- 출력 플러그인(jsonlog·textlog) 로드가 실패했고, 나머지 기능은 정상 동작해
  겉으로는 문제가 드러나지 않았다

**해결**
- `chown -R 999:999 /opt/cowrie/log /opt/cowrie/lib`
- `run-cowrie.sh` 에 UID를 상수로 분리해 이미지 변경 시 한 곳만 고치도록 함

**교훈**
- 경로·마운트를 추측하기 전에 컨테이너 표준출력의 에러부터 읽는다.
  원인은 처음부터 로그 상단에 적혀 있었다
