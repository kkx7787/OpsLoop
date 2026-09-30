#!/usr/bin/env python3
"""차단 집행기 (이슈 #47 · #51 · #77). DB 차단 목록을 집행 지점에 넘기고, 지점이 보고한 적용 결과를 DB 에 되쓴다.

데이터 노드에서 돈다. opsloop-enforcer.timer 가 1분마다 opsloop-enforcer 사용자로 `run` 을 돌린다.

  DB blocklist ─(opsloop_enforcer, 읽기)→ 목록 문서 ─(S3 쓰기 사용자)→ s3://<버킷>/block/v1/latest.json
  관문 block-sync.py (1분) ─ entries 읽기 · 재검사 · fail2ban 또는 nft 집합 → s3://<버킷>/hb/v1/host=<관문 ID>-block/latest.json
  내부 방화벽 block-sync.py (1분 · nft) ─ points.fw (없으면 entries) → s3://<버킷>/hb/v1/host=<OPSLOOP_FW_ID>-block/latest.json
                                                                                         (이슈 #51, 설정했을 때만)
  이 집행기 ─(원장 읽기 사용자)→ 보고 대조 → blocklist 의 method · enforced_at · enforce_note (관문의 확인, 세 열) 와
                                              enforcement (지점별 결과, jsonb)

목록 문서 (이슈 #77)
  {"v":1, "generated_at", "entries":[{ip, until}], "digest", "points":{"fw":{"entries":[…], "digest"}}}
  points.fw 는 내부 방화벽 목록(아래 '원하는 목록'의 모든 행), entries 는 관문 목록이다. 요청 지점은 blocklist.points
  ('{gateway,fw}' · '{fw}'. 열이 없거나 모양이 틀리면 두 지점)다. 모든 행이 두 지점이면 entries · digest 가 #77 전과 같다.
  관문 목록 모드: 지점별이면 관문을 요청한 행만, 전체면 모든 행을 entries 에 싣는다. 지점별은 OPSLOOP_FW_ID 가 있고, 그 회차
    목록을 만들기 전에 읽은 내부 방화벽 보고의 list 가 "fw" 일 때다. list 가 없거나 "legacy"(모르는 값 포함)면 그 회차부터 전체다. 보고를 못
    읽었거나 list 가 null 이면 모드를 그대로 두되, 모드를 정한 회차(fw_list_seq)가 직전 회차일 때만이다(아니면 전체).
    옛 내부 방화벽 동기화(entries 만 적용)로 돌아가도 그 보고를 읽은 회차의 목록이 전체라 내부 방화벽 전용 주소가 곧 다시 들어간다.

집행 지점별 결과 (enforcement, 이슈 #51 · #77)
  {"gateway": {...}, "fw": {...}}. 행이 요청한 지점과, 요청했다가 빼서 빠짐 확인 전인 지점만 키가 있다. 지점마다
    state  pending(보고 전 · 확인 전) · confirmed(그 지점이 적용한 목록에 이 행이 있음) · failed(그 지점이 거부) ·
           stale(보고 없음 · 5분 넘게 멈춤 · 5분 넘게 미반영 · 목록을 못 올림 · 목록 상한 · 설정 없음 · 옛 판) ·
           removing(목록에서 빠진 행, 그 지점이 뺐다고 확인하기 전)
    since  그 상태가 된 시각 (confirmed 는 처음 확인한 보고의 at). 상태 · 문구(숫자만 다른 것은 같다)가 바뀔 때만 다시 적는다
    mode   그 지점이 보고한 방식(nft · fail2ban). note 는 failed · stale 의 짧은 까닭
  관문의 세 열과 감사(console.block.enforced · unenforced)는 관문을 요청한(unenforced 는 요청했던) 행만이다. 콘솔은 enforcement 로
  지점별 표를 그린다.
  내부 방화벽을 요청했는데 OPSLOOP_FW_ID 가 없으면 stale '내부 방화벽 설정 없음'이다.
  내부 방화벽 보고는 내부 방화벽 장부(fw_book)로 먼저, 거기 없는 목록이면 기존(관문) 장부로 판단한다(옛 판 동기화). 기존 장부로
  판단하는 동안 내부 방화벽 목록에 든 지 5분이 지나도 적용되지 않은 행은 stale '내부 방화벽 동기화 옛 판'이다.
  목록에서 빠진 행(해제 · 만료 · 제외)은 직전 결과가 있던 지점마다 removing 으로 두고, 그 지점이 이 행이 빠진 목록을 오류 없이
  적용했다고 보고하면(또는 만료 · 해제 행은 만료 뒤 24시간, 관문은 관문 목록에서 빠질 때의 until 뒤 24시간에도) 그 키를 지운다.
  모두 지워지면 NULL 이다. 목록 행의 요청하지 않은 지점도 직전 결과가 있으면(관리자 관문 빼기 · 관문 없이 다시 건 행) 같다.
  그 지점 목록에 아직 있으면(전체 모드의 관문 목록) 계속 removing 이다. 요청 지점은 removing 을 이어받지 않는다(빠짐 확인 전에
  다시 건 행 · 다시 요청한 지점).

차단 보고 생존 신호 (sensor_heartbeats, 이슈 #52)
  회차마다 관문 · 내부 방화벽 보고를 읽은 결과를 source='block:gateway' · 'block:fw'(설정했을 때만) 한 줄씩에 적는다.
  seen_at = 검증한 보고의 at(못 읽었으면 옛 값을 둔다) · checked_at = DB now() · problem = 못 읽은 까닭(읽었으면 NULL).
  대시보드 대상 카드의 대응 구역이 '<지점> 보고 <시각>' 으로 보인다. 오래된 보고도 읽었으면 문제가 아니다(시각으로 판단한다).
  기록은 집행과 따로다. 실패해도 종료 코드를 바꾸지 않고 로그만 남긴다(표 · 권한이 없으면 등급 5, 그 밖은 4).

하위 명령
  run [--dry-run]  한 회차. --dry-run 은 DB · 관문 보고를 읽고 할 일만 찍는다 (S3 · DB · 상태 파일을 고치지 않는다)
  list             올릴 목록 JSON 을 찍는다 (DB 와 상태 파일의 관문 목록 모드만 읽는다)
  status           마지막 회차 · 관문 목록 모드 · 보고 · 집행 상태별 건수 · 지점별 요청 · 확인 · 미요청 · 빠짐 확인 전 수를 찍는다
                   (읽기만)

원하는 목록
  released_at IS NULL · expires_at > now() · IPv4 /32 · 금지 대역(block_exempt 표와 EXEMPT_NETS) 밖인 행.
  4096 개(집합 크기)를 넘으면 요청이 늦은 것부터 넣고 나머지는 요청 지점마다 stale '목록 상한 …', 관문을 요청한 행은
  '관문 불일치 · 목록 상한 …' 으로 둔다. 상한은 내부 방화벽 목록(모든 행)에 건다.
  두 목록 가운데 하나라도 바뀔 때와 10분마다(생존 표시) 올린다. DB 를 못 읽으면 올리지 않는다(관문은 옛 집합을 두고 만료로 저절로 뺀다).
  digest 는 entries 를 ip 문자열 순으로 두고 json.dumps(sort_keys=True, separators=(",", ":")) 로 쓴 UTF-8 의 sha256 이다.
  points.fw.digest 도 같은 식이다. until 은 expires_at 을 초 단위로 내린 UTC ISO(…Z)다.

관문 보고 대조 (행마다, 관문을 요청한 행만. 관문 미요청 행에는 관문 세 열 · 쪽지를 쓰지 않는다)
  관문 보고의 list_digest 가 이 집행기가 올린 목록이면, 그 목록이 S3 에 있던 마지막 회차로 행이 들어 있는지 가린다.
  목록이 1분마다 바뀌어도(흡수 후속 차단) 관문이 한 회차 늦게 반영한 행을 확인할 수 있다. 지금 목록과 digest 가
  같을 때만 보면 목록이 쉬지 않고 바뀌는 동안 아무 행도 확인되지 않는다.
  - 확인(보고가 5분 안 · 그 목록에 (ip, until) 이 있음 · rejected 에 없음 · 셈이 맞음): enforced_at = 처음 확인한 보고의 at,
    method = 보고의 mode, enforce_note = '관문 반영 · <digest 앞 8자> · <at>'. 같은 (ip, until, mode) 는 다시 쓰지 않는다
    (감사 이벤트가 쌓이지 않게). 앞 확인(확인 시각 · 반영 쪽지)이 비운 적 없이 남은 채 새로 확인하면(다시 걸기 · 연장 · 방식 바뀜)
    쪽지 끝에 ' · 기존 차단 유지'(NOTE_KEPT)를 붙인다. 관문이 이 주소를 뺐다고 확인하지 못한 채 새 목록을 적용한 것이라 기간 보고서가
    관문 반영 지연에서 뺀다(이슈 #77 결정 2). 관문은 목록을 적용한 뒤 실제 집합과 대조해 빠진 항목을 rejected 로 돌려주므로 행마다의 판단은
    rejected 가 맡는다. 다른 관문 오류(되살림 · 일부 반영 실패 · 목록 밖 원소)는 로그에만 남기고 그 밖의 행은 확인한다 — 한 행이
    계속 실패한다고 집합에 있는 행까지 불일치로 두면 화면 · 대시보드가 '막지 못했다'고 잘못 읽히고, 풀릴 때 행마다 새 at 으로
    다시 써 감사 이벤트가 쌓인다.
    셈이 맞지 않으면(적용 수 + 거부 수 < 목록 · 집합 원소 수 < 적용 수 · 거부 목록이 관문 상한 200 에 닿아 잘렸을 수 있음)
    어느 행이 빠졌는지 모르므로 어느 행도 확인하지 않는다.
  - rejected · 확인은 관문이 적용한 목록에 이 행의 (ip, until) 이 들어 있을 때만 이 행의 것이다. 연장 전 until 로 만든 옛 목록의
    '만료 지남' 거부나 (상태 파일을 잃은 뒤의) 모르는 목록의 거부는 이 행에 붙이지 않고 새 목록의 보고를 기다린다.
  - 불일치: 관문 보고를 5분 넘게 못 읽음 · 보고가 5분 넘게 멈춤 · 모르는 목록 5분 · 셈이 맞지 않는 보고 5분 · 올린 지 5분이 지나도
    반영 안 됨 · 관문이 거부(rejected, 바로) · 목록을 5분 넘게 못 올려 S3 에 없는 행 → enforce_note '관문 불일치 · <사유>'.
    enforced_at 은 그대로 둔다. 불일치를 거친 행은 다시 확인될 때 새 at 으로 확인한다 (그 사이 집합이 비었다 되살아났을 수 있다).
  - 목록에서 빠진 행(해제 · 만료 · 제외): 관문이 그 행이 빠진 목록을 오류 없이 적용했다고 보고하면 enforced_at 을 NULL 로
    (unenforced 감사. 관문 오류가 있는 회차는 목록 밖 원소가 남았을 수 있어 기다린다).
    해제 · 만료된 행은 만료 뒤 24시간(관문 jail bantime)이 지나면 보고 없이도 NULL 로 한다. 관문 원소는 nft 방식이면 목록의
    until 에, fail2ban 방식이면 마지막으로 건 때부터 24시간 뒤에 빠지므로 어느 쪽이든 그때는 없다. 그 전에는 관문 확인을 기다린다.
    쪽지는 그대로 둔다 (언제 반영됐는지의 기록. 화면은 해제 · 만료를 released_at · expires_at 으로 먼저 가른다).
    관문 미요청 행에 남은 관문 세 열(관리자 관문 빼기 · 관문 없이 다시 걸기는 세 열을 둔다 · 옛 집행기 시절)은 관문 목록 밖이 된 뒤
    같은 조건으로 세 열을 모두 비운다(unenforced 감사가 관문이 실제로 뺀 뒤에 남는다. 24시간은 관문 목록에서 빠질 때의 until 부터도
    센다 — 관문 없이 다시 건 행은 만료가 늘어도 관문은 그 until 까지만 받았다). 확인 시각 없이 남은 쪽지 · 방식은 바로 비운다.
    관문 목록에 다시 든 행(빠짐 확인 전에 관문을 다시 요청 · 전체 모드로 돌아감 등)은 관문이
    이 주소가 빠진 목록을 오류 없이 적용했다고 보고한 뒤에만 남은 세 열을 비운다(관문을 요청한 행은 다시 적용하면 새로 확인한다).
    관문이 빠지기 전 목록을 아직 적용 중이면 세 열을 두고 확인을 잇는다.
  - 다시 건 행(해제 · 만료로 두 목록 밖이었다가 다시 든 행, 결정 2): 콘솔 · triage · 흡수는 관문 포함 여부와 무관하게 관문 세 열을
    요청 시각에 비우지 않는다. 관문이 그 사이 이 주소가 빠진 목록을 오류 없이 적용했다고 보고했으면(regained · 다시 걸기 전의
    gone_seen) 세 열을 비우고(unenforced 한 번) 새로 확인한다. 아니면 관문 차단이 이어진 것으로 보고 unenforced 없이 다시 든 목록을
    올린 뒤의 보고(그 목록 회차 ≤ 보고 회차 · 보고 시각 ≥ 올린 시각)로만 확인해 기존 차단 유지로 적는다. 다시 걸기 전의 확인은
    이어받지 않는다(adopt 는 상태 파일을 잃었을 때만). 마지막 확인 뒤 새로 요청해 관문 목록에 새로 든 행(관문 없이 다시 건 행이나 관리자
    관문 빼기 뒤의 행을 풀고 관문을 포함해 다시 걸기 · 상태 파일을 잃음 · 옛 집행기가 이어받은 확인, outdated)도 남은 확인을 쓰지 않고
    새 보고로 기존 차단 유지를 적는다. 확인 전에는 관문 결과가 pending(집행기 회차 전에는 removing)이라 종합 상태가
    대기다. 확인 시각 없이 남은 방식 · 반영 쪽지(관문이 뺐다고 확인해 비운 뒤 다시 건 행)는 첫 회차에 감사 없이 비운다.
  - 만료: 지난 2일 안에 만료된 행마다 note_block_expired(ip, expires_at) 를 한 번 부른다 (DB 쪽이 line_hash 로 멱등).
  - 제외: 만료 없음 · 금지 대역 · 대역 주소 행은 enforce_note '집행 제외 · …' (값이 같으면 쓰지 않는다).
    제외였던 행이 목록에 들어오면(만료를 새로 줬다 등) 확인될 때까지 쪽지를 비워 '집행 대기'로 둔다.
    IPv6 /128 행은 관문 집합(IPv4 만)에 넣지 않지만 계약에 맞는 쪽지가 없어 쪽지를 두지 않는다.
  쪽지 · 집행 열은 값이 바뀔 때만 쓴다. 숫자만 다른 불일치 쪽지(관문 문구의 분 · 건수)는 같은 것으로 본다.
  DB 쓰기는 읽은 값(released_at · expires_at · 집행 세 열 · enforcement · points)이 그대로일 때만 한다. 그 사이 콘솔이 고친 행은
  다음 회차에 본다.

상태 파일 ($OPSLOOP_ENFORCER_HOME/state.json, v 1)
  회차 번호 · 올린 목록 · digest 별 마지막 회차 · 행이 목록에 들어온/빠진 회차(다시 든 행은 빠져 있던 회차도) · 확인 기록 ·
  5분 시계 · 만료 기록.
  기존 장부(seen · entries · gone)는 관문 목록(entries)의 것이고, 내부 방화벽 목록은 fw_book{seen, entries, gone, seq} 에 둔다.
  관문 목록 모드는 fw_list_ok · fw_list_seq(모드를 정한 회차)다. 옛 집행기는 이 키들을 모르는 채 저장하므로, fw_book.seq 가
  직전 회차가 아니면 fw_book 을 기존 장부에서 다시 만들고, fw_list_seq 가 직전 회차가 아니면 전체 모드로 시작한다.
  잃으면 목록을 다시 올리고, DB 에 남은 확인 쪽지를 이어받는다 (같은 값을 다시 쓰지 않는다).

종료 코드
  0  정상 (관문 불일치는 DB 쪽지 · 로그 경고로 드러낸다)
  1  이번 회차에 못 한 일이 있다 (DB 읽기 · 쓰기, 목록 올리기, 관문 보고 읽기)
  2  설정 오류 (버킷 · 비밀 파일 · 인자)

설정
  /etc/default/opsloop-enforcer  OPSLOOP_BUCKET · OPSLOOP_GATEWAY_ID · OPSLOOP_FW_ID(선택, fw-<이름>. 내부 방화벽 동기화의 OPSLOOP_HOST 와 같다)
                                 · OPSLOOP_ENFORCER_HOME · AWS_DEFAULT_REGION (비밀 아님)
  비밀 파일 셋은 0600 root:root 다. 서비스는 systemd LoadCredential 로 읽기 전용 사본을 받는다($CREDENTIALS_DIRECTORY).
  root 로 손으로 돌리면 /etc/opsloop 의 원본을 읽는다.
    enforcer.env   DATABASE_URL (opsloop_enforcer 역할). DB 연결에만 쓴다
    s3-block.env   AWS_ACCESS_KEY_ID · AWS_SECRET_ACCESS_KEY (opsloop-block-writer, block/v1/latest.json 쓰기만)
    s3-pull.env    AWS_ACCESS_KEY_ID · AWS_SECRET_ACCESS_KEY (opsloop-archive-reader, hb/* 읽기. 적재기와 같은 키)
  비밀 파일은 셸로 읽지 않는다 (KEY=VALUE 만 읽고 실행하지 않는다). 키는 S3 클라이언트에만 넘긴다.
"""
import argparse
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timedelta, timezone

LIST_KEY = "block/v1/latest.json"
STATUS_KEY = "hb/v1/host={gw}-block/latest.json"
LIST_MAX = 4096                          # 관문 · 내부 방화벽 nft 집합 opsloop_block 의 size
REFRESH = timedelta(minutes=10)          # 목록이 그대로여도 이 간격으로 다시 올린다 (관문이 목록이 살아 있음을 안다)
REFRESH_EARLY = timedelta(seconds=30)    # 1분 타이머가 조금 늦어도 10분을 넘기지 않게
STALE = timedelta(minutes=5)             # 관문 보고의 신선도 · 불일치로 볼 때까지 기다리는 시간
FUTURE_SLACK = timedelta(minutes=2)      # 관문 시계가 이보다 앞서면 보고를 믿지 않는다
EXPIRED_LOOKBACK = timedelta(days=2)     # 이 안에 만료된 행만 만료 기록을 남긴다 (집행기가 멈췄던 동안의 만료도 줍는다)
BAN_HOLD = timedelta(hours=24)           # 관문 jail opsloop-block 의 bantime. 만료 뒤 이만큼 지나면 어느 방식이든 빠졌다
COUNT_SLACK = timedelta(minutes=2)       # 적용 수를 셀 때 곧 만료될 항목은 빼고 센다
SEEN_KEEP = 360                          # digest 별 마지막 회차를 이만큼(6시간) 기억한다
KEEP = timedelta(days=3)                 # 빠진 행 · 만료 기록을 상태에 두는 기간
STATUS_MAX = 2 * 1024 * 1024
REJECTED_MAX = 4096
GW_REJECTED_CAP = 200                    # 관문 block-sync.py 의 MAX_REJECTED. 거부 수가 여기 닿으면 잘렸을 수 있어 확인하지 않는다
ERRORS_MAX = 100
TEXT_MAX = 160                           # 관문이 보낸 문구를 쪽지에 넣을 때의 상한
LOCK_WAIT = 30
DEFAULT_GATEWAY = "i-0ffeb29efad03546d"  # 설정 OPSLOOP_GATEWAY_ID 가 없을 때 (2026-09-27 조사)
GATEWAY_ID_RE = re.compile(r"i-[0-9a-f]{8,17}")
FW_ID_RE = re.compile(r"fw-[a-z0-9-]{1,40}")   # 내부 방화벽 동기화의 OPSLOOP_HOST (infra/aws/gateway/block-sync.py HOST_RE 의 fw 갈래)
POINT_LABEL = {"gateway": "관문", "fw": "내부 방화벽"}
POINTS = ("gateway", "fw")               # 요청 지점 (이슈 #77 blocklist.points). 이 순서가 정규 순서다
POINT_STATES = ("pending", "confirmed", "failed", "stale")   # 목록 행의 상태 (removing 은 이어받지 않는다)
REMOVING = "removing"                    # 목록에서 빠진 행, 요청했던 지점이 뺐다고 확인하기 전 (이슈 #77)
LISTS = ("gateway", "fw", "legacy")      # 동기화 보고의 list (이슈 #77). 키가 없는 옛 판 보고 · 모르는 값은 legacy 로 본다
MODE_LABEL = {True: "지점별", False: "전체 · 내부 방화벽 확인 전"}   # 관문 목록 모드 (이슈 #77)
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
MODES = ("fail2ban", "nft")

# 차단 금지 대역. DB 의 block_exempt 표가 먼저고(트리거가 막는다), 이 상수는 표가 비거나 바뀌어도 남는 둘째 벽이다.
# 관문 block-sync.py 도 같은 목록으로 한 번 더 거른다. 문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)은
# 시험 출발지로 쓰므로 넣지 않는다. 15.164.37.49 는 관문 EIP 다
EXEMPT_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "15.164.37.49/32",
    "::1/128", "fc00::/7", "fe80::/10"))

NOTE_APPLIED = "관문 반영 · {d8} · {at}"
NOTE_KEPT = " · 기존 차단 유지"                  # 앞 확인을 비운 적 없이 새로 확인했다 (이슈 #77 결정 2, 보고서가 읽는다)
NOTE_MISMATCH = "관문 불일치 · {why}"
NOTE_NO_EXPIRY = "집행 제외 · 만료 없음"
NOTE_EXEMPT = "집행 제외 · 금지 대역"
NOTE_RANGE = "집행 제외 · 대역 주소"
NOTE_OVERCAP = "목록 상한 {n} 초과"
NOTE_FW_UNSET = "내부 방화벽 설정 없음"         # 내부 방화벽을 요청했는데 OPSLOOP_FW_ID 가 없다 (이슈 #77)
NOTE_FW_OLD = "내부 방화벽 동기화 옛 판"        # 내부 방화벽이 관문 목록(entries)을 적용한다 (이슈 #77)
APPLIED_RE = re.compile(r"관문 반영 · ([0-9a-f]{8}) · ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z)( · 기존 차단 유지)?")

# systemd 가 표준 출력의 <N> 접두사를 로그 등급으로 읽는다. 손으로 돌릴 때는 붙이지 않는다
_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SURROGATE = re.compile("[\ud800-\udfff]")


class ConfigError(Exception):
    """설정 오류 (종료 코드 2)."""


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


def clean(v, n=TEXT_MAX):
    """관문 · S3 가 준 문구를 로그 · DB 쪽지에 넣을 때. 제어 · 형식(Cf) · 줄 구분 문자를 '?' 로 바꾸고 자른다."""
    s = _SURROGATE.sub("?", _CTRL.sub("?", str(v)))
    s = "".join("?" if unicodedata.category(c) in ("Cf", "Zl", "Zp") else c for c in s)
    return s[:n]


def why(e):
    return clean(f"{type(e).__name__}: {e}", 300)


def iso(dt):
    """초 단위로 내린 UTC ISO (…Z). 목록의 until · 쪽지의 시각에 쓴다."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if dt else None


def iso_full(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?"
                 r"(Z|[+-][0-9]{2}:?[0-9]{2})")


def parse_ts(v):
    """시간대가 있는 ISO 8601 → UTC datetime. 못 읽으면 None (시간대 없는 값도 받지 않는다)."""
    if not isinstance(v, str) or len(v) > 40:
        return None
    m = _TS.fullmatch(v.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), int((frac or "0")[:6].ljust(6, "0")))
        if tz != "Z":
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))
            return dt.replace(tzinfo=timezone(off if tz[0] == "+" else -off)).astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def read_env(path):
    """KEY=VALUE 파일. 셸로 읽지 않는다 (값에 셸 문자가 있어도 실행되지 않는다)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def settings():
    """버킷 · 관문 ID · 상태 폴더 · 지역. 환경변수가 먼저고, 없으면 /etc/default/opsloop-enforcer 에서 읽는다."""
    try:
        conf = read_env(os.environ.get("OPSLOOP_ENFORCER_DEFAULTS", "/etc/default/opsloop-enforcer"))
    except OSError:
        conf = {}

    def get(k, default=None):
        return os.environ.get(k) or conf.get(k) or default
    gw = get("OPSLOOP_GATEWAY_ID", DEFAULT_GATEWAY)
    if not GATEWAY_ID_RE.fullmatch(gw):
        raise ConfigError(f"OPSLOOP_GATEWAY_ID 가 인스턴스 ID 가 아니다: {clean(gw, 40)}")
    fw = (get("OPSLOOP_FW_ID") or "").strip() or None
    if fw is not None and not FW_ID_RE.fullmatch(fw):
        raise ConfigError(f"OPSLOOP_FW_ID 가 fw-<이름> 꼴이 아니다: {clean(fw, 40)}")
    return {"bucket": get("OPSLOOP_BUCKET"), "gateway": gw, "fw": fw,
            "home": get("OPSLOOP_ENFORCER_HOME", "/var/lib/opsloop-enforcer"),
            "region": get("AWS_DEFAULT_REGION", "ap-northeast-2")}


SECRET_OVERRIDE = {"enforcer.env": "OPSLOOP_ENFORCER_DB_ENV", "s3-block.env": "OPSLOOP_ENFORCER_S3_BLOCK_ENV",
                   "s3-pull.env": "OPSLOOP_ENFORCER_S3_PULL_ENV"}


def secret_path(name):
    """서비스로 돌면 systemd 가 건넨 사본($CREDENTIALS_DIRECTORY), 손으로 돌리면 /etc/opsloop 의 원본."""
    over = os.environ.get(SECRET_OVERRIDE[name])
    if over:
        return over
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd and os.path.exists(os.path.join(cd, name)):
        return os.path.join(cd, name)
    return os.path.join("/etc/opsloop", name)


def db_connect():
    path = secret_path("enforcer.env")
    try:
        url = read_env(path)["DATABASE_URL"]
    except (OSError, KeyError) as e:
        raise ConfigError(f"DB 접속 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    import psycopg2
    return psycopg2.connect(url, connect_timeout=10, application_name="opsloop-enforcer")


def s3_client(cfg, name):
    """name 의 키로 만든 S3 클라이언트. 키는 이 클라이언트에만 넘기고 환경변수에 두지 않는다."""
    if not cfg["bucket"]:
        raise ConfigError("OPSLOOP_BUCKET 이 없다 (/etc/default/opsloop-enforcer)")
    path = secret_path(name)
    try:
        keys = read_env(path)
    except OSError as e:
        raise ConfigError(f"S3 키 파일을 읽지 못했다 ({path}: {type(e).__name__})") from None
    if not keys.get("AWS_ACCESS_KEY_ID") or not keys.get("AWS_SECRET_ACCESS_KEY"):
        raise ConfigError(f"S3 키가 비었다 ({path})")
    # 노드의 ~/.aws 설정 · 인스턴스 메타데이터를 보지 않는다 (내부망 VM 이라 메타데이터 조회는 시간만 끈다)
    for k in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        os.environ.setdefault(k, os.devnull)
    os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
    import boto3
    from botocore.config import Config
    return boto3.client("s3", region_name=cfg["region"], aws_access_key_id=keys["AWS_ACCESS_KEY_ID"],
                        aws_secret_access_key=keys["AWS_SECRET_ACCESS_KEY"],
                        config=Config(connect_timeout=10, read_timeout=30, retries={"max_attempts": 3}))


def err_code(e):
    try:
        return str(e.response["Error"]["Code"])
    except (AttributeError, KeyError, TypeError):
        return type(e).__name__


# ── 목록 ─────────────────────────────────────────────────────────────────────

def in_exempt(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in EXEMPT_NETS if n.version == a.version)


def classify(row, now):
    """행 하나의 갈래. ('list', expires_at) · ('exclude', 쪽지) · ('expired'|'released'|'skip', None)."""
    if row["released_at"] is not None:
        return "released", None
    exp = row["expires_at"]
    if exp is not None and exp <= now:
        return "expired", None
    if row["mask"] != (32 if row["fam"] == 4 else 128):
        return "exclude", NOTE_RANGE
    if row["exempt_net"] or in_exempt(row["ip"]):
        return "exclude", NOTE_EXEMPT
    if exp is None:
        return "exclude", NOTE_NO_EXPIRY
    if row["fam"] != 4:
        # 관문 유입(EIP)은 IPv4 뿐이고 집합도 ipv4_addr 다. 계약의 쪽지 다섯에 맞는 것이 없어 쪽지를 두지 않는다
        return "skip", None
    return "list", exp


def requested(row):
    """행이 요청한 지점 (이슈 #77). points 가 NULL(열이 없는 DB) 이거나 두 값('{gateway,fw}' · '{fw}') 밖이면 두 지점이다."""
    p = row.get("points")
    if isinstance(p, list) and all(isinstance(x, str) for x in p) and len(p) == len(set(p)) \
            and set(p) in ({"gateway", "fw"}, {"fw"}):
        return tuple(x for x in POINTS if x in p)
    return POINTS


def wants(row, point):
    return point in requested(row)


def classify_rows(rows, now, per_point=False):
    """행마다 kind · extra · gw 를 달고 (관문 목록, 내부 방화벽 목록) 을 돌려준다 (이슈 #77).
    내부 방화벽 목록은 목록에 드는 모든 행(상한 안)이고, 상한을 넘은 행은 kind='overcap' 이다. 관문 목록은 지점별 모드
    (per_point)면 관문을 요청한 행, 전체 모드면 내부 방화벽 목록과 같다. r['gw'] 는 관문 목록에 들었는가."""
    listed = []
    for r in rows:
        r["kind"], r["extra"] = classify(r, now)
        r["gw"] = False
        if r["kind"] == "list":
            listed.append(r)
    # 요청이 늦은 것부터 (같으면 주소 순). 오래된 요청보다 새 요청이 지금의 위협에 가깝다
    listed.sort(key=lambda r: (-(r["created_at"].timestamp() if r["created_at"] else 0), r["ip"]))
    for r in listed[LIST_MAX:]:
        r["kind"] = "overcap"
    gw, fw = [], []
    for r in listed[:LIST_MAX]:
        fw.append({"ip": r["ip"], "until": iso(r["extra"])})
        if not per_point or wants(r, "gateway"):
            r["gw"] = True
            gw.append({"ip": r["ip"], "until": iso(r["extra"])})
    return sorted(gw, key=lambda e: e["ip"]), sorted(fw, key=lambda e: e["ip"])


def canonical(entries):
    return json.dumps(sorted(entries, key=lambda e: e["ip"]), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_of(entries):
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def list_doc(gw_entries, fw_entries, now):
    """목록 문서 (이슈 #77). entries 는 관문 목록, points.fw 는 내부 방화벽 목록이다. points 는 늘 싣는다."""
    gw = sorted(gw_entries, key=lambda e: e["ip"])
    fw = sorted(fw_entries, key=lambda e: e["ip"])
    return {"v": 1, "generated_at": iso(now), "entries": gw, "digest": digest_of(gw),
            "points": {"fw": {"entries": fw, "digest": digest_of(fw)}}}


# ── 상태 ─────────────────────────────────────────────────────────────────────

def new_state():
    return {"v": 1, "seq": 0, "published": None, "seen": {}, "entries": {}, "gone": {}, "confirmed": {},
            "status_fail_since": None, "unknown_since": None, "error_since": None, "upload_fail_since": None,
            "expired_noted": {},
            # 지점별 결과 (이슈 #51). fw_* 는 내부 방화벽 보고의 5분 시계, points 는 지점 → ip → 지금 상태 기록
            "fw_status_fail_since": None, "fw_unknown_since": None, "fw_error_since": None, "points": {},
            # 이슈 #77. fw_book 은 내부 방화벽 목록(points.fw)의 장부(seq 는 마지막 회차), fw_list_ok · fw_list_seq 는
            # 관문 목록 모드(True 면 지점별)와 그것을 정한 회차다. 기존 장부(seen · entries · gone)는 관문 목록(entries)의 것이다
            "fw_book": {"seen": {}, "entries": {}, "gone": {}, "seq": 0}, "fw_list_ok": False, "fw_list_seq": 0}


def resume(st):
    """끊긴 상태를 맞춘다 (이슈 #77). 옛 집행기는 fw_book · fw_list_* 를 모르는 채 저장하므로, 되돌렸다 다시 올리면 낡은 값이 남는다.
    fw_book 이 없거나 마지막 회차가 직전 회차가 아니면 기존 장부에서 다시 만든다(옛 집행기의 목록은 모든 행이라 내부 방화벽
    목록과 같다). fw_list_seq 가 직전 회차가 아니면 전체 모드로 시작한다. 여러 번 불러도 같다."""
    prev = st["seq"]
    fb = st.get("fw_book")
    if not (isinstance(fb, dict) and all(isinstance(fb.get(k), dict) for k in ("seen", "entries", "gone"))
            and fb.get("seq") == prev):
        st["fw_book"] = {"seen": dict(st["seen"]), "entries": copy.deepcopy(st["entries"]),
                         "gone": copy.deepcopy(st["gone"]), "seq": prev}
        if prev:
            log("내부 방화벽 장부를 기존 장부에서 다시 만들었다 (옛 상태 파일 · 옛 집행기가 그 사이 돌았다)", 5)
    if st.get("fw_list_seq") != prev:
        if st.get("fw_list_ok"):
            log(f"관문 목록 모드: 끊긴 상태 파일의 모드라 {MODE_LABEL[False]} 으로 시작한다", 4)
        st["fw_list_ok"], st["fw_list_seq"] = False, prev


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            st = json.load(f)
        if not isinstance(st, dict) or st.get("v") != 1:
            raise ValueError("판이 다르다")
    except FileNotFoundError:
        return new_state()
    except (OSError, ValueError) as e:
        log(f"상태 파일을 읽지 못해 새로 시작한다 ({why(e)}). 목록을 다시 올리고 DB 의 확인 쪽지를 이어받는다", 4)
        return new_state()
    for k, v in new_state().items():
        if k not in st or (v is not None and not isinstance(st[k], type(v))):
            st[k] = v
    resume(st)
    return st


def save_state(path, st):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def take_lock(home, wait=LOCK_WAIT, sleep=time.sleep):
    # 읽기로 연다. root 가 손으로 돌려(--dry-run · status) 만든 잠금 파일도 서비스 사용자가 열 수 있다 (flock 은 읽기로도 된다)
    try:
        os.makedirs(home, exist_ok=True)
        f = os.fdopen(os.open(os.path.join(home, "enforcer.lock"), os.O_RDONLY | os.O_CREAT, 0o644), "rb")
    except OSError as e:
        raise ConfigError(f"상태 폴더를 쓸 수 없다 ({home}: {type(e).__name__})") from None
    waited = 0
    while True:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except BlockingIOError:
            if waited >= wait:
                f.close()
                raise ConfigError(f"다른 실행이 {wait}초 넘게 끝나지 않았다") from None
            sleep(1)
            waited += 1


def since(st, key, now):
    """5분 시계. 처음이면 지금을 적고, 적힌 때부터 지난 시간을 돌려준다."""
    t = parse_ts(st.get(key)) if st.get(key) else None
    if t is None or t > now:
        st[key] = iso_full(now)
        return timedelta(0)
    return now - t


def bookkeep(book, entries, digest, seq, now):
    """올린 목록이 S3 에 있는 회차의 기록. 행이 목록에 들어온 회차 · 빠진 회차 · digest 가 마지막으로 있던 회차.
    book 은 기존 장부(상태 그 자체, entries 목록) 또는 fw_book(points.fw 목록)이다 (이슈 #77).

    지점이 digest D 를 적용했다고 하면: seen[D] ≥ 들어온 회차인 행은 D 에 있고(그 뒤로 빠진 적이 없으므로),
    seen[D] ≥ 빠진 회차인 행은 D 에 없다. 같은 내용이 다시 나오면 digest 도 같으니 마지막 회차만 기억하면 된다.
    다시 든 행은 빠져 있던 회차 [left, back) 를 남긴다(연장해도 잇는다). seen[D] 가 그 안이면 D 에 그 행이 없다 (regained).
    """
    book["seen"][digest] = seq
    cur = {e["ip"]: e["until"] for e in entries}
    for ip, until in cur.items():
        e = book["entries"].get(ip)
        if not e or e.get("until") != until:
            g = book["gone"].get(ip)
            if not e and isinstance(g, dict) and isinstance(g.get("seq"), int):
                gap = {"left": g["seq"], "back": seq}
            else:
                gap = {k: e[k] for k in ("left", "back") if e and isinstance(e.get(k), int)}
            book["entries"][ip] = {"until": until, "seq": seq, "at": iso_full(now), **gap}
        book["gone"].pop(ip, None)
    for ip in [ip for ip in book["entries"] if ip not in cur]:
        # until 은 빠질 때 그 목록의 until 이다(관문은 gone_held). 옛 집행기는 seq · at 만 읽는다
        book["gone"][ip] = {"seq": seq, "at": iso_full(now), "until": book["entries"][ip].get("until")}
        del book["entries"][ip]
    book["seen"] = {d: s for d, s in book["seen"].items() if isinstance(s, int) and s >= seq - SEEN_KEEP}


# ── 관문 보고 ─────────────────────────────────────────────────────────────────

def _no_const(v):
    raise ValueError(f"JSON 상수 {v}")


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10 ** 9 else None


def validate_status(d, now, label="관문"):
    """(보고, None) 또는 (None, 까닭). 관문이 장악돼도 이 값으로 DB 에 쓰는 것은 검증한 시각 · 방식 · 짧은 문구뿐이다."""
    if not isinstance(d, dict) or d.get("v") != 1:
        return None, "형식 틀림 (v)"
    at = parse_ts(d.get("at"))
    if at is None:
        return None, "형식 틀림 (at)"
    if at > now + FUTURE_SLACK:
        return None, f"{label} 시각이 앞섬"
    mode = d.get("mode")
    if mode not in MODES:
        return None, "형식 틀림 (mode)"
    dg = d.get("list_digest")
    if dg is not None and not (isinstance(dg, str) and DIGEST_RE.fullmatch(dg)):
        return None, "형식 틀림 (list_digest)"
    rej = d.get("rejected") or []
    errs = d.get("errors") or []
    if not isinstance(rej, list) or len(rej) > REJECTED_MAX or not isinstance(errs, list):
        return None, "형식 틀림 (rejected · errors)"
    if _int(d.get("applied")) is None:
        return None, "형식 틀림 (applied)"    # 셈 대조의 기준이라 없으면 보고를 믿지 않는다 (set_count 는 집합을 못 읽으면 null)
    # 고른 목록 (이슈 #77, 선택 필드). 키가 없으면 #77 전 판 동기화다(entries 를 적용한다). null 은 목록을 못 읽은 회차다.
    # 모르는 값(앞으로의 판 · 오작동)은 보고를 버리지 않고 legacy 로 본다. 버리면 직전 모드(지점별)가 이어져 내부 방화벽 전용 행이 빠질 수 있다
    lst = d.get("list", "legacy")
    if lst is not None and lst not in LISTS:
        log(f"{label} 보고의 list 를 모른다 ({clean(lst, 20)}). legacy 로 본다 (관문 목록 전체)", 4)
        lst = "legacy"
    rejected = {}
    for x in rej:
        # 관문은 형식이 틀린 목록 항목도 거부로 돌려준다(주소 칸이 빈 문자열 등). 그런 항목만 건너뛰고 보고는 쓴다
        if not isinstance(x, dict) or not isinstance(x.get("ip"), str):
            continue
        try:
            ip = str(ipaddress.ip_address(x["ip"]))
        except ValueError:
            continue
        rejected[ip] = clean(x.get("why") or "사유 없음", 80)
    selftest = d.get("selftest")
    return {"at": at, "mode": mode, "list": lst, "digest": dg, "list_generated_at": parse_ts(d.get("list_generated_at")),
            "applied": _int(d["applied"]), "set_count": _int(d.get("set_count")), "rejected": rejected,
            "errors": [clean(e, 120) for e in errs[:ERRORS_MAX]] + (["오류 더 있음"] if len(errs) > ERRORS_MAX else []),
            "selftest": clean(selftest, 80) if isinstance(selftest, str) else None}, None


def read_status(s3r, bucket, key, now, label="관문"):
    """(보고, 까닭). 못 읽었거나 틀렸으면 보고는 None."""
    try:
        r = s3r.get_object(Bucket=bucket, Key=key)
        body = r["Body"].read(STATUS_MAX + 1)
    except Exception as e:  # noqa: BLE001 - boto3 · 연결 오류를 모두 '읽지 못함'으로 본다
        code = err_code(e)
        return None, f"없음 ({label} 동기화가 아직 쓰지 않았다)" if code in ("NoSuchKey", "404") else clean(code, 60)
    if len(body) > STATUS_MAX:
        return None, "크기 초과"
    try:
        d = json.loads(body, parse_constant=_no_const)
    except (ValueError, RecursionError):
        return None, "JSON 이 아니다"
    return validate_status(d, now, label)


def judge(st, gw, problem, now, books, prefix="", label="관문"):
    """집행 지점(관문 · 내부 방화벽)의 보고를 이번 회차의 판단으로. books 는 [(장부, published)] 이고 보고 digest 를 앞 장부부터
    찾는다(이슈 #77: 관문은 기존 장부, 내부 방화벽은 fw_book 다음 기존 장부 · 옛 판 동기화). published 는 (digest, 항목) —
    그 장부의 목록이 S3 에 있을 때만이고, 셈 대조는 찾은 장부의 목록으로 한다. j['book'] 은 찾은 장부(못 찾으면 첫 장부),
    j['legacy'] 는 첫 장부가 아닌 곳에서 찾았는가. prefix 는 5분 시계 키의 접두("" 관문 · "fw_" 내부 방화벽), label 은 문구에
    쓰는 이름이다. 관문의 문구는 그대로다."""
    j = {"ok": False, "verified": False, "gseq": None, "mode": None, "at": None, "d8": None, "mismatch": None,
         "rejected": {}, "problems": [], "book": books[0][0], "legacy": False}
    k_fail, k_unknown, k_error = prefix + "status_fail_since", prefix + "unknown_since", prefix + "error_since"
    if gw is None:
        age = since(st, k_fail, now)
        j["problems"].append(f"{label} 보고를 읽지 못했다: {problem}")
        if age >= STALE:
            j["mismatch"] = f"{label} 상태를 읽지 못함 ({problem})"
        return j
    st[k_fail] = None
    j.update(mode=gw["mode"], at=gw["at"])
    if now - gw["at"] > STALE:
        # 쪽지가 회차마다 바뀌지 않게 지난 시간(분) 대신 마지막 보고 시각을 적는다
        st[k_unknown] = st[k_error] = None
        j["mismatch"] = f"{label} 보고가 5분 넘게 멈춤 (마지막 {iso(gw['at'])})"
        return j
    j["rejected"] = gw["rejected"]
    dg = gw["digest"]
    published = None
    for i, (book, pub) in enumerate(books if dg else ()):
        if dg in book["seen"]:
            j.update(book=book, legacy=i > 0, gseq=book["seen"][dg])
            published = pub
            break
    j["d8"] = dg[:8] if dg else None
    if j["gseq"] is None:
        # list_digest 가 비면 그 지점이 목록을 못 읽었거나 대조를 못 마친 것이다. 그 지점의 첫 오류가 까닭이다
        age = since(st, k_unknown, now)
        if dg:
            what = f"{label}이 모르는 목록을 적용함 ({dg[:8]})"
        elif gw["errors"]:
            what = f"{label}이 목록을 적용하지 못함 · {gw['errors'][0]}"
        else:
            what = f"{label}이 목록을 아직 적용하지 않음"
        j["problems"].append(what)
        if age >= STALE:
            j["mismatch"] = what
        return j
    st[k_unknown] = None
    # 관문이 아는 목록을 적용했다. 행마다의 판단은 rejected 가 맡는다 (관문이 실제 집합과 대조해 빠진 항목을 돌려준다).
    # 셈이 맞지 않으면 어느 행이 빠졌는지 모르므로 어느 행도 확인하지 않는다. 그 밖의 관문 오류는 로그에만 남긴다
    problems = []
    if published and dg == published[0]:
        want = sum(1 for e in published[1] if (parse_ts(e["until"]) or now) > gw["at"] + COUNT_SLACK)
        if gw["applied"] + len(gw["rejected"]) < want:
            problems.append(f"적용 수 부족 ({gw['applied']}/{want})")
    if gw["set_count"] is not None and gw["set_count"] < gw["applied"]:
        problems.append(f"집합 원소 수 부족 ({gw['set_count']}/{gw['applied']})")
    if len(gw["rejected"]) >= GW_REJECTED_CAP:
        problems.append(f"거부 목록이 {label} 상한에 닿음 ({len(gw['rejected'])})")
    j["problems"] += problems + gw["errors"]
    if problems:
        age = since(st, k_error, now)
        if age >= STALE:
            j["mismatch"] = f"{label} 오류 · {problems[0]}"
        return j
    st[k_error] = None
    j["verified"] = True                  # 행마다 확인 · 거부를 판단할 수 있다
    j["ok"] = not gw["errors"]            # 목록 밖 원소까지 없는 깨끗한 회차 (집행 해제는 이때만)
    return j


def unset_judge(st):
    """OPSLOOP_FW_ID 가 없을 때 내부 방화벽의 판단 (이슈 #77 G7). 내부 방화벽은 늘 요청되므로 목록 행은 stale '설정 없음'이고,
    목록 밖 행의 fw 갈래는 확인할 곳이 없어 바로 지운다."""
    return {"ok": False, "verified": False, "gseq": None, "mode": None, "at": None, "d8": None, "mismatch": NOTE_FW_UNSET,
            "rejected": {}, "problems": [], "book": st["fw_book"], "legacy": False, "unset": True}


# ── 행마다 할 일 ──────────────────────────────────────────────────────────────

def mismatch(reason):
    return NOTE_MISMATCH.format(why=clean(reason, TEXT_MAX))


_DIGITS = re.compile(r"[0-9]+")


def same_mismatch(a, b):
    """숫자만 다른 불일치 쪽지는 같은 것으로 본다 ('목록이 오래됨 (12분)' 처럼 관문 문구의 수가 회차마다 바뀐다)."""
    p = NOTE_MISMATCH.format(why="")
    return bool(a) and bool(b) and a.startswith(p) and b.startswith(p) and _DIGITS.sub("#", a) == _DIGITS.sub("#", b)


def req_of(row):
    """행의 마지막 요청 시각(created_at. 콘솔 · triage · 흡수가 요청마다 적는다). 확인 기록에 함께 둔다."""
    return iso_full(row.get("created_at"))


def outdated(row, e, at, req=None):
    """관문 확인(시각 at)이 이 행의 마지막 요청 전의 것이라 낡았는가 (이슈 #77 결정 2). 확인 뒤에 새로 요청했고 관문 목록 항목(장부 e)도
    확인 뒤에 새로 들었다(관문 없이 다시 건 행이나 관리자 관문 빼기 뒤의 행을 풀고 관문을 포함해 다시 걸기 · 옛 집행기가 이어받은 확인 ·
    상태 파일을 잃음). 목록 항목이 확인 전부터 그대로인 재요청(살아 있는 차단을 같은 만료로 다시 요청 · 전체 모드라 관문 목록에서 빠진
    적 없음)은 관문이 새로 적용할 것이 없어 낡지 않았다. req 는 그 확인을 적을 때의 요청 시각이다(같으면 낡지 않았다. 지점 시계가
    늦어도 회차마다 다시 확인하지 않는다). at 은 초 단위라 같은 초 안의 요청 · 목록도 그 뒤로 본다."""
    created, entered = row.get("created_at"), parse_ts((e or {}).get("at"))
    if at is None or created is None or (req is not None and req == req_of(row)):
        return False
    return created > at and (entered is None or entered > at)


def adopt(row, until, j):
    """상태 파일을 잃었을 때 DB 에 남은 확인을 이어받는다 (같은 값을 다시 써서 감사 이벤트를 만들지 않게)."""
    m = APPLIED_RE.fullmatch(row["note"] or "")
    if not m or row["enforced_at"] is None or row["method"] != j["mode"] or m.group(2) != iso(row["enforced_at"]):
        return None
    return {"until": until, "at": iso(row["enforced_at"]), "d8": m.group(1), "mode": j["mode"], "req": req_of(row),
            **({"kept": True} if m.group(3) else {})}


def confirmation(row, until, j):
    """새 관문 확인 기록. 앞 확인(확인 시각 · 반영 쪽지)이 비운 적 없이 남아 있으면 기존 차단 유지(kept)다 (이슈 #77 결정 2):
    관문이 이 주소를 뺐다고 확인하지 못한 채(다시 걸기 · 연장 · 방식 바뀜) 새 목록을 적용했다. 불일치 쪽지를 거쳤으면 아니다."""
    c = {"until": until, "at": iso(j["at"]), "d8": j["d8"], "mode": j["mode"], "req": req_of(row)}
    if row["enforced_at"] is not None and APPLIED_RE.fullmatch(row["note"] or ""):
        c["kept"] = True
    return c


def applied_note(c):
    return NOTE_APPLIED.format(d8=c["d8"], at=c["at"]) + (NOTE_KEPT if c.get("kept") else "")


def rearmed(ip, st, book=None):
    """해제 · 만료로 목록 밖이었다가 다시 건 행인가 (이슈 #77 결정 2). 그 장부(기본은 관문 목록의 기존 장부)에 다시 든 회차가 내부
    방화벽 목록(목록 행 모두)에 다시 든 회차와 같다. 살아 있는 채 관문만 뺐다 다시 더한 행(넓히기)은 내부 방화벽 목록에서 빠진 적이
    없어 아니다."""
    back = ((st if book is None else book)["entries"].get(ip) or {}).get("back")
    return isinstance(back, int) and back == (st["fw_book"]["entries"].get(ip) or {}).get("back")


def applied_in(row, st, j, book):
    """그 지점이 적용한 목록에 이 행의 (ip, until) 이 들어 있는가. (장부 기록, 올림, 적용). 연장 전 until 의 옛 목록이나 모르는
    목록의 거부 · 확인은 이 행의 것이 아니다. 다시 건 행(결정 2)은 다시 든 목록을 올린 뒤의 보고로만 적용으로 본다. 같은 내용의
    목록이 전에도 있었으면(같은 만료로 다시 걸었다) 다시 걸기 전의 보고도 그 목록 회차를 적용한 것으로 보이기 때문이다(보고 시각은 초 단위)."""
    ip, until = row["ip"], iso(row["extra"])
    e = book["entries"].get(ip)
    published = bool(e) and e.get("until") == until
    applied = published and j["gseq"] is not None and j["gseq"] >= e["seq"]
    if applied and rearmed(ip, st, book) and j["at"] < (parse_ts(e.get("at")) or j["at"]).replace(microsecond=0):
        applied = False
    return e, published, applied


def want_listed(row, st, j, now):
    ip, until = row["ip"], iso(row["extra"])
    e, published, applied = applied_in(row, st, j, st)
    again = rearmed(ip, st)
    if applied and ip in j["rejected"]:
        if row["extra"] <= j["at"] + COUNT_SLACK:
            # 곧 만료될 행의 거부(관문 시각으로 '만료 지남')는 확인도 불일치도 아니다. 다음 회차에 만료로 빠진다
            return {}, "pending"
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch("관문 거부 · " + j["rejected"][ip])}, "reject"
    if j["verified"] and applied:
        c = st["confirmed"].get(ip)
        if (not c or c.get("until") != until or c.get("mode") != j["mode"]
                or outdated(row, e, parse_ts(c.get("at")), c.get("req"))):
            # 상태 파일을 잃었으면 DB 에 남은 확인을 이어받는다. 다시 건 행 · 마지막 확인 뒤 새로 요청해 관문 목록에 새로 든 행은
            # 이어받지 않는다(요청 전의 확인이다, 결정 2). 남은 확인이 그렇게 낡았어도 새로 확인한다(기존 차단 유지)
            fresh = not c and not again and not outdated(row, e, row["enforced_at"])
            c = (adopt(row, until, j) if fresh else None) or confirmation(row, until, j)
            st["confirmed"][ip] = c
        return {"enforced_at": parse_ts(c["at"]), "method": c["mode"], "enforce_note": applied_note(c)}, "confirm"
    if j["mismatch"]:
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch(j["mismatch"])}, "mismatch"
    if not published and j.get("upload_stuck"):
        # 이 (ip, until) 이 든 목록을 5분 넘게 S3 에 올리지 못했다. 관문은 옛 목록을 적용하므로 이대로는 반영되지 않는다
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch(j["upload_stuck"])}, "mismatch"
    # 셈이 맞는 보고인데 그 목록에 이 행이 없고 올린 지 5분이 지났다. 그렇지 않은 회차(셈 불일치 · 모르는 목록 · 못 읽음)는
    # 위의 5분 시계들이 맡는다
    if j["verified"] and published and now - (parse_ts(e.get("at")) or now) >= STALE:
        st["confirmed"].pop(ip, None)
        return {"enforce_note": mismatch("5분 넘게 반영되지 않음")}, "mismatch"
    return {}, "pending"


def point_state(row, st, j, now):
    """지점 하나에서 이 행의 (state, note). want_listed 와 같은 판단이지만 관문의 열은 고치지 않는다 (이슈 #51).
    장부는 그 보고를 찾은 장부(j['book'])다 (이슈 #77)."""
    ip, until = row["ip"], iso(row["extra"])
    e, published, applied = applied_in(row, st, j, j["book"])
    if applied and ip in j["rejected"]:
        if row["extra"] <= j["at"] + COUNT_SLACK:
            return None, None                            # 곧 만료될 행의 '만료 지남' 거부는 확인도 실패도 아니다 (보류)
        return "failed", j["rejected"][ip]
    if j["verified"] and applied:
        return "confirmed", None
    if j["mismatch"]:
        return "stale", j["mismatch"]
    if not published and j.get("upload_stuck"):
        return "stale", j["upload_stuck"]
    if j["legacy"] and j["verified"]:
        # 내부 방화벽이 관문 목록(entries)을 적용했다(옛 판 동기화). 내부 방화벽 목록에 든 지 5분이 지나도 그 목록에 없으면 옛 판 탓이다
        f = st["fw_book"]["entries"].get(ip)
        if f and f.get("until") == until and now - (parse_ts(f.get("at")) or now) >= STALE:
            return "stale", NOTE_FW_OLD
    if j["verified"] and published and now - (parse_ts(e.get("at")) or now) >= STALE:
        return "stale", "5분 넘게 반영되지 않음"
    # 판정할 수 있는 보고인데 아직 이 행이 없으면 대기다. 보고를 못 읽었거나 · 모르는 목록 · 셈이 맞지 않는 회차(5분 전)는
    # 판정할 수 없으므로 보류(None)다. 직전 상태를 그대로 둔다 (want_listed 가 관문 확인을 유지하는 것과 같다)
    return ("pending", None) if j["verified"] else (None, None)


def same_note(a, b):
    """숫자만 다른 문구는 같은 것으로 본다 (지점 문구의 분 · 건수가 회차마다 바뀐다)."""
    if a is None or b is None:
        return a is b
    return _DIGITS.sub("#", a) == _DIGITS.sub("#", b)


def _view(rec):
    return {"state": rec["state"], "since": rec.get("since"), "mode": rec.get("mode"), "note": rec.get("note")}


def _prev_point(row, point):
    """DB 에 남은 그 지점의 결과(상태 파일을 잃었거나 처음 배포할 때 이어받는다). 모양이 틀리면 None.
    요청 지점은 removing 을 이어받지 않는다 (빠짐을 확인하기 전에 다시 건 행 · 다시 요청한 지점, 이슈 #77)."""
    prev = row.get("enforcement")
    prev = prev.get(point) if isinstance(prev, dict) else None
    if not isinstance(prev, dict) or prev.get("state") not in POINT_STATES:
        return None
    return prev


def enforcement_of(row, st, judges, now, fixed=None, current=False):
    """지점별 결과. 행이 요청한 지점을 싣고, 요청하지 않은 지점은 빠짐 확인 전(leaving)일 때만 싣는다 (이슈 #77).
    상태 · 문구가 바뀔 때만 since 를 새로 적어 회차마다 DB 를 다시 쓰지 않는다.
    - 판정할 수 없는 회차(보류)는 직전 기록을 그대로 둔다. 기록이 없으면 DB 의 값, 그것도 없으면 대기다
    - 상태 파일에 기록이 없으면(분실 · 첫 배포) DB 의 같은 상태 · 같은 문구를 이어받는다
    - 관문의 적용 확인 시각은 관문 열의 확인 시각(st['confirmed'] · enforced_at)과 늘 같다
    fixed 는 모든 요청 지점에 둘 (state, note) 다 (목록 상한을 넘은 행). current 는 지금 목록이 S3 에 있는가다."""
    out, until, req = {}, iso(row["extra"]), requested(row)
    for point in req:
        j = judges[point]
        state, note = fixed or point_state(row, st, j, now)
        note = clean(note, TEXT_MAX) if note else None
        book = st["points"].setdefault(point, {})
        rec = book.get(row["ip"])
        renewed = bool(rec) and rec.get("until") != until      # 만료가 바뀌었다(다시 걸기 · 연장). DB 의 결과는 옛 만료의 것이다
        if renewed:
            rec = None
        prev = _prev_point(row, point)
        if state is None:
            # 판정할 수 없는 회차에 옛 만료의 결과를 새 만료로 옮기지 않는다(다시 건 뒤의 보고로만 확인한다, 결정 2)
            if rec is None and prev is not None and not renewed:
                rec = {"until": until, "state": prev["state"], "note": prev.get("note"), "mode": prev.get("mode"),
                       "since": prev.get("since")}
                book[row["ip"]] = rec
            if rec is not None:
                out[point] = _view(rec)
                continue
            state, note = "pending", None
        if rec is None and prev is not None and prev["state"] == state and same_note(prev.get("note"), note):
            rec = {"until": until, "state": state, "note": prev.get("note"), "mode": prev.get("mode") or j["mode"],
                   "since": prev.get("since")}
            book[row["ip"]] = rec
        if rec is None or rec.get("state") != state or not same_note(rec.get("note"), note):
            rec = {"until": until, "state": state, "note": note, "mode": j["mode"],
                   "since": iso(j["at"] if state == "confirmed" and j["at"] else now)}
            book[row["ip"]] = rec
        elif j["mode"] and rec.get("mode") != j["mode"]:
            rec["mode"] = j["mode"]
        if point == "gateway" and rec["state"] == "confirmed":
            c = st["confirmed"].get(row["ip"])
            if c and c.get("until") == until and c.get("at"):
                rec["since"] = c["at"]
        out[point] = _view(rec)
    # 요청하지 않은 지점 (이슈 #77 결정 14). 요청했던 지점(관리자 관문 빼기 · 관문 없이 다시 건 행)은 뺐다고 확인할 때까지
    # removing 이다. 그 지점의 목록 행 기록은 버린다(다시 요청하면 새로 센다)
    for point in POINTS:
        if point not in req:
            st["points"].get(point, {}).pop(row["ip"], None)
            rec = leaving(row, st, point, judges.get(point), now, current)
            if rec:
                out[point] = rec
    return out


def gone_seen(ip, st, j, now, current):
    """그 지점이 이 주소가 빠진 목록을 오류 없이 적용했다고 보고했는가 (그 장부의 빠진 회차 ≤ 보고 회차).
    장부에 빠진 기록이 없으면(상태 파일을 잃었다 · 다른 곳에서 썼다) 지금 올린 목록부터 센다."""
    book = j["book"]
    g = book["gone"].get(ip)
    if g is None and current:
        g = book["gone"][ip] = {"seq": st["seq"], "at": iso_full(now)}
    return bool(g) and j["ok"] and j["gseq"] >= g["seq"]


def regained(ip, st, j):
    """관문 목록에 다시 든 주소를, 관문이 그 전에 이 주소가 빠진 목록을 오류 없이 적용했다고 보고했는가 (이슈 #77).
    빠져 있던 회차 [left, back) 안에 S3 에 있던 목록이면 이 주소가 없다. 빠지기 전 목록을 아직 적용 중이거나 판단할 수 없으면 거짓이다."""
    e = st["entries"].get(ip) or {}
    left, back = e.get("left"), e.get("back")
    return (isinstance(left, int) and isinstance(back, int) and j["ok"] and j["gseq"] is not None
            and left <= j["gseq"] < back)


def gone_held(ip, st, now):
    """관문 목록에서 빠진 주소가 빠질 때의 until 뒤 BAN_HOLD 가 지났는가 (이슈 #77). 그때는 어느 방식이든 관문 원소가 없다.
    관문 없이 다시 건 행은 만료가 늘어도 관문이 마지막으로 받은 until 로 본다. until 이 없는 옛 기록 · 목록에 다시 든 주소는 거짓이다.
    내부 방화벽은 늘 요청 지점이라 목록 행의 until 을 끝까지 받으므로 만료로 본다."""
    g = st["gone"].get(ip)
    until = parse_ts(g.get("until")) if isinstance(g, dict) else None
    return until is not None and now >= until + BAN_HOLD


def leaving(row, st, point, j, now, current, held=False):
    """요청했던 지점 하나의 빠짐 확인 전(removing) 기록 또는 None (이슈 #77). 직전 결과가 없거나, 확인할 곳이 없거나(OPSLOOP_FW_ID
    없음), held(해제 · 만료 행의 만료 + BAN_HOLD · gone_held)거나, 그 지점이 이 행이 빠진 목록을 오류 없이 적용했다고 보고했으면
    None 이다. 그 지점의 목록에 아직 있으면(전체 모드의 관문 목록) 계속 removing 이다."""
    prev = row.get("enforcement")
    p = prev.get(point) if isinstance(prev, dict) else None
    if not isinstance(p, dict) or p.get("state") not in POINT_STATES + (REMOVING,):
        return None
    if held or j is None or j.get("unset") or (point == "gateway" and gone_held(row["ip"], st, now)):
        return None
    listed = row["gw"] if point == "gateway" else row["kind"] == "list"
    if not listed and gone_seen(row["ip"], st, j, now, current):
        return None
    since_ = p.get("since") if p["state"] == REMOVING else iso(now)
    return {"state": REMOVING, "since": since_, "mode": p.get("mode"), "note": None}


def removing_of(row, st, judges, now, current):
    """목록 밖 행(해제 · 만료 · 제외)의 지점별 결과 (이슈 #77). 직전 결과가 있던 지점마다(요청하지 않은 지점 포함) leaving 이다.
    모두 지워지면 None."""
    exp = row["expires_at"]
    held = row["kind"] in ("expired", "released") and exp is not None and now >= exp + BAN_HOLD
    out = {}
    for point in POINTS:
        rec = leaving(row, st, point, judges.get(point), now, current, held)
        if rec:
            out[point] = rec
    return out or None


def want_unenforce(row, st, j, now, current):
    """관문 목록 밖 행(목록 밖이거나, 관문 미요청이라 entries 에 없음)의 enforced_at 을 NULL 로 할 때인가."""
    if row["enforced_at"] is None:
        return False
    if gone_seen(row["ip"], st, j, now, current):
        return True
    # 관문 보고가 끊겨도 만료 뒤 24시간이면 관문 원소는 빠졌다 (해제도 같다. 해제는 만료를 바꾸지 않는다). 관문 없이 다시 건 행은
    # 관문 목록에서 빠질 때의 until 로 본다 (gone_held)
    exp = row["expires_at"]
    if row["kind"] in ("expired", "released") and exp is not None and now >= exp + BAN_HOLD:
        return True
    return gone_held(row["ip"], st, now)


def plan(rows, st, j, now, current, judges=None):
    """DB 에 쓸 것 (행마다 바꿀 열 · 읽은 값) 과 만료 기록을 부를 행. judges 는 지점 → 판단(관문 j 를 포함).
    관문 세 열은 관문을 요청한 행만 쓴다. 관문 미요청 행에 남은 관문 세 열(관리자 관문 빼기 · 옛 집행기 시절)은 관문 목록 밖이 되고
    관문이 뺐다고 확인한 뒤 비운다 (이슈 #77)."""
    judges = judges or {"gateway": j, "fw": unset_judge(st)}
    updates, expired, tally = [], [], {}
    for row in rows:
        kind, ip = row["kind"], row["ip"]
        want, tag = {}, kind
        alive = kind in ("list", "overcap")
        if kind == "list" and wants(row, "gateway"):
            want, tag = want_listed(row, st, j, now)
            if tag == "pending" and row["enforced_at"] is not None and regained(ip, st, j):
                # 관문 목록에 다시 든 행(관리자 관문 빼기 뒤 넓히기 등, 이슈 #77)인데 관문이 그 전에 이 주소가 빠진 목록을 오류 없이
                # 적용했다. 남은 세 열은 관문이 뺀 뒤의 옛 확인이라 비운다(unenforced). 관문이 다시 적용하면 새 시각으로 확인한다.
                # 관문이 빠지기 전 목록을 아직 적용 중이거나 판단할 수 없으면 세 열을 두고 기다린다(다시 적용하면 확인을 잇는다)
                want, tag = {"enforced_at": None, "method": None, "enforce_note": None}, "pending+reset"
            elif tag == "pending" and (row["note"] or "").startswith("집행 제외"):
                # 제외였던 행이 목록에 들어왔다 (만료가 생겼거나 금지 대역에서 빠졌다). 확인 전까지는 '집행 대기'다
                want = {"enforce_note": None}
            elif tag == "pending" and row["enforced_at"] is None and (row["method"] is not None
                                                                      or APPLIED_RE.fullmatch(row["note"] or "")):
                # 확인 시각 없이 남은 방식 · 반영 쪽지(관문이 뺐다고 확인해 비운 뒤 다시 건 행. 다시 걸기는 세 열을 두므로, 결정 2).
                # 감사 없이 비우고 확인되면 새로 쓴다
                want = {"method": None, "enforce_note": None}
            want["enforcement"] = enforcement_of(row, st, judges, now, current=current)
        elif kind == "list":
            # 관문 미요청 (이슈 #77). 관문의 확인 · 불일치 쪽지를 쓰지 않는다. 확인 시각 없이 남은 쪽지(관문 · 제외) · 방식(관문이 이미 뺀
            # 옛 확인을 두고 관문 없이 다시 건 행)은 비우고, 남은 관문 세 열은 관문이 뺀 뒤 아래 want_unenforce 가 비운다. 요청했던
            # 관문은 그때까지 removing 이다
            st["confirmed"].pop(ip, None)
            if row["enforced_at"] is None:
                want["enforce_note"] = want["method"] = None
            want["enforcement"] = enforcement_of(row, st, judges, now, current=current)
            tag = "fw-" + want["enforcement"]["fw"]["state"] + ("+gw-removing" if "gateway" in want["enforcement"] else "")
            if row["enforced_at"] is not None and row["gw"] and regained(ip, st, j):
                # 전체 모드라 관문 목록에 다시 들었는데 관문이 그 전에 이 주소가 빠진 목록을 오류 없이 적용했다. 남은 세 열은 관문이
                # 뺀 뒤의 옛 확인이라 비운다(unenforced). 관문이 다시 넣는 것은 관문 미요청이라 적지 않고 빠짐 확인 전을 잇는다
                want.update(enforced_at=None, method=None, enforce_note=None)
                tag += "+reset"
        else:
            st["confirmed"].pop(ip, None)
            if kind == "overcap":
                want["enforcement"] = enforcement_of(row, st, judges, now, fixed=("stale", NOTE_OVERCAP.format(n=LIST_MAX)),
                                                     current=current)
                if wants(row, "gateway"):
                    want["enforce_note"] = mismatch(NOTE_OVERCAP.format(n=LIST_MAX))
            else:
                for book in st["points"].values():
                    book.pop(ip, None)
                want["enforcement"] = removing_of(row, st, judges, now, current)
                if kind == "exclude":
                    want["enforce_note"] = row["extra"]
        if not row["gw"] and want_unenforce(row, st, j, now, current):
            want["enforced_at"] = None
            if alive and not wants(row, "gateway"):
                want["method"] = want["enforce_note"] = None      # 관문 빼기 · 옛 집행기 시절의 관문 세 열 (관문 미요청 행)
            st["gone"].pop(ip, None)
            tag = f"{tag}+unenforce"
        tally[tag] = tally.get(tag, 0) + 1
        cur = {"enforced_at": row["enforced_at"], "method": row["method"], "enforce_note": row["note"],
               "enforcement": row.get("enforcement")}
        change = {k: v for k, v in want.items() if cur[k] != v}
        if "enforce_note" in change and same_mismatch(cur["enforce_note"], change["enforce_note"]):
            del change["enforce_note"]
        if change:
            updates.append({"key": row["key"], "ip": ip, "set": change, "tag": tag,
                            "guard": {"released_at": row["released_at"], "expires_at": row["expires_at"], **cur,
                                      "points": row.get("points")}})
        if kind == "expired" and now - row["expires_at"] <= EXPIRED_LOOKBACK:
            k = f"{row['key']}|{iso_full(row['expires_at'])}"
            if k not in st["expired_noted"]:
                expired.append((row["key"], row["expires_at"], k))
    return updates, expired, tally


def prune(st, rows, now):
    fetched = {r["ip"] for r in rows}
    for book in (st, st["fw_book"]):
        for ip in [ip for ip, g in book["gone"].items()
                   if ip not in fetched or now - (parse_ts(g.get("at")) or now) > KEEP]:
            del book["gone"][ip]
    listed = {r["ip"] for r in rows if r["kind"] == "list"}
    for ip in [ip for ip in st["confirmed"] if ip not in listed]:
        del st["confirmed"][ip]
    alive = {r["ip"] for r in rows if r["kind"] in ("list", "overcap")}
    for book in st["points"].values():
        for ip in [ip for ip in book if ip not in alive]:
            del book[ip]
    for k in [k for k, t in st["expired_noted"].items() if now - (parse_ts(t) or now) > KEEP]:
        del st["expired_noted"][k]


# ── DB ───────────────────────────────────────────────────────────────────────

# points(이슈 #77)는 to_jsonb 로 읽어 열이 없는 DB(20261003 전)에서도 돈다 (NULL → 두 지점)
FETCH_SQL = """
SELECT abbrev(b.actor_ip) AS key, host(b.actor_ip) AS ip, family(b.actor_ip) AS fam, masklen(b.actor_ip) AS mask,
       to_jsonb(b) -> 'points' AS points,
       b.created_at, b.expires_at, b.released_at, b.enforced_at, b.method, b.enforce_note, b.enforcement,
       (SELECT e.cidr::text FROM block_exempt e WHERE b.actor_ip <<= e.cidr
         ORDER BY masklen(e.cidr) DESC LIMIT 1) AS exempt_net
  FROM blocklist b
 WHERE (b.released_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > now() - %s::interval))
    OR b.enforced_at IS NOT NULL
    OR b.enforcement IS NOT NULL      -- 관문 확인 전에 해제 · 만료된 행의 지점별 결과를 비우려고 읽는다 (이슈 #51)
 ORDER BY b.actor_ip"""
FIELDS = ("key", "ip", "fam", "mask", "points", "created_at", "expires_at", "released_at", "enforced_at", "method", "note",
          "enforcement", "exempt_net")
GUARD = ("released_at", "expires_at", "enforced_at", "method", "enforce_note", "enforcement")
# 읽은 값 대조에 더하는 식 (이슈 #77). 콘솔이 그 사이 넓힌 행은 다음 회차에 본다. 열이 없는 DB 에서도 돈다
GUARD_EXPR = {"points": "to_jsonb(blocklist) -> 'points'"}
JSON_COLS = ("enforcement", "points")


# 차단 보고 생존 신호 (이슈 #52). 트리거(sensor_heartbeats_guard)가 집행 역할에 block_report 행만 허락한다.
# seen_at 은 DB now() 보다 늦으면 now() 로 한다(관문 시계가 2분까지 앞설 수 있다). least() 는 NULL 을 건너뛰므로 CASE 로 감싼다.
# 못 읽은 회차는 옛 seen_at 을 둔다. 관문 인스턴스가 바뀌었으면(host 가 다르면) 옛 관문의 시각을 이어 쓰지 않는다
HEARTBEAT_SQL = """
INSERT INTO sensor_heartbeats AS h (source, kind, role, host, seen_at, checked_at, problem)
VALUES (%(source)s, 'block_report', %(role)s, %(host)s,
        CASE WHEN %(seen_at)s::timestamptz IS NOT NULL THEN least(%(seen_at)s::timestamptz, now()) END,
        now(), %(problem)s)
ON CONFLICT (source) DO UPDATE SET
    kind = EXCLUDED.kind, role = EXCLUDED.role, host = EXCLUDED.host,
    seen_at = CASE WHEN h.host = EXCLUDED.host THEN coalesce(EXCLUDED.seen_at, h.seen_at) ELSE EXCLUDED.seen_at END,
    checked_at = EXCLUDED.checked_at, problem = EXCLUDED.problem"""
HEARTBEAT_SKIP = ("42P01", "42501")     # 표 없음(마이그레이션 전) · 권한 없음(#47 · 역할 블록을 다시 적용한 뒤). 등급 5 로만 알린다


def beat(point, host, report, problem):
    """지점 하나의 생존 신호 행. report 는 validate_status 가 검증한 보고(못 읽었으면 None)다."""
    return {"source": f"block:{point}", "role": point, "host": host,
            "seen_at": report["at"] if report else None, "problem": None if report else clean(problem or "까닭 없음", 120)}


def _pg_value(col, v):
    """jsonb 열은 Json 으로 감싼다 (None 은 SQL NULL 그대로)."""
    if col in JSON_COLS and v is not None:
        from psycopg2.extras import Json
        return Json(v)
    return v


def _ph(col):
    return "%s::jsonb" if col in JSON_COLS else "%s"


class PgStore:
    """opsloop_enforcer 역할로 읽고 쓴다. 쓰는 열은 method · enforced_at · enforce_note · enforcement 넷뿐이다.
    그 밖에 차단 보고 생존 신호(sensor_heartbeats 의 block_report 행, 이슈 #52)를 쓴다."""

    def __init__(self, conn):
        self.conn = conn

    def fetch(self):
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '30s'")
            cur.execute("SELECT now()")
            now = cur.fetchone()[0]
            cur.execute(FETCH_SQL, (f"{int(EXPIRED_LOOKBACK.total_seconds())} seconds",))
            rows = [dict(zip(FIELDS, r)) for r in cur.fetchall()]
        return {"now": now, "rows": rows}

    def apply(self, updates):
        """한 트랜잭션. 읽은 값이 그대로인 행만 바꾼다. 바꾼 행 수를 돌려준다."""
        n = 0
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '5s'")
            cur.execute("SET LOCAL statement_timeout = '30s'")
            guard = GUARD + tuple(GUARD_EXPR)
            for u in updates:
                cols = sorted(u["set"])
                sql = ("UPDATE blocklist SET " + ", ".join(f"{c} = {_ph(c)}" for c in cols)
                       + " WHERE actor_ip = %s::inet AND "
                       + " AND ".join(f"{GUARD_EXPR.get(c, c)} IS NOT DISTINCT FROM {_ph(c)}" for c in guard))
                cur.execute(sql, [_pg_value(c, u["set"][c]) for c in cols] + [u["key"]]
                            + [_pg_value(c, u["guard"][c]) for c in guard])
                n += cur.rowcount
        return n

    def note_expired(self, key, expires):
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '30s'")
            cur.execute("SELECT note_block_expired(%s::inet, %s)", (key, expires))

    def heartbeat(self, rows):
        """지점별 차단 보고 생존 신호를 한 트랜잭션으로 넣거나 고친다 (이슈 #52)."""
        with self.conn, self.conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '5s'")
            cur.execute("SET LOCAL statement_timeout = '30s'")
            for r in rows:
                cur.execute(HEARTBEAT_SQL, r)


# ── 한 회차 ───────────────────────────────────────────────────────────────────

def cycle(cfg, store, s3w, s3r, st, dry_run=False):
    """한 회차. 종료 코드를 돌려준다. st 는 그 자리에서 고친다 (dry_run 이면 호출자가 버린다)."""
    rc = 0
    try:
        snap = store.fetch()
    except Exception as e:  # noqa: BLE001
        log(f"DB 를 읽지 못했다. 목록을 올리지 않는다 (관문은 옛 집합을 두고 만료로 뺀다): {why(e)}", 3)
        return 1
    now, rows = snap["now"], snap["rows"]
    resume(st)
    st["seq"] += 1
    st["fw_book"]["seq"] = st["seq"]
    # 내부 방화벽 보고를 목록보다 먼저 읽어 이번 회차 목록의 모드를 정한다 (이슈 #77). 뒤의 판단도 이 보고를 쓴다
    fw = fproblem = None
    if cfg.get("fw"):
        fw, fproblem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["fw"]), now, label="내부 방화벽")
        if fw is None:
            rc = 1
    per_point = list_mode(st, cfg, fw)
    gw_entries, fw_entries = classify_rows(rows, now, per_point)
    doc = list_doc(gw_entries, fw_entries, now)
    fdg = doc["points"]["fw"]["digest"]
    pub = st["published"]
    last_up = parse_ts(pub.get("uploaded_at")) if pub else None
    # 옛 상태 파일(published 에 fw_digest 가 없음)이면 바로 올린다 (내부 방화벽 동기화가 points 를 곧 읽는다)
    changed = not pub or pub.get("digest") != doc["digest"] or pub.get("fw_digest") != fdg
    need = changed or last_up is None or now - last_up >= REFRESH - REFRESH_EARLY
    counts = f"관문 {len(gw_entries)}개 digest {doc['digest'][:8]} · 내부 방화벽 {len(fw_entries)}개 digest {fdg[:8]}"
    if need and dry_run:
        log(f"(dry-run) 목록을 올릴 차례다: {counts}")
    elif need:
        try:
            s3w.put_object(Bucket=cfg["bucket"], Key=LIST_KEY, ContentType="application/json",
                           CacheControl="no-cache", Body=json.dumps(doc, ensure_ascii=True).encode("utf-8"))
            st["published"] = {"digest": doc["digest"], "fw_digest": fdg, "generated_at": doc["generated_at"],
                               "uploaded_at": iso_full(now), "count": len(gw_entries), "fw_count": len(fw_entries)}
            st["upload_fail_since"] = None
            log(f"목록을 올렸다: {counts}" + ("" if changed else " (그대로 · 생존 표시)"))
        except Exception as e:  # noqa: BLE001
            rc = 1
            since(st, "upload_fail_since", now)
            log(f"목록을 올리지 못했다 (s3://{cfg['bucket']}/{LIST_KEY}): {why(e)}", 3)
    elif not dry_run:
        st["upload_fail_since"] = None     # S3 의 목록이 지금 목록이다 (올릴 것이 없다)
    pub = st["published"]
    current = bool(pub) and pub.get("digest") == doc["digest"] and pub.get("fw_digest") == fdg
    if current:
        bookkeep(st, gw_entries, doc["digest"], st["seq"], now)
        bookkeep(st["fw_book"], fw_entries, fdg, st["seq"], now)
    gw, problem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["gateway"]), now)
    if gw is None:
        rc = rc or 1
    gw_pub = (doc["digest"], gw_entries) if current else None
    fw_pub = (fdg, fw_entries) if current else None
    j = judge(st, gw, problem, now, [(st, gw_pub)])
    fail_at = parse_ts(st.get("upload_fail_since")) if st.get("upload_fail_since") else None
    stuck = None
    if fail_at is not None and now - fail_at >= STALE:
        # 쪽지가 회차마다 바뀌지 않게 오류 문구 · 지난 시간을 넣지 않는다 (까닭은 로그의 '목록을 올리지 못했다')
        stuck = j["upload_stuck"] = "목록을 5분 넘게 올리지 못함"
        log(f"목록을 {fail_at.isoformat()} 부터 올리지 못했다. S3 에 없는 행은 관문 불일치로 둔다", 4)
    if j["mismatch"]:
        log(f"관문 불일치: {j['mismatch']}", 4)
    elif j["problems"] and j["verified"]:
        log("관문 오류 (행 확인은 보고대로): " + "; ".join(j["problems"])[:500], 4)
    elif j["problems"]:
        log("관문 확인 보류: " + "; ".join(j["problems"])[:500], 5)
    beats = [beat("gateway", cfg["gateway"], gw, problem)]
    if cfg.get("fw"):
        # 내부 방화벽 (이슈 #51 · #77). 보고는 목록 전에 읽었다. 내부 방화벽 목록 장부(fw_book)로 먼저, 거기 없으면 기존 장부
        # (옛 판 동기화가 entries 를 적용)로 판단한다. 관문의 세 열에는 닿지 않고 enforcement 의 fw 갈래만 쓴다
        beats.append(beat("fw", cfg["fw"], fw, fproblem))
        fwj = judge(st, fw, fproblem, now, [(st["fw_book"], fw_pub), (st, gw_pub)], prefix="fw_", label="내부 방화벽")
        if stuck:
            fwj["upload_stuck"] = stuck
        if fwj["mismatch"]:
            log(f"내부 방화벽 불일치: {fwj['mismatch']}", 4)
        elif fwj["problems"]:
            log("내부 방화벽 " + ("오류 (행 확인은 보고대로): " if fwj["verified"] else "확인 보류: ")
                + "; ".join(fwj["problems"])[:500], 4 if fwj["verified"] else 5)
        if fwj["legacy"]:
            log(f"내부 방화벽이 관문 목록을 적용했다 ({NOTE_FW_OLD} · 목록 {fwj['d8']})", 4)
    else:
        # 설정에서 뺀 내부 방화벽의 시계를 버린다. 다시 넣으면 새로 센다 (옛 확인 시각을 이어 쓰지 않는다)
        fwj = unset_judge(st)
        st["fw_status_fail_since"] = st["fw_unknown_since"] = st["fw_error_since"] = None
    judges = {"gateway": j, "fw": fwj}
    for p in [p for p in st["points"] if p not in judges]:
        del st["points"][p]
    updates, expired, tally = plan(rows, st, j, now, current, judges)
    summary = " · ".join(f"{k} {v}" for k, v in sorted(tally.items())) or "없음"
    if dry_run:
        for u in updates:
            log(f"(dry-run) {u['ip']} {u['tag']}: " + ", ".join(f"{k}={clean(v, 80)}" for k, v in u["set"].items()))
        for key, exp, _ in expired:
            log(f"(dry-run) 만료 기록 {clean(key, 60)} {iso(exp)}")
        log(f"(dry-run) 행 {len(rows)}: {summary}. 고칠 행 {len(updates)} · 만료 기록 {len(expired)}")
        return rc
    if updates:
        try:
            n = store.apply(updates)
            log(f"집행 기록 {n}/{len(updates)}행을 고쳤다"
                + ("" if n == len(updates) else " (나머지는 그 사이 바뀌어 다음 회차에 본다)"))
        except Exception as e:  # noqa: BLE001
            rc = 1
            log(f"집행 기록을 쓰지 못했다 (다음 회차에 다시 쓴다): {why(e)}", 3)
    for key, exp, k in expired:
        try:
            store.note_expired(key, exp)
            st["expired_noted"][k] = iso_full(now)
        except Exception as e:  # noqa: BLE001
            rc = 1
            log(f"만료 기록을 남기지 못했다 ({clean(key, 60)}): {why(e)}", 3)
    try:
        store.heartbeat(beats)
    except Exception as e:  # noqa: BLE001 - 생존 신호는 집행과 따로다. 종료 코드를 바꾸지 않는다
        skip = getattr(e, "pgcode", None) in HEARTBEAT_SKIP
        hint = "infra/migrations/20260930_status_board.sql 을 적용한다" if skip else "다음 회차에 다시 쓴다"
        log(f"차단 보고 생존 신호를 기록하지 못했다 (집행은 그대로 · {hint}): {why(e)}", 5 if skip else 4)
    prune(st, rows, now)
    gws = f"관문 {j['mode']} {iso(j['at'])} 목록 {j['d8'] or '-'}" if gw else f"관문 보고 없음 ({problem})"
    if cfg.get("fw"):
        gws += (f" · 내부 방화벽 {fwj['mode']} {iso(fwj['at'])} 목록 {fwj['d8'] or '-'}" if fwj["at"]
                else f" · 내부 방화벽 보고 없음 ({fwj['problems'][0] if fwj['problems'] else '-'})")
    log(f"행 {len(rows)} · 목록 관문 {len(gw_entries)} · 내부 방화벽 {len(fw_entries)} (관문 목록 {MODE_LABEL[per_point]})"
        f" · {gws}: {summary}")
    return rc


def list_mode(st, cfg, fw):
    """이번 회차의 관문 목록 모드 (이슈 #77). True 면 지점별(entries 는 관문을 요청한 행), False 면 전체(모든 행).
    fw 는 이번 회차에 목록을 만들기 전에 읽은 내부 방화벽 보고(못 읽었으면 None)다. st['seq'] 는 이번 회차다."""
    before = bool(st["fw_list_ok"])
    if not cfg.get("fw"):
        ok, why_ = False, "OPSLOOP_FW_ID 없음"
    elif fw is not None and fw["list"] == "fw":
        ok, why_ = True, "내부 방화벽 보고 list fw"
    elif fw is not None and fw["list"] is not None:
        ok, why_ = False, f"내부 방화벽 보고 list {fw['list']}"
    else:
        # 못 읽었거나 list null 이면 직전 회차에 정한 모드만 이어 간다 (끊긴 상태 파일의 모드는 믿지 않는다)
        ok = before and st["fw_list_seq"] == st["seq"] - 1
        why_ = "내부 방화벽 보고를 읽지 못함" if fw is None else "내부 방화벽 보고 list null"
    st["fw_list_ok"], st["fw_list_seq"] = ok, st["seq"]
    if ok != before:
        log(f"관문 목록 모드: {MODE_LABEL[before]} → {MODE_LABEL[ok]} ({why_})", 4)
    return ok


# ── 명령 ─────────────────────────────────────────────────────────────────────

def cmd_run(args):
    if not args.dry_run and os.geteuid() == 0:
        # root 가 쓴 상태 파일(0600)은 서비스 사용자가 읽지 못한다
        raise ConfigError("root 로는 run --dry-run 만 한다. 한 회차는 sudo systemctl start opsloop-enforcer.service")
    cfg = settings()
    if not cfg["bucket"]:
        raise ConfigError("OPSLOOP_BUCKET 이 없다 (/etc/default/opsloop-enforcer)")
    s3w, s3r = s3_client(cfg, "s3-block.env"), s3_client(cfg, "s3-pull.env")
    lock = take_lock(cfg["home"])
    try:
        path = os.path.join(cfg["home"], "state.json")
        st = load_state(path)
        try:
            conn = db_connect()
        except ConfigError:
            raise
        except Exception as e:  # noqa: BLE001
            log(f"DB 에 붙지 못했다. 목록을 올리지 않는다: {why(e)}", 3)
            return 1
        try:
            rc = cycle(cfg, PgStore(conn), s3w, s3r, st, dry_run=args.dry_run)
        finally:
            conn.close()
        if not args.dry_run:
            save_state(path, st)
        return rc
    finally:
        lock.close()


def saved_mode(home):
    """상태 파일에 남은 마지막 회차의 관문 목록 모드 (list 용, 읽기만 · 로그 없음). 못 읽거나 끊겼으면 전체다."""
    try:
        with open(os.path.join(home, "state.json"), encoding="utf-8") as f:
            st = json.load(f)
        return st.get("fw_list_ok") is True and st.get("fw_list_seq") == st.get("seq")
    except (OSError, ValueError, AttributeError):
        return False


def cmd_list(args):
    cfg = settings()
    per_point = bool(cfg["fw"]) and saved_mode(cfg["home"])
    conn = db_connect()
    try:
        snap = PgStore(conn).fetch()
    finally:
        conn.close()
    gw, fw = classify_rows(snap["rows"], snap["now"], per_point)
    doc = list_doc(gw, fw, snap["now"])
    # 표준 출력을 먼저 비운다. 파이프로 받으면(설치기 `list 2>&1 | tail -n 1`) 버퍼 때문에 아래 갈래 수가 JSON 앞에 온다
    print(json.dumps(doc, ensure_ascii=False, indent=1), flush=True)
    kinds = {}
    for r in snap["rows"]:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"# 관문 목록 {MODE_LABEL[per_point]} (마지막 회차) · 관문 {len(gw)} · 내부 방화벽 {len(fw)}", file=sys.stderr)
    print(f"# 행 {len(snap['rows'])}: " + " · ".join(f"{k} {v}" for k, v in sorted(kinds.items())), file=sys.stderr)
    return 0


def state_label(r):
    """화면(B4)과 같은 다섯 갈래를 사람이 읽게. 관문 미요청 행은 내부 방화벽 결과로 본다 (이슈 #77)."""
    if r["kind"] in ("released", "expired"):
        return "해제/만료"
    note = r["note"] or ""
    if note.startswith("집행 제외"):
        return "집행 제외"
    if not wants(r, "gateway"):
        state = _point_rec(r, "fw").get("state")
        if state == "confirmed":
            return "집행 확인"
        return "내부 방화벽 불일치" if state in ("failed", "stale") else "집행 대기"
    if note.startswith("관문 불일치"):
        return "관문 불일치"
    if r["enforced_at"] is not None and _state(r, "gateway") not in ("pending", "removing"):
        return "집행 확인"                # 다시 걸거나 연장한 뒤 새 목록을 확인하기 전(관문 결과 대기)은 대기다 (결정 2)
    return "집행 대기"


def _point_rec(r, point):
    e = r.get("enforcement")
    p = e.get(point) if isinstance(e, dict) else None
    return p if isinstance(p, dict) else {}


def _state(r, point):
    return _point_rec(r, point).get("state")


def held_at(r, point):
    """그 지점에 남은 기록(state 가 글자인 결과 기록, 관문은 확인 시각도). 요청하지 않은 지점이면 빠짐 확인 전이다 (이슈 #77, 콘솔
    block_points.held_sql · 화면 heldPoint 와 같은 정의)."""
    return isinstance(_state(r, point), str) or (point == "gateway" and r["enforced_at"] is not None)


def point_counts(rows):
    """지점별 (요청, 확인, 미요청, 빠짐 확인 전) 수 (목록 행, 이슈 #77). 요청하지 않은 행 가운데 그 지점에 기록이 남은 행은
    미요청이 아니라 빠짐 확인 전으로 따로 센다."""
    live = [r for r in rows if r["kind"] == "list"]
    out = {}
    for p in POINTS:
        req = [r for r in live if wants(r, p)]
        left = sum(1 for r in live if not wants(r, p) and held_at(r, p))
        out[p] = (len(req), sum(1 for r in req if _state(r, p) == "confirmed"), len(live) - len(req) - left, left)
    return out


def cmd_status(args, out=print):
    cfg = settings()
    st = load_state(os.path.join(cfg["home"], "state.json"))
    pub = st.get("published") or {}
    out(f"마지막 회차 {st['seq']} · 올린 목록 관문 {pub.get('count', '-')}개 digest {str(pub.get('digest') or '-')[:8]}"
        f" · 내부 방화벽 {pub.get('fw_count', '-')}개 digest {str(pub.get('fw_digest') or '-')[:8]}"
        f" · 올린 시각 {pub.get('uploaded_at') or '-'}")
    mode = bool(cfg.get("fw")) and st["fw_list_ok"]
    out(f"관문 목록: {MODE_LABEL[mode]}" + ("" if cfg.get("fw") else " (OPSLOOP_FW_ID 없음)"))
    for k in ("status_fail_since", "unknown_since", "error_since", "upload_fail_since"):
        if st.get(k):
            out(f"  5분 시계 {k}: {st[k]}")
    rc = 0
    try:
        conn = db_connect()
        try:
            snap = PgStore(conn).fetch()
        finally:
            conn.close()
        classify_rows(snap["rows"], snap["now"], mode)
        labels = {}
        for r in snap["rows"]:
            labels[state_label(r)] = labels.get(state_label(r), 0) + 1
        out("DB (지난 2일 안의 만료 · 집행 기록이 남은 행 포함): "
            + (" · ".join(f"{k} {v}" for k, v in sorted(labels.items())) or "행 없음"))
        pc = point_counts(snap["rows"])
        out("지점별 (목록 행): " + " / ".join(
            f"{POINT_LABEL[p]} 요청 {pc[p][0]} · 확인 {pc[p][1]}" + (f" · 미요청 {pc[p][2]}" if pc[p][2] else "")
            + (f" · 빠짐 확인 전 {pc[p][3]}" if pc[p][3] else "") for p in POINTS))
    except ConfigError:
        raise
    except Exception as e:  # noqa: BLE001
        rc = 1
        out(f"DB 를 읽지 못했다: {why(e)}")
    try:
        s3r = s3_client(cfg, "s3-pull.env")
        gw, problem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["gateway"]), datetime.now(timezone.utc))
    except ConfigError as e:
        out(f"관문 보고를 읽을 수 없다: {e}")
        return 1
    if gw is None:
        out(f"관문 보고: 없음 ({problem})")
        return 1
    out(f"관문 보고: {iso(gw['at'])} · {gw['mode']} · 목록 {gw['list'] or '-'} {str(gw['digest'] or '-')[:8]}"
        f" · 적용 {gw['applied']}"
        f" · 집합 {gw['set_count']} · 거부 {len(gw['rejected'])} · 오류 {len(gw['errors'])}"
        f" · 자가 시험 {gw['selftest'] or '-'}")
    for e in gw["errors"][:5]:
        out(f"  오류: {e}")
    if cfg.get("fw"):
        fw, fproblem = read_status(s3r, cfg["bucket"], STATUS_KEY.format(gw=cfg["fw"]), datetime.now(timezone.utc),
                                   label="내부 방화벽")
        if fw is None:
            out(f"내부 방화벽 보고: 없음 ({fproblem})")
            return 1
        out(f"내부 방화벽 보고: {iso(fw['at'])} · {fw['mode']} · 목록 {fw['list'] or '-'} {str(fw['digest'] or '-')[:8]}"
            f" · 적용 {fw['applied']} · 집합 {fw['set_count']} · 거부 {len(fw['rejected'])} · 오류 {len(fw['errors'])}"
            f" · 자가 시험 {fw['selftest'] or '-'}")
        for e in fw["errors"][:5]:
            out(f"  오류: {e}")
    return rc


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"인자 오류: {message}", file=sys.stderr)
        sys.exit(2)


def build_parser():
    p = _Parser(prog="opsloop-enforcer", description="차단 집행기 (DB 차단 목록 → 관문, 관문 보고 → DB)")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    r = sub.add_parser("run", help="한 회차 (타이머)")
    r.add_argument("--dry-run", action="store_true", help="읽기만 하고 할 일을 찍는다")
    r.set_defaults(func=cmd_run)
    sub.add_parser("list", help="올릴 목록 JSON 을 찍는다").set_defaults(func=cmd_list)
    sub.add_parser("status", help="마지막 회차 · 관문 목록 모드 · 보고 · 상태별 건수").set_defaults(func=cmd_status)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        log(f"설정 오류: {e}", 3)
        return 2


if __name__ == "__main__":
    sys.exit(main())
