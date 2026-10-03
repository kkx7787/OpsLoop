#!/usr/bin/env python3
"""Loki 보존 설정 후보만 작성한다. 운영 설정 교체나 서비스 재시작은 하지 않는다."""
import argparse
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / 'compose' / 'loki.yaml'


def prepare(base, days):
    if days not in (7, 30):
        raise ValueError('지원 보존 기간: 7일 또는 30일')
    if base.count('\nlimits_config:\n') != 1 or '\ncompactor:' in base or '  retention_period:' in base:
        raise ValueError('기본 설정이 변경되었습니다. 기존 보존 설정과의 충돌을 검토하세요.')
    base = base.replace('보존 삭제는 하지 않는다 (원장).', f'보존 기간 {days}일(이 설정을 배포하면 원본 로그가 삭제됨).')
    base = base.replace('\nlimits_config:\n', f'\nlimits_config:\n  retention_period: {days*24}h\n')
    return base + '''
# 단일 Loki의 지속 저장소에 삭제 표식을 둔다. 사건/판정/감사 DB는 대상이 아니다.
compactor:
  working_directory: /loki/compactor
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 10
  delete_request_store: filesystem
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--days', type=int, choices=(7,30), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    content=prepare(BASE.read_text(), args.days)
    # 기존 파일을 덮어쓰지 않는다. 배포자는 생성된 후보와 현재 설정을 대조한다.
    with args.output.open('x') as file:
        file.write(content)
    print(f'{args.output}: {args.days}일 설정 후보 생성. 운영 반영 전 백업과 재생성 범위를 확인하세요.')


if __name__ == '__main__':
    main()
