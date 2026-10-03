#!/usr/bin/env python3
"""data01 자원 측정. 원장이 아닌 최신 한 행만 갱신한다. --check 는 DB에 쓰지 않는다."""
import argparse
import json
import math
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

LABELS = {'root': '루트', 'postgres': 'PostgreSQL', 'loki': 'Loki'}
UPSERT = """INSERT INTO data_node_health(singleton, checked_at, cpu_pct, mem_used_pct, load1, disks, problems)
VALUES(true, clock_timestamp(), %s, %s, %s, %s::jsonb, %s)
ON CONFLICT(singleton) DO UPDATE SET checked_at=EXCLUDED.checked_at, cpu_pct=EXCLUDED.cpu_pct,
mem_used_pct=EXCLUDED.mem_used_pct, load1=EXCLUDED.load1, disks=EXCLUDED.disks, problems=EXCLUDED.problems"""


def cpu_ticks(path='/proc/stat'):
    fields = Path(path).read_text().splitlines()[0].split()
    if fields[0] != 'cpu' or len(fields) < 5:
        raise ValueError('cpu')
    # guest는 user/nice에 이미 포함된다. 8개만 더한다.
    values = [int(v) for v in fields[1:9]]
    if any(v < 0 for v in values):
        raise ValueError('cpu')
    return sum(values), values[3] + (values[4] if len(values) > 4 else 0)


def cpu_percent(before, after):
    total, idle = after[0] - before[0], after[1] - before[1]
    if total <= 0 or not 0 <= idle <= total:
        raise ValueError('cpu delta')
    return round((total - idle) / total * 100, 1)


def memory_percent(path='/proc/meminfo'):
    rows = {line.split(':')[0]: int(line.split()[1]) for line in Path(path).read_text().splitlines()}
    total, available = rows['MemTotal'], rows['MemAvailable']
    if total <= 0 or not 0 <= available <= total:
        raise ValueError('memory')
    return round((total - available) / total * 100, 1)


def disk_stats(paths):
    """같은 파일시스템은 한 행. 경로가 없거나 권한이 없으면 루트값으로 대신하지 않는다."""
    disks, by_device = [], {}
    for key, label in LABELS.items():
        path = paths[key]
        try:
            device = os.stat(path).st_dev
            if device in by_device:
                by_device[device]['labels'].append(label)
                continue
            fs = os.statvfs(path)
            used, available = fs.f_blocks - fs.f_bfree, fs.f_bavail
            if used < 0 or available < 0 or used + available <= 0:
                raise ValueError('disk counters')
            row = {'labels': [label], 'used_pct': round(100 * used / (used + available), 1),
                   'available_bytes': available * fs.f_frsize,
                   'inode_used_pct': round(100 * (fs.f_files - fs.f_ffree) / fs.f_files, 1) if fs.f_files > 0 else None}
            by_device[device] = row
        except (OSError, ValueError):
            row = {'labels': [label], 'used_pct': None, 'available_bytes': None, 'inode_used_pct': None, 'error': True}
        disks.append(row)
    return disks


def sample(paths):
    problems = []
    cpu = memory = load = None
    try:
        before = cpu_ticks()
        time.sleep(1)
        cpu = cpu_percent(before, cpu_ticks())
    except (OSError, ValueError, IndexError):
        problems.append('CPU 측정 실패')
    try:
        memory = memory_percent()
    except (OSError, ValueError, KeyError, IndexError):
        problems.append('메모리 측정 실패')
    try:
        load = os.getloadavg()[0]
        if not math.isfinite(load) or load < 0:
            load = None
            raise ValueError('load')
    except (OSError, ValueError):
        problems.append('부하 측정 실패')
    return {'cpu_pct': cpu, 'mem_used_pct': memory, 'load1': load, 'disks': disk_stats(paths), 'problems': problems}


def load_paths(path):
    paths = json.loads(Path(path).read_text())
    if not isinstance(paths, dict) or set(paths) != set(LABELS):
        raise ValueError('resource paths')
    if paths['root'] != '/' or any(not isinstance(p, str) or not p.startswith('/') for p in paths.values()):
        raise ValueError('resource paths')
    return paths


def database_url(path):
    # 셸로 source 하지 않고 KEY=VALUE 파일을 읽는다. 오류에도 원문을 출력하지 않는다.
    values = dict(line.strip().split('=', 1) for line in Path(path).read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith('#') and '=' in line)
    url = values['DATABASE_URL'].strip()
    parsed = urlsplit(url)
    if parsed.scheme not in ('postgresql', 'postgres') or parsed.username != 'opsloop_ingest':
        raise ValueError('ingest role required')
    return url


def store(connection, result):
    with connection.cursor() as cursor:
        cursor.execute(UPSERT, (result['cpu_pct'], result['mem_used_pct'], result['load1'],
                               json.dumps(result['disks'], allow_nan=False), result['problems']))
    connection.commit()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--paths', default='/etc/opsloop/data-health.json')
    parser.add_argument('--env', default='/etc/opsloop/collector.env')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = sample(load_paths(args.paths))
        if args.check:
            print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        else:
            import psycopg2
            connection = psycopg2.connect(database_url(args.env), connect_timeout=5,
                options='-c statement_timeout=5000 -c lock_timeout=2000', application_name='opsloop-data-health')
            try:
                store(connection, result)
            finally:
                connection.close()
            print('data-health: 최신 상태 저장 완료')
        return 0
    except Exception as exc:
        # psycopg2/config 예외 문자열은 자격 증명 또는 호스트를 담을 수 있다.
        print(f'data-health: 측정/저장 실패 ({type(exc).__name__})', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
