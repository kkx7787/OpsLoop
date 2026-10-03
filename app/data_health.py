"""#109: 데이터 노드 자원 상태. 저장된 최신 한 행으로 카드와 이상 띠를 함께 판정한다."""
import json
import math

STALE_SECONDS = 600
GIB = 1024 ** 3
READABLE_SQL = """SELECT CASE WHEN to_regclass('data_node_health') IS NULL THEN 'missing'
    WHEN has_table_privilege(current_user, 'data_node_health', 'SELECT') THEN 'ok'
    ELSE 'denied' END"""


def number(value, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return value if maximum is None or value <= maximum else None


def view(row, as_of, readable='ok'):
    result = {'state': 'no_data', 'metrics': None, 'disks': [], 'capacity': 'unknown', 'problems': []}
    if readable != 'ok' or row is None:
        result['state'] = 'no_privilege' if readable == 'denied' else 'no_data'
        result['problems'] = [('데이터 노드 자원 수집 미설치' if readable == 'missing' else
                               '데이터 노드 자원 조회 권한 없음' if readable == 'denied' else '데이터 노드 자원 수집 기록 없음')]
        return result
    at = row['checked_at']
    age = (as_of - at).total_seconds()
    stale = age > STALE_SECONDS or age < -300
    raw = row['disks']
    try:
        disks = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        disks = None
    problems = [str(p)[:160] for p in (row['problems'] or [])[:8]]
    if not isinstance(disks, list) or not 1 <= len(disks) <= 3:
        disks = []
        problems.append('디스크 측정 형식 확인 필요')
    result['state'] = 'stale' if stale else 'ok'
    result['metrics'] = {'ts': at.isoformat(), 'cpu_pct': number(row['cpu_pct'], 100),
                         'mem_used_pct': number(row['mem_used_pct'], 100), 'load1': number(row['load1']),
                         'disk_root_pct': None}
    worst = 'ok'
    covered = set()
    for disk in disks:
        if not isinstance(disk, dict):
            problems.append('디스크 측정 형식 확인 필요')
            continue
        labels = disk.get('labels')
        if not isinstance(labels, list) or not labels or any(x not in ('루트', 'PostgreSQL', 'Loki') for x in labels):
            problems.append('디스크 측정 대상 확인 필요')
            continue
        covered.update(labels)
        used, free, inodes = number(disk.get('used_pct'), 100), number(disk.get('available_bytes')), number(disk.get('inode_used_pct'), 100)
        level = 'unknown'
        if used is not None and free is not None and not disk.get('error'):
            level = ('critical' if used >= 90 or free <= GIB or (inodes is not None and inodes >= 95) else
                     'warning' if used >= 80 or free <= 2 * GIB or (inodes is not None and inodes >= 90) else 'ok')
        else:
            problems.append(' · '.join(labels) + ' 디스크 측정 실패')
        if level == 'critical' or (level == 'warning' and worst != 'critical'):
            worst = level
        result['disks'].append({'label': ' · '.join(labels), 'used_pct': used, 'available_bytes': free,
                                'inode_used_pct': inodes, 'state': 'unknown' if stale else level})
        if '루트' in labels:
            result['metrics']['disk_root_pct'] = used
    if not {'루트', 'PostgreSQL', 'Loki'} <= covered:
        problems.append('루트 · DB · 원장 측정 대상 누락')
    if result['metrics']['cpu_pct'] is None or result['metrics']['mem_used_pct'] is None:
        problems.append('CPU · 메모리 측정 확인 필요')
    result['problems'] = list(dict.fromkeys(problems))
    result['capacity'] = 'unknown' if stale or (problems and worst == 'ok') else worst
    return result


def alerts(system):
    if system['state'] == 'stale':
        return [{'key': 'data_resources', 'level': 'unknown', 'label': '데이터 노드 자원 지표',
                 'reason': '측정이 10분 넘게 오래됐거나 시계 확인이 필요함', 'at': system['metrics']['ts'], 'count': None}]
    out = []
    if system['problems']:
        out.append({'key': 'data_resources', 'level': 'unknown', 'label': '데이터 노드 자원 지표',
                    'reason': ' · '.join(system['problems']), 'at': None, 'count': None})
    for i, disk in enumerate(system['disks']):
        if disk['state'] in ('warning', 'critical'):
            out.append({'key': f'data_disk:{i}', 'level': 'alert',
                        'label': f"데이터 노드 {disk['label']} 용량",
                        'reason': f"{'부족' if disk['state'] == 'critical' else '여유 감소'} · 사용 {disk['used_pct']:.1f}% · "
                                  f"남음 {disk['available_bytes'] / GIB:.1f} GiB"
                                  + (f" · inode 사용 {disk['inode_used_pct']:.1f}%" if disk['inode_used_pct'] is not None and disk['inode_used_pct'] >= 90 else ''),
                        'at': system['metrics']['ts'], 'count': None})
    return out


async def read(connection, as_of):
    readable = await connection.fetchval(READABLE_SQL)
    row = await connection.fetchrow('SELECT * FROM data_node_health WHERE singleton') if readable == 'ok' else None
    return view(row, as_of, readable)
